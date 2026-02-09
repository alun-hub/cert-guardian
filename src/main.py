#!/usr/bin/env python3
"""
Certificate Guardian - Main Application
Monitor TLS certificates and alert before expiry
"""
import os
import sys
import yaml
import logging
import time
import argparse
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from database import Database
from scanner import TLSScanner
from notifier import MattermostNotifier
from ca_bundle import update_ca_bundle

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('cert-guardian.log')
    ]
)
logger = logging.getLogger(__name__)


class CertificateGuardian:
    def __init__(self, config_path: str):
        """Initialize Certificate Guardian"""
        self.config_path = config_path
        self.config = self._load_config(config_path)
        
        # Initialize components
        db_path = self.config['database']['path']
        self.db = Database(db_path)
        
        # Load custom CAs and build outbound TLS bundle
        custom_ca_pems = self.db.get_all_trusted_ca_pems()
        update_ca_bundle(custom_ca_pems)

        self.scanner = TLSScanner(
            timeout=self.config['scanner'].get('timeout_seconds', 10),
            custom_ca_pems=custom_ca_pems
        )
        
        webhook_url = self.config['mattermost']['webhook_url']
        if not webhook_url or webhook_url == "https://your-mattermost.com/hooks/xxxxxxxxxxxxx":
            logger.warning("Mattermost webhook not configured - notifications disabled")
            self.notifier = None
        else:
            self.notifier = MattermostNotifier(
                webhook_url=webhook_url,
                username=self.config['mattermost'].get('username', 'Certificate Guardian'),
                icon_emoji=self.config['mattermost'].get('icon_emoji', ':lock:')
            )
    
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Loaded configuration from {config_path}")
            return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            sys.exit(1)
    
    def setup_endpoints(self):
        """Setup endpoints from config into database"""
        endpoints = self.config.get('endpoints', [])
        
        for endpoint in endpoints:
            host = endpoint['host']
            port = endpoint.get('port', 443)
            owner = endpoint.get('owner')
            criticality = endpoint.get('criticality', 'medium')
            
            self.db.add_endpoint(host, port, owner, criticality)
            logger.info(f"Added endpoint: {host}:{port}")
    
    def scan_all_endpoints(self):
        """Scan all configured endpoints"""
        endpoints = self.db.get_all_endpoints()
        logger.info(f"Starting scan of {len(endpoints)} endpoints")
        
        for endpoint in endpoints:
            self._scan_endpoint(endpoint)
    
    def _scan_endpoint(self, endpoint: dict):
        """Scan a single endpoint"""
        host = endpoint['host']
        port = endpoint['port']
        endpoint_id = endpoint['id']
        
        # Scan the endpoint
        cert_info = self.scanner.scan_endpoint(host, port)
        
        if cert_info:
            # Store certificate
            cert_id = self.db.add_certificate(
                fingerprint=cert_info.fingerprint,
                subject=cert_info.subject,
                issuer=cert_info.issuer,
                not_before=cert_info.not_before.isoformat(),
                not_after=cert_info.not_after.isoformat(),
                serial_number=cert_info.serial_number,
                san_list=cert_info.san_list,
                key_type=cert_info.key_type,
                key_size=cert_info.key_size,
                signature_algorithm=cert_info.signature_algorithm,
                hostname_matches=cert_info.hostname_matches,
                ocsp_present=cert_info.ocsp_present,
                crl_present=cert_info.crl_present,
                eku_server_auth=cert_info.eku_server_auth,
                key_usage_digital_signature=cert_info.key_usage_digital_signature,
                key_usage_key_encipherment=cert_info.key_usage_key_encipherment,
                chain_has_expiring=cert_info.chain_has_expiring,
                weak_signature=cert_info.weak_signature,
                is_self_signed=cert_info.is_self_signed,
                is_trusted_ca=cert_info.is_trusted_ca,
                validation_error=cert_info.validation_error,
                chain_length=cert_info.chain_length
            )
            
            # Record successful scan
            self.db.add_scan(
                cert_id, endpoint_id, 'success',
                tls_version=cert_info.tls_version,
                cipher=cert_info.cipher
            )
            
            # Check if we need to notify about expiry
            days_until_expiry = self.scanner.get_days_until_expiry(cert_info.not_after)
            self._check_and_notify(cert_id, endpoint, days_until_expiry)
            
            # Also send immediate alert if cert has trust issues
            if cert_info.is_self_signed or not cert_info.is_trusted_ca:
                self._send_security_alert_for_cert(cert_id, endpoint, cert_info)
        else:
            # Record failed scan
            self.db.add_scan(0, endpoint_id, 'failed', 'Failed to retrieve certificate')
    
    def _check_and_notify(self, cert_id: int, endpoint: dict, days_until_expiry: float):
        """Check if notification should be sent"""
        if not self.notifier:
            return
        
        notification_thresholds = self.config['notifications']['warning_days']
        
        for threshold in notification_thresholds:
            # Check if we're within this threshold
            if days_until_expiry <= threshold:
                # Check if we already sent notification for this threshold
                if not self.db.was_notification_sent(cert_id, endpoint['id'], threshold, hours_ago=24):
                    # Get full cert info for notification
                    cert_data = self._get_certificate_data(cert_id)
                    
                    # Determine notification type
                    if days_until_expiry <= 1:
                        notif_type = 'emergency'
                    elif days_until_expiry <= 7:
                        notif_type = 'critical'
                    elif days_until_expiry <= 30:
                        notif_type = 'warning'
                    else:
                        notif_type = 'info'
                    
                    # Send notification
                    success = self.notifier.send_expiry_alert(
                        cert_data, endpoint, days_until_expiry
                    )
                    
                    if success:
                        # Record that we sent notification
                        self.db.add_notification(
                            cert_id, endpoint['id'], threshold, notif_type
                        )
    
    def _get_certificate_data(self, cert_id: int) -> dict:
        """Get certificate data from database"""
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,))
        row = cursor.fetchone()
        return dict(row) if row else {}
    
    def send_daily_summary(self):
        """Send daily summary of all expiring certificates"""
        if not self.notifier:
            return
        
        # Get all certificates expiring within 90 days
        expiring = self.db.get_expiring_certificates(90)
        
        if expiring:
            self.notifier.send_daily_summary(expiring)
            logger.info(f"Sent daily summary with {len(expiring)} expiring certificates")
    
    def _send_security_alert_for_cert(self, cert_id: int, endpoint: dict, cert_info):
        """Send security alert for a single certificate with trust issues"""
        if not self.notifier:
            return
        
        # Check if we already sent security alert for this cert recently
        if self.db.was_notification_sent(cert_id, endpoint['id'], 999, hours_ago=168):  # 7 days
            return
        
        # Get full cert data
        cert_data = self._get_certificate_data(cert_id)
        
        # Send alert (days_until_expiry doesn't matter for security alerts)
        days = self.scanner.get_days_until_expiry(cert_info.not_after)
        success = self.notifier.send_expiry_alert(cert_data, endpoint, days)
        
        if success:
            # Record that we sent security notification (use 999 as special marker)
            self.db.add_notification(cert_id, endpoint['id'], 999, 'security')
    
    def send_security_summary(self):
        """Send summary of all untrusted/self-signed certificates"""
        if not self.notifier:
            return
        
        untrusted = self.db.get_untrusted_certificates()
        
        if untrusted:
            self.notifier.send_security_alert(untrusted)
            logger.info(f"Sent security summary with {len(untrusted)} untrusted certificates")
    
    def run_once(self):
        """Run one scan cycle"""
        logger.info("=== Starting scan cycle ===")
        self.scan_all_endpoints()
        logger.info("=== Scan cycle complete ===")
    
    def run_continuous(self):
        """Run continuous monitoring"""
        interval = self.config['scanner'].get('interval_seconds', 3600)
        logger.info(f"Starting continuous monitoring (interval: {interval}s)")
        
        # Test Mattermost connection
        if self.notifier:
            if self.notifier.test_connection():
                logger.info("✅ Mattermost connection test successful")
            else:
                logger.warning("⚠️ Mattermost connection test failed")
        
        while True:
            try:
                self.run_once()
                interval = self._get_interval_seconds(interval)
                logger.info(f"Sleeping for {interval} seconds...")
                time.sleep(interval)
            except KeyboardInterrupt:
                logger.info("Shutting down...")
                break
            except Exception as e:
                logger.error(f"Error in scan cycle: {e}", exc_info=True)
                time.sleep(60)  # Wait a minute before retrying

    def _get_interval_seconds(self, current_interval: int) -> int:
        """Reload interval from config file if updated"""
        try:
            with open(self.config_path, 'r') as f:
                latest = yaml.safe_load(f) or {}
            new_interval = int(latest.get('scanner', {}).get('interval_seconds', current_interval))
            if new_interval <= 0:
                return current_interval
            if new_interval != current_interval:
                logger.info(f"Updated scan interval to {new_interval}s from config")
            return new_interval
        except Exception as e:
            logger.warning(f"Failed to reload scan interval: {e}")
            return current_interval


def main():
    parser = argparse.ArgumentParser(description='Certificate Guardian - Monitor TLS certificates')
    parser.add_argument('--config', default='config/config.yaml', help='Path to config file')
    parser.add_argument('--once', action='store_true', help='Run once and exit')
    parser.add_argument('--summary', action='store_true', help='Send daily summary and exit')
    parser.add_argument('--security', action='store_true', help='Send security summary of untrusted certs and exit')
    parser.add_argument('--setup', action='store_true', help='Setup endpoints from config')
    
    args = parser.parse_args()
    
    # Initialize Guardian
    guardian = CertificateGuardian(args.config)
    
    if args.setup:
        logger.info("Setting up endpoints from config...")
        guardian.setup_endpoints()
        logger.info("Setup complete")
    elif args.summary:
        logger.info("Sending daily summary...")
        guardian.send_daily_summary()
    elif args.security:
        logger.info("Sending security summary...")
        guardian.send_security_summary()
    elif args.once:
        guardian.run_once()
    else:
        guardian.run_continuous()


if __name__ == '__main__':
    main()
