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
                chain_length=cert_info.chain_length,
                header_score=cert_info.header_score,
                header_grade=cert_info.header_grade,
                headers_present=cert_info.headers_present,
                headers_missing=cert_info.headers_missing,
                hsts_max_age=cert_info.hsts_max_age,
                csp_has_unsafe_inline=cert_info.csp_has_unsafe_inline,
                header_recommendations=cert_info.header_recommendations,
            )

            # Record successful scan
            self.db.add_scan(
                cert_id, endpoint_id, 'success',
                tls_version=cert_info.tls_version,
                cipher=cert_info.cipher
            )
            
            # Check if we need to notify about expiry
            days_until_expiry = self.scanner.get_days_until_expiry(cert_info.not_after)
            threshold_matched = self._check_and_notify(cert_id, endpoint, days_until_expiry)

            # Send standalone security alert only when no expiry threshold
            # matched — the expiry alert already includes security warnings.
            if not threshold_matched and (cert_info.is_self_signed or not cert_info.is_trusted_ca):
                self._send_security_alert_for_cert(cert_id, endpoint, cert_info)
        else:
            # Record failed scan
            self.db.add_scan(0, endpoint_id, 'failed', 'Failed to retrieve certificate')
    
    def _check_and_notify(self, cert_id: int, endpoint: dict, days_until_expiry: float) -> bool:
        """Check if notification should be sent.

        Sends at most ONE notification per scan — for the lowest matching
        threshold that hasn't already been sent (ever).

        Returns True if a threshold matched (regardless of whether a new
        notification was actually sent), so callers can skip redundant
        security alerts.
        """
        if not self.notifier:
            return False

        notification_thresholds = self.config['notifications']['warning_days']

        # Find all thresholds this cert qualifies for
        matching = [t for t in notification_thresholds if days_until_expiry <= t]
        if not matching:
            return False

        # Pick lowest matching threshold (most urgent)
        target = min(matching)

        # One alert per threshold — no time window
        if self.db.was_notification_sent(cert_id, endpoint['id'], target):
            return True

        cert_data = self._get_certificate_data(cert_id)

        if days_until_expiry <= 1:
            notif_type = 'emergency'
        elif days_until_expiry <= 7:
            notif_type = 'critical'
        elif days_until_expiry <= 30:
            notif_type = 'warning'
        else:
            notif_type = 'info'

        # Use per-endpoint webhook if configured, otherwise global
        success = self.notifier.send_expiry_alert(
            cert_data, endpoint, days_until_expiry,
            webhook_url=endpoint.get('webhook_url')
        )

        if success:
            self.db.add_notification(
                cert_id, endpoint['id'], target, notif_type
            )
        return True
    
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

        # One security alert per cert/endpoint — no time window
        if self.db.was_notification_sent(cert_id, endpoint['id'], 999):
            return

        cert_data = self._get_certificate_data(cert_id)

        days = self.scanner.get_days_until_expiry(cert_info.not_after)
        success = self.notifier.send_expiry_alert(
            cert_data, endpoint, days,
            webhook_url=endpoint.get('webhook_url')
        )

        if success:
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
        # Reload custom CAs from DB (may have been added via UI since last cycle)
        custom_ca_pems = self.db.get_all_trusted_ca_pems()
        self.scanner.set_custom_cas(custom_ca_pems)
        update_ca_bundle(custom_ca_pems)
        self.scan_all_endpoints()
        deleted = self.db.cleanup_orphaned_certificates()
        if deleted:
            logger.info(f"Cleaned up {deleted} orphaned certificate(s)")
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
