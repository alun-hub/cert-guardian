#!/usr/bin/env python3
"""
Mattermost Notifier for Certificate Expiry Alerts
"""
import requests
import logging
from typing import Dict, List
from datetime import datetime

logger = logging.getLogger(__name__)


class MattermostNotifier:
    def __init__(self, webhook_url: str, username: str = "Certificate Guardian",
                 icon_emoji: str = ":lock:"):
        self.webhook_url = webhook_url
        self.username = username
        self.icon_emoji = icon_emoji
    
    def send_expiry_alert(self, cert_info: Dict, endpoint: Dict,
                         days_until_expiry: float,
                         webhook_url: str = None) -> bool:
        """
        Send certificate expiry alert to Mattermost
        
        Args:
            cert_info: Certificate information dict
            endpoint: Endpoint information dict
            days_until_expiry: Days until certificate expires
            
        Returns:
            True if notification sent successfully
        """
        # Determine alert level
        if days_until_expiry <= 1:
            color = "danger"
            emoji = "🚨"
            level = "EMERGENCY"
        elif days_until_expiry <= 7:
            color = "danger"
            emoji = "⚠️"
            level = "CRITICAL"
        elif days_until_expiry <= 30:
            color = "warning"
            emoji = "⚠️"
            level = "WARNING"
        else:
            color = "good"
            emoji = "ℹ️"
            level = "INFO"
        
        # Check for trust issues
        is_self_signed = cert_info.get('is_self_signed', 0)
        is_trusted = cert_info.get('is_trusted_ca', 0)
        validation_error = cert_info.get('validation_error')
        
        # Add security warnings
        security_warnings = []
        if is_self_signed:
            security_warnings.append("🔴 **SELF-SIGNED CERTIFICATE**")
            color = "danger"
        if not is_trusted and not is_self_signed:
            security_warnings.append("⚠️ **UNTRUSTED CA**")
            if color == "good":
                color = "warning"
        
        # Format expiry date
        expiry_date = cert_info.get('not_after', 'Unknown')
        if isinstance(expiry_date, str):
            try:
                dt = datetime.fromisoformat(expiry_date)
                expiry_date = dt.strftime('%Y-%m-%d %H:%M UTC')
            except:
                pass
        
        # Build message header
        header_text = f"{emoji} **{level}: Certificate Expiring Soon**"
        if security_warnings:
            header_text = f"{emoji} **{level}: Certificate Issue Detected**"
        
        # Build fields
        fields = [
            {
                "title": "Endpoint",
                "value": f"{endpoint['host']}:{endpoint['port']}",
                "short": True
            },
            {
                "title": "Days Until Expiry",
                "value": f"**{int(days_until_expiry)} days**",
                "short": True
            }
        ]
        
        # Add security warning fields if present
        if security_warnings:
            fields.insert(0, {
                "title": "Security Issues",
                "value": "\n".join(security_warnings),
                "short": False
            })
            
            if validation_error:
                fields.append({
                    "title": "Validation Error",
                    "value": f"`{validation_error}`",
                    "short": False
                })
        
        # Add standard fields
        fields.extend([
            {
                "title": "Subject",
                "value": cert_info.get('subject', 'Unknown'),
                "short": False
            },
            {
                "title": "Issuer",
                "value": cert_info.get('issuer', 'Unknown'),
                "short": False
            },
            {
                "title": "Expires",
                "value": expiry_date,
                "short": True
            },
            {
                "title": "Owner",
                "value": endpoint.get('owner', 'Unassigned'),
                "short": True
            },
            {
                "title": "Criticality",
                "value": endpoint.get('criticality', 'medium').upper(),
                "short": True
            }
        ])
        
        # Add trust status
        trust_status = "✅ Trusted CA" if is_trusted else "❌ Untrusted"
        if is_self_signed:
            trust_status = "⛔ Self-Signed"
        
        fields.append({
            "title": "Trust Status",
            "value": trust_status,
            "short": True
        })
        
        # Add chain length if available
        chain_length = cert_info.get('chain_length', 0)
        if chain_length > 0:
            fields.append({
                "title": "Chain Length",
                "value": str(chain_length),
                "short": True
            })
        
        fields.append({
            "title": "Fingerprint",
            "value": f"`{cert_info.get('fingerprint', 'Unknown')[:16]}...`",
            "short": True
        })
        
        # Build message text (Mattermost-compatible markdown)
        message_lines = [header_text, ""]

        for field in fields:
            if field.get("short"):
                message_lines.append(f"**{field['title']}:** {field['value']}")
            else:
                message_lines.append(f"**{field['title']}:**")
                message_lines.append(field['value'])
                message_lines.append("")

        message_lines.append("---")
        message_lines.append("_Certificate Guardian_")

        # Build payload (simple Mattermost format)
        payload = {
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "text": "\n".join(message_lines)
        }
        
        target_url = webhook_url or self.webhook_url
        try:
            response = requests.post(
                target_url,
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                logger.info(f"Sent {level} notification for {endpoint['host']}:{endpoint['port']}")
                return True
            else:
                logger.error(f"Failed to send notification: {response.status_code} - {response.text}")
                return False

        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending notification to Mattermost: {e}")
            return False
    
    def send_daily_summary(self, expiring_certs: List[Dict]) -> bool:
        """
        Send daily summary of expiring certificates
        
        Args:
            expiring_certs: List of expiring certificate information
            
        Returns:
            True if notification sent successfully
        """
        if not expiring_certs:
            return True
        
        # Group by urgency
        emergency = [c for c in expiring_certs if c['days_until_expiry'] <= 1]
        critical = [c for c in expiring_certs if 1 < c['days_until_expiry'] <= 7]
        warning = [c for c in expiring_certs if 7 < c['days_until_expiry'] <= 30]
        info = [c for c in expiring_certs if c['days_until_expiry'] > 30]
        
        # Build summary text
        summary_parts = []
        
        if emergency:
            summary_parts.append(f"🚨 **{len(emergency)} certificates expiring within 24 hours!**")
        if critical:
            summary_parts.append(f"⚠️ **{len(critical)} certificates expiring within 7 days**")
        if warning:
            summary_parts.append(f"⚠️ {len(warning)} certificates expiring within 30 days")
        if info:
            summary_parts.append(f"ℹ️ {len(info)} certificates expiring within 90 days")
        
        summary_text = "\n".join(summary_parts)
        
        # Build attachment with top 10 most urgent
        top_certs = sorted(expiring_certs, key=lambda x: x['days_until_expiry'])[:10]
        
        fields = []
        for cert in top_certs:
            days = int(cert['days_until_expiry'])
            fields.append({
                "title": f"{cert['host']}:{cert['port']}",
                "value": f"Expires in **{days} days** - {cert['subject'][:50]}...",
                "short": False
            })
        
        # Build message text
        message_lines = [
            "📊 **Daily Certificate Expiry Summary**",
            "",
            summary_text,
            "",
            "### Top 10 Most Urgent Certificates",
            ""
        ]

        for field in fields:
            message_lines.append(f"- **{field['title']}**: {field['value']}")

        message_lines.append("")
        message_lines.append("---")
        message_lines.append("_Certificate Guardian - Daily Summary_")

        payload = {
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "text": "\n".join(message_lines)
        }
        
        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Sent daily summary with {len(expiring_certs)} certificates")
                return True
            else:
                logger.error(f"Failed to send summary: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending summary to Mattermost: {e}")
            return False
    
    def send_security_alert(self, untrusted_certs: List[Dict]) -> bool:
        """
        Send security alert for untrusted or self-signed certificates
        
        Args:
            untrusted_certs: List of untrusted certificate information
            
        Returns:
            True if notification sent successfully
        """
        if not untrusted_certs:
            return True
        
        # Count by type
        self_signed = [c for c in untrusted_certs if c['is_self_signed']]
        untrusted = [c for c in untrusted_certs if not c['is_trusted_ca'] and not c['is_self_signed']]
        
        # Build summary
        summary_parts = []
        if self_signed:
            summary_parts.append(f"🔴 **{len(self_signed)} SELF-SIGNED certificates detected**")
        if untrusted:
            summary_parts.append(f"⚠️ **{len(untrusted)} certificates from UNTRUSTED CAs**")
        
        summary_text = "\n".join(summary_parts)
        
        # Build list of affected endpoints
        fields = []
        for cert in untrusted_certs[:10]:  # Limit to 10
            status = "⛔ SELF-SIGNED" if cert['is_self_signed'] else "❌ UNTRUSTED CA"
            
            value_parts = [
                f"**Status:** {status}",
                f"**Subject:** {cert['subject'][:60]}...",
                f"**Issuer:** {cert['issuer'][:60]}..."
            ]
            
            if cert.get('validation_error'):
                value_parts.append(f"**Error:** `{cert['validation_error'][:80]}...`")
            
            fields.append({
                "title": f"{cert['host']}:{cert['port']} ({cert['criticality'].upper()})",
                "value": "\n".join(value_parts),
                "short": False
            })
        
        if len(untrusted_certs) > 10:
            fields.append({
                "title": "Additional Issues",
                "value": f"... and {len(untrusted_certs) - 10} more certificates with trust issues",
                "short": False
            })
        
        # Build message text
        message_lines = [
            "🔐 **Security Alert: Certificate Trust Issues Detected**",
            "",
            summary_text,
            "",
            "### Affected Endpoints",
            ""
        ]

        for field in fields:
            message_lines.append(f"**{field['title']}**")
            message_lines.append(field['value'])
            message_lines.append("")

        message_lines.append("---")
        message_lines.append("_Certificate Guardian - Security Check_")

        payload = {
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "text": "\n".join(message_lines)
        }
        
        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Sent security alert for {len(untrusted_certs)} untrusted certificates")
                return True
            else:
                logger.error(f"Failed to send security alert: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending security alert to Mattermost: {e}")
            return False
    
    def test_connection(self) -> bool:
        """Test Mattermost webhook connection"""
        payload = {
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "text": "✅ Certificate Guardian is now monitoring your certificates!",
        }
        
        try:
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            return response.status_code == 200
        except:
            return False
