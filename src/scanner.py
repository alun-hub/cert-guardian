#!/usr/bin/env python3
"""
TLS Certificate Scanner
"""
import ssl
import socket
import hashlib
from datetime import datetime
from typing import Optional, Dict, List
from dataclasses import dataclass
import logging

try:
    import certifi
    CA_FILE = certifi.where()
except ImportError:
    CA_FILE = None

# For parsing DER certificates
from cryptography import x509
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


@dataclass
class CertificateInfo:
    """Certificate information"""
    fingerprint: str
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    serial_number: str
    san_list: List[str]
    is_self_signed: bool
    is_trusted_ca: bool
    validation_error: Optional[str]
    chain_length: int


class TLSScanner:
    def __init__(self, timeout: int = 10, custom_ca_pems: List[str] = None):
        self.timeout = timeout
        self.custom_ca_pems = custom_ca_pems or []
        self._custom_ca_file = None

    def set_custom_cas(self, ca_pems: List[str]):
        """Update custom CA certificates"""
        self.custom_ca_pems = ca_pems
        self._custom_ca_file = None  # Reset cached file

    def _get_ca_context(self) -> ssl.SSLContext:
        """Create SSL context with system + custom CAs"""
        import tempfile
        import os

        context = ssl.create_default_context(cafile=CA_FILE)

        # Add custom CAs if any
        if self.custom_ca_pems:
            # Create temp file with all CAs
            if not self._custom_ca_file or not os.path.exists(self._custom_ca_file):
                fd, self._custom_ca_file = tempfile.mkstemp(suffix='.pem')
                with os.fdopen(fd, 'w') as f:
                    # First add system CAs
                    if CA_FILE:
                        with open(CA_FILE, 'r') as system_cas:
                            f.write(system_cas.read())
                    # Then add custom CAs
                    for pem in self.custom_ca_pems:
                        f.write('\n')
                        f.write(pem)

            context = ssl.create_default_context(cafile=self._custom_ca_file)

        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def scan_endpoint(self, host: str, port: int = 443) -> Optional[CertificateInfo]:
        """
        Scan a TLS endpoint and extract certificate information

        Args:
            host: Hostname or IP address
            port: Port number (default 443)

        Returns:
            CertificateInfo object or None if scan failed
        """
        try:
            logger.info(f"Scanning {host}:{port}")

            # First, try with verification to check if cert is trusted
            is_trusted = False
            validation_error = None

            try:
                # Create SSL context with verification enabled (includes custom CAs)
                verify_context = self._get_ca_context()

                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with verify_context.wrap_socket(sock, server_hostname=host) as secure_sock:
                        # If we get here, cert is trusted
                        is_trusted = True
                        logger.info(f"Certificate for {host}:{port} is trusted")
            except ssl.SSLCertVerificationError as e:
                is_trusted = False
                validation_error = str(e.verify_message if hasattr(e, 'verify_message') else e)
                logger.warning(f"Certificate verification failed for {host}:{port}: {validation_error}")
            except ssl.SSLError as e:
                is_trusted = False
                validation_error = f"SSL Error: {str(e)}"
                logger.warning(f"SSL error for {host}:{port}: {validation_error}")
            except Exception as e:
                is_trusted = False
                validation_error = f"Verification error: {str(e)}"
                logger.warning(f"Could not verify {host}:{port}: {validation_error}")

            # Now get certificate details without verification
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Connect and get certificate
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                    # Get certificate in DER format
                    cert_der = secure_sock.getpeercert(binary_form=True)

                    if not cert_der:
                        logger.error(f"Failed to get certificate from {host}:{port}")
                        return None

                    # Parse certificate using cryptography library
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())

                    # Calculate fingerprint (SHA256)
                    fingerprint = hashlib.sha256(cert_der).hexdigest()

                    # Extract subject
                    subject = self._extract_x509_name(cert.subject)

                    # Extract issuer
                    issuer = self._extract_x509_name(cert.issuer)

                    # Check if self-signed (subject == issuer)
                    is_self_signed = (subject == issuer)
                    if is_self_signed:
                        logger.warning(f"Certificate for {host}:{port} is SELF-SIGNED")
                        if not validation_error:
                            validation_error = "Self-signed certificate"

                    # Extract validity dates
                    not_before = cert.not_valid_before_utc.replace(tzinfo=None)
                    not_after = cert.not_valid_after_utc.replace(tzinfo=None)

                    # Extract serial number
                    serial_number = format(cert.serial_number, 'x').upper()

                    # Extract SAN (Subject Alternative Names)
                    san_list = []
                    try:
                        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        for name in san_ext.value:
                            if isinstance(name, x509.DNSName):
                                san_list.append(name.value)
                            elif isinstance(name, x509.IPAddress):
                                san_list.append(str(name.value))
                    except x509.ExtensionNotFound:
                        pass

                    cert_info = CertificateInfo(
                        fingerprint=fingerprint,
                        subject=subject,
                        issuer=issuer,
                        not_before=not_before,
                        not_after=not_after,
                        serial_number=serial_number,
                        san_list=san_list,
                        is_self_signed=is_self_signed,
                        is_trusted_ca=is_trusted,
                        validation_error=validation_error,
                        chain_length=1 if is_self_signed else 0
                    )

                    status_msg = f"Successfully scanned {host}:{port} - expires {not_after}"
                    if is_self_signed:
                        status_msg += " [SELF-SIGNED]"
                    if not is_trusted:
                        status_msg += " [UNTRUSTED]"
                    logger.info(status_msg)

                    return cert_info

        except socket.timeout:
            logger.error(f"Timeout connecting to {host}:{port}")
            return None
        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for {host}: {e}")
            return None
        except ssl.SSLError as e:
            logger.error(f"SSL error connecting to {host}:{port}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error scanning {host}:{port}: {e}")
            return None
    
    def _extract_x509_name(self, name: x509.Name) -> str:
        """
        Extract Distinguished Name from x509.Name object

        Args:
            name: x509.Name object from cryptography library

        Returns:
            Formatted DN string
        """
        dn_parts = []
        for attr in name:
            dn_parts.append(f"{attr.oid._name}={attr.value}")
        return ", ".join(dn_parts)
    
    def get_days_until_expiry(self, not_after: datetime) -> float:
        """Calculate days until certificate expires"""
        delta = not_after - datetime.utcnow()
        return delta.total_seconds() / 86400
