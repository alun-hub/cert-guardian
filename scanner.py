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
import certifi

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
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
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
            chain_length = 0
            
            try:
                # Create SSL context with verification enabled
                verify_context = ssl.create_default_context(cafile=certifi.where())
                verify_context.check_hostname = True
                verify_context.verify_mode = ssl.CERT_REQUIRED
                
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with verify_context.wrap_socket(sock, server_hostname=host) as secure_sock:
                        # If we get here, cert is trusted by system CA store
                        is_trusted = True
                        # Get certificate chain length
                        cert_chain = secure_sock.getpeercert_chain()
                        if cert_chain:
                            chain_length = len(cert_chain)
                        logger.info(f"Certificate for {host}:{port} is trusted (chain length: {chain_length})")
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
                    # Get certificate in dict format
                    cert_dict = secure_sock.getpeercert()
                    
                    if not cert_der or not cert_dict:
                        logger.error(f"Failed to get certificate from {host}:{port}")
                        return None
                    
                    # Calculate fingerprint (SHA256)
                    fingerprint = hashlib.sha256(cert_der).hexdigest()
                    
                    # Extract subject
                    subject = self._extract_dn(cert_dict.get('subject', []))
                    
                    # Extract issuer
                    issuer = self._extract_dn(cert_dict.get('issuer', []))
                    
                    # Check if self-signed (subject == issuer)
                    is_self_signed = (subject == issuer)
                    if is_self_signed:
                        logger.warning(f"Certificate for {host}:{port} is SELF-SIGNED")
                        if not validation_error:
                            validation_error = "Self-signed certificate"
                    
                    # Extract validity dates
                    not_before = datetime.strptime(
                        cert_dict['notBefore'], '%b %d %H:%M:%S %Y %Z'
                    )
                    not_after = datetime.strptime(
                        cert_dict['notAfter'], '%b %d %H:%M:%S %Y %Z'
                    )
                    
                    # Extract serial number
                    serial_number = cert_dict.get('serialNumber', '')
                    
                    # Extract SAN (Subject Alternative Names)
                    san_list = []
                    if 'subjectAltName' in cert_dict:
                        san_list = [name[1] for name in cert_dict['subjectAltName']]
                    
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
                        chain_length=chain_length
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
    
    def _extract_dn(self, dn_tuple_list: List) -> str:
        """
        Extract Distinguished Name from certificate tuple format
        
        Args:
            dn_tuple_list: List of tuples containing DN components
            
        Returns:
            Formatted DN string
        """
        if not dn_tuple_list:
            return ""
        
        dn_parts = []
        for rdn in dn_tuple_list:
            for name_type, value in rdn:
                dn_parts.append(f"{name_type}={value}")
        
        return ", ".join(dn_parts)
    
    def get_days_until_expiry(self, not_after: datetime) -> float:
        """Calculate days until certificate expires"""
        delta = not_after - datetime.utcnow()
        return delta.total_seconds() / 86400
