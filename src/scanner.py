#!/usr/bin/env python3
"""
TLS Certificate Scanner
"""
import ssl
import socket
import hashlib
import ipaddress
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
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

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
    key_type: Optional[str]
    key_size: Optional[int]
    signature_algorithm: Optional[str]
    is_self_signed: bool
    is_trusted_ca: bool
    validation_error: Optional[str]
    chain_length: int
    tls_version: Optional[str]
    cipher: Optional[str]
    hostname_matches: Optional[bool]
    ocsp_present: Optional[bool]
    crl_present: Optional[bool]
    eku_server_auth: Optional[bool]
    key_usage_digital_signature: Optional[bool]
    key_usage_key_encipherment: Optional[bool]
    chain_has_expiring: Optional[bool]
    weak_signature: Optional[bool]


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
                    tls_version = secure_sock.version()
                    cipher_info = secure_sock.cipher()
                    cipher = cipher_info[0] if cipher_info else None

                    # Get certificate in DER format
                    cert_der = secure_sock.getpeercert(binary_form=True)
                    cert_dict = secure_sock.getpeercert()

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

                    # Extract public key info
                    key_type = None
                    key_size = None
                    try:
                        public_key = cert.public_key()
                        key_size = getattr(public_key, "key_size", None)
                        if isinstance(public_key, rsa.RSAPublicKey):
                            key_type = "RSA"
                        elif isinstance(public_key, ec.EllipticCurvePublicKey):
                            key_type = "EC"
                        elif isinstance(public_key, dsa.DSAPublicKey):
                            key_type = "DSA"
                        elif isinstance(public_key, ed25519.Ed25519PublicKey):
                            key_type = "Ed25519"
                        elif isinstance(public_key, ed448.Ed448PublicKey):
                            key_type = "Ed448"
                        else:
                            key_type = public_key.__class__.__name__
                    except Exception:
                        key_type = None
                        key_size = None

                    # Extract signature algorithm
                    signature_algorithm = None
                    try:
                        signature_algorithm = cert.signature_algorithm_oid._name
                    except Exception:
                        signature_algorithm = None

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

                    # Hostname match (best-effort)
                    hostname_matches = None
                    try:
                        cn = None
                        try:
                            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                        except Exception:
                            cn = None

                        match_cert = {}
                        if cn:
                            match_cert["subject"] = ((("commonName", cn),),)

                        san_entries = []
                        for san in san_list:
                            try:
                                ipaddress.ip_address(san)
                                san_entries.append(("IP Address", san))
                            except ValueError:
                                san_entries.append(("DNS", san))
                        if san_entries:
                            match_cert["subjectAltName"] = san_entries

                        if match_cert:
                            ssl.match_hostname(match_cert, host)
                            hostname_matches = True
                        else:
                            hostname_matches = None
                    except Exception:
                        hostname_matches = False

                    # OCSP / CRL presence
                    ocsp_present = None
                    crl_present = None
                    try:
                        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
                        ocsp_present = any(
                            desc.access_method == x509.AuthorityInformationAccessOID.OCSP
                            for desc in aia.value
                        )
                    except x509.ExtensionNotFound:
                        ocsp_present = False
                    except Exception:
                        ocsp_present = None

                    try:
                        crl = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
                        crl_present = bool(crl.value)
                    except x509.ExtensionNotFound:
                        crl_present = False
                    except Exception:
                        crl_present = None

                    # EKU / Key Usage
                    eku_server_auth = None
                    try:
                        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
                        eku_server_auth = x509.ExtendedKeyUsageOID.SERVER_AUTH in eku.value
                    except x509.ExtensionNotFound:
                        eku_server_auth = False
                    except Exception:
                        eku_server_auth = None

                    key_usage_digital_signature = None
                    key_usage_key_encipherment = None
                    try:
                        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
                        key_usage_digital_signature = bool(ku.value.digital_signature)
                        key_usage_key_encipherment = bool(ku.value.key_encipherment)
                    except x509.ExtensionNotFound:
                        key_usage_digital_signature = False
                        key_usage_key_encipherment = False
                    except Exception:
                        key_usage_digital_signature = None
                        key_usage_key_encipherment = None

                    # Chain length + expiring intermediates (best-effort)
                    chain_length = None
                    chain_has_expiring = None
                    try:
                        chain = None
                        if hasattr(secure_sock, "get_verified_chain"):
                            chain = secure_sock.get_verified_chain()
                        elif hasattr(secure_sock, "getpeercertchain"):
                            chain = secure_sock.getpeercertchain()
                        if chain:
                            chain_length = len(chain)
                            chain_has_expiring = False
                            for cert_bytes in chain:
                                try:
                                    c = x509.load_der_x509_certificate(cert_bytes, default_backend())
                                    days = (c.not_valid_after_utc.replace(tzinfo=None) - datetime.utcnow()).days
                                    if days <= 30:
                                        chain_has_expiring = True
                                        break
                                except Exception:
                                    continue
                    except Exception:
                        chain_length = None
                        chain_has_expiring = None

                    weak_signature = None
                    if signature_algorithm:
                        algo = signature_algorithm.lower()
                        weak_signature = ("sha1" in algo) or ("md5" in algo)

                    cert_info = CertificateInfo(
                        fingerprint=fingerprint,
                        subject=subject,
                        issuer=issuer,
                        not_before=not_before,
                        not_after=not_after,
                        serial_number=serial_number,
                        san_list=san_list,
                        key_type=key_type,
                        key_size=key_size,
                        signature_algorithm=signature_algorithm,
                        is_self_signed=is_self_signed,
                        is_trusted_ca=is_trusted,
                        validation_error=validation_error,
                        chain_length=chain_length if chain_length is not None else (1 if is_self_signed else 0),
                        tls_version=tls_version,
                        cipher=cipher,
                        hostname_matches=hostname_matches,
                        ocsp_present=ocsp_present,
                        crl_present=crl_present,
                        eku_server_auth=eku_server_auth,
                        key_usage_digital_signature=key_usage_digital_signature,
                        key_usage_key_encipherment=key_usage_key_encipherment,
                        chain_has_expiring=chain_has_expiring,
                        weak_signature=weak_signature
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
