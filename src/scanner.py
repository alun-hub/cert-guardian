#!/usr/bin/env python3
"""
TLS Certificate Scanner
"""
import ssl
import socket
import hashlib
import ipaddress
import re
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
        self._parsed_cas = None

    def set_custom_cas(self, ca_pems: List[str]):
        """Update custom CA certificates"""
        self.custom_ca_pems = ca_pems
        self._custom_ca_file = None
        self._parsed_cas = None

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

    def _get_known_certs(self) -> list:
        """Get parsed CA certificates (cached) for chain building"""
        if self._parsed_cas is not None:
            return self._parsed_cas

        certs = []
        for pem in self.custom_ca_pems:
            for block in re.finditer(
                r'(-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----)', pem
            ):
                try:
                    ca = x509.load_pem_x509_certificate(
                        block.group(1).encode(), default_backend()
                    )
                    certs.append(ca)
                except Exception:
                    continue

        if CA_FILE:
            try:
                with open(CA_FILE, 'r') as f:
                    system_pem = f.read()
                for block in re.finditer(
                    r'(-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----)',
                    system_pem
                ):
                    try:
                        ca = x509.load_pem_x509_certificate(
                            block.group(1).encode(), default_backend()
                        )
                        certs.append(ca)
                    except Exception:
                        continue
            except Exception:
                pass

        self._parsed_cas = certs
        return certs

    def _match_hostname(self, host: str, san_list: List[str], cn: Optional[str] = None) -> bool:
        """Check if hostname matches certificate SAN entries or CN (RFC 6125)"""
        # Per RFC 6125: if SAN is present, only check SAN, ignore CN
        names_to_check = san_list if san_list else ([cn] if cn else [])
        if not names_to_check:
            return False

        host_ip = None
        try:
            host_ip = ipaddress.ip_address(host)
        except ValueError:
            pass

        for name in names_to_check:
            if host_ip is not None:
                try:
                    if host_ip == ipaddress.ip_address(name):
                        return True
                except ValueError:
                    continue
            else:
                if self._dns_name_matches(host.lower(), name.lower()):
                    return True

        return False

    def _dns_name_matches(self, hostname: str, pattern: str) -> bool:
        """Match hostname against DNS pattern with wildcard support (RFC 6125)"""
        if hostname == pattern:
            return True

        # Wildcard matching: *.example.com
        if pattern.startswith('*.') and '.' in hostname:
            suffix = pattern[2:]
            if hostname.endswith('.' + suffix):
                prefix = hostname[:-(len(suffix) + 1)]
                # Wildcard matches exactly one label (no dots)
                if '.' not in prefix and len(prefix) > 0:
                    return True

        return False

    def _build_chain_info(self, leaf_cert) -> tuple:
        """Build certificate chain from known CAs and check expiry.

        Returns:
            (chain_length, chain_has_expiring) tuple
        """
        known_certs = self._get_known_certs()

        chain = [leaf_cert]
        current = leaf_cert

        if not known_certs:
            if current.subject == current.issuer:
                return (1, False)
            return (None, None)

        # Walk the chain upward (max 10 to prevent loops)
        for _ in range(10):
            if current.subject == current.issuer:
                break  # Self-signed root

            found = False
            for ca in known_certs:
                if ca.subject == current.issuer:
                    # Avoid adding the leaf cert itself
                    if ca.serial_number == current.serial_number:
                        continue
                    chain.append(ca)
                    current = ca
                    found = True
                    break

            if not found:
                break

        chain_length = len(chain)
        chain_has_expiring = False
        for c in chain[1:]:  # Skip leaf cert
            try:
                not_after = c.not_valid_after_utc.replace(tzinfo=None)
            except AttributeError:
                not_after = c.not_valid_after
            days = (not_after - datetime.utcnow()).days
            if days <= 30:
                chain_has_expiring = True
                break

        return (chain_length, chain_has_expiring)

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

                    # Hostname match (RFC 6125)
                    hostname_matches = None
                    try:
                        cn = None
                        try:
                            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                        except Exception:
                            cn = None
                        hostname_matches = self._match_hostname(host, san_list, cn)
                    except Exception:
                        hostname_matches = None

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

                    # Chain length + expiring intermediates
                    chain_length, chain_has_expiring = self._build_chain_info(cert)

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
