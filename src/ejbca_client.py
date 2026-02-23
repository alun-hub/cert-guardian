#!/usr/bin/env python3
"""
EJBCA REST API client for Certificate Guardian.
Fetches issued certificates directly from an EJBCA CA server.
"""
import base64
import logging
import tempfile
import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


@dataclass
class EjbcaCertificate:
    fingerprint: str
    subject: str
    issuer: str
    not_before: str
    not_after: str
    serial_number: str
    san_list: List[str]
    key_type: Optional[str]
    key_size: Optional[int]
    signature_algorithm: Optional[str]
    is_self_signed: bool
    weak_signature: bool
    # EJBCA metadata
    ca_dn: str
    username: Optional[str]
    end_entity_profile: Optional[str]
    certificate_profile: Optional[str]
    ejbca_status: str


class EjbcaClient:
    def __init__(self, base_url: str,
                 client_cert_pem: str = None,
                 client_key_pem: str = None,
                 ca_pem: str = None,
                 verify_tls: bool = True,
                 api_key: str = None,
                 timeout: int = 30):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self._tmpfiles: List[str] = []

        self.session = requests.Session()

        # mTLS authentication
        if client_cert_pem and client_key_pem:
            cert_path = self._write_tmpfile(client_cert_pem, suffix='.pem')
            key_path = self._write_tmpfile(client_key_pem, suffix='.pem')
            self.session.cert = (cert_path, key_path)

        # Custom CA verification
        if ca_pem:
            ca_path = self._write_tmpfile(ca_pem, suffix='.pem')
            self.session.verify = ca_path
        else:
            self.session.verify = verify_tls

        # API key authentication (Bearer token)
        if api_key:
            self.session.headers.update({'Authorization': f'Bearer {api_key}'})

        self.session.headers.update({'Accept': 'application/json',
                                     'Content-Type': 'application/json'})

    def _write_tmpfile(self, content: str, suffix: str = '.pem') -> str:
        """Write PEM string to a temporary file and track for cleanup."""
        fd, path = tempfile.mkstemp(suffix=suffix)
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(content)
        except Exception:
            os.close(fd)
            raise
        self._tmpfiles.append(path)
        return path

    def __del__(self):
        for path in self._tmpfiles:
            try:
                os.unlink(path)
            except Exception:
                pass

    def test_connection(self) -> Tuple[bool, str]:
        """Test EJBCA connectivity by fetching the CA list.

        Returns (True, message) on success or (False, error_message) on failure.
        """
        try:
            cas = self.get_ca_list()
            n = len(cas)
            return True, f"{n} CA{'s' if n != 1 else ''} found"
        except requests.exceptions.SSLError as e:
            return False, f"TLS error: {e}"
        except requests.exceptions.ConnectionError as e:
            return False, f"Connection failed: {e}"
        except requests.exceptions.Timeout:
            return False, "Connection timed out"
        except Exception as e:
            return False, str(e)

    def get_ca_list(self) -> List[dict]:
        """Fetch the list of CAs from EJBCA."""
        url = f"{self.base_url}/v1/ca"
        resp = self.session.get(url, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        # Response is either {"certificate_authorities": [...]} or a list directly
        if isinstance(data, list):
            return data
        return data.get('certificate_authorities', data.get('cas', []))

    def fetch_certificates(self, ca_dn_filter: str = None,
                           max_total: int = 10_000) -> List[EjbcaCertificate]:
        """Fetch all active certificates from EJBCA with pagination.

        Args:
            ca_dn_filter: Comma-separated CA DNs to filter by (empty = all CAs).
            max_total: Maximum total certificates to retrieve.

        Returns list of EjbcaCertificate objects.
        """
        page_size = min(1000, max_total)
        ca_filters = [dn.strip() for dn in ca_dn_filter.split(',') if dn.strip()] \
            if ca_dn_filter else []

        all_certs: List[EjbcaCertificate] = []
        url = f"{self.base_url}/v1/search/certificates"

        if ca_filters:
            # Fetch per CA DN
            for ca_dn in ca_filters:
                all_certs.extend(self._fetch_pages(url, page_size, max_total, ca_dn))
        else:
            all_certs.extend(self._fetch_pages(url, page_size, max_total, None))

        return all_certs

    def _fetch_pages(self, url: str, page_size: int, max_total: int,
                     ca_dn: Optional[str]) -> List[EjbcaCertificate]:
        """Paginate through all result pages for a given (optional) CA filter."""
        results: List[EjbcaCertificate] = []
        current_page = 0

        while len(results) < max_total:
            criteria = [
                {"property": "STATUS", "value": "CERT_ACTIVE", "operation": "EQUAL"}
            ]
            if ca_dn:
                criteria.append(
                    {"property": "ISSUER_DN", "value": ca_dn, "operation": "EQUAL"}
                )

            body = {
                "max_number_of_results": page_size,
                "current_page": current_page,
                "criteria": criteria,
            }

            resp = self.session.post(url, json=body, timeout=60)
            resp.raise_for_status()
            data = resp.json()

            raw_certs = data.get('certificates', [])
            for item in raw_certs:
                try:
                    cert = self._parse_item(item)
                    if cert:
                        results.append(cert)
                except Exception as e:
                    fp = item.get('fingerprint', '?')
                    logger.warning(f"Failed to parse EJBCA cert {fp}: {e}")

            # Check for more pages
            more = data.get('more_results')
            if more is None:
                # Some EJBCA versions nest pagination info
                summary = data.get('pagination_summary', {})
                more = summary.get('response_more_results', False)

            if not more or len(raw_certs) == 0:
                break
            current_page += 1

        return results

    def _parse_item(self, item: dict) -> Optional[EjbcaCertificate]:
        """Parse one EJBCA search result item into an EjbcaCertificate."""
        der_b64 = item.get('certificate')
        if not der_b64:
            return None

        der_bytes = base64.b64decode(der_b64)
        parsed = self._parse_x509(der_bytes)

        # EJBCA metadata — field names vary by version
        ca_dn = (item.get('ca_dn') or item.get('issuer_dn') or parsed['issuer'])
        username = item.get('username')
        end_entity_profile = (item.get('end_entity_profile_name') or
                               item.get('end_entity_profile'))
        certificate_profile = (item.get('certificate_profile_name') or
                                item.get('certificate_profile'))
        ejbca_status = item.get('status', 'CERT_ACTIVE')

        return EjbcaCertificate(
            fingerprint=parsed['fingerprint'],
            subject=parsed['subject'],
            issuer=parsed['issuer'],
            not_before=parsed['not_before'],
            not_after=parsed['not_after'],
            serial_number=parsed['serial_number'],
            san_list=parsed['san_list'],
            key_type=parsed['key_type'],
            key_size=parsed['key_size'],
            signature_algorithm=parsed['signature_algorithm'],
            is_self_signed=parsed['is_self_signed'],
            weak_signature=parsed['weak_signature'],
            ca_dn=ca_dn,
            username=username,
            end_entity_profile=end_entity_profile,
            certificate_profile=certificate_profile,
            ejbca_status=ejbca_status,
        )

    def _parse_x509(self, der_bytes: bytes) -> dict:
        """Parse a DER-encoded X.509 certificate into a metadata dict."""
        cert = x509.load_der_x509_certificate(der_bytes, default_backend())

        # Subject and issuer as RFC 4514 strings
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()

        # SHA-256 fingerprint
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()

        # Validity dates — use timezone-aware attributes when available
        try:
            not_before = cert.not_valid_before_utc.isoformat()
            not_after = cert.not_valid_after_utc.isoformat()
        except AttributeError:
            # Fallback for older cryptography versions
            from datetime import timezone as _tz
            not_before = cert.not_valid_before.replace(
                tzinfo=_tz.utc).isoformat()
            not_after = cert.not_valid_after.replace(
                tzinfo=_tz.utc).isoformat()

        serial_number = format(cert.serial_number, 'x')

        # Subject Alternative Names
        san_list: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_list.append(f"DNS:{name.value}")
                elif isinstance(name, x509.IPAddress):
                    san_list.append(f"IP:{name.value}")
                elif isinstance(name, x509.RFC822Name):
                    san_list.append(f"email:{name.value}")
                elif isinstance(name, x509.UniformResourceIdentifier):
                    san_list.append(f"URI:{name.value}")
        except x509.ExtensionNotFound:
            pass

        # Public key info
        pub_key = cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            key_type = 'RSA'
            key_size = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_type = 'EC'
            key_size = pub_key.key_size
        elif isinstance(pub_key, dsa.DSAPublicKey):
            key_type = 'DSA'
            key_size = pub_key.key_size
        elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key_type = type(pub_key).__name__.replace('PublicKey', '')
            key_size = None
        else:
            key_type = type(pub_key).__name__
            key_size = None

        # Signature algorithm
        try:
            hash_alg = cert.signature_hash_algorithm
            sig_alg = hash_alg.name if hash_alg else 'unknown'
        except Exception:
            sig_alg = 'unknown'

        is_self_signed = (cert.subject == cert.issuer)
        sig_alg_lower = sig_alg.lower()
        weak_signature = 'sha1' in sig_alg_lower or 'md5' in sig_alg_lower

        return {
            'fingerprint': fingerprint,
            'subject': subject,
            'issuer': issuer,
            'not_before': not_before,
            'not_after': not_after,
            'serial_number': serial_number,
            'san_list': san_list,
            'key_type': key_type,
            'key_size': key_size,
            'signature_algorithm': sig_alg,
            'is_self_signed': is_self_signed,
            'weak_signature': weak_signature,
        }
