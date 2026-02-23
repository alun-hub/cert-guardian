"""
OIDC / SAML Authentication Security Scanner

Passively checks:
  - OIDC discovery document (/.well-known/openid-configuration)
  - SAML metadata (common paths)

No credentials required — all checks use public endpoints.
"""
import base64
import json
import logging
import ssl
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

logger = logging.getLogger(__name__)

OIDC_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

SAML_PATHS = [
    "/saml/metadata",
    "/saml2/metadata",
    "/saml/metadata.xml",
    "/saml2/metadata.xml",
    "/FederationMetadata/2007-06/FederationMetadata.xml",
    "/Shibboleth.sso/Metadata",
    "/.well-known/saml-metadata",
]

SAML_MD_NS  = "urn:oasis:names:tc:SAML:2.0:metadata"
XMLDSIG_NS  = "http://www.w3.org/2000/09/xmldsig#"


@dataclass
class OIDCConfig:
    found: bool = False
    issuer: Optional[str] = None
    response_types_supported: List[str] = field(default_factory=list)
    grant_types_supported: List[str] = field(default_factory=list)
    id_token_signing_alg_values_supported: List[str] = field(default_factory=list)
    code_challenge_methods_supported: List[str] = field(default_factory=list)
    token_endpoint_auth_methods_supported: List[str] = field(default_factory=list)


@dataclass
class SAMLConfig:
    found: bool = False
    metadata_url: Optional[str] = None
    has_signing_cert: bool = False
    signing_cert_not_after: Optional[str] = None  # ISO-8601, nearest-expiring


class OIDCScanner:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def scan(self, host: str, port: int):
        """Return (OIDCConfig, SAMLConfig)."""
        oidc = self._scan_oidc(host, port)
        saml = self._scan_saml(host, port)
        return oidc, saml

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _base_url(self, host: str, port: int) -> str:
        return f"https://{host}" if port == 443 else f"https://{host}:{port}"

    def _fetch(self, url: str) -> Optional[bytes]:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "CertGuardian-AuthScanner/1.0"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                if resp.status == 200:
                    return resp.read(256 * 1024)  # cap at 256 KB
        except Exception as exc:
            logger.debug("Fetch failed for %s: %s", url, exc)
        return None

    def _scan_oidc(self, host: str, port: int) -> OIDCConfig:
        base = self._base_url(host, port)
        for path in OIDC_PATHS:
            data = self._fetch(base + path)
            if data is None:
                continue
            try:
                doc = json.loads(data)
                if not isinstance(doc, dict) or "issuer" not in doc:
                    continue
                return OIDCConfig(
                    found=True,
                    issuer=doc.get("issuer"),
                    response_types_supported=doc.get("response_types_supported") or [],
                    grant_types_supported=doc.get("grant_types_supported") or [],
                    id_token_signing_alg_values_supported=doc.get("id_token_signing_alg_values_supported") or [],
                    code_challenge_methods_supported=doc.get("code_challenge_methods_supported") or [],
                    token_endpoint_auth_methods_supported=doc.get("token_endpoint_auth_methods_supported") or [],
                )
            except Exception as exc:
                logger.debug("OIDC parse error at %s%s: %s", base, path, exc)
        return OIDCConfig(found=False)

    def _scan_saml(self, host: str, port: int) -> SAMLConfig:
        base = self._base_url(host, port)
        for path in SAML_PATHS:
            data = self._fetch(base + path)
            if data is None:
                continue
            try:
                root = ET.fromstring(data)
            except ET.ParseError:
                continue

            # Must look like SAML metadata
            if "EntityDescriptor" not in root.tag and "EntitiesDescriptor" not in root.tag:
                continue

            saml = SAMLConfig(found=True, metadata_url=path)
            earliest: Optional[datetime] = None

            for kd in root.iter(f"{{{SAML_MD_NS}}}KeyDescriptor"):
                # use defaults to "signing" when attribute absent
                if kd.get("use", "signing") != "signing":
                    continue
                for cert_el in kd.iter(f"{{{XMLDSIG_NS}}}X509Certificate"):
                    b64_text = (cert_el.text or "").strip().replace("\n", "").replace("\r", "").replace(" ", "")
                    if not b64_text:
                        continue
                    saml.has_signing_cert = True
                    not_after = _cert_not_after(b64_text)
                    if not_after and (earliest is None or not_after < earliest):
                        earliest = not_after

            if earliest:
                saml.signing_cert_not_after = earliest.strftime("%Y-%m-%dT%H:%M:%S")
            return saml

        return SAMLConfig(found=False)


def _cert_not_after(b64_der: str) -> Optional[datetime]:
    """Parse a base64-DER certificate and return its not_after as naive UTC datetime."""
    try:
        from cryptography import x509 as cx509
        from cryptography.hazmat.backends import default_backend

        der = base64.b64decode(b64_der)
        cert = cx509.load_der_x509_certificate(der, default_backend())
        # cryptography >= 42 uses not_valid_after_utc (timezone-aware)
        # older versions use not_valid_after (naive UTC)
        try:
            dt = cert.not_valid_after_utc.replace(tzinfo=None)
        except AttributeError:
            dt = cert.not_valid_after  # naive UTC
        return dt
    except Exception as exc:
        logger.debug("Failed to parse SAML cert: %s", exc)
        return None
