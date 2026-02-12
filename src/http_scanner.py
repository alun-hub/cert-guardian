#!/usr/bin/env python3
"""
HTTP Security Header Scanner

Analyzes HTTP response headers for security best practices:
HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
Permissions-Policy, X-XSS-Protection.
"""
import socket
import ssl
import logging
from dataclasses import dataclass, field
from typing import Optional, List
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)

GRADE_THRESHOLDS = [
    (90, "A"),
    (70, "B"),
    (50, "C"),
    (30, "D"),
    (0,  "F"),
]


@dataclass
class HeaderResult:
    header_score: int                       # 0-100
    header_grade: str                       # A/B/C/D/F
    headers_present: List[str] = field(default_factory=list)
    headers_missing: List[str] = field(default_factory=list)
    hsts_max_age: Optional[int] = None
    csp_has_unsafe_inline: Optional[bool] = None
    recommendations: List[str] = field(default_factory=list)


def _score_to_grade(score: int) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


class HTTPHeaderScanner:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def scan_headers(self, host: str, port: int = 443) -> Optional[HeaderResult]:
        """Perform HTTPS request and analyse security headers.

        Returns HeaderResult or None on connection failure.
        Skips non-HTTP TLS services (LDAPS, IMAPS, etc.) via quick probe.
        """
        if not self._is_http_service(host, port):
            logger.info("Skipping HTTP header scan for %s:%d (not an HTTP service)", host, port)
            return None

        url = f"https://{host}:{port}/" if port != 443 else f"https://{host}/"

        headers = self._fetch_headers(url)
        if headers is None:
            return None

        return self._analyse(headers)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_http_service(self, host: str, port: int) -> bool:
        """Quick probe to check if the TLS endpoint speaks HTTP.

        Opens a TLS connection, sends a minimal HTTP HEAD request, and checks
        whether the first bytes of the response look like an HTTP status line.
        Uses a short 3-second timeout so non-HTTP services fail fast instead
        of blocking the scanner for the full request timeout.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        raw = None
        try:
            raw = socket.create_connection((host, port), timeout=3)
            conn = ctx.wrap_socket(raw, server_hostname=host)
            conn.settimeout(3)
            conn.sendall(
                f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
            )
            data = conn.recv(32)
            conn.close()
            return data.startswith(b"HTTP/")
        except Exception:
            return False
        finally:
            if raw is not None:
                try:
                    raw.close()
                except Exception:
                    pass

    def _fetch_headers(self, url: str) -> Optional[dict]:
        """GET *url* and return a lower-cased header dict, or None on error."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # We only care about HTTP headers

        req = Request(url, method="GET")
        req.add_header("User-Agent", "CertGuardian-HeaderScanner/1.0")

        try:
            with urlopen(req, timeout=self.timeout, context=ctx) as resp:
                return {k.lower(): v for k, v in resp.headers.items()}
        except URLError as exc:
            logger.warning("HTTP header scan failed for %s: %s", url, exc)
            return None
        except Exception as exc:
            logger.warning("HTTP header scan error for %s: %s", url, exc)
            return None

    def _analyse(self, headers: dict) -> HeaderResult:
        score = 0
        present: List[str] = []
        missing: List[str] = []
        recommendations: List[str] = []
        hsts_max_age: Optional[int] = None
        csp_has_unsafe_inline: Optional[bool] = None

        # --- HSTS (max 30p) ---
        hsts = headers.get("strict-transport-security")
        if hsts:
            present.append("hsts")
            hsts_max_age = self._parse_max_age(hsts)
            if hsts_max_age is not None and hsts_max_age >= 31536000:
                score += 30
            else:
                score += 15
                recommendations.append(
                    "Set HSTS max-age to at least 31536000 (1 year)"
                )
        else:
            missing.append("hsts")
            recommendations.append(
                "Add Strict-Transport-Security header with max-age >= 1 year"
            )

        # --- CSP (max 25p) ---
        csp = headers.get("content-security-policy")
        if csp:
            present.append("csp")
            csp_lower = csp.lower()
            csp_has_unsafe_inline = "'unsafe-inline'" in csp_lower
            has_default_src = "default-src" in csp_lower
            has_script_src = "script-src" in csp_lower

            if (has_default_src or has_script_src) and not csp_has_unsafe_inline:
                score += 25
            else:
                score += 15
                if csp_has_unsafe_inline:
                    recommendations.append(
                        "Remove 'unsafe-inline' from Content-Security-Policy"
                    )
        else:
            missing.append("csp")
            csp_has_unsafe_inline = None
            recommendations.append(
                "Add Content-Security-Policy header to protect against XSS"
            )

        # --- X-Content-Type-Options (15p) ---
        xcto = headers.get("x-content-type-options")
        if xcto and "nosniff" in xcto.lower():
            present.append("x-content-type-options")
            score += 15
        else:
            missing.append("x-content-type-options")
            recommendations.append(
                "Add X-Content-Type-Options: nosniff header"
            )

        # --- X-Frame-Options (15p) ---
        xfo = headers.get("x-frame-options")
        if xfo and xfo.upper() in ("DENY", "SAMEORIGIN"):
            present.append("x-frame-options")
            score += 15
        else:
            missing.append("x-frame-options")
            recommendations.append(
                "Add X-Frame-Options: DENY or SAMEORIGIN header"
            )

        # --- Referrer-Policy (10p) ---
        rp = headers.get("referrer-policy")
        if rp:
            present.append("referrer-policy")
            score += 10
        else:
            missing.append("referrer-policy")
            recommendations.append("Add Referrer-Policy header")

        # --- Permissions-Policy (5p) ---
        pp = headers.get("permissions-policy")
        if pp:
            present.append("permissions-policy")
            score += 5
        else:
            missing.append("permissions-policy")
            recommendations.append("Add Permissions-Policy header")

        # --- X-XSS-Protection (informational, 0p) ---
        xxss = headers.get("x-xss-protection")
        if xxss:
            present.append("x-xss-protection")
        # Not added to missing — deprecated header, info only

        # Cap score at 100
        score = min(score, 100)

        return HeaderResult(
            header_score=score,
            header_grade=_score_to_grade(score),
            headers_present=present,
            headers_missing=missing,
            hsts_max_age=hsts_max_age,
            csp_has_unsafe_inline=csp_has_unsafe_inline,
            recommendations=recommendations,
        )

    @staticmethod
    def _parse_max_age(hsts_value: str) -> Optional[int]:
        """Extract max-age integer from HSTS header value."""
        for part in hsts_value.lower().split(";"):
            part = part.strip()
            if part.startswith("max-age"):
                try:
                    return int(part.split("=", 1)[1].strip())
                except (ValueError, IndexError):
                    return None
        return None
