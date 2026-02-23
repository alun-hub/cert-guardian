#!/usr/bin/env python3
"""
HTTP Security Header Scanner

Analyzes HTTP response headers for security best practices:
HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
Permissions-Policy, X-XSS-Protection.

Also checks:
- HTTP → HTTPS redirect (port 80 redirects to HTTPS)
- Cookie security flags (Secure, HttpOnly, SameSite)
"""
import re
import socket
import ssl
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from urllib.request import Request, urlopen
from urllib.error import URLError
from urllib.parse import urlparse
import http.client

logger = logging.getLogger(__name__)

GRADE_THRESHOLDS = [
    (90, "A"),
    (70, "B"),
    (50, "C"),
    (30, "D"),
    (0,  "F"),
]


@dataclass
class CookieIssue:
    name: str
    missing_flags: List[str]   # e.g. ["Secure", "HttpOnly", "SameSite"]


@dataclass
class HeaderResult:
    header_score: int                       # 0-100
    header_grade: str                       # A/B/C/D/F
    headers_present: List[str] = field(default_factory=list)
    headers_missing: List[str] = field(default_factory=list)
    hsts_max_age: Optional[int] = None
    csp_has_unsafe_inline: Optional[bool] = None
    recommendations: List[str] = field(default_factory=list)
    # HTTP → HTTPS redirect
    redirects_to_https: Optional[bool] = None
    redirect_status_code: Optional[int] = None
    # Cookie security flags
    cookie_issues: List[CookieIssue] = field(default_factory=list)
    # Additional checks
    server_header: Optional[str] = None       # Raw value if version disclosed
    cors_wildcard: Optional[bool] = None      # True if ACAO: *
    trace_enabled: Optional[bool] = None      # True if TRACE returns 200


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

        headers, set_cookies = self._fetch_headers(url)
        if headers is None:
            return None

        result = self._analyse(headers, set_cookies)

        # HTTP → HTTPS redirect check (only relevant for standard HTTPS on 443)
        if port == 443:
            redirects, status = self._check_http_redirect(host)
            result.redirects_to_https = redirects
            result.redirect_status_code = status

        # TRACE method check
        result.trace_enabled = self._check_trace(host, port)

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_http_service(self, host: str, port: int) -> bool:
        """Quick probe to check if the TLS endpoint speaks HTTP."""
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

    def _fetch_headers(self, url: str):
        """GET *url* and return (headers_dict, set_cookie_list), or (None, []) on error.

        Collects all Set-Cookie headers separately to preserve duplicates.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = Request(url, method="GET")
        req.add_header("User-Agent", "CertGuardian-HeaderScanner/1.0")

        try:
            with urlopen(req, timeout=self.timeout, context=ctx) as resp:
                headers = {}
                set_cookies = []
                for k, v in resp.headers.items():
                    k_lower = k.lower()
                    if k_lower == "set-cookie":
                        set_cookies.append(v)
                    else:
                        headers[k_lower] = v
                return headers, set_cookies
        except URLError as exc:
            logger.warning("HTTP header scan failed for %s: %s", url, exc)
            return None, []
        except Exception as exc:
            logger.warning("HTTP header scan error for %s: %s", url, exc)
            return None, []

    def _check_http_redirect(self, host: str) -> tuple:
        """Check if http://host:80/ redirects to HTTPS.

        Returns (redirects_to_https: bool, status_code: int | None).
        """
        try:
            conn = http.client.HTTPConnection(host, 80, timeout=5)
            conn.request("HEAD", "/", headers={"Host": host,
                                                "User-Agent": "CertGuardian-HeaderScanner/1.0"})
            resp = conn.getresponse()
            status = resp.status
            location = resp.getheader("Location", "")
            conn.close()

            if status in (301, 302, 307, 308):
                redirects = location.lower().startswith("https://")
                return redirects, status
            else:
                # Port 80 responds but doesn't redirect
                return False, status
        except ConnectionRefusedError:
            # Port 80 not open — can't determine redirect
            return None, None
        except Exception as exc:
            logger.debug("HTTP redirect check failed for %s: %s", host, exc)
            return None, None

    def _check_trace(self, host: str, port: int) -> Optional[bool]:
        """Send HTTP TRACE request over TLS. Return True if server responds 200."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            conn = http.client.HTTPSConnection(host, port, timeout=5, context=ctx)
            conn.request("TRACE", "/", headers={
                "Host": host,
                "User-Agent": "CertGuardian-SecurityScanner/1.0",
            })
            resp = conn.getresponse()
            enabled = resp.status == 200
            conn.close()
            return enabled
        except Exception as exc:
            logger.debug("TRACE check failed for %s:%d: %s", host, port, exc)
            return None

    def _parse_cookies(self, set_cookies: List[str]) -> List[CookieIssue]:
        """Parse Set-Cookie headers and report missing security flags."""
        issues = []
        for raw in set_cookies:
            parts = [p.strip() for p in raw.split(";")]
            if not parts:
                continue

            # First part is name=value
            name = parts[0].split("=", 1)[0].strip() or "<unnamed>"
            flags_lower = {p.lower() for p in parts[1:]}

            missing = []
            if "secure" not in flags_lower:
                missing.append("Secure")
            if "httponly" not in flags_lower:
                missing.append("HttpOnly")
            if not any(f.startswith("samesite") for f in flags_lower):
                missing.append("SameSite")

            if missing:
                issues.append(CookieIssue(name=name, missing_flags=missing))

        return issues

    def _analyse(self, headers: dict, set_cookies: List[str]) -> HeaderResult:
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

        score = min(score, 100)

        cookie_issues = self._parse_cookies(set_cookies)

        # Server version disclosure — Server or X-Powered-By containing word/digit
        server_raw = headers.get("server") or headers.get("x-powered-by")
        server_header = server_raw if (server_raw and re.search(r'[\w.-]+/\d', server_raw)) else None

        # CORS wildcard
        acao = headers.get("access-control-allow-origin")
        cors_wildcard = (acao.strip() == "*") if acao is not None else None

        return HeaderResult(
            header_score=score,
            header_grade=_score_to_grade(score),
            headers_present=present,
            headers_missing=missing,
            hsts_max_age=hsts_max_age,
            csp_has_unsafe_inline=csp_has_unsafe_inline,
            recommendations=recommendations,
            cookie_issues=cookie_issues,
            server_header=server_header,
            cors_wildcard=cors_wildcard,
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
