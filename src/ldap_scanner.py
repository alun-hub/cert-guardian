#!/usr/bin/env python3
"""
LDAP Security Scanner

Tests LDAP/LDAPS servers for:
- Anonymous bind allowed (unauthorized data access risk)
- Plain-text LDAP (port 389) accessible alongside LDAPS (port 636)

Uses raw TCP sockets + BER-encoded LDAP packets.
No external LDAP library required.
Based on RFC 4511 - Lightweight Directory Access Protocol (LDAP): The Protocol.
"""
import socket
import ssl
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# BER-encoded LDAP Anonymous BindRequest
#
# 30 0c           SEQUENCE (LDAPMessage)
#   02 01 01      INTEGER 1 (messageID)
#   60 07         [APPLICATION 0] CONSTRUCTED (BindRequest)
#     02 01 03    INTEGER 3 (version = 3)
#     04 00       OCTET STRING "" (name / DN, empty)
#     80 00       [0] PRIMITIVE "" (simple authentication, empty password)
# ------------------------------------------------------------------ #
ANON_BIND_REQUEST = bytes.fromhex("300c020101600702010304008000")

LDAP_SUCCESS = 0  # resultCode 0 = success


# ------------------------------------------------------------------ #
# Data model
# ------------------------------------------------------------------ #

@dataclass
class LdapScanResult:
    anon_bind_allowed: Optional[bool] = None  # anonymous bind on LDAPS succeeded?
    plain_available: Optional[bool] = None    # port 389 reachable?
    scan_error: Optional[str] = None


# ------------------------------------------------------------------ #
# Internal helpers
# ------------------------------------------------------------------ #

def _read_response(sock: socket.socket, max_bytes: int = 1024) -> Optional[bytes]:
    """Read raw LDAP response bytes from socket."""
    try:
        data = b""
        while len(data) < max_bytes:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
            if len(data) >= 14:   # minimal BindResponse is ~14 bytes
                break
        return data if data else None
    except Exception:
        return None


def _parse_result_code(data: bytes) -> Optional[int]:
    """
    Extract the LDAP resultCode from a BindResponse.

    Minimal BER walk:
      30 LL           SEQUENCE  (LDAPMessage)
        02 01 XX      INTEGER   (messageID)
        61 LL         [APPLICATION 1] CONSTRUCTED (BindResponse)
          0a 01 RC    ENUMERATED (resultCode)
          04 00       OCTET STRING (matchedDN, often empty)
          04 00       OCTET STRING (diagnosticMessage, often empty)
    """
    if not data or len(data) < 14:
        return None
    try:
        idx = 0
        # Outer SEQUENCE (tag 0x30)
        if data[idx] != 0x30:
            return None
        idx += 1
        # Skip length (short or long form)
        if data[idx] & 0x80:
            idx += 1 + (data[idx] & 0x7f)
        else:
            idx += 1
        # INTEGER messageID (tag 0x02)
        if data[idx] != 0x02:
            return None
        msg_id_len = data[idx + 1]
        idx += 2 + msg_id_len
        # BindResponse tag 0x61
        if data[idx] != 0x61:
            return None
        idx += 1
        if data[idx] & 0x80:
            idx += 1 + (data[idx] & 0x7f)
        else:
            idx += 1
        # ENUMERATED resultCode (tag 0x0a)
        if data[idx] != 0x0a:
            return None
        rc_len = data[idx + 1]
        if rc_len == 1:
            return data[idx + 2]
        return None
    except (IndexError, Exception):
        return None


def _try_anon_bind_tls(host: str, port: int, timeout: int) -> Optional[bool]:
    """
    Attempt an anonymous LDAP bind over TLS (LDAPS).
    Returns True if bind succeeds, False if rejected, None on error.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # cert trust checked separately by TLS scanner
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                tls.sendall(ANON_BIND_REQUEST)
                resp = _read_response(tls)
                if resp is None:
                    return None
                rc = _parse_result_code(resp)
                if rc is None:
                    return None
                return rc == LDAP_SUCCESS
    except Exception as e:
        logger.debug(f"LDAPS anon bind {host}:{port} error: {e}")
        return None


def _port_open(host: str, port: int, timeout: int) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


# ------------------------------------------------------------------ #
# Public API
# ------------------------------------------------------------------ #

def scan_ldap(host: str, ldaps_port: int = 636, timeout: int = 10) -> LdapScanResult:
    """
    Scan LDAP security posture for a host.

    Checks:
    1. Whether an anonymous bind is accepted on ldaps_port (LDAPS / TLS).
    2. Whether plain LDAP port 389 is reachable at all.

    Args:
        host:       Hostname or IP address
        ldaps_port: Port running LDAPS (default 636)
        timeout:    Socket timeout in seconds
    """
    result = LdapScanResult()
    try:
        result.anon_bind_allowed = _try_anon_bind_tls(host, ldaps_port, timeout)
        result.plain_available = _port_open(host, 389, timeout=min(timeout, 5))
        logger.info(
            f"LDAP scan {host}:{ldaps_port}: "
            f"anon_bind={result.anon_bind_allowed} "
            f"plain_389={result.plain_available}"
        )
    except Exception as e:
        result.scan_error = str(e)
        logger.warning(f"LDAP scan {host} error: {e}")
    return result
