#!/usr/bin/env python3
"""
SSH Security Scanner

Connects to an SSH server via raw TCP socket, reads the server banner,
and parses the SSH_MSG_KEXINIT packet to discover supported algorithms.

No external SSH library required.
Based on RFC 4253 - The Secure Shell (SSH) Transport Layer Protocol.
"""
import socket
import struct
import logging
from dataclasses import dataclass, field
from typing import Optional, List

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Weak algorithm sets
# ------------------------------------------------------------------ #

# KEX algorithms considered weak
WEAK_KEX = {
    "diffie-hellman-group1-sha1",         # 1024-bit DH – broken
    "diffie-hellman-group14-sha1",        # 2048-bit DH with SHA-1
    "diffie-hellman-group-exchange-sha1",
    "gss-gex-sha1-*",
    "gss-group1-sha1-*",
    "gss-group14-sha1-*",
}

# Host-key algorithms considered weak or deprecated
WEAK_HOST_KEY = {
    "ssh-dss",    # DSA – formally deprecated (RFC 9142)
    "ssh-rsa",    # RSA + SHA-1 – disabled by default in OpenSSH ≥ 8.8
}

# Symmetric encryption algorithms considered weak
WEAK_ENCRYPTION = {
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "blowfish-cbc",
    "cast128-cbc",
    "des-cbc",
    "none",
    "idea-cbc",
    "seed-cbc",
    "twofish-cbc",
    "twofish128-cbc",
    "twofish256-cbc",
}

# MAC algorithms considered weak
WEAK_MAC = {
    "hmac-md5",
    "hmac-md5-96",
    "hmac-sha1",
    "hmac-sha1-96",
    "umac-64@openssh.com",
    "umac-64",
    "none",
}

SSH_MSG_KEXINIT = 20


# ------------------------------------------------------------------ #
# Data model
# ------------------------------------------------------------------ #

@dataclass
class SSHScanResult:
    banner: Optional[str] = None
    protocol_version: Optional[str] = None   # "1.x" or "2.0"
    server_software: Optional[str] = None
    kex_algorithms: List[str] = field(default_factory=list)
    server_host_key_algorithms: List[str] = field(default_factory=list)
    encryption_algorithms: List[str] = field(default_factory=list)
    mac_algorithms: List[str] = field(default_factory=list)
    compression_algorithms: List[str] = field(default_factory=list)
    # Detected weaknesses
    supports_ssh1: bool = False
    weak_kex: List[str] = field(default_factory=list)
    weak_host_key: List[str] = field(default_factory=list)
    weak_encryption: List[str] = field(default_factory=list)
    weak_mac: List[str] = field(default_factory=list)
    scan_error: Optional[str] = None


# ------------------------------------------------------------------ #
# Internal helpers
# ------------------------------------------------------------------ #

def _read_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(
                f"Connection closed after {len(buf)}/{n} bytes"
            )
        buf += chunk
    return buf


def _read_name_list(data: bytes, offset: int):
    """
    Parse one SSH name-list at the given offset.

    A name-list is: uint32 length, then 'length' bytes of
    comma-separated ASCII algorithm names.

    Returns (list_of_names, new_offset).
    """
    if offset + 4 > len(data):
        return [], offset
    length = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4
    if length == 0:
        return [], offset
    if offset + length > len(data):
        return [], offset
    raw = data[offset:offset + length].decode("ascii", errors="replace")
    offset += length
    return [n.strip() for n in raw.split(",") if n.strip()], offset


def _parse_kexinit(payload: bytes) -> dict:
    """
    Parse an SSH_MSG_KEXINIT payload.

    Layout after msg-type byte (payload[0]):
      16 bytes  cookie (random)
      name-list kex_algorithms
      name-list server_host_key_algorithms
      name-list encryption_client_to_server
      name-list encryption_server_to_client
      name-list mac_client_to_server
      name-list mac_server_to_client
      name-list compression_client_to_server
      name-list compression_server_to_client
      name-list languages_client_to_server
      name-list languages_server_to_client
      boolean   first_kex_packet_follows
      uint32    0 (reserved)
    """
    # Skip msg-type (1 byte) + cookie (16 bytes)
    offset = 17
    result = {}
    for field_name in [
        "kex_algorithms",
        "server_host_key_algorithms",
        "encryption_client_to_server",
        "encryption_server_to_client",
        "mac_client_to_server",
        "mac_server_to_client",
        "compression_client_to_server",
        "compression_server_to_client",
        "languages_client_to_server",
        "languages_server_to_client",
    ]:
        names, offset = _read_name_list(payload, offset)
        result[field_name] = names
    return result


# ------------------------------------------------------------------ #
# Public API
# ------------------------------------------------------------------ #

def scan_ssh(host: str, port: int = 22, timeout: int = 10) -> SSHScanResult:
    """
    Scan an SSH server and return an SSHScanResult with algorithm details
    and detected weaknesses.
    """
    result = SSHScanResult()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:

            # ── 1. Read server banner (terminated by LF) ──────────
            banner_bytes = b""
            while len(banner_bytes) < 512:
                ch = sock.recv(1)
                if not ch:
                    break
                banner_bytes += ch
                if banner_bytes.endswith(b"\n"):
                    break

            banner = banner_bytes.decode("utf-8", errors="replace").strip()
            result.banner = banner

            # Parse "SSH-<proto>-<software>" from banner
            if not banner.startswith("SSH-"):
                result.scan_error = f"Unexpected banner: {banner[:80]}"
                return result

            parts = banner.split("-", 2)
            if len(parts) >= 2:
                result.protocol_version = parts[1]
            if len(parts) >= 3:
                result.server_software = parts[2]

            if result.protocol_version and result.protocol_version.startswith("1."):
                result.supports_ssh1 = True

            # ── 2. Send our banner to trigger server KEXINIT ──────
            sock.sendall(b"SSH-2.0-CertGuardian_1.0\r\n")

            # ── 3. Read binary SSH packet ──────────────────────────
            # Format: uint32 packet_length | byte padding_length | payload | padding
            header = _read_exact(sock, 5)
            packet_length = struct.unpack(">I", header[:4])[0]
            padding_length = header[4]

            if packet_length < 1 or packet_length > 35000:
                result.scan_error = f"Unexpected packet length: {packet_length}"
                return result

            # Remaining bytes after padding_length byte
            rest = _read_exact(sock, packet_length - 1)
            payload_len = (packet_length - 1) - padding_length
            if payload_len < 1:
                result.scan_error = "Empty packet payload"
                return result
            payload = rest[:payload_len]

            if payload[0] != SSH_MSG_KEXINIT:
                result.scan_error = (
                    f"Expected KEXINIT (20), got msg type {payload[0]}"
                )
                return result

            # ── 4. Parse algorithm lists ───────────────────────────
            kex_data = _parse_kexinit(payload)
            result.kex_algorithms = kex_data.get("kex_algorithms", [])
            result.server_host_key_algorithms = kex_data.get(
                "server_host_key_algorithms", []
            )
            result.encryption_algorithms = kex_data.get(
                "encryption_client_to_server", []
            )
            result.mac_algorithms = kex_data.get("mac_client_to_server", [])
            result.compression_algorithms = kex_data.get(
                "compression_client_to_server", []
            )

            # ── 5. Flag weaknesses ─────────────────────────────────
            result.weak_kex = [
                a for a in result.kex_algorithms if a.lower() in WEAK_KEX
            ]
            result.weak_host_key = [
                a for a in result.server_host_key_algorithms
                if a.lower() in WEAK_HOST_KEY
            ]
            result.weak_encryption = [
                a for a in result.encryption_algorithms
                if a.lower() in WEAK_ENCRYPTION
            ]
            result.weak_mac = [
                a for a in result.mac_algorithms if a.lower() in WEAK_MAC
            ]

            logger.info(
                f"SSH scan {host}:{port}: {banner} "
                f"kex={result.kex_algorithms[:2]} "
                f"weak_kex={result.weak_kex}"
            )

    except socket.timeout:
        result.scan_error = "Connection timed out"
        logger.warning(f"SSH scan {host}:{port} timed out")
    except ConnectionRefusedError:
        result.scan_error = "Connection refused"
        logger.warning(f"SSH scan {host}:{port} connection refused")
    except Exception as e:
        result.scan_error = str(e)
        logger.warning(f"SSH scan {host}:{port} failed: {e}")

    return result
