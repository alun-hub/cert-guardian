import json
import socket
import ssl
import struct
from datetime import datetime, timezone


class SiemClient:
    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self._ca_path = None
        self._cert_path = None
        self._key_path = None
        self._cache_pems()

    def configure(self, config: dict | None):
        self.config = config or {}
        self._cache_pems()

    def _cache_pems(self):
        self._ca_path = self._write_temp_pem(self.config.get("ca_pem"))
        self._cert_path = self._write_temp_pem(self.config.get("client_cert_pem"))
        self._key_path = self._write_temp_pem(self.config.get("client_key_pem"))

    def send_event(self, event: dict) -> bool:
        mode = (self.config.get("mode") or "disabled").lower()
        if mode == "disabled":
            return False

        if mode == "stdout":
            return self._send_stdout(event)
        if mode == "syslog":
            return self._send_syslog(event)
        if mode == "beats":
            return self._send_beats(event)
        return False

    def _build_ssl_context(self) -> ssl.SSLContext | None:
        tls_enabled = bool(self.config.get("tls_enabled", True))
        if not tls_enabled:
            return None

        verify = bool(self.config.get("tls_verify", True))
        if verify:
            context = ssl.create_default_context()
        else:
            context = ssl._create_unverified_context()

        if self._ca_path:
            context.load_verify_locations(cafile=self._ca_path)

        if self._cert_path and self._key_path:
            context.load_cert_chain(certfile=self._cert_path, keyfile=self._key_path)
        return context

    def _write_temp_pem(self, pem_data: str | None) -> str | None:
        import tempfile
        import os
        if not pem_data:
            return None
        fd, path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as f:
            f.write(pem_data)
        return path

    def _send_stdout(self, event: dict) -> bool:
        """Print audit events as JSON to stdout for Kubernetes log collection."""
        import sys
        fields = self._event_to_fields(event)
        try:
            print(json.dumps(fields, ensure_ascii=False), file=sys.stdout, flush=True)
            return True
        except Exception:
            return False

    def _send_syslog(self, event: dict) -> bool:
        host = self.config.get("host")
        port = self.config.get("port")
        if not host or not port:
            return False

        msg = self._format_syslog_message(event)
        payload = f"{len(msg)} {msg}".encode("utf-8")

        try:
            with socket.create_connection((host, int(port)), timeout=5) as sock:
                context = self._build_ssl_context()
                if context:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        ssock.sendall(payload)
                else:
                    sock.sendall(payload)
            return True
        except Exception:
            return False

    def _format_syslog_message(self, event: dict) -> str:
        pri = 134  # local0.info
        timestamp = datetime.now(timezone.utc).isoformat()
        hostname = socket.gethostname()
        app = "cert-guardian"
        procid = "-"
        msgid = event.get("action") or "audit"
        structured_data = "-"
        msg = json.dumps(event, ensure_ascii=False)
        return f"<{pri}>1 {timestamp} {hostname} {app} {procid} {msgid} {structured_data} {msg}"

    def _send_beats(self, event: dict) -> bool:
        host = self.config.get("host")
        port = self.config.get("port")
        if not host or not port:
            return False

        # Lumberjack v2 (Beats) - JSON frame implementation
        fields = self._event_to_fields(event)
        seq = 1
        window = 1
        try:
            with socket.create_connection((host, int(port)), timeout=5) as sock:
                context = self._build_ssl_context()
                if context:
                    conn = context.wrap_socket(sock, server_hostname=host)
                else:
                    conn = sock

                conn.settimeout(5)
                # Window frame: version '2' + type 'W' + size
                conn.sendall(b'2W' + struct.pack('>I', window))
                # JSON data frame: version '2' + type 'J' + seq + payload_len + payload
                payload = json.dumps(fields, ensure_ascii=False).encode('utf-8')
                frame = b'2J' + struct.pack('>I', seq) + struct.pack('>I', len(payload)) + payload
                conn.sendall(frame)

                # Read ack: version + type 'A' + seq
                ack = conn.recv(6)
                conn.close()
            return True
        except Exception:
            return False

    def _event_to_fields(self, event: dict) -> dict:
        fields = {
            "type": "cert-guardian",
            "@timestamp": event.get("created_at") or datetime.now(timezone.utc).isoformat(),
        }
        for k, v in event.items():
            if v is None:
                continue
            fields[k] = str(v)
        return fields
