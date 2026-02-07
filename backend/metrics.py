import os
import time

from prometheus_client import Counter, Gauge, Histogram, Info, generate_latest, CONTENT_TYPE_LATEST


# --- Gauges (certificate/endpoint state) ---

CERTIFICATES_TOTAL = Gauge(
    "cert_guardian_certificates_total",
    "Total number of unique certificates",
)
ENDPOINTS_TOTAL = Gauge(
    "cert_guardian_endpoints_total",
    "Total number of monitored endpoints",
)
CERTIFICATES_EXPIRING = Gauge(
    "cert_guardian_certificates_expiring",
    "Certificates expiring within window",
    ["window"],
)
CERTIFICATES_EXPIRED = Gauge(
    "cert_guardian_certificates_expired",
    "Certificates that have already expired",
)
CERTIFICATES_SELF_SIGNED = Gauge(
    "cert_guardian_certificates_self_signed",
    "Self-signed certificates",
)
CERTIFICATES_UNTRUSTED = Gauge(
    "cert_guardian_certificates_untrusted",
    "Certificates not trusted by system or custom CAs",
)
CERTIFICATES_WEAK_KEYS = Gauge(
    "cert_guardian_certificates_weak_keys",
    "Certificates with weak cryptographic keys",
)
ENDPOINTS_LEGACY_TLS = Gauge(
    "cert_guardian_endpoints_legacy_tls",
    "Endpoints using TLS 1.0 or 1.1",
)
DATABASE_SIZE_BYTES = Gauge(
    "cert_guardian_database_size_bytes",
    "SQLite database file size in bytes",
)
SCANS_TOTAL = Gauge(
    "cert_guardian_scans_total",
    "Total number of certificate scans performed",
)

# --- Counters (HTTP request tracking) ---

HTTP_REQUESTS_TOTAL = Counter(
    "cert_guardian_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)

# --- Histogram (request duration) ---

HTTP_REQUEST_DURATION = Histogram(
    "cert_guardian_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# --- Info ---

APP_INFO = Info(
    "cert_guardian",
    "Certificate Guardian application info",
)

# --- Cache for DB metrics ---

_last_update = 0.0
_cache_ttl = 60.0  # seconds


def update_certificate_metrics(db, config: dict | None = None):
    """Update certificate gauges from database. Cached with 60s TTL."""
    global _last_update
    now = time.time()
    if now - _last_update < _cache_ttl:
        return
    _last_update = now

    try:
        cursor = db.conn.cursor()

        # Total certificates
        cursor.execute("SELECT COUNT(DISTINCT fingerprint) FROM certificates")
        CERTIFICATES_TOTAL.set(cursor.fetchone()[0])

        # Total endpoints
        cursor.execute("SELECT COUNT(*) FROM endpoints")
        ENDPOINTS_TOTAL.set(cursor.fetchone()[0])

        # Expiring windows
        for days, label in [(7, "7d"), (30, "30d"), (90, "90d")]:
            cursor.execute(
                "SELECT COUNT(DISTINCT id) FROM certificates "
                "WHERE julianday(not_after) - julianday('now') <= ? "
                "AND julianday(not_after) - julianday('now') > 0",
                (days,),
            )
            CERTIFICATES_EXPIRING.labels(window=label).set(cursor.fetchone()[0])

        # Expired
        cursor.execute(
            "SELECT COUNT(DISTINCT id) FROM certificates "
            "WHERE julianday(not_after) - julianday('now') < 0"
        )
        CERTIFICATES_EXPIRED.set(cursor.fetchone()[0])

        # Self-signed
        cursor.execute("SELECT COUNT(*) FROM certificates WHERE is_self_signed = 1")
        CERTIFICATES_SELF_SIGNED.set(cursor.fetchone()[0])

        # Untrusted
        cursor.execute("SELECT COUNT(*) FROM certificates WHERE is_trusted_ca = 0")
        CERTIFICATES_UNTRUSTED.set(cursor.fetchone()[0])

        # Weak keys
        cursor.execute(
            "SELECT COUNT(DISTINCT id) FROM certificates WHERE "
            "(key_type = 'RSA' AND key_size IS NOT NULL AND key_size < 2048) OR "
            "(key_type = 'EC' AND key_size IS NOT NULL AND key_size < 256) OR "
            "(key_type = 'DSA')"
        )
        CERTIFICATES_WEAK_KEYS.set(cursor.fetchone()[0])

        # Legacy TLS
        cursor.execute(
            "SELECT COUNT(DISTINCT endpoint_id) FROM certificate_scans "
            "WHERE tls_version IN ('TLSv1', 'TLSv1.0', 'TLSv1.1')"
        )
        ENDPOINTS_LEGACY_TLS.set(cursor.fetchone()[0])

        # Total scans
        cursor.execute("SELECT COUNT(*) FROM certificate_scans")
        SCANS_TOTAL.set(cursor.fetchone()[0])

        # Database size
        db_path = (config or {}).get("database", {}).get("path", "data/certificates.db")
        if os.path.exists(db_path):
            DATABASE_SIZE_BYTES.set(os.path.getsize(db_path))

    except Exception:
        pass  # Metrics update failure should not break the app


def set_app_info(version: str, auth_mode: str):
    """Set application info metric."""
    APP_INFO.info({"version": version, "auth_mode": auth_mode})


def get_metrics_output() -> bytes:
    """Generate Prometheus text format output."""
    return generate_latest()


def get_metrics_content_type() -> str:
    """Return the correct content type for Prometheus."""
    return CONTENT_TYPE_LATEST
