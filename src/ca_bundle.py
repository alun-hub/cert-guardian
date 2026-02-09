"""
CA Bundle Builder - combines system CAs with custom CAs from database
for use by outbound TLS connections (Mattermost, SIEM, etc.)

Sets REQUESTS_CA_BUNDLE and SSL_CERT_FILE so that the requests library
and Python ssl module automatically use custom CA certificates uploaded
via the Settings UI.
"""
import os
import tempfile
import logging

logger = logging.getLogger(__name__)

_bundle_path = None

try:
    import certifi
    _SYSTEM_CA_FILE = certifi.where()
except ImportError:
    _SYSTEM_CA_FILE = None


def update_ca_bundle(custom_ca_pems: list) -> str:
    """Build a combined CA bundle from system CAs and custom CAs.

    Sets REQUESTS_CA_BUNDLE and SSL_CERT_FILE environment variables
    so that all outbound TLS connections trust the custom CAs.

    Args:
        custom_ca_pems: List of PEM strings from database

    Returns:
        Path to the combined CA bundle file
    """
    global _bundle_path

    if not custom_ca_pems:
        # No custom CAs — clear override, use system defaults
        for var in ('REQUESTS_CA_BUNDLE', 'SSL_CERT_FILE'):
            os.environ.pop(var, None)
        logger.info("No custom CAs configured, using system trust store")
        return _SYSTEM_CA_FILE or ""

    # Remove old bundle if it exists
    if _bundle_path and os.path.exists(_bundle_path):
        try:
            os.unlink(_bundle_path)
        except OSError:
            pass

    # Create new combined bundle
    fd, _bundle_path = tempfile.mkstemp(suffix='.pem', prefix='cert-guardian-ca-')
    with os.fdopen(fd, 'w') as f:
        # System CAs first
        if _SYSTEM_CA_FILE:
            with open(_SYSTEM_CA_FILE, 'r') as system_cas:
                f.write(system_cas.read())

        # Custom CAs from database
        for pem in custom_ca_pems:
            f.write('\n')
            f.write(pem)

    # Set environment variables for requests and ssl modules
    os.environ['REQUESTS_CA_BUNDLE'] = _bundle_path
    os.environ['SSL_CERT_FILE'] = _bundle_path

    logger.info(f"Updated CA bundle with {len(custom_ca_pems)} custom CA(s): {_bundle_path}")

    return _bundle_path
