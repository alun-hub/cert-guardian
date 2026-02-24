#!/usr/bin/env python3
"""
Shared EJBCA synchronisation logic.
Called from both src/main.py (scheduled) and backend/api.py (on-demand).
"""
import logging
from typing import TYPE_CHECKING

from ejbca_client import EjbcaClient

if TYPE_CHECKING:
    from database import Database

logger = logging.getLogger(__name__)


def run_ejbca_sync(ejbca_cfg: dict, db: 'Database') -> dict:
    """Fetch all active certificates from EJBCA and store them in the database.

    Returns:
        dict with keys: certs_found, certs_new, certs_updated, status, error
    """
    client = EjbcaClient(
        base_url=ejbca_cfg['base_url'],
        client_cert_pem=ejbca_cfg.get('client_cert_pem') or None,
        client_key_pem=ejbca_cfg.get('client_key_pem') or None,
        ca_pem=ejbca_cfg.get('ca_pem') or None,
        verify_tls=ejbca_cfg.get('verify_tls', True),
        api_key=ejbca_cfg.get('api_key') or None,
    )

    page_size = ejbca_cfg.get('max_results_per_page', 1000)
    max_total = page_size * 20

    try:
        certs = client.fetch_certificates(
            ca_dn_filter=ejbca_cfg.get('ca_dn_filter') or None,
            max_total=max_total,
        )
    except Exception as e:
        logger.error(f"EJBCA fetch failed: {e}", exc_info=True)
        db.add_ejbca_sync_log(0, 0, 0, 'failed', str(e))
        return {
            'certs_found': 0,
            'certs_new': 0,
            'certs_updated': 0,
            'status': 'failed',
            'error': str(e),
        }

    new_count = 0
    updated_count = 0

    for cert in certs:
        existing = db.get_certificate_by_fingerprint(cert.fingerprint)

        cert_id = db.add_certificate(
            fingerprint=cert.fingerprint,
            subject=cert.subject,
            issuer=cert.issuer,
            not_before=cert.not_before,
            not_after=cert.not_after,
            serial_number=cert.serial_number,
            san_list=cert.san_list,
            key_type=cert.key_type,
            key_size=cert.key_size,
            signature_algorithm=cert.signature_algorithm,
            is_self_signed=cert.is_self_signed,
            is_trusted_ca=not cert.is_self_signed,
            weak_signature=cert.weak_signature,
            source='ejbca',
        )

        db.add_ejbca_certificate(
            certificate_id=cert_id,
            ejbca_url=ejbca_cfg['base_url'],
            ca_dn=cert.ca_dn,
            username=cert.username,
            end_entity_profile=cert.end_entity_profile,
            certificate_profile=cert.certificate_profile,
            ejbca_status=cert.ejbca_status,
        )

        # Auto-map EJBCA username → cert-guardian user (never overrides manual assignment)
        if cert.username:
            db.map_ejbca_username_to_user(cert_id, cert.username)

        if existing:
            updated_count += 1
        else:
            new_count += 1

    db.add_ejbca_sync_log(
        certs_found=len(certs),
        certs_new=new_count,
        certs_updated=updated_count,
        status='success',
    )

    logger.info(
        f"EJBCA sync complete: {len(certs)} found, "
        f"{new_count} new, {updated_count} updated"
    )

    return {
        'certs_found': len(certs),
        'certs_new': new_count,
        'certs_updated': updated_count,
        'status': 'success',
        'error': None,
    }
