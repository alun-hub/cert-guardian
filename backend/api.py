#!/usr/bin/env python3
"""
Certificate Guardian - FastAPI Backend
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from database import Database
from scanner import TLSScanner
from notifier import MattermostNotifier
import yaml

app = FastAPI(
    title="Certificate Guardian API",
    description="API for monitoring TLS certificate expiry",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
db: Optional[Database] = None
scanner: Optional[TLSScanner] = None
notifier: Optional[MattermostNotifier] = None
config: Optional[Dict] = None


# Pydantic models
class EndpointCreate(BaseModel):
    host: str
    port: int = 443
    owner: Optional[str] = None
    criticality: str = "medium"


class EndpointUpdate(BaseModel):
    owner: Optional[str] = None
    criticality: Optional[str] = None
    webhook_url: Optional[str] = None


class ScanRequest(BaseModel):
    endpoint_id: Optional[int] = None


class TrustedCACreate(BaseModel):
    name: str
    pem_data: str


class WebhookTest(BaseModel):
    webhook_url: str
    message: Optional[str] = "Test message from Certificate Guardian"


class DashboardStats(BaseModel):
    total_certificates: int
    total_endpoints: int
    expiring_soon: int  # Within 30 days
    expired: int
    self_signed: int
    untrusted: int


class CertificateInfo(BaseModel):
    id: int
    fingerprint: str
    subject: str
    issuer: str
    not_before: str
    not_after: str
    days_until_expiry: float
    is_self_signed: bool
    is_trusted_ca: bool
    validation_error: Optional[str]
    endpoints: List[Dict[str, Any]]


# Initialize
@app.on_event("startup")
async def startup_event():
    global db, scanner, notifier, config

    # Load config
    config_path = Path(__file__).parent.parent / "config" / "config.yaml"
    with open(config_path) as f:
        config = yaml.safe_load(f)

    # Initialize database
    db_path = Path(__file__).parent.parent / config['database']['path']
    db = Database(str(db_path))

    # Load custom CAs from database
    custom_ca_pems = db.get_all_trusted_ca_pems()

    # Initialize scanner with custom CAs
    scanner = TLSScanner(
        timeout=config['scanner'].get('timeout_seconds', 10),
        custom_ca_pems=custom_ca_pems
    )

    # Initialize notifier
    webhook_url = config['mattermost']['webhook_url']
    if webhook_url and "your-mattermost" not in webhook_url:
        notifier = MattermostNotifier(
            webhook_url=webhook_url,
            username=config['mattermost'].get('username', 'Certificate Guardian'),
            icon_emoji=config['mattermost'].get('icon_emoji', ':lock:')
        )


@app.on_event("shutdown")
async def shutdown_event():
    if db:
        db.close()


# Health check
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "database": "connected" if db else "disconnected"
    }


# Dashboard statistics
@app.get("/api/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats():
    """Get dashboard statistics"""
    cursor = db.conn.cursor()
    
    # Total certificates
    cursor.execute("SELECT COUNT(DISTINCT fingerprint) FROM certificates")
    total_certs = cursor.fetchone()[0]
    
    # Total endpoints
    cursor.execute("SELECT COUNT(*) FROM endpoints")
    total_endpoints = cursor.fetchone()[0]
    
    # Expiring soon (30 days)
    expiring = db.get_expiring_certificates(30)
    expiring_soon = len(expiring)
    
    # Expired
    cursor.execute("""
        SELECT COUNT(DISTINCT c.id)
        FROM certificates c
        WHERE julianday(c.not_after) - julianday('now') < 0
    """)
    expired = cursor.fetchone()[0]
    
    # Self-signed
    cursor.execute("SELECT COUNT(*) FROM certificates WHERE is_self_signed = 1")
    self_signed = cursor.fetchone()[0]
    
    # Untrusted
    cursor.execute("SELECT COUNT(*) FROM certificates WHERE is_trusted_ca = 0")
    untrusted = cursor.fetchone()[0]
    
    return DashboardStats(
        total_certificates=total_certs,
        total_endpoints=total_endpoints,
        expiring_soon=expiring_soon,
        expired=expired,
        self_signed=self_signed,
        untrusted=untrusted
    )


# Get all certificates
@app.get("/api/certificates")
async def get_certificates(
    expiring_days: Optional[int] = None,
    self_signed: Optional[bool] = None,
    untrusted: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0
):
    """Get certificates with optional filters"""
    cursor = db.conn.cursor()
    
    query = """
        SELECT 
            c.id,
            c.fingerprint,
            c.subject,
            c.issuer,
            c.not_before,
            c.not_after,
            c.is_self_signed,
            c.is_trusted_ca,
            c.validation_error,
            c.chain_length,
            julianday(c.not_after) - julianday('now') as days_until_expiry
        FROM certificates c
        WHERE 1=1
    """
    
    params = []
    
    if expiring_days is not None:
        query += " AND julianday(c.not_after) - julianday('now') <= ?"
        params.append(expiring_days)
    
    if self_signed is not None:
        query += " AND c.is_self_signed = ?"
        params.append(int(self_signed))
    
    if untrusted is not None:
        query += " AND c.is_trusted_ca = ?"
        params.append(int(not untrusted))
    
    query += " ORDER BY days_until_expiry ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    
    results = []
    for row in cursor.fetchall():
        cert_dict = dict(row)
        
        # Get endpoints where the LATEST scan returned this certificate
        cursor.execute("""
            SELECT e.id, e.host, e.port, e.owner, e.criticality
            FROM endpoints e
            JOIN certificate_scans cs ON e.id = cs.endpoint_id
            WHERE cs.certificate_id = ?
            AND cs.status = 'success'
            AND cs.scanned_at = (
                SELECT MAX(scanned_at)
                FROM certificate_scans
                WHERE endpoint_id = e.id
            )
        """, (cert_dict['id'],))
        
        cert_dict['endpoints'] = [dict(ep) for ep in cursor.fetchall()]
        results.append(cert_dict)
    
    return {
        "certificates": results,
        "total": len(results),
        "limit": limit,
        "offset": offset
    }


# Get single certificate details
@app.get("/api/certificates/{cert_id}")
async def get_certificate(cert_id: int):
    """Get detailed certificate information"""
    cursor = db.conn.cursor()
    
    cursor.execute("""
        SELECT 
            c.*,
            julianday(c.not_after) - julianday('now') as days_until_expiry
        FROM certificates c
        WHERE c.id = ?
    """, (cert_id,))
    
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Certificate not found")
    
    cert_dict = dict(row)
    
    # Get endpoints
    cursor.execute("""
        SELECT e.*, cs.scanned_at, cs.status
        FROM endpoints e
        JOIN certificate_scans cs ON e.id = cs.endpoint_id
        WHERE cs.certificate_id = ?
        ORDER BY cs.scanned_at DESC
    """, (cert_id,))
    
    cert_dict['endpoints'] = [dict(ep) for ep in cursor.fetchall()]
    
    # Get scan history
    cursor.execute("""
        SELECT cs.*, e.host, e.port
        FROM certificate_scans cs
        JOIN endpoints e ON cs.endpoint_id = e.id
        WHERE cs.certificate_id = ?
        ORDER BY cs.scanned_at DESC
        LIMIT 10
    """, (cert_id,))
    
    cert_dict['scan_history'] = [dict(scan) for scan in cursor.fetchall()]
    
    return cert_dict


# Get all endpoints
@app.get("/api/endpoints")
async def get_endpoints():
    """Get all monitored endpoints"""
    endpoints = db.get_all_endpoints()
    
    # Add last scan info for each endpoint
    cursor = db.conn.cursor()
    for endpoint in endpoints:
        cursor.execute("""
            SELECT cs.scanned_at, cs.status, c.not_after,
                   julianday(c.not_after) - julianday('now') as days_until_expiry
            FROM certificate_scans cs
            LEFT JOIN certificates c ON cs.certificate_id = c.id
            WHERE cs.endpoint_id = ?
            ORDER BY cs.scanned_at DESC
            LIMIT 1
        """, (endpoint['id'],))
        
        last_scan = cursor.fetchone()
        if last_scan:
            endpoint['last_scan'] = dict(last_scan)
        else:
            endpoint['last_scan'] = None
    
    return {"endpoints": endpoints}


# Create endpoint
@app.post("/api/endpoints")
async def create_endpoint(endpoint: EndpointCreate):
    """Add new endpoint to monitor"""
    endpoint_id = db.add_endpoint(
        host=endpoint.host,
        port=endpoint.port,
        owner=endpoint.owner,
        criticality=endpoint.criticality
    )
    
    return {"id": endpoint_id, "message": "Endpoint created successfully"}


# Update endpoint
@app.put("/api/endpoints/{endpoint_id}")
async def update_endpoint(endpoint_id: int, update: EndpointUpdate):
    """Update endpoint information"""
    cursor = db.conn.cursor()

    # Check if endpoint exists
    cursor.execute("SELECT * FROM endpoints WHERE id = ?", (endpoint_id,))
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="Endpoint not found")

    # Update
    updates = []
    params = []

    if update.owner is not None:
        updates.append("owner = ?")
        params.append(update.owner)

    if update.criticality is not None:
        updates.append("criticality = ?")
        params.append(update.criticality)

    if update.webhook_url is not None:
        updates.append("webhook_url = ?")
        params.append(update.webhook_url if update.webhook_url else None)

    if updates:
        query = f"UPDATE endpoints SET {', '.join(updates)} WHERE id = ?"
        params.append(endpoint_id)
        cursor.execute(query, params)
        db.conn.commit()

    return {"message": "Endpoint updated successfully"}


# Delete endpoint
@app.delete("/api/endpoints/{endpoint_id}")
async def delete_endpoint(endpoint_id: int):
    """Delete endpoint and clean up orphaned certificates"""
    cursor = db.conn.cursor()

    # Check if endpoint exists
    cursor.execute("SELECT id FROM endpoints WHERE id = ?", (endpoint_id,))
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="Endpoint not found")

    # Find certificates that will become orphaned after this endpoint is deleted
    cursor.execute("""
        SELECT DISTINCT certificate_id FROM certificate_scans
        WHERE endpoint_id = ?
        AND certificate_id NOT IN (
            SELECT DISTINCT certificate_id FROM certificate_scans
            WHERE endpoint_id != ?
        )
    """, (endpoint_id, endpoint_id))
    orphaned_cert_ids = [row[0] for row in cursor.fetchall()]

    # Delete notifications for this endpoint
    cursor.execute("DELETE FROM notifications WHERE endpoint_id = ?", (endpoint_id,))

    # Delete certificate scans for this endpoint
    cursor.execute("DELETE FROM certificate_scans WHERE endpoint_id = ?", (endpoint_id,))

    # Delete the endpoint
    cursor.execute("DELETE FROM endpoints WHERE id = ?", (endpoint_id,))

    # Delete orphaned certificates
    if orphaned_cert_ids:
        placeholders = ','.join('?' * len(orphaned_cert_ids))
        cursor.execute(f"DELETE FROM certificates WHERE id IN ({placeholders})", orphaned_cert_ids)

    db.conn.commit()

    return {
        "message": "Endpoint deleted successfully",
        "orphaned_certificates_deleted": len(orphaned_cert_ids)
    }


# Trigger scan
@app.post("/api/scan")
async def trigger_scan(background_tasks: BackgroundTasks, request: ScanRequest):
    """Trigger certificate scan"""
    
    async def do_scan(endpoint_id: Optional[int] = None):
        if endpoint_id:
            # Scan specific endpoint
            cursor = db.conn.cursor()
            cursor.execute("SELECT * FROM endpoints WHERE id = ?", (endpoint_id,))
            endpoint = cursor.fetchone()
            
            if not endpoint:
                return
            
            endpoint_dict = dict(endpoint)
            cert_info = scanner.scan_endpoint(endpoint_dict['host'], endpoint_dict['port'])
            
            if cert_info:
                cert_id = db.add_certificate(
                    fingerprint=cert_info.fingerprint,
                    subject=cert_info.subject,
                    issuer=cert_info.issuer,
                    not_before=cert_info.not_before.isoformat(),
                    not_after=cert_info.not_after.isoformat(),
                    serial_number=cert_info.serial_number,
                    san_list=cert_info.san_list,
                    is_self_signed=cert_info.is_self_signed,
                    is_trusted_ca=cert_info.is_trusted_ca,
                    validation_error=cert_info.validation_error,
                    chain_length=cert_info.chain_length
                )
                db.add_scan(cert_id, endpoint_id, 'success')
        else:
            # Scan all endpoints
            endpoints = db.get_all_endpoints()
            for endpoint in endpoints:
                cert_info = scanner.scan_endpoint(endpoint['host'], endpoint['port'])
                
                if cert_info:
                    cert_id = db.add_certificate(
                        fingerprint=cert_info.fingerprint,
                        subject=cert_info.subject,
                        issuer=cert_info.issuer,
                        not_before=cert_info.not_before.isoformat(),
                        not_after=cert_info.not_after.isoformat(),
                        serial_number=cert_info.serial_number,
                        san_list=cert_info.san_list,
                        is_self_signed=cert_info.is_self_signed,
                        is_trusted_ca=cert_info.is_trusted_ca,
                        validation_error=cert_info.validation_error,
                        chain_length=cert_info.chain_length
                    )
                    db.add_scan(cert_id, endpoint['id'], 'success')
    
    background_tasks.add_task(do_scan, request.endpoint_id)
    
    return {
        "message": "Scan initiated",
        "endpoint_id": request.endpoint_id if request.endpoint_id else "all"
    }


# Get expiry timeline
@app.get("/api/timeline")
async def get_expiry_timeline(months: int = 12):
    """Get certificate expiry timeline"""
    cursor = db.conn.cursor()

    # Get certificates grouped by month
    cursor.execute("""
        SELECT
            strftime('%Y-%m', not_after) as month,
            COUNT(*) as count
        FROM certificates
        WHERE julianday(not_after) - julianday('now') <= ?
        AND julianday(not_after) - julianday('now') > 0
        GROUP BY month
        ORDER BY month
    """, (months * 30,))

    cert_counts = {row[0]: row[1] for row in cursor.fetchall()}

    # Generate all months in range and fill with 0 if no certs
    from datetime import datetime
    from dateutil.relativedelta import relativedelta

    timeline = []
    current = datetime.now()
    for i in range(months):
        month_str = current.strftime('%Y-%m')
        month_label = current.strftime('%b %Y')
        timeline.append({
            "month": month_str,
            "label": month_label,
            "count": cert_counts.get(month_str, 0)
        })
        current = current + relativedelta(months=1)

    return {"timeline": timeline}


# Get security issues
@app.get("/api/security/issues")
async def get_security_issues():
    """Get all security issues (self-signed, untrusted)"""
    untrusted = db.get_untrusted_certificates()
    
    return {
        "issues": untrusted,
        "total": len(untrusted),
        "self_signed_count": len([c for c in untrusted if c['is_self_signed']]),
        "untrusted_count": len([c for c in untrusted if not c['is_trusted_ca'] and not c['is_self_signed']])
    }


# Send test notification
@app.post("/api/notifications/test")
async def send_test_notification():
    """Send test notification to Mattermost"""
    if not notifier:
        raise HTTPException(status_code=400, detail="Mattermost not configured")

    success = notifier.test_connection()

    if success:
        return {"message": "Test notification sent successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to send notification")


# Test webhook URL
@app.post("/api/webhooks/test")
async def test_webhook(request: WebhookTest):
    """Test a webhook URL"""
    import requests

    try:
        payload = {
            "text": request.message,
            "username": "Certificate Guardian",
            "icon_emoji": ":lock:"
        }
        response = requests.post(request.webhook_url, json=payload, timeout=10)

        if response.status_code == 200:
            return {"success": True, "message": "Webhook test successful"}
        else:
            return {"success": False, "message": f"Webhook returned status {response.status_code}"}
    except requests.exceptions.Timeout:
        return {"success": False, "message": "Webhook request timed out"}
    except requests.exceptions.RequestException as e:
        return {"success": False, "message": f"Webhook error: {str(e)}"}


# ===== Trusted CA Management =====

@app.get("/api/trusted-cas")
async def get_trusted_cas():
    """Get all trusted CA certificates"""
    cas = db.get_all_trusted_cas()
    return {"trusted_cas": cas, "total": len(cas)}


@app.post("/api/trusted-cas")
async def add_trusted_ca(ca: TrustedCACreate):
    """Add a trusted CA certificate"""
    import hashlib
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    try:
        # Parse the PEM certificate
        pem_data = ca.pem_data.strip()
        if not pem_data.startswith("-----BEGIN CERTIFICATE-----"):
            raise HTTPException(status_code=400, detail="Invalid PEM format")

        cert = x509.load_pem_x509_certificate(pem_data.encode(), default_backend())

        # Extract certificate info
        fingerprint = hashlib.sha256(cert.public_bytes(
            encoding=x509.base.serialization.Encoding.DER
        )).hexdigest()

        subject_parts = []
        for attr in cert.subject:
            subject_parts.append(f"{attr.oid._name}={attr.value}")
        subject = ", ".join(subject_parts)

        issuer_parts = []
        for attr in cert.issuer:
            issuer_parts.append(f"{attr.oid._name}={attr.value}")
        issuer = ", ".join(issuer_parts)

        not_after = cert.not_valid_after_utc.isoformat()

        # Add to database
        ca_id = db.add_trusted_ca(
            name=ca.name,
            pem_data=pem_data,
            fingerprint=fingerprint,
            subject=subject,
            issuer=issuer,
            not_after=not_after
        )

        # Refresh scanner's CA list
        scanner.set_custom_cas(db.get_all_trusted_ca_pems())

        return {
            "id": ca_id,
            "fingerprint": fingerprint,
            "subject": subject,
            "message": "Trusted CA added successfully"
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid certificate: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing certificate: {str(e)}")


@app.delete("/api/trusted-cas/{ca_id}")
async def delete_trusted_ca(ca_id: int):
    """Delete a trusted CA certificate"""
    if db.delete_trusted_ca(ca_id):
        # Refresh scanner's CA list
        scanner.set_custom_cas(db.get_all_trusted_ca_pems())
        return {"message": "Trusted CA deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="Trusted CA not found")


@app.get("/api/trusted-cas/{ca_id}/pem")
async def get_trusted_ca_pem(ca_id: int):
    """Get PEM data for a trusted CA"""
    pem = db.get_trusted_ca_pem(ca_id)
    if pem:
        return {"pem_data": pem}
    else:
        raise HTTPException(status_code=404, detail="Trusted CA not found")


# ===== Network Sweep Endpoints =====

class SweepCreate(BaseModel):
    name: str
    target: str
    ports: List[int] = [443]
    owner: Optional[str] = None
    criticality: str = "medium"
    webhook_url: Optional[str] = None


class SweepValidation(BaseModel):
    target: str


@app.post("/api/sweeps/validate")
async def validate_sweep_target(request: SweepValidation):
    """Validate a sweep target (CIDR or IP range)"""
    from network_scanner import validate_target

    valid, error, ip_count = validate_target(request.target)

    return {
        "valid": valid,
        "error": error if error else None,
        "ip_count": ip_count
    }


@app.post("/api/sweeps")
async def create_sweep(sweep: SweepCreate, background_tasks: BackgroundTasks):
    """Create and execute a new network sweep"""
    from network_scanner import validate_target

    # Validate target
    valid, error, ip_count = validate_target(sweep.target)
    if not valid:
        raise HTTPException(status_code=400, detail=error)

    # Validate ports
    if not sweep.ports:
        raise HTTPException(status_code=400, detail="At least one port required")

    for port in sweep.ports:
        if port < 1 or port > 65535:
            raise HTTPException(status_code=400, detail=f"Invalid port: {port}")

    # Create sweep record
    sweep_id = db.create_sweep(
        name=sweep.name,
        target=sweep.target,
        ports=sweep.ports,
        owner=sweep.owner,
        criticality=sweep.criticality,
        webhook_url=sweep.webhook_url
    )

    # Set initial progress
    total_scans = ip_count * len(sweep.ports)
    db.update_sweep_status(sweep_id, "pending", progress_total=total_scans)

    # Start sweep in background
    background_tasks.add_task(execute_sweep, sweep_id)

    return {"id": sweep_id, "message": "Sweep started", "total_scans": total_scans}


async def execute_sweep(sweep_id: int):
    """Execute sweep and discover endpoints"""
    import asyncio
    import json
    from network_scanner import NetworkScanner

    sweep = db.get_sweep(sweep_id)
    if not sweep:
        return

    try:
        db.update_sweep_status(sweep_id, "running",
                               started_at=datetime.utcnow().isoformat())

        scanner_net = NetworkScanner(timeout=3.0, max_concurrent=100)
        ports = json.loads(sweep['ports'])

        def update_progress(progress):
            db.update_sweep_status(
                sweep_id, "running",
                progress_scanned=progress.scanned,
                progress_found=progress.found
            )

        # Run the async sweep
        open_ports = await scanner_net.sweep(sweep['target'], ports, update_progress)

        # Process discovered endpoints
        for result in open_ports:
            # Create endpoint with metadata from sweep config
            endpoint_id = db.add_endpoint(
                host=result.ip,
                port=result.port,
                owner=sweep['owner'],
                criticality=sweep['criticality']
            )

            # Set webhook if configured
            if sweep['webhook_url']:
                db.update_endpoint_webhook(endpoint_id, sweep['webhook_url'])

            # Record sweep result
            db.add_sweep_result(sweep_id, result.ip, result.port, "open", endpoint_id)

            # Scan certificate immediately
            cert_info = scanner.scan_endpoint(result.ip, result.port)
            if cert_info:
                cert_id = db.add_certificate(
                    fingerprint=cert_info.fingerprint,
                    subject=cert_info.subject,
                    issuer=cert_info.issuer,
                    not_before=cert_info.not_before.isoformat(),
                    not_after=cert_info.not_after.isoformat(),
                    serial_number=cert_info.serial_number,
                    san_list=cert_info.san_list,
                    is_self_signed=cert_info.is_self_signed,
                    is_trusted_ca=cert_info.is_trusted_ca,
                    validation_error=cert_info.validation_error,
                    chain_length=cert_info.chain_length
                )
                db.add_scan(cert_id, endpoint_id, 'success')

        db.update_sweep_status(sweep_id, "completed",
                               completed_at=datetime.utcnow().isoformat())

    except Exception as e:
        import logging
        logging.error(f"Sweep {sweep_id} failed: {e}")
        db.update_sweep_status(sweep_id, "failed", error_message=str(e))


@app.get("/api/sweeps")
async def get_sweeps():
    """Get all sweeps"""
    sweeps = db.get_all_sweeps()
    return {"sweeps": sweeps, "total": len(sweeps)}


@app.get("/api/sweeps/{sweep_id}")
async def get_sweep(sweep_id: int):
    """Get sweep details including results"""
    sweep = db.get_sweep(sweep_id)
    if not sweep:
        raise HTTPException(status_code=404, detail="Sweep not found")

    sweep['results'] = db.get_sweep_results(sweep_id)
    return sweep


@app.delete("/api/sweeps/{sweep_id}")
async def delete_sweep(sweep_id: int):
    """Delete a sweep and its results"""
    # Check if sweep is running
    sweep = db.get_sweep(sweep_id)
    if sweep and sweep['status'] == 'running':
        raise HTTPException(status_code=400, detail="Cannot delete running sweep")

    if db.delete_sweep(sweep_id):
        return {"message": "Sweep deleted"}
    raise HTTPException(status_code=404, detail="Sweep not found")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
