#!/usr/bin/env python3
"""
Certificate Guardian - FastAPI Backend
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
import sys
import logging
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from database import Database
from scanner import TLSScanner
from notifier import MattermostNotifier
from auth import AuthManager, User, LocalAuthProvider
from siem_client import SiemClient
from ca_bundle import update_ca_bundle
import yaml
import time as _time

from backend.metrics import (
    update_certificate_metrics, set_app_info, get_metrics_output,
    get_metrics_content_type, HTTP_REQUESTS_TOTAL, HTTP_REQUEST_DURATION,
)

CONFIG_PATH = Path(__file__).parent.parent / "config" / "config.yaml"

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Certificate Guardian API",
    description="API for monitoring TLS certificate expiry",
    version="1.2.0"
)

security = HTTPBearer(auto_error=False)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Prometheus metrics middleware
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    path = request.url.path
    # Skip metrics noise from scraping and health checks
    if path in ("/metrics", "/health"):
        return await call_next(request)
    method = request.method
    # Normalize path to avoid high cardinality (strip IDs)
    endpoint = path.split("?")[0]
    for part in endpoint.split("/"):
        if part.isdigit():
            endpoint = endpoint.replace(f"/{part}", "/{id}")
    start = _time.time()
    response = await call_next(request)
    duration = _time.time() - start
    HTTP_REQUESTS_TOTAL.labels(method=method, endpoint=endpoint, status=response.status_code).inc()
    HTTP_REQUEST_DURATION.labels(method=method, endpoint=endpoint).observe(duration)
    return response


# Global instances
db: Optional[Database] = None
scanner: Optional[TLSScanner] = None
notifier: Optional[MattermostNotifier] = None
config: Optional[Dict] = None
auth_manager: Optional[AuthManager] = None
siem_client: Optional[SiemClient] = None


# Pydantic models
class EndpointCreate(BaseModel):
    host: str
    port: int = 443
    owner: Optional[str] = None
    criticality: str = "medium"
    webhook_url: Optional[str] = None


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


# ===== Auth Models =====

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class UserCreate(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    role: str = "viewer"


class UserUpdate(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class ScannerSettingsUpdate(BaseModel):
    interval_seconds: Optional[int] = None


class DbHealth(BaseModel):
    db_size_bytes: int
    page_size: int
    page_count: int
    freelist_count: int
    approx_db_bytes: int
    approx_free_bytes: int
    counts: Dict[str, int]
    scans_last_30_days: int


class SiemSettings(BaseModel):
    mode: str  # "disabled" | "stdout" | "syslog" | "beats"
    host: Optional[str] = None
    port: Optional[int] = None
    tls_enabled: bool = True
    tls_verify: bool = True
    ca_pem: Optional[str] = None
    client_cert_pem: Optional[str] = None
    client_key_pem: Optional[str] = None


class SiemTestRequest(BaseModel):
    message: Optional[str] = "Test event from Certificate Guardian"


class DashboardStats(BaseModel):
    total_certificates: int
    total_endpoints: int
    expiring_7: int
    expiring_30: int
    expiring_90: int
    expired: int
    self_signed: int
    untrusted: int
    last_scan_at: Optional[str]
    last_scan_status: Optional[str]
    weak_keys: int
    legacy_tls: int
    cert_changes_24h: int


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
    global db, scanner, notifier, config, auth_manager
    global siem_client

    # Load config
    with open(CONFIG_PATH) as f:
        config = yaml.safe_load(f)

    # Initialize database
    db_path = Path(__file__).parent.parent / config['database']['path']
    db = Database(str(db_path))

    # Load custom CAs from database
    custom_ca_pems = db.get_all_trusted_ca_pems()

    # Build combined CA bundle for outbound TLS (Mattermost, etc.)
    update_ca_bundle(custom_ca_pems)

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

    # Initialize authentication
    auth_config = config.get('auth', {'mode': 'local'})
    auth_manager = AuthManager(db, auth_config)
    siem_client = SiemClient(config.get("siem", {}))

    # Initialize Prometheus app info
    auth_mode = config.get("auth", {}).get("mode", "local")
    set_app_info(version=app.version, auth_mode=auth_mode)


@app.on_event("shutdown")
async def shutdown_event():
    if db:
        db.close()


# ===== Auth Dependencies =====

async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[User]:
    """Get current user from request. Returns None if not authenticated."""
    if not auth_manager:
        return None
    return await auth_manager.authenticate(request)


async def require_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> User:
    """Require authentication. Raises 401 if not authenticated."""
    user = await get_current_user(request, credentials)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user


async def require_editor(user: User = Depends(require_auth)) -> User:
    """Require editor role or higher."""
    if not user.has_role("editor"):
        raise HTTPException(status_code=403, detail="Editor role required")
    return user


async def require_admin(user: User = Depends(require_auth)) -> User:
    """Require admin role."""
    if not user.has_role("admin"):
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


# ===== Auth Endpoints =====

@app.get("/api/auth/mode")
async def get_auth_mode():
    """Get current authentication mode"""
    if not auth_manager:
        return {"mode": "none", "message": "Authentication not configured"}
    return {"mode": auth_manager.get_mode()}


def get_client_ip(request: Request) -> str:
    """Get client IP from request, handling proxies"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def mask_webhook_url(url: Optional[str]) -> Optional[str]:
    """Mask a webhook URL for safe display.

    Example: 'https://mattermost.example.com/hooks/abc123xyz' -> 'https://matte...23xyz'
    """
    if not url:
        return None
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or ""
        # Show first 5 chars of host and last 3 chars of path
        host_prefix = host[:5]
        path_suffix = path[-3:] if len(path) > 3 else path
        return f"{parsed.scheme}://{host_prefix}...{path_suffix}"
    except Exception:
        if len(url) <= 10:
            return "***"
        return f"{url[:8]}...{url[-3:]}"


def audit_log(user_email: str, action: str, resource_type: str = None,
              resource_id: int = None, details: str = None,
              ip_address: str = None):
    """Persist audit log entry and forward to SIEM if configured."""
    if not db:
        return
    log_id = db.add_audit_log(
        user_email=user_email,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address
    )
    if siem_client:
        event = {
            "audit_id": log_id,
            "user_email": user_email,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "details": details,
            "ip_address": ip_address,
            "created_at": datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
        }
        siem_client.send_event(event)


@app.post("/api/auth/login")
async def login(login_request: LoginRequest, request: Request, response: Response):
    """Login with username/password (local mode only)"""
    if not auth_manager:
        raise HTTPException(status_code=500, detail="Authentication not configured")

    if auth_manager.get_mode() != "local":
        raise HTTPException(
            status_code=400,
            detail=f"Login endpoint not available in {auth_manager.get_mode()} mode"
        )

    result = auth_manager.login(login_request.username, login_request.password)
    if not result:
        # Log failed login attempt
        audit_log(
            user_email=login_request.username,
            action="login_failed",
            details="Invalid username or password",
            ip_address=get_client_ip(request)
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Log successful login
    audit_log(
        user_email=result["user"]["email"],
        action="login",
        details=f"User logged in successfully",
        ip_address=get_client_ip(request)
    )

    # Set refresh token as httpOnly cookie
    response.set_cookie(
        key="refresh_token",
        value=result["refresh_token"],
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
        max_age=30 * 24 * 60 * 60  # 30 days
    )

    # Don't include refresh token in response body
    return {
        "access_token": result["access_token"],
        "token_type": result["token_type"],
        "expires_in": result["expires_in"],
        "user": result["user"]
    }


@app.post("/api/auth/refresh")
async def refresh_token(
    request: Request,
    response: Response,
    body: Optional[TokenRefreshRequest] = None
):
    """Refresh access token using refresh token"""
    if not auth_manager:
        raise HTTPException(status_code=500, detail="Authentication not configured")

    if auth_manager.get_mode() != "local":
        raise HTTPException(
            status_code=400,
            detail=f"Token refresh not available in {auth_manager.get_mode()} mode"
        )

    # Get refresh token from cookie or body
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token and body:
        refresh_token = body.refresh_token

    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token required")

    result = auth_manager.refresh(refresh_token)
    if not result:
        # Clear invalid cookie
        response.delete_cookie("refresh_token")
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    return result


@app.post("/api/auth/logout")
async def logout(request: Request, response: Response, user: User = Depends(get_current_user)):
    """Logout and revoke refresh token"""
    if auth_manager and auth_manager.get_mode() == "local":
        refresh_token = request.cookies.get("refresh_token")
        if refresh_token:
            auth_manager.logout(refresh_token)

    # Log logout
    if user:
        audit_log(
            user_email=user.email,
            action="logout",
            ip_address=get_client_ip(request)
        )

    response.delete_cookie("refresh_token")
    return {"message": "Logged out successfully"}


@app.get("/api/auth/me")
async def get_current_user_info(user: User = Depends(require_auth)):
    """Get current authenticated user info"""
    return user.to_dict()


# ===== User Management Endpoints (Admin only) =====

@app.get("/api/users")
async def list_users(admin: User = Depends(require_admin)):
    """List all users (admin only)"""
    users = db.get_all_users()
    return {"users": users, "total": len(users)}


@app.post("/api/users")
async def create_user(user_data: UserCreate, request: Request, admin: User = Depends(require_admin)):
    """Create a new user (admin only)"""
    if auth_manager.get_mode() != "local":
        raise HTTPException(
            status_code=400,
            detail="User creation only available in local auth mode"
        )

    # Check if username already exists
    existing = db.get_user_by_username(user_data.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    # Validate role
    valid_roles = ["viewer", "editor", "admin"]
    if user_data.role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {valid_roles}")

    # Hash password and create user
    password_hash = auth_manager.hash_password(user_data.password)
    user_id = db.create_user(
        username=user_data.username,
        password_hash=password_hash,
        email=user_data.email or f"{user_data.username}@local",
        role=user_data.role
    )

    # Audit log
    audit_log(
        user_email=admin.email,
        action="user_create",
        resource_type="user",
        resource_id=user_id,
        details=f"Created user '{user_data.username}' with role '{user_data.role}'",
        ip_address=get_client_ip(request)
    )

    return {"id": user_id, "message": "User created successfully"}


@app.get("/api/users/{user_id}")
async def get_user(user_id: int, admin: User = Depends(require_admin)):
    """Get user details (admin only)"""
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.put("/api/users/{user_id}")
async def update_user(
    user_id: int,
    update: UserUpdate,
    request: Request,
    admin: User = Depends(require_admin)
):
    """Update user (admin only)"""
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent deactivating the last admin
    if update.is_active is False or (update.role and update.role != "admin"):
        cursor = db.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1")
        admin_count = cursor.fetchone()[0]
        if admin_count <= 1 and user['role'] == 'admin':
            raise HTTPException(
                status_code=400,
                detail="Cannot deactivate or demote the last admin user"
            )

    # Build update
    updates = {}
    changes = []
    if update.email is not None:
        updates['email'] = update.email
        changes.append(f"email→{update.email}")
    if update.role is not None:
        valid_roles = ["viewer", "editor", "admin"]
        if update.role not in valid_roles:
            raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {valid_roles}")
        updates['role'] = update.role
        changes.append(f"role→{update.role}")
    if update.is_active is not None:
        updates['is_active'] = 1 if update.is_active else 0
        changes.append(f"active→{update.is_active}")

    if updates:
        db.update_user(user_id, **updates)

        # Audit log
        audit_log(
            user_email=admin.email,
            action="user_update",
            resource_type="user",
            resource_id=user_id,
            details=f"Updated user '{user['username']}': {', '.join(changes)}",
            ip_address=get_client_ip(request)
        )

    return {"message": "User updated successfully"}


@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int, request: Request, admin: User = Depends(require_admin)):
    """Delete user (admin only)"""
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent deleting the last admin
    if user['role'] == 'admin':
        cursor = db.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1")
        admin_count = cursor.fetchone()[0]
        if admin_count <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete the last admin user"
            )

    # Prevent self-deletion
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    username = user['username']
    db.delete_user(user_id)

    # Audit log
    audit_log(
        user_email=admin.email,
        action="user_delete",
        resource_type="user",
        resource_id=user_id,
        details=f"Deleted user '{username}'",
        ip_address=get_client_ip(request)
    )

    return {"message": "User deleted successfully"}


class PasswordReset(BaseModel):
    new_password: str


@app.post("/api/users/{user_id}/password")
async def reset_user_password(
    user_id: int,
    request: PasswordReset,
    admin: User = Depends(require_admin)
):
    """Reset user password (admin only)"""
    if auth_manager.get_mode() != "local":
        raise HTTPException(
            status_code=400,
            detail="Password reset only available in local auth mode"
        )

    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    password_hash = auth_manager.hash_password(request.new_password)
    db.update_user_password(user_id, password_hash)

    return {"message": "Password reset successfully"}


@app.post("/api/auth/change-password")
async def change_own_password(
    request: PasswordChange,
    user: User = Depends(require_auth)
):
    """Change own password"""
    if auth_manager.get_mode() != "local":
        raise HTTPException(
            status_code=400,
            detail="Password change only available in local auth mode"
        )

    # Verify current password
    user_data = db.get_user_by_id(user.id)
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")

    provider = auth_manager.provider
    if isinstance(provider, LocalAuthProvider):
        if not provider.verify_password(request.current_password, user_data['password_hash']):
            raise HTTPException(status_code=400, detail="Current password is incorrect")

        # Update password
        new_hash = provider.hash_password(request.new_password)
        db.update_user_password(user.id, new_hash)

        return {"message": "Password changed successfully"}

    raise HTTPException(status_code=400, detail="Password change not supported")


# Health check
@app.get("/metrics", include_in_schema=False)
async def prometheus_metrics():
    """Prometheus metrics endpoint."""
    if db:
        update_certificate_metrics(db, config)
    return Response(content=get_metrics_output(), media_type=get_metrics_content_type())


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
    
    # Expiring soon (7/30/90 days)
    cursor.execute("""
        SELECT COUNT(DISTINCT c.id)
        FROM certificates c
        WHERE julianday(c.not_after) - julianday('now') <= 7
        AND julianday(c.not_after) - julianday('now') > 0
    """)
    expiring_7 = cursor.fetchone()[0]
    cursor.execute("""
        SELECT COUNT(DISTINCT c.id)
        FROM certificates c
        WHERE julianday(c.not_after) - julianday('now') <= 30
        AND julianday(c.not_after) - julianday('now') > 0
    """)
    expiring_30 = cursor.fetchone()[0]
    cursor.execute("""
        SELECT COUNT(DISTINCT c.id)
        FROM certificates c
        WHERE julianday(c.not_after) - julianday('now') <= 90
        AND julianday(c.not_after) - julianday('now') > 0
    """)
    expiring_90 = cursor.fetchone()[0]
    
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

    # Last scan
    cursor.execute("""
        SELECT scanned_at, status
        FROM certificate_scans
        ORDER BY scanned_at DESC
        LIMIT 1
    """)
    last_scan = cursor.fetchone()
    last_scan_at = last_scan['scanned_at'] if last_scan else None
    last_scan_status = last_scan['status'] if last_scan else None

    # Weak keys (RSA < 2048, EC < 256, DSA < 2048)
    cursor.execute("""
        SELECT COUNT(DISTINCT id)
        FROM certificates
        WHERE (
            (key_type = 'RSA' AND key_size IS NOT NULL AND key_size < 2048) OR
            (key_type = 'EC' AND key_size IS NOT NULL AND key_size < 256) OR
            (key_type = 'DSA' AND key_size IS NOT NULL AND key_size < 2048)
        )
    """)
    weak_keys = cursor.fetchone()[0]

    # Legacy TLS (latest scan per endpoint with TLS < 1.2)
    cursor.execute("""
        WITH latest_scans AS (
            SELECT cs.*
            FROM certificate_scans cs
            JOIN (
                SELECT endpoint_id, MAX(scanned_at) AS max_scanned
                FROM certificate_scans
                GROUP BY endpoint_id
            ) ls
            ON cs.endpoint_id = ls.endpoint_id AND cs.scanned_at = ls.max_scanned
        )
        SELECT COUNT(*) FROM latest_scans
        WHERE tls_version IN ('TLSv1', 'TLSv1.1')
    """)
    legacy_tls = cursor.fetchone()[0]

    # Certificate changes in last 24h (latest cert differs from previous per endpoint)
    cursor.execute("""
        WITH ordered AS (
            SELECT
                endpoint_id,
                certificate_id,
                scanned_at,
                ROW_NUMBER() OVER (PARTITION BY endpoint_id ORDER BY scanned_at DESC) AS rn,
                LAG(certificate_id) OVER (PARTITION BY endpoint_id ORDER BY scanned_at DESC) AS prev_cert_id
            FROM certificate_scans
        )
        SELECT COUNT(*) FROM ordered
        WHERE rn = 1
          AND prev_cert_id IS NOT NULL
          AND certificate_id != prev_cert_id
          AND julianday('now') - julianday(scanned_at) <= 1
    """)
    cert_changes_24h = cursor.fetchone()[0]
    
    return DashboardStats(
        total_certificates=total_certs,
        total_endpoints=total_endpoints,
        expiring_7=expiring_7,
        expiring_30=expiring_30,
        expiring_90=expiring_90,
        expired=expired,
        self_signed=self_signed,
        untrusted=untrusted,
        last_scan_at=last_scan_at,
        last_scan_status=last_scan_status,
        weak_keys=weak_keys,
        legacy_tls=legacy_tls,
        cert_changes_24h=cert_changes_24h
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
            c.hostname_matches,
            c.ocsp_present,
            c.crl_present,
            c.eku_server_auth,
            c.key_usage_digital_signature,
            c.key_usage_key_encipherment,
            c.chain_has_expiring,
            c.weak_signature,
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


@app.get("/api/settings/scanner")
async def get_scanner_settings(user: User = Depends(require_auth)):
    """Get scanner settings"""
    scanner_config = config.get("scanner", {}) if config else {}
    return {
        "interval_seconds": scanner_config.get("interval_seconds", 3600),
        "timeout_seconds": scanner_config.get("timeout_seconds", 10),
        "max_concurrent": scanner_config.get("max_concurrent", 10)
    }


@app.put("/api/settings/scanner")
async def update_scanner_settings(
    settings: ScannerSettingsUpdate,
    request: Request,
    user: User = Depends(require_admin)
):
    """Update scanner settings (admin only)"""
    if not config:
        raise HTTPException(status_code=500, detail="Configuration not loaded")

    if settings.interval_seconds is None:
        raise HTTPException(status_code=400, detail="No settings provided")

    interval = int(settings.interval_seconds)
    if interval < 10 or interval > 86400:
        raise HTTPException(status_code=400, detail="interval_seconds must be between 10 and 86400")

    config.setdefault("scanner", {})
    config["scanner"]["interval_seconds"] = interval

    try:
        with open(CONFIG_PATH, "w") as f:
            yaml.safe_dump(config, f, sort_keys=False)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write config: {e}")

    audit_log(
        user_email=user.email,
        action="scanner_settings_update",
        resource_type="settings",
        resource_id=None,
        details=f"Updated scanner interval to {interval} seconds",
        ip_address=get_client_ip(request)
    )

    return {
        "interval_seconds": interval,
        "timeout_seconds": config["scanner"].get("timeout_seconds", 10),
        "max_concurrent": config["scanner"].get("max_concurrent", 10)
    }


@app.get("/api/settings/db-health", response_model=DbHealth)
async def get_db_health(admin: User = Depends(require_admin)):
    """Get database health and size stats (admin only)"""
    if not config:
        raise HTTPException(status_code=500, detail="Configuration not loaded")

    db_path = Path(__file__).parent.parent / config['database']['path']
    db_size_bytes = db_path.stat().st_size if db_path.exists() else 0

    cursor = db.conn.cursor()
    tables = [
        "certificates",
        "certificate_scans",
        "endpoints",
        "sweeps",
        "sweep_results",
        "trusted_cas",
        "notifications",
        "audit_log"
    ]
    counts: Dict[str, int] = {}
    for table in tables:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            counts[table] = cursor.fetchone()[0]
        except Exception:
            counts[table] = 0

    try:
        cursor.execute("SELECT COUNT(*) FROM certificate_scans WHERE julianday('now') - julianday(scanned_at) <= 30")
        scans_last_30_days = cursor.fetchone()[0]
    except Exception:
        scans_last_30_days = 0

    try:
        cursor.execute("PRAGMA page_size")
        page_size = cursor.fetchone()[0]
        cursor.execute("PRAGMA page_count")
        page_count = cursor.fetchone()[0]
        cursor.execute("PRAGMA freelist_count")
        freelist_count = cursor.fetchone()[0]
    except Exception:
        page_size = 0
        page_count = 0
        freelist_count = 0

    return DbHealth(
        db_size_bytes=db_size_bytes,
        page_size=page_size,
        page_count=page_count,
        freelist_count=freelist_count,
        approx_db_bytes=page_size * page_count,
        approx_free_bytes=page_size * freelist_count,
        counts=counts,
        scans_last_30_days=scans_last_30_days
    )


@app.get("/api/settings/siem", response_model=SiemSettings)
async def get_siem_settings(admin: User = Depends(require_admin)):
    """Get SIEM forwarding settings (admin only)"""
    siem = (config or {}).get("siem", {}) if config else {}
    return SiemSettings(
        mode=siem.get("mode", "disabled"),
        host=siem.get("host"),
        port=siem.get("port"),
        tls_enabled=siem.get("tls_enabled", True),
        tls_verify=siem.get("tls_verify", True),
        ca_pem=siem.get("ca_pem"),
        client_cert_pem=siem.get("client_cert_pem"),
        client_key_pem=siem.get("client_key_pem")
    )


@app.put("/api/settings/siem", response_model=SiemSettings)
async def update_siem_settings(
    settings: SiemSettings,
    request: Request,
    admin: User = Depends(require_admin)
):
    """Update SIEM forwarding settings (admin only)"""
    if not config:
        raise HTTPException(status_code=500, detail="Configuration not loaded")

    mode = settings.mode.lower()
    if mode not in {"disabled", "stdout", "syslog", "beats"}:
        raise HTTPException(status_code=400, detail="mode must be disabled, stdout, syslog, or beats")

    if mode in {"syslog", "beats"}:
        if not settings.host or not settings.port:
            raise HTTPException(status_code=400, detail="host and port are required for syslog or beats")
        if settings.port <= 0 or settings.port > 65535:
            raise HTTPException(status_code=400, detail="port must be between 1 and 65535")

    config["siem"] = {
        "mode": mode,
        "host": settings.host,
        "port": settings.port,
        "tls_enabled": bool(settings.tls_enabled),
        "tls_verify": bool(settings.tls_verify),
        "ca_pem": settings.ca_pem,
        "client_cert_pem": settings.client_cert_pem,
        "client_key_pem": settings.client_key_pem
    }

    try:
        with open(CONFIG_PATH, "w") as f:
            yaml.safe_dump(config, f, sort_keys=False)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write config: {e}")

    audit_log(
        user_email=admin.email,
        action="siem_settings_update",
        resource_type="settings",
        resource_id=None,
        details=f"Updated SIEM settings: mode={mode}",
        ip_address=get_client_ip(request)
    )

    if siem_client:
        siem_client.configure(config["siem"])

    return SiemSettings(**config["siem"])


@app.post("/api/settings/siem/test")
async def test_siem_settings(
    body: SiemTestRequest,
    request: Request,
    admin: User = Depends(require_admin)
):
    """Send a test SIEM event (admin only)"""
    if not siem_client:
        raise HTTPException(status_code=500, detail="SIEM client not initialized")

    event = {
        "audit_id": None,
        "user_email": admin.email,
        "action": "siem_test",
        "resource_type": "settings",
        "resource_id": None,
        "details": body.message,
        "ip_address": get_client_ip(request),
        "created_at": datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
    }
    ok = siem_client.send_event(event)
    if not ok:
        raise HTTPException(status_code=502, detail="Failed to send test event to SIEM")
    return {"status": "sent"}


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
    # Parse SAN list JSON if present
    if cert_dict.get('san_list'):
        try:
            import json
            cert_dict['san_list'] = json.loads(cert_dict['san_list'])
        except Exception:
            pass
    
    # Get endpoints
    cursor.execute("""
        SELECT e.*, cs.scanned_at, cs.status, cs.tls_version, cs.cipher
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
async def get_endpoints(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
):
    """Get all monitored endpoints"""
    # Optional auth — used to decide if webhook URLs should be unmasked
    current_user = await get_current_user(request, credentials)

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

        cursor.execute("""
            SELECT cs.scanned_at, cs.status
            FROM certificate_scans cs
            WHERE cs.endpoint_id = ?
            ORDER BY cs.scanned_at DESC
            LIMIT 12
        """, (endpoint['id'],))
        endpoint['recent_scans'] = [dict(scan) for scan in cursor.fetchall()]

        # Mask webhook URL — only owner or admin sees full URL
        endpoint['webhook_url_masked'] = mask_webhook_url(endpoint.get('webhook_url'))
        is_owner = (
            current_user
            and endpoint.get('created_by')
            and endpoint['created_by'] == current_user.email
        )
        is_admin_user = current_user and current_user.has_role("admin")
        if not (is_owner or is_admin_user):
            endpoint['webhook_url'] = None

    return {"endpoints": endpoints}


# Get full webhook URL for an endpoint (owner/admin only)
@app.get("/api/endpoints/{endpoint_id}/webhook")
async def get_endpoint_webhook(
    endpoint_id: int,
    user: User = Depends(require_editor)
):
    """Get the full (unmasked) webhook URL for an endpoint.

    Requires editor role and ownership or admin.
    """
    cursor = db.conn.cursor()
    cursor.execute("SELECT * FROM endpoints WHERE id = ?", (endpoint_id,))
    endpoint = cursor.fetchone()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    endpoint_dict = dict(endpoint)
    is_owner = (
        endpoint_dict.get('created_by')
        and endpoint_dict['created_by'] == user.email
    )
    if not (is_owner or user.has_role("admin")):
        raise HTTPException(status_code=403, detail="Only the owner or an admin can view the webhook URL")

    return {"webhook_url": endpoint_dict.get('webhook_url')}


# Create endpoint
@app.post("/api/endpoints")
async def create_endpoint(
    endpoint: EndpointCreate,
    request: Request,
    user: User = Depends(require_editor)
):
    """Add new endpoint to monitor (editor+)"""
    # If endpoint exists, only creator or admin can modify it via create
    cursor = db.conn.cursor()
    cursor.execute("SELECT * FROM endpoints WHERE host = ? AND port = ?", (endpoint.host, endpoint.port))
    existing = cursor.fetchone()
    if existing:
        existing_dict = dict(existing)
        if existing_dict.get('created_by') and existing_dict['created_by'] != user.email and not user.has_role("admin"):
            raise HTTPException(status_code=403, detail="Only the creator or an admin can modify this endpoint")

    endpoint_id = db.add_endpoint(
        host=endpoint.host,
        port=endpoint.port,
        owner=endpoint.owner,
        criticality=endpoint.criticality,
        created_by=user.email,
        webhook_url=endpoint.webhook_url
    )

    # Audit log
    audit_log(
        user_email=user.email,
        action="endpoint_create",
        resource_type="endpoint",
        resource_id=endpoint_id,
        details=f"Created endpoint {endpoint.host}:{endpoint.port}",
        ip_address=get_client_ip(request)
    )

    return {"id": endpoint_id, "message": "Endpoint created successfully"}


# Update endpoint
@app.put("/api/endpoints/{endpoint_id}")
async def update_endpoint(
    endpoint_id: int,
    update: EndpointUpdate,
    request: Request,
    user: User = Depends(require_editor)
):
    """Update endpoint information (editor+)"""
    cursor = db.conn.cursor()

    # Check if endpoint exists
    cursor.execute("SELECT * FROM endpoints WHERE id = ?", (endpoint_id,))
    endpoint = cursor.fetchone()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    endpoint_dict = dict(endpoint)
    if endpoint_dict.get('created_by') and endpoint_dict['created_by'] != user.email and not user.has_role("admin"):
        raise HTTPException(status_code=403, detail="Only the creator or an admin can modify this endpoint")

    # Update
    updates = []
    params = []
    changes = []

    if update.owner is not None:
        updates.append("owner = ?")
        params.append(update.owner)
        changes.append(f"owner→{update.owner}")

    if update.criticality is not None:
        updates.append("criticality = ?")
        params.append(update.criticality)
        changes.append(f"criticality→{update.criticality}")

    if update.webhook_url is not None:
        updates.append("webhook_url = ?")
        params.append(update.webhook_url if update.webhook_url else None)
        changes.append(f"webhook→{'set' if update.webhook_url else 'cleared'}")

    if updates:
        query = f"UPDATE endpoints SET {', '.join(updates)} WHERE id = ?"
        params.append(endpoint_id)
        cursor.execute(query, params)
        db.conn.commit()

        # Audit log
        audit_log(
            user_email=user.email,
            action="endpoint_update",
            resource_type="endpoint",
            resource_id=endpoint_id,
            details=f"Updated {endpoint_dict['host']}:{endpoint_dict['port']}: {', '.join(changes)}",
            ip_address=get_client_ip(request)
        )

    return {"message": "Endpoint updated successfully"}


# Delete endpoint
@app.delete("/api/endpoints/{endpoint_id}")
async def delete_endpoint(
    endpoint_id: int,
    request: Request,
    user: User = Depends(require_editor)
):
    """Delete endpoint and clean up orphaned certificates (editor+)"""
    cursor = db.conn.cursor()

    # Check if endpoint exists
    cursor.execute("SELECT * FROM endpoints WHERE id = ?", (endpoint_id,))
    endpoint = cursor.fetchone()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    endpoint_dict = dict(endpoint)
    if endpoint_dict.get('created_by') and endpoint_dict['created_by'] != user.email and not user.has_role("admin"):
        raise HTTPException(status_code=403, detail="Only the creator or an admin can delete this endpoint")

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

    # Audit log
    audit_log(
        user_email=user.email,
        action="endpoint_delete",
        resource_type="endpoint",
        resource_id=endpoint_id,
        details=f"Deleted endpoint {endpoint_dict['host']}:{endpoint_dict['port']}",
        ip_address=get_client_ip(request)
    )

    return {
        "message": "Endpoint deleted successfully",
        "orphaned_certificates_deleted": len(orphaned_cert_ids)
    }


# Trigger scan
@app.post("/api/scan")
async def trigger_scan(
    background_tasks: BackgroundTasks,
    scan_request: ScanRequest,
    request: Request,
    user: User = Depends(require_editor)
):
    """Trigger certificate scan (editor+)"""
    
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
                    key_type=cert_info.key_type,
                    key_size=cert_info.key_size,
                    signature_algorithm=cert_info.signature_algorithm,
                    hostname_matches=cert_info.hostname_matches,
                    ocsp_present=cert_info.ocsp_present,
                    crl_present=cert_info.crl_present,
                    eku_server_auth=cert_info.eku_server_auth,
                    key_usage_digital_signature=cert_info.key_usage_digital_signature,
                    key_usage_key_encipherment=cert_info.key_usage_key_encipherment,
                    chain_has_expiring=cert_info.chain_has_expiring,
                    weak_signature=cert_info.weak_signature,
                    is_self_signed=cert_info.is_self_signed,
                    is_trusted_ca=cert_info.is_trusted_ca,
                    validation_error=cert_info.validation_error,
                    chain_length=cert_info.chain_length
                )
                db.add_scan(
                    cert_id, endpoint_id, 'success',
                    tls_version=cert_info.tls_version,
                    cipher=cert_info.cipher
                )
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
                        key_type=cert_info.key_type,
                        key_size=cert_info.key_size,
                        signature_algorithm=cert_info.signature_algorithm,
                        hostname_matches=cert_info.hostname_matches,
                        ocsp_present=cert_info.ocsp_present,
                        crl_present=cert_info.crl_present,
                        eku_server_auth=cert_info.eku_server_auth,
                        key_usage_digital_signature=cert_info.key_usage_digital_signature,
                        key_usage_key_encipherment=cert_info.key_usage_key_encipherment,
                        chain_has_expiring=cert_info.chain_has_expiring,
                        weak_signature=cert_info.weak_signature,
                        is_self_signed=cert_info.is_self_signed,
                        is_trusted_ca=cert_info.is_trusted_ca,
                        validation_error=cert_info.validation_error,
                        chain_length=cert_info.chain_length
                    )
                    db.add_scan(
                        cert_id, endpoint['id'], 'success',
                        tls_version=cert_info.tls_version,
                        cipher=cert_info.cipher
                    )

        # Clean up orphaned certificates after scan
        db.cleanup_orphaned_certificates()

    background_tasks.add_task(do_scan, scan_request.endpoint_id)

    # Audit log
    audit_log(
        user_email=user.email,
        action="scan_trigger",
        resource_type="endpoint" if scan_request.endpoint_id else None,
        resource_id=scan_request.endpoint_id,
        details=f"Triggered scan for {'endpoint ' + str(scan_request.endpoint_id) if scan_request.endpoint_id else 'all endpoints'}",
        ip_address=get_client_ip(request)
    )

    return {
        "message": "Scan initiated",
        "endpoint_id": scan_request.endpoint_id if scan_request.endpoint_id else "all"
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
async def send_test_notification(
    request: Request,
    user: User = Depends(require_editor)
):
    """Send test notification to Mattermost (editor+)"""
    if not notifier:
        raise HTTPException(status_code=400, detail="Mattermost not configured")

    success = notifier.test_connection()

    # Audit log
    audit_log(
        user_email=user.email,
        action="notification_test",
        details=f"Test notification {'succeeded' if success else 'failed'}",
        ip_address=get_client_ip(request)
    )

    if success:
        return {"message": "Test notification sent successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to send notification")


# Test webhook URL
@app.post("/api/webhooks/test")
async def test_webhook(
    webhook_request: WebhookTest,
    request: Request,
    user: User = Depends(require_editor)
):
    """Test a webhook URL (editor+)"""
    import requests as http_requests

    try:
        payload = {
            "text": webhook_request.message,
            "username": "Certificate Guardian",
            "icon_emoji": ":lock:"
        }
        response = http_requests.post(webhook_request.webhook_url, json=payload, timeout=10)

        if response.status_code == 200:
            return {"success": True, "message": "Webhook test successful"}
        else:
            return {"success": False, "message": f"Webhook returned status {response.status_code}"}
    except http_requests.exceptions.Timeout:
        return {"success": False, "message": "Webhook request timed out"}
    except http_requests.exceptions.RequestException as e:
        return {"success": False, "message": f"Webhook error: {str(e)}"}


# ===== Trusted CA Management =====

@app.get("/api/trusted-cas")
async def get_trusted_cas():
    """Get all trusted CA certificates"""
    cas = db.get_all_trusted_cas()
    return {"trusted_cas": cas, "total": len(cas)}


@app.post("/api/trusted-cas")
async def add_trusted_ca(
    ca: TrustedCACreate,
    request: Request,
    user: User = Depends(require_editor)
):
    """Add a trusted CA certificate or CA bundle (editor+)"""
    import hashlib
    import re
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization

    try:
        pem_data = ca.pem_data.strip()
        if "-----BEGIN CERTIFICATE-----" not in pem_data:
            raise HTTPException(status_code=400, detail="Invalid PEM format")

        # Split PEM bundle into individual certificates
        pem_blocks = re.findall(
            r'(-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----)',
            pem_data
        )

        if not pem_blocks:
            raise HTTPException(status_code=400, detail="No valid PEM certificates found")

        added = []
        for i, pem_block in enumerate(pem_blocks):
            pem_block = pem_block.strip()
            cert = x509.load_pem_x509_certificate(pem_block.encode(), default_backend())

            fingerprint = hashlib.sha256(cert.public_bytes(
                encoding=serialization.Encoding.DER
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

            # Use subject CN as name for bundle certs, fallback to indexed name
            if len(pem_blocks) == 1:
                cert_name = ca.name
            else:
                try:
                    cn = cert.subject.get_attributes_for_oid(
                        x509.NameOID.COMMON_NAME
                    )[0].value
                    cert_name = cn
                except Exception:
                    cert_name = f"{ca.name} ({i+1})"

            ca_id = db.add_trusted_ca(
                name=cert_name,
                pem_data=pem_block,
                fingerprint=fingerprint,
                subject=subject,
                issuer=issuer,
                not_after=not_after
            )

            added.append({
                "id": ca_id,
                "fingerprint": fingerprint,
                "subject": subject
            })

        # Refresh scanner's CA list and outbound TLS bundle
        custom_pems = db.get_all_trusted_ca_pems()
        scanner.set_custom_cas(custom_pems)
        update_ca_bundle(custom_pems)

        # Audit log
        if len(added) == 1:
            details = f"Added trusted CA '{ca.name}'"
        else:
            details = f"Added {len(added)} CA certificates from bundle '{ca.name}'"

        audit_log(
            user_email=user.email,
            action="ca_create",
            resource_type="trusted_ca",
            resource_id=added[0]["id"],
            details=details,
            ip_address=get_client_ip(request)
        )

        if len(added) == 1:
            return {
                "id": added[0]["id"],
                "fingerprint": added[0]["fingerprint"],
                "subject": added[0]["subject"],
                "message": "Trusted CA added successfully"
            }
        else:
            return {
                "certificates": added,
                "total": len(added),
                "message": f"Added {len(added)} CA certificates from bundle"
            }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid certificate: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing certificate: {str(e)}")


@app.delete("/api/trusted-cas/{ca_id}")
async def delete_trusted_ca(
    ca_id: int,
    request: Request,
    user: User = Depends(require_editor)
):
    """Delete a trusted CA certificate (editor+)"""
    # Get CA info before deleting for audit log
    cas = db.get_all_trusted_cas()
    ca_info = next((c for c in cas if c['id'] == ca_id), None)

    if db.delete_trusted_ca(ca_id):
        # Refresh scanner's CA list and outbound TLS bundle
        custom_pems = db.get_all_trusted_ca_pems()
        scanner.set_custom_cas(custom_pems)
        update_ca_bundle(custom_pems)

        # Audit log
        audit_log(
            user_email=user.email,
            action="ca_delete",
            resource_type="trusted_ca",
            resource_id=ca_id,
            details=f"Deleted trusted CA '{ca_info['name'] if ca_info else 'unknown'}'",
            ip_address=get_client_ip(request)
        )

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
async def create_sweep(
    sweep: SweepCreate,
    background_tasks: BackgroundTasks,
    request: Request,
    user: User = Depends(require_editor)
):
    """Create and execute a new network sweep (editor+)"""
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
        webhook_url=sweep.webhook_url,
        created_by=user.email
    )

    # Set initial progress
    total_scans = ip_count * len(sweep.ports)
    db.update_sweep_status(sweep_id, "pending", progress_total=total_scans)

    # Start sweep in background
    background_tasks.add_task(execute_sweep, sweep_id)

    # Audit log
    audit_log(
        user_email=user.email,
        action="sweep_create",
        resource_type="sweep",
        resource_id=sweep_id,
        details=f"Started network sweep '{sweep.name}' on {sweep.target}",
        ip_address=get_client_ip(request)
    )

    return {"id": sweep_id, "message": "Sweep started", "total_scans": total_scans}


@app.post("/api/sweeps/{sweep_id}/restart")
async def restart_sweep(
    sweep_id: int,
    background_tasks: BackgroundTasks,
    request: Request,
    user: User = Depends(require_editor)
):
    """Restart a sweep by clearing previous results and re-running it (editor+)"""
    sweep = db.get_sweep(sweep_id)
    if not sweep:
        raise HTTPException(status_code=404, detail="Sweep not found")

    if sweep.get('created_by') and sweep['created_by'] != user.email and not user.has_role("admin"):
        raise HTTPException(status_code=403, detail="Only the creator or an admin can restart this sweep")

    if sweep['status'] == 'running':
        raise HTTPException(status_code=400, detail="Cannot restart a running sweep")

    # Recalculate total scans
    import json
    from network_scanner import validate_target

    valid, error, ip_count = validate_target(sweep['target'])
    if not valid:
        raise HTTPException(status_code=400, detail=error)

    ports = json.loads(sweep['ports'])
    total_scans = ip_count * len(ports)

    # Reset sweep and clear results
    db.reset_sweep(sweep_id, total_scans=total_scans)

    # Start sweep in background
    background_tasks.add_task(execute_sweep, sweep_id)

    # Audit log
    audit_log(
        user_email=user.email,
        action="sweep_restart",
        resource_type="sweep",
        resource_id=sweep_id,
        details=f"Restarted network sweep '{sweep['name']}'",
        ip_address=get_client_ip(request)
    )

    return {"id": sweep_id, "message": "Sweep restarted", "total_scans": total_scans}


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
                criticality=sweep['criticality'],
                created_by=sweep.get('created_by')
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
                    key_type=cert_info.key_type,
                    key_size=cert_info.key_size,
                    signature_algorithm=cert_info.signature_algorithm,
                    hostname_matches=cert_info.hostname_matches,
                    ocsp_present=cert_info.ocsp_present,
                    crl_present=cert_info.crl_present,
                    eku_server_auth=cert_info.eku_server_auth,
                    key_usage_digital_signature=cert_info.key_usage_digital_signature,
                    key_usage_key_encipherment=cert_info.key_usage_key_encipherment,
                    chain_has_expiring=cert_info.chain_has_expiring,
                    weak_signature=cert_info.weak_signature,
                    is_self_signed=cert_info.is_self_signed,
                    is_trusted_ca=cert_info.is_trusted_ca,
                    validation_error=cert_info.validation_error,
                    chain_length=cert_info.chain_length
                )
                db.add_scan(
                    cert_id, endpoint_id, 'success',
                    tls_version=cert_info.tls_version,
                    cipher=cert_info.cipher
                )

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
async def delete_sweep(
    sweep_id: int,
    request: Request,
    user: User = Depends(require_editor)
):
    """Delete a sweep and its results (editor+)"""
    # Check if sweep is running
    sweep = db.get_sweep(sweep_id)
    if not sweep:
        raise HTTPException(status_code=404, detail="Sweep not found")

    if sweep.get('created_by') and sweep['created_by'] != user.email and not user.has_role("admin"):
        raise HTTPException(status_code=403, detail="Only the creator or an admin can delete this sweep")

    if sweep['status'] == 'running':
        raise HTTPException(status_code=400, detail="Cannot delete running sweep")

    sweep_name = sweep['name']
    if db.delete_sweep(sweep_id):
        # Audit log
        audit_log(
            user_email=user.email,
            action="sweep_delete",
            resource_type="sweep",
            resource_id=sweep_id,
            details=f"Deleted sweep '{sweep_name}'",
            ip_address=get_client_ip(request)
        )
        return {"message": "Sweep deleted"}
    raise HTTPException(status_code=404, detail="Sweep not found")


# ===== Audit Log Endpoints =====

@app.get("/api/audit-logs")
async def get_audit_logs(
    limit: int = 100,
    offset: int = 0,
    user_email: Optional[str] = None,
    action: Optional[str] = None,
    admin: User = Depends(require_admin)
):
    """Get audit logs (admin only)"""
    logs = db.get_audit_logs(
        limit=limit,
        offset=offset,
        user_email=user_email,
        action=action
    )
    return {"logs": logs, "total": len(logs), "limit": limit, "offset": offset}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
