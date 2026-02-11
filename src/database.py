#!/usr/bin/env python3
"""
Database models for Certificate Guardian
"""
import sqlite3
import os
from datetime import datetime, timezone
from typing import Optional, List, Dict
def _bool_or_none(value):
    if value is None:
        return None
    return 1 if value else 0
import json


class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = None
        self._init_db()

    def _init_db(self):
        """Initialize database schema"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        
        cursor = self.conn.cursor()
        
        # Certificates table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT UNIQUE NOT NULL,
                subject TEXT NOT NULL,
                issuer TEXT NOT NULL,
                not_before TEXT NOT NULL,
                not_after TEXT NOT NULL,
                serial_number TEXT,
                san_list TEXT,
                key_type TEXT,
                key_size INTEGER,
                signature_algorithm TEXT,
                hostname_matches INTEGER,
                ocsp_present INTEGER,
                crl_present INTEGER,
                eku_server_auth INTEGER,
                key_usage_digital_signature INTEGER,
                key_usage_key_encipherment INTEGER,
                chain_has_expiring INTEGER,
                weak_signature INTEGER,
                is_self_signed INTEGER DEFAULT 0,
                is_trusted_ca INTEGER DEFAULT 0,
                validation_error TEXT,
                chain_length INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        
        # Endpoints table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                owner TEXT,
                criticality TEXT DEFAULT 'medium',
                webhook_url TEXT,
                created_by TEXT,
                UNIQUE(host, port)
            )
        """)

        # Try to add webhook_url column if it doesn't exist (migration)
        try:
            cursor.execute("ALTER TABLE endpoints ADD COLUMN webhook_url TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
        try:
            cursor.execute("ALTER TABLE endpoints ADD COLUMN created_by TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists

        # Trusted CAs table (custom root certificates)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS trusted_cas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                pem_data TEXT NOT NULL,
                fingerprint TEXT UNIQUE NOT NULL,
                subject TEXT NOT NULL,
                issuer TEXT NOT NULL,
                not_after TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        
        # Certificate scans table (tracks where certs are found)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS certificate_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                certificate_id INTEGER NOT NULL,
                endpoint_id INTEGER NOT NULL,
                scanned_at TEXT NOT NULL,
                status TEXT NOT NULL,
                error_message TEXT,
                tls_version TEXT,
                cipher TEXT,
                FOREIGN KEY (certificate_id) REFERENCES certificates(id),
                FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
            )
        """)

        # Migrations for new certificate fields
        for col_def in [
            "key_type TEXT",
            "key_size INTEGER",
            "signature_algorithm TEXT",
            "hostname_matches INTEGER",
            "ocsp_present INTEGER",
            "crl_present INTEGER",
            "eku_server_auth INTEGER",
            "key_usage_digital_signature INTEGER",
            "key_usage_key_encipherment INTEGER",
            "chain_has_expiring INTEGER",
            "weak_signature INTEGER",
        ]:
            try:
                cursor.execute(f"ALTER TABLE certificates ADD COLUMN {col_def}")
            except sqlite3.OperationalError:
                pass  # Column already exists

        # Migrations for scan metadata
        for col_def in [
            "tls_version TEXT",
            "cipher TEXT",
        ]:
            try:
                cursor.execute(f"ALTER TABLE certificate_scans ADD COLUMN {col_def}")
            except sqlite3.OperationalError:
                pass  # Column already exists
        
        # Notifications table (track what we've already sent)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                certificate_id INTEGER NOT NULL,
                endpoint_id INTEGER NOT NULL,
                days_until_expiry INTEGER NOT NULL,
                sent_at TEXT NOT NULL,
                notification_type TEXT NOT NULL,
                FOREIGN KEY (certificate_id) REFERENCES certificates(id),
                FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
            )
        """)

        # Network sweeps table (IP range scanning configurations)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sweeps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                target TEXT NOT NULL,
                ports TEXT NOT NULL,
                owner TEXT,
                criticality TEXT DEFAULT 'medium',
                webhook_url TEXT,
                created_by TEXT,
                status TEXT DEFAULT 'pending',
                progress_total INTEGER DEFAULT 0,
                progress_scanned INTEGER DEFAULT 0,
                progress_found INTEGER DEFAULT 0,
                started_at TEXT,
                completed_at TEXT,
                created_at TEXT NOT NULL,
                error_message TEXT
            )
        """)
        try:
            cursor.execute("ALTER TABLE sweeps ADD COLUMN created_by TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists

        # Sweep results table (individual scan results)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sweep_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sweep_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                port INTEGER NOT NULL,
                status TEXT NOT NULL,
                endpoint_id INTEGER,
                scanned_at TEXT NOT NULL,
                FOREIGN KEY (sweep_id) REFERENCES sweeps(id),
                FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
            )
        """)

        # Users table (for local auth mode)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'viewer',
                is_active INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        # Refresh tokens table (for remember me functionality)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        # Audit log table (for tracking user actions)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT,
                resource_id INTEGER,
                details TEXT,
                ip_address TEXT,
                created_at TEXT NOT NULL
            )
        """)

        self.conn.commit()
    
    def add_endpoint(self, host: str, port: int, owner: str = None,
                     criticality: str = "medium", created_by: str = None,
                     webhook_url: str = None) -> int:
        """Add or update an endpoint"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO endpoints (host, port, owner, criticality, created_by, webhook_url)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(host, port) DO UPDATE SET
                owner = excluded.owner,
                criticality = excluded.criticality,
                webhook_url = excluded.webhook_url
        """, (host, port, owner, criticality, created_by, webhook_url))
        self.conn.commit()
        return cursor.lastrowid
    
    def add_certificate(self, fingerprint: str, subject: str, issuer: str,
                       not_before: str, not_after: str, serial_number: str = None,
                       san_list: List[str] = None, key_type: str = None,
                       key_size: int = None, signature_algorithm: str = None,
                       hostname_matches: bool = None, ocsp_present: bool = None,
                       crl_present: bool = None, eku_server_auth: bool = None,
                       key_usage_digital_signature: bool = None,
                       key_usage_key_encipherment: bool = None,
                       chain_has_expiring: bool = None,
                       weak_signature: bool = None,
                       is_self_signed: bool = False, is_trusted_ca: bool = False,
                       validation_error: str = None, chain_length: int = 0) -> int:
        """Add or update a certificate"""
        cursor = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        san_json = json.dumps(san_list) if san_list else None

        cursor.execute("""
            INSERT INTO certificates (
                fingerprint, subject, issuer, not_before, not_after,
                serial_number, san_list, key_type, key_size, signature_algorithm,
                hostname_matches, ocsp_present, crl_present, eku_server_auth,
                key_usage_digital_signature, key_usage_key_encipherment,
                chain_has_expiring, weak_signature,
                is_self_signed, is_trusted_ca, validation_error, chain_length,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                subject = excluded.subject,
                issuer = excluded.issuer,
                not_before = excluded.not_before,
                not_after = excluded.not_after,
                serial_number = excluded.serial_number,
                san_list = excluded.san_list,
                key_type = excluded.key_type,
                key_size = excluded.key_size,
                signature_algorithm = excluded.signature_algorithm,
                hostname_matches = excluded.hostname_matches,
                ocsp_present = excluded.ocsp_present,
                crl_present = excluded.crl_present,
                eku_server_auth = excluded.eku_server_auth,
                key_usage_digital_signature = excluded.key_usage_digital_signature,
                key_usage_key_encipherment = excluded.key_usage_key_encipherment,
                chain_has_expiring = excluded.chain_has_expiring,
                weak_signature = excluded.weak_signature,
                is_self_signed = excluded.is_self_signed,
                is_trusted_ca = excluded.is_trusted_ca,
                validation_error = excluded.validation_error,
                chain_length = excluded.chain_length,
                updated_at = excluded.updated_at
        """, (fingerprint, subject, issuer, not_before, not_after,
              serial_number, san_json, key_type, key_size, signature_algorithm,
              _bool_or_none(hostname_matches), _bool_or_none(ocsp_present),
              _bool_or_none(crl_present), _bool_or_none(eku_server_auth),
              _bool_or_none(key_usage_digital_signature), _bool_or_none(key_usage_key_encipherment),
              _bool_or_none(chain_has_expiring), _bool_or_none(weak_signature),
              int(is_self_signed), int(is_trusted_ca), validation_error,
              chain_length, now, now))
        self.conn.commit()

        # Get the actual certificate ID (lastrowid is unreliable with ON CONFLICT)
        cursor.execute("SELECT id FROM certificates WHERE fingerprint = ?", (fingerprint,))
        return cursor.fetchone()[0]
    
    def add_scan(self, certificate_id: int, endpoint_id: int, 
                 status: str, error_message: str = None,
                 tls_version: str = None, cipher: str = None) -> int:
        """Record a certificate scan"""
        cursor = self.conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        cursor.execute("""
            INSERT INTO certificate_scans (
                certificate_id, endpoint_id, scanned_at, status, error_message,
                tls_version, cipher
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (certificate_id, endpoint_id, now, status, error_message, tls_version, cipher))
        self.conn.commit()
        return cursor.lastrowid
    
    def add_notification(self, certificate_id: int, endpoint_id: int,
                        days_until_expiry: int, notification_type: str) -> int:
        """Record a sent notification"""
        cursor = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        
        cursor.execute("""
            INSERT INTO notifications (
                certificate_id, endpoint_id, days_until_expiry,
                sent_at, notification_type
            )
            VALUES (?, ?, ?, ?, ?)
        """, (certificate_id, endpoint_id, days_until_expiry, now, notification_type))
        self.conn.commit()
        return cursor.lastrowid
    
    def get_expiring_certificates(self, days: int) -> List[Dict]:
        """Get certificates expiring within specified days"""
        cursor = self.conn.cursor()
        
        query = """
            SELECT 
                c.id,
                c.fingerprint,
                c.subject,
                c.issuer,
                c.not_after,
                e.host,
                e.port,
                e.owner,
                e.criticality,
                julianday(c.not_after) - julianday('now') as days_until_expiry
            FROM certificates c
            JOIN certificate_scans cs ON c.id = cs.certificate_id
            JOIN endpoints e ON cs.endpoint_id = e.id
            WHERE cs.status = 'success'
            AND cs.scanned_at = (
                SELECT MAX(scanned_at) 
                FROM certificate_scans 
                WHERE certificate_id = c.id AND endpoint_id = e.id
            )
            AND julianday(c.not_after) - julianday('now') <= ?
            AND julianday(c.not_after) - julianday('now') > 0
            ORDER BY days_until_expiry ASC
        """
        
        cursor.execute(query, (days,))
        return [dict(row) for row in cursor.fetchall()]
    
    def was_notification_sent(self, certificate_id: int, endpoint_id: int,
                             days_until_expiry: int, hours_ago: int = 24) -> bool:
        """Check if notification was already sent recently"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM notifications
            WHERE certificate_id = ?
            AND endpoint_id = ?
            AND days_until_expiry = ?
            AND julianday('now') - julianday(sent_at) < ?
        """, (certificate_id, endpoint_id, days_until_expiry, hours_ago / 24.0))
        
        result = cursor.fetchone()
        return result['count'] > 0
    
    def get_all_endpoints(self) -> List[Dict]:
        """Get all configured endpoints"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM endpoints")
        return [dict(row) for row in cursor.fetchall()]
    
    def get_untrusted_certificates(self) -> List[Dict]:
        """Get certificates that are not trusted by system CA store"""
        cursor = self.conn.cursor()
        
        query = """
            SELECT 
                c.id,
                c.fingerprint,
                c.subject,
                c.issuer,
                c.not_after,
                c.is_self_signed,
                c.is_trusted_ca,
                c.validation_error,
                c.chain_length,
                e.host,
                e.port,
                e.owner,
                e.criticality
            FROM certificates c
            JOIN certificate_scans cs ON c.id = cs.certificate_id
            JOIN endpoints e ON cs.endpoint_id = e.id
            WHERE cs.status = 'success'
            AND cs.scanned_at = (
                SELECT MAX(scanned_at) 
                FROM certificate_scans 
                WHERE certificate_id = c.id AND endpoint_id = e.id
            )
            AND (c.is_trusted_ca = 0 OR c.is_self_signed = 1)
            ORDER BY c.is_self_signed DESC, e.criticality DESC
        """
        
        cursor.execute(query)
        return [dict(row) for row in cursor.fetchall()]
    
    def add_trusted_ca(self, name: str, pem_data: str, fingerprint: str,
                       subject: str, issuer: str, not_after: str) -> int:
        """Add a trusted CA certificate"""
        cursor = self.conn.cursor()
        now = datetime.utcnow().isoformat()

        cursor.execute("""
            INSERT INTO trusted_cas (name, pem_data, fingerprint, subject, issuer, not_after, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                name = excluded.name,
                pem_data = excluded.pem_data
        """, (name, pem_data, fingerprint, subject, issuer, not_after, now))
        self.conn.commit()

        cursor.execute("SELECT id FROM trusted_cas WHERE fingerprint = ?", (fingerprint,))
        return cursor.fetchone()[0]

    def get_all_trusted_cas(self) -> List[Dict]:
        """Get all trusted CA certificates"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, name, fingerprint, subject, issuer, not_after, created_at FROM trusted_cas")
        return [dict(row) for row in cursor.fetchall()]

    def get_trusted_ca_pem(self, ca_id: int) -> Optional[str]:
        """Get PEM data for a specific CA"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT pem_data FROM trusted_cas WHERE id = ?", (ca_id,))
        row = cursor.fetchone()
        return row['pem_data'] if row else None

    def get_all_trusted_ca_pems(self) -> List[str]:
        """Get all trusted CA PEM data for building trust store"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT pem_data FROM trusted_cas")
        return [row['pem_data'] for row in cursor.fetchall()]

    def delete_trusted_ca(self, ca_id: int) -> bool:
        """Delete a trusted CA"""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM trusted_cas WHERE id = ?", (ca_id,))
        self.conn.commit()
        return cursor.rowcount > 0

    def update_endpoint_webhook(self, endpoint_id: int, webhook_url: Optional[str]) -> bool:
        """Update endpoint's webhook URL"""
        cursor = self.conn.cursor()
        cursor.execute("UPDATE endpoints SET webhook_url = ? WHERE id = ?", (webhook_url, endpoint_id))
        self.conn.commit()
        return cursor.rowcount > 0

    def get_endpoint_webhook(self, endpoint_id: int) -> Optional[str]:
        """Get endpoint's webhook URL"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT webhook_url FROM endpoints WHERE id = ?", (endpoint_id,))
        row = cursor.fetchone()
        return row['webhook_url'] if row else None

    # ==================== Sweep Methods ====================

    def create_sweep(self, name: str, target: str, ports: List[int],
                     owner: str = None, criticality: str = "medium",
                     webhook_url: str = None, created_by: str = None) -> int:
        """Create a new network sweep configuration"""
        cursor = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        ports_json = json.dumps(ports)

        cursor.execute("""
            INSERT INTO sweeps (name, target, ports, owner, criticality, webhook_url, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, target, ports_json, owner, criticality, webhook_url, created_by, now))
        self.conn.commit()
        return cursor.lastrowid

    def get_sweep(self, sweep_id: int) -> Optional[Dict]:
        """Get sweep by ID"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM sweeps WHERE id = ?", (sweep_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_all_sweeps(self) -> List[Dict]:
        """Get all sweeps"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM sweeps ORDER BY created_at DESC")
        return [dict(row) for row in cursor.fetchall()]

    def update_sweep_status(self, sweep_id: int, status: str,
                            progress_scanned: int = None,
                            progress_found: int = None,
                            progress_total: int = None,
                            started_at: str = None,
                            completed_at: str = None,
                            error_message: str = None) -> bool:
        """Update sweep execution status and progress"""
        cursor = self.conn.cursor()
        updates = ["status = ?"]
        params = [status]

        if progress_scanned is not None:
            updates.append("progress_scanned = ?")
            params.append(progress_scanned)
        if progress_found is not None:
            updates.append("progress_found = ?")
            params.append(progress_found)
        if progress_total is not None:
            updates.append("progress_total = ?")
            params.append(progress_total)
        if started_at is not None:
            updates.append("started_at = ?")
            params.append(started_at)
        if completed_at is not None:
            updates.append("completed_at = ?")
            params.append(completed_at)
        if error_message is not None:
            updates.append("error_message = ?")
            params.append(error_message)

        params.append(sweep_id)
        query = f"UPDATE sweeps SET {', '.join(updates)} WHERE id = ?"
        cursor.execute(query, params)
        self.conn.commit()
        return cursor.rowcount > 0

    def add_sweep_result(self, sweep_id: int, ip_address: str, port: int,
                         status: str, endpoint_id: int = None) -> int:
        """Record individual sweep scan result"""
        cursor = self.conn.cursor()
        now = datetime.utcnow().isoformat()

        cursor.execute("""
            INSERT INTO sweep_results (sweep_id, ip_address, port, status, endpoint_id, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (sweep_id, ip_address, port, status, endpoint_id, now))
        self.conn.commit()
        return cursor.lastrowid

    def get_sweep_results(self, sweep_id: int) -> List[Dict]:
        """Get all results for a specific sweep"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM sweep_results
            WHERE sweep_id = ?
            ORDER BY scanned_at DESC
        """, (sweep_id,))
        return [dict(row) for row in cursor.fetchall()]

    def reset_sweep(self, sweep_id: int, total_scans: int = None) -> bool:
        """Reset sweep status and clear previous results"""
        cursor = self.conn.cursor()
        # Clear previous results
        cursor.execute("DELETE FROM sweep_results WHERE sweep_id = ?", (sweep_id,))
        # Reset sweep status
        updates = [
            "status = 'pending'",
            "progress_total = COALESCE(?, progress_total)",
            "progress_scanned = 0",
            "progress_found = 0",
            "started_at = NULL",
            "completed_at = NULL",
            "error_message = NULL",
        ]
        cursor.execute(
            f"UPDATE sweeps SET {', '.join(updates)} WHERE id = ?",
            (total_scans, sweep_id)
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def delete_sweep(self, sweep_id: int) -> bool:
        """Delete sweep and all its results"""
        cursor = self.conn.cursor()
        # Delete results first
        cursor.execute("DELETE FROM sweep_results WHERE sweep_id = ?", (sweep_id,))
        # Delete sweep
        cursor.execute("DELETE FROM sweeps WHERE id = ?", (sweep_id,))
        self.conn.commit()
        return cursor.rowcount > 0

    # ==================== User Methods ====================

    def create_user(self, username: str, password_hash: str, email: str = None,
                    role: str = "viewer") -> int:
        """Create a new user"""
        cursor = self.conn.cursor()
        now = datetime.utcnow().isoformat()

        cursor.execute("""
            INSERT INTO users (username, email, password_hash, role, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, email, password_hash, role, now, now))
        self.conn.commit()
        return cursor.lastrowid

    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Get user by username"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Get user by ID"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_all_users(self) -> List[Dict]:
        """Get all users (without password hashes)"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT id, username, email, role, is_active, created_at, updated_at
            FROM users ORDER BY username
        """)
        return [dict(row) for row in cursor.fetchall()]

    def update_user(self, user_id: int, email: str = None, role: str = None,
                    is_active: bool = None) -> bool:
        """Update user details"""
        cursor = self.conn.cursor()
        updates = ["updated_at = ?"]
        params = [datetime.utcnow().isoformat()]

        if email is not None:
            updates.append("email = ?")
            params.append(email)
        if role is not None:
            updates.append("role = ?")
            params.append(role)
        if is_active is not None:
            updates.append("is_active = ?")
            params.append(int(is_active))

        params.append(user_id)
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
        cursor.execute(query, params)
        self.conn.commit()
        return cursor.rowcount > 0

    def update_user_password(self, user_id: int, password_hash: str) -> bool:
        """Update user's password"""
        cursor = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute("""
            UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?
        """, (password_hash, now, user_id))
        self.conn.commit()
        return cursor.rowcount > 0

    def delete_user(self, user_id: int) -> bool:
        """Delete a user (also deletes their refresh tokens via CASCADE)"""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        self.conn.commit()
        return cursor.rowcount > 0

    def count_users(self) -> int:
        """Count total users"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM users")
        return cursor.fetchone()['count']

    # ==================== Refresh Token Methods ====================

    def store_refresh_token(self, user_id: int, token_hash: str, expires_at: str) -> int:
        """Store a refresh token"""
        cursor = self.conn.cursor()
        now = datetime.utcnow().isoformat()

        cursor.execute("""
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at, created_at)
            VALUES (?, ?, ?, ?)
        """, (user_id, token_hash, expires_at, now))
        self.conn.commit()
        return cursor.lastrowid

    def get_refresh_token(self, token_hash: str) -> Optional[Dict]:
        """Get refresh token by hash"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT rt.*, u.username, u.role, u.is_active
            FROM refresh_tokens rt
            JOIN users u ON rt.user_id = u.id
            WHERE rt.token_hash = ?
        """, (token_hash,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def delete_refresh_token(self, token_hash: str) -> bool:
        """Delete a specific refresh token (logout)"""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM refresh_tokens WHERE token_hash = ?", (token_hash,))
        self.conn.commit()
        return cursor.rowcount > 0

    def delete_user_refresh_tokens(self, user_id: int) -> int:
        """Delete all refresh tokens for a user (logout all sessions)"""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM refresh_tokens WHERE user_id = ?", (user_id,))
        self.conn.commit()
        return cursor.rowcount

    def cleanup_expired_tokens(self) -> int:
        """Remove expired refresh tokens"""
        cursor = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute("DELETE FROM refresh_tokens WHERE expires_at < ?", (now,))
        self.conn.commit()
        return cursor.rowcount

    def cleanup_orphaned_certificates(self) -> int:
        """Remove certificates not referenced by the latest scan of any endpoint.

        When a server rotates its certificate, the old cert remains in the DB
        but is no longer the latest scan result for any endpoint. This method
        removes those orphaned certificates and their scan history.
        """
        cursor = self.conn.cursor()

        # Find certificates that are NOT the latest scan result for any endpoint
        cursor.execute("""
            DELETE FROM certificate_scans WHERE certificate_id IN (
                SELECT c.id FROM certificates c
                WHERE c.id NOT IN (
                    SELECT cs.certificate_id
                    FROM certificate_scans cs
                    WHERE cs.status = 'success'
                    AND cs.scanned_at = (
                        SELECT MAX(cs2.scanned_at)
                        FROM certificate_scans cs2
                        WHERE cs2.endpoint_id = cs.endpoint_id
                    )
                )
            )
        """)
        cursor.execute("""
            DELETE FROM certificates WHERE id NOT IN (
                SELECT cs.certificate_id
                FROM certificate_scans cs
                WHERE cs.status = 'success'
                AND cs.scanned_at = (
                    SELECT MAX(cs2.scanned_at)
                    FROM certificate_scans cs2
                    WHERE cs2.endpoint_id = cs.endpoint_id
                )
            )
        """)
        deleted = cursor.rowcount
        self.conn.commit()
        return deleted

    # ==================== Audit Log Methods ====================

    def add_audit_log(self, user_email: str, action: str, resource_type: str = None,
                      resource_id: int = None, details: str = None,
                      ip_address: str = None) -> int:
        """Add an audit log entry"""
        cursor = self.conn.cursor()
        now = datetime.utcnow().isoformat()

        cursor.execute("""
            INSERT INTO audit_log (user_email, action, resource_type, resource_id, details, ip_address, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_email, action, resource_type, resource_id, details, ip_address, now))
        self.conn.commit()
        return cursor.lastrowid

    def get_audit_logs(self, limit: int = 100, offset: int = 0,
                       user_email: str = None, action: str = None) -> List[Dict]:
        """Get audit log entries with optional filters"""
        cursor = self.conn.cursor()
        query = "SELECT * FROM audit_log WHERE 1=1"
        params = []

        if user_email:
            query += " AND user_email = ?"
            params.append(user_email)
        if action:
            query += " AND action = ?"
            params.append(action)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
