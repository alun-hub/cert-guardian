#!/usr/bin/env python3
"""
Database models for Certificate Guardian
"""
import sqlite3
from datetime import datetime
from typing import Optional, List, Dict
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
                UNIQUE(host, port)
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
                FOREIGN KEY (certificate_id) REFERENCES certificates(id),
                FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
            )
        """)
        
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
        
        self.conn.commit()
    
    def add_endpoint(self, host: str, port: int, owner: str = None, 
                     criticality: str = "medium") -> int:
        """Add or update an endpoint"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO endpoints (host, port, owner, criticality)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(host, port) DO UPDATE SET
                owner = excluded.owner,
                criticality = excluded.criticality
        """, (host, port, owner, criticality))
        self.conn.commit()
        return cursor.lastrowid
    
    def add_certificate(self, fingerprint: str, subject: str, issuer: str,
                       not_before: str, not_after: str, serial_number: str = None,
                       san_list: List[str] = None, is_self_signed: bool = False,
                       is_trusted_ca: bool = False, validation_error: str = None,
                       chain_length: int = 0) -> int:
        """Add or update a certificate"""
        cursor = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        san_json = json.dumps(san_list) if san_list else None

        cursor.execute("""
            INSERT INTO certificates (
                fingerprint, subject, issuer, not_before, not_after,
                serial_number, san_list, is_self_signed, is_trusted_ca,
                validation_error, chain_length, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                is_self_signed = excluded.is_self_signed,
                is_trusted_ca = excluded.is_trusted_ca,
                validation_error = excluded.validation_error,
                chain_length = excluded.chain_length,
                updated_at = excluded.updated_at
        """, (fingerprint, subject, issuer, not_before, not_after,
              serial_number, san_json, int(is_self_signed), int(is_trusted_ca),
              validation_error, chain_length, now, now))
        self.conn.commit()

        # Get the actual certificate ID (lastrowid is unreliable with ON CONFLICT)
        cursor.execute("SELECT id FROM certificates WHERE fingerprint = ?", (fingerprint,))
        return cursor.fetchone()[0]
    
    def add_scan(self, certificate_id: int, endpoint_id: int, 
                 status: str, error_message: str = None) -> int:
        """Record a certificate scan"""
        cursor = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        
        cursor.execute("""
            INSERT INTO certificate_scans (
                certificate_id, endpoint_id, scanned_at, status, error_message
            )
            VALUES (?, ?, ?, ?, ?)
        """, (certificate_id, endpoint_id, now, status, error_message))
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
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
