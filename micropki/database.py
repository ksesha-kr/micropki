import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class DatabaseError(Exception):
    pass


class CertificateDatabase:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.conn = None
        self._init_connection()

    def _init_connection(self):
        try:
            self.conn = sqlite3.connect(str(self.db_path))
            self.conn.row_factory = sqlite3.Row
            logger.info(f"Connected to database: {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to connect to database: {str(e)}")
            raise DatabaseError(f"Cannot connect to database: {str(e)}")

    def init_schema(self):
        try:
            cursor = self.conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    serial_hex TEXT UNIQUE NOT NULL,
                    subject TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    not_before TEXT NOT NULL,
                    not_after TEXT NOT NULL,
                    cert_pem TEXT NOT NULL,
                    status TEXT NOT NULL,
                    revocation_reason TEXT,
                    revocation_date TEXT,
                    created_at TEXT NOT NULL
                )
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_serial ON certificates(serial_hex)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_status ON certificates(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_issuer ON certificates(issuer)")

            self.conn.commit()
            logger.info("Database schema initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize schema: {str(e)}")
            raise DatabaseError(f"Cannot initialize schema: {str(e)}")

    def insert_certificate(self, certificate_data: Dict[str, Any]) -> int:
        try:
            cursor = self.conn.cursor()

            cursor.execute("""
                INSERT INTO certificates (
                    serial_hex, subject, issuer, not_before, not_after,
                    cert_pem, status, revocation_reason, revocation_date, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                certificate_data['serial_hex'],
                certificate_data['subject'],
                certificate_data['issuer'],
                certificate_data['not_before'],
                certificate_data['not_after'],
                certificate_data['cert_pem'],
                certificate_data.get('status', 'valid'),
                certificate_data.get('revocation_reason'),
                certificate_data.get('revocation_date'),
                certificate_data.get('created_at', datetime.now(timezone.utc).isoformat())
            ))

            self.conn.commit()
            logger.info(f"Inserted certificate with serial {certificate_data['serial_hex']}")
            return cursor.lastrowid

        except sqlite3.IntegrityError as e:
            logger.error(f"Duplicate serial number: {str(e)}")
            raise DatabaseError(f"Duplicate serial number: {certificate_data['serial_hex']}")
        except Exception as e:
            logger.error(f"Failed to insert certificate: {str(e)}")
            raise DatabaseError(f"Cannot insert certificate: {str(e)}")

    def get_certificate_by_serial(self, serial_hex: str) -> Optional[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM certificates WHERE serial_hex = ?",
                (serial_hex.upper(),)
            )
            row = cursor.fetchone()

            if row:
                logger.info(f"Retrieved certificate with serial {serial_hex}")
                return dict(row)

            logger.warning(f"Certificate with serial {serial_hex} not found")
            return None

        except Exception as e:
            logger.error(f"Failed to retrieve certificate: {str(e)}")
            raise DatabaseError(f"Cannot retrieve certificate: {str(e)}")

    def list_certificates(
            self,
            status: Optional[str] = None,
            issuer: Optional[str] = None,
            limit: int = 100,
            offset: int = 0
    ) -> List[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            query = "SELECT * FROM certificates"
            params = []
            conditions = []

            if status:
                conditions.append("status = ?")
                params.append(status)

            if issuer:
                conditions.append("issuer = ?")
                params.append(issuer)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor.execute(query, params)
            rows = cursor.fetchall()

            logger.info(f"Listed {len(rows)} certificates")
            return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to list certificates: {str(e)}")
            raise DatabaseError(f"Cannot list certificates: {str(e)}")

    def update_certificate_status(
            self,
            serial_hex: str,
            status: str,
            revocation_reason: Optional[str] = None
    ):
        try:
            cursor = self.conn.cursor()

            update_data = {
                'status': status,
                'revocation_reason': revocation_reason
            }

            if status == 'revoked':
                update_data['revocation_date'] = datetime.now(timezone.utc).isoformat()

            cursor.execute("""
                UPDATE certificates
                SET status = ?, revocation_reason = ?, revocation_date = ?
                WHERE serial_hex = ?
            """, (
                update_data['status'],
                update_data.get('revocation_reason'),
                update_data.get('revocation_date'),
                serial_hex.upper()
            ))

            self.conn.commit()
            logger.info(f"Updated certificate {serial_hex} status to {status}")

        except Exception as e:
            logger.error(f"Failed to update certificate status: {str(e)}")
            raise DatabaseError(f"Cannot update certificate: {str(e)}")

    def get_revoked_certificates(self) -> List[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM certificates WHERE status = 'revoked' ORDER BY revocation_date"
            )
            rows = cursor.fetchall()
            logger.info(f"Retrieved {len(rows)} revoked certificates")
            return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to retrieve revoked certificates: {str(e)}")
            raise DatabaseError(f"Cannot retrieve revoked certificates: {str(e)}")

    def close(self):
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")

    def init_schema(self):
        try:
            cursor = self.conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    serial_hex TEXT UNIQUE NOT NULL,
                    subject TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    not_before TEXT NOT NULL,
                    not_after TEXT NOT NULL,
                    cert_pem TEXT NOT NULL,
                    status TEXT NOT NULL,
                    revocation_reason TEXT,
                    revocation_date TEXT,
                    created_at TEXT NOT NULL
                )
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_serial ON certificates(serial_hex)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_status ON certificates(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_issuer ON certificates(issuer)")

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS crl_metadata (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ca_subject TEXT NOT NULL UNIQUE,
                    crl_number INTEGER NOT NULL,
                    last_generated TEXT NOT NULL,
                    next_update TEXT NOT NULL,
                    crl_path TEXT NOT NULL
                )
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ca_subject ON crl_metadata(ca_subject)")

            self.conn.commit()
            logger.info("Database schema initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize schema: {str(e)}")
            raise DatabaseError(f"Cannot initialize schema: {str(e)}")

    def get_crl_metadata(self, ca_subject: str) -> Optional[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM crl_metadata WHERE ca_subject = ?",
                (ca_subject,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get CRL metadata: {str(e)}")
            raise DatabaseError(f"Cannot get CRL metadata: {str(e)}")

    def update_crl_metadata(self, ca_subject: str, crl_number: int, next_update: str, crl_path: str):
        try:
            cursor = self.conn.cursor()

            existing = self.get_crl_metadata(ca_subject)

            if existing:
                cursor.execute("""
                    UPDATE crl_metadata
                    SET crl_number = ?, last_generated = ?, next_update = ?, crl_path = ?
                    WHERE ca_subject = ?
                """, (crl_number, datetime.now(timezone.utc).isoformat(), next_update, crl_path, ca_subject))
            else:
                cursor.execute("""
                    INSERT INTO crl_metadata (ca_subject, crl_number, last_generated, next_update, crl_path)
                    VALUES (?, ?, ?, ?, ?)
                """, (ca_subject, crl_number, datetime.now(timezone.utc).isoformat(), next_update, crl_path))

            self.conn.commit()
            logger.info(f"CRL metadata updated for {ca_subject}")

        except Exception as e:
            logger.error(f"Failed to update CRL metadata: {str(e)}")
            raise DatabaseError(f"Cannot update CRL metadata: {str(e)}")

    def get_revoked_certificates_by_issuer(self, issuer_dn: str) -> List[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM certificates WHERE issuer = ? AND status = 'revoked' ORDER BY revocation_date DESC",
                (issuer_dn,)
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get revoked certificates: {str(e)}")
            raise DatabaseError(f"Cannot get revoked certificates: {str(e)}")
