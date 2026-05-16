import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)

class CompromiseError(Exception):
    pass

def compute_public_key_hash(public_key) -> str:
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(public_bytes).hexdigest()

def get_public_key_from_cert(cert_path: str) -> str:
    with open(cert_path, 'rb') as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    return compute_public_key_hash(cert.public_key())

def get_public_key_from_csr(csr_path: str) -> str:
    with open(csr_path, 'rb') as f:
        csr_data = f.read()
    csr = x509.load_pem_x509_csr(csr_data, default_backend())
    return compute_public_key_hash(csr.public_key())

def mark_key_compromised(db, serial_hex: str, public_key_hash: str, reason: str):
    from datetime import datetime, timezone
    cursor = db.conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO compromised_keys (public_key_hash, certificate_serial, compromise_date, compromise_reason)
        VALUES (?, ?, ?, ?)
    """, (public_key_hash, serial_hex, datetime.now(timezone.utc).isoformat(), reason))
    db.conn.commit()
    logger.warning(f"Key compromised: {public_key_hash[:16]}... for certificate {serial_hex}")

def is_key_compromised(db, public_key_hash: str) -> bool:
    cursor = db.conn.cursor()
    cursor.execute("SELECT 1 FROM compromised_keys WHERE public_key_hash = ?", (public_key_hash,))
    return cursor.fetchone() is not None

def get_compromised_keys(db) -> list:
    cursor = db.conn.cursor()
    cursor.execute("SELECT * FROM compromised_keys ORDER BY compromise_date DESC")
    return [dict(row) for row in cursor.fetchall()]