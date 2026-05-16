import pytest
import tempfile
from pathlib import Path
from micropki.compromise import compute_public_key_hash
from micropki.database import CertificateDatabase
from micropki.crypto_utils import generate_rsa_key


def test_compute_public_key_hash():
    key = generate_rsa_key(2048)
    hash1 = compute_public_key_hash(key.public_key())
    hash2 = compute_public_key_hash(key.public_key())
    assert hash1 == hash2
    assert len(hash1) == 64


def test_compromised_key_db():
    with tempfile.NamedTemporaryFile(suffix='.db') as tmp:
        db = CertificateDatabase(tmp.name)
        db.init_schema()

        cursor = db.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='compromised_keys'")
        assert cursor.fetchone() is not None

        db.add_compromised_key("test_hash_123", "SERIAL001", "keyCompromise")
        assert db.is_key_compromised("test_hash_123") is True
        assert db.is_key_compromised("nonexistent") is False
        db.close()