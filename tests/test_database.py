import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from micropki.database import CertificateDatabase, DatabaseError


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix='.db') as tmp:
        yield tmp.name


def test_init_schema(temp_db):
    db = CertificateDatabase(temp_db)
    db.init_schema()

    cursor = db.conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='certificates'")
    assert cursor.fetchone() is not None

    db.close()


def test_insert_certificate(temp_db):
    db = CertificateDatabase(temp_db)
    db.init_schema()

    cert_data = {
        'serial_hex': '1A2B3C',
        'subject': 'CN=Test',
        'issuer': 'CN=Root',
        'not_before': '2024-01-01T00:00:00',
        'not_after': '2025-01-01T00:00:00',
        'cert_pem': '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----',
        'status': 'valid'
    }

    cert_id = db.insert_certificate(cert_data)
    assert cert_id > 0

    retrieved = db.get_certificate_by_serial('1A2B3C')
    assert retrieved is not None
    assert retrieved['subject'] == 'CN=Test'

    db.close()


def test_get_certificate_not_found(temp_db):
    db = CertificateDatabase(temp_db)
    db.init_schema()

    result = db.get_certificate_by_serial('NONEXISTENT')
    assert result is None

    db.close()


def test_list_certificates(temp_db):
    db = CertificateDatabase(temp_db)
    db.init_schema()

    for i in range(3):
        cert_data = {
            'serial_hex': f'SERIAL{i:02X}',
            'subject': f'CN=Test{i}',
            'issuer': 'CN=Root',
            'not_before': '2024-01-01T00:00:00',
            'not_after': '2025-01-01T00:00:00',
            'cert_pem': f'CERT{i}',
            'status': 'valid' if i < 2 else 'revoked'
        }
        db.insert_certificate(cert_data)

    all_certs = db.list_certificates()
    assert len(all_certs) == 3

    valid_certs = db.list_certificates(status='valid')
    assert len(valid_certs) == 2

    db.close()


def test_update_certificate_status(temp_db):
    db = CertificateDatabase(temp_db)
    db.init_schema()

    cert_data = {
        'serial_hex': 'UPDATE01',
        'subject': 'CN=Test',
        'issuer': 'CN=Root',
        'not_before': '2024-01-01T00:00:00',
        'not_after': '2025-01-01T00:00:00',
        'cert_pem': 'CERT',
        'status': 'valid'
    }
    db.insert_certificate(cert_data)

    db.update_certificate_status('UPDATE01', 'revoked', 'Key compromise')

    cert = db.get_certificate_by_serial('UPDATE01')
    assert cert['status'] == 'revoked'
    assert cert['revocation_reason'] == 'Key compromise'

    db.close()


def test_duplicate_serial(temp_db):
    db = CertificateDatabase(temp_db)
    db.init_schema()

    cert_data = {
        'serial_hex': 'DUPLICATE',
        'subject': 'CN=Test1',
        'issuer': 'CN=Root',
        'not_before': '2024-01-01T00:00:00',
        'not_after': '2025-01-01T00:00:00',
        'cert_pem': 'CERT1',
        'status': 'valid'
    }
    db.insert_certificate(cert_data)

    cert_data['subject'] = 'CN=Test2'
    cert_data['cert_pem'] = 'CERT2'

    with pytest.raises(DatabaseError):
        db.insert_certificate(cert_data)

    db.close()