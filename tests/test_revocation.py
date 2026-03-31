import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from micropki.database import CertificateDatabase
from micropki.revocation import revoke_certificate, check_revoked, RevocationError


@pytest.fixture
def test_db():
    with tempfile.NamedTemporaryFile(suffix='.db') as tmp:
        db = CertificateDatabase(tmp.name)
        db.init_schema()

        cert_data = {
            'serial_hex': '1A2B3C4D',
            'subject': 'CN=Test Cert',
            'issuer': 'CN=Test CA',
            'not_before': '2024-01-01T00:00:00',
            'not_after': '2025-01-01T00:00:00',
            'cert_pem': '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----',
            'status': 'valid'
        }
        db.insert_certificate(cert_data)

        yield db
        db.close()


def test_revoke_certificate(test_db):
    result = revoke_certificate(test_db, '1A2B3C4D', 'keyCompromise', force=True)

    assert result['status'] == 'revoked'
    assert result['reason'] == 'keyCompromise'

    cert = test_db.get_certificate_by_serial('1A2B3C4D')
    assert cert['status'] == 'revoked'
    assert cert['revocation_reason'] == 'keyCompromise'


def test_revoke_nonexistent(test_db):
    with pytest.raises(RevocationError):
        revoke_certificate(test_db, 'NONEXISTENT', 'unspecified', force=True)


def test_revoke_already_revoked(test_db):
    revoke_certificate(test_db, '1A2B3C4D', 'keyCompromise', force=True)

    result = revoke_certificate(test_db, '1A2B3C4D', 'superseded', force=True)
    assert result['status'] == 'already_revoked'


def test_check_revoked(test_db):
    result = check_revoked(test_db, '1A2B3C4D')
    assert result['exists'] is True
    assert result['revoked'] is False

    revoke_certificate(test_db, '1A2B3C4D', 'keyCompromise', force=True)

    result = check_revoked(test_db, '1A2B3C4D')
    assert result['revoked'] is True
    assert result['revocation_reason'] == 'keyCompromise'