import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from micropki.crl import (
    generate_crl, save_crl, load_crl, crl_to_pem,
    CRLError
)


@pytest.fixture
def ca_cert_key():
    key = rsa.generate_private_key(65537, 4096, default_backend())
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test CA")
    ])

    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())

    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).serial_number(
        1
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).public_key(
        key.public_key()
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).add_extension(
        ski, critical=False
    ).add_extension(
        aki, critical=False
    ).sign(key, hashes.SHA256(), default_backend())

    return cert, key


@pytest.fixture
def revoked_certs():
    return [
        {
            'serial_hex': '1A2B3C4D',
            'revocation_date': datetime.now(timezone.utc).isoformat(),
            'revocation_reason': None
        },
        {
            'serial_hex': '2E5F6A7B',
            'revocation_date': datetime.now(timezone.utc).isoformat(),
            'revocation_reason': None
        }
    ]


def test_generate_crl(ca_cert_key, revoked_certs):
    cert, key = ca_cert_key
    crl = generate_crl(cert, key, revoked_certs, next_update_days=7, crl_number=1)

    assert crl.issuer == cert.subject
    assert crl.next_update_utc > crl.last_update_utc
    assert len(crl) == 2


def test_save_and_load_crl(ca_cert_key, revoked_certs, tmp_path):
    cert, key = ca_cert_key
    crl = generate_crl(cert, key, revoked_certs, next_update_days=7, crl_number=1)

    crl_path = tmp_path / "test.crl.pem"
    save_crl(crl, str(crl_path))

    loaded_crl = load_crl(str(crl_path))
    assert loaded_crl.issuer == crl.issuer
    assert loaded_crl.last_update_utc == crl.last_update_utc
    assert loaded_crl.next_update_utc == crl.next_update_utc
    assert len(loaded_crl) == len(crl)


def test_crl_to_pem(ca_cert_key, revoked_certs):
    cert, key = ca_cert_key
    crl = generate_crl(cert, key, revoked_certs, next_update_days=7, crl_number=1)

    pem_data = crl_to_pem(crl)
    assert b"BEGIN X509 CRL" in pem_data
    assert b"END X509 CRL" in pem_data


def test_crl_number_increment(ca_cert_key, revoked_certs):
    cert, key = ca_cert_key

    crl1 = generate_crl(cert, key, revoked_certs, next_update_days=7, crl_number=1)
    crl2 = generate_crl(cert, key, revoked_certs, next_update_days=7, crl_number=2)

    crl1_number = None
    crl2_number = None

    for ext in crl1.extensions:
        if ext.oid == ExtensionOID.CRL_NUMBER:
            crl1_number = ext.value.crl_number

    for ext in crl2.extensions:
        if ext.oid == ExtensionOID.CRL_NUMBER:
            crl2_number = ext.value.crl_number

    assert crl1_number is not None
    assert crl2_number is not None
    assert crl2_number == crl1_number + 1