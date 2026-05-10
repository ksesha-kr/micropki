import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from micropki.revocation_check import RevocationChecker
from micropki.crl import generate_crl, save_crl, load_crl

def crl_to_bytes(crl: x509.CertificateRevocationList) -> bytes:
    return crl.public_bytes(serialization.Encoding.PEM)

@pytest.fixture
def test_certs():
    root_key = rsa.generate_private_key(65537, 4096, default_backend())
    root_subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test Root CA")])
    root_ski = x509.SubjectKeyIdentifier.from_public_key(root_key.public_key())
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .serial_number(1)
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .public_key(root_key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(root_ski, critical=False)
        .sign(root_key, hashes.SHA256(), default_backend())
    )

    inter_key = rsa.generate_private_key(65537, 4096, default_backend())
    inter_subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test Intermediate CA")])
    inter_ski = x509.SubjectKeyIdentifier.from_public_key(inter_key.public_key())
    inter_cert = (
        x509.CertificateBuilder()
        .subject_name(inter_subject)
        .issuer_name(root_subject)
        .serial_number(2)
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .public_key(inter_key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(inter_ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski), critical=False)
        .sign(root_key, hashes.SHA256(), default_backend())
    )

    leaf_key = rsa.generate_private_key(65537, 2048, default_backend())
    leaf_subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test.example.com")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject)
        .issuer_name(inter_subject)
        .serial_number(123456)
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .public_key(leaf_key.public_key())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(inter_ski), critical=False)
        .sign(inter_key, hashes.SHA256(), default_backend())
    )

    return root_cert, inter_cert, leaf_cert, inter_key

def test_get_ocsp_url(test_certs):
    root, inter, leaf, inter_key = test_certs
    checker = RevocationChecker()
    aia = x509.AuthorityInformationAccess([
        x509.AccessDescription(
            x509.oid.AuthorityInformationAccessOID.OCSP,
            x509.UniformResourceIdentifier("http://localhost:8080/ocsp")
        )
    ])
    cert_with_aia = (
        x509.CertificateBuilder()
        .subject_name(leaf.subject)
        .issuer_name(leaf.issuer)
        .serial_number(999)
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .public_key(leaf.public_key())
        .add_extension(aia, critical=False)
        .sign(inter_key, hashes.SHA256(), default_backend())
    )
    url = checker.get_ocsp_url(cert_with_aia)
    assert url == "http://localhost:8080/ocsp"

def test_check_crl_good(test_certs, tmp_path):
    root, inter, leaf, inter_key = test_certs
    checker = RevocationChecker()
    crl = generate_crl(inter, inter_key, [], next_update_days=7, crl_number=1)
    crl_path = tmp_path / "test.crl.pem"
    save_crl(crl, str(crl_path))
    loaded_crl = load_crl(str(crl_path))
    status, reason, rev_date = checker.check_crl(leaf, inter, crl_data=crl_to_bytes(loaded_crl))
    assert status == 'good'

def test_check_crl_revoked(test_certs, tmp_path):
    root, inter, leaf, inter_key = test_certs
    checker = RevocationChecker()
    revoked_certs = [{
        'serial_hex': hex(leaf.serial_number)[2:].upper(),
        'revocation_date': datetime.now(timezone.utc).isoformat(),
        'revocation_reason': 'keyCompromise'
    }]
    crl = generate_crl(inter, inter_key, revoked_certs, next_update_days=7, crl_number=1)
    crl_path = tmp_path / "test.crl.pem"
    save_crl(crl, str(crl_path))
    loaded_crl = load_crl(str(crl_path))
    status, reason, rev_date = checker.check_crl(leaf, inter, crl_data=crl_to_bytes(loaded_crl))
    assert status == 'revoked'

    if reason is not None:
        assert reason == 'keyCompromise'