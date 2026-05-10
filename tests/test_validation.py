import pytest
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from micropki.validation import PathValidator

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

    return root_cert, inter_cert, leaf_cert

def test_valid_chain(test_certs):
    root, inter, leaf = test_certs
    validator = PathValidator()
    result = validator.validate_chain(leaf, [inter], [root], 'server')
    print("ERRORS:", result.errors)
    print("STEPS:", result.steps)
    assert result.passed is True

def test_expired_certificate(test_certs):
    root, inter, leaf = test_certs
    future = datetime.now(timezone.utc) + timedelta(days=365)
    validator = PathValidator(validation_time=future)
    result = validator.validate_chain(leaf, [inter], [root], 'server')
    assert result.passed is False
    assert any("expired" in err.lower() for err in result.errors)