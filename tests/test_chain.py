import pytest
import tempfile
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
from micropki.chain import (
    verify_chain, verify_signature, verify_validity_period,
    verify_basic_constraints, load_certificate, ChainError
)


class TestChainValidation:
    def test_valid_chain(self, root_cert_with_key, intermediate_cert_with_key, leaf_cert_with_key):
        root_cert, root_key = root_cert_with_key
        intermediate_cert, intermediate_key = intermediate_cert_with_key
        leaf_cert, leaf_key = leaf_cert_with_key

        with tempfile.TemporaryDirectory() as tmpdir:
            root_path = Path(tmpdir) / "root.pem"
            intermediate_path = Path(tmpdir) / "intermediate.pem"
            leaf_path = Path(tmpdir) / "leaf.pem"

            with open(root_path, 'wb') as f:
                f.write(root_cert.public_bytes(serialization.Encoding.PEM))
            with open(intermediate_path, 'wb') as f:
                f.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))
            with open(leaf_path, 'wb') as f:
                f.write(leaf_cert.public_bytes(serialization.Encoding.PEM))

            assert verify_chain(str(leaf_path), str(intermediate_path), str(root_path)) is True

    def test_invalid_signature(self, root_cert_with_key, intermediate_cert_with_key, wrong_key_cert):
        root_cert, root_key = root_cert_with_key
        intermediate_cert, intermediate_key = intermediate_cert_with_key
        wrong_cert, wrong_key = wrong_key_cert

        with tempfile.TemporaryDirectory() as tmpdir:
            root_path = Path(tmpdir) / "root.pem"
            intermediate_path = Path(tmpdir) / "intermediate.pem"
            leaf_path = Path(tmpdir) / "leaf.pem"

            with open(root_path, 'wb') as f:
                f.write(root_cert.public_bytes(serialization.Encoding.PEM))
            with open(intermediate_path, 'wb') as f:
                f.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))
            with open(leaf_path, 'wb') as f:
                f.write(wrong_cert.public_bytes(serialization.Encoding.PEM))

            assert verify_chain(str(leaf_path), str(intermediate_path), str(root_path)) is False


class TestSignatureVerification:
    def test_verify_valid_signature(self, root_cert_with_key, intermediate_cert_with_key):
        root_cert, root_key = root_cert_with_key
        intermediate_cert, intermediate_key = intermediate_cert_with_key
        assert verify_signature(root_cert, intermediate_cert) is True

    def test_verify_invalid_signature(self, root_cert_with_key, wrong_key_cert):
        root_cert, root_key = root_cert_with_key
        wrong_cert, wrong_key = wrong_key_cert
        assert verify_signature(root_cert, wrong_cert) is False


class TestValidityPeriod:
    def test_valid_certificate(self, root_cert_with_key):
        cert, key = root_cert_with_key
        assert verify_validity_period(cert) is True

    def test_expired_certificate(self):
        key = rsa.generate_private_key(65537, 2048, default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Expired CA")
        ])

        expired_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).serial_number(
            999
        ).not_valid_before(
            datetime.now(timezone.utc) - timedelta(days=400)
        ).not_valid_after(
            datetime.now(timezone.utc) - timedelta(days=1)
        ).public_key(
            key.public_key()
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(key, hashes.SHA256(), default_backend())

        assert verify_validity_period(expired_cert) is False


class TestBasicConstraints:
    def test_ca_certificate(self, root_cert_with_key):
        cert, key = root_cert_with_key
        assert verify_basic_constraints(cert, expected_ca=True) is True

    def test_leaf_certificate(self, leaf_cert_with_key):
        cert, key = leaf_cert_with_key
        assert verify_basic_constraints(cert, expected_ca=False) is True

    def test_wrong_ca_flag(self, root_cert_with_key):
        cert, key = root_cert_with_key
        assert verify_basic_constraints(cert, expected_ca=False) is False

@pytest.fixture
def root_cert_with_key():
    key = rsa.generate_private_key(65537, 4096, default_backend())
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test Root CA")
    ])

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
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
    ).sign(key, hashes.SHA256(), default_backend())

    return cert, key


@pytest.fixture
def intermediate_cert_with_key(root_cert_with_key):
    root_cert, root_key = root_cert_with_key

    key = rsa.generate_private_key(65537, 4096, default_backend())
    subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test Intermediate CA")
    ])

    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())

    root_ski = None
    for ext in root_cert.extensions:
        if ext.oid == x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER:
            root_ski = ext.value

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        root_cert.subject
    ).serial_number(
        2
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).public_key(
        key.public_key()
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True
    ).add_extension(
        ski, critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski), critical=False
    ).sign(root_key, hashes.SHA256(), default_backend())

    return cert, key


@pytest.fixture
def leaf_cert_with_key(intermediate_cert_with_key):
    intermediate_cert, intermediate_key = intermediate_cert_with_key

    key = rsa.generate_private_key(65537, 2048, default_backend())
    subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test Leaf")
    ])

    intermediate_ski = None
    for ext in intermediate_cert.extensions:
        if ext.oid == x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER:
            intermediate_ski = ext.value

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        intermediate_cert.subject
    ).serial_number(
        3
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=30)
    ).public_key(
        key.public_key()
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(intermediate_ski), critical=False
    ).sign(intermediate_key, hashes.SHA256(), default_backend())

    return cert, key


@pytest.fixture
def wrong_key_cert():
    key = rsa.generate_private_key(65537, 2048, default_backend())
    wrong_key = rsa.generate_private_key(65537, 2048, default_backend())

    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Wrong CA")
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).serial_number(
        99
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).public_key(
        key.public_key()
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(wrong_key, hashes.SHA256(), default_backend())

    return cert, wrong_key