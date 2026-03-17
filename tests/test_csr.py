import pytest
from micropki.csr import generate_csr, sign_csr, load_csr, save_csr, verify_csr_signature, CSRError
from micropki.crypto_utils import generate_rsa_key, generate_ecc_key
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
import tempfile
from pathlib import Path


class TestCSRGeneration:
    def test_generate_rsa_csr(self):
        key = generate_rsa_key(4096)
        csr = generate_csr("/CN=Test Intermediate CA", key, 'rsa', is_ca=True, pathlen=0)

        assert csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "Test Intermediate CA"

        basic_constraints = csr.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
        assert basic_constraints.value.ca is True
        assert basic_constraints.value.path_length == 0

    def test_generate_ecc_csr(self):
        key = generate_ecc_key()
        csr = generate_csr("CN=Test ECC CA", key, 'ecc', is_ca=True, pathlen=1)

        basic_constraints = csr.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
        assert basic_constraints.value.ca is True
        assert basic_constraints.value.path_length == 1

    def test_generate_non_ca_csr(self):
        key = generate_rsa_key(4096)
        csr = generate_csr("/CN=Test User", key, 'rsa', is_ca=False)

        with pytest.raises(x509.ExtensionNotFound):
            csr.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)


class TestCSRSigning:
    def test_sign_csr_with_rsa(self, root_cert_with_key):
        root_cert, root_key = root_cert_with_key
        key = generate_rsa_key(4096)
        csr = generate_csr("/CN=Test Cert", key, 'rsa', is_ca=False)

        cert = sign_csr(
            csr=csr,
            issuer_cert=root_cert,
            issuer_key=root_key,
            validity_days=365,
            template_name='server',
            san_entries=['dns:example.com'],
            is_ca=False,
            key_type='rsa'
        )

        assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "Test Cert"
        assert cert.issuer == root_cert.subject


class TestCSRFileOperations:
    def test_save_and_load_csr(self, tmp_path):
        key = generate_rsa_key(4096)
        csr = generate_csr("/CN=Test", key, 'rsa', is_ca=False)

        csr_path = tmp_path / "test.csr.pem"
        save_csr(csr, str(csr_path))

        loaded_csr = load_csr(str(csr_path))
        assert loaded_csr.subject == csr.subject

    def test_verify_csr_signature(self):
        key = generate_rsa_key(4096)
        csr = generate_csr("/CN=Test", key, 'rsa', is_ca=False)

        assert verify_csr_signature(csr) is True

@pytest.fixture
def root_cert_with_key():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    from cryptography import x509
    from datetime import datetime, timedelta, timezone

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
    ).sign(key, hashes.SHA256(), default_backend())

    return cert, key