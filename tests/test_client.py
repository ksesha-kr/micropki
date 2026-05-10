import pytest
import tempfile
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from micropki.client import PKIClient


def test_generate_csr():
    with tempfile.TemporaryDirectory() as tmpdir:
        client = PKIClient()
        out_key = Path(tmpdir) / "key.pem"
        out_csr = Path(tmpdir) / "request.csr.pem"

        result = client.generate_csr(
            subject_dn="CN=test.example.com",
            key_type="rsa",
            key_size=2048,
            san_entries=["dns:test.example.com"],
            out_key=str(out_key),
            out_csr=str(out_csr)
        )

        assert out_key.exists()
        assert out_csr.exists()

        with open(out_csr, 'rb') as f:
            csr = x509.load_pem_x509_csr(f.read(), default_backend())

        attrs = {attr.oid._name: attr.value for attr in csr.subject}
        assert attrs.get('commonName') == 'test.example.com'


def test_generate_csr_ecc():
    with tempfile.TemporaryDirectory() as tmpdir:
        client = PKIClient()
        out_key = Path(tmpdir) / "key.pem"
        out_csr = Path(tmpdir) / "request.csr.pem"

        result = client.generate_csr(
            subject_dn="CN=test.example.com",
            key_type="ecc",
            key_size=256,
            out_key=str(out_key),
            out_csr=str(out_csr)
        )

        assert out_key.exists()
        assert out_csr.exists()