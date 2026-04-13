import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from micropki.ocsp import (
    extract_nonce_from_request, compute_issuer_hashes
)


def test_compute_issuer_hashes():
    key = rsa.generate_private_key(65537, 2048, default_backend())
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test CA")
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
    ).sign(key, hashes.SHA256(), default_backend())

    name_hash, key_hash = compute_issuer_hashes(cert)
    assert len(name_hash) == 20
    assert len(key_hash) == 20