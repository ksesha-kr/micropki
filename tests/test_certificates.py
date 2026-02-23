import pytest
import tempfile
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from micropki.certificates import (
    parse_dn_string, generate_serial_number, compute_ski,
    create_self_signed_ca_certificate, CertificateError,
    verify_certificate_self_signed, certificate_to_pem
)
from micropki.crypto_utils import generate_rsa_key, generate_ecc_key


def test_parse_dn_slash_notation():
    dn = parse_dn_string("/CN=Test CA/O=MicroPKI/C=US")
    assert len(dn.rdns) == 3
    attrs = {attr.oid._name: attr.value for attr in dn}
    assert attrs['commonName'] == 'Test CA'
    assert attrs['organizationName'] == 'MicroPKI'
    assert attrs['countryName'] == 'US'


def test_parse_dn_comma_notation():
    dn = parse_dn_string("CN=Test CA, O=MicroPKI, C=US")
    assert len(dn.rdns) == 3
    attrs = {attr.oid._name: attr.value for attr in dn}
    assert attrs['commonName'] == 'Test CA'
    assert attrs['organizationName'] == 'MicroPKI'
    assert attrs['countryName'] == 'US'


def test_parse_dn_invalid():
    with pytest.raises(CertificateError):
        parse_dn_string("Invalid DN")


def test_generate_serial_number():
    serial1 = generate_serial_number()
    serial2 = generate_serial_number()

    assert serial1 > 0
    assert serial2 > 0
    assert serial1 != serial2
    assert serial1.bit_length() <= 159


def test_compute_ski_rsa():
    private_key = generate_rsa_key(4096)
    ski = compute_ski(private_key.public_key())
    assert len(ski) == 20
    assert isinstance(ski, bytes)


def test_compute_ski_ecc():
    private_key = generate_ecc_key()
    ski = compute_ski(private_key.public_key())
    assert len(ski) == 20
    assert isinstance(ski, bytes)


def test_create_self_signed_ca_rsa():
    private_key = generate_rsa_key(4096)
    cert = create_self_signed_ca_certificate(
        subject_dn="/CN=RSA Test CA/O=Test",
        private_key=private_key,
        validity_days=365,
        key_type='rsa'
    )

    assert cert.subject == cert.issuer
    assert cert.not_valid_after_utc > cert.not_valid_before_utc
    assert cert.version == x509.Version.v3

    basic_constraints = cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.BASIC_CONSTRAINTS
    )
    assert basic_constraints.critical is True
    assert basic_constraints.value.ca is True


def test_create_self_signed_ca_ecc():
    private_key = generate_ecc_key()
    cert = create_self_signed_ca_certificate(
        subject_dn="CN=ECC Test CA,O=Test",
        private_key=private_key,
        validity_days=365,
        key_type='ecc'
    )

    assert cert.subject == cert.issuer
    assert cert.version == x509.Version.v3

    basic_constraints = cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.BASIC_CONSTRAINTS
    )
    assert basic_constraints.critical is True
    assert basic_constraints.value.ca is True


def test_certificate_validity_period():
    private_key = generate_rsa_key(4096)
    validity_days = 3650
    cert = create_self_signed_ca_certificate(
        subject_dn="/CN=Test CA",
        private_key=private_key,
        validity_days=validity_days,
        key_type='rsa'
    )

    time_difference = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert time_difference.days == validity_days


def test_certificate_to_pem():
    private_key = generate_rsa_key(4096)
    cert = create_self_signed_ca_certificate(
        subject_dn="/CN=Test CA",
        private_key=private_key,
        validity_days=365,
        key_type='rsa'
    )

    pem_data = certificate_to_pem(cert)
    assert pem_data.startswith(b'-----BEGIN CERTIFICATE-----')
    assert pem_data.endswith(b'-----END CERTIFICATE-----\n')


def test_verify_certificate_self_signed():
    private_key = generate_rsa_key(4096)
    cert = create_self_signed_ca_certificate(
        subject_dn="/CN=Test CA",
        private_key=private_key,
        validity_days=365,
        key_type='rsa'
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path = Path(tmpdir) / "cert.pem"
        with open(cert_path, 'wb') as f:
            f.write(certificate_to_pem(cert))

        assert verify_certificate_self_signed(str(cert_path)) is True


def test_certificate_has_required_extensions():
    private_key = generate_rsa_key(4096)
    cert = create_self_signed_ca_certificate(
        subject_dn="/CN=Test CA",
        private_key=private_key,
        validity_days=365,
        key_type='rsa'
    )

    ext_oids = [ext.oid for ext in cert.extensions]

    assert x509.oid.ExtensionOID.BASIC_CONSTRAINTS in ext_oids
    assert x509.oid.ExtensionOID.KEY_USAGE in ext_oids
    assert x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER in ext_oids
    assert x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER in ext_oids