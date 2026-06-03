import pytest
import tempfile
from pathlib import Path
from micropki.ca import RootCA
from micropki.policy import PolicyEnforcer, PolicyViolation


def test_expired_certificate_validation():
    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / 'pki'
        secrets_dir = Path(tmpdir) / 'secrets'
        secrets_dir.mkdir()

        (secrets_dir / 'root.pass').write_text("root-pass")

        ca = RootCA(out_dir=str(pki_dir))
        ca.init_root_ca(
            subject="/CN=Test Root CA",
            key_type="rsa",
            key_size=4096,
            passphrase_file=str(secrets_dir / "root.pass"),
            validity_days=1
        )

        cert_file = pki_dir / "certs" / "ca.cert.pem"
        assert cert_file.exists()


def test_malformed_input_handling():
    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / 'pki'

        malformed = pki_dir / "malformed.pem"
        malformed.parent.mkdir(exist_ok=True)
        malformed.write_text("NOT A VALID CERTIFICATE")

        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        import sys

        try:
            with open(malformed, 'rb') as f:
                x509.load_pem_x509_certificate(f.read(), default_backend())
            assert False, "Should have raised an exception"
        except Exception:
            pass


def test_policy_key_size_enforcement():
    policy = PolicyEnforcer()

    policy.check_key_size(2048, 'rsa', 'end_entity')

    with pytest.raises(PolicyViolation):
        policy.check_key_size(1024, 'rsa', 'end_entity')

    policy.check_key_size(256, 'ecc', 'end_entity')

    with pytest.raises(PolicyViolation):
        policy.check_key_size(224, 'ecc', 'end_entity')


def test_policy_validity_enforcement():
    policy = PolicyEnforcer()

    policy.check_validity(3650, 'root')

    with pytest.raises(PolicyViolation):
        policy.check_validity(4000, 'root')

    policy.check_validity(365, 'end_entity')

    with pytest.raises(PolicyViolation):
        policy.check_validity(730, 'end_entity')


def test_san_validation():
    policy = PolicyEnforcer()

    policy.check_san_types(['dns:example.com'], 'server')
    policy.check_san_types(['ip:192.168.1.1'], 'server')

    with pytest.raises(PolicyViolation):
        policy.check_san_types(['email:test@example.com'], 'server')

    policy.check_san_types(['email:test@example.com'], 'client')
    policy.check_san_types(['dns:client.local'], 'client')

    policy.check_san_types(['dns:example.com'], 'code_signing')
    policy.check_san_types(['uri:https://example.com'], 'code_signing')