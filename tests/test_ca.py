import pytest
import tempfile
import os
from pathlib import Path
from micropki.ca import RootCA, CAError


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def passphrase_file(temp_dir):
    pass_file = Path(temp_dir) / "pass.txt"
    pass_file.write_bytes(b"test-passphrase\n")
    return str(pass_file)


def test_ca_initialization_rsa(temp_dir, passphrase_file):
    ca = RootCA(out_dir=temp_dir)
    result = ca.init_root_ca(
        subject="/CN=Test Root CA",
        key_type="rsa",
        key_size=4096,
        passphrase_file=passphrase_file,
        validity_days=365
    )

    assert Path(result['private_key']).exists()
    assert Path(result['certificate']).exists()
    assert Path(result['policy']).exists()


def test_ca_initialization_ecc(temp_dir, passphrase_file):
    ca = RootCA(out_dir=temp_dir)
    result = ca.init_root_ca(
        subject="CN=ECC Test CA,O=Test",
        key_type="ecc",
        key_size=384,
        passphrase_file=passphrase_file,
        validity_days=365
    )

    assert Path(result['private_key']).exists()
    assert Path(result['certificate']).exists()
    assert Path(result['policy']).exists()


def test_ca_init_invalid_passphrase_file(temp_dir):
    ca = RootCA(out_dir=temp_dir)
    with pytest.raises(CAError):
        ca.init_root_ca(
            subject="/CN=Test Root CA",
            key_type="rsa",
            key_size=4096,
            passphrase_file="/nonexistent/pass.txt",
            validity_days=365
        )
