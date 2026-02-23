import pytest
import os
import stat
from micropki.crypto_utils import (
    generate_rsa_key, generate_ecc_key, encrypt_private_key,
    load_encrypted_private_key, set_secure_permissions,
    read_passphrase_from_file, CryptoError
)
from cryptography.hazmat.primitives.asymmetric import rsa, ec


class TestKeyGeneration:
    def test_generate_rsa_key_valid(self):
        key = generate_rsa_key(4096)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 4096

    def test_generate_ecc_key_valid(self):
        key = generate_ecc_key()
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == 'secp384r1'

    def test_generate_rsa_key_invalid_size(self):
        with pytest.raises(CryptoError, match="Failed to generate RSA key: key_size must be 4096 for RSA"):
            generate_rsa_key(2048)


class TestKeyEncryption:
    def test_encrypt_rsa_key(self, rsa_key, passphrase):
        encrypted = encrypt_private_key(rsa_key, passphrase)
        assert encrypted.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----')

    def test_encrypt_ecc_key(self, ecc_key, passphrase):
        encrypted = encrypt_private_key(ecc_key, passphrase)
        assert encrypted.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----')

    def test_load_encrypted_key(self, tmp_path, rsa_key, passphrase):
        key_path = tmp_path / "test.key"
        encrypted = encrypt_private_key(rsa_key, passphrase)
        key_path.write_bytes(encrypted)

        loaded_key = load_encrypted_private_key(str(key_path), passphrase)
        assert isinstance(loaded_key, rsa.RSAPrivateKey)


class TestFilePermissions:
    def test_set_secure_permissions_file(self, tmp_path):
        if os.name != 'posix':
            pytest.skip("Permission tests only on Unix-like systems")

        test_file = tmp_path / "test.txt"
        test_file.touch()
        set_secure_permissions(str(test_file), is_dir=False)

        mode = test_file.stat().st_mode
        assert mode & stat.S_IRWXG == 0
        assert mode & stat.S_IRWXO == 0

    def test_set_secure_permissions_dir(self, tmp_path):
        if os.name != 'posix':
            pytest.skip("Permission tests only on Unix-like systems")

        test_dir = tmp_path / "testdir"
        test_dir.mkdir()
        set_secure_permissions(str(test_dir), is_dir=True)

        mode = test_dir.stat().st_mode
        assert mode & stat.S_IRWXU == stat.S_IRWXU


class TestPassphraseHandling:
    def test_read_passphrase_file(self, tmp_path, passphrase):
        pass_file = tmp_path / "pass.txt"
        pass_file.write_bytes(passphrase + b'\n')

        result = read_passphrase_from_file(str(pass_file))
        assert result == passphrase

    def test_read_passphrase_file_no_newline(self, tmp_path, passphrase):
        pass_file = tmp_path / "pass.txt"
        pass_file.write_bytes(passphrase)

        result = read_passphrase_from_file(str(pass_file))
        assert result == passphrase

    def test_read_passphrase_file_not_found(self):
        with pytest.raises(CryptoError):
            read_passphrase_from_file("/nonexistent/file")

    def test_read_passphrase_file_empty(self, tmp_path):
        pass_file = tmp_path / "empty.txt"
        pass_file.touch()

        with pytest.raises(CryptoError):
            read_passphrase_from_file(str(pass_file))


class TestEdgeCases:
    def test_key_type_preservation(self, rsa_key, ecc_key, passphrase, tmp_path):
        key_path = tmp_path / "key.pem"
        encrypted = encrypt_private_key(rsa_key, passphrase)
        key_path.write_bytes(encrypted)

        loaded = load_encrypted_private_key(str(key_path), passphrase)
        assert isinstance(loaded, rsa.RSAPrivateKey)

        key_path.write_bytes(encrypt_private_key(ecc_key, passphrase))
        loaded = load_encrypted_private_key(str(key_path), passphrase)
        assert isinstance(loaded, ec.EllipticCurvePrivateKey)


@pytest.fixture
def rsa_key():
    return generate_rsa_key(4096)


@pytest.fixture
def ecc_key():
    return generate_ecc_key()


@pytest.fixture
def passphrase():
    return b'test-passphrase-123'