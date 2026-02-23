import os
import stat
from typing import Union, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import logging

logger = logging.getLogger(__name__)


class CryptoError(Exception):
    pass


def generate_rsa_key(key_size: int = 4096) -> rsa.RSAPrivateKey:
    try:
        if key_size != 4096:
            raise ValueError("key_size must be 4096 for RSA")

        logger.info(f"Starting RSA key generation ({key_size} bits)")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        logger.info("RSA key generation completed successfully")
        return private_key
    except Exception as e:
        logger.error(f"RSA key generation failed: {str(e)}")
        raise CryptoError(f"Failed to generate RSA key: {str(e)}")


def generate_ecc_key() -> ec.EllipticCurvePrivateKey:
    try:
        logger.info("Starting ECC key generation (P-384)")
        private_key = ec.generate_private_key(
            curve=ec.SECP384R1(),
            backend=default_backend()
        )
        logger.info("ECC key generation completed successfully")
        return private_key
    except Exception as e:
        logger.error(f"ECC key generation failed: {str(e)}")
        raise CryptoError(f"Failed to generate ECC key: {str(e)}")


def encrypt_private_key(
        private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        passphrase: bytes
) -> bytes:
    try:
        logger.info("Encrypting private key with passphrase")
        encrypted_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
        )
        logger.info("Private key encrypted successfully")
        return encrypted_key
    except Exception as e:
        logger.error(f"Key encryption failed: {str(e)}")
        raise CryptoError(f"Failed to encrypt private key: {str(e)}")


def load_encrypted_private_key(
        key_path: str,
        passphrase: bytes
) -> Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]:
    try:
        logger.info(f"Loading encrypted private key from {key_path}")
        with open(key_path, 'rb') as f:
            pem_data = f.read()

        private_key = serialization.load_pem_private_key(
            pem_data,
            password=passphrase,
            backend=default_backend()
        )
        logger.info("Private key loaded and decrypted successfully")
        return private_key
    except Exception as e:
        logger.error(f"Failed to load encrypted private key: {str(e)}")
        raise CryptoError(f"Failed to load private key: {str(e)}")


def set_secure_permissions(path: str, is_dir: bool = False) -> None:
    try:
        if os.name == 'posix':
            if is_dir:
                os.chmod(path, stat.S_IRWXU)
                logger.debug(f"Set directory permissions 0o700 for {path}")
            else:
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
                logger.debug(f"Set file permissions 0o600 for {path}")
    except Exception as e:
        logger.warning(f"Failed to set permissions for {path}: {str(e)}")


def read_passphrase_from_file(passphrase_file: str) -> bytes:
    try:
        logger.info(f"Reading passphrase from {passphrase_file}")
        with open(passphrase_file, 'rb') as f:
            passphrase = f.read().rstrip(b'\n')

        if not passphrase:
            raise CryptoError("Passphrase file is empty")

        return passphrase
    except Exception as e:
        logger.error(f"Failed to read passphrase file: {str(e)}")
        raise CryptoError(f"Cannot read passphrase file: {str(e)}")