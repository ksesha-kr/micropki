import argparse
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import os


def test_key_match(key_path: str, cert_path: str, passphrase_file: str):
    try:
        with open(passphrase_file, 'rb') as f:
            passphrase = f.read().rstrip(b'\n')

        with open(key_path, 'rb') as f:
            key_data = f.read()

        private_key = serialization.load_pem_private_key(
            key_data,
            password=passphrase,
            backend=default_backend()
        )

        with open(cert_path, 'rb') as f:
            cert_data = f.read()

        certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
        public_key = certificate.public_key()

        message = b"MicroPKI test message"

        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            signature = private_key.sign(
                message,
                ec.ECDSA(hashes.SHA384())
            )
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA384())
            )

        print("Private key matches certificate public key")
        return True

    except Exception as e:
        print(f"Test failed: {str(e)}")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test key-certificate matching")
    parser.add_argument("--key", required=True, help="Path to private key file")
    parser.add_argument("--cert", required=True, help="Path to certificate file")
    parser.add_argument("--passphrase-file", required=True, help="Path to passphrase file")

    args = parser.parse_args()

    success = test_key_match(args.key, args.cert, args.passphrase_file)
    sys.exit(0 if success else 1)