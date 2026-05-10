from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path
import requests
import logging

logger = logging.getLogger(__name__)


class ClientError(Exception):
    pass


class PKIClient:
    def __init__(self, log_file: Optional[str] = None):
        self.log_file = log_file

    def generate_csr(
            self,
            subject_dn: str,
            key_type: str,
            key_size: int,
            san_entries: Optional[List[str]] = None,
            out_key: str = './key.pem',
            out_csr: str = './request.csr.pem'
    ) -> Dict[str, str]:
        from micropki.crypto_utils import generate_rsa_key, generate_ecc_key, set_secure_permissions
        from micropki.certificates import parse_dn_string
        from micropki.csr import generate_csr, save_csr

        if key_type == 'rsa':
            if key_size not in [2048, 4096]:
                raise ClientError(f"RSA key size must be 2048 or 4096, got {key_size}")
            key = generate_rsa_key(key_size)
        else:
            if key_size not in [256, 384]:
                raise ClientError(f"ECC key size must be 256 or 384, got {key_size}")
            key = generate_ecc_key()

        csr = generate_csr(subject_dn, key, key_type, is_ca=False)

        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(out_key, 'wb') as f:
            f.write(key_pem)
        set_secure_permissions(out_key, is_dir=False)

        save_csr(csr, out_csr)

        logger.info(f"Generated CSR: {out_csr}")
        logger.warning(f"Private key saved unencrypted: {out_key}")

        return {'key': out_key, 'csr': out_csr}

    def request_certificate(
            self,
            csr_path: str,
            template: str,
            ca_url: str,
            out_cert: str = './cert.pem',
            api_key: Optional[str] = None
    ) -> Dict[str, str]:
        with open(csr_path, 'rb') as f:
            csr_data = f.read()

        headers = {'Content-Type': 'application/x-pem-file'}
        if api_key:
            headers['X-API-Key'] = api_key

        response = requests.post(
            f"{ca_url.rstrip('/')}/request-cert",
            params={'template': template},
            data=csr_data,
            headers=headers,
            timeout=30
        )

        if response.status_code != 201:
            raise ClientError(f"Certificate request failed: {response.status_code} - {response.text}")

        with open(out_cert, 'wb') as f:
            f.write(response.content)

        logger.info(f"Certificate saved: {out_cert}")

        return {'certificate': out_cert}