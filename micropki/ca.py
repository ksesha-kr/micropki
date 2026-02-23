import os
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from micropki.crypto_utils import (
    generate_rsa_key, generate_ecc_key, encrypt_private_key,
    set_secure_permissions, read_passphrase_from_file, CryptoError
)
from micropki.certificates import (
    create_self_signed_ca_certificate, certificate_to_pem,
    verify_certificate_self_signed, CertificateError
)
from micropki.logger import setup_logger
import logging

logger = logging.getLogger(__name__)


class CAError(Exception):
    pass


class RootCA:

    def __init__(self, out_dir: str, log_file: Optional[str] = None):
        self.out_dir = Path(out_dir)
        self.private_dir = self.out_dir / "private"
        self.certs_dir = self.out_dir / "certs"

        self.logger = setup_logger("micropki.ca", log_file)

        self.config: Dict[str, Any] = {}

    def _create_directories(self) -> None:
        try:
            self.logger.info(f"Creating directory structure in {self.out_dir}")

            self.out_dir.mkdir(parents=True, exist_ok=True)

            self.private_dir.mkdir(exist_ok=True)
            set_secure_permissions(str(self.private_dir), is_dir=True)

            self.certs_dir.mkdir(exist_ok=True)

            self.logger.info("Directory structure created successfully")
        except Exception as e:
            self.logger.error(f"Failed to create directories: {str(e)}")
            raise CAError(f"Cannot create directories: {str(e)}")

    def _save_private_key(self, key_pem: bytes) -> Path:
        key_path = self.private_dir / "ca.key.pem"

        try:
            self.logger.info(f"Saving private key to {key_path}")

            with open(key_path, 'wb') as f:
                f.write(key_pem)

            set_secure_permissions(str(key_path), is_dir=False)

            self.logger.info(f"Private key saved successfully")
            return key_path
        except Exception as e:
            self.logger.error(f"Failed to save private key: {str(e)}")
            raise CAError(f"Cannot save private key: {str(e)}")

    def _save_certificate(self, cert_pem: bytes) -> Path:

        cert_path = self.certs_dir / "ca.cert.pem"

        try:
            self.logger.info(f"Saving certificate to {cert_path}")

            with open(cert_path, 'wb') as f:
                f.write(cert_pem)

            self.logger.info(f"Certificate saved successfully")
            return cert_path
        except Exception as e:
            self.logger.error(f"Failed to save certificate: {str(e)}")
            raise CAError(f"Cannot save certificate: {str(e)}")

    def _create_policy_file(
            self,
            subject: str,
            serial: int,
            not_before: datetime,
            not_after: datetime,
            key_type: str,
            key_size: int
    ) -> Path:
        policy_path = self.out_dir / "policy.txt"

        try:
            self.logger.info(f"Creating policy document at {policy_path}")

            policy_content = f"""MicroPKI Certificate Policy Document
==================================
Version: 1.0
Created: {datetime.now(timezone.utc).isoformat()}

CA Information:
--------------
Subject DN: {subject}
Certificate Serial Number: {hex(serial)}
Validity Period:
  Not Before: {not_before.isoformat()}
  Not After:  {not_after.isoformat()}

Key Details:
-----------
Algorithm: {'RSA' if key_type == 'rsa' else 'ECC'}
Key Size: {key_size} bits

Policy Statement:
----------------
This Root CA is part of the MicroPKI demonstration project.
It is intended for educational and testing purposes only.
This CA should not be used in production environments.

Certificate Usage:
-----------------
* Issuing subordinate CAs
* Code signing (if extended)
* TLS/SSL server certificates (if extended)

Certificate Revocation:
----------------------
This CA does not maintain a CRL or OCSP responder.
Certificate revocation is not supported.

Contact:
--------
MicroPKI Project
https://github.com/micropki/micropki

--- End of Policy Document ---
"""
            with open(policy_path, 'w', encoding='utf-8') as f:
                f.write(policy_content)

            self.logger.info(f"Policy document created successfully")
            return policy_path
        except Exception as e:
            self.logger.error(f"Failed to create policy file: {str(e)}")
            raise CAError(f"Cannot create policy file: {str(e)}")

    def init_root_ca(
            self,
            subject: str,
            key_type: str,
            key_size: int,
            passphrase_file: str,
            validity_days: int
    ) -> Dict[str, str]:
        try:
            self.logger.info("Starting Root CA initialization")

            self.config.update({
                'subject': subject,
                'key_type': key_type,
                'key_size': key_size,
                'validity_days': validity_days
            })

            self._create_directories()

            passphrase = read_passphrase_from_file(passphrase_file)

            if key_type == 'rsa':
                private_key = generate_rsa_key(key_size)
            else:
                private_key = generate_ecc_key()

            certificate = create_self_signed_ca_certificate(
                subject_dn=subject,
                private_key=private_key,
                validity_days=validity_days,
                key_type=key_type
            )

            encrypted_key = encrypt_private_key(private_key, passphrase)
            key_path = self._save_private_key(encrypted_key)

            cert_pem = certificate_to_pem(certificate)
            cert_path = self._save_certificate(cert_pem)

            policy_path = self._create_policy_file(
                subject=subject,
                serial=certificate.serial_number,
                not_before=certificate.not_valid_before_utc,
                not_after=certificate.not_valid_after_utc,
                key_type=key_type,
                key_size=key_size
            )

            try:
                verify_certificate_self_signed(str(cert_path))
                self.logger.info("Self-consistency check passed")
            except CertificateError as e:
                self.logger.warning(f"Self-consistency check warning: {str(e)}")

            self.logger.info("Root CA initialization completed successfully")

            return {
                'private_key': str(key_path),
                'certificate': str(cert_path),
                'policy': str(policy_path),
                'out_dir': str(self.out_dir)
            }

        except (CryptoError, CertificateError) as e:
            self.logger.error(f"CA initialization failed: {str(e)}")
            raise CAError(str(e))
        except Exception as e:
            self.logger.error(f"Unexpected error during CA initialization: {str(e)}")
            raise CAError(f"CA initialization failed: {str(e)}")