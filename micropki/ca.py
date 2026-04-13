import os
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from micropki.crypto_utils import (
    generate_rsa_key, generate_ecc_key, encrypt_private_key,
    set_secure_permissions, read_passphrase_from_file, CryptoError,
    load_encrypted_private_key
)
from micropki.certificates import (
    create_self_signed_ca_certificate, certificate_to_pem,
    verify_certificate_self_signed, CertificateError,
    generate_key_pair_for_entity, parse_san_string
)
from micropki.csr import generate_csr, sign_csr, save_csr, load_csr, verify_csr_signature
from micropki.templates import validate_san_types, TemplateError
from micropki.logger import setup_logger
import logging

from micropki.database import CertificateDatabase, DatabaseError
from micropki.serial import SerialGenerator

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

            csr_dir = self.out_dir / "csrs"
            csr_dir.mkdir(exist_ok=True)

            self.logger.info("Directory structure created successfully")
        except Exception as e:
            self.logger.error(f"Failed to create directories: {str(e)}")
            raise CAError(f"Cannot create directories: {str(e)}")

    def _save_private_key(self, key_pem: bytes, filename: str = "ca.key.pem") -> Path:

        key_path = self.private_dir / filename

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

    def _save_certificate(self, cert_pem: bytes, filename: str = "ca.cert.pem") -> Path:

        cert_path = self.certs_dir / filename

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

--- End of Policy Document ---
"""
            with open(policy_path, 'w', encoding='utf-8') as f:
                f.write(policy_content)

            self.logger.info(f"Policy document created successfully")
            return policy_path
        except Exception as e:
            self.logger.error(f"Failed to create policy file: {str(e)}")
            raise CAError(f"Cannot create policy file: {str(e)}")

    def _update_policy_with_intermediate(self, subject, serial, not_before, not_after, key_type, key_size, pathlen,
                                         issuer_dn):
        policy_path = self.out_dir / "policy.txt"

        with open(policy_path, 'a', encoding='utf-8') as f:
            f.write(f"""
Intermediate CA Information
===========================
Created: {datetime.now(timezone.utc).isoformat()}

Subject DN: {subject}
Issuer: {issuer_dn}
Certificate Serial Number: {hex(serial)}
Validity Period:
  Not Before: {not_before.isoformat()}
  Not After:  {not_after.isoformat()}

Key Details:
-----------
Algorithm: {'RSA' if key_type == 'rsa' else 'ECC'}
Key Size: {key_size} bits
Path Length Constraint: {pathlen}

--- End of Intermediate CA Section ---
""")

        self.logger.info(f"Policy document updated with Intermediate CA info")

    def init_root_ca(
            self,
            subject: str,
            key_type: str,
            key_size: int,
            passphrase_file: str,
            validity_days: int,
            db_path: Optional[str] = None
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
            key_path = self._save_private_key(encrypted_key, "ca.key.pem")

            cert_pem = certificate_to_pem(certificate)
            cert_path = self._save_certificate(cert_pem, "ca.cert.pem")

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

            if db_path:
                self._store_certificate_in_db(certificate, db_path)

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

    def issue_intermediate(
            self,
            root_cert_path: str,
            root_key_path: str,
            root_passphrase_file: str,
            subject: str,
            key_type: str,
            key_size: int,
            passphrase_file: str,
            validity_days: int,
            pathlen: int = 0,
            db_path: Optional[str] = None
    ) -> Dict[str, str]:
        try:
            self.logger.info("Starting Intermediate CA issuance")

            root_passphrase = read_passphrase_from_file(root_passphrase_file)
            root_key = load_encrypted_private_key(root_key_path, root_passphrase)

            with open(root_cert_path, 'rb') as f:
                root_cert_data = f.read()
            root_cert = x509.load_pem_x509_certificate(root_cert_data, default_backend())

            self._create_directories()

            if key_type == 'rsa':
                intermediate_key = generate_rsa_key(key_size)
            else:
                intermediate_key = generate_ecc_key()

            csr = generate_csr(
                subject_dn=subject,
                private_key=intermediate_key,
                key_type=key_type,
                is_ca=True,
                pathlen=pathlen
            )

            csr_dir = self.out_dir / "csrs"
            csr_dir.mkdir(exist_ok=True)
            csr_path = csr_dir / "intermediate.csr.pem"
            save_csr(csr, str(csr_path))

            intermediate_passphrase = read_passphrase_from_file(passphrase_file)
            encrypted_key = encrypt_private_key(intermediate_key, intermediate_passphrase)
            key_path = self._save_private_key(encrypted_key, "intermediate.key.pem")

            intermediate_cert = sign_csr(
                csr=csr,
                issuer_cert=root_cert,
                issuer_key=root_key,
                validity_days=validity_days,
                template_name='ca',
                is_ca=True,
                pathlen=pathlen,
                key_type=key_type
            )

            cert_path = self._save_certificate(
                intermediate_cert.public_bytes(serialization.Encoding.PEM),
                "intermediate.cert.pem"
            )

            self._update_policy_with_intermediate(
                subject=subject,
                serial=intermediate_cert.serial_number,
                not_before=intermediate_cert.not_valid_before_utc,
                not_after=intermediate_cert.not_valid_after_utc,
                key_type=key_type,
                key_size=key_size,
                pathlen=pathlen,
                issuer_dn=root_cert.subject.rfc4514_string()
            )

            if db_path:
                self._store_certificate_in_db(intermediate_cert, db_path)

            self.logger.info("Intermediate CA issued successfully")

            return {
                'private_key': str(key_path),
                'certificate': str(cert_path),
                'csr': str(csr_path)
            }

        except Exception as e:
            self.logger.error(f"Intermediate CA issuance failed: {str(e)}")
            raise CAError(str(e))

    def issue_certificate(
            self,
            ca_cert_path: str,
            ca_key_path: str,
            ca_passphrase_file: str,
            template: str,
            subject: str,
            san_entries: Optional[List[str]] = None,
            out_dir: str = None,
            validity_days: int = 365,
            csr_path: Optional[str] = None,
            db_path: Optional[str] = None
    ) -> Dict[str, str]:

        try:
            self.logger.info(f"Starting certificate issuance with template: {template}")

            if san_entries:
                validate_san_types(template, san_entries)

            ca_passphrase = read_passphrase_from_file(ca_passphrase_file)
            ca_key = load_encrypted_private_key(ca_key_path, ca_passphrase)

            with open(ca_cert_path, 'rb') as f:
                ca_cert_data = f.read()
            ca_cert = x509.load_pem_x509_certificate(ca_cert_data, default_backend())

            if out_dir is None:
                out_dir = str(self.certs_dir)
            out_path = Path(out_dir)
            out_path.mkdir(parents=True, exist_ok=True)

            if csr_path:
                csr = load_csr(csr_path)
                if not verify_csr_signature(csr):
                    raise CAError("CSR signature verification failed")

                for ext in csr.extensions:
                    if ext.oid == x509.oid.ExtensionOID.BASIC_CONSTRAINTS:
                        if ext.value.ca:
                            raise CAError("CSR requests CA=True - rejecting for end-entity certificate")

                cert = sign_csr(
                    csr=csr,
                    issuer_cert=ca_cert,
                    issuer_key=ca_key,
                    validity_days=validity_days,
                    template_name=template,
                    san_entries=san_entries,
                    is_ca=False,
                    key_type='rsa'
                )

                cert_filename = f"csr_signed_{cert.serial_number}.cert.pem"
                cert_path = out_path / cert_filename
                with open(cert_path, 'wb') as f:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))

                if db_path:
                    self._store_certificate_in_db(cert, db_path)

                return {'certificate': str(cert_path)}

            else:
                private_key, actual_key_type = generate_key_pair_for_entity('rsa', 2048)

                csr = generate_csr(subject, private_key, actual_key_type, is_ca=False)

                cert = sign_csr(
                    csr=csr,
                    issuer_cert=ca_cert,
                    issuer_key=ca_key,
                    validity_days=validity_days,
                    template_name=template,
                    san_entries=san_entries,
                    is_ca=False,
                    key_type=actual_key_type
                )

                from micropki.certificates import parse_dn_string
                cn = "cert"
                for attr in parse_dn_string(subject):
                    if attr.oid == x509.oid.NameOID.COMMON_NAME:
                        cn = attr.value.replace(' ', '_').replace('*', 'wildcard')
                        break

                cert_filename = f"{cn}.cert.pem"
                key_filename = f"{cn}.key.pem"

                cert_path = out_path / cert_filename
                key_path = out_path / key_filename

                with open(cert_path, 'wb') as f:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))

                unencrypted_key = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                with open(key_path, 'wb') as f:
                    f.write(unencrypted_key)
                set_secure_permissions(str(key_path), is_dir=False)

                self.logger.warning(f"Unencrypted private key saved to {key_path}")

                if db_path:
                    self._store_certificate_in_db(cert, db_path)

                return {
                    'certificate': str(cert_path),
                    'private_key': str(key_path)
                }

        except TemplateError as e:
            self.logger.error(f"Template validation failed: {str(e)}")
            raise CAError(str(e))
        except Exception as e:
            self.logger.error(f"Certificate issuance failed: {str(e)}")
            raise CAError(str(e))

    def _store_certificate_in_db(self, cert: x509.Certificate, db_path: str):
        try:
            from micropki.certificates import certificate_to_pem
            db = CertificateDatabase(db_path)

            cert_data = {
                'serial_hex': hex(cert.serial_number)[2:].upper(),
                'subject': cert.subject.rfc4514_string(),
                'issuer': cert.issuer.rfc4514_string(),
                'not_before': cert.not_valid_before_utc.isoformat(),
                'not_after': cert.not_valid_after_utc.isoformat(),
                'cert_pem': certificate_to_pem(cert).decode('utf-8'),
                'status': 'valid'
            }

            db.insert_certificate(cert_data)
            db.close()
            self.logger.info(f"Certificate stored in database with serial {cert_data['serial_hex']}")

        except DatabaseError as e:
            self.logger.error(f"Database insertion failed: {str(e)}")
            raise CAError(f"Failed to store certificate in database: {str(e)}")

    def revoke_certificate(self, serial_hex: str, reason: str, db_path: str, force: bool = False) -> Dict[str, Any]:
        from micropki.database import CertificateDatabase
        from micropki.revocation import revoke_certificate as revoke

        try:
            db = CertificateDatabase(db_path)
            result = revoke(db, serial_hex, reason, force)
            db.close()
            return result
        except Exception as e:
            self.logger.error(f"Revocation failed: {str(e)}")
            raise CAError(str(e))

    def generate_crl(
            self,
            ca_type: str,
            ca_cert_path: str,
            ca_key_path: str,
            ca_passphrase_file: str,
            db_path: str,
            out_dir: str,
            next_update_days: int = 7,
            out_file: Optional[str] = None
    ) -> Dict[str, Any]:
        from micropki.database import CertificateDatabase
        from micropki.crypto_utils import load_encrypted_private_key, read_passphrase_from_file
        from micropki.crl import generate_crl, save_crl, get_reason_code
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from pathlib import Path

        try:
            self.logger.info(f"Generating CRL for {ca_type} CA")

            with open(ca_cert_path, 'rb') as f:
                ca_cert_data = f.read()
            ca_cert = x509.load_pem_x509_certificate(ca_cert_data, default_backend())

            ca_passphrase = read_passphrase_from_file(ca_passphrase_file)
            ca_key = load_encrypted_private_key(ca_key_path, ca_passphrase)

            db = CertificateDatabase(db_path)
            revoked_certs = db.get_revoked_certificates_by_issuer(ca_cert.subject.rfc4514_string())

            crl_metadata = db.get_crl_metadata(ca_cert.subject.rfc4514_string())
            crl_number = 1
            if crl_metadata:
                crl_number = crl_metadata['crl_number'] + 1

            crl = generate_crl(
                issuer_cert=ca_cert,
                issuer_key=ca_key,
                revoked_certs=revoked_certs,
                next_update_days=next_update_days,
                crl_number=crl_number
            )

            if out_file:
                crl_path = Path(out_file)
            else:
                crl_dir = Path(out_dir) / "crl"
                crl_dir.mkdir(parents=True, exist_ok=True)
                crl_path = crl_dir / f"{ca_type}.crl.pem"

            save_crl(crl, str(crl_path))

            db.update_crl_metadata(
                ca_subject=ca_cert.subject.rfc4514_string(),
                crl_number=crl_number,
                next_update=(datetime.now(timezone.utc) + timedelta(days=next_update_days)).isoformat(),
                crl_path=str(crl_path)
            )

            db.close()

            self.logger.info(f"CRL generated successfully for {ca_type} CA")

            return {
                'crl_path': str(crl_path),
                'crl_number': crl_number,
                'revoked_count': len(revoked_certs),
                'next_update_days': next_update_days
            }

        except Exception as e:
            self.logger.error(f"CRL generation failed: {str(e)}")
            raise CAError(str(e))

    def check_revoked(self, serial_hex: str, db_path: str) -> Dict[str, Any]:
        from micropki.database import CertificateDatabase
        from micropki.revocation import check_revoked as check

        try:
            db = CertificateDatabase(db_path)
            result = check(db, serial_hex)
            db.close()
            return result
        except Exception as e:
            self.logger.error(f"Status check failed: {str(e)}")
            raise CAError(str(e))

    def issue_ocsp_certificate(
            self,
            ca_cert_path: str,
            ca_key_path: str,
            ca_passphrase_file: str,
            subject: str,
            key_type: str,
            key_size: int,
            out_dir: str,
            validity_days: int = 365,
            san_entries: Optional[List[str]] = None,
            db_path: Optional[str] = None
    ) -> Dict[str, str]:
        try:
            self.logger.info(f"Issuing OCSP responder certificate")

            from micropki.crypto_utils import (
                load_encrypted_private_key, read_passphrase_from_file,
                generate_rsa_key, generate_ecc_key, encrypt_private_key,
                set_secure_permissions
            )
            from micropki.certificates import (
                parse_dn_string, generate_serial_number, compute_ski,
                certificate_to_pem
            )
            from micropki.csr import generate_csr, sign_csr
            from cryptography import x509
            from cryptography.x509.oid import ExtendedKeyUsageOID
            from cryptography.hazmat.backends import default_backend

            ca_passphrase = read_passphrase_from_file(ca_passphrase_file)
            ca_key = load_encrypted_private_key(ca_key_path, ca_passphrase)

            with open(ca_cert_path, 'rb') as f:
                ca_cert_data = f.read()
            ca_cert = x509.load_pem_x509_certificate(ca_cert_data, default_backend())

            if key_type == 'rsa':
                ocsp_key = generate_rsa_key(key_size)
            else:
                ocsp_key = generate_ecc_key()

            csr = generate_csr(subject, ocsp_key, key_type, is_ca=False)

            cert = sign_csr(
                csr=csr,
                issuer_cert=ca_cert,
                issuer_key=ca_key,
                validity_days=validity_days,
                template_name='ocsp',
                san_entries=san_entries,
                is_ca=False,
                key_type=key_type
            )

            out_path = Path(out_dir)
            out_path.mkdir(parents=True, exist_ok=True)

            cert_filename = f"ocsp.cert.pem"
            key_filename = f"ocsp.key.pem"

            cert_path = out_path / cert_filename
            key_path = out_path / key_filename

            with open(cert_path, 'wb') as f:
                f.write(certificate_to_pem(cert))

            unencrypted_key = ocsp_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(key_path, 'wb') as f:
                f.write(unencrypted_key)
            set_secure_permissions(str(key_path), is_dir=False)

            self.logger.warning(f"Unencrypted OCSP private key saved to {key_path}")

            if db_path:
                self._store_certificate_in_db(cert, db_path)

            return {
                'certificate': str(cert_path),
                'private_key': str(key_path)
            }

        except Exception as e:
            self.logger.error(f"OCSP certificate issuance failed: {str(e)}")
            raise CAError(str(e))
