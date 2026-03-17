from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
import secrets
from typing import Union, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class CertificateError(Exception):
    pass


def parse_dn_string(dn_string: str) -> x509.Name:
    try:
        logger.debug(f"Parsing DN string: {dn_string}")

        if dn_string.startswith('/'):
            parts = dn_string.strip('/').split('/')
        else:
            parts = dn_string.split(',')

        attributes = []
        for part in parts:
            part = part.strip()
            if '=' not in part:
                raise CertificateError(f"Invalid DN component: {part}")

            key, value = part.split('=', 1)
            key = key.strip().upper()
            value = value.strip()

            if key == 'CN':
                attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, value))
            elif key == 'O':
                attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, value))
            elif key == 'OU':
                attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, value))
            elif key == 'C':
                attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, value))
            elif key == 'ST':
                attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, value))
            elif key == 'L':
                attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, value))
            elif key == 'EMAIL':
                attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, value))
            else:
                logger.warning(f"Unknown DN component: {key}")

        if not attributes:
            raise CertificateError("No valid DN components found")

        return x509.Name(attributes)

    except Exception as e:
        logger.error(f"DN parsing failed: {str(e)}")
        raise CertificateError(f"Failed to parse DN: {str(e)}")


def generate_serial_number() -> int:
    serial_bytes = secrets.token_bytes(19)
    serial = int.from_bytes(serial_bytes, byteorder='big')
    logger.debug(f"Generated serial number: {hex(serial)}")
    return serial


def compute_ski(public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]) -> bytes:
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(public_bytes)
    ski = digest.finalize()

    logger.debug(f"Computed SKI: {ski.hex()}")
    return ski


def generate_key_pair_for_entity(key_type: str = 'rsa', key_size: int = 2048) -> Tuple[
    Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey], str]:

    try:
        if key_type == 'rsa':
            if key_size != 2048:
                logger.warning(f"RSA key size for end-entity should be 2048, got {key_size}")
            from micropki.crypto_utils import generate_rsa_key
            private_key = generate_rsa_key(key_size)
        else:
            from micropki.crypto_utils import generate_ecc_key
            private_key = generate_ecc_key()
            key_type = 'ecc'

        logger.info(f"Generated {key_type} key pair for end-entity")
        return private_key, key_type

    except Exception as e:
        logger.error(f"Failed to generate key pair: {str(e)}")
        raise CertificateError(f"Key generation failed: {str(e)}")


def create_self_signed_ca_certificate(
        subject_dn: str,
        private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        validity_days: int,
        key_type: str
) -> x509.Certificate:
    try:
        logger.info("Starting self-signed CA certificate generation")
        subject = parse_dn_string(subject_dn)
        issuer = subject

        serial = generate_serial_number()

        not_before = datetime.now(timezone.utc)
        not_after = not_before + timedelta(days=validity_days)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.serial_number(serial)
        builder = builder.not_valid_before(not_before)
        builder = builder.not_valid_after(not_after)
        builder = builder.public_key(private_key.public_key())

        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )

        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        ski = compute_ski(private_key.public_key())
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier(ski),
            critical=False
        )

        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=ski,
                authority_cert_issuer=None,
                authority_cert_serial_number=None
            ),
            critical=False
        )

        if key_type == 'rsa':
            signature_hash = hashes.SHA256()
            logger.info("Using SHA256 with RSA for signing")
        else:
            signature_hash = hashes.SHA384()
            logger.info("Using SHA384 with ECDSA for signing")

        certificate = builder.sign(
            private_key=private_key,
            algorithm=signature_hash,
            backend=default_backend()
        )

        logger.info("CA certificate generated successfully")
        return certificate

    except Exception as e:
        logger.error(f"Certificate generation failed: {str(e)}")
        raise CertificateError(f"Failed to create certificate: {str(e)}")


def certificate_to_pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(encoding=serialization.Encoding.PEM)


def verify_certificate_self_signed(cert_path: str) -> bool:
    try:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()

        certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

        if certificate.subject != certificate.issuer:
            raise CertificateError("Certificate is not self-signed (subject != issuer)")

        try:
            basic_constraints = certificate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            )
            if not basic_constraints.value.ca:
                raise CertificateError("Certificate is not a CA certificate")
        except x509.ExtensionNotFound:
            raise CertificateError("Basic Constraints extension not found")

        logger.info(f"Certificate {cert_path} verified successfully")
        return True

    except Exception as e:
        logger.error(f"Certificate verification failed: {str(e)}")
        raise CertificateError(f"Verification failed: {str(e)}")


def parse_san_string(san_string: str) -> Tuple[str, str]:

    if ':' not in san_string:
        raise CertificateError(f"Invalid SAN format: {san_string}")

    san_type, san_value = san_string.split(':', 1)
    san_type = san_type.lower()

    valid_types = ['dns', 'ip', 'email', 'uri']
    if san_type not in valid_types:
        raise CertificateError(f"Unsupported SAN type: {san_type}. Must be one of {valid_types}")

    return san_type, san_value
