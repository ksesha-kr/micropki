from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timezone
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class ChainError(Exception):
    pass


def load_certificate(path: str) -> x509.Certificate:
    try:
        with open(path, 'rb') as f:
            cert_data = f.read()
        return x509.load_pem_x509_certificate(cert_data, default_backend())
    except Exception as e:
        raise ChainError(f"Failed to load certificate from {path}: {str(e)}")


def verify_signature(issuer_cert: x509.Certificate, subject_cert: x509.Certificate) -> bool:
    try:
        issuer_public_key = issuer_cert.public_key()

        if subject_cert.signature_hash_algorithm is None:
            logger.error("Certificate has no signature hash algorithm")
            return False

        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            issuer_public_key.verify(
                subject_cert.signature,
                subject_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                subject_cert.signature_hash_algorithm
            )
        else:
            issuer_public_key.verify(
                subject_cert.signature,
                subject_cert.tbs_certificate_bytes,
                subject_cert.signature_hash_algorithm
            )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        logger.error(f"Signature verification error: {str(e)}")
        return False


def verify_validity_period(cert: x509.Certificate, at_time: Optional[datetime] = None) -> bool:
    if at_time is None:
        at_time = datetime.now(timezone.utc)

    return cert.not_valid_before_utc <= at_time <= cert.not_valid_after_utc


def verify_basic_constraints(cert: x509.Certificate, expected_ca: bool) -> bool:
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )

        if basic_constraints.value.ca != expected_ca:
            logger.error(f"CA flag mismatch: expected {expected_ca}, got {basic_constraints.value.ca}")
            return False

        return True
    except x509.ExtensionNotFound:
        if expected_ca:
            logger.error("CA certificate missing Basic Constraints")
            return False
        return True


def verify_chain(
        leaf_path: str,
        intermediate_path: str,
        root_path: str,
        at_time: Optional[datetime] = None
) -> bool:
    try:
        leaf = load_certificate(leaf_path)
        intermediate = load_certificate(intermediate_path)
        root = load_certificate(root_path)

        logger.info("Starting chain validation")

        if not verify_validity_period(leaf, at_time):
            logger.error("Leaf certificate validity period check failed")
            return False

        if not verify_validity_period(intermediate, at_time):
            logger.error("Intermediate certificate validity period check failed")
            return False

        if not verify_validity_period(root, at_time):
            logger.error("Root certificate validity period check failed")
            return False

        if not verify_basic_constraints(leaf, expected_ca=False):
            logger.error("Leaf certificate Basic Constraints check failed")
            return False

        if not verify_basic_constraints(intermediate, expected_ca=True):
            logger.error("Intermediate certificate Basic Constraints check failed")
            return False

        if not verify_basic_constraints(root, expected_ca=True):
            logger.error("Root certificate Basic Constraints check failed")
            return False

        if not verify_signature(intermediate, leaf):
            logger.error("Leaf signature verification by Intermediate failed")
            return False

        if not verify_signature(root, intermediate):
            logger.error("Intermediate signature verification by Root failed")
            return False

        if leaf.issuer != intermediate.subject:
            logger.error("Leaf issuer does not match Intermediate subject")
            return False

        if intermediate.issuer != root.subject:
            logger.error("Intermediate issuer does not match Root subject")
            return False

        logger.info("Chain validation successful")
        return True

    except Exception as e:
        logger.error(f"Chain validation failed: {str(e)}")
        return False


def get_chain_info(leaf_path: str, intermediate_path: str, root_path: str) -> dict:
    leaf = load_certificate(leaf_path)
    intermediate = load_certificate(intermediate_path)
    root = load_certificate(root_path)

    return {
        'leaf': {
            'subject': leaf.subject.rfc4514_string(),
            'issuer': leaf.issuer.rfc4514_string(),
            'serial': hex(leaf.serial_number),
            'valid_from': leaf.not_valid_before_utc.isoformat(),
            'valid_to': leaf.not_valid_after_utc.isoformat()
        },
        'intermediate': {
            'subject': intermediate.subject.rfc4514_string(),
            'issuer': intermediate.issuer.rfc4514_string(),
            'serial': hex(intermediate.serial_number)
        },
        'root': {
            'subject': root.subject.rfc4514_string(),
            'serial': hex(root.serial_number)
        }
    }