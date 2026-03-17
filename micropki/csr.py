from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
from typing import Union, Optional, List
import logging

logger = logging.getLogger(__name__)


class CSRError(Exception):
    pass


def generate_csr(
        subject_dn: str,
        private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        key_type: str,
        is_ca: bool = False,
        pathlen: Optional[int] = None
) -> x509.CertificateSigningRequest:
    try:
        logger.info("Starting CSR generation")

        from micropki.certificates import parse_dn_string
        subject = parse_dn_string(subject_dn)

        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(subject)

        if is_ca:
            basic_constraints = x509.BasicConstraints(ca=True, path_length=pathlen)
            builder = builder.add_extension(basic_constraints, critical=True)
            logger.info(f"Added CA basic constraints to CSR with pathlen={pathlen}")

        csr = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256() if key_type == 'rsa' else hashes.SHA384(),
            backend=default_backend()
        )

        logger.info("CSR generated successfully")
        return csr

    except Exception as e:
        logger.error(f"CSR generation failed: {str(e)}")
        raise CSRError(f"Failed to generate CSR: {str(e)}")


def sign_csr(
        csr: x509.CertificateSigningRequest,
        issuer_cert: x509.Certificate,
        issuer_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        validity_days: int,
        template_name: str,
        san_entries: Optional[List[str]] = None,
        is_ca: bool = False,
        pathlen: Optional[int] = None,
        key_type: str = 'rsa'
) -> x509.Certificate:
    try:
        logger.info("Starting CSR signing")

        from micropki.certificates import generate_serial_number, compute_ski
        from micropki.templates import get_template_extensions

        serial = generate_serial_number()

        not_before = datetime.now(timezone.utc)
        not_after = not_before + timedelta(days=validity_days)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(issuer_cert.subject)
        builder = builder.serial_number(serial)
        builder = builder.not_valid_before(not_before)
        builder = builder.not_valid_after(not_after)
        builder = builder.public_key(csr.public_key())

        if is_ca:
            basic_constraints = x509.BasicConstraints(ca=True, path_length=pathlen)
            builder = builder.add_extension(basic_constraints, critical=True)

            key_usage = x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            )
            builder = builder.add_extension(key_usage, critical=True)
        else:
            template_extensions = get_template_extensions(template_name, san_entries)
            for ext in template_extensions:
                builder = builder.add_extension(ext.value, ext.critical)

        ski = compute_ski(csr.public_key())
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier(ski),
            critical=False
        )

        issuer_ski = None
        for ext in issuer_cert.extensions:
            if ext.oid == x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                issuer_ski = ext.value.digest
                break

        if issuer_ski:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier(
                    key_identifier=issuer_ski,
                    authority_cert_issuer=None,
                    authority_cert_serial_number=None
                ),
                critical=False
            )

        signature_hash = hashes.SHA256() if key_type == 'rsa' else hashes.SHA384()
        certificate = builder.sign(
            private_key=issuer_key,
            algorithm=signature_hash,
            backend=default_backend()
        )

        logger.info(f"Certificate signed successfully with serial {hex(serial)}")
        return certificate

    except Exception as e:
        logger.error(f"CSR signing failed: {str(e)}")
        raise CSRError(f"Failed to sign CSR: {str(e)}")


def load_csr(csr_path: str) -> x509.CertificateSigningRequest:
    try:
        with open(csr_path, 'rb') as f:
            csr_data = f.read()

        csr = x509.load_pem_x509_csr(csr_data, default_backend())
        logger.info(f"Loaded CSR from {csr_path}")
        return csr

    except Exception as e:
        logger.error(f"Failed to load CSR: {str(e)}")
        raise CSRError(f"Cannot load CSR: {str(e)}")


def save_csr(csr: x509.CertificateSigningRequest, path: str) -> None:
    try:
        pem_data = csr.public_bytes(serialization.Encoding.PEM)
        with open(path, 'wb') as f:
            f.write(pem_data)
        logger.info(f"Saved CSR to {path}")

    except Exception as e:
        logger.error(f"Failed to save CSR: {str(e)}")
        raise CSRError(f"Cannot save CSR: {str(e)}")


def verify_csr_signature(csr: x509.CertificateSigningRequest) -> bool:
    try:
        public_key = csr.public_key()

        if csr.signature_hash_algorithm is None:
            logger.error("CSR has no signature hash algorithm")
            return False

        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                padding.PKCS1v15(),
                csr.signature_hash_algorithm
            )
        else:
            public_key.verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                csr.signature_hash_algorithm
            )
        logger.info("CSR signature verified successfully")
        return True
    except Exception as e:
        logger.error(f"CSR signature verification failed: {str(e)}")
        return False