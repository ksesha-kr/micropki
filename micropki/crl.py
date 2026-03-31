from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class CRLError(Exception):
    pass


def build_revoked_certificate(
        serial_number: int,
        revocation_date: datetime,
        reason: Optional[str] = None
) -> x509.RevokedCertificate:
    builder = x509.RevokedCertificateBuilder()
    builder = builder.serial_number(serial_number)
    builder = builder.revocation_date(revocation_date)

    return builder.build()


def generate_crl(
        issuer_cert: x509.Certificate,
        issuer_key,
        revoked_certs: List[Dict[str, Any]],
        next_update_days: int = 7,
        crl_number: int = 1
) -> x509.CertificateRevocationList:
    try:
        logger.info(f"Generating CRL with {len(revoked_certs)} revoked certificates")

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(issuer_cert.subject)
        builder = builder.last_update(datetime.now(timezone.utc))
        builder = builder.next_update(
            datetime.now(timezone.utc) + timedelta(days=next_update_days)
        )

        for revoked in revoked_certs:
            try:
                rev_date = datetime.fromisoformat(revoked['revocation_date'])
                serial_hex = revoked['serial_hex'].upper()
                try:
                    serial_num = int(serial_hex, 16)
                except ValueError:
                    raise CRLError(f"Invalid serial number format: {serial_hex}")

                rev_cert = build_revoked_certificate(
                    serial_number=serial_num,
                    revocation_date=rev_date,
                    reason=revoked.get('revocation_reason')
                )
                builder = builder.add_revoked_certificate(rev_cert)
            except Exception as e:
                logger.error(f"Error processing revoked certificate: {str(e)}")
                raise CRLError(f"Invalid certificate data: {str(e)}")

        aki = None
        for ext in issuer_cert.extensions:
            if ext.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                aki = ext.value
                break

        if aki:
            builder = builder.add_extension(aki, critical=False)

        builder = builder.add_extension(
            x509.CRLNumber(crl_number),
            critical=False
        )

        signature_algorithm = hashes.SHA256()
        if isinstance(issuer_key, ec.EllipticCurvePrivateKey):
            signature_algorithm = hashes.SHA384()

        crl = builder.sign(
            private_key=issuer_key,
            algorithm=signature_algorithm,
            backend=default_backend()
        )

        logger.info(f"CRL generated successfully with number {crl_number}")
        return crl

    except Exception as e:
        logger.error(f"CRL generation failed: {str(e)}")
        raise CRLError(f"Failed to generate CRL: {str(e)}")


def crl_to_pem(crl: x509.CertificateRevocationList) -> bytes:
    return crl.public_bytes(serialization.Encoding.PEM)


def load_crl(crl_path: str) -> x509.CertificateRevocationList:
    try:
        with open(crl_path, 'rb') as f:
            crl_data = f.read()
        return x509.load_pem_x509_crl(crl_data, default_backend())
    except Exception as e:
        raise CRLError(f"Failed to load CRL: {str(e)}")


def save_crl(crl: x509.CertificateRevocationList, path: str) -> None:
    try:
        with open(path, 'wb') as f:
            f.write(crl_to_pem(crl))
        logger.info(f"CRL saved to {path}")
    except Exception as e:
        raise CRLError(f"Failed to save CRL: {str(e)}")