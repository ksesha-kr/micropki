from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.ocsp import (
    OCSPRequestBuilder, OCSPResponseBuilder, OCSPRequest,
    OCSPResponse, OCSPResponseStatus
)
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Dict, Any, List
import logging

logger = logging.getLogger(__name__)

OCSP_NONCE_OID = ObjectIdentifier("1.3.6.1.5.5.7.48.1.2")
OCSP_BASIC_RESPONSE_OID = ObjectIdentifier("1.3.6.1.5.5.7.48.1.1")


class OCSPError(Exception):
    pass

REASON_CODES = {
    'unspecified': 0,
    'keyCompromise': 1,
    'cACompromise': 2,
    'affiliationChanged': 3,
    'superseded': 4,
    'cessationOfOperation': 5,
    'certificateHold': 6,
    'removeFromCRL': 8,
    'privilegeWithdrawn': 9,
    'aACompromise': 10
}


def get_reason_code(reason_str: str) -> int:
    if reason_str is None:
        return 0

    reason_str_lower = reason_str.lower().replace('_', '').replace('-', '')

    mapping = {
        'keycompromise': 'keyCompromise',
        'cacompromise': 'cACompromise',
        'affiliationchanged': 'affiliationChanged',
        'superseded': 'superseded',
        'cessationofoperation': 'cessationOfOperation',
        'certificatehold': 'certificateHold',
        'removefromcrl': 'removeFromCRL',
        'privilegewithdrawn': 'privilegeWithdrawn',
        'aacompromise': 'aACompromise',
        'unspecified': 'unspecified'
    }

    normalized = mapping.get(reason_str_lower, reason_str_lower)

    for name, code in REASON_CODES.items():
        if name.lower() == normalized.lower():
            return code

    return 0


def parse_ocsp_request(request_data: bytes) -> Optional[OCSPRequest]:
    try:
        return x509.ocsp.load_der_ocsp_request(request_data)
    except Exception as e:
        logger.error(f"Failed to parse OCSP request: {str(e)}")
        return None


def build_ocsp_response_good(
        responder_cert: x509.Certificate,
        responder_key,
        issuer_cert: x509.Certificate,
        serial_number: int,
        this_update: datetime,
        next_update: datetime,
        nonce: Optional[bytes] = None
) -> bytes:
    try:
        builder = OCSPResponseBuilder()

        issuer_key_id = None
        for ext in issuer_cert.extensions:
            if ext.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                issuer_key_id = ext.value.digest
                break

        if issuer_key_id is None:
            raise OCSPError("Issuer certificate has no SubjectKeyIdentifier")

        builder = builder.add_response(
            cert=issuer_cert,
            issuer_key_identifier=issuer_key_id,
            serial_number=serial_number,
            cert_status=x509.ocsp.OCSPCertStatus.good,
            revocation_time=None,
            this_update=this_update,
            next_update=next_update
        )

        builder = builder.responder_id(x509.ocsp.OCSPResponderEncoding.hash, responder_cert)
        builder = builder.produced_at(this_update)

        if nonce:
            builder = builder.add_extension(x509.ocsp.OCSPNonce(nonce), critical=False)

        response = builder.sign(responder_key, hashes.SHA256(), default_backend())
        return response.public_bytes(serialization.Encoding.DER)

    except Exception as e:
        logger.error(f"Failed to build good response: {str(e)}")
        raise


def build_ocsp_response_revoked(
        responder_cert: x509.Certificate,
        responder_key,
        issuer_cert: x509.Certificate,
        serial_number: int,
        revocation_date: datetime,
        revocation_reason: Optional[str],
        this_update: datetime,
        next_update: datetime,
        nonce: Optional[bytes] = None
) -> bytes:
    try:
        builder = OCSPResponseBuilder()

        issuer_key_id = None
        for ext in issuer_cert.extensions:
            if ext.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                issuer_key_id = ext.value.digest
                break

        if issuer_key_id is None:
            raise OCSPError("Issuer certificate has no SubjectKeyIdentifier")

        reason_code = get_reason_code(revocation_reason) if revocation_reason else 0

        builder = builder.add_response(
            cert=issuer_cert,
            issuer_key_identifier=issuer_key_id,
            serial_number=serial_number,
            cert_status=x509.ocsp.OCSPCertStatus.revoked,
            revocation_time=revocation_date,
            this_update=this_update,
            next_update=next_update,
            revocation_reason=reason_code
        )

        builder = builder.responder_id(x509.ocsp.OCSPResponderEncoding.hash, responder_cert)
        builder = builder.produced_at(this_update)

        if nonce:
            builder = builder.add_extension(x509.ocsp.OCSPNonce(nonce), critical=False)

        response = builder.sign(responder_key, hashes.SHA256(), default_backend())
        return response.public_bytes(serialization.Encoding.DER)

    except Exception as e:
        logger.error(f"Failed to build revoked response: {str(e)}")
        raise


def build_ocsp_response_unknown(
        responder_cert: x509.Certificate,
        responder_key,
        issuer_cert: x509.Certificate,
        serial_number: int,
        this_update: datetime,
        nonce: Optional[bytes] = None
) -> bytes:
    try:
        builder = OCSPResponseBuilder()

        issuer_key_id = None
        for ext in issuer_cert.extensions:
            if ext.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                issuer_key_id = ext.value.digest
                break

        if issuer_key_id is None:
            raise OCSPError("Issuer certificate has no SubjectKeyIdentifier")

        builder = builder.add_response(
            cert=issuer_cert,
            issuer_key_identifier=issuer_key_id,
            serial_number=serial_number,
            cert_status=x509.ocsp.OCSPCertStatus.unknown,
            revocation_time=None,
            this_update=this_update,
            next_update=None
        )

        builder = builder.responder_id(x509.ocsp.OCSPResponderEncoding.hash, responder_cert)
        builder = builder.produced_at(this_update)

        if nonce:
            builder = builder.add_extension(x509.ocsp.OCSPNonce(nonce), critical=False)

        response = builder.sign(responder_key, hashes.SHA256(), default_backend())
        return response.public_bytes(serialization.Encoding.DER)

    except Exception as e:
        logger.error(f"Failed to build unknown response: {str(e)}")
        raise


def extract_nonce_from_request(request: OCSPRequest) -> Optional[bytes]:
    try:
        for ext in request.extensions:
            if ext.oid == OCSP_NONCE_OID:
                return ext.value
        return None
    except Exception:
        return None


def compute_issuer_hashes(cert: x509.Certificate) -> Tuple[bytes, bytes]:
    from cryptography.hazmat.primitives import hashes

    name_hash = hashes.Hash(hashes.SHA1(), default_backend())
    name_hash.update(cert.subject.public_bytes())
    issuer_name_hash = name_hash.finalize()

    key_hash = hashes.Hash(hashes.SHA1(), default_backend())
    key_hash.update(cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    issuer_key_hash = key_hash.finalize()

    return issuer_name_hash, issuer_key_hash