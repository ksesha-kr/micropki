from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any
import logging

logger = logging.getLogger(__name__)


class ValidationResult:
    def __init__(self):
        self.passed = True
        self.errors = []
        self.steps = []
        self.chain = []


class PathValidator:
    def __init__(self, validation_time: Optional[datetime] = None):
        self.validation_time = validation_time or datetime.now(timezone.utc)

    def _verify_signature(self, cert: x509.Certificate, issuer: x509.Certificate) -> bool:
        try:
            pub_key = issuer.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                pub_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm
                )
            else:
                pub_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    cert.signature_hash_algorithm
                )
            return True
        except Exception as e:
            logger.debug(f"Signature verification failed: {e}")
            return False

    def build_chain(
        self,
        leaf_cert: x509.Certificate,
        intermediates: List[x509.Certificate],
        roots: List[x509.Certificate]
    ) -> Tuple[List[x509.Certificate], List[str]]:
        chain = [leaf_cert]
        current = leaf_cert
        errors = []

        max_depth = 10
        for _ in range(max_depth):
            issuer_found = False
            for cert in intermediates:
                if cert.subject == current.issuer:
                    chain.append(cert)
                    current = cert
                    issuer_found = True
                    break
            if not issuer_found:
                for cert in roots:
                    if cert.subject == current.issuer:
                        chain.append(cert)
                        current = cert
                        issuer_found = True
                        break
            if not issuer_found:
                errors.append(f"No issuer found for {current.subject.rfc4514_string()}")
                break
            if current in roots or current.subject in [r.subject for r in roots]:
                break

        if chain[-1] not in roots and chain[-1].subject not in [r.subject for r in roots]:
            errors.append("Chain does not terminate at a trusted root")
        return chain, errors

    def _validate_certificate(
        self,
        cert: x509.Certificate,
        issuer: Optional[x509.Certificate],
        purpose: str
    ) -> Tuple[bool, List[str]]:
        errors = []

        if issuer and not self._verify_signature(cert, issuer):
            errors.append("Invalid signature")

        if self.validation_time < cert.not_valid_before_utc:
            errors.append(f"Not yet valid (valid from {cert.not_valid_before_utc})")
        elif self.validation_time > cert.not_valid_after_utc:
            errors.append(f"Expired (valid until {cert.not_valid_after_utc})")

        try:
            bc = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
            is_ca = bc.value.ca
            if purpose == 'ca' and not is_ca:
                errors.append("Expected CA certificate but CA=false")
            elif purpose != 'ca' and is_ca:
                errors.append("Expected end-entity certificate but CA=true")
        except x509.ExtensionNotFound:
            if purpose == 'ca':
                errors.append("CA certificate missing Basic Constraints")
        return len(errors) == 0, errors

    def validate_chain(
            self,
            leaf_cert: x509.Certificate,
            intermediates: List[x509.Certificate],
            roots: List[x509.Certificate],
            purpose: str = 'server'
    ) -> ValidationResult:
        result = ValidationResult()
        chain, build_errors = self.build_chain(leaf_cert, intermediates, roots)
        result.chain = chain

        if build_errors:
            result.passed = False
            result.errors.extend(build_errors)
            for err in build_errors:
                result.steps.append({'cert_index': -1, 'step': 'chain_building', 'passed': False, 'message': err})
            return result

        for i, cert in enumerate(chain):
            cert_purpose = 'ca' if i > 0 else purpose
            issuer = chain[i + 1] if i + 1 < len(chain) else None
            passed, cert_errors = self._validate_certificate(cert, issuer, cert_purpose)

            for err in cert_errors:
                result.steps.append({
                    'cert_index': i,
                    'cert_subject': cert.subject.rfc4514_string(),
                    'step': 'validation',
                    'passed': False,
                    'message': err
                })
                result.errors.append(err)
                result.passed = False

        if result.passed:
            for i, cert in enumerate(chain):
                result.steps.append({
                    'cert_index': i,
                    'cert_subject': cert.subject.rfc4514_string(),
                    'step': 'validation',
                    'passed': True,
                    'message': 'OK'
                })
        return result