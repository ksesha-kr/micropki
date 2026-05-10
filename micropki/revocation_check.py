from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any
import requests
import logging

logger = logging.getLogger(__name__)


class RevocationChecker:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def get_ocsp_url(self, cert: x509.Certificate) -> Optional[str]:
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for access_desc in aia.value:
                if access_desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    return access_desc.access_location.value
            return None
        except x509.ExtensionNotFound:
            return None

    def get_crl_url(self, cert: x509.Certificate) -> Optional[str]:
        try:
            cdp = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            for point in cdp.value:
                for name in point.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        return name.value
            return None
        except x509.ExtensionNotFound:
            return None

    def check_ocsp(
        self,
        cert: x509.Certificate,
        issuer_cert: x509.Certificate,
        ocsp_url: Optional[str] = None
    ) -> Tuple[str, Optional[str], Optional[datetime]]:
        ocsp_url = ocsp_url or self.get_ocsp_url(cert)
        if not ocsp_url:
            return 'unknown', 'No OCSP URL found', None

        try:
            from cryptography.x509.ocsp import OCSPRequestBuilder
            builder = OCSPRequestBuilder()
            builder = builder.add_certificate(cert, issuer_cert, hashes.SHA1())
            request = builder.build()
            request_der = request.public_bytes(serialization.Encoding.DER)

            response = requests.post(
                ocsp_url,
                data=request_der,
                headers={'Content-Type': 'application/ocsp-request'},
                timeout=self.timeout
            )
            if response.status_code != 200:
                return 'unknown', f'HTTP {response.status_code}', None

            from cryptography.x509.ocsp import load_der_ocsp_response
            ocsp_response = load_der_ocsp_response(response.content)
            if ocsp_response.response_status.value != 0:
                return 'unknown', f'OCSP error status: {ocsp_response.response_status}', None

            for single_response in ocsp_response.responses:
                if single_response.certificate_serial_number == cert.serial_number:
                    status = single_response.certificate_status
                    if status.name == 'GOOD':
                        return 'good', None, None
                    elif status.name == 'REVOKED':
                        reason = None
                        if status.revocation_reason:
                            reason = status.revocation_reason.name.lower()
                        return 'revoked', reason, status.revocation_time
                    else:
                        return 'unknown', None, None
            return 'unknown', 'Certificate not found in OCSP response', None
        except Exception as e:
            logger.warning(f"OCSP check failed: {str(e)}")
            return 'unknown', str(e), None

    def check_crl(
        self,
        cert: x509.Certificate,
        issuer_cert: x509.Certificate,
        crl_data: Optional[bytes] = None,
        crl_url: Optional[str] = None
    ) -> Tuple[str, Optional[str], Optional[datetime]]:
        if crl_data is None and crl_url:
            try:
                response = requests.get(crl_url, timeout=self.timeout)
                if response.status_code != 200:
                    return 'unknown', f'HTTP {response.status_code}', None
                crl_data = response.content
            except Exception as e:
                return 'unknown', str(e), None

        if crl_data is None:
            return 'unknown', 'No CRL provided', None

        try:
            crl = x509.load_pem_x509_crl(crl_data, default_backend())
        except:
            try:
                crl = x509.load_der_x509_crl(crl_data, default_backend())
            except Exception as e:
                return 'unknown', f'Failed to load CRL: {str(e)}', None

        try:
            pub_key = issuer_cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                pub_key.verify(
                    crl.signature,
                    crl.tbs_certlist_bytes,
                    padding.PKCS1v15(),
                    crl.signature_hash_algorithm
                )
            else:
                pub_key.verify(
                    crl.signature,
                    crl.tbs_certlist_bytes,
                    crl.signature_hash_algorithm
                )
        except Exception as e:
            logger.warning(f"CRL signature verification failed: {str(e)}")
            return 'unknown', f'CRL signature invalid: {str(e)}', None

        if datetime.now(timezone.utc) > crl.next_update_utc:
            logger.warning(f"CRL is expired (next update {crl.next_update_utc})")

        REASON_CODE_OID = ObjectIdentifier("2.5.29.21")

        for revoked in crl:
            if revoked.serial_number == cert.serial_number:
                reason_str = None
                try:
                    reason_ext = revoked.extensions.get_extension_for_oid(REASON_CODE_OID)
                    reason_code = reason_ext.value.value
                    reason_map = {
                        0: 'unspecified', 1: 'keyCompromise', 2: 'cACompromise',
                        3: 'affiliationChanged', 4: 'superseded', 5: 'cessationOfOperation',
                        6: 'certificateHold', 8: 'removeFromCRL', 9: 'privilegeWithdrawn',
                        10: 'aACompromise'
                    }
                    reason_str = reason_map.get(reason_code, 'unknown')
                except x509.ExtensionNotFound:
                    pass
                return 'revoked', reason_str, revoked.revocation_date_utc

        return 'good', None, None

    def check_status(
        self,
        cert: x509.Certificate,
        issuer_cert: x509.Certificate,
        ocsp_url: Optional[str] = None,
        crl_data: Optional[bytes] = None,
        crl_url: Optional[str] = None,
        prefer_ocsp: bool = True
    ) -> Dict[str, Any]:
        result = {
            'status': 'unknown',
            'reason': None,
            'revocation_date': None,
            'method': None,
            'fallback_used': False
        }

        ocsp_available = ocsp_url or self.get_ocsp_url(cert)
        if prefer_ocsp and ocsp_available:
            status, reason, rev_date = self.check_ocsp(cert, issuer_cert, ocsp_url)
            if status != 'unknown':
                result.update(status=status, reason=reason, revocation_date=rev_date, method='ocsp')
                return result

        crl_available = crl_url or self.get_crl_url(cert) or crl_data is not None
        if crl_available:
            status, reason, rev_date = self.check_crl(cert, issuer_cert, crl_data, crl_url)
            if status != 'unknown':
                result.update(status=status, reason=reason, revocation_date=rev_date, method='crl', fallback_used=(prefer_ocsp and ocsp_available))
                return result

        return result