from typing import Optional, Dict, Any
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


class RevocationError(Exception):
    pass


def revoke_certificate(
        db,
        serial_hex: str,
        reason: str,
        force: bool = False
) -> Dict[str, Any]:
    try:
        serial_hex_upper = serial_hex.upper()

        cert = db.get_certificate_by_serial(serial_hex_upper)
        if not cert:
            raise RevocationError(f"Certificate with serial {serial_hex} not found")

        if cert['status'] == 'revoked':
            logger.warning(f"Certificate {serial_hex} is already revoked")
            return {'status': 'already_revoked', 'certificate': cert}

        if not force:
            print(f"Certificate to revoke:")
            print(f"  Subject: {cert['subject']}")
            print(f"  Issuer: {cert['issuer']}")
            print(f"  Valid until: {cert['not_after']}")
            print(f"  Reason: {reason}")
            response = input("Proceed with revocation? [y/N] ").strip().lower()
            if response not in ['y', 'yes']:
                logger.info(f"Revocation cancelled for {serial_hex}")
                return {'status': 'cancelled'}

        db.update_certificate_status(
            serial_hex=serial_hex_upper,
            status='revoked',
            revocation_reason=reason
        )

        logger.info(f"Certificate {serial_hex} revoked with reason: {reason}")

        return {
            'status': 'revoked',
            'certificate': cert,
            'revocation_date': datetime.now(timezone.utc).isoformat(),
            'reason': reason
        }

    except Exception as e:
        logger.error(f"Revocation failed: {str(e)}")
        raise RevocationError(str(e))


def check_revoked(db, serial_hex: str) -> Dict[str, Any]:
    try:
        cert = db.get_certificate_by_serial(serial_hex.upper())
        if not cert:
            return {'exists': False, 'revoked': False}

        return {
            'exists': True,
            'revoked': cert['status'] == 'revoked',
            'status': cert['status'],
            'revocation_reason': cert.get('revocation_reason'),
            'revocation_date': cert.get('revocation_date')
        }

    except Exception as e:
        logger.error(f"Status check failed: {str(e)}")
        raise RevocationError(str(e))