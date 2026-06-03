from cryptography import x509
from typing import List, Dict, Any, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class PolicyViolation(Exception):
    pass


class PolicyEnforcer:
    MAX_ROOT_VALIDITY = 3650
    MAX_INTERMEDIATE_VALIDITY = 1825
    MAX_END_ENTITY_VALIDITY = 365

    MIN_RSA_ROOT = 4096
    MIN_RSA_INTERMEDIATE = 3072
    MIN_RSA_END_ENTITY = 2048

    MIN_ECC_ROOT = 384
    MIN_ECC_INTERMEDIATE = 384
    MIN_ECC_END_ENTITY = 256

    ALLOWED_SAN_TYPES = {
        'server': ['dns', 'ip'],
        'client': ['email', 'dns'],
        'code_signing': ['dns', 'uri']
    }

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.allow_wildcards = self.config.get('allow_wildcards', False)

    def check_key_size(self, key_size: int, key_type: str, purpose: str) -> bool:
        if key_type == 'rsa':
            if purpose == 'root':
                min_size = self.MIN_RSA_ROOT
            elif purpose == 'intermediate':
                min_size = self.MIN_RSA_INTERMEDIATE
            else:
                min_size = self.MIN_RSA_END_ENTITY
        else:
            if purpose in ['root', 'intermediate']:
                min_size = self.MIN_ECC_ROOT
            else:
                min_size = self.MIN_ECC_END_ENTITY

        if key_size < min_size:
            raise PolicyViolation(
                f"{key_type.upper()} key size {key_size} too small for {purpose}. Minimum: {min_size}")
        return True

    def check_validity(self, validity_days: int, purpose: str) -> bool:
        if purpose == 'root':
            max_days = self.MAX_ROOT_VALIDITY
        elif purpose == 'intermediate':
            max_days = self.MAX_INTERMEDIATE_VALIDITY
        else:
            max_days = self.MAX_END_ENTITY_VALIDITY

        if validity_days > max_days:
            raise PolicyViolation(f"Validity {validity_days} days exceeds maximum {max_days} days for {purpose}")
        return True

    def check_san_types(self, san_entries: List[str], template: str) -> bool:
        if not san_entries:
            if template == 'server':
                raise PolicyViolation("Server certificate must have at least one SAN")
            return True
        allowed = self.ALLOWED_SAN_TYPES.get(template, [])
        for san in san_entries:
            if ':' not in san:
                raise PolicyViolation(f"Invalid SAN format: {san}")
            san_type, san_value = san.split(':', 1)
            san_type = san_type.lower()
            if san_type not in allowed:
                raise PolicyViolation(f"SAN type '{san_type}' not allowed for {template}. Allowed: {allowed}")
            if san_type == 'dns' and '*' in san_value and not self.allow_wildcards:
                raise PolicyViolation(f"Wildcard SAN '{san_value}' not allowed")
        return True

    def check_csr(self, csr: x509.CertificateSigningRequest, template: str) -> bool:
        try:
            key = csr.public_key()
            if hasattr(key, 'key_size'):
                key_size = key.key_size
                key_type = 'rsa'
            else:
                key_size = key.curve.key_size
                key_type = 'ecc'
            self.check_key_size(key_size, key_type, 'end_entity')

            for ext in csr.extensions:
                if ext.oid == x509.oid.ExtensionOID.BASIC_CONSTRAINTS:
                    if ext.value.ca:
                        raise PolicyViolation("CSR with CA=true not allowed for end-entity")
            return True
        except PolicyViolation:
            raise
        except Exception as e:
            raise PolicyViolation(f"CSR validation failed: {str(e)}")

    def check_root_ca_params(self, key_size: int, key_type: str, validity_days: int) -> bool:
        self.check_key_size(key_size, key_type, 'root')
        self.check_validity(validity_days, 'root')
        return True

    def check_intermediate_ca_params(self, key_size: int, key_type: str, validity_days: int, pathlen: int) -> bool:
        self.check_key_size(key_size, key_type, 'intermediate')
        self.check_validity(validity_days, 'intermediate')
        if pathlen != 0:
            raise PolicyViolation(f"Intermediate CA pathlen must be 0, got {pathlen}")
        return True

    def check_end_entity_params(self, validity_days: int, san_entries: List[str], template: str) -> bool:
        self.check_validity(validity_days, 'end_entity')
        if san_entries:
            self.check_san_types(san_entries, template)
        return True
