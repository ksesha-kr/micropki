from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from typing import List, Optional
from ipaddress import IPv4Address, IPv6Address
import logging

logger = logging.getLogger(__name__)


class TemplateError(Exception):
    pass


class TemplateExtension:
    def __init__(self, value: x509.ExtensionType, critical: bool):
        self.value = value
        self.critical = critical


def validate_san_types(template: str, san_entries: List[str]) -> None:
    if not san_entries:
        if template == 'server':
            raise TemplateError("Server certificate requires at least one SAN entry")
        return

    for san in san_entries:
        if ':' not in san:
            raise TemplateError(f"Invalid SAN format: {san}")

        san_type, san_value = san.split(':', 1)
        san_type = san_type.lower()

        if template == 'server':
            if san_type not in ['dns', 'ip']:
                raise TemplateError(f"Server certificate cannot have SAN type: {san_type}")

        elif template == 'client':
            if san_type not in ['email', 'dns']:
                raise TemplateError(f"Client certificate cannot have SAN type: {san_type}")

        elif template == 'code_signing':
            if san_type not in ['dns', 'uri']:
                raise TemplateError(f"Code signing certificate cannot have SAN type: {san_type}")


def get_template_extensions(template: str, san_entries: Optional[List[str]] = None) -> List[TemplateExtension]:
    extensions = []

    basic_constraints = x509.BasicConstraints(ca=False, path_length=None)
    extensions.append(TemplateExtension(basic_constraints, critical=True))

    if template == 'server':
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )
        extensions.append(TemplateExtension(key_usage, critical=True))

        eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
        extensions.append(TemplateExtension(eku, critical=False))

        if san_entries:
            san = build_san_extension(san_entries)
            extensions.append(TemplateExtension(san, critical=False))
        else:
            pass

    elif template == 'client':
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )
        extensions.append(TemplateExtension(key_usage, critical=True))

        eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
        extensions.append(TemplateExtension(eku, critical=False))

        if san_entries:
            san = build_san_extension(san_entries)
            extensions.append(TemplateExtension(san, critical=False))

    elif template == 'code_signing':
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )
        extensions.append(TemplateExtension(key_usage, critical=True))

        eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING])
        extensions.append(TemplateExtension(eku, critical=False))

        if san_entries:
            san = build_san_extension(san_entries)
            extensions.append(TemplateExtension(san, critical=False))

    else:
        raise TemplateError(f"Unknown template: {template}")

    return extensions


def build_san_extension(san_entries: List[str]) -> x509.SubjectAlternativeName:
    general_names = []

    for san in san_entries:
        if ':' not in san:
            raise TemplateError(f"Invalid SAN format: {san}")

        san_type, san_value = san.split(':', 1)
        san_type = san_type.lower()

        if san_type == 'dns':
            general_names.append(x509.DNSName(san_value))
        elif san_type == 'ip':
            try:
                ip = IPv4Address(san_value)
            except:
                try:
                    ip = IPv6Address(san_value)
                except:
                    raise TemplateError(f"Invalid IP address: {san_value}")
            general_names.append(x509.IPAddress(ip))
        elif san_type == 'email':
            general_names.append(x509.RFC822Name(san_value))
        elif san_type == 'uri':
            general_names.append(x509.UniformResourceIdentifier(san_value))
        else:
            raise TemplateError(f"Unsupported SAN type: {san_type}")

    return x509.SubjectAlternativeName(general_names)