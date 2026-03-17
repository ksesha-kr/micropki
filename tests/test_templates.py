import pytest
from micropki.templates import (
    get_template_extensions, validate_san_types,
    build_san_extension, TemplateError
)
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID


class TestServerTemplate:
    def test_server_template_extensions(self):
        extensions = get_template_extensions('server', ['dns:example.com'])

        found_basic = False
        found_key_usage = False
        found_eku = False
        found_san = False

        for ext in extensions:
            if isinstance(ext.value, x509.BasicConstraints):
                assert ext.critical is True
                assert ext.value.ca is False
                found_basic = True
            elif isinstance(ext.value, x509.KeyUsage):
                assert ext.critical is True
                assert ext.value.digital_signature is True
                assert ext.value.key_encipherment is True
                found_key_usage = True
            elif isinstance(ext.value, x509.ExtendedKeyUsage):
                assert ext.critical is False
                assert ExtendedKeyUsageOID.SERVER_AUTH in ext.value
                found_eku = True
            elif isinstance(ext.value, x509.SubjectAlternativeName):
                assert ext.critical is False
                assert len(ext.value) == 1
                found_san = True

        assert found_basic and found_key_usage and found_eku and found_san

    def test_server_template_no_san(self):
        with pytest.raises(TemplateError):
            validate_san_types('server', [])

        extensions = get_template_extensions('server', None)
        assert len(extensions) == 3


class TestClientTemplate:
    def test_client_template_extensions(self):
        extensions = get_template_extensions('client', ['email:alice@example.com'])

        found_key_usage = False
        found_eku = False

        for ext in extensions:
            if isinstance(ext.value, x509.KeyUsage):
                assert ext.value.digital_signature is True
                assert ext.value.key_agreement is True
                found_key_usage = True
            elif isinstance(ext.value, x509.ExtendedKeyUsage):
                assert ExtendedKeyUsageOID.CLIENT_AUTH in ext.value
                found_eku = True

        assert found_key_usage and found_eku


class TestCodeSigningTemplate:
    def test_code_signing_template_extensions(self):
        extensions = get_template_extensions('code_signing', None)

        found_key_usage = False
        found_eku = False

        for ext in extensions:
            if isinstance(ext.value, x509.KeyUsage):
                assert ext.value.digital_signature is True
                assert ext.value.key_encipherment is False
                found_key_usage = True
            elif isinstance(ext.value, x509.ExtendedKeyUsage):
                assert ExtendedKeyUsageOID.CODE_SIGNING in ext.value
                found_eku = True

        assert found_key_usage and found_eku


class TestSANValidation:
    def test_valid_server_san(self):
        validate_san_types('server', ['dns:example.com', 'ip:192.168.1.1'])

    def test_invalid_server_san(self):
        with pytest.raises(TemplateError):
            validate_san_types('server', ['email:alice@example.com'])

    def test_valid_client_san(self):
        validate_san_types('client', ['email:alice@example.com', 'dns:client.local'])

    def test_invalid_client_san(self):
        with pytest.raises(TemplateError):
            validate_san_types('client', ['ip:192.168.1.1'])

    def test_code_signing_san(self):
        validate_san_types('code_signing', ['dns:example.com', 'uri:https://example.com'])

        with pytest.raises(TemplateError):
            validate_san_types('code_signing', ['ip:192.168.1.1'])


class TestSANBuilding:
    def test_build_dns_san(self):
        san = build_san_extension(['dns:example.com', 'dns:www.example.com'])
        assert len(san) == 2

    def test_build_ip_san(self):
        san = build_san_extension(['ip:192.168.1.1', 'ip:10.0.0.1'])
        assert len(san) == 2

    def test_build_email_san(self):
        san = build_san_extension(['email:alice@example.com'])
        assert len(san) == 1

    def test_build_uri_san(self):
        san = build_san_extension(['uri:https://example.com'])
        assert len(san) == 1

    def test_build_mixed_san(self):
        san = build_san_extension(['dns:example.com', 'ip:192.168.1.1', 'email:alice@example.com'])
        assert len(san) == 3

    def test_invalid_san_format(self):
        with pytest.raises(TemplateError):
            build_san_extension(['invalid'])

    def test_invalid_ip(self):
        with pytest.raises(TemplateError):
            build_san_extension(['ip:300.300.300.300'])