import pytest
import tempfile
from pathlib import Path
from micropki.repository import RepositoryServer
from micropki.database import CertificateDatabase
import json


class TestRepositoryServer:
    @pytest.fixture
    def client(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / 'test.db'
            cert_dir = Path(tmpdir) / 'certs'
            cert_dir.mkdir()

            test_cert_path = cert_dir / 'ca.cert.pem'
            test_cert_path.write_text("-----BEGIN CERTIFICATE-----\nTEST ROOT CA\n-----END CERTIFICATE-----")

            test_intermediate_path = cert_dir / 'intermediate.cert.pem'
            test_intermediate_path.write_text(
                "-----BEGIN CERTIFICATE-----\nTEST INTERMEDIATE CA\n-----END CERTIFICATE-----")

            db = CertificateDatabase(str(db_path))
            db.init_schema()

            cert_data = {
                'serial_hex': '1A2B3C4D',
                'subject': 'CN=Test Cert',
                'issuer': 'CN=Test CA',
                'not_before': '2024-01-01T00:00:00',
                'not_after': '2025-01-01T00:00:00',
                'cert_pem': '-----BEGIN CERTIFICATE-----\nTEST CERTIFICATE\n-----END CERTIFICATE-----',
                'status': 'valid'
            }
            db.insert_certificate(cert_data)
            db.close()

            server = RepositoryServer(str(db_path), str(cert_dir), '127.0.0.1', 8080)
            yield server.app.test_client()

    def test_get_certificate_not_found(self, client):
        response = client.get('/certificate/FFFFFFFF')
        assert response.status_code == 404
        assert b"Certificate not found" in response.data

    def test_get_certificate_invalid_serial(self, client):
        response = client.get('/certificate/INVALID')
        assert response.status_code == 400
        assert b"Invalid serial number format" in response.data

    def test_get_certificate_valid(self, client):
        response = client.get('/certificate/1A2B3C4D')
        assert response.status_code == 200
        assert b"BEGIN CERTIFICATE" in response.data

    def test_get_ca_root(self, client):
        response = client.get('/ca/root')
        assert response.status_code == 200
        assert b"ROOT CA" in response.data

    def test_get_ca_intermediate(self, client):
        response = client.get('/ca/intermediate')
        assert response.status_code == 200
        assert b"INTERMEDIATE CA" in response.data

    def test_get_ca_invalid_level(self, client):
        response = client.get('/ca/invalid')
        assert response.status_code == 400
        assert b"Invalid CA level" in response.data

    def test_get_crl(self, client):
        response = client.get('/crl')
        assert response.status_code == 501
        assert b"not yet implemented" in response.data

    def test_health_endpoint(self, client):
        response = client.get('/health')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'ok'

    def test_not_found_endpoint(self, client):
        response = client.get('/nonexistent')
        assert response.status_code == 404
        assert b"Not found" in response.data