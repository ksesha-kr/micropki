import sys
import time
import threading
import requests
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from micropki.ca import RootCA
from micropki.database import CertificateDatabase
from micropki.repository import RepositoryServer
from micropki.serial import SerialGenerator
import tempfile
import os


def test_full_workflow():
    print("=== MicroPKI Sprint 3 Full Workflow Test ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / "pki"
        secrets_dir = Path(tmpdir) / "secrets"
        secrets_dir.mkdir()

        print("1. Creating Root CA...")
        with open(secrets_dir / "root.pass", 'w') as f:
            f.write("root-pass")

        ca = RootCA(out_dir=str(pki_dir))
        ca.init_root_ca(
            subject="/CN=Test Root CA",
            key_type="rsa",
            key_size=4096,
            passphrase_file=str(secrets_dir / "root.pass"),
            validity_days=365
        )
        print(" Root CA created")

        print("2. Initializing database...")
        db_path = pki_dir / "micropki.db"
        db = CertificateDatabase(str(db_path))
        db.init_schema()
        print(f" Database initialized at {db_path}")

        print("3. Creating Intermediate CA...")
        with open(secrets_dir / "intermediate.pass", 'w') as f:
            f.write("intermediate-pass")

        result = ca.issue_intermediate(
            root_cert_path=str(pki_dir / "certs" / "ca.cert.pem"),
            root_key_path=str(pki_dir / "private" / "ca.key.pem"),
            root_passphrase_file=str(secrets_dir / "root.pass"),
            subject="CN=Test Intermediate CA",
            key_type="rsa",
            key_size=4096,
            passphrase_file=str(secrets_dir / "intermediate.pass"),
            validity_days=365,
            pathlen=0
        )
        print(" Intermediate CA created")

        print("4. Issuing test certificates...")
        certs = []
        serials = []

        for i in range(3):
            cert_result = ca.issue_certificate(
                ca_cert_path=str(pki_dir / "certs" / "intermediate.cert.pem"),
                ca_key_path=str(pki_dir / "private" / "intermediate.key.pem"),
                ca_passphrase_file=str(secrets_dir / "intermediate.pass"),
                template="server" if i == 0 else ("client" if i == 1 else "code_signing"),
                subject=f"CN=test{i}.example.com",
                san_entries=["dns:test0.example.com"] if i == 0 else None,
                out_dir=str(pki_dir / "certs"),
                validity_days=365
            )
            certs.append(cert_result)

            with open(cert_result['certificate'], 'r') as f:
                cert_data = f.read()

            db_cert = db.list_certificates(limit=100)
            serials = [c['serial_hex'] for c in db_cert]
            print(f" Issued certificate {i + 1} with serial {serials[-1]}")

        print("5. Starting repository server...")
        server = RepositoryServer(
            db_path=str(db_path),
            cert_dir=str(pki_dir / "certs"),
            host="127.0.0.1",
            port=0
        )

        def run_server():
            server.start()

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        time.sleep(2)

        port = server.port
        base_url = f"http://127.0.0.1:{port}"

        print(f" Server started on port {port}")

        print("6. Testing API endpoints...")
        for serial in serials:
            response = requests.get(f"{base_url}/certificate/{serial}")
            assert response.status_code == 200
            assert b"BEGIN CERTIFICATE" in response.content
            print(f" Retrieved certificate {serial}")

        response = requests.get(f"{base_url}/ca/root")
        assert response.status_code == 200
        print(" Retrieved Root CA certificate")

        response = requests.get(f"{base_url}/ca/intermediate")
        assert response.status_code == 200
        print(" Retrieved Intermediate CA certificate")

        response = requests.get(f"{base_url}/crl")
        assert response.status_code == 501
        print(" CRL endpoint returns 501")

        response = requests.get(f"{base_url}/health")
        assert response.status_code == 200
        print(" Health endpoint OK")

        db.close()

        print("\nFull workflow test completed successfully!")


if __name__ == "__main__":
    test_full_workflow()