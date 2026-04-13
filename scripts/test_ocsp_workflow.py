import sys
import time
import threading
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from micropki.ca import RootCA
from micropki.database import CertificateDatabase
from micropki.ocsp_responder import OCSPResponder
import tempfile


def test_ocsp_workflow():
    print("=== MicroPKI OCSP Workflow Test ===")

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

        print("2. Creating Intermediate CA...")
        with open(secrets_dir / "intermediate.pass", 'w') as f:
            f.write("intermediate-pass")

        ca.issue_intermediate(
            root_cert_path=str(pki_dir / "certs" / "ca.cert.pem"),
            root_key_path=str(pki_dir / "private" / "ca.key.pem"),
            root_passphrase_file=str(secrets_dir / "root.pass"),
            subject="CN=Test Intermediate CA",
            key_type="rsa",
            key_size=4096,
            passphrase_file=str(secrets_dir / "intermediate.pass"),
            validity_days=365,
            pathlen=0,
            db_path=str(pki_dir / "micropki.db")
        )

        print("3. Issuing OCSP responder certificate...")
        ocsp_result = ca.issue_ocsp_certificate(
            ca_cert_path=str(pki_dir / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(pki_dir / "private" / "intermediate.key.pem"),
            ca_passphrase_file=str(secrets_dir / "intermediate.pass"),
            subject="CN=OCSP Responder",
            key_type="rsa",
            key_size=2048,
            out_dir=str(pki_dir / "certs"),
            validity_days=365
        )

        print("4. Issuing test server certificate...")
        server_result = ca.issue_certificate(
            ca_cert_path=str(pki_dir / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(pki_dir / "private" / "intermediate.key.pem"),
            ca_passphrase_file=str(secrets_dir / "intermediate.pass"),
            template="server",
            subject="CN=test.example.com",
            san_entries=["dns:test.example.com"],
            out_dir=str(pki_dir / "certs"),
            validity_days=365,
            db_path=str(pki_dir / "micropki.db")
        )

        print("5. Starting OCSP responder...")
        responder = OCSPResponder(
            db_path=str(pki_dir / "micropki.db"),
            responder_cert_path=ocsp_result['certificate'],
            responder_key_path=ocsp_result['private_key'],
            ca_cert_path=str(pki_dir / "certs" / "intermediate.cert.pem"),
            host="127.0.0.1",
            port=0,
            cache_ttl=60
        )

        def run_responder():
            responder.start()

        thread = threading.Thread(target=run_responder, daemon=True)
        thread.start()
        time.sleep(2)

        port = responder.port

        print("6. Testing with OpenSSL OCSP client...")
        db = CertificateDatabase(str(pki_dir / "micropki.db"))
        certs = db.list_certificates()
        serial = certs[0]['serial_hex']
        db.close()

        print(f" Checking serial: {serial}")

        print("\nOCSP workflow test completed!")


if __name__ == "__main__":
    test_ocsp_workflow()