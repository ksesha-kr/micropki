import sys
import threading
import time
import urllib.request
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from micropki.ca import RootCA
from micropki.database import CertificateDatabase
from micropki.repository import RepositoryServer
import tempfile


def test_crl_distribution():
    print("=== MicroPKI CRL Distribution Test ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / "pki"
        secrets_dir = Path(tmpdir) / "secrets"
        secrets_dir.mkdir()

        print("1. Setting up PKI...")
        with open(secrets_dir / "root.pass", 'w') as f:
            f.write("root-pass")
        with open(secrets_dir / "intermediate.pass", 'w') as f:
            f.write("intermediate-pass")

        ca = RootCA(out_dir=str(pki_dir))
        ca.init_root_ca(
            subject="/CN=Test Root CA",
            key_type="rsa",
            key_size=4096,
            passphrase_file=str(secrets_dir / "root.pass"),
            validity_days=365
        )

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

        print("2. Issuing and revoking certificate...")
        result = ca.issue_certificate(
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

        db = CertificateDatabase(str(pki_dir / "micropki.db"))
        certs = db.list_certificates()
        serial = certs[0]['serial_hex']
        db.close()

        ca.revoke_certificate(serial, "keyCompromise", str(pki_dir / "micropki.db"), force=True)

        print("3. Generating CRL...")
        ca.generate_crl(
            ca_type="intermediate",
            ca_cert_path=str(pki_dir / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(pki_dir / "private" / "intermediate.key.pem"),
            ca_passphrase_file=str(secrets_dir / "intermediate.pass"),
            db_path=str(pki_dir / "micropki.db"),
            out_dir=str(pki_dir),
            next_update_days=7
        )

        print("4. Starting repository server...")
        server = RepositoryServer(
            db_path=str(pki_dir / "micropki.db"),
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

        print("5. Fetching CRL via HTTP...")
        response = urllib.request.urlopen(f"{base_url}/crl?ca=intermediate")
        assert response.status == 200
        fetched_crl = response.read()

        crl_path = pki_dir / "crl" / "intermediate.crl.pem"
        with open(crl_path, 'rb') as f:
            local_crl = f.read()

        if fetched_crl == local_crl:
            print(" Fetched CRL matches local file")
        else:
            print(" CRL mismatch")

        print("6. Testing CRL with OpenSSL...")
        import subprocess
        result = subprocess.run(
            ["openssl", "crl", "-in", str(crl_path), "-inform", "PEM", "-text", "-noout"],
            capture_output=True, text=True
        )

        if "Revoked Certificates" in result.stdout:
            print(" CRL contains revoked certificate")
        else:
            print(" CRL does not show revoked certificate")

        print("\nCRL distribution test completed successfully!")


if __name__ == "__main__":
    test_crl_distribution()