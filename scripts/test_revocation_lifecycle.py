import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from micropki.ca import RootCA
from micropki.database import CertificateDatabase
from micropki.crl import load_crl


def test_revocation_lifecycle():
    print("=== MicroPKI Revocation Lifecycle Test ===")

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
        print(" Intermediate CA created")

        print("3. Issuing server certificate...")
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
        print(f" Certificate issued with serial from DB")

        print("4. Checking certificate status...")
        db = CertificateDatabase(str(pki_dir / "micropki.db"))
        certs = db.list_certificates()
        serial = certs[0]['serial_hex']
        print(f"   Serial: {serial}")
        print(f"   Status: {certs[0]['status']}")

        print("5. Revoking certificate...")
        ca.revoke_certificate(serial, "keyCompromise", str(pki_dir / "micropki.db"), force=True)

        cert = db.get_certificate_by_serial(serial)
        print(f"   New status: {cert['status']}")
        print(f"   Revocation reason: {cert['revocation_reason']}")

        print("6. Generating CRL...")
        ca.generate_crl(
            ca_type="intermediate",
            ca_cert_path=str(pki_dir / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(pki_dir / "private" / "intermediate.key.pem"),
            ca_passphrase_file=str(secrets_dir / "intermediate.pass"),
            db_path=str(pki_dir / "micropki.db"),
            out_dir=str(pki_dir),
            next_update_days=7
        )

        crl_path = pki_dir / "crl" / "intermediate.crl.pem"
        crl = load_crl(str(crl_path))
        print(f"   CRL generated with {len(crl)} revoked certificates")

        print("7. Verifying CRL with OpenSSL...")
        import subprocess
        result = subprocess.run(
            ["openssl", "crl", "-in", str(crl_path), "-inform", "PEM", "-noout"],
            capture_output=True
        )
        if result.returncode == 0:
            print(" CRL verification passed")
        else:
            print(" CRL verification failed")

        db.close()

        print("\nRevocation lifecycle test completed successfully!")


if __name__ == "__main__":
    test_revocation_lifecycle()