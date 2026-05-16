import sys
import time
import threading
import tempfile
import requests
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from micropki.ca import RootCA
from micropki.database import CertificateDatabase
from micropki.repository import RepositoryServer
from micropki.audit import AuditLogger
from micropki.policy import PolicyEnforcer, PolicyViolation


def test_security_hardening():
    print("=== MicroPKI Security Hardening Test ===")
    failures = []

    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / "pki"
        secrets_dir = Path(tmpdir) / "secrets"
        secrets_dir.mkdir()

        print("1. Testing policy enforcement...")
        policy = PolicyEnforcer()

        try:
            policy.check_key_size(1024, 'rsa', 'end_entity')
            failures.append("Weak key size not rejected")
        except PolicyViolation:
            print("   Weak RSA-1024 rejected")

        try:
            policy.check_validity(400, 'end_entity')
            failures.append("Excessive validity not rejected")
        except PolicyViolation:
            print("   Excessive validity rejected")

        try:
            policy.check_san_types(['email:test@example.com'], 'server')
            failures.append("Invalid SAN type not rejected")
        except PolicyViolation:
            print("   Invalid SAN type rejected")

        print("2. Setting up PKI infrastructure...")
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

        ca.issue_ocsp_certificate(
            ca_cert_path=str(pki_dir / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(pki_dir / "private" / "intermediate.key.pem"),
            ca_passphrase_file=str(secrets_dir / "intermediate.pass"),
            subject="CN=OCSP Responder",
            key_type="rsa",
            key_size=2048,
            out_dir=str(pki_dir / "certs"),
            validity_days=365
        )

        print("3. Testing audit logging...")
        audit = AuditLogger(str(pki_dir))
        audit.log("AUDIT", "test", "success", "Test audit entry", {})

        passed, idx = audit.verify()
        if passed:
            print("   Audit integrity OK")
        else:
            failures.append("Audit verification failed")

        print("4. Testing CT log...")
        audit.ct_log("123456", "CN=test", "fingerprint", "CN=CA")
        if audit.ct_verify("123456"):
            print("   CT log entry found")
        else:
            failures.append("CT log entry not found")

        print("5. Testing rate limiting...")
        cert_dir = pki_dir / 'certs'
        db_path = pki_dir / 'micropki.db'

        server = RepositoryServer(str(db_path), str(cert_dir), '127.0.0.1', 0, rate_limit=1.0, rate_burst=2)

        def run_server():
            server.start()

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        time.sleep(2)

        port = server.port
        base_url = f"http://127.0.0.1:{port}"

        rate_limit_hit = False
        for i in range(5):
            try:
                response = requests.get(f"{base_url}/ca/root", timeout=5)
                if response.status_code == 429:
                    rate_limit_hit = True
                    break
            except:
                pass
            time.sleep(0.1)

        if rate_limit_hit:
            print("   Rate limiting working")
        else:
            failures.append("Rate limiting not triggered")

        print("6. Testing compromise simulation...")
        cert_result = ca.issue_certificate(
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
        serial = certs[0]['serial_hex'] if certs else None
        db.close()

        if serial:
            ca.compromise_certificate(
                cert_path=cert_result['certificate'],
                reason="keyCompromise",
                db_path=str(pki_dir / "micropki.db"),
                force=True
            )

            db = CertificateDatabase(str(pki_dir / "micropki.db"))
            cert = db.get_certificate_by_serial(serial)
            db.close()

            if cert and cert['status'] == 'revoked':
                print("   Compromise simulation working")
            else:
                failures.append("Compromise simulation failed")
        else:
            failures.append("No certificate issued for compromise test")

    if failures:
        print(f"\nSecurity hardening test FAILED: {failures}")
        return 1
    else:
        print("\nSecurity hardening test PASSED")
        return 0


if __name__ == "__main__":
    sys.exit(test_security_hardening())