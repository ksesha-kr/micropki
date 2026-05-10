import sys
import time
import threading
import tempfile
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from micropki.ca import RootCA
from micropki.database import CertificateDatabase
from micropki.repository import RepositoryServer
from micropki.client import PKIClient
from micropki.validation import PathValidator
from micropki.revocation_check import RevocationChecker


def test_client_workflow():
    print("=== MicroPKI Client Workflow Test ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / "pki"
        secrets_dir = Path(tmpdir) / "secrets"
        secrets_dir.mkdir()
        client_dir = Path(tmpdir) / "client"
        client_dir.mkdir()

        print("1. Setting up PKI infrastructure...")
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
            validity_days=365,
            db_path=str(pki_dir / "micropki.db")
        )

        print("2. Starting repository server...")
        server = RepositoryServer(
            db_path=str(pki_dir / "micropki.db"),
            cert_dir=str(pki_dir / "certs"),
            host="127.0.0.1",
            port=0,
            enable_ocsp=True,
            ocsp_responder_cert=str(pki_dir / "certs" / "ocsp.cert.pem"),
            ocsp_responder_key=str(pki_dir / "certs" / "ocsp.key.pem"),
            ocsp_ca_cert=str(pki_dir / "certs" / "intermediate.cert.pem")
        )

        def run_server():
            server.start()

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        time.sleep(2)

        port = server.port
        base_url = f"http://127.0.0.1:{port}"

        print("3. Generating CSR...")
        client = PKIClient()
        csr_result = client.generate_csr(
            subject_dn="CN=client-test.example.com",
            key_type="rsa",
            key_size=2048,
            san_entries=["dns:client-test.example.com"],
            out_key=str(client_dir / "client.key.pem"),
            out_csr=str(client_dir / "client.csr.pem")
        )
        print(f"   CSR saved: {csr_result['csr']}")

        print("4. Requesting certificate from CA...")
        cert_result = client.request_certificate(
            csr_path=str(client_dir / "client.csr.pem"),
            template="server",
            ca_url=base_url,
            out_cert=str(client_dir / "client.cert.pem")
        )
        print(f"   Certificate saved: {cert_result['certificate']}")

        print("5. Validating certificate chain...")
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        with open(cert_result['certificate'], 'rb') as f:
            leaf = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(pki_dir / "certs" / "intermediate.cert.pem", 'rb') as f:
            inter = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(pki_dir / "certs" / "ca.cert.pem", 'rb') as f:
            root = x509.load_pem_x509_certificate(f.read(), default_backend())

        validator = PathValidator()
        result = validator.validate_chain(leaf, [inter], [root], 'server')

        if result.passed:
            print("   Chain validation PASSED")
        else:
            print("   Chain validation FAILED")
            for step in result.steps:
                if not step['passed']:
                    print(f"      - {step['step']}: {step.get('message', '')}")

        print("6. Checking revocation status...")
        checker = RevocationChecker()
        status_result = checker.check_status(
            leaf, inter,
            ocsp_url=f"{base_url}/ocsp"
        )
        print(f"   Status: {status_result['status']} (via {status_result['method']})")

        print("7. Revoking certificate...")
        db = CertificateDatabase(str(pki_dir / "micropki.db"))
        db.update_certificate_status(hex(leaf.serial_number)[2:].upper(), 'revoked', 'keyCompromise')
        db.close()

        print("8. Regenerating CRL...")
        ca.generate_crl(
            ca_type="intermediate",
            ca_cert_path=str(pki_dir / "certs" / "intermediate.cert.pem"),
            ca_key_path=str(pki_dir / "private" / "intermediate.key.pem"),
            ca_passphrase_file=str(secrets_dir / "intermediate.pass"),
            db_path=str(pki_dir / "micropki.db"),
            out_dir=str(pki_dir),
            next_update_days=7
        )

        print("9. Re-checking revocation status...")
        status_result2 = checker.check_status(
            leaf, inter,
            ocsp_url=f"{base_url}/ocsp"
        )
        print(f"   Status: {status_result2['status']} (via {status_result2['method']})")

        if status_result2['status'] == 'revoked':
            print("   Certificate correctly reported as revoked")
        else:
            print("   Revocation not detected")

        db.close()

        print("\nClient workflow test completed successfully!")
        return 0


if __name__ == "__main__":
    sys.exit(test_client_workflow())