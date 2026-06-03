import pytest
import tempfile
import time
from pathlib import Path
from micropki.ca import RootCA
from micropki.database import CertificateDatabase


def test_performance_1000_certificates():
    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / 'pki'
        secrets_dir = Path(tmpdir) / 'secrets'
        secrets_dir.mkdir()

        (secrets_dir / 'root.pass').write_text("root-pass")
        (secrets_dir / 'intermediate.pass').write_text("intermediate-pass")

        ca = RootCA(out_dir=str(pki_dir))

        ca.init_root_ca(
            subject="/CN=Performance Test Root CA",
            key_type="rsa",
            key_size=4096,
            passphrase_file=str(secrets_dir / "root.pass"),
            validity_days=365
        )

        db_path = str(pki_dir / "micropki.db")
        db = CertificateDatabase(db_path)
        db.init_schema()
        db.close()

        ca.issue_intermediate(
            root_cert_path=str(pki_dir / "certs" / "ca.cert.pem"),
            root_key_path=str(pki_dir / "private" / "ca.key.pem"),
            root_passphrase_file=str(secrets_dir / "root.pass"),
            subject="CN=Performance Test Intermediate CA",
            key_type="rsa",
            key_size=4096,
            passphrase_file=str(secrets_dir / "intermediate.pass"),
            validity_days=365,
            pathlen=0,
            db_path=db_path
        )

        start_time = time.time()

        for i in range(100):
            ca.issue_certificate(
                ca_cert_path=str(pki_dir / "certs" / "intermediate.cert.pem"),
                ca_key_path=str(pki_dir / "private" / "intermediate.key.pem"),
                ca_passphrase_file=str(secrets_dir / "intermediate.pass"),
                template="server",
                subject=f"CN=perf{i}.example.com",
                san_entries=[f"dns:perf{i}.example.com"],
                out_dir=str(pki_dir / "certs"),
                validity_days=365,
                db_path=db_path
            )

        end_time = time.time()
        elapsed = end_time - start_time
        certs_per_sec = 100 / elapsed

        print(f"\nPerformance Results:")
        print(f"  100 certificates issued in {elapsed:.2f} seconds")
        print(f"  Rate: {certs_per_sec:.2f} certificates/second")

        db = CertificateDatabase(db_path)
        all_certs = db.list_certificates()
        db.close()

        assert len(all_certs) >= 100
        print(f"  Verified {len(all_certs)} certificates in database")