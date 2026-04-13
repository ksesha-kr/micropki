import sys
import time
import threading
import requests
import subprocess
import tempfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).parent.parent))

from micropki.ca import RootCA
from micropki.database import CertificateDatabase
from micropki.ocsp_responder import OCSPResponder


def test_ocsp_performance():
    print("=== MicroPKI OCSP Performance Test ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / "pki"
        secrets_dir = Path(tmpdir) / "secrets"
        secrets_dir.mkdir()

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

        print("2. Issuing OCSP responder certificate...")
        ocsp_result = ca.issue_ocsp_certificate(
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

        print("3. Issuing test certificates...")
        serials = []
        for i in range(10):
            result = ca.issue_certificate(
                ca_cert_path=str(pki_dir / "certs" / "intermediate.cert.pem"),
                ca_key_path=str(pki_dir / "private" / "intermediate.key.pem"),
                ca_passphrase_file=str(secrets_dir / "intermediate.pass"),
                template="server",
                subject=f"CN=test{i}.example.com",
                san_entries=[f"dns:test{i}.example.com"],
                out_dir=str(pki_dir / "certs"),
                validity_days=365,
                db_path=str(pki_dir / "micropki.db")
            )

            db = CertificateDatabase(str(pki_dir / "micropki.db"))
            certs = db.list_certificates(limit=100)
            if certs:
                serials.append(certs[-1]['serial_hex'])
            db.close()

        print(f"   Issued {len(serials)} test certificates")

        print("4. Starting OCSP responder...")
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
        base_url = f"http://127.0.0.1:{port}/ocsp"

        print(f"5. Running performance tests on port {port}...")

        def make_ocsp_request(serial):
            try:
                cmd = [
                    "openssl", "ocsp",
                    "-issuer", str(pki_dir / "certs" / "intermediate.cert.pem"),
                    "-serial", f"0x{serial}",
                    "-url", base_url,
                    "-no_nonce",
                    "-timeout", "5"
                ]

                start = time.time()
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                elapsed = (time.time() - start) * 1000

                if "good" in result.stdout.lower() or "revoked" in result.stdout.lower():
                    return {"success": True, "time_ms": elapsed, "serial": serial}
                else:
                    return {"success": False, "time_ms": elapsed, "error": result.stderr[:100]}
            except Exception as e:
                return {"success": False, "time_ms": 0, "error": str(e)}

        print("\n   Test 1: Sequential requests (10 certificates)...")
        sequential_times = []
        for serial in serials:
            result = make_ocsp_request(serial)
            if result["success"]:
                sequential_times.append(result["time_ms"])
                print(f"     Serial {serial}: {result['time_ms']:.2f}ms")
            else:
                print(f"     Serial {serial}: FAILED - {result.get('error', 'Unknown')}")

        if sequential_times:
            avg_seq = sum(sequential_times) / len(sequential_times)
            print(f"\n   Average sequential response time: {avg_seq:.2f}ms")

        print("\n   Test 2: Concurrent requests (50 requests, 10 concurrent)...")
        concurrency = 10
        total_requests = 50

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = []
            for i in range(total_requests):
                serial = serials[i % len(serials)]
                futures.append(executor.submit(make_ocsp_request, serial))

            concurrent_results = []
            for future in as_completed(futures):
                result = future.result()
                concurrent_results.append(result)

        successful = [r for r in concurrent_results if r["success"]]
        failed = [r for r in concurrent_results if not r["success"]]

        if successful:
            avg_con = sum(r["time_ms"] for r in successful) / len(successful)
            print(f"   Successful: {len(successful)}/{total_requests}")
            print(f"   Failed: {len(failed)}/{total_requests}")
            print(f"   Average response time: {avg_con:.2f}ms")
            print(f"   Throughput: {len(successful) / (max(r['time_ms'] for r in successful) / 1000):.2f} req/sec")

        print("\n   Test 3: Cache performance (repeated requests)...")
        test_serial = serials[0]

        first_result = make_ocsp_request(test_serial)
        if first_result["success"]:
            print(f"   First request: {first_result['time_ms']:.2f}ms")

            cached_results = []
            for i in range(5):
                result = make_ocsp_request(test_serial)
                if result["success"]:
                    cached_results.append(result["time_ms"])

            if cached_results:
                avg_cached = sum(cached_results) / len(cached_results)
                print(f"   Average cached request: {avg_cached:.2f}ms")
                print(
                    f"   Cache improvement: {(first_result['time_ms'] - avg_cached) / first_result['time_ms'] * 100:.1f}%")

        print("\n   Test 4: High concurrency stress test (100 concurrent)...")
        high_concurrency = 100
        with ThreadPoolExecutor(max_workers=high_concurrency) as executor:
            futures = []
            for i in range(high_concurrency):
                serial = serials[i % len(serials)]
                futures.append(executor.submit(make_ocsp_request, serial))

            stress_results = []
            for future in as_completed(futures):
                stress_results.append(future.result())

        stress_successful = [r for r in stress_results if r["success"]]
        if stress_successful:
            avg_stress = sum(r["time_ms"] for r in stress_successful) / len(stress_successful)
            print(f"   Successful: {len(stress_successful)}/{high_concurrency}")
            print(f"   Average response time: {avg_stress:.2f}ms")
            print(
                f"   Peak throughput: {len(stress_successful) / (max(r['time_ms'] for r in stress_successful) / 1000):.2f} req/sec")

        print("\n6. Performance Summary:")
        print(f"   Total certificates issued: {len(serials)}")
        if sequential_times:
            print(f"   Sequential avg: {avg_seq:.2f}ms")
        if successful:
            print(f"   Concurrent avg (50 req, 10 workers): {avg_con:.2f}ms")
        if stress_successful:
            print(f"   Stress avg (100 concurrent): {avg_stress:.2f}ms")

        db = CertificateDatabase(str(pki_dir / "micropki.db"))
        cert_count = len(db.list_certificates())
        db.close()

        print(f"   Database certificate count: {cert_count}")

        if successful and len(successful) > 0:
            print("\nOCSP performance test completed!")
        else:
            print("\nOCSP performance test completed with errors")
            return 1

        return 0


if __name__ == "__main__":
    sys.exit(test_ocsp_performance())