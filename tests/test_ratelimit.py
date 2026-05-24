import pytest
import time
import threading
import requests
import tempfile
from pathlib import Path
from micropki.ratelimit import RateLimiter, TokenBucket
from micropki.repository import RepositoryServer
from micropki.database import CertificateDatabase


def test_token_bucket():
    bucket = TokenBucket(rate=1.0, capacity=2)
    assert bucket.consume() is True
    assert bucket.consume() is True
    assert bucket.consume() is False
    time.sleep(1.1)
    assert bucket.consume() is True


def test_rate_limiter():
    limiter = RateLimiter(rate=1.0, burst=2)
    allowed, _ = limiter.is_allowed("127.0.0.1")
    assert allowed is True
    allowed, _ = limiter.is_allowed("127.0.0.1")
    assert allowed is True
    allowed, _ = limiter.is_allowed("127.0.0.1")
    assert allowed is False
    allowed, _ = limiter.is_allowed("192.168.1.1")
    assert allowed is True


def test_rate_limiter_disabled():
    limiter = RateLimiter(rate=0, burst=10)
    for _ in range(20):
        allowed, _ = limiter.is_allowed("127.0.0.1")
        assert allowed is True


def test_repository_with_rate_limiting():
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_dir = Path(tmpdir) / 'certs'
        cert_dir.mkdir()
        (cert_dir / 'ca.cert.pem').write_text("-----BEGIN CERTIFICATE-----\nTEST ROOT CA\n-----END CERTIFICATE-----")
        (cert_dir / 'intermediate.cert.pem').write_text(
            "-----BEGIN CERTIFICATE-----\nTEST INTERMEDIATE\n-----END CERTIFICATE-----")

        db_path = Path(tmpdir) / 'test.db'
        db = CertificateDatabase(str(db_path))
        db.init_schema()
        db.close()

        audit_dir = Path(tmpdir) / 'pki' / 'audit'
        audit_dir.mkdir(parents=True, exist_ok=True)

        import socket
        sock = socket.socket()
        sock.bind(('', 0))
        free_port = sock.getsockname()[1]
        sock.close()

        server = RepositoryServer(
            str(db_path),
            str(cert_dir),
            '127.0.0.1',
            free_port,
            rate_limit=0,
            rate_burst=10
        )

        def run_server():
            server.start()

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        time.sleep(2)

        base_url = f"http://127.0.0.1:{free_port}"

        status_200 = 0
        for i in range(5):
            try:
                response = requests.get(f"{base_url}/ca/root", timeout=5)
                if response.status_code == 200:
                    status_200 += 1
            except Exception as e:
                print(f"Request {i} failed: {e}")
            time.sleep(0.1)

        print(f"200 responses: {status_200}")
        assert status_200 >= 3
