from flask import Flask, request
from flask_cors import CORS
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple
import time
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class OCSPError(Exception):
    pass

class OCSPHandler:

    def __init__(
            self,
            db_path: str,
            responder_cert_path: str,
            responder_key_path: str,
            ca_cert_path: str,
            cache_ttl: int = 60
    ):
        self.db_path = db_path
        self.cache_ttl = cache_ttl
        self.cache: Dict[str, tuple] = {}
        self.issuer_certs: List[x509.Certificate] = []
        self.issuer_hashes: List[Tuple[bytes, bytes, x509.Certificate]] = []

        self._load_certificates(responder_cert_path, responder_key_path, ca_cert_path)

    def _load_certificates(self, responder_cert_path, responder_key_path, ca_cert_path):
        try:
            with open(responder_cert_path, 'rb') as f:
                self.responder_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            with open(responder_key_path, 'rb') as f:
                self.responder_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )

            with open(ca_cert_path, 'rb') as f:
                ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                self.issuer_certs.append(ca_cert)
                self._add_issuer_hashes(ca_cert)

            root_ca_path = Path(ca_cert_path).parent.parent / 'certs' / 'ca.cert.pem'
            if root_ca_path.exists():
                with open(root_ca_path, 'rb') as f:
                    root_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                    self.issuer_certs.append(root_cert)
                    self._add_issuer_hashes(root_cert)

            logger.info(f"OCSP certificates loaded: {len(self.issuer_certs)} issuer(s)")

        except Exception as e:
            logger.error(f"Failed to load certificates: {str(e)}")
            raise

    def _add_issuer_hashes(self, cert: x509.Certificate):
        from micropki.ocsp import compute_issuer_hashes
        name_hash, key_hash = compute_issuer_hashes(cert)
        self.issuer_hashes.append((name_hash, key_hash, cert))

    def find_issuer_by_hashes(self, req_name_hash: bytes, req_key_hash: bytes) -> Optional[x509.Certificate]:
        for name_hash, key_hash, cert in self.issuer_hashes:
            if name_hash == req_name_hash and key_hash == req_key_hash:
                return cert
        return None

    def handle_request(self, flask_request) -> tuple:
        start_time = time.time()

        if flask_request.content_type != 'application/ocsp-request':
            return "Expected Content-Type: application/ocsp-request", 400

        from micropki.ocsp import (
            parse_ocsp_request, extract_nonce_from_request,
            build_ocsp_response_good, build_ocsp_response_revoked,
            build_ocsp_response_unknown
        )
        from micropki.database import CertificateDatabase

        ocsp_request = parse_ocsp_request(flask_request.data)
        if ocsp_request is None:
            return "Malformed OCSP request", 400

        nonce = extract_nonce_from_request(ocsp_request)
        this_update = datetime.now(timezone.utc)
        next_update = this_update + timedelta(seconds=self.cache_ttl)

        db = CertificateDatabase(self.db_path)
        responses = []
        last_serial = None
        last_status = None
        last_issuer = None

        for req in ocsp_request:
            serial_hex = hex(req.serial_number)[2:].upper()
            last_serial = serial_hex

            issuer_cert = self.find_issuer_by_hashes(req.issuer_name_hash, req.issuer_key_hash)
            last_issuer = issuer_cert

            if issuer_cert is None:
                response = build_ocsp_response_unknown(
                    self.responder_cert, self.responder_key,
                    self.issuer_certs[0] if self.issuer_certs else None,
                    req.serial_number,
                    this_update, nonce
                )
                last_status = 'unknown_issuer'
            else:
                cache_key = f"{serial_hex}:{issuer_cert.subject.rfc4514_string()}"
                if cache_key in self.cache:
                    response_data, expiry = self.cache[cache_key]
                    if expiry > time.time():
                        db.close()
                        return response_data, 200, {'Content-Type': 'application/ocsp-response'}

                cert = db.get_certificate_by_serial(serial_hex)

                if not cert:
                    response = build_ocsp_response_unknown(
                        self.responder_cert, self.responder_key,
                        issuer_cert, req.serial_number,
                        this_update, nonce
                    )
                    last_status = 'unknown'
                elif cert['status'] == 'revoked':
                    response = build_ocsp_response_revoked(
                        self.responder_cert, self.responder_key,
                        issuer_cert, req.serial_number,
                        datetime.fromisoformat(cert['revocation_date']),
                        cert.get('revocation_reason'),
                        this_update, next_update, nonce
                    )
                    last_status = 'revoked'
                else:
                    response = build_ocsp_response_good(
                        self.responder_cert, self.responder_key,
                        issuer_cert, req.serial_number,
                        this_update, next_update, nonce
                    )
                    last_status = 'good'

                self.cache[cache_key] = (response, time.time() + self.cache_ttl)

            responses.append(response)

        db.close()

        elapsed_ms = (time.time() - start_time) * 1000
        issuer_name = last_issuer.subject.rfc4514_string() if last_issuer else 'unknown'
        logger.info(
            f"[OCSP] Serial: {last_serial}, Status: {last_status}, Issuer: {issuer_name}, Time: {elapsed_ms:.2f}ms")

        return responses[0] if responses else b'', 200, {'Content-Type': 'application/ocsp-response'}


class OCSPResponder:

    def __init__(
            self,
            db_path: str,
            responder_cert_path: str,
            responder_key_path: str,
            ca_cert_path: str,
            host: str = '127.0.0.1',
            port: int = 8081,
            cache_ttl: int = 60,
            log_file: Optional[str] = None
    ):
        self.host = host
        self.port = port
        self.handler = OCSPHandler(db_path, responder_cert_path, responder_key_path, ca_cert_path, cache_ttl)

        self.app = Flask('micropki-ocsp')
        CORS(self.app)

        @self.app.before_request
        def log_request():
            logger.info(f"[OCSP] {request.method} {request.path} from {request.remote_addr}")

        @self.app.route('/ocsp', methods=['POST'])
        def handle():
            return self.handler.handle_request(request)

        @self.app.route('/health', methods=['GET'])
        def health():
            return {"status": "ok", "service": "ocsp", "timestamp": datetime.now().isoformat()}, 200

    def start(self):
        logger.info(f"Starting OCSP responder on {self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, threaded=True)
