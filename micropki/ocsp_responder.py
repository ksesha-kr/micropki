from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
import threading
import time
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


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
        self.db_path = db_path
        self.responder_cert_path = Path(responder_cert_path)
        self.responder_key_path = Path(responder_key_path)
        self.ca_cert_path = Path(ca_cert_path)
        self.host = host
        self.port = port
        self.cache_ttl = cache_ttl
        self.cache: Dict[str, tuple] = {}

        self.app = Flask('micropki-ocsp')
        CORS(self.app)

        self._load_certificates()
        self._setup_routes()

    def _load_certificates(self):
        try:
            with open(self.responder_cert_path, 'rb') as f:
                self.responder_cert = x509.load_pem_x509_certificate(
                    f.read(), default_backend()
                )

            with open(self.responder_key_path, 'rb') as f:
                self.responder_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )

            with open(self.ca_cert_path, 'rb') as f:
                self.ca_cert = x509.load_pem_x509_certificate(
                    f.read(), default_backend()
                )

            logger.info("OCSP certificates loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load certificates: {str(e)}")
            raise

    def _setup_routes(self):
        from micropki.ocsp import (
            parse_ocsp_request, extract_nonce_from_request,
            build_ocsp_response_good, build_ocsp_response_revoked,
            build_ocsp_response_unknown
        )
        from micropki.database import CertificateDatabase
        from micropki.serial import validate_serial_hex

        @self.app.before_request
        def log_request():
            logger.info(f"[OCSP] {request.method} {request.path} from {request.remote_addr}")

        @self.app.route('/ocsp', methods=['POST'])
        def handle_ocsp():
            start_time = time.time()

            if request.content_type != 'application/ocsp-request':
                return "Expected Content-Type: application/ocsp-request", 400

            ocsp_request = parse_ocsp_request(request.data)
            if ocsp_request is None:
                return "Malformed OCSP request", 400

            nonce = extract_nonce_from_request(ocsp_request)
            this_update = datetime.now(timezone.utc)
            next_update = this_update + timedelta(seconds=self.cache_ttl)

            db = CertificateDatabase(self.db_path)
            responses = []

            for req in ocsp_request:
                serial_hex = hex(req.serial_number)[2:].upper()

                cache_key = f"{serial_hex}:{nonce.hex() if nonce else 'none'}"
                if cache_key in self.cache:
                    response_data, expiry = self.cache[cache_key]
                    if expiry > time.time():
                        db.close()
                        return response_data, 200, {'Content-Type': 'application/ocsp-response'}

                cert = db.get_certificate_by_serial(serial_hex)

                if not cert:
                    response = build_ocsp_response_unknown(
                        self.responder_cert, self.responder_key,
                        self.ca_cert, req.serial_number,
                        this_update, nonce
                    )
                elif cert['status'] == 'revoked':
                    response = build_ocsp_response_revoked(
                        self.responder_cert, self.responder_key,
                        self.ca_cert, req.serial_number,
                        datetime.fromisoformat(cert['revocation_date']),
                        cert.get('revocation_reason'),
                        this_update, next_update, nonce
                    )
                else:
                    response = build_ocsp_response_good(
                        self.responder_cert, self.responder_key,
                        self.ca_cert, req.serial_number,
                        this_update, next_update, nonce
                    )

                self.cache[cache_key] = (response, time.time() + self.cache_ttl)
                responses.append((response, cert['status'] if cert else 'unknown'))

            db.close()

            elapsed_ms = (time.time() - start_time) * 1000
            for response, status in responses:
                logger.info(f"[OCSP] Serial: {req.serial_number}, Status: {status}, Time: {elapsed_ms:.2f}ms")

            return responses[0][0], 200, {'Content-Type': 'application/ocsp-response'}

        @self.app.route('/health', methods=['GET'])
        def health():
            return {"status": "ok", "service": "ocsp", "timestamp": datetime.now().isoformat()}, 200

    def start(self):
        logger.info(f"Starting OCSP responder on {self.host}:{self.port}")
        logger.info(f"Database: {self.db_path}")
        logger.info(f"Cache TTL: {self.cache_ttl}s")
        self.app.run(host=self.host, port=self.port, threaded=True)