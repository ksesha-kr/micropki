import os
import tempfile
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class RepositoryServer:
    def __init__(
            self,
            db_path: str,
            cert_dir: str,
            host: str = '127.0.0.1',
            port: int = 8080,
            enable_ocsp: bool = False,
            ocsp_responder_cert: Optional[str] = None,
            ocsp_responder_key: Optional[str] = None,
            ocsp_ca_cert: Optional[str] = None,
            ocsp_cache_ttl: int = 60
    ):
        self.db_path = db_path
        self.cert_dir = Path(cert_dir)
        self.host = host
        self.port = port
        self.enable_ocsp = enable_ocsp
        self.ocsp_responder_cert = ocsp_responder_cert
        self.ocsp_responder_key = ocsp_responder_key
        self.ocsp_ca_cert = ocsp_ca_cert
        self.ocsp_cache_ttl = ocsp_cache_ttl
        self.ocsp_handler = None

        self.app = Flask('micropki-repo')
        CORS(self.app, resources={r"/*": {"origins": "*"}})

        self._setup_routes()

        if enable_ocsp:
            self._setup_ocsp()

    def _setup_ocsp(self):
        try:
            from micropki.ocsp_responder import OCSPHandler
            from flask import request

            self.ocsp_handler = OCSPHandler(
                db_path=self.db_path,
                responder_cert_path=self.ocsp_responder_cert,
                responder_key_path=self.ocsp_responder_key,
                ca_cert_path=self.ocsp_ca_cert,
                cache_ttl=self.ocsp_cache_ttl
            )

            @self.app.route('/ocsp', methods=['POST'])
            def handle_ocsp():
                return self.ocsp_handler.handle_request(request)

            logger.info("OCSP endpoint enabled on /ocsp")

        except Exception as e:
            logger.error(f"Failed to initialize OCSP handler: {str(e)}")
            raise

    def _setup_routes(self):
        from micropki.database import CertificateDatabase
        from micropki.serial import validate_serial_hex

        @self.app.before_request
        def log_request():
            logger.info(f"[HTTP] {request.method} {request.path} from {request.remote_addr}")

        @self.app.route('/certificate/<serial_hex>', methods=['GET'])
        def get_certificate(serial_hex):
            try:
                if not validate_serial_hex(serial_hex):
                    return "Invalid serial number format. Must be hexadecimal.", 400

                db = CertificateDatabase(self.db_path)
                cert_record = db.get_certificate_by_serial(serial_hex)
                db.close()

                if not cert_record:
                    return "Certificate not found", 404

                return cert_record['cert_pem'], 200, {'Content-Type': 'application/x-pem-file'}

            except Exception as e:
                logger.error(f"Error retrieving certificate: {str(e)}")
                return "Internal server error", 500

        @self.app.route('/ca/<level>', methods=['GET'])
        def get_ca(level):
            if level not in ['root', 'intermediate']:
                return "Invalid CA level. Must be 'root' or 'intermediate'", 400

            filename = 'ca.cert.pem' if level == 'root' else 'intermediate.cert.pem'
            cert_path = self.cert_dir / filename

            if not cert_path.exists():
                cert_path = self.cert_dir.parent / 'certs' / filename

            if not cert_path.exists():
                return f"{level.capitalize()} CA certificate not found", 404

            try:
                with open(cert_path, 'r') as f:
                    cert_pem = f.read()
                return cert_pem, 200, {'Content-Type': 'application/x-pem-file'}
            except Exception as e:
                logger.error(f"Error reading CA certificate: {str(e)}")
                return "Internal server error", 500

        @self.app.route('/crl', methods=['GET'])
        def get_crl():
            ca_type = request.args.get('ca', 'intermediate')

            if ca_type not in ['root', 'intermediate']:
                return "Invalid CA type. Must be 'root' or 'intermediate'", 400

            filename = 'root.crl.pem' if ca_type == 'root' else 'intermediate.crl.pem'
            crl_dir = self.cert_dir.parent / 'crl'
            crl_path = crl_dir / filename

            if not crl_path.exists():
                return f"{ca_type.capitalize()} CRL not found", 404

            try:
                with open(crl_path, 'rb') as f:
                    crl_data = f.read()

                mod_time = datetime.fromtimestamp(crl_path.stat().st_mtime)

                return crl_data, 200, {
                    'Content-Type': 'application/pkix-crl',
                    'Last-Modified': mod_time.strftime('%a, %d %b %Y %H:%M:%S GMT'),
                    'Cache-Control': 'max-age=604800'
                }
            except Exception as e:
                logger.error(f"Error reading CRL: {str(e)}")
                return "Internal server error", 500

        @self.app.route('/health', methods=['GET'])
        def health():
            status = {"status": "ok", "timestamp": datetime.now().isoformat()}
            if self.enable_ocsp and self.ocsp_handler:
                status["ocsp"] = "enabled"
            return jsonify(status), 200

        @self.app.errorhandler(404)
        def not_found(e):
            return "Not found", 404

        @self.app.errorhandler(405)
        def method_not_allowed(e):
            return "Method not allowed", 405

        @self.app.route('/request-cert', methods=['POST'])
        def request_certificate():
            try:
                template = request.args.get('template')
                if template not in ['server', 'client', 'code_signing']:
                    return "Invalid template. Must be server, client, or code_signing", 400

                api_key = request.headers.get('X-API-Key')
                if api_key != 'changeme':
                    logger.warning(f"Invalid API key from {request.remote_addr}")

                csr_data = request.data
                csr = x509.load_pem_x509_csr(csr_data, default_backend())

                from micropki.ca import RootCA
                ca = RootCA(out_dir=str(self.cert_dir.parent), log_file=None)

                with tempfile.NamedTemporaryFile(mode='wb', suffix='.csr') as tmp_csr:
                    tmp_csr.write(csr_data)
                    tmp_csr.flush()

                    result = ca.issue_certificate(
                        ca_cert_path=str(self.cert_dir / 'intermediate.cert.pem'),
                        ca_key_path=str(self.cert_dir.parent / 'private' / 'intermediate.key.pem'),
                        ca_passphrase_file=str(self.cert_dir.parent.parent / 'secrets' / 'intermediate.pass'),
                        template=template,
                        subject=csr.subject.rfc4514_string(),
                        csr_path=tmp_csr.name,
                        out_dir=str(self.cert_dir),
                        db_path=self.db_path
                    )

                with open(result['certificate'], 'rb') as f:
                    cert_pem = f.read()

                logger.info(f"Certificate issued via API for {csr.subject.rfc4514_string()} from {request.remote_addr}")

                return cert_pem, 201, {'Content-Type': 'application/x-pem-file'}

            except Exception as e:
                logger.error(f"Certificate request failed: {str(e)}")
                return f"Failed to issue certificate: {str(e)}", 500

    def start(self):
        logger.info(f"Starting repository server on {self.host}:{self.port}")
        if self.enable_ocsp:
            logger.info(f"OCSP endpoint available at http://{self.host}:{self.port}/ocsp")
        self.app.run(host=self.host, port=self.port, threaded=True)
