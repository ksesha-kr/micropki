import os
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class RepositoryServer:
    def __init__(self, db_path: str, cert_dir: str, host: str = '127.0.0.1', port: int = 8080):
        self.db_path = db_path
        self.cert_dir = Path(cert_dir)
        self.host = host
        self.port = port
        self.app = Flask('micropki-repo')

        CORS(self.app, resources={r"/*": {"origins": "*"}})

        self._setup_routes()

    def _setup_routes(self):
        from micropki.database import CertificateDatabase
        from micropki.serial import validate_serial_hex

        @self.app.before_request
        def log_request():
            logger.info(f"[HTTP] {request.method} {request.path} from {request.remote_addr}")

        @self.app.route('/certificate/<serial_hex>', methods=['GET'])
        def get_certificate(serial_hex):
            try:
                from micropki.serial import validate_serial_hex
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
            cert_path = self.cert_dir / 'certs' / filename

            if not cert_path.exists():
                cert_path = self.cert_dir / filename

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
            crl_dir = self.cert_dir / 'crl'
            crl_path = crl_dir / filename

            if not crl_path.exists():
                crl_path = Path(self.cert_dir).parent / 'crl' / filename

            if not crl_path.exists():
                return f"{ca_type.capitalize()} CRL not found", 404

            try:
                with open(crl_path, 'rb') as f:
                    crl_data = f.read()

                from datetime import datetime
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
            return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()}), 200

        @self.app.errorhandler(404)
        def not_found(e):
            return "Not found", 404

        @self.app.errorhandler(405)
        def method_not_allowed(e):
            return "Method not allowed", 405

    def start(self):
        logger.info(f"Starting repository server on {self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, threaded=True)
