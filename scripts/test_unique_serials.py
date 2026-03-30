import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from micropki.serial import SerialGenerator
from micropki.database import CertificateDatabase
from micropki.crypto_utils import generate_rsa_key
from micropki.certificates import create_self_signed_ca_certificate, certificate_to_pem
from datetime import datetime, timezone
import tempfile


def test_unique_serials():
    print("Testing unique serial number generation...")

    with tempfile.NamedTemporaryFile(suffix='.db') as tmp:
        db = CertificateDatabase(tmp.name)
        db.init_schema()

        generator = SerialGenerator()

        certificates = []

        for i in range(100):
            serial_hex = generator.generate_serial_hex()

            cert_data = {
                'serial_hex': serial_hex,
                'subject': f'CN=Test{i}',
                'issuer': 'CN=Root CA',
                'not_before': datetime.now(timezone.utc).isoformat(),
                'not_after': datetime.now(timezone.utc).isoformat(),
                'cert_pem': f'CERT{i}',
                'status': 'valid'
            }

            db.insert_certificate(cert_data)
            certificates.append(serial_hex)
            print(f"  Inserted serial {serial_hex}")

        assert len(set(certificates)) == 100
        print(f"Successfully inserted 100 certificates with unique serials")

        db.close()


if __name__ == "__main__":
    test_unique_serials()