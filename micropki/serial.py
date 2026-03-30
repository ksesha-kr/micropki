import secrets
import time
from typing import Optional
from cryptography.hazmat.primitives import hashes
import logging

logger = logging.getLogger(__name__)


class SerialGenerator:
    def __init__(self, db_connection=None):
        self.db_connection = db_connection
        self.counter = 0

    def generate_serial(self) -> int:
        timestamp = int(time.time())

        random_part = secrets.randbits(32)

        serial = (timestamp << 32) | random_part

        logger.debug(f"Generated serial number: {hex(serial)}")
        return serial

    def generate_serial_hex(self) -> str:
        serial = self.generate_serial()
        return hex(serial)[2:].upper()


def validate_serial_hex(serial_hex: str) -> bool:
    try:
        int(serial_hex, 16)
        return True
    except ValueError:
        return False