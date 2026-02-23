import logging
import sys
from datetime import datetime
from typing import Optional


def setup_logger(
        name: str = "micropki",
        log_file: Optional[str] = None,
        level: int = logging.INFO
) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)

    logger.handlers.clear()

    formatter = logging.Formatter(
        fmt='%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S'
    )

    if log_file:
        handler = logging.FileHandler(log_file, encoding='utf-8')
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def redact_passphrase(msg: str) -> str:
    if "passphrase" in msg.lower() and ":" in msg:
        parts = msg.split(":", 1)
        return f"{parts[0]}: [REDACTED]"
    return msg