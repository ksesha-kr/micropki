import json
import hashlib
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
import logging

logger = logging.getLogger(__name__)


class AuditError(Exception):
    pass


class AuditLogger:
    def __init__(self, out_dir: str = './pki'):
        self.audit_dir = Path(out_dir) / 'audit'
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.audit_dir / 'audit.log'
        self.chain_file = self.audit_dir / 'chain.dat'
        self.ct_file = self.audit_dir / 'ct.log'
        self._lock = threading.Lock()
        self._init_log()

    def _init_log(self):
        if not self.log_file.exists():
            first_entry = self._create_entry(
                level="AUDIT",
                operation="audit_init",
                status="success",
                message="Audit log initialized",
                metadata={}
            )
            with self._lock:
                with open(self.log_file, 'w') as f:
                    f.write(json.dumps(first_entry) + '\n')
                with open(self.chain_file, 'w') as f:
                    f.write(first_entry['integrity']['hash'])

    def _calculate_hash(self, entry: Dict[str, Any]) -> str:
        entry_copy = entry.copy()
        entry_copy.pop('integrity', None)
        canonical = json.dumps(entry_copy, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _get_prev_hash(self) -> str:
        if not self.chain_file.exists():
            return '0' * 64
        with open(self.chain_file, 'r') as f:
            return f.read().strip()

    def _update_chain(self, current_hash: str):
        with open(self.chain_file, 'w') as f:
            f.write(current_hash)

    def _create_entry(self, level: str, operation: str, status: str, message: str, metadata: Dict[str, Any]) -> Dict[
        str, Any]:
        prev_hash = self._get_prev_hash()
        entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(timespec='microseconds'),
            'level': level,
            'operation': operation,
            'status': status,
            'message': message,
            'metadata': metadata,
            'integrity': {
                'prev_hash': prev_hash,
                'hash': ''
            }
        }
        entry['integrity']['hash'] = self._calculate_hash(entry)
        return entry

    def log(self, level: str, operation: str, status: str, message: str, metadata: Dict[str, Any] = None):
        entry = self._create_entry(level, operation, status, message, metadata or {})
        with self._lock:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(entry) + '\n')
            self._update_chain(entry['integrity']['hash'])
        logger.info(f"AUDIT: {operation} - {status}")

    def query(self, from_time: Optional[str] = None, to_time: Optional[str] = None, level: Optional[str] = None,
              operation: Optional[str] = None, serial: Optional[str] = None) -> List[Dict[str, Any]]:
        results = []
        if not self.log_file.exists():
            return results

        with open(self.log_file, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                entry = json.loads(line)

                if from_time and entry['timestamp'] < from_time:
                    continue
                if to_time and entry['timestamp'] > to_time:
                    continue
                if level and entry['level'] != level:
                    continue
                if operation and entry['operation'] != operation:
                    continue
                if serial:
                    meta_serial = entry.get('metadata', {}).get('serial')
                    if meta_serial != serial:
                        continue
                results.append(entry)
        return results

    def verify(self) -> Tuple[bool, Optional[int]]:
        if not self.log_file.exists():
            return True, None

        prev_hash = '0' * 64
        entries = []
        with open(self.log_file, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                entries.append(json.loads(line))

        for i, entry in enumerate(entries):
            stored_prev = entry['integrity']['prev_hash']
            stored_hash = entry['integrity']['hash']
            if stored_prev != prev_hash:
                return False, i
            computed_hash = self._calculate_hash(entry)
            if computed_hash != stored_hash:
                return False, i
            prev_hash = stored_hash

        if self.chain_file.exists():
            with open(self.chain_file, 'r') as f:
                stored_chain = f.read().strip()
            if stored_chain != prev_hash:
                return False, len(entries) - 1
        return True, None

    def ct_log(self, serial: str, subject: str, fingerprint: str, issuer: str):
        with self._lock:
            with open(self.ct_file, 'a') as f:
                f.write(f"{datetime.now(timezone.utc).isoformat()} | {serial} | {subject} | {fingerprint} | {issuer}\n")

    def ct_verify(self, serial: str) -> bool:
        if not self.ct_file.exists():
            return False
        with open(self.ct_file, 'r') as f:
            for line in f:
                if serial in line:
                    return True
        return False


_audit_logger = None


def get_audit_logger(out_dir: str = './pki') -> AuditLogger:
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger(out_dir)
    return _audit_logger