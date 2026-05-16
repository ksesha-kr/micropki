import pytest
import tempfile
import json
from pathlib import Path
from micropki.audit import AuditLogger


def test_audit_log_creation():
    with tempfile.TemporaryDirectory() as tmpdir:
        audit = AuditLogger(tmpdir)
        audit.log("AUDIT", "test_op", "success", "Test message", {})
        log_file = Path(tmpdir) / 'audit' / 'audit.log'
        assert log_file.exists()


def test_audit_integrity():
    with tempfile.TemporaryDirectory() as tmpdir:
        audit = AuditLogger(tmpdir)
        audit.log("AUDIT", "op1", "success", "Entry 1", {})
        audit.log("AUDIT", "op2", "success", "Entry 2", {})
        passed, idx = audit.verify()
        assert passed is True
        assert idx is None


def test_audit_tamper_detection():
    with tempfile.TemporaryDirectory() as tmpdir:
        audit = AuditLogger(tmpdir)
        audit.log("AUDIT", "op1", "success", "Entry 1", {})
        audit.log("AUDIT", "op2", "success", "Entry 2", {})

        log_file = Path(tmpdir) / 'audit' / 'audit.log'
        content = log_file.read_text()
        lines = content.strip().split('\n')

        entry = json.loads(lines[1])
        entry['message'] = 'Tampered'
        lines[1] = json.dumps(entry)
        log_file.write_text('\n'.join(lines) + '\n')

        passed, idx = audit.verify()
        assert passed is False
        assert idx == 1


def test_ct_log():
    with tempfile.TemporaryDirectory() as tmpdir:
        audit = AuditLogger(tmpdir)
        audit.ct_log("123456", "CN=test", "fingerprint", "CN=CA")
        assert audit.ct_verify("123456") is True