"""
Regression: the raw client key is the sole credential (and the encryption KDF
input), so it must never reach the logs. The service write/rotate exception
paths log a non-reversible fingerprint instead. These tests fail loudly if a
future edit reintroduces the raw key into a log line.
"""

import logging
import uuid
from unittest.mock import patch

import pytest

from auth.audit import client_fingerprint
from auth.database import SessionLocal
from auth.services.service import AuthorizationService


def test_write_failure_logs_fingerprint_not_raw_key(caplog):
    key = str(uuid.uuid4())
    db = SessionLocal()
    try:
        svc = AuthorizationService(db, key)
        with patch.object(db, "execute", side_effect=RuntimeError("boom")):
            with caplog.at_level(logging.ERROR):
                assert svc.add_role("engineers") is False
        assert key not in caplog.text, "raw client key leaked into logs"
        assert client_fingerprint(key) in caplog.text, "expected fingerprint in logs"
    finally:
        db.rollback()
        db.close()


def test_rotation_failure_logs_fingerprint_not_raw_key(caplog):
    key = str(uuid.uuid4())
    db = SessionLocal()
    try:
        svc = AuthorizationService(db, key)
        with patch.object(db, "execute", side_effect=RuntimeError("boom")):
            with caplog.at_level(logging.ERROR):
                with pytest.raises(RuntimeError):
                    svc.rotate_client_key(str(uuid.uuid4()))
        assert key not in caplog.text, "raw client key leaked into rotation log"
        assert client_fingerprint(key) in caplog.text
    finally:
        db.rollback()
        db.close()


def test_invalid_client_key_error_does_not_echo_the_key():
    bad = "not-a-uuid-but-still-secret"
    with pytest.raises(ValueError) as exc:
        AuthorizationService(SessionLocal(), bad)
    assert bad not in str(exc.value), "invalid-key error must not echo the raw key"
