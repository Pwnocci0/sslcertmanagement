"""Tests für Login-Schutz, Session-Manager und fail2ban-Service."""
from __future__ import annotations

import os
import hashlib
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

import pytest

os.environ.setdefault("APP_SECRET_KEY", "test-secret-key-for-security-tests")
os.environ.setdefault("CSR_KEY_PASSPHRASE", "test-passphrase")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app import models


# ── Test-DB-Setup ────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    return eng


@pytest.fixture
def db(engine):
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.rollback()
    session.close()


_user_counter = 0


@pytest.fixture
def user(db):
    global _user_counter
    _user_counter += 1
    u = models.User(
        username=f"testuser_{_user_counter}",
        email=f"test_{_user_counter}@example.com",
        hashed_password="hashed",
        is_active=True,
        is_admin=True,
        mfa_setup_completed=True,
    )
    db.add(u)
    db.commit()
    return u


# ── Login-Schutz ──────────────────────────────────────────────────────────────

class TestLoginProtection:
    def test_record_attempt_success(self, db, user):
        from app.services.login_protection import record_attempt, get_recent_stats
        record_attempt(db, "testuser", "1.2.3.4", success=True)
        stats = get_recent_stats(db, hours=24)
        assert stats["success"] >= 1

    def test_record_attempt_failed(self, db, user):
        from app.services.login_protection import record_attempt, get_recent_attempts
        record_attempt(db, "baduser", "5.6.7.8", success=False)
        attempts = get_recent_attempts(db, limit=100)
        usernames = [a.username for a in attempts]
        assert "baduser" in usernames

    def test_not_locked_out_when_disabled(self, db):
        from app.services.login_protection import is_locked_out, record_attempt
        for _ in range(10):
            record_attempt(db, "victim", "9.9.9.9", success=False)
        # max_attempts=0 → deaktiviert
        assert is_locked_out(db, "victim", "9.9.9.9", max_attempts=0) is False

    def test_lockout_by_username(self, db):
        from app.services.login_protection import is_locked_out, record_attempt
        for _ in range(5):
            record_attempt(db, "locked_user", "10.0.0.1", success=False)
        assert is_locked_out(db, "locked_user", "10.0.0.1", max_attempts=5, window_minutes=60) is True

    def test_lockout_by_ip(self, db):
        from app.services.login_protection import is_locked_out, record_attempt
        for _ in range(5):
            record_attempt(db, "different_user", "192.168.1.1", success=False)
        # Gleiche IP, anderer Benutzername → trotzdem gesperrt
        assert is_locked_out(db, "other_user", "192.168.1.1", max_attempts=5, window_minutes=60) is True

    def test_not_locked_out_below_threshold(self, db):
        from app.services.login_protection import is_locked_out, record_attempt
        record_attempt(db, "almost_locked", "172.16.0.1", success=False)
        assert is_locked_out(db, "almost_locked", "172.16.0.1", max_attempts=5, window_minutes=60) is False

    def test_clear_attempts(self, db):
        from app.services.login_protection import (
            is_locked_out, record_attempt, clear_attempts_for_user,
        )
        for _ in range(5):
            record_attempt(db, "clearme", "11.22.33.44", success=False)
        assert is_locked_out(db, "clearme", "11.22.33.44", max_attempts=5, window_minutes=60) is True
        clear_attempts_for_user(db, "clearme")
        assert is_locked_out(db, "clearme", "11.22.33.44", max_attempts=5, window_minutes=60) is False

    def test_cleanup_old_attempts(self, db):
        from app.services.login_protection import cleanup_old_attempts
        old = models.LoginAttempt(
            username="olduser",
            ip_address="1.1.1.1",
            success=False,
            created_at=datetime.utcnow() - timedelta(days=60),
        )
        db.add(old)
        db.flush()
        deleted = cleanup_old_attempts(db, older_than_days=30)
        assert deleted >= 1

    def test_get_recent_stats(self, db):
        from app.services.login_protection import get_recent_stats, record_attempt
        record_attempt(db, "statsuser", "2.2.2.2", success=True)
        record_attempt(db, "statsuser", "2.2.2.2", success=False)
        stats = get_recent_stats(db, hours=24)
        assert "total" in stats
        assert "failed" in stats
        assert "success" in stats
        assert stats["total"] == stats["failed"] + stats["success"]


# ── Session-Manager ───────────────────────────────────────────────────────────

class TestSessionManager:
    def test_create_and_validate_session(self, db, user):
        from app.services.session_manager import create_session, validate_session
        token = create_session(db, user.id, "127.0.0.1", "TestBrowser/1.0")
        assert isinstance(token, str) and len(token) > 10
        sess = validate_session(db, token)
        assert sess is not None
        assert sess.user_id == user.id
        assert sess.is_active is True

    def test_validate_invalid_token(self, db):
        from app.services.session_manager import validate_session
        assert validate_session(db, "totally-invalid-token") is None

    def test_revoke_session(self, db, user):
        from app.services.session_manager import create_session, validate_session, revoke_session
        token = create_session(db, user.id, "127.0.0.1", "TestBrowser/1.0")
        sess = validate_session(db, token)
        assert sess is not None
        revoke_session(db, sess.id)
        assert validate_session(db, token) is None

    def test_revoke_nonexistent_returns_false(self, db):
        from app.services.session_manager import revoke_session
        assert revoke_session(db, 999999) is False

    def test_revoke_all_for_user(self, db, user):
        from app.services.session_manager import create_session, validate_session, revoke_all_for_user
        t1 = create_session(db, user.id, "1.1.1.1", "A")
        t2 = create_session(db, user.id, "2.2.2.2", "B")
        count = revoke_all_for_user(db, user.id)
        assert count >= 2
        assert validate_session(db, t1) is None
        assert validate_session(db, t2) is None

    def test_revoke_all_except_current(self, db, user):
        from app.services.session_manager import create_session, validate_session, revoke_all_for_user
        keep = create_session(db, user.id, "3.3.3.3", "Keep")
        other = create_session(db, user.id, "4.4.4.4", "Other")
        revoke_all_for_user(db, user.id, except_token=keep)
        # keep soll noch aktiv sein
        assert validate_session(db, keep) is not None
        assert validate_session(db, other) is None

    def test_get_active_sessions(self, db, user):
        from app.services.session_manager import create_session, get_active_sessions, revoke_all_for_user
        revoke_all_for_user(db, user.id)
        create_session(db, user.id, "5.5.5.5", "X")
        sessions = get_active_sessions(db, user_id=user.id)
        assert len(sessions) >= 1
        assert all(s.is_active for s in sessions)

    def test_cleanup_old_sessions(self, db, user):
        from app.services.session_manager import cleanup_old_sessions
        old_hash = hashlib.sha256(b"old-token-unique-xyz").hexdigest()
        old_sess = models.UserSession(
            user_id=user.id,
            session_token_hash=old_hash,
            is_active=False,
            last_seen_at=datetime.utcnow() - timedelta(days=60),
        )
        db.add(old_sess)
        db.flush()
        deleted = cleanup_old_sessions(db, older_than_days=30)
        assert deleted >= 1

    def test_last_seen_updated_on_validate(self, db, user):
        from app.services.session_manager import create_session, validate_session
        token = create_session(db, user.id, "6.6.6.6", "Z")
        sess1 = validate_session(db, token)
        first_seen = sess1.last_seen_at
        import time; time.sleep(0.05)
        sess2 = validate_session(db, token)
        # last_seen_at sollte sich aktualisiert haben (oder zumindest nicht vorher)
        assert sess2.last_seen_at >= first_seen


# ── fail2ban-Service ──────────────────────────────────────────────────────────

class TestFail2banService:
    def test_is_available_when_missing(self):
        from app.services import fail2ban as fb
        with patch("os.path.exists", return_value=False):
            assert fb.is_available() is False

    def test_is_available_when_present(self):
        from app.services import fail2ban as fb
        with patch("os.path.exists", return_value=True):
            assert fb.is_available() is True

    def test_get_status_not_available(self):
        from app.services import fail2ban as fb
        with patch.object(fb, "is_available", return_value=False):
            result = fb.get_status()
        assert result["jails"] == []
        assert result["error"] is not None

    def test_get_status_parses_jails(self):
        import pickle
        from app.services import fail2ban as fb
        # fail2ban antwortet: [0, [("Number of jail", 2), ("Jail list", "sshd, nginx-http-auth")]]
        response = pickle.dumps([0, [("Number of jail", 2), ("Jail list", "sshd, nginx-http-auth")]], 2)
        with patch.object(fb, "is_available", return_value=True), \
             patch.object(fb, "_send", return_value=([("Number of jail", 2), ("Jail list", "sshd, nginx-http-auth")], None)):
            result = fb.get_status()
        assert "sshd" in result["jails"]
        assert "nginx-http-auth" in result["jails"]
        assert result["error"] is None

    def test_get_status_on_error(self):
        from app.services import fail2ban as fb
        with patch.object(fb, "is_available", return_value=True), \
             patch.object(fb, "_send", return_value=(None, "fail2ban ist nicht erreichbar")):
            result = fb.get_status()
        assert result["error"] is not None

    def test_get_jail_status_invalid_name(self):
        from app.services import fail2ban as fb
        result = fb.get_jail_status("../../etc/passwd")
        assert result["error"] is not None

    def test_get_jail_status_parses_output(self):
        from app.services import fail2ban as fb
        payload = [
            ("Filter", [
                ("Currently failed", 3),
                ("Total failed", 42),
            ]),
            ("Actions", [
                ("Currently banned", 2),
                ("Total banned", 10),
                ("Banned IP list", ["1.2.3.4", "5.6.7.8"]),
            ]),
        ]
        with patch.object(fb, "is_available", return_value=True), \
             patch.object(fb, "_send", return_value=(payload, None)):
            result = fb.get_jail_status("sshd")
        assert result["total_banned"] == 2
        assert result["total_failed"] == 42
        assert "1.2.3.4" in result["banned_ips"]
        assert result["error"] is None

    def test_get_jail_status_timeout(self):
        import socket
        from app.services import fail2ban as fb
        with patch.object(fb, "is_available", return_value=True), \
             patch.object(fb, "_send", return_value=(None, "Timeout beim Verbinden mit fail2ban.")):
            result = fb.get_jail_status("sshd")
        assert result["error"] is not None


# ── stepup: dynamische Dauer ──────────────────────────────────────────────────

class TestStepupDuration:
    def test_default_duration_when_cache_empty(self):
        from app.stepup import _get_stepup_duration, STEPUP_DURATION
        with patch("app.settings_service._cache_valid", False):
            assert _get_stepup_duration() == STEPUP_DURATION

    def test_reads_from_cache(self):
        from app import stepup
        with patch("app.settings_service._cache_valid", True), \
             patch("app.settings_service._cache", {"security.stepup_duration_seconds": "600"}):
            assert stepup._get_stepup_duration() == 600

    def test_clamps_minimum(self):
        from app import stepup
        with patch("app.settings_service._cache_valid", True), \
             patch("app.settings_service._cache", {"security.stepup_duration_seconds": "10"}):
            assert stepup._get_stepup_duration() == 60

    def test_clamps_maximum(self):
        from app import stepup
        with patch("app.settings_service._cache_valid", True), \
             patch("app.settings_service._cache", {"security.stepup_duration_seconds": "9999"}):
            assert stepup._get_stepup_duration() == 3600
