"""Unit-Tests für den SettingsService."""
import os
import pytest
from unittest.mock import MagicMock, patch

os.environ.setdefault("APP_SECRET_KEY", "test-secret-key-for-unit-tests")

from app.settings_service import SettingsService, DEFINITIONS, _invalidate_cache
from app import models


def _make_service(rows: list[models.AppSetting] | None = None):
    """Erzeugt einen SettingsService mit einem gemockten DB-Session."""
    db = MagicMock()
    db.query.return_value.all.return_value = rows or []
    _invalidate_cache()
    return SettingsService(db)


# ── Cache-Verhalten ───────────────────────────────────────────────────────────

class TestCache:
    def test_defaults_loaded_without_db_rows(self):
        svc = _make_service()
        assert svc.get_str("app.name") == "SSL Cert Management"

    def test_db_row_overrides_default(self):
        row = models.AppSetting(key="app.name", value="Mein Manager")
        svc = _make_service([row])
        assert svc.get_str("app.name") == "Mein Manager"

    def test_cache_not_reloaded_on_second_call(self):
        db = MagicMock()
        db.query.return_value.all.return_value = []
        _invalidate_cache()
        svc = SettingsService(db)
        svc.get_str("app.name")
        svc.get_str("app.name")
        # query().all() sollte nur einmal aufgerufen worden sein
        assert db.query.return_value.all.call_count == 1

    def test_invalidate_triggers_reload(self):
        db = MagicMock()
        db.query.return_value.all.return_value = []
        _invalidate_cache()
        svc = SettingsService(db)
        svc.get_str("app.name")
        _invalidate_cache()
        svc.get_str("app.name")
        assert db.query.return_value.all.call_count == 2


# ── Typ-Konvertierung ─────────────────────────────────────────────────────────

class TestTypedGetters:
    def test_get_bool_true_values(self):
        for val in ("true", "1", "yes", "on"):
            row = models.AppSetting(key="security.mfa_required", value=val)
            svc = _make_service([row])
            assert svc.get_bool("security.mfa_required") is True

    def test_get_bool_false_values(self):
        for val in ("false", "0", "no", "off"):
            row = models.AppSetting(key="security.mfa_required", value=val)
            svc = _make_service([row])
            assert svc.get_bool("security.mfa_required") is False

    def test_get_int(self):
        row = models.AppSetting(key="security.session_timeout_hours", value="24")
        svc = _make_service([row])
        assert svc.get_int("security.session_timeout_hours") == 24

    def test_get_int_invalid_returns_default(self):
        row = models.AppSetting(key="security.session_timeout_hours", value="nope")
        svc = _make_service([row])
        assert svc.get_int("security.session_timeout_hours", default=99) == 99

    def test_get_str_missing_key_returns_default(self):
        svc = _make_service()
        assert svc.get_str("nonexistent.key", default="fallback") == "fallback"


# ── Sensitive Werte ───────────────────────────────────────────────────────────

class TestSensitiveSettings:
    def test_sensitive_value_decrypted_on_read(self):
        from app.settings_service import _encrypt
        plaintext = "my-secret-token"
        encrypted = _encrypt(plaintext)

        row = models.AppSetting(key="thesslstore.auth_token_live", value=encrypted)
        svc = _make_service([row])
        assert svc.get_str("thesslstore.auth_token_live") == plaintext

    def test_bad_ciphertext_returns_none(self):
        row = models.AppSetting(key="thesslstore.auth_token_live", value="not-valid-fernet")
        svc = _make_service([row])
        assert svc.get_raw("thesslstore.auth_token_live") is None

    def test_set_sensitive_encrypts_value(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        _invalidate_cache()
        svc = SettingsService(db)
        svc.set("thesslstore.auth_token_live", "plaintext-secret")

        added_row = db.add.call_args[0][0]
        assert added_row.value != "plaintext-secret"  # verschlüsselt
        assert added_row.key == "thesslstore.auth_token_live"


# ── set / set_many ────────────────────────────────────────────────────────────

class TestWrite:
    def test_set_updates_existing_row(self):
        existing = models.AppSetting(key="app.name", value="Old")
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        _invalidate_cache()
        svc = SettingsService(db)
        svc.set("app.name", "New", user_id=1)
        assert existing.value == "New"
        db.commit.assert_called_once()

    def test_set_many_commits_once(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        _invalidate_cache()
        svc = SettingsService(db)
        svc.set_many({"app.name": "X", "app.base_url": "https://x.de"})
        db.commit.assert_called_once()

    def test_get_all_by_category_returns_all_categories(self):
        svc = _make_service()
        grouped = svc.get_all_by_category()
        from app.settings_service import CATEGORY_LABELS
        for cat in CATEGORY_LABELS:
            assert cat in grouped
