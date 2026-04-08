# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env  # set APP_SECRET_KEY and CSR_KEY_PASSPHRASE

python init_db.py
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Required `.env` variables: `APP_SECRET_KEY`, `CSR_KEY_PASSPHRASE`, `DATABASE_URL` (defaults to `sqlite:///./data/sslcertmanagement.db`).

## Running Tests

```bash
# All tests
pytest

# Single test file
pytest tests/test_settings_service.py

# Single test class or function
pytest tests/test_settings_service.py::TestCache::test_defaults_loaded_without_db_rows
```

Tests require `APP_SECRET_KEY` set (the test files set it via `os.environ.setdefault`).

## Architecture

**Stack:** FastAPI + Jinja2 (server-rendered HTML) + SQLite via SQLAlchemy + Starlette sessions (cookie-based auth).

**Authentication flow (multi-step):**
1. Password step → sets `pre_mfa_user_id` in session
2. MFA step (TOTP via `pyotp`, or recovery code) → sets `user_id` in session
3. `app/auth.py:login_required()` enforces both steps and redirects appropriately

All routes call `login_required()` manually (no FastAPI dependency injection middleware). Admin-only routes additionally check `user.is_admin`.

**Step-up auth** (`app/stepup.py`, `app/routers/stepup.py`): sensitive operations (e.g., viewing private keys) require re-confirming the TOTP code. Grants a short-lived `stepup_until` timestamp in session.

**Settings system** (`app/settings_service.py`): key-value settings stored in `app_settings` DB table with typed getters (`get_str`, `get_bool`, `get_int`). Sensitive values (API tokens) are Fernet-encrypted before storage. Module-level cache is invalidated via `_invalidate_cache()` after writes.

**TheSSLStore integration** (`app/services/thesslstore/`): external CA API integration. `client.py` handles HTTP, `service.py` provides business logic, `schemas.py` defines Pydantic models. Supports sandbox/live mode toggled via `thesslstore.sandbox` setting.

**Crypto** (`app/crypto.py`): RSA private keys are AES-encrypted with `CSR_KEY_PASSPHRASE` from `.env` before storing in the DB. **Do not change `CSR_KEY_PASSPHRASE` after initial setup** — existing encrypted keys become unreadable.

**MFA secrets** are Fernet-encrypted (key derived from `APP_SECRET_KEY`). Recovery codes are stored as HMAC-SHA256 hashes, never plaintext.

**Audit logging** (`app/audit.py`): all significant user actions are written to the `audit_logs` table.

**Routers** (`app/routers/`): one file per entity/feature. Templates are in `app/templates/`. Static assets in `static/`.

## Data Model Key Points

- `Certificate.status`: `pending` | `active` | `expiring_soon` | `expired` | `revoked`
- `Customer` can be archived (soft delete) — filter `is_archived=False` for active customers
- `CsrRequest.private_key_encrypted` — never expose decrypted key without step-up auth
- `User.mfa_setup_completed` must be `True` for full session access

## Deployment

`install.sh` sets up a systemd service (`certmgr`) running as the `certmgr` user. Two modes:
- **Mode 1:** Local Nginx + Let's Encrypt
- **Mode 2:** External reverse proxy (generates Nginx config template at `deploy/external-nginx-example.conf`)

Logs go to `data/app.log` (rotating, 5 MB × 5 files).
