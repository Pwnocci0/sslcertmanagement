import logging
import logging.handlers
import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .database import Base, engine
from .routers import (
    admin, analytics, auth, backups, certificates, csrs, csrtemplates, customer_groups,
    customers, dashboard, domains, exports, letsencrypt, mail_settings, mailtemplates,
    mfa, notifications, profile, report, security, settings, stepup, tasks, thesslstore,
)
from .scheduler import shutdown_scheduler, start_scheduler, trigger_cert_status_update
from .templates_config import templates as _jinja_templates

load_dotenv()

# ── Datei-Logging einrichten ──────────────────────────────────────────────────
_LOG_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "app.log"
)
os.makedirs(os.path.dirname(_LOG_FILE), exist_ok=True)

_log_formatter = logging.Formatter(
    fmt="%(asctime)s %(levelname)-8s %(name)-45s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

_file_handler = logging.handlers.RotatingFileHandler(
    _LOG_FILE,
    maxBytes=5 * 1024 * 1024,  # 5 MB
    backupCount=5,
    encoding="utf-8",
)
_file_handler.setFormatter(_log_formatter)
_file_handler.setLevel(logging.DEBUG)

# Root-Logger: alle App-Logger schreiben in die Datei
_root = logging.getLogger()
_root.setLevel(logging.DEBUG)
_root.addHandler(_file_handler)

# Uvicorn-Logger ebenfalls in Datei leiten
for _uv_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
    logging.getLogger(_uv_name).addHandler(_file_handler)

app = FastAPI(
    title="SSL Cert Management",
    description="Interne SSL-Zertifikatsverwaltung für MSP",
    version="0.1.0",
    docs_url=None,   # In Produktion ausblenden
    redoc_url=None,
)

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("APP_SECRET_KEY", "dev-secret-key-CHANGE-IN-PRODUCTION"),
    session_cookie="sslmgmt_session",
    max_age=8 * 3600,  # 8 Stunden
    https_only=False,  # auf True setzen wenn HTTPS aktiv
)

_BASE_DIR = Path(__file__).resolve().parent.parent
_STATIC_DIR = _BASE_DIR / "static"

app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# Uploads-Verzeichnis sicherstellen
(_STATIC_DIR / "uploads").mkdir(parents=True, exist_ok=True)


@app.on_event("startup")
def on_startup():
    start_scheduler()
    trigger_cert_status_update()  # Bestehende Statuses beim Start sofort korrigieren
    # Jinja2-Globals aus Einstellungen laden
    try:
        from .database import SessionLocal
        from .settings_service import get_settings_service
        db = SessionLocal()
        try:
            svc = get_settings_service(db)
            _jinja_templates.env.globals["app_name"] = svc.get_str("app.name", "SSL Cert Management")
            _jinja_templates.env.globals["app_timezone"] = svc.get_str("app.timezone", "Europe/Berlin")
            _jinja_templates.env.globals["app_favicon"] = svc.get_str("app.favicon_path", "")
            _jinja_templates.env.globals["app_logo"] = svc.get_str("app.logo_path", "")
        finally:
            db.close()
    except Exception:
        pass  # Fehler beim Laden der Einstellungen → Defaults bleiben


@app.on_event("shutdown")
def on_shutdown():
    shutdown_scheduler()


# Routers einbinden
app.include_router(auth.router)
app.include_router(mfa.router)
app.include_router(dashboard.router)
app.include_router(customers.router)
app.include_router(domains.router)
app.include_router(csrs.router)
app.include_router(certificates.router)
app.include_router(settings.router)
app.include_router(thesslstore.router)
app.include_router(stepup.router)
app.include_router(tasks.router)
app.include_router(admin.router)
app.include_router(csrtemplates.router)
app.include_router(customer_groups.router)
app.include_router(exports.router)
app.include_router(mail_settings.router)
app.include_router(mailtemplates.router)
app.include_router(notifications.router)
app.include_router(backups.router)
app.include_router(profile.router)
app.include_router(report.router)
app.include_router(security.router)
app.include_router(letsencrypt.router)
app.include_router(analytics.router)

# Tabellen beim Start anlegen (nur für SQLite-Dev, nicht für Produktions-Migrations-Workflow)
Base.metadata.create_all(bind=engine)
