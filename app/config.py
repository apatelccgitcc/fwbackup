"""Environment configuration. Secrets live in the environment (.env), never in the database."""
import os
from pathlib import Path


def _env(name, default=""):
    return os.environ.get(name, default).strip()


DATA_DIR = Path(_env("DATA_DIR", str(Path(__file__).resolve().parent.parent / "data")))
BACKUP_DIR = DATA_DIR / "backups"
REPORT_DIR = DATA_DIR / "reports"
DB_PATH = DATA_DIR / "fwbackup.db"

# Web app
ADMIN_PASSWORD = _env("ADMIN_PASSWORD")
APP_SECRET_KEY = _env("APP_SECRET_KEY")          # used for sessions and for encrypting firewall passwords
APP_BASE_URL = _env("APP_BASE_URL", "http://localhost:8080").rstrip("/")

# Sophos Central / Fusion partner API credential
SOPHOS_CLIENT_ID = _env("SOPHOS_CLIENT_ID")
SOPHOS_CLIENT_SECRET = _env("SOPHOS_CLIENT_SECRET")
SOPHOS_ID_URL = _env("SOPHOS_ID_URL", "https://id.sophos.com/api/v2/oauth2/token")
SOPHOS_GLOBAL_URL = _env("SOPHOS_GLOBAL_URL", "https://api.central.sophos.com")
EXPORT_POLL_SECONDS = float(_env("EXPORT_POLL_SECONDS", "10") or 10)
EXPORT_TIMEOUT = int(_env("EXPORT_TIMEOUT", "900") or 900)

# Default firewall API login (can be overridden per firewall in the UI)
FW_DEFAULT_USERNAME = _env("FW_DEFAULT_USERNAME")
FW_DEFAULT_PASSWORD = _env("FW_DEFAULT_PASSWORD")
FW_API_PORT = int(_env("FW_API_PORT", "4444") or 4444)
FW_VERIFY_TLS = _env("FW_VERIFY_TLS", "false").lower() in ("1", "true", "yes")
FW_TIMEOUT = float(_env("FW_TIMEOUT", "45") or 45)
FW_CONCURRENCY = int(_env("FW_CONCURRENCY", "6") or 6)

# Email: "smtp" or "graph"
EMAIL_METHOD = _env("EMAIL_METHOD", "smtp").lower()
MAIL_FROM = _env("MAIL_FROM")
SMTP_HOST = _env("SMTP_HOST")
SMTP_PORT = int(_env("SMTP_PORT", "587") or 587)
SMTP_USERNAME = _env("SMTP_USERNAME")
SMTP_PASSWORD = _env("SMTP_PASSWORD")
SMTP_SECURITY = _env("SMTP_SECURITY", "starttls").lower()   # starttls | ssl | none
GRAPH_TENANT_ID = _env("GRAPH_TENANT_ID")
GRAPH_CLIENT_ID = _env("GRAPH_CLIENT_ID")
GRAPH_CLIENT_SECRET = _env("GRAPH_CLIENT_SECRET")


def central_configured():
    return bool(SOPHOS_CLIENT_ID and SOPHOS_CLIENT_SECRET)


def email_configured():
    if EMAIL_METHOD == "graph":
        return bool(GRAPH_TENANT_ID and GRAPH_CLIENT_ID and GRAPH_CLIENT_SECRET and MAIL_FROM)
    return bool(SMTP_HOST and MAIL_FROM)


for d in (DATA_DIR, BACKUP_DIR, REPORT_DIR):
    d.mkdir(parents=True, exist_ok=True)
