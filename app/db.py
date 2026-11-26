"""SQLite storage: settings, firewalls, backups, runs."""
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from . import config

_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS firewalls (
    id TEXT PRIMARY KEY,            -- Sophos Central firewall id, or 'serial:<serial>' for imported-only
    tenant_id TEXT, tenant_name TEXT, api_host TEXT,
    serial TEXT, hostname TEXT, name TEXT, model TEXT, firmware TEXT,
    connected INTEGER, external_ip TEXT, ha_role TEXT,
    host_override TEXT, port INTEGER,
    username TEXT, password_enc TEXT,
    enabled INTEGER DEFAULT 1,
    in_central INTEGER DEFAULT 1,
    last_backup_at TEXT, last_status TEXT, last_error TEXT,
    updated_at TEXT
);
CREATE INDEX IF NOT EXISTS fw_serial ON firewalls(serial);
CREATE TABLE IF NOT EXISTS backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firewall_id TEXT, taken_at TEXT, sha256 TEXT, path TEXT,
    source TEXT, entity_count INTEGER, size INTEGER, note TEXT
);
CREATE INDEX IF NOT EXISTS bk_fw ON backups(firewall_id, taken_at);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT, finished_at TEXT, trigger TEXT, status TEXT,
    summary_json TEXT, report_path TEXT, emailed INTEGER DEFAULT 0, email_error TEXT
);
CREATE TABLE IF NOT EXISTS run_results (
    run_id INTEGER, firewall_id TEXT, status TEXT, error TEXT,
    backup_id INTEGER, prev_backup_id INTEGER, change_count INTEGER, review_count INTEGER,
    changes_json TEXT
);
CREATE TABLE IF NOT EXISTS imported_files (path TEXT PRIMARY KEY, mtime REAL, imported_at TEXT);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT,
    password_hash TEXT NOT NULL,
    invite_hash TEXT, invite_expires TEXT,
    is_admin INTEGER DEFAULT 0,
    disabled INTEGER DEFAULT 0,
    must_change_password INTEGER DEFAULT 0,
    totp_secret_enc TEXT, totp_enabled INTEGER DEFAULT 0, totp_last_counter INTEGER DEFAULT -1,
    session_version INTEGER DEFAULT 1,
    created_at TEXT, last_login_at TEXT, last_login_ip TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT, username TEXT, ip TEXT, event TEXT, detail TEXT
);
CREATE INDEX IF NOT EXISTS audit_at ON audit_log(at);
"""

DEFAULT_SETTINGS = {
    "schedule_time": "02:00",
    "timezone": "America/New_York",
    "recipients": "",
    "send_when_no_changes": "1",
    "retention_days": "180",
    "import_folder": "",
    "ignore_patterns": "",
    "ignore_types": "RouterAdvertisement",   # whole configuration types left out of comparisons
    "entity_types": "",          # blank = built-in list
    "default_username": "",
    "default_password_enc": "",
}


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _connect():
    conn = sqlite3.connect(config.DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


_conn = None


def conn():
    global _conn
    if _conn is None:
        _conn = _connect()
        _conn.executescript(SCHEMA)
        cols = {r[1] for r in _conn.execute("PRAGMA table_info(firewalls)")}
        if "api_host" not in cols:   # upgrade databases created before the Fusion export
            _conn.execute("ALTER TABLE firewalls ADD COLUMN api_host TEXT")
        if "ha_role" not in cols:    # upgrade databases created before HA auxiliaries were skipped
            _conn.execute("ALTER TABLE firewalls ADD COLUMN ha_role TEXT")
        for k, v in DEFAULT_SETTINGS.items():
            _conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", (k, v))
        _conn.commit()
    return _conn


@contextmanager
def tx():
    with _lock:
        c = conn()
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise


def q(sql, args=()):
    with _lock:
        return [dict(r) for r in conn().execute(sql, args).fetchall()]


def q1(sql, args=()):
    rows = q(sql, args)
    return rows[0] if rows else None


def get_settings():
    return {r["key"]: r["value"] for r in q("SELECT key, value FROM settings")}


def get_setting(key):
    r = q1("SELECT value FROM settings WHERE key=?", (key,))
    return r["value"] if r else DEFAULT_SETTINGS.get(key, "")


def set_settings(values: dict):
    with tx() as c:
        for k, v in values.items():
            c.execute("INSERT INTO settings(key, value) VALUES (?, ?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, v))


def dumps(obj):
    return json.dumps(obj, default=str)
