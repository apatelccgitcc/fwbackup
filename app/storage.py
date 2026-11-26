"""Backup files on disk (gzip) + their database rows."""
import gzip
import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import config, db
from .normalize import compile_ignores, ignored_types, parse_config


def _safe(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s or "unknown")[:80]


def save_backup(firewall_id, xml_bytes, source, entity_count, taken_at=None, note=""):
    taken_at = taken_at or db.now_iso()
    sha = hashlib.sha256(xml_bytes).hexdigest()
    folder = config.BACKUP_DIR / _safe(firewall_id)
    folder.mkdir(parents=True, exist_ok=True)
    stamp = taken_at.replace(":", "").replace("-", "").replace("+0000", "Z")[:15]
    path = folder / f"{stamp}_{sha[:8]}.xml.gz"
    with gzip.open(path, "wb") as fh:
        fh.write(xml_bytes)
    with db.tx() as c:
        cur = c.execute("INSERT INTO backups(firewall_id, taken_at, sha256, path, source, entity_count, size, note) "
                        "VALUES (?,?,?,?,?,?,?,?)",
                        (firewall_id, taken_at, sha, str(path.relative_to(config.DATA_DIR)), source,
                         entity_count, path.stat().st_size, note))
        return cur.lastrowid


def load_backup_bytes(backup):
    with gzip.open(config.DATA_DIR / backup["path"], "rb") as fh:
        return fh.read()


def load_parsed(backup, ignores=None, skip_types=None):
    if ignores is None:
        ignores = compile_ignores(db.get_setting("ignore_patterns"))
    if skip_types is None:
        skip_types = ignored_types(db.get_setting("ignore_types"))
    return parse_config(load_backup_bytes(backup), ignores, skip_types)


def get_backup(backup_id):
    return db.q1("SELECT * FROM backups WHERE id=?", (backup_id,))


def latest_backup(firewall_id, before_id=None):
    if before_id:
        return db.q1("SELECT * FROM backups WHERE firewall_id=? AND id<? ORDER BY taken_at DESC, id DESC LIMIT 1",
                     (firewall_id, before_id))
    return db.q1("SELECT * FROM backups WHERE firewall_id=? ORDER BY taken_at DESC, id DESC LIMIT 1",
                 (firewall_id,))


def prune(retention_days):
    """Delete backups older than the retention period, always keeping each firewall's newest 5."""
    if not retention_days or retention_days <= 0:
        return 0
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
    removed = 0
    for fw in db.q("SELECT DISTINCT firewall_id FROM backups"):
        rows = db.q("SELECT * FROM backups WHERE firewall_id=? ORDER BY taken_at DESC, id DESC", (fw["firewall_id"],))
        for b in rows[5:]:
            if b["taken_at"] < cutoff:
                try:
                    (config.DATA_DIR / b["path"]).unlink(missing_ok=True)
                except OSError:
                    pass
                with db.tx() as c:
                    c.execute("DELETE FROM backups WHERE id=?", (b["id"],))
                removed += 1
    return removed
