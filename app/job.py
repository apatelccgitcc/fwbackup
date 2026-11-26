"""The nightly run: sync firewalls from Fusion, back each one up, compare, report, email."""
import logging
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from . import config, crypto, db, importer, report, sfos, storage
from .diff import diff_configs
from .normalize import EXCLUDED_TYPES, compile_ignores, count_entities, ignored_types
from .sophos_central import CentralClient, entities_from_tar, flatten_firewall, supports_central_export

log = logging.getLogger("fwbackup")
_run_lock = threading.Lock()
progress = {"running": False, "message": "", "run_id": None}


# -- firewall inventory ------------------------------------------------------
def sync_inventory(client=None):
    client = client or CentralClient()
    tenants = client.tenants()
    seen, errors = set(), []
    for t in tenants:
        try:
            fws = client.firewalls(t)
        except Exception as e:  # one tenant failing shouldn't stop the rest
            errors.append(f"{t.get('name')}: {e}")
            continue
        for fw in fws:
            row = flatten_firewall(t, fw)
            seen.add(row["id"])
            with db.tx() as c:
                c.execute("""INSERT INTO firewalls(id, tenant_id, tenant_name, api_host, serial, hostname, name, model,
                                 firmware, connected, external_ip, ha_role, in_central, updated_at)
                             VALUES (:id,:tenant_id,:tenant_name,:api_host,:serial,:hostname,:name,:model,:firmware,
                                 :connected,:external_ip,:ha_role,1,:now)
                             ON CONFLICT(id) DO UPDATE SET tenant_id=excluded.tenant_id,
                                 tenant_name=excluded.tenant_name, api_host=excluded.api_host, serial=excluded.serial,
                                 hostname=excluded.hostname, name=excluded.name, model=excluded.model,
                                 firmware=excluded.firmware, connected=excluded.connected,
                                 external_ip=excluded.external_ip, ha_role=excluded.ha_role, in_central=1,
                                 updated_at=excluded.updated_at""",
                          {**row, "now": db.now_iso()})
                # an import-only placeholder for the same serial gets merged into the Central record
                if row["serial"]:
                    ph = f"serial:{row['serial']}"
                    if c.execute("SELECT 1 FROM firewalls WHERE id=?", (ph,)).fetchone():
                        c.execute("UPDATE backups SET firewall_id=? WHERE firewall_id=?", (row["id"], ph))
                        c.execute("UPDATE run_results SET firewall_id=? WHERE firewall_id=?", (row["id"], ph))
                        c.execute("DELETE FROM firewalls WHERE id=?", (ph,))
    if seen:
        with db.tx() as c:
            qmarks = ",".join("?" * len(seen))
            c.execute(f"UPDATE firewalls SET in_central=0 WHERE id NOT LIKE 'serial:%' AND id NOT IN ({qmarks})",
                      list(seen))
    with db.tx() as c:   # auxiliaries aren't backed up, so don't keep showing an old error for them
        c.execute("UPDATE firewalls SET last_status=NULL, last_error=NULL WHERE ha_role='auxiliary'")
    return {"tenants": len(tenants), "firewalls": len(seen), "errors": errors}


def firewall_credentials(fw):
    if fw.get("username") and fw.get("password_enc"):
        return fw["username"], crypto.decrypt(fw["password_enc"])
    s = db.get_settings()
    if s.get("default_username") and s.get("default_password_enc"):
        return s["default_username"], crypto.decrypt(s["default_password_enc"])
    if config.FW_DEFAULT_USERNAME and config.FW_DEFAULT_PASSWORD:
        return config.FW_DEFAULT_USERNAME, config.FW_DEFAULT_PASSWORD
    return None, None


def entity_types():
    custom = [t for t in db.get_setting("entity_types").split() if t not in EXCLUDED_TYPES]
    return custom or sfos.DEFAULT_ENTITY_TYPES


def has_api_login(fw):
    try:
        return bool(firewall_credentials(fw)[0])
    except RuntimeError:
        return True   # a login is stored but can't be decrypted - let the attempt report it


def backup_firewall_xmlapi(fw, http=None):
    """Fallback: read the configuration straight from the firewall's XML API."""
    host = (fw.get("host_override") or fw.get("external_ip") or "").strip()
    if not host:
        return {"status": "skipped", "error": "No address to reach the firewall API (set one on the firewall page)"}
    try:
        user, pw = firewall_credentials(fw)
    except RuntimeError as e:
        return {"status": "failed", "error": str(e)}
    if not user:
        return {"status": "skipped", "error": "No firewall API login set"}
    try:
        xml, count, skipped = sfos.fetch_config(host, user, pw, fw.get("port") or None, entity_types(), http=http)
        return {"status": "ok", "xml": xml, "count": count, "source": "api",
                "note": ("Skipped types: " + ", ".join(skipped)) if skipped else ""}
    except Exception as e:
        return {"status": "failed", "error": str(e)}


def backup_firewall_central(fw, client):
    """Primary: full configuration export through Sophos Fusion (SFOS 22.0 MR2+)."""
    if not fw.get("api_host") or not fw.get("tenant_id"):
        return {"status": "failed", "error": "Tenant region unknown - sync from Sophos Fusion first"}
    if not fw.get("connected"):
        return {"status": "failed", "error": "Firewall isn't connected to Sophos Fusion"}
    try:
        tar = client.export_config(fw["api_host"], fw["tenant_id"], fw["id"])
        xml = entities_from_tar(tar)
        return {"status": "ok", "xml": xml, "count": count_entities(xml), "source": "central", "note": ""}
    except Exception as e:
        return {"status": "failed", "error": f"Fusion export: {e}"}


def backup_firewall(fw, client=None, http=None):
    """Fusion export first; the firewall's own API only if a login is set for it."""
    use_central = client is not None and fw.get("in_central")
    old_fw = use_central and supports_central_export(fw.get("firmware")) is False
    if use_central and not old_fw:
        res = backup_firewall_central(fw, client)
        if res["status"] == "ok" or not has_api_login(fw):
            return res
        fallback = backup_firewall_xmlapi(fw, http)
        if fallback["status"] != "ok":
            fallback["error"] = f"{res['error']}; firewall API fallback: {fallback['error']}"
        return fallback
    if has_api_login(fw):
        return backup_firewall_xmlapi(fw, http)
    if old_fw:
        return {"status": "skipped",
                "error": f"Firmware {fw.get('firmware')} is older than SFOS 22.0 MR2, so Fusion can't export it. "
                         "Upgrade it, or set a firewall API login"}
    return {"status": "skipped", "error": "Sophos Fusion API credential not set"}


# backwards-compatible name used by the web UI's "Back up now"
def backup_firewall_api(fw, http=None):
    client = CentralClient(http=http) if config.central_configured() else None
    return backup_firewall(fw, client, http)


# -- imports -------------------------------------------------------------------
def run_imports():
    folder = db.get_setting("import_folder").strip()
    if not folder:
        return {}, []
    results, errors = {}, []
    try:
        files = importer.find_tar_files(folder)
    except Exception as e:
        return {}, [str(e)]
    done = {r["path"]: r["mtime"] for r in db.q("SELECT path, mtime FROM imported_files")}
    firewalls = db.q("SELECT * FROM firewalls")
    for p in files:
        mtime = p.stat().st_mtime
        if done.get(str(p)) == mtime:
            continue
        try:
            xml = importer.read_entities_from_tar(p)
            fw, serial, client = importer.match_firewall(p, firewalls)
            if fw is None:
                fid = f"serial:{serial or p.stem}"
                with db.tx() as c:
                    c.execute("""INSERT OR IGNORE INTO firewalls(id, tenant_name, serial, name, in_central, enabled, updated_at)
                                 VALUES (?,?,?,?,0,1,?)""", (fid, client, serial, p.stem, db.now_iso()))
                fw = db.q1("SELECT * FROM firewalls WHERE id=?", (fid,))
                firewalls.append(fw)
            taken = datetime.fromtimestamp(mtime, timezone.utc).replace(microsecond=0).isoformat()
            bid = storage.save_backup(fw["id"], xml, "import", count_entities(xml), taken, note=str(p.name))
            results.setdefault(fw["id"], []).append(bid)
            with db.tx() as c:
                c.execute("INSERT OR REPLACE INTO imported_files(path, mtime, imported_at) VALUES (?,?,?)",
                          (str(p), mtime, db.now_iso()))
        except Exception as e:
            errors.append(f"{p.name}: {e}")
    return results, errors


# -- the run ---------------------------------------------------------------------
def run(trigger="schedule", http=None, central_client=None, send_email=True):
    if not _run_lock.acquire(blocking=False):
        return None
    run_id = None
    try:
        started = db.now_iso()
        with db.tx() as c:
            run_id = c.execute("INSERT INTO runs(started_at, trigger, status) VALUES (?,?,?)",
                               (started, trigger, "running")).lastrowid
        progress.update(running=True, run_id=run_id, message="Syncing firewalls from Sophos Fusion")
        notes = []
        # 1. inventory
        client = central_client or (CentralClient() if config.central_configured() else None)
        if client:
            try:
                inv = sync_inventory(client)
                notes.append(f"Fusion: {inv['firewalls']} firewalls across {inv['tenants']} tenants")
                notes += [f"Fusion tenant error - {e}" for e in inv["errors"]]
            except Exception as e:
                notes.append(f"Fusion sync failed: {e}")
        # 2. remember each firewall's latest backup before this run
        before = {r["firewall_id"]: r["mx"] for r in
                  db.q("SELECT firewall_id, MAX(id) AS mx FROM backups GROUP BY firewall_id")}
        # 3. imports from folder
        progress["message"] = "Importing exported backups"
        imported, imp_err = run_imports()
        notes += [f"Import error - {e}" for e in imp_err]
        # 4. backups: Fusion export, falling back to the firewall API where a login is set.
        #    HA auxiliaries are skipped: Fusion can't export them and the primary's backup covers the cluster.
        fws = db.q("SELECT * FROM firewalls WHERE enabled=1 AND in_central=1 "
                   "AND COALESCE(ha_role, '') != 'auxiliary' ORDER BY tenant_name, name")
        statuses = {}
        progress["message"] = f"Backing up {len(fws)} firewalls"
        with ThreadPoolExecutor(max_workers=max(1, config.FW_CONCURRENCY)) as ex:
            futs = {ex.submit(backup_firewall, fw, client, http): fw for fw in fws}
            for n, fut in enumerate(as_completed(futs), 1):
                fw = futs[fut]
                res = fut.result()
                progress["message"] = f"Backed up {n} of {len(fws)} firewalls"
                if res["status"] == "ok":
                    bid = storage.save_backup(fw["id"], res["xml"], res["source"], res["count"], note=res["note"])
                    statuses[fw["id"]] = ("ok", "", bid)
                else:
                    statuses[fw["id"]] = (res["status"], res["error"], None)
        # imported backups count as success for firewalls whose API backup didn't work
        for fid, bids in imported.items():
            st = statuses.get(fid)
            if st is None or st[0] != "ok":
                statuses[fid] = ("ok", "", max(bids))
        # 5. compare
        progress["message"] = "Comparing configurations"
        ignores = compile_ignores(db.get_setting("ignore_patterns"))
        skip = ignored_types(db.get_setting("ignore_types"))
        results = []
        for fid, (status, err, bid) in statuses.items():
            row = {"run_id": run_id, "firewall_id": fid, "status": status, "error": err, "backup_id": bid,
                   "prev_backup_id": None, "change_count": 0, "review_count": 0, "changes_json": "[]"}
            if bid:
                prev_id = before.get(fid)
                if prev_id:
                    row["prev_backup_id"] = prev_id
                    try:
                        old = storage.load_parsed(storage.get_backup(prev_id), ignores, skip)
                        new = storage.load_parsed(storage.get_backup(bid), ignores, skip)
                        ch = diff_configs(old, new)
                        row.update(change_count=len(ch), review_count=sum(1 for c in ch if c["review"]),
                                   changes_json=db.dumps(ch))
                    except Exception as e:
                        row.update(status="failed", error=f"Compare failed: {e}")
                else:
                    row["status"] = "first"
            results.append(row)
            with db.tx() as c:
                c.execute("""INSERT INTO run_results(run_id, firewall_id, status, error, backup_id, prev_backup_id,
                             change_count, review_count, changes_json) VALUES
                             (:run_id,:firewall_id,:status,:error,:backup_id,:prev_backup_id,:change_count,
                              :review_count,:changes_json)""", row)
                c.execute("UPDATE firewalls SET last_status=?, last_error=?, last_backup_at=COALESCE(?, last_backup_at) "
                          "WHERE id=?", (row["status"], row["error"],
                                         db.now_iso() if bid else None, fid))
        # 6. retention
        try:
            pruned = storage.prune(int(db.get_setting("retention_days") or 0))
            if pruned:
                notes.append(f"Removed {pruned} backups past the retention period")
        except Exception as e:
            notes.append(f"Retention cleanup failed: {e}")
        # 7. report + email
        progress["message"] = "Building report"
        rep = report.build(run_id, notes)
        path = config.REPORT_DIR / f"run-{run_id}.html"
        path.write_text(rep["html"], encoding="utf-8")
        emailed, email_err = 0, None
        if send_email:
            if rep["summary"]["changed_firewalls"] or db.get_setting("send_when_no_changes") == "1":
                try:
                    report.send(rep["subject"], rep["html"])
                    emailed = 1
                except Exception as e:
                    email_err = str(e)
        with db.tx() as c:
            c.execute("UPDATE runs SET finished_at=?, status=?, summary_json=?, report_path=?, emailed=?, email_error=? "
                      "WHERE id=?", (db.now_iso(), "done", db.dumps({**rep["summary"], "notes": notes}),
                                     str(path.relative_to(config.DATA_DIR)), emailed, email_err, run_id))
        return run_id
    except Exception as e:
        log.exception("Run failed")
        if run_id:
            with db.tx() as c:
                c.execute("UPDATE runs SET finished_at=?, status=?, summary_json=? WHERE id=?",
                          (db.now_iso(), "error", db.dumps({"error": str(e), "trace": traceback.format_exc()}), run_id))
        return run_id
    finally:
        progress.update(running=False, message="")
        _run_lock.release()


def run_in_background(trigger="manual"):
    if progress["running"]:
        return False
    threading.Thread(target=run, kwargs={"trigger": trigger}, daemon=True).start()
    return True
