"""Web UI + scheduler."""
import hmac
import json
import logging
import threading
import time
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from . import config, crypto, db, job, report, storage
from .diff import diff_configs
from .normalize import compile_ignores, ignored_types
from .sfos import DEFAULT_ENTITY_TYPES

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("fwbackup")

app = FastAPI(title="Firewall Backup & Change Report", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
tpl = report.env
scheduler = BackgroundScheduler()


def render(request, name, **ctx):
    ctx.update(request=request, progress=job.progress, central_ok=config.central_configured(),
               email_ok=config.email_configured(), next_run=next_run_time(), path=request.url.path)
    return HTMLResponse(tpl.get_template(name).render(**ctx))


# -- auth --------------------------------------------------------------------------
PUBLIC = ("/login", "/static", "/healthz")


@app.middleware("http")
async def require_login(request: Request, call_next):
    if not request.url.path.startswith(PUBLIC) and not request.session.get("ok"):
        return RedirectResponse("/login", status_code=303)
    return await call_next(request)


# added after require_login so it wraps it (outermost) and the session is available there
app.add_middleware(SessionMiddleware, secret_key=config.APP_SECRET_KEY or "unset-secret",
                   same_site="lax", https_only=config.APP_BASE_URL.startswith("https"), max_age=12 * 3600)


@app.get("/healthz")
def healthz():
    return {"ok": True}


# Lock out an address after repeated wrong passwords, so the password can't be guessed by brute force.
MAX_FAILURES = 5
FAILURE_WINDOW = 15 * 60     # seconds in which the failures are counted
LOCKOUT_SECONDS = 15 * 60
_failures = {}               # ip -> list of failure times
_locked_until = {}           # ip -> time the lockout ends
_login_lock = threading.Lock()


def _client_ip(request):
    return request.client.host if request.client else "unknown"


def _lockout_remaining(ip):
    with _login_lock:
        until = _locked_until.get(ip, 0)
        if until <= time.time():
            _locked_until.pop(ip, None)
            return 0
        return int(until - time.time()) + 1


def _record_failure(ip):
    now = time.time()
    with _login_lock:
        recent = [t for t in _failures.get(ip, []) if now - t < FAILURE_WINDOW] + [now]
        _failures[ip] = recent
        if len(recent) >= MAX_FAILURES:
            _locked_until[ip] = now + LOCKOUT_SECONDS
            _failures.pop(ip, None)
            log.warning("Login locked for %s after %d wrong passwords", ip, len(recent))
            return True
    log.warning("Wrong password from %s", ip)
    return False


def _locked_message(seconds):
    mins = max(1, (seconds + 59) // 60)
    return f"Too many wrong passwords. Try again in {mins} minute{'s' if mins != 1 else ''}."


@app.get("/login")
def login_page(request: Request):
    return render(request, "login.html", error=None, configured=bool(config.ADMIN_PASSWORD and config.APP_SECRET_KEY))


@app.post("/login")
def login(request: Request, password: str = Form("")):
    configured = bool(config.ADMIN_PASSWORD and config.APP_SECRET_KEY)
    ip = _client_ip(request)
    remaining = _lockout_remaining(ip)
    if remaining:   # even the right password is refused while locked
        return render(request, "login.html", error=_locked_message(remaining), configured=configured)
    if configured and hmac.compare_digest(password.encode(), config.ADMIN_PASSWORD.encode()):
        with _login_lock:
            _failures.pop(ip, None)
        request.session["ok"] = True
        return RedirectResponse("/", status_code=303)
    time.sleep(1)   # slows down guessing
    if _record_failure(ip):
        return render(request, "login.html", error=_locked_message(LOCKOUT_SECONDS), configured=configured)
    return render(request, "login.html", error="Wrong password", configured=configured)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# -- dashboard -----------------------------------------------------------------------
@app.get("/")
def dashboard(request: Request):
    runs = db.q("SELECT * FROM runs ORDER BY id DESC LIMIT 20")
    for r in runs:
        r["summary"] = json.loads(r["summary_json"] or "{}")
    last = next((r for r in runs if r["status"] == "done"), None)
    changed = []
    if last:
        changed = db.q("""SELECT rr.*, f.name, f.tenant_name FROM run_results rr
                          LEFT JOIN firewalls f ON f.id=rr.firewall_id
                          WHERE rr.run_id=? AND (rr.change_count>0 OR rr.status='failed')
                          ORDER BY rr.review_count DESC, rr.change_count DESC""", (last["id"],))
    counts = db.q1("""SELECT COUNT(*) AS total, SUM(enabled) AS enabled,
                      SUM(CASE WHEN last_status IN ('ok','first') THEN 1 ELSE 0 END) AS healthy,
                      SUM(CASE WHEN last_status='failed' THEN 1 ELSE 0 END) AS failed,
                      SUM(CASE WHEN last_status='skipped' OR last_status IS NULL THEN 1 ELSE 0 END) AS setup
                      FROM firewalls WHERE enabled=1 AND COALESCE(ha_role, '') != 'auxiliary'""")
    return render(request, "dashboard.html", runs=runs, last=last, changed=changed, counts=counts)


@app.post("/run")
def run_now():
    job.run_in_background("manual")
    return RedirectResponse("/", status_code=303)


@app.get("/status")
def status():
    return JSONResponse({k: job.progress[k] for k in ("running", "message", "run_id")})


@app.post("/sync")
def sync(request: Request):
    try:
        res = job.sync_inventory()
        msg = f"Synced {res['firewalls']} firewalls from {res['tenants']} tenants." + (
            f" {len(res['errors'])} tenant errors." if res["errors"] else "")
    except Exception as e:
        msg = f"Sync failed: {e}"
    request.session["flash"] = msg
    return RedirectResponse("/firewalls", status_code=303)


@app.get("/runs/{run_id}")
def run_report(run_id: int):
    r = db.q1("SELECT * FROM runs WHERE id=?", (run_id,))
    if not r or not r["report_path"]:
        return HTMLResponse("Report not found", status_code=404)
    return HTMLResponse((config.DATA_DIR / r["report_path"]).read_text(encoding="utf-8"))


# -- firewalls -------------------------------------------------------------------------
@app.get("/firewalls")
def firewalls(request: Request, q: str = "", client: str = "", show: str = ""):
    sql = "SELECT f.*, (SELECT COUNT(*) FROM backups b WHERE b.firewall_id=f.id) AS backups FROM firewalls f WHERE 1=1"
    args = []
    if q:
        sql += " AND (f.name LIKE ? OR f.serial LIKE ? OR f.hostname LIKE ? OR f.tenant_name LIKE ?)"
        args += [f"%{q}%"] * 4
    if client:
        sql += " AND f.tenant_name=?"
        args.append(client)
    if show == "problems":
        sql += " AND f.enabled=1 AND COALESCE(f.ha_role, '') != 'auxiliary' AND (f.last_status IN ('failed','skipped') OR f.last_status IS NULL)"
    sql += " ORDER BY f.tenant_name COLLATE NOCASE, f.name COLLATE NOCASE"
    rows = db.q(sql, args)
    clients = [r["tenant_name"] for r in db.q("SELECT DISTINCT tenant_name FROM firewalls ORDER BY tenant_name COLLATE NOCASE")]
    defaults = bool((db.get_setting("default_username") and db.get_setting("default_password_enc"))
                    or (config.FW_DEFAULT_USERNAME and config.FW_DEFAULT_PASSWORD))
    flash = request.session.pop("flash", None)
    return render(request, "firewalls.html", rows=rows, clients=clients, q=q, client=client, show=show,
                  defaults=defaults, flash=flash)


@app.get("/firewalls/{fid:path}/edit")
def firewall_page(request: Request, fid: str):
    fw = db.q1("SELECT * FROM firewalls WHERE id=?", (fid,))
    if not fw:
        return HTMLResponse("Not found", status_code=404)
    backups = db.q("SELECT * FROM backups WHERE firewall_id=? ORDER BY taken_at DESC, id DESC", (fid,))
    history = db.q("""SELECT rr.*, r.started_at FROM run_results rr JOIN runs r ON r.id=rr.run_id
                      WHERE rr.firewall_id=? ORDER BY rr.run_id DESC LIMIT 30""", (fid,))
    flash = request.session.pop("flash", None)
    return render(request, "firewall.html", fw=fw, backups=backups, history=history, flash=flash,
                  default_port=config.FW_API_PORT)


@app.post("/firewalls/{fid:path}/edit")
def firewall_save(request: Request, fid: str, host_override: str = Form(""), port: str = Form(""),
                  username: str = Form(""), password: str = Form(""), clear_login: str = Form(""),
                  enabled: str = Form("")):
    fw = db.q1("SELECT * FROM firewalls WHERE id=?", (fid,))
    if not fw:
        return HTMLResponse("Not found", status_code=404)
    pw_enc = fw["password_enc"]
    user = username.strip()
    if clear_login:
        user, pw_enc = "", ""
    elif password:
        pw_enc = crypto.encrypt(password)
    with db.tx() as c:
        c.execute("UPDATE firewalls SET host_override=?, port=?, username=?, password_enc=?, enabled=? WHERE id=?",
                  (host_override.strip(), int(port) if port.strip().isdigit() else None, user, pw_enc,
                   1 if enabled else 0, fid))
    request.session["flash"] = "Saved."
    return RedirectResponse(f"/firewalls/{fid}/edit", status_code=303)


@app.post("/firewalls/{fid:path}/test")
def firewall_test(request: Request, fid: str):
    fw = db.q1("SELECT * FROM firewalls WHERE id=?", (fid,))
    res = job.backup_firewall_api(fw)
    if res["status"] == "ok":
        bid = storage.save_backup(fid, res["xml"], res["source"], res["count"],
                                  note=("manual backup " + res.get("note", "")).strip())
        with db.tx() as c:
            c.execute("UPDATE firewalls SET last_status='ok', last_error='', last_backup_at=? WHERE id=?",
                      (db.now_iso(), fid))
        via = "Sophos Fusion export" if res["source"] == "central" else "the firewall API"
        request.session["flash"] = f"Backup OK via {via}: {res['count']} configuration items saved (backup #{bid})."
    else:
        request.session["flash"] = f"Backup {res['status']}: {res['error']}"
    return RedirectResponse(f"/firewalls/{fid}/edit", status_code=303)


@app.get("/backups/{bid}/download")
def download(bid: int):
    b = storage.get_backup(bid)
    if not b:
        return Response("Not found", status_code=404)
    fw = db.q1("SELECT name FROM firewalls WHERE id=?", (b["firewall_id"],)) or {"name": "firewall"}
    name = f"{fw['name']}_{b['taken_at'][:10]}.xml".replace(" ", "_").replace("/", "_")
    return Response(storage.load_backup_bytes(b), media_type="application/xml",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/diff")
def diff_page(request: Request, a: int, b: int):
    ba, bb = storage.get_backup(a), storage.get_backup(b)
    if not ba or not bb:
        return HTMLResponse("Backup not found", status_code=404)
    if ba["taken_at"] > bb["taken_at"]:
        ba, bb = bb, ba
    ignores = compile_ignores(db.get_setting("ignore_patterns"))
    skip = ignored_types(db.get_setting("ignore_types"))
    changes = diff_configs(storage.load_parsed(ba, ignores, skip), storage.load_parsed(bb, ignores, skip))
    fw = db.q1("SELECT * FROM firewalls WHERE id=?", (bb["firewall_id"],))
    backups = db.q("SELECT id, taken_at, source FROM backups WHERE firewall_id=? ORDER BY taken_at DESC",
                   (bb["firewall_id"],))
    return render(request, "diff.html", a=ba, b=bb, fw=fw, changes=changes, backups=backups)


# -- settings ------------------------------------------------------------------------------
@app.get("/settings")
def settings_page(request: Request):
    s = db.get_settings()
    flash = request.session.pop("flash", None)
    return render(request, "settings.html", s=s, flash=flash, default_types=" ".join(DEFAULT_ENTITY_TYPES),
                  cfg=config, env_default_login=bool(config.FW_DEFAULT_USERNAME))


@app.post("/settings")
def settings_save(request: Request, schedule_time: str = Form("02:00"), timezone: str = Form("America/New_York"),
                  recipients: str = Form(""), send_when_no_changes: str = Form(""),
                  retention_days: str = Form("180"), import_folder: str = Form(""),
                  ignore_patterns: str = Form(""), ignore_types: str = Form(""), entity_types: str = Form(""),
                  default_username: str = Form(""), default_password: str = Form("")):
    vals = {"schedule_time": schedule_time.strip() or "02:00", "timezone": timezone.strip() or "UTC",
            "recipients": recipients.strip(), "send_when_no_changes": "1" if send_when_no_changes else "0",
            "retention_days": retention_days.strip() or "0", "import_folder": import_folder.strip(),
            "ignore_patterns": ignore_patterns.strip(), "ignore_types": " ".join(ignore_types.split()),
            "entity_types": entity_types.strip(),
            "default_username": default_username.strip()}
    if default_password:
        vals["default_password_enc"] = crypto.encrypt(default_password)
    if not vals["default_username"]:
        vals["default_password_enc"] = ""
    try:
        h, m = (int(x) for x in vals["schedule_time"].split(":"))
        CronTrigger(hour=h, minute=m, timezone=vals["timezone"])
    except Exception:
        request.session["flash"] = "Invalid time or time zone - use HH:MM and an IANA zone like America/New_York."
        return RedirectResponse("/settings", status_code=303)
    db.set_settings(vals)
    schedule()
    request.session["flash"] = "Settings saved."
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/test-email")
def test_email(request: Request):
    try:
        last = db.q1("SELECT * FROM runs WHERE status='done' ORDER BY id DESC LIMIT 1")
        if last:
            rep = report.build(last["id"], ["This is a test send of the latest report."])
            report.send("[TEST] " + rep["subject"], rep["html"])
        else:
            report.send("[TEST] Firewall change report", "<p>Test email from the firewall backup app.</p>")
        request.session["flash"] = "Test email sent to " + ", ".join(report.recipients())
    except Exception as e:
        request.session["flash"] = f"Test email failed: {e}"
    return RedirectResponse("/settings", status_code=303)


# -- scheduler ---------------------------------------------------------------------------------
def schedule():
    s = db.get_settings()
    h, m = (int(x) for x in (s.get("schedule_time") or "02:00").split(":"))
    trig = CronTrigger(hour=h, minute=m, timezone=s.get("timezone") or "UTC")
    if scheduler.get_job("nightly"):
        scheduler.reschedule_job("nightly", trigger=trig)
    else:
        scheduler.add_job(job.run, trig, id="nightly", kwargs={"trigger": "schedule"},
                          misfire_grace_time=3600, coalesce=True, max_instances=1)


def next_run_time():
    j = scheduler.get_job("nightly") if scheduler.running else None
    return j.next_run_time.isoformat() if j and j.next_run_time else None


@app.on_event("startup")
def _start():
    db.conn()
    # a run interrupted by a restart
    with db.tx() as c:
        c.execute("UPDATE runs SET status='interrupted', finished_at=? WHERE status='running'", (db.now_iso(),))
    if not scheduler.running:
        scheduler.start()
    schedule()
    log.info("Scheduler started; next run %s", next_run_time())


@app.on_event("shutdown")
def _stop():
    if scheduler.running:
        scheduler.shutdown(wait=False)
