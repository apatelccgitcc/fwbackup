"""Web UI + scheduler."""
import hmac
import json
import logging
import time
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from . import auth, config, crypto, db, job, report, storage
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
    ctx.update(request=request, user=current_user(request), progress=job.progress, central_ok=config.central_configured(),
               email_ok=config.email_configured(), next_run=next_run_time(), path=request.url.path)
    return HTMLResponse(tpl.get_template(name).render(**ctx))


# -- auth --------------------------------------------------------------------------
PUBLIC = ("/login", "/static", "/healthz", "/setup", "/invite/")
ADMIN_ONLY = ("/settings", "/users", "/audit")
PENDING_SECONDS = 5 * 60        # time allowed between the password and the authenticator code
FAIL_DELAY = 1.0                # seconds added to every failed attempt to slow down guessing


def client_ip(request):
    return request.client.host if request.client else "unknown"


def current_user(request):
    return getattr(request.state, "user", None)


def actor(request):
    u = current_user(request)
    return u["username"] if u else ""


def _start_session(request, user):
    request.session.clear()
    request.session.update(uid=user["id"], sv=user["session_version"], at=int(time.time()))


@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    if path.startswith(PUBLIC):
        return await call_next(request)
    sess = request.session
    now = int(time.time())
    if sess.get("setup"):
        return RedirectResponse("/setup" if not auth.users_exist() else "/logout", status_code=303)
    user = None
    if sess.get("emergency") and auth.emergency_login_allowed():
        user = {"id": None, "username": "(emergency admin)", "is_admin": 1, "totp_enabled": 1,
                "must_change_password": 0}
    elif sess.get("uid"):
        u = auth.get_user(sess["uid"])
        if u and not u["disabled"] and u["session_version"] == sess.get("sv"):
            user = u
    if user is None:
        for k in ("uid", "sv", "emergency", "at"):   # keep a sign-in that's waiting for its code
            sess.pop(k, None)
        return RedirectResponse("/login", status_code=303)
    if now - int(sess.get("at", 0)) > config.SESSION_IDLE_MINUTES * 60:
        sess.clear()
        sess["flash"] = "You were signed out after a period of inactivity."
        return RedirectResponse("/login", status_code=303)
    sess["at"] = now
    request.state.user = user
    # first sign-in: set a new password, then set up the authenticator app, before anything else
    if path != "/logout":
        if user["must_change_password"] and path != "/account/password":
            return RedirectResponse("/account/password", status_code=303)
        if not user["must_change_password"] and not user["totp_enabled"] and not path.startswith("/account/2fa"):
            return RedirectResponse("/account/2fa", status_code=303)
    if path.startswith(ADMIN_ONLY) and not user["is_admin"]:
        return HTMLResponse("Only admins can open this page.", status_code=403)
    return await call_next(request)


# added after require_login so it wraps it (outermost) and the session is available there
app.add_middleware(SessionMiddleware, secret_key=config.APP_SECRET_KEY or "unset-secret",
                   same_site="lax", https_only=config.APP_BASE_URL.startswith("https"), max_age=12 * 3600)


@app.get("/healthz")
def healthz():
    return {"ok": True}


def _login_page(request, error=None, step="password", status_code=200, emergency=False):
    configured = bool(config.APP_SECRET_KEY)
    first_run = configured and not auth.users_exist()
    html = render(request, "login.html", error=error, step=step, configured=configured,
                  first_run=first_run, emergency=emergency, admin_pw_set=bool(config.ADMIN_PASSWORD),
                  emergency_allowed=auth.users_exist() and auth.emergency_login_allowed(),
                  flash=request.session.pop("flash", None))
    html.status_code = status_code
    return html


@app.get("/login")
def login_page(request: Request, emergency: int = 0):
    if request.session.get("pending_uid") and not emergency:
        return _login_page(request, step="code")
    return _login_page(request, emergency=bool(emergency))


def _fail(request, keys, event, username, detail, step="password", emergency=False):
    time.sleep(FAIL_DELAY)
    ip = client_ip(request)
    auth.audit(event, username, ip, detail)
    if auth.record_failure(*keys):
        auth.audit("locked_out", username, ip, f"after {auth.MAX_FAILURES} failed attempts")
        if step == "code":
            request.session.clear()
        return _login_page(request, auth.locked_message(auth.LOCKOUT_SECONDS), status_code=429, emergency=emergency)
    msg = "Wrong code. Check your authenticator app and try again." if step == "code" else (
        "Wrong password." if emergency else "Wrong username or password.")
    return _login_page(request, msg, step=step, status_code=401, emergency=emergency)


@app.post("/login")
def login(request: Request, username: str = Form(""), password: str = Form(""), mode: str = Form("")):
    ip = client_ip(request)
    # the ADMIN_PASSWORD from .env: creates the first account, or (if turned on) an emergency sign-in
    if mode == "admin" and auth.emergency_login_allowed():
        keys = (f"ip:{ip}", "user:(admin password)")
        rem = auth.lockout_remaining(*keys)
        if rem:
            return _login_page(request, auth.locked_message(rem), status_code=429, emergency=True)
        if not hmac.compare_digest(password.encode(), config.ADMIN_PASSWORD.encode()):
            return _fail(request, keys, "login_failed", "(admin password)", "wrong admin password", emergency=True)
        auth.clear_failures(*keys)
        request.session.clear()
        if not auth.users_exist():
            request.session.update(setup=True, at=int(time.time()))
            auth.audit("setup_started", "(admin password)", ip)
            return RedirectResponse("/setup", status_code=303)
        request.session.update(emergency=True, at=int(time.time()))
        auth.audit("emergency_login", "(admin password)", ip, "signed in with ADMIN_PASSWORD")
        return RedirectResponse("/users", status_code=303)

    uname = username.strip()
    keys = (f"ip:{ip}", f"user:{uname.lower()}")
    rem = auth.lockout_remaining(*keys)
    if rem:
        auth.audit("login_refused", uname, ip, "locked out")
        return _login_page(request, auth.locked_message(rem), status_code=429)
    user = auth.find_user(uname)
    if not user:
        auth.burn_password_check(password)
        return _fail(request, keys, "login_failed", uname, "unknown username")
    if not auth.verify_password(password, user["password_hash"]):
        return _fail(request, keys, "login_failed", user["username"], "wrong password")
    if user["disabled"]:
        return _fail(request, keys, "login_failed", user["username"], "account disabled")
    if user["totp_enabled"]:
        request.session.clear()
        request.session.update(pending_uid=user["id"], pending_sv=user["session_version"],
                               pending_at=int(time.time()))
        return RedirectResponse("/login", status_code=303)
    # no authenticator yet (new account): signed in, then sent straight to set one up
    auth.clear_failures(*keys)
    auth.update_user(user["id"], last_login_at=db.now_iso(), last_login_ip=ip)
    auth.audit("login_ok", user["username"], ip, "password only - authenticator setup required")
    _start_session(request, user)
    return RedirectResponse("/", status_code=303)


@app.post("/login/code")
def login_code(request: Request, code: str = Form("")):
    ip = client_ip(request)
    sess = request.session
    user = auth.get_user(sess.get("pending_uid"))
    if (not user or user["disabled"] or user["session_version"] != sess.get("pending_sv")
            or time.time() - sess.get("pending_at", 0) > PENDING_SECONDS):
        sess.clear()
        sess["flash"] = "That took too long. Sign in again."
        return RedirectResponse("/login", status_code=303)
    keys = (f"ip:{ip}", f"user:{user['username'].lower()}")
    rem = auth.lockout_remaining(*keys)
    if rem:
        sess.clear()
        return _login_page(request, auth.locked_message(rem), status_code=429)
    counter = auth.totp_match(auth.totp_secret(user), code, user["totp_last_counter"])
    if counter is None:
        return _fail(request, keys, "code_failed", user["username"], "wrong or reused authenticator code", step="code")
    auth.clear_failures(*keys)
    auth.update_user(user["id"], totp_last_counter=counter, last_login_at=db.now_iso(), last_login_ip=ip)
    auth.audit("login_ok", user["username"], ip)
    _start_session(request, auth.get_user(user["id"]))
    return RedirectResponse("/", status_code=303)


@app.get("/logout")
def logout(request: Request):
    who = request.session.get("uid")
    u = auth.get_user(who) if who else None
    if u or request.session.get("emergency"):
        auth.audit("logout", u["username"] if u else "(emergency admin)", client_ip(request))
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# -- first account -----------------------------------------------------------------------
@app.get("/setup")
def setup_page(request: Request):
    if not request.session.get("setup") or auth.users_exist():
        return RedirectResponse("/login", status_code=303)
    return render(request, "setup.html", error=None, username="")


@app.post("/setup")
def setup_save(request: Request, username: str = Form(""), password: str = Form(""), confirm: str = Form("")):
    if not request.session.get("setup") or auth.users_exist():
        return RedirectResponse("/login", status_code=303)
    uname = username.strip()
    err = None
    if not uname or len(uname) > 64 or any(ch.isspace() for ch in uname):
        err = "Choose a username without spaces."
    elif password != confirm:
        err = "The passwords don't match."
    else:
        err = auth.password_problem(password, uname)
    if err:
        return render(request, "setup.html", error=err, username=uname)
    uid = auth.create_user(uname, password, is_admin=True)
    auth.update_user(uid, last_login_at=db.now_iso(), last_login_ip=client_ip(request))
    auth.audit("user_created", uname, client_ip(request), "first admin account")
    _start_session(request, auth.get_user(uid))
    return RedirectResponse("/account/2fa", status_code=303)


# -- set-password links ------------------------------------------------------------------
@app.get("/invite/{token}")
def invite_page(request: Request, token: str):
    u = auth.user_for_invite(token)
    return render(request, "invite.html", invitee=u, error=None, token=token)


@app.post("/invite/{token}")
def invite_save(request: Request, token: str, password: str = Form(""), confirm: str = Form("")):
    ip = client_ip(request)
    rem = auth.lockout_remaining(f"ip:{ip}")
    u = auth.user_for_invite(token)
    if rem or not u:
        if not u:
            auth.record_failure(f"ip:{ip}")
        return render(request, "invite.html", invitee=None, error=None, token=token)
    err = "The passwords don't match." if password != confirm else auth.password_problem(password, u["username"])
    if err:
        return render(request, "invite.html", invitee=u, error=err, token=token)
    auth.update_user(u["id"], password_hash=auth.hash_password(password), must_change_password=0,
                     invite_hash=None, invite_expires=None)
    auth.bump_sessions(u["id"])
    auth.audit("password_set_from_link", u["username"], ip)
    request.session.clear()
    request.session["flash"] = ("Password set. Sign in to continue." if u["totp_enabled"]
                                else "Password set. Sign in, then set up your authenticator app.")
    return RedirectResponse("/login", status_code=303)


# -- your account --------------------------------------------------------------------------
@app.get("/account")
def account_page(request: Request):
    return render(request, "account.html", flash=request.session.pop("flash", None), error=None)


@app.get("/account/password")
def password_page(request: Request):
    return render(request, "password.html", error=None)


@app.post("/account/password")
def password_save(request: Request, current: str = Form(""), password: str = Form(""), confirm: str = Form("")):
    user = current_user(request)
    if not user.get("id"):
        return RedirectResponse("/users", status_code=303)
    ip = client_ip(request)
    err = None
    if not auth.verify_password(current, user["password_hash"]):
        err = "Your current password is wrong."
        auth.audit("password_change_failed", user["username"], ip, "wrong current password")
    elif password != confirm:
        err = "The new passwords don't match."
    elif password == current:
        err = "Choose a different password from the current one."
    else:
        err = auth.password_problem(password, user["username"])
    if err:
        return render(request, "password.html", error=err)
    auth.update_user(user["id"], password_hash=auth.hash_password(password), must_change_password=0)
    auth.bump_sessions(user["id"])          # signs out every other session
    auth.audit("password_changed", user["username"], ip)
    _start_session(request, auth.get_user(user["id"]))
    request.session["flash"] = "Password changed. Any other sessions were signed out."
    return RedirectResponse("/account" if user["totp_enabled"] else "/account/2fa", status_code=303)


@app.get("/account/2fa")
def twofa_page(request: Request):
    user = current_user(request)
    if user["totp_enabled"] or not user.get("id"):
        return RedirectResponse("/account", status_code=303)
    secret = request.session.get("new_totp") or auth.new_totp_secret()
    request.session["new_totp"] = secret
    uri = auth.totp_uri(secret, user["username"])
    return render(request, "twofa.html", secret=" ".join(secret[i:i + 4] for i in range(0, len(secret), 4)),
                  qr=auth.qr_svg(uri), error=None, flash=request.session.pop("flash", None))


@app.post("/account/2fa")
def twofa_save(request: Request, code: str = Form("")):
    user = current_user(request)
    secret = request.session.get("new_totp")
    if user["totp_enabled"] or not user.get("id") or not secret:
        return RedirectResponse("/account", status_code=303)
    counter = auth.totp_match(secret, code)
    if counter is None:
        auth.audit("2fa_setup_failed", user["username"], client_ip(request), "wrong code")
        return render(request, "twofa.html", secret=" ".join(secret[i:i + 4] for i in range(0, len(secret), 4)),
                      qr=auth.qr_svg(auth.totp_uri(secret, user["username"])), flash=None,
                      error="That code didn't match. Check the time on your phone is set automatically, then try the newest code.")
    auth.update_user(user["id"], totp_secret_enc=crypto.encrypt(secret), totp_enabled=1, totp_last_counter=counter)
    request.session.pop("new_totp", None)
    auth.audit("2fa_enabled", user["username"], client_ip(request))
    request.session["flash"] = "Authenticator app set up. You'll be asked for a code each time you sign in."
    return RedirectResponse("/", status_code=303)


# -- users (admins) -------------------------------------------------------------------------
@app.get("/users")
def users_page(request: Request):
    users = db.q("SELECT * FROM users ORDER BY username COLLATE NOCASE")
    local = any(h in config.APP_BASE_URL for h in ("localhost", "127.0.0.1"))
    return render(request, "users.html", users=users, flash=request.session.pop("flash", None),
                  min_len=auth.MIN_PASSWORD_LENGTH, invite_hours=auth.INVITE_HOURS, base_url_local=local)


def _email_link(request, user, reset=False):
    """Email a set-password link; if sending fails, show the link so the admin can pass it on."""
    token = auth.new_invite(user["id"])
    user = auth.get_user(user["id"])
    try:
        auth.send_invite(user, token, reset=reset)
        auth.audit("invite_sent" if not reset else "reset_link_sent", actor(request), client_ip(request),
                   f"{user['username']} <{user['email']}>")
        return f"Emailed a set-password link to {user['email']}. It expires in {auth.INVITE_HOURS} hours."
    except Exception as e:
        auth.audit("invite_email_failed", actor(request), client_ip(request), f"{user['username']}: {e}")
        return (f"Couldn't send the email ({e}). Send {user['username']} this link yourself instead "
                f"(it works once and expires in {auth.INVITE_HOURS} hours): {auth.invite_link(token)}")


@app.post("/users/new")
def users_new(request: Request, username: str = Form(""), email: str = Form(""), password: str = Form(""),
              is_admin: str = Form("")):
    uname, email = username.strip(), email.strip()
    if not uname or len(uname) > 64 or any(ch.isspace() for ch in uname):
        request.session["flash"] = "Choose a username without spaces."
    elif auth.find_user(uname):
        request.session["flash"] = f"There's already a user called {uname}."
    elif email and not auth.valid_email(email):
        request.session["flash"] = "That email address doesn't look right."
    elif not email and not password:
        request.session["flash"] = "Enter an email address to send an invite, or a temporary password."
    elif password and auth.password_problem(password, uname):
        request.session["flash"] = auth.password_problem(password, uname)
    else:
        # with no temporary password the account has an unusable random one until the invite is used
        uid = auth.create_user(uname, password or auth.secrets.token_urlsafe(32), is_admin=bool(is_admin))
        auth.update_user(uid, email=email or None, must_change_password=1 if password else 0)
        auth.audit("user_created", actor(request), client_ip(request),
                   f"{uname}{' (admin)' if is_admin else ''}{' <' + email + '>' if email else ''}")
        if password:
            request.session["flash"] = (f"Created {uname}. Give them the temporary password; they'll choose their "
                                        "own and set up an authenticator app when they first sign in.")
        else:
            request.session["flash"] = f"Created {uname}. " + _email_link(request, auth.get_user(uid))
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{uid}/action")
def users_action(request: Request, uid: int, action: str = Form(""), password: str = Form(""),
                 email: str = Form("")):
    me = current_user(request)
    target = auth.get_user(uid)
    if not target:
        return RedirectResponse("/users", status_code=303)
    name, ip = target["username"], client_ip(request)
    self_action = me.get("id") == uid
    removes_admin = action in ("disable", "delete", "remove_admin") and target["is_admin"] and not target["disabled"]
    msg = None
    if self_action and action in ("disable", "delete", "remove_admin"):
        msg = "You can't do that to your own account."
    elif removes_admin and auth.admin_count(exclude=uid) == 0:
        msg = "Keep at least one active admin."
    elif action == "disable":
        auth.update_user(uid, disabled=1)
        auth.bump_sessions(uid)
        msg = f"Disabled {name} and signed them out."
    elif action == "enable":
        auth.update_user(uid, disabled=0)
        msg = f"Enabled {name}."
    elif action == "reset_2fa":
        auth.update_user(uid, totp_secret_enc=None, totp_enabled=0, totp_last_counter=-1)
        auth.bump_sessions(uid)
        msg = f"Reset {name}'s authenticator. They'll set up a new one at their next sign-in."
    elif action == "reset_password":
        problem = auth.password_problem(password, name)
        if problem:
            msg = problem
        else:
            auth.update_user(uid, password_hash=auth.hash_password(password), must_change_password=1)
            auth.bump_sessions(uid)
            msg = f"Set a temporary password for {name}. They'll choose a new one at their next sign-in."
    elif action == "send_link":
        email = email.strip() or (target["email"] or "")
        if not auth.valid_email(email):
            msg = "Enter an email address for this user."
        else:
            if email != (target["email"] or ""):
                auth.update_user(uid, email=email)
                auth.audit("user_email_changed", actor(request), ip, f"{name} <{email}>")
            msg = _email_link(request, auth.get_user(uid), reset=bool(target["last_login_at"]))
            request.session["flash"] = msg
            return RedirectResponse("/users", status_code=303)
    elif action == "make_admin":
        auth.update_user(uid, is_admin=1)
        msg = f"{name} is now an admin."
    elif action == "remove_admin":
        auth.update_user(uid, is_admin=0)
        msg = f"{name} is no longer an admin."
    elif action == "delete":
        with db.tx() as c:
            c.execute("DELETE FROM users WHERE id=?", (uid,))
        msg = f"Deleted {name}."
    else:
        msg = "Unknown action."
    if msg and not msg.startswith(("You can't", "Keep at least", "Unknown", "Use at least", "The password",
                                   "Enter an email")):
        auth.audit(f"user_{action}", actor(request), ip, name)
    if self_action and action in ("reset_2fa", "reset_password"):
        return RedirectResponse("/login", status_code=303)
    request.session["flash"] = msg
    return RedirectResponse("/users", status_code=303)


@app.get("/audit")
def audit_page(request: Request, q: str = ""):
    sql, args = "SELECT * FROM audit_log", []
    if q:
        sql += " WHERE username LIKE ? OR ip LIKE ? OR event LIKE ? OR detail LIKE ?"
        args = [f"%{q}%"] * 4
    rows = db.q(sql + " ORDER BY id DESC LIMIT 500", args)
    return render(request, "audit.html", rows=rows, q=q)


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
    return render(request, "dashboard.html", runs=runs, last=last, changed=changed, counts=counts,
                  flash=request.session.pop("flash", None))


@app.post("/run")
def run_now(request: Request):
    if job.run_in_background("manual"):
        auth.audit("run_started", actor(request), client_ip(request), "manual backup & report")
    return RedirectResponse("/", status_code=303)


@app.get("/status")
def status():
    return JSONResponse({k: job.progress[k] for k in ("running", "message", "run_id")})


@app.post("/sync")
def sync(request: Request):
    auth.audit("firewalls_synced", actor(request), client_ip(request))
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
    if not current_user(request)["is_admin"]:
        return HTMLResponse("Only admins can change firewall settings.", status_code=403)
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
    auth.audit("firewall_edited", actor(request), client_ip(request), fw["name"])
    request.session["flash"] = "Saved."
    return RedirectResponse(f"/firewalls/{fid}/edit", status_code=303)


@app.post("/firewalls/{fid:path}/test")
def firewall_test(request: Request, fid: str):
    fw = db.q1("SELECT * FROM firewalls WHERE id=?", (fid,))
    if not fw:
        return RedirectResponse("/firewalls", status_code=303)
    auth.audit("backup_now", actor(request), client_ip(request), fw["name"])
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
def download(request: Request, bid: int):
    b = storage.get_backup(bid)
    if not b:
        return Response("Not found", status_code=404)
    fw = db.q1("SELECT name FROM firewalls WHERE id=?", (b["firewall_id"],)) or {"name": "firewall"}
    auth.audit("backup_downloaded", actor(request), client_ip(request), f"{fw['name']} backup #{bid}")
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
    old = db.get_settings()
    db.set_settings(vals)
    changed = sorted(k for k, v in vals.items() if old.get(k, "") != v)
    auth.audit("settings_changed", actor(request), client_ip(request),
               ", ".join("default firewall password" if k == "default_password_enc" else k for k in changed)
               or "no changes")
    schedule()
    request.session["flash"] = "Settings saved."
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/test-email")
def test_email(request: Request):
    auth.audit("test_email", actor(request), client_ip(request))
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
