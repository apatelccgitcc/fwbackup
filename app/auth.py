"""User accounts: hashed passwords, authenticator-app codes (TOTP), lockouts and the audit log."""
import base64
import hashlib
import hmac
import io
import logging
import secrets
import struct
import threading
import time
from urllib.parse import quote

from . import config, crypto, db

log = logging.getLogger("fwbackup")

MIN_PASSWORD_LENGTH = 12
MAX_FAILURES = 5              # wrong passwords or codes before a lockout
FAILURE_WINDOW = 15 * 60      # seconds in which failures are counted
LOCKOUT_SECONDS = 15 * 60
TOTP_ISSUER = "Firewall Backups"
TOTP_STEP = 30
clock = time.time             # replaceable in tests


# -- passwords (scrypt, standard library) ------------------------------------------
_N, _R, _P = 2 ** 14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(h).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, h = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                              dklen=len(base64.b64decode(h)))
        return hmac.compare_digest(calc, base64.b64decode(h))
    except Exception:
        return False


_DUMMY_HASH = None


def burn_password_check(password: str):
    """Spend the same time as a real check, so unknown usernames can't be told apart by timing."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_hex(8))
    verify_password(password, _DUMMY_HASH)


def password_problem(password: str, username: str = ""):
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Use at least {MIN_PASSWORD_LENGTH} characters."
    if username and password.lower() == username.lower():
        return "The password can't be the same as the username."
    return None


# -- authenticator codes (RFC 6238 TOTP, standard library) -----------------------------
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def totp_now(secret: str, at=None) -> str:
    return _hotp(secret, int((at or clock()) // TOTP_STEP))


def totp_match(secret: str, code: str, last_counter: int = -1, at=None):
    """Return the matching time step (allowing one step of clock drift either way), or None.
    A step at or before last_counter is refused, so a code can't be used twice."""
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(code) != 6:
        return None
    now = int((at or clock()) // TOTP_STEP)
    for counter in (now - 1, now, now + 1):
        if counter > last_counter and hmac.compare_digest(_hotp(secret, counter), code):
            return counter
    return None


def totp_uri(secret: str, username: str) -> str:
    label = quote(f"{TOTP_ISSUER}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(TOTP_ISSUER)}&digits=6&period={TOTP_STEP}"


def qr_svg(text: str) -> str:
    import qrcode
    import qrcode.image.svg
    img = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=7, border=2)
    buf = io.BytesIO()
    img.save(buf)
    svg = buf.getvalue().decode()
    return svg[svg.index("<svg"):]


# -- users ----------------------------------------------------------------------------
def users_exist() -> bool:
    return bool(db.q1("SELECT 1 FROM users LIMIT 1"))


def get_user(uid):
    return db.q1("SELECT * FROM users WHERE id=?", (uid,)) if uid else None


def find_user(username: str):
    return db.q1("SELECT * FROM users WHERE username=? COLLATE NOCASE", ((username or "").strip(),))


def create_user(username: str, password: str, is_admin=False):
    with db.tx() as c:
        return c.execute("""INSERT INTO users(username, password_hash, is_admin, must_change_password,
                            created_at, session_version) VALUES (?,?,?,?,?,1)""",
                         (username.strip(), hash_password(password), 1 if is_admin else 0, 0,
                          db.now_iso())).lastrowid


def update_user(uid, **fields):
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    with db.tx() as c:
        c.execute(f"UPDATE users SET {cols} WHERE id=?", (*fields.values(), uid))


def bump_sessions(uid):
    """Sign the user out everywhere (sessions carry the version and are checked on every request)."""
    with db.tx() as c:
        c.execute("UPDATE users SET session_version=session_version+1 WHERE id=?", (uid,))


def admin_count(exclude=None):
    r = db.q1("SELECT COUNT(*) AS n FROM users WHERE is_admin=1 AND disabled=0 AND id!=?", (exclude or -1,))
    return r["n"]


def totp_secret(user):
    return crypto.decrypt(user["totp_secret_enc"]) if user.get("totp_secret_enc") else ""


# -- set-password links (invites and resets) ---------------------------------------------
INVITE_HOURS = 48


def _token_hash(token: str) -> str:
    return hashlib.sha256(("fwbackup-invite:" + token).encode()).hexdigest()


def new_invite(uid) -> str:
    """Create a one-time set-password link token for a user (replaces any earlier one)."""
    from datetime import datetime, timedelta, timezone
    token = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(hours=INVITE_HOURS)).replace(microsecond=0).isoformat()
    update_user(uid, invite_hash=_token_hash(token), invite_expires=expires)
    return token


def user_for_invite(token: str):
    if not token:
        return None
    u = db.q1("SELECT * FROM users WHERE invite_hash=?", (_token_hash(token),))
    if not u or u["disabled"] or (u["invite_expires"] or "") < db.now_iso():
        return None
    return u


def invite_link(token: str) -> str:
    return f"{config.APP_BASE_URL}/invite/{token}"


def send_invite(user, token: str, reset=False):
    from . import report
    link = invite_link(token)
    what = "reset your password for" if reset else "set up your account on"
    html = f"""<div style="font-family:-apple-system,Segoe UI,Arial,sans-serif;font-size:14px;color:#1f2937;max-width:520px">
<p>Hi {user['username']},</p>
<p>Use the link below to {what} <strong>Firewall Backups</strong>. You'll choose a password and then set up an
authenticator app (such as Microsoft Authenticator or Google Authenticator) for the sign-in code.</p>
<p><a href="{link}" style="display:inline-block;background:#1d5fbf;color:#fff;padding:9px 16px;border-radius:6px;text-decoration:none">
{'Reset my password' if reset else 'Set my password'}</a></p>
<p style="color:#6b7280;font-size:12px">Your username is <strong>{user['username']}</strong>. The link works once and expires in
{INVITE_HOURS} hours. If you weren't expecting this, you can ignore it.<br>{link}</p></div>"""
    subject = "Reset your Firewall Backups password" if reset else "Your Firewall Backups account"
    report.send(subject, html, to=[user["email"]])


def valid_email(email: str) -> bool:
    import re
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email or ""))


# -- lockouts (in memory; a restart clears them) ---------------------------------------
_failures, _locked_until = {}, {}
_lock = threading.Lock()


def lockout_remaining(*keys):
    now = time.time()
    with _lock:
        rem = 0
        for k in keys:
            until = _locked_until.get(k, 0)
            if until <= now:
                _locked_until.pop(k, None)
            else:
                rem = max(rem, int(until - now) + 1)
        return rem


def record_failure(*keys):
    """Count a failure against each key (ip:..., user:...). Returns True if any key is now locked."""
    now, locked = time.time(), False
    with _lock:
        for k in keys:
            recent = [t for t in _failures.get(k, []) if now - t < FAILURE_WINDOW] + [now]
            if len(recent) >= MAX_FAILURES:
                _locked_until[k] = now + LOCKOUT_SECONDS
                _failures.pop(k, None)
                locked = True
            else:
                _failures[k] = recent
    return locked


def clear_failures(*keys):
    with _lock:
        for k in keys:
            _failures.pop(k, None)


def reset_lockouts():
    with _lock:
        _failures.clear()
        _locked_until.clear()


def locked_message(seconds):
    mins = max(1, (seconds + 59) // 60)
    return f"Too many failed attempts. Try again in {mins} minute{'s' if mins != 1 else ''}."


# -- audit log -------------------------------------------------------------------------
def audit(event: str, username: str = "", ip: str = "", detail: str = ""):
    log.info("audit %s user=%s ip=%s %s", event, username or "-", ip or "-", detail)
    try:
        with db.tx() as c:
            c.execute("INSERT INTO audit_log(at, username, ip, event, detail) VALUES (?,?,?,?,?)",
                      (db.now_iso(), username or "", ip or "", event, (detail or "")[:500]))
    except Exception:
        log.exception("Couldn't write the audit log")


def prune_audit(days=365):
    with db.tx() as c:
        c.execute("DELETE FROM audit_log WHERE at < datetime('now', ?)", (f"-{int(days)} days",))


def emergency_login_allowed() -> bool:
    """The ADMIN_PASSWORD login: only before the first account exists, or if explicitly turned back on."""
    if not (config.ADMIN_PASSWORD and config.APP_SECRET_KEY):
        return False
    return not users_exist() or config.ALLOW_ADMIN_PASSWORD_LOGIN
