"""Sign-in tests: first admin, authenticator codes, lockouts, roles, user management and the audit log.

Run:  python -m tests.test_auth
"""
import os
import re
import tempfile
import time
from pathlib import Path

TMP = Path(tempfile.mkdtemp(prefix="fwbackup-auth-"))
os.environ.update(DATA_DIR=str(TMP / "data"), APP_SECRET_KEY="test-secret", ADMIN_PASSWORD="first-run-pw",
                  SOPHOS_CLIENT_ID="", SOPHOS_CLIENT_SECRET="")

from fastapi.testclient import TestClient  # noqa: E402

from app import auth, config, db, web  # noqa: E402

web.FAIL_DELAY = 0
NOW = [time.time()]
auth.clock = lambda: NOW[0]


def tick():
    """Move the authenticator clock to the next 30-second step."""
    NOW[0] += auth.TOTP_STEP


def code_for(secret):
    return auth.totp_now(secret)


def secret_from(page):
    m = re.search(r'<div class="mono"[^>]*>([A-Z2-7 ]+)</div>', page)
    return m.group(1).replace(" ", "")


def client():
    return TestClient(web.app, follow_redirects=False)


def check(cond, msg):
    assert cond, msg
    print("ok -", msg)


def main():
    # RFC 6238 test vector (SHA-1, T=59s -> 94287082, last 6 digits)
    check(auth.totp_now("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", at=59) == "287082", "TOTP matches RFC 6238")
    h = auth.hash_password("correct horse battery")
    check(auth.verify_password("correct horse battery", h) and not auth.verify_password("nope", h),
          "password hashing verifies")

    c = client()
    check(c.get("/").headers["location"] == "/login", "signed-out visit goes to /login")
    check("ADMIN_PASSWORD" in c.get("/login").text, "first run asks for ADMIN_PASSWORD")
    check(c.post("/login", data={"mode": "admin", "password": "bad"}).status_code == 401, "wrong admin password refused")
    r = c.post("/login", data={"mode": "admin", "password": "first-run-pw"})
    check(r.headers["location"] == "/setup", "ADMIN_PASSWORD leads to account setup")
    check(c.get("/").headers["location"] == "/setup", "setup session can't reach the app")
    check("at least 12" in c.post("/setup", data={"username": "andy", "password": "short", "confirm": "short"}).text,
          "short password rejected")
    r = c.post("/setup", data={"username": "andy", "password": "a-long-admin-pass", "confirm": "a-long-admin-pass"})
    check(r.headers["location"] == "/account/2fa", "first admin created, sent to authenticator setup")
    check(c.get("/").headers["location"] == "/account/2fa", "app is blocked until the authenticator is set up")
    page = c.get("/account/2fa").text
    check("<svg" in page, "QR code shown")
    secret = secret_from(page)
    check(c.post("/account/2fa", data={"code": "000000"}).status_code == 200, "wrong setup code refused")
    check(c.post("/account/2fa", data={"code": code_for(secret)}).headers["location"] == "/", "authenticator turned on")
    check(c.get("/").status_code == 200, "dashboard opens")

    # ADMIN_PASSWORD no longer works once an account exists
    c2 = client()
    c2.post("/login", data={"mode": "admin", "password": "first-run-pw"})
    check(c2.get("/").headers["location"] == "/login", "ADMIN_PASSWORD refused once accounts exist")

    # normal sign-in: password, then code; a code can't be reused
    c.get("/logout")
    tick()
    r = c.post("/login", data={"username": "ANDY", "password": "a-long-admin-pass"})
    check(r.headers["location"] == "/login" and "Authenticator code" in c.get("/login").text,
          "password accepted (username not case-sensitive), code requested")
    check(c.get("/").headers["location"] == "/login", "no access between password and code")
    check(c.post("/login/code", data={"code": "123456"}).status_code == 401, "wrong code refused")
    good = code_for(secret)
    check(c.post("/login/code", data={"code": good}).headers["location"] == "/", "right code signs in")
    c.get("/logout")
    c.post("/login", data={"username": "andy", "password": "a-long-admin-pass"})
    check(c.post("/login/code", data={"code": good}).status_code == 401, "same code can't be used twice")
    tick()
    check(c.post("/login/code", data={"code": code_for(secret)}).headers["location"] == "/", "next code works")

    # admin adds a regular user
    r = c.post("/users/new", data={"username": "bob", "password": "temporary-pass-1"})
    check(auth.find_user("bob")["must_change_password"] == 1, "new user created with a temporary password")
    b = client()
    b.post("/login", data={"username": "bob", "password": "temporary-pass-1"})
    check(b.get("/").headers["location"] == "/account/password", "new user must choose a password first")
    r = b.post("/account/password", data={"current": "temporary-pass-1", "password": "bobs-own-password",
                                          "confirm": "bobs-own-password"})
    check(r.headers["location"] == "/account/2fa", "then set up an authenticator")
    bsecret = secret_from(b.get("/account/2fa").text)
    b.post("/account/2fa", data={"code": code_for(bsecret)})
    check(b.get("/").status_code == 200, "regular user can use the dashboard")
    check(b.get("/settings").status_code == 403 and b.get("/users").status_code == 403
          and b.get("/audit").status_code == 403, "regular user can't open Settings, Users or Audit log")
    check(b.post("/firewalls/x/edit", data={}).status_code == 403, "regular user can't change firewall logins")
    check("Users" not in b.get("/").text.split("</nav>")[0], "admin links hidden for regular users")

    # disabling signs them out
    bob = auth.find_user("bob")
    c.post(f"/users/{bob['id']}/action", data={"action": "disable"})
    check(b.get("/").headers["location"] == "/login", "disabled user is signed out")
    tick()
    b.post("/login", data={"username": "bob", "password": "bobs-own-password"})
    check(b.get("/").headers["location"] == "/login", "disabled user can't sign in")
    c.post(f"/users/{bob['id']}/action", data={"action": "enable"})

    # admin can't remove their own admin rights or the last admin
    me = auth.find_user("andy")
    c.post(f"/users/{me['id']}/action", data={"action": "remove_admin"})
    check(auth.find_user("andy")["is_admin"] == 1, "can't remove your own admin rights")

    # reset authenticator: next sign-in asks to set one up again
    c.post(f"/users/{bob['id']}/action", data={"action": "reset_2fa"})
    b = client()
    auth.reset_lockouts()
    b.post("/login", data={"username": "bob", "password": "bobs-own-password"})
    check(b.get("/").headers["location"] == "/account/2fa", "after a reset the user sets up a new authenticator")

    # lockout: 5 wrong passwords, then even the right one is refused
    auth.reset_lockouts()
    x = client()
    for _ in range(auth.MAX_FAILURES):
        r = x.post("/login", data={"username": "andy", "password": "wrong-password"})
    check(r.status_code == 429, "locked out after 5 wrong passwords")
    r = x.post("/login", data={"username": "andy", "password": "a-long-admin-pass"})
    check(r.status_code == 429, "right password refused while locked")
    auth.reset_lockouts()

    # lockout also applies to wrong codes
    y = client()
    for _ in range(auth.MAX_FAILURES):
        y.post("/login", data={"username": "andy", "password": "a-long-admin-pass"})
        r = y.post("/login/code", data={"code": "000000"})
    check(r.status_code == 429, "locked out after 5 wrong codes")
    auth.reset_lockouts()

    # invite by email: the user sets their own password from a one-time link
    from app import report
    sent = []
    report.send = lambda subject, html, to=None: sent.append((subject, html, to))
    c.post("/users/new", data={"username": "carol", "email": "carol@example.com"})
    check(sent and sent[-1][2] == ["carol@example.com"], "invite emailed to the new user")
    link = re.search(r'href="(http[^"]+/invite/[^"]+)"', sent[-1][1]).group(1)
    path = link.split("8080", 1)[-1] if "8080" in link else "/invite/" + link.rsplit("/invite/", 1)[1]
    z = client()
    check(z.post("/login", data={"username": "carol", "password": "anything-at-all"}).status_code == 401,
          "invited user can't sign in before setting a password")
    check("Choose a password for" in z.get(path).text, "invite link opens the set-password page")
    check("at least 12" in z.post(path, data={"password": "short", "confirm": "short"}).text,
          "invite page enforces the password rules")
    r = z.post(path, data={"password": "carols-own-password", "confirm": "carols-own-password"})
    check(r.headers["location"] == "/login", "password set from the link")
    check("expired or has already been used" in z.get(path).text, "the link only works once")
    z.post("/login", data={"username": "carol", "password": "carols-own-password"})
    check(z.get("/").headers["location"] == "/account/2fa", "then signs in and sets up an authenticator")
    check(auth.find_user("carol")["must_change_password"] == 0, "no second password change needed")
    check("expired or has already been used" in client().get("/invite/not-a-real-token").text,
          "made-up links are refused")

    # an expired link is refused
    carol = auth.find_user("carol")
    c.post(f"/users/{carol['id']}/action", data={"action": "send_link"})
    check(sent[-1][0].startswith("Reset"), "existing user gets a reset email")
    link2 = "/invite/" + re.search(r'/invite/([^"]+)"', sent[-1][1]).group(1)
    auth.update_user(carol["id"], invite_expires="2000-01-01T00:00:00+00:00")
    check("expired" in client().get(link2).text, "expired link refused")

    # if email can't be sent, the admin gets the link to pass on
    def boom(*a, **k):
        raise RuntimeError("SMTP down")
    report.send = boom
    c.post("/users/new", data={"username": "dave", "email": "dave@example.com"})
    flash = c.get("/users").text
    check("SMTP down" in flash and "/invite/" in flash, "failed email shows the link to the admin instead")
    check("at least 12" not in c.post("/users/new", data={"username": "erin", "email": "not-an-email"}).text
          and auth.find_user("erin") is None, "bad email address rejected")

    # idle timeout
    config.SESSION_IDLE_MINUTES = -1
    check(c.get("/").headers["location"] == "/login", "signed out after inactivity")
    config.SESSION_IDLE_MINUTES = 60

    # emergency sign-in, only when turned on
    config.ALLOW_ADMIN_PASSWORD_LOGIN = True
    e = client()
    r = e.post("/login", data={"mode": "admin", "password": "first-run-pw"})
    check(r.headers["location"] == "/users" and e.get("/users").status_code == 200,
          "emergency sign-in works when ALLOW_ADMIN_PASSWORD_LOGIN is on")
    config.ALLOW_ADMIN_PASSWORD_LOGIN = False
    check(e.get("/users").headers["location"] == "/login", "and stops working when it's turned off")

    events = {r["event"] for r in db.q("SELECT event FROM audit_log")}
    need = {"setup_started", "user_created", "2fa_enabled", "login_ok", "login_failed", "code_failed",
            "locked_out", "user_disable", "user_reset_2fa", "password_changed", "emergency_login", "logout",
            "invite_sent", "reset_link_sent", "password_set_from_link", "invite_email_failed"}
    check(need <= events, f"audit log records sign-ins and changes (missing: {sorted(need - events)})")
    print("All sign-in tests passed. Data dir:", TMP)


if __name__ == "__main__":
    main()
