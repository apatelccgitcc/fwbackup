"""Build the change report (email-safe HTML) and send it."""
import json
import smtplib
from collections import OrderedDict
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from zoneinfo import ZoneInfo

import httpx
from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import config, db

TEMPLATES = Path(__file__).parent / "templates"
env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html"]),
                  finalize=lambda v: "" if v is None else v)

POLICY_CONTAINERS = ("NetworkPolicy", "UserPolicy", "HTTPBasedPolicy")
PLURAL_PARENTS = {"Zone": "Zones", "Service": "Services", "Network": "Networks", "Interface": "Interface",
                  "Host": "Host", "Category": "Category", "User": "Users", "Group": "Groups"}


def field_label(path):
    segs = path.split("/")
    if segs and segs[0] in POLICY_CONTAINERS:
        segs = segs[1:]
    if len(segs) >= 2 and any(segs[-2].endswith(p) for k, p in PLURAL_PARENTS.items() if segs[-1] == k):
        segs = segs[:-1]
    return " › ".join(s.replace("@", "") for s in segs) or path


env.filters["field_label"] = field_label


def backup_method(fw):
    """How the nightly run will back this firewall up (for display)."""
    from .sophos_central import supports_central_export
    if fw.get("ha_role") == "auxiliary":
        return ("aux", "Skipped (HA auxiliary)")
    has_login = bool(fw.get("username") or db.get_setting("default_username") or config.FW_DEFAULT_USERNAME)
    if fw.get("in_central") and supports_central_export(fw.get("firmware")) is not False:
        return ("central", "Fusion export" + (" (API fallback)" if has_login else ""))
    if has_login:
        return ("api", "Firewall API")
    if not fw.get("in_central"):
        return ("import", "Import folder")
    return ("none", "Needs SFOS 22.0 MR2+")


env.globals["backup_method"] = backup_method


def local_time(iso, tzname=None, fmt="%b %d, %Y %I:%M %p"):
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(iso)
        return dt.astimezone(ZoneInfo(tzname or db.get_setting("timezone") or "UTC")).strftime(fmt)
    except Exception:
        return iso


env.filters["local_time"] = local_time


def build(run_id, notes=None):
    run = db.q1("SELECT * FROM runs WHERE id=?", (run_id,))
    rows = db.q("""SELECT rr.*, f.name, f.tenant_name, f.serial, f.model, f.firmware, f.hostname
                   FROM run_results rr LEFT JOIN firewalls f ON f.id = rr.firewall_id
                   WHERE rr.run_id=? ORDER BY f.tenant_name COLLATE NOCASE, f.name COLLATE NOCASE""", (run_id,))
    # firewalls that are enabled but produced nothing at all this run
    for r in rows:
        r["changes"] = json.loads(r["changes_json"] or "[]")
    changed = [r for r in rows if r["change_count"]]
    clients = OrderedDict()
    for r in changed:
        clients.setdefault(r["tenant_name"] or "(unknown client)", []).append(r)
    problems = [r for r in rows if r["status"] in ("failed",)]
    setup_needed = [r for r in rows if r["status"] == "skipped"]
    first = [r for r in rows if r["status"] == "first"]
    unchanged = [r for r in rows if r["status"] == "ok" and not r["change_count"]]
    summary = {
        "firewalls": len(rows),
        "backed_up": sum(1 for r in rows if r["backup_id"]),
        "changed_firewalls": len(changed),
        "changes": sum(r["change_count"] for r in rows),
        "review": sum(r["review_count"] for r in rows),
        "failed": len(problems),
        "skipped": len(setup_needed),
        "first": len(first),
    }
    tz = db.get_setting("timezone")
    date_str = local_time(run["started_at"], tz, "%a %b %d, %Y")
    if summary["changes"]:
        subject = (f"Firewall changes: {summary['changes']} change{'s' if summary['changes'] != 1 else ''} on "
                   f"{summary['changed_firewalls']} firewall{'s' if summary['changed_firewalls'] != 1 else ''}"
                   + (f" ({summary['review']} to review)" if summary["review"] else "") + f" - {date_str}")
    else:
        subject = f"Firewall changes: none - {date_str}"
    if summary["failed"]:
        subject += f" - {summary['failed']} backup{'s' if summary['failed'] != 1 else ''} failed"
    html = env.get_template("email_report.html").render(
        run=run, summary=summary, clients=clients, problems=problems, setup_needed=setup_needed,
        first=first, unchanged=unchanged, notes=notes or [], base_url=config.APP_BASE_URL,
        date_str=date_str, tz=tz)
    return {"html": html, "subject": subject, "summary": summary}


# -- sending ------------------------------------------------------------------------
def recipients():
    raw = db.get_setting("recipients")
    return [x.strip() for x in raw.replace(";", ",").replace("\n", ",").split(",") if x.strip()]


def send(subject, html, to=None):
    to = to or recipients()
    if not to:
        raise RuntimeError("No report recipients set (Settings)")
    if not config.email_configured():
        raise RuntimeError("Email isn't configured (see EMAIL_METHOD and related settings in .env)")
    if config.EMAIL_METHOD == "graph":
        return _send_graph(subject, html, to)
    return _send_smtp(subject, html, to)


def _send_smtp(subject, html, to):
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, config.MAIL_FROM, ", ".join(to)
    msg.set_content("This report is HTML. Open it in an HTML-capable mail client, or view it in the web app: "
                    + config.APP_BASE_URL)
    msg.add_alternative(html, subtype="html")
    if config.SMTP_SECURITY == "ssl":
        s = smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, timeout=60)
    else:
        s = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=60)
        if config.SMTP_SECURITY == "starttls":
            s.starttls()
    with s:
        if config.SMTP_USERNAME:
            s.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
        s.send_message(msg)


def _send_graph(subject, html, to):
    tok = httpx.post(f"https://login.microsoftonline.com/{config.GRAPH_TENANT_ID}/oauth2/v2.0/token", data={
        "client_id": config.GRAPH_CLIENT_ID, "client_secret": config.GRAPH_CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"}, timeout=30)
    if tok.status_code != 200:
        raise RuntimeError(f"Microsoft sign-in failed ({tok.status_code}): {tok.text[:300]}")
    body = {"message": {"subject": subject, "body": {"contentType": "HTML", "content": html},
                        "toRecipients": [{"emailAddress": {"address": a}} for a in to]},
            "saveToSentItems": True}
    r = httpx.post(f"https://graph.microsoft.com/v1.0/users/{config.MAIL_FROM}/sendMail",
                   headers={"Authorization": f"Bearer {tok.json()['access_token']}"}, json=body, timeout=60)
    if r.status_code not in (200, 202):
        raise RuntimeError(f"Graph sendMail failed ({r.status_code}): {r.text[:300]}")
