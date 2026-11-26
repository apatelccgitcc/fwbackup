"""End-to-end test: mock Sophos Central + three firewalls + an import folder, two nightly runs.

Run:  python -m tests.test_e2e
"""
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import parse_qs

TMP = Path(tempfile.mkdtemp(prefix="fwbackup-test-"))
os.environ.update(DATA_DIR=str(TMP / "data"), APP_SECRET_KEY="test-secret", ADMIN_PASSWORD="pw",
                  SOPHOS_CLIENT_ID="cid", SOPHOS_CLIENT_SECRET="csecret",
                  FW_DEFAULT_USERNAME="apiuser", FW_DEFAULT_PASSWORD="apipass",
                  EMAIL_METHOD="smtp", SMTP_HOST="smtp.test", MAIL_FROM="fw@test", EXPORT_POLL_SECONDS="0")

import httpx  # noqa: E402

from app import db, job, report  # noqa: E402
from app.sophos_central import CentralClient  # noqa: E402
from tests import sample_configs as S  # noqa: E402

STATE = {"fw-a": S.baseline(), "fw-b": S.baseline()}
SENT = []
POLLS = {}
CALLS = {"export": 0, "xmlapi": 0}


def tar_bytes(parts):
    data = S.config(parts)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo("Entities.xml")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def entities_for(parts, types):
    root = ET.fromstring(S.config(parts))
    return [ET.tostring(el, encoding="unicode") for el in root if el.tag in types]


def handler(request: httpx.Request):
    url = str(request.url)
    if "id.sophos.com" in url:
        return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
    if url.endswith("/whoami/v1"):
        return httpx.Response(200, json={"id": "partner-1", "idType": "partner"})
    if "/partner/v1/tenants" in url:
        return httpx.Response(200, json={"items": [
            {"id": "t1", "name": "Acme Health", "apiHost": "https://api-us01.central.sophos.com"},
            {"id": "t2", "name": "Beta Credit Union", "apiHost": "https://api-us03.central.sophos.com"}],
            "pages": {"current": 1, "total": 1}})
    # Fusion configuration export (SFOS 22.0 MR2+)
    if "/firewall-config/firewalls/" in url and url.endswith("/export"):
        assert json.loads(request.content) == {"fullExport": True}
        assert request.headers["X-Tenant-ID"] in ("t1", "t2")
        fid = url.split("/firewalls/")[1].split("/")[0]
        CALLS["export"] += 1
        return httpx.Response(201, json={"transactionId": f"tx-{fid}"})
    if "/firewall-config/firewalls/transactions/" in url:
        tx = url.rsplit("/", 1)[1]
        fid = tx[3:]
        POLLS[tx] = POLLS.get(tx, 0) + 1
        if POLLS[tx] == 1:
            return httpx.Response(200, json={"status": "started"})
        if fid == "fw-b":   # export doesn't work for this one -> app falls back to the firewall API
            return httpx.Response(200, json={"status": "finished", "result": "error",
                                             "response": {"message": "Firewall subscription not eligible"}})
        return httpx.Response(200, json={"status": "finished", "result": "success",
                                         "response": {"url": f"https://download.test/{fid}.tar?sig=abc"}})
    if "download.test" in url:
        assert "Authorization" not in request.headers
        fid = request.url.path.strip("/").split(".")[0]
        return httpx.Response(200, content=tar_bytes(STATE[fid]))
    if "/firewall/v1/firewalls" in url:
        t = request.headers["X-Tenant-ID"]
        items = {"t1": [
            {"id": "fw-a", "serialNumber": "X1100AAA111", "hostname": "acme-main", "name": "Acme Main",
             "model": "XGS2100", "firmwareVersion": "SFOS 22.0.2 MR-2-Build123", "status": {"connected": True},
             "externalIpv4Addresses": ["198.51.100.10"]},
            {"id": "fw-c", "serialNumber": "X1100CCC333", "hostname": "acme-branch", "name": "Acme Branch",
             "model": "XGS107", "firmwareVersion": "SFOS 21.0.1 MR-1", "status": {"connected": True},
             "externalIpv4Addresses": ["198.51.100.30"]},
            # auxiliary unit of fw-a's HA pair: must never be backed up or reported
            {"id": "fw-a-aux", "serialNumber": "X1100AAA112", "hostname": "acme-main", "name": "X1100AAA112",
             "model": "XGS2100", "firmwareVersion": "SFOS 22.0.2 MR-2-Build123", "status": {"connected": True},
             "cluster": {"id": "cl-1", "mode": "activePassive", "status": "auxiliary"},
             "externalIpv4Addresses": []}],
            "t2": [{"id": "fw-b", "serialNumber": "X1100BBB222", "hostname": "beta-hq", "name": "Beta HQ",
                    "model": "XGS136", "firmwareVersion": "SFOS 22.0.2 MR-2-Build123", "status": {"connected": True},
                    "externalIpv4Addresses": ["198.51.100.20"]}]}[t]
        return httpx.Response(200, json={"items": items, "pages": {"current": 1, "total": 1}})
    if "/webconsole/APIController" in url:
        host = request.url.host
        fid = {"198.51.100.10": "fw-a", "198.51.100.20": "fw-b", "198.51.100.30": "fw-c"}[host]
        CALLS["xmlapi"] += 1
        if fid == "fw-c":
            raise httpx.ConnectTimeout("timed out")
        req = ET.fromstring(parse_qs(request.content.decode())["reqxml"][0])
        if req.findtext("Login/Password") != "apipass":
            return httpx.Response(200, text="<Response><Login><status>Authentication Failure</status></Login></Response>")
        types = [e.tag for e in req.find("Get")]
        if "Bogus" in types:   # unsupported type breaks the batch, like old firmware
            return httpx.Response(500)
        body = "".join(entities_for(STATE[fid], types))
        for t in types:
            if t not in body:
                body += f'<{t}><Status code="526">Record does not exist.</Status></{t}>'
        return httpx.Response(200, text=f'<Response APIVersion="2100.1"><Login><status>Authentication Successful'
                                        f'</status></Login>{body}</Response>')
    return httpx.Response(404)


def make_tar(path, parts):
    data = S.config(parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w") as tf:
        ti = tarfile.TarInfo("Entities.xml")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))


def main():
    transport = httpx.MockTransport(handler)
    http = httpx.Client(transport=transport)
    report.send = lambda subject, html, to=None: SENT.append((subject, html))
    db.set_settings({"recipients": "noc@test", "entity_types": "FirewallRule NATRule Zone IPHost User AdminSettings Bogus"})

    # import folder in the existing exporter's layout, for a firewall with no API access
    imports = TMP / "imports"
    make_tar(imports / "2026-11-24" / "Gamma Pharmacy" / "Pharmacy-XG.tar", S.baseline())
    (imports / "2026-11-24" / "summary.csv").write_text(
        "Tenant,Firewall Name,Serial,Firmware,Result\nGamma Pharmacy,Pharmacy-XG,X1100GGG777,SFOS 21,ok\n")
    db.set_settings({"import_folder": str(imports)})

    central = CentralClient(http=http)
    r1 = job.run("test", http=http, central_client=central)
    run1 = db.q1("SELECT * FROM runs WHERE id=?", (r1,))
    s1 = json.loads(run1["summary_json"])
    print("RUN 1:", run1["status"], {k: s1[k] for k in ("firewalls", "backed_up", "first", "failed", "changes")})
    assert run1["status"] == "done", run1
    assert s1["first"] == 3 and s1["failed"] == 1, s1

    # a day later: changes on fw-a, nothing on fw-b, new import for the pharmacy with one change
    STATE["fw-a"] = S.changed()
    time.sleep(1.1)
    pharm = S.baseline()
    pharm[4] = S.rule("Internet Access", desc="LAN to internet", wf="None")
    make_tar(imports / "2026-11-25" / "Gamma Pharmacy" / "Pharmacy-XG.tar", pharm)
    r2 = job.run("test", http=http, central_client=central)
    run2 = db.q1("SELECT * FROM runs WHERE id=?", (r2,))
    s2 = json.loads(run2["summary_json"])
    print("RUN 2:", run2["status"], {k: s2[k] for k in ("firewalls", "backed_up", "changed_firewalls", "changes", "review", "failed")})
    for r in db.q("SELECT rr.firewall_id, rr.status, rr.change_count, rr.review_count, rr.error FROM run_results rr WHERE run_id=?", (r2,)):
        print("   ", r)
    assert s2["changed_firewalls"] == 2, s2
    srcs = {r["firewall_id"]: r["source"] for r in db.q(
        "SELECT firewall_id, source FROM backups WHERE id IN (SELECT backup_id FROM run_results WHERE run_id=?)", (r2,))}
    print("SOURCES:", srcs, "CALLS:", CALLS)
    assert srcs["fw-a"] == "central" and srcs["fw-b"] == "api", srcs
    assert run2["emailed"] == 1
    subj, html = SENT[-1]
    print("SUBJECT:", subj)
    out = Path(__file__).resolve().parent.parent / "sample_report.html"
    out.write_text(html)
    print("Report written to", out)
    # HA auxiliary: synced and labelled, but never exported, backed up or reported
    aux = db.q1("SELECT * FROM firewalls WHERE id='fw-a-aux'")
    assert aux and aux["ha_role"] == "auxiliary", aux
    assert not db.q("SELECT 1 FROM run_results WHERE firewall_id='fw-a-aux'")
    assert not db.q("SELECT 1 FROM backups WHERE firewall_id='fw-a-aux'")
    assert "tx-fw-a-aux" not in POLLS, POLLS
    assert "X1100AAA112" not in html
    assert report.backup_method(aux)[0] == "aux"

    # Time: dropped from the request list (even from a saved custom list) and from comparisons
    from app import sfos
    from app.normalize import parse_config
    assert "Time" not in sfos.DEFAULT_ENTITY_TYPES
    db.set_settings({"entity_types": "FirewallRule Time"})
    assert job.entity_types() == ["FirewallRule"], job.entity_types()
    cfg = b"<Configuration><Time><TimeZone>America/New_York</TimeZone></Time><Zone><Name>LAN</Name></Zone></Configuration>"
    assert set(parse_config(cfg)["entities"]) == {"Zone"}
    # Configuration types to ignore (Settings): RouterAdvertisement ignored by default, others addable
    from app import storage
    from app.diff import diff_configs
    from app.normalize import ignored_types
    old = b"<C><AntiSpamQuarantineDigestSettings><SpamDigestUsers><DisableUsers><DisableUser>a@x</DisableUser></DisableUsers></SpamDigestUsers></AntiSpamQuarantineDigestSettings></C>"
    new = (b"<C><AntiSpamQuarantineDigestSettings><SpamDigestUsers><DisableUsers><DisableUser>a@x</DisableUser>"
           b"<DisableUser>b@x</DisableUser></DisableUsers></SpamDigestUsers></AntiSpamQuarantineDigestSettings>"
           b"<RouterAdvertisement><Interface>PortF1.999</Interface></RouterAdvertisement></C>")
    assert db.get_setting("ignore_types") == "RouterAdvertisement"
    skip = ignored_types(db.get_setting("ignore_types"))
    assert "Time" in skip
    ch = diff_configs(parse_config(old, skip_types=skip), parse_config(new, skip_types=skip))
    assert [c["type"] for c in ch] == ["AntiSpamQuarantineDigestSettings"], ch
    skip = ignored_types("RouterAdvertisement,\nAntiSpamQuarantineDigestSettings")
    assert not diff_configs(parse_config(old, skip_types=skip), parse_config(new, skip_types=skip))
    assert storage.load_parsed.__defaults__ == (None, None)
    print("HA auxiliary + Time checks passed")
    print("Data dir:", TMP)
    return TMP


if __name__ == "__main__":
    main()
