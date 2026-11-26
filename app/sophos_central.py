"""Sophos Central / Fusion API: partner -> tenants -> firewalls."""
import io
import re
import tarfile
import threading
import time

import httpx

from . import config


class CentralError(Exception):
    pass


class CentralClient:
    def __init__(self, client_id=None, client_secret=None, http=None):
        self.client_id = client_id or config.SOPHOS_CLIENT_ID
        self.client_secret = client_secret or config.SOPHOS_CLIENT_SECRET
        self.http = http or httpx.Client(timeout=60)
        self.token = None
        self.token_exp = 0
        self.id_type = None
        self.whoami_id = None
        self.api_hosts = {}
        self._lock = threading.Lock()

    # -- plumbing -------------------------------------------------------------
    def _auth(self, force=False):
        with self._lock:
            if not force and self.token and time.time() < self.token_exp - 60:
                return self.token
            r = self.http.post(config.SOPHOS_ID_URL, data={
                "grant_type": "client_credentials", "client_id": self.client_id,
                "client_secret": self.client_secret, "scope": "token"})
            if r.status_code != 200:
                raise CentralError(f"Sophos sign-in failed ({r.status_code}): {r.text[:300]}")
            j = r.json()
            self.token = j["access_token"]
            self.token_exp = time.time() + int(j.get("expires_in", 3600))
            return self.token

    def _request(self, method, url, headers=None, params=None, json=None):
        for attempt in range(6):
            token = self._auth(force=attempt > 0 and getattr(self, "_last_401", False))
            self._last_401 = False
            h = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            h.update(headers or {})
            r = self.http.request(method, url, headers=h, params=params, json=json)
            if r.status_code == 429 or r.status_code >= 500:
                wait = float(r.headers.get("Retry-After", 0) or 0) or min(2 ** attempt, 30)
                time.sleep(wait)
                continue
            if r.status_code == 401 and attempt == 0:
                self._last_401 = True
                continue
            if r.status_code not in (200, 201, 202):
                raise CentralError(f"{method} {url.split('/firewall/')[-1]} failed ({r.status_code}): "
                                   f"{_error_text(r)}")
            return r.json() if r.content else {}
        raise CentralError(f"{method} {url} kept failing (rate limited or server error)")

    def _get(self, url, headers=None, params=None):
        return self._request("GET", url, headers, params)

    def whoami(self):
        j = self._get(f"{config.SOPHOS_GLOBAL_URL}/whoami/v1")
        self.id_type = j.get("idType")
        self.whoami_id = j.get("id")
        self.api_hosts = j.get("apiHosts", {})
        return j

    # -- tenants ------------------------------------------------------------
    def tenants(self):
        if self.id_type is None:
            self.whoami()
        if self.id_type == "tenant":
            return [{"id": self.whoami_id, "name": "(this tenant)",
                     "apiHost": self.api_hosts.get("dataRegion"), "dataRegion": ""}]
        if self.id_type == "organization":
            base, hdr = f"{config.SOPHOS_GLOBAL_URL}/organization/v1/tenants", {"X-Organization-ID": self.whoami_id}
        elif self.id_type == "partner":
            base, hdr = f"{config.SOPHOS_GLOBAL_URL}/partner/v1/tenants", {"X-Partner-ID": self.whoami_id}
        else:
            raise CentralError(f"Unsupported credential type: {self.id_type}")
        out, page = [], 1
        while True:
            j = self._get(base, hdr, {"page": page, "pageSize": 100, "pageTotal": "true"})
            out.extend(j.get("items", []))
            total = (j.get("pages") or {}).get("total") or 1
            if page >= total:
                break
            page += 1
        return out

    # -- firewalls ----------------------------------------------------------
    def firewalls(self, tenant):
        host = tenant.get("apiHost")
        if not host:
            return []
        hdr = {"X-Tenant-ID": tenant["id"]}
        out, params = [], {"pageSize": 100}
        while True:
            j = self._get(f"{host}/firewall/v1/firewalls", hdr, params)
            out.extend(j.get("items", []))
            pages = j.get("pages") or {}
            if pages.get("nextKey"):
                params = {"pageSize": 100, "pageFromKey": pages["nextKey"]}
                continue
            if pages.get("current") and pages.get("total") and pages["current"] < pages["total"]:
                params = {"pageSize": 100, "page": pages["current"] + 1}
                continue
            break
        return out


    # -- configuration export (SFOS 22.0 MR2+, Central Firewall Management 2026.29+) ----------
    def export_config(self, api_host, tenant_id, firewall_id, poll_seconds=None, timeout=None):
        """Ask Central for a full configuration export of one firewall and return the TAR bytes."""
        poll_seconds = config.EXPORT_POLL_SECONDS if poll_seconds is None else poll_seconds
        timeout = config.EXPORT_TIMEOUT if timeout is None else timeout
        hdr = {"X-Tenant-ID": tenant_id}
        base = f"{api_host}/firewall/v1/firewall-config/firewalls"
        start = self._request("POST", f"{base}/{firewall_id}/export", hdr, json={"fullExport": True})
        tx = start.get("transactionId")
        if not tx:
            raise CentralError(f"Export didn't return a transaction id: {str(start)[:300]}")
        deadline = time.time() + timeout
        while True:
            st = self._request("GET", f"{base}/transactions/{tx}", hdr)
            status = (st.get("status") or "").lower()
            if status == "finished":
                break
            if time.time() > deadline:
                raise CentralError(f"Export still '{status}' after {timeout // 60} minutes")
            time.sleep(poll_seconds)
        result = st.get("result") or ""
        url = (st.get("response") or {}).get("url")
        if result != "success" or not url:
            detail = st.get("response") or st.get("error") or st.get("errors") or ""
            raise CentralError(f"Export finished with result '{result or 'unknown'}'"
                               + (f": {str(detail)[:300]}" if detail else ""))
        # pre-signed, time-limited link: fetch without our bearer token
        r = self.http.get(url, timeout=300, follow_redirects=True)
        if r.status_code != 200:
            raise CentralError(f"Export download failed ({r.status_code})")
        return r.content


def _error_text(r):
    try:
        j = r.json()
        return (j.get("message") or j.get("error") or str(j))[:300]
    except Exception:
        return r.text[:300]


def entities_from_tar(data: bytes) -> bytes:
    """Pull Entities.xml out of an export TAR (plain or gzipped)."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for m in tf.getmembers():
            if m.isfile() and m.name.lower().endswith("entities.xml"):
                return tf.extractfile(m).read()
    raise CentralError("Export archive has no Entities.xml")


def supports_central_export(firmware: str):
    """True / False if the firmware string clearly is / isn't SFOS 22.0 MR2+, None if unknown."""
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", firmware or "")
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    if (major, minor) != (22, 0):
        return (major, minor) > (22, 0)
    mr = re.search(r"MR[-_ ]?(\d+)", firmware, re.I)
    if mr:
        return int(mr.group(1)) >= 2
    if re.search(r"\bGA\b", firmware, re.I):
        return False
    return None   # 22.0 without a clear MR number: just try the export


def ha_role(fw):
    """'primary' / 'auxiliary' for a firewall in an HA cluster, '' for a standalone one."""
    cluster = fw.get("cluster") or {}
    for v in (cluster.get("status"), cluster.get("role"), cluster.get("nodeRole"),
              fw.get("haRole"), (fw.get("status") or {}).get("haRole")):
        v = str(v or "").lower()
        if "aux" in v or "secondary" in v:
            return "auxiliary"
        if "primary" in v:
            return "primary"
    return ""


def flatten_firewall(t, fw):
    status = fw.get("status") or {}
    ips = fw.get("externalIpv4Addresses") or []
    return {
        "id": fw["id"],
        "tenant_id": t["id"],
        "api_host": t.get("apiHost") or "",
        "tenant_name": t.get("showAs") or t.get("name") or "",
        "serial": fw.get("serialNumber") or "",
        "hostname": fw.get("hostname") or "",
        "name": fw.get("name") or fw.get("hostname") or fw.get("serialNumber") or fw["id"],
        "model": fw.get("model") or "",
        "firmware": fw.get("firmwareVersion") or "",
        "connected": 1 if status.get("connected") else 0,
        "external_ip": ips[0] if ips else "",
        "ha_role": ha_role(fw),
    }
