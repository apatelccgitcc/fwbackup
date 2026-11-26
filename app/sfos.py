"""Sophos Firewall (SFOS) XML API: pull the full configuration as one XML snapshot.

The firewall must have API access turned on (Backup & firmware > API) with this
server's IP on the allowed list, and an admin (ideally read-only profile) for the login.
"""
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

import httpx

from . import config

# Entity types requested from each firewall. Types a firmware version doesn't know are
# skipped automatically, so it's safe for this list to be broad. Editable in Settings.
DEFAULT_ENTITY_TYPES = """
FirewallRule FirewallRuleGroup NATRule
Zone Interface VLAN Alias LAG BridgePair WirelessNetworks AccessPoint
IPHost IPHostGroup FQDNHost FQDNHostGroup MACHost CountryGroup
Services ServiceGroup Schedule
UnicastRoute SDWANPolicyRoute SDWANProfile Gateway GatewayHost
DNS DNSHostEntry DNSRequestRoute DHCPServer DHCPRelay
LocalServiceACL AdminSettings AdministrationProfile User Group UserGroup
AuthenticationServer ActiveDirectory LDAPServer RADIUSServer AuthCTA
SSLVPNPolicy SSLTunnelAccessSettings SSLVPNAuthentication ClientlessPolicy
VPNIPSecConnection VPNProfile IPSecConnection L2TPConfiguration PPTPConfiguration
REDDevice REDProfile
IPSPolicy WebFilterPolicy WebFilterURLGroup WebFilterException FileType
ApplicationFilterPolicy ApplicationClassification TrafficShapingPolicy QoSPolicy
DoSSettings DoSBypassRule SpoofPrevention ARPConfiguration
WAFRule WebServer
SNMPCommunity SNMPv3User SNMPAgentConfiguration SyslogServers Notification NotificationList
CentralManagement NTPServer HAConfigure ATP ZeroDayProtection
SMTPPolicy POPIMAPScanningPolicy MTAAddressGroup
""".split()

BATCH = 8


class FirewallAPIError(Exception):
    pass


def _endpoint(host, port):
    return f"https://{host}:{port}/webconsole/APIController"


def _request_xml(username, password, types):
    gets = "".join(f"<{t}/>" for t in types)
    return (f"<Request><Login><Username>{escape(username)}</Username>"
            f"<Password>{escape(password)}</Password></Login><Get>{gets}</Get></Request>")


def _post(client, url, reqxml):
    r = client.post(url, data={"reqxml": reqxml})
    if r.status_code != 200:
        raise FirewallAPIError(f"HTTP {r.status_code} from firewall API")
    try:
        return ET.fromstring(r.content)
    except ET.ParseError as e:
        raise FirewallAPIError(f"Firewall returned invalid XML: {e}")


def _check_login(root):
    st = root.find("Status")
    if st is not None and root.find("Login") is None:
        code = st.get("code", "")
        raise FirewallAPIError(f"Firewall API refused the request ({code}): {(st.text or '').strip()}")
    login = root.find("Login/status")
    if login is not None and "success" not in (login.text or "").lower():
        raise FirewallAPIError(f"Firewall API login failed: {(login.text or '').strip()}")


def _is_error_entity(el):
    """An entity element that only carries a Status child means 'no records' or 'unsupported'."""
    kids = list(el)
    return len(kids) == 1 and kids[0].tag == "Status"


def fetch_config(host, username, password, port=None, entity_types=None, http=None):
    """Return (xml_bytes, entity_count, skipped_types)."""
    port = port or config.FW_API_PORT
    types = entity_types or DEFAULT_ENTITY_TYPES
    url = _endpoint(host, port)
    client = http or httpx.Client(verify=config.FW_VERIFY_TLS, timeout=config.FW_TIMEOUT)
    out = ET.Element("Configuration", {"source": "xmlapi", "host": host})
    skipped, count, apiver, last_err = [], 0, "", None
    try:
        for i in range(0, len(types), BATCH):
            batch = types[i:i + BATCH]
            try:
                root = _post(client, url, _request_xml(username, password, batch))
                _check_login(root)
                roots = [root]
            except FirewallAPIError as e:
                if "login" in str(e).lower() or "refused" in str(e).lower():
                    raise
                # one unsupported type can spoil a whole batch on some firmware; retry one at a time
                roots = []
                for t in batch:
                    try:
                        r1 = _post(client, url, _request_xml(username, password, [t]))
                        _check_login(r1)
                        roots.append(r1)
                    except FirewallAPIError as e1:
                        if "login" in str(e1).lower() or "refused" in str(e1).lower():
                            raise
                        skipped.append(t)
                        last_err = e1
            for root in roots:
                apiver = apiver or root.get("APIVersion", "")
                for el in root:
                    if el.tag in ("Login", "Status"):
                        continue
                    if _is_error_entity(el):
                        continue
                    el.attrib.pop("transactionid", None)
                    out.append(el)
                    count += 1
    except httpx.HTTPError as e:
        raise FirewallAPIError(f"Can't reach firewall API at {host}:{port} ({type(e).__name__}: {e})")
    finally:
        if http is None:
            client.close()
    if apiver:
        out.set("APIVersion", apiver)
    if count == 0:
        if last_err and len(skipped) == len(types):
            raise last_err
        raise FirewallAPIError("Firewall API returned no configuration (check the admin profile's permissions)")
    ET.indent(out)
    return ET.tostring(out, encoding="utf-8", xml_declaration=True), count, skipped
