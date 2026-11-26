"""Compare two normalized configurations and describe what changed."""
from difflib import SequenceMatcher

TYPE_LABELS = {
    "FirewallRule": "Firewall rule", "FirewallRuleGroup": "Rule group", "NATRule": "NAT rule",
    "Zone": "Zone", "Interface": "Interface", "VLAN": "VLAN", "Alias": "Interface alias",
    "IPHost": "IP host", "IPHostGroup": "IP host group", "FQDNHost": "FQDN host",
    "FQDNHostGroup": "FQDN host group", "MACHost": "MAC host", "CountryGroup": "Country group",
    "Services": "Service", "ServiceGroup": "Service group", "Schedule": "Schedule",
    "UnicastRoute": "Static route", "SDWANPolicyRoute": "SD-WAN route", "SDWANProfile": "SD-WAN profile",
    "GatewayHost": "Gateway", "Gateway": "Gateway", "DNS": "DNS settings", "DNSHostEntry": "DNS host entry",
    "DHCPServer": "DHCP server", "LocalServiceACL": "Device access (local service ACL)",
    "AdminSettings": "Admin settings", "AdministrationProfile": "Admin profile", "User": "User",
    "Group": "User group", "UserGroup": "User group", "AuthenticationServer": "Authentication server",
    "SSLVPNPolicy": "SSL VPN policy", "SSLTunnelAccessSettings": "SSL VPN settings",
    "VPNIPSecConnection": "IPsec connection", "IPSecConnection": "IPsec connection",
    "VPNProfile": "IPsec profile", "IPSPolicy": "IPS policy", "WebFilterPolicy": "Web filter policy",
    "WebFilterURLGroup": "URL group", "WebFilterException": "Web exception",
    "ApplicationFilterPolicy": "App control policy", "DoSSettings": "DoS settings",
    "SNMPCommunity": "SNMP community", "SNMPv3User": "SNMPv3 user", "SyslogServers": "Syslog server",
    "CentralManagement": "Central management", "HAConfigure": "High availability",
    "WAFRule": "WAF rule", "REDDevice": "RED device", "WirelessNetworks": "Wireless network",
}

# Display priority (lower first). Anything unknown sorts after these.
TYPE_PRIORITY = ["FirewallRule", "NATRule", "Zone", "LocalServiceACL", "AdministrationProfile", "User",
                 "AdminSettings", "SSLVPNPolicy", "VPNIPSecConnection", "IPSecConnection", "Interface",
                 "VLAN", "UnicastRoute", "SDWANPolicyRoute", "WebFilterPolicy", "IPSPolicy",
                 "ApplicationFilterPolicy"]

RULE_SUMMARY_FIELDS = [
    ("Status", "Status"), ("Action", "Action"), ("SourceZones", "Source zones"),
    ("DestinationZones", "Dest zones"), ("SourceNetworks", "Source networks"),
    ("DestinationNetworks", "Dest networks"), ("Services", "Services"), ("LogTraffic", "Log"),
    ("OriginalSource", "Orig source"), ("OriginalDestination", "Orig dest"), ("OriginalService", "Orig service"),
    ("TranslatedSource", "Xlated source"), ("TranslatedDestination", "Xlated dest"),
    ("TranslatedService", "Xlated service"), ("InboundInterface", "Inbound if"), ("OutboundInterface", "Outbound if"),
    ("Description", "Description"),
]


def label(t):
    return TYPE_LABELS.get(t, t)


POLICY_CONTAINERS = ("NetworkPolicy", "UserPolicy", "HTTPBasedPolicy")


def _get_suffix(fields, name):
    """Value of a rule field whether it sits at top level or inside a policy container."""
    vals = []
    for k, v in fields.items():
        segs = k.split("/")
        if segs[0] in POLICY_CONTAINERS:
            segs = segs[1:]
        if segs and segs[0] == name and v:
            vals.append(v)
    return ", ".join(vals)


def summarize(etype, fields):
    if etype not in ("FirewallRule", "NATRule"):
        out = []
        for k, v in fields.items():
            last = k.split("/")[-1].lstrip("@")
            if last in ("Name", "IPFamily", "transactionid") or not v or len(v) > 80:
                continue
            out.append((last, v))
            if len(out) == 4:
                break
        return out
    out = []
    for key, lbl in RULE_SUMMARY_FIELDS:
        v = _get_suffix(fields, key)
        if v:
            out.append((lbl, v))
    return out


def _review_reasons(etype, kind, fields_new, fields_old, changed):
    """Heuristics for changes a human should look at closely."""
    reasons = []
    f = fields_new or fields_old or {}
    joined = " ".join(f"{k}={v}" for k, v in f.items())
    if etype == "FirewallRule":
        src = _get_suffix(f, "SourceZones")
        action = _get_suffix(f, "Action")
        if "WAN" in src.split(", ") and kind in ("added", "modified") and action.lower() in ("accept", ""):
            reasons.append("allows traffic from WAN")
        for c in changed:
            segs = c["field"].split("/")
            fld = segs[-1]
            new_v = c["new"].lower()
            if fld == "LogTraffic" and new_v.startswith("disable"):
                reasons.append("logging turned off")
            if fld == "Action" and new_v == "accept":
                reasons.append("changed to Accept")
            if fld == "Status" and len(segs) == 1 and new_v.startswith("disable"):
                reasons.append("rule disabled")
            for wide in ("SourceZones", "SourceNetworks", "DestinationNetworks", "Services"):
                if wide in segs and not c["new"] and c["old"]:
                    reasons.append(f"{wide} widened to Any")
            if fld in ("IntrusionPrevention", "WebFilter", "ApplicationControl", "ScanVirus", "ScanHTTP",
                       "WebFilterInternetScheme"):
                if new_v in ("none", "", "disable", "allow all", "allowall"):
                    reasons.append(f"{fld} turned off")
    elif etype == "NATRule" and kind in ("added", "modified"):
        reasons.append("NAT / port forward change")
    elif etype in ("Zone", "LocalServiceACL") and ("WAN" in joined or kind != "modified"):
        reasons.append("device access exposure change")
    elif etype in ("AdministrationProfile", "AdminSettings", "User", "CentralManagement", "AuthenticationServer"):
        reasons.append("admin / authentication change")
    elif etype in ("SSLVPNPolicy", "VPNIPSecConnection", "IPSecConnection") and kind == "added":
        reasons.append("new VPN access")
    return sorted(set(reasons))


def diff_configs(old, new):
    """Return list of change dicts. old/new come from normalize.parse_config."""
    changes = []
    oe, ne = old["entities"], new["entities"]
    for etype in sorted(set(oe) | set(ne)):
        a, b = oe.get(etype, {}), ne.get(etype, {})
        for key in sorted(set(b) - set(a)):
            changes.append(_mk(etype, key, "added", None, b[key], []))
        for key in sorted(set(a) - set(b)):
            changes.append(_mk(etype, key, "removed", a[key], None, []))
        for key in sorted(set(a) & set(b)):
            fa, fb = a[key], b[key]
            if fa == fb:
                continue
            changed = []
            for fld in sorted(set(fa) | set(fb)):
                va, vb = fa.get(fld, ""), fb.get(fld, "")
                if va != vb:
                    changed.append({"field": fld, "old": va, "new": vb})
            if changed:
                changes.append(_mk(etype, key, "modified", fa, fb, changed))
    # rule order
    for etype in sorted(set(old.get("order", {})) & set(new.get("order", {}))):
        oo = [k for k in old["order"][etype] if k in set(new["order"][etype])]
        no = [k for k in new["order"][etype] if k in set(old["order"][etype])]
        if oo == no:
            continue
        sm = SequenceMatcher(a=oo, b=no, autojunk=False)
        stable = set()
        for blk in sm.get_matching_blocks():
            stable.update(oo[blk.a:blk.a + blk.size])
        full_old, full_new = old["order"][etype], new["order"][etype]
        for key in no:
            if key not in stable:
                ch = _mk(etype, key, "moved", oe[etype][key], ne[etype][key], [])
                ch["position"] = [full_old.index(key) + 1, full_new.index(key) + 1]
                changes.append(ch)
    pri = {t: i for i, t in enumerate(TYPE_PRIORITY)}
    kind_pri = {"added": 0, "removed": 1, "modified": 2, "moved": 3}
    changes.sort(key=lambda c: (pri.get(c["type"], 99), c["type"], kind_pri[c["kind"]], c["key"]))
    return changes


def _mk(etype, key, kind, fold, fnew, changed):
    return {
        "type": etype, "label": label(etype), "key": key, "kind": kind,
        "fields": changed,
        "summary": summarize(etype, fnew if fnew is not None else fold) if kind in ("added", "removed") else [],
        "review": _review_reasons(etype, kind, fnew, fold, changed),
    }
