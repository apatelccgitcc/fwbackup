"""Turn a firewall configuration XML (Entities.xml or XML API snapshot) into comparable data.

Result shape:
    {"entities": {type: {key: {field_path: value}}},
     "order":    {type: [key, ...]}}          # document order, used for rule moves
"""
import hashlib
import re
import xml.etree.ElementTree as ET
from collections import defaultdict

# Fields that never mean a real change, or that are re-encrypted on every export.
BUILTIN_IGNORE = [
    r"@transactionid$",
    r"(^|/)(Position|After|Before)(/|$)",          # rule position is tracked via order instead
    r"(?i)(^|/)[^/]*(password|passphrase|presharedkey|sharedsecret|secretkey|privatekey|psk)[^/]*$",
    r"(?i)(^|/)(EncryptedPassword|Hash|Checksum|LastModified|ModifiedTime|CreatedTime|UpdatedAt)$",
]

# Entity types left out of every comparison (Fusion exports include them even though the
# firewall API fallback no longer requests them).
EXCLUDED_TYPES = {"Time"}

ORDERED_TYPES = {"FirewallRule", "NATRule", "SDWANPolicyRoute", "DNSRequestRoute", "FirewallRuleGroup"}

# How to identify entities that have no <Name>
KEY_FIELDS = {
    "UnicastRoute": ["DestinationIP", "Netmask", "Gateway", "Interface"],
    "DNSHostEntry": ["HostName"],
    "DoSBypassRule": ["SourceIP", "DestinationIP", "Protocol", "SourcePort", "DestinationPort"],
    "SpoofPrevention": [],
}


def ignored_types(extra_text=""):
    """Entity types to leave out of comparisons: the built-in ones plus those listed in Settings."""
    return set(EXCLUDED_TYPES) | {t for t in re.split(r"[\s,;]+", extra_text or "") if t}


def compile_ignores(extra_text=""):
    pats = list(BUILTIN_IGNORE)
    for line in (extra_text or "").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            pats.append(line)
    out = []
    for p in pats:
        try:
            out.append(re.compile(p))
        except re.error:
            pass
    return out


def _flatten(el, prefix, out):
    for k, v in el.attrib.items():
        out[f"{prefix}@{k}" if prefix else f"@{k}"] = v
    kids = list(el)
    if not kids:
        txt = (el.text or "").strip()
        if prefix:
            out.setdefault(prefix, [])
            out[prefix].append(txt)
        return
    groups = defaultdict(list)
    for c in kids:
        groups[c.tag].append(c)
    for tag, items in groups.items():
        path = f"{prefix}/{tag}" if prefix else tag
        leafy = all(len(i) == 0 for i in items)
        if len(items) == 1 or leafy:
            for i in items:
                _flatten(i, path, out)
        else:
            for n, i in enumerate(items, 1):
                nm = i.find("Name")
                label = (nm.text or "").strip() if nm is not None and nm.text else str(n)
                _flatten(i, f"{path}[{label}]", out)


def flatten_entity(el):
    raw = {}
    for c in el:
        _flatten(c, c.tag, raw)
    for k, v in el.attrib.items():
        raw[f"@{k}"] = v
    flat = {}
    for k, v in raw.items():
        if isinstance(v, list):
            vals = [x for x in v if x != ""]
            flat[k] = ", ".join(sorted(vals)) if len(vals) > 1 else (vals[0] if vals else "")
        else:
            flat[k] = v
    return flat


def entity_key(tag, el, flat, seen_count):
    nm = el.find("Name")
    if nm is not None and (nm.text or "").strip():
        return nm.text.strip()
    if tag in KEY_FIELDS and KEY_FIELDS[tag]:
        parts = [flat.get(f, "") for f in KEY_FIELDS[tag]]
        if any(parts):
            return " ".join(p for p in parts if p)
    if seen_count == 0:
        return "(settings)"
    return "#" + hashlib.sha1(repr(sorted(flat.items())).encode()).hexdigest()[:8]


def parse_config(xml_bytes, ignores=None, skip_types=None):
    ignores = ignores if ignores is not None else compile_ignores()
    skip_types = skip_types if skip_types is not None else EXCLUDED_TYPES
    root = ET.fromstring(xml_bytes)
    entities = defaultdict(dict)
    order = defaultdict(list)
    singles = defaultdict(int)
    for el in root:
        tag = el.tag
        if tag in ("Login", "Status") or tag in skip_types or (len(el) == 1 and el[0].tag == "Status"):
            continue
        flat = flatten_entity(el)
        flat = {k: v for k, v in flat.items() if not any(p.search(k) for p in ignores)}
        key = entity_key(tag, el, flat, singles[tag])
        singles[tag] += 1
        base, n = key, 2
        while key in entities[tag]:
            key = f"{base} ({n})"
            n += 1
        entities[tag][key] = flat
        if tag in ORDERED_TYPES:
            order[tag].append(key)
    return {"entities": dict(entities), "order": dict(order)}


def count_entities(xml_bytes):
    root = ET.fromstring(xml_bytes)
    return sum(1 for el in root if el.tag not in ("Login", "Status"))
