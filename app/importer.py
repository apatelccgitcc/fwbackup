"""Import .tar configuration exports (containing Entities.xml) from a folder.

Works with the folder layout your existing exporter writes:
    <import folder>/<date>/<Client name>/<firewall name or serial>.tar
    <import folder>/<date>/summary.csv   (optional: tenant, firewall name, serial ...)
"""
import csv
import re
import tarfile
from pathlib import Path


def _norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def read_entities_from_tar(path):
    with tarfile.open(path) as tf:
        for m in tf.getmembers():
            if m.isfile() and m.name.lower().endswith("entities.xml"):
                return tf.extractfile(m).read()
    raise ValueError(f"No Entities.xml inside {path}")


def _summary_rows(folder: Path):
    """Read any summary.csv in this folder or its parents (up to 3 levels)."""
    rows = []
    for d in [folder, *list(folder.parents)[:3]]:
        f = d / "summary.csv"
        if f.exists():
            try:
                with open(f, newline="", encoding="utf-8-sig") as fh:
                    for r in csv.DictReader(fh):
                        rows.append({(k or "").strip().lower(): (v or "").strip() for k, v in r.items()})
            except Exception:
                pass
    return rows


def _col(row, *needles):
    for k, v in row.items():
        if any(n in k for n in needles) and v:
            return v
    return ""


def find_tar_files(root):
    root = Path(root).expanduser()
    if not root.is_dir():
        raise FileNotFoundError(f"Import folder not found: {root}")
    return sorted((p for p in root.rglob("*.tar") if p.is_file()), key=lambda p: p.stat().st_mtime)


def match_firewall(tar_path: Path, firewalls):
    """Return (firewall_dict or None, guessed_serial, client_name)."""
    stem = _norm(tar_path.stem)
    client = tar_path.parent.name
    serial = ""
    for row in _summary_rows(tar_path.parent):
        name = _col(row, "firewall", "name", "hostname")
        ser = _col(row, "serial")
        if stem and (stem == _norm(name) or stem == _norm(ser)):
            serial = ser
            client = _col(row, "tenant", "customer", "client") or client
            break
    if not serial and re.fullmatch(r"[a-z0-9]{12,20}", stem) and any(c.isdigit() for c in stem):
        serial = tar_path.stem
    for fw in firewalls:
        if serial and _norm(fw.get("serial")) == _norm(serial):
            return fw, serial, client
    for fw in firewalls:
        if stem and stem in (_norm(fw.get("serial")), _norm(fw.get("hostname")), _norm(fw.get("name"))):
            return fw, fw.get("serial") or serial, client
    return None, serial, client
