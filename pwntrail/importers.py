"""Turn scanner output into findings, services and endpoints.

Supported (auto-detected):
  nmap   -oX file.xml
  nuclei -jsonl / -json-export
  ffuf   -of json -o file.json
  nikto  -Format xml / -Format json
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit

from .db import Case, now
from .kb import advise

SENSITIVE_PATHS = [
    (r"/\.git(/|$)", "Exposed .git directory", "high"),
    (r"/\.env$", "Exposed .env file", "high"),
    (r"/\.svn(/|$)", "Exposed .svn directory", "high"),
    (r"/\.ds_store$", "Exposed .DS_Store file", "low"),
    (r"/(phpinfo|info)\.php$", "phpinfo() page exposed", "medium"),
    (r"/server-status$", "Apache server-status exposed", "medium"),
    (r"\.(bak|old|backup|swp|sql|tar|tar\.gz|tgz|zip|7z)$", "Backup or archive file exposed", "medium"),
    (r"/(swagger|swagger-ui|api-docs|openapi\.json)", "API documentation exposed (swagger)", "low"),
    (r"/actuator(/|$)", "Spring Boot actuator endpoint exposed", "medium"),
    (r"/(wp-admin|administrator|admin|phpmyadmin|manager/html)(/|$)", "Administrative interface reachable", "medium"),
    (r"/(web\.config|config\.php|config\.json|settings\.py|wp-config\.php)(\.\w+)?$",
     "Configuration file exposed", "high"),
]


class ImportErrorUnknown(Exception):
    pass


def _safe_xml(data: bytes) -> ET.Element:
    if b"<!ENTITY" in data:
        raise ValueError("refusing XML with entity declarations")
    return ET.fromstring(data)


def detect(path: Path) -> str | None:
    try:
        head = path.read_bytes()[:8192]
    except OSError:
        return None
    s = head.lstrip()
    if b"<nmaprun" in head:
        return "nmap"
    if b"<niktoscan" in head or b"<niktoscan>" in head:
        return "nikto"
    if s.startswith((b"{", b"[")):
        if b'"commandline"' in head and b'"results"' in head:
            return "ffuf"
        if b'"template-id"' in head or b'"templateID"' in head:
            return "nuclei"
        if b'"vulnerabilities"' in head and (b'"host"' in head or b'"ip"' in head):
            return "nikto"
    return None


def _link_command(case: Case, path: Path) -> int | None:
    """Find the recorded command that most likely produced this file."""
    name = path.name
    r = case.conn.execute(
        "SELECT id FROM commands WHERE command LIKE ? ORDER BY id DESC LIMIT 1", (f"%{name}%",)
    ).fetchone()
    return r["id"] if r else None


def _evidence(cmd_id: int | None) -> dict:
    return {"commands": [cmd_id]} if cmd_id else {}


def import_file(case: Case, path: Path) -> dict:
    kind = detect(path)
    if not kind:
        raise ImportErrorUnknown(str(path))
    rel, digest = case.store_file(path, "imports")
    cmd_id = _link_command(case, path)
    with case.tx() as c:
        cur = c.execute("INSERT INTO imports(ts, path, original, kind, sha256, command_id) VALUES (?,?,?,?,?,?)",
                        (now(), rel, str(path), kind, digest, cmd_id))
        imp_id = cur.lastrowid
    case.custody("import", f"import:{imp_id}", digest)
    stored = case.dir / rel
    parser = {"nmap": _nmap, "nuclei": _nuclei, "ffuf": _ffuf, "nikto": _nikto}[kind]
    stats = parser(case, stored, imp_id, cmd_id)
    stats["kind"] = kind
    stats["linked_command"] = cmd_id
    summary = ", ".join(f"{v} {k}" for k, v in stats.items() if isinstance(v, int) and k != "linked_command")
    with case.tx() as c:
        c.execute("UPDATE imports SET summary=? WHERE id=?", (summary, imp_id))
    case.event("import", f"Imported {kind} results from {path.name} ({summary})", ref={"import": imp_id})
    return stats


def import_path(case: Case, path: Path) -> list[tuple[Path, dict | str]]:
    results: list[tuple[Path, dict | str]] = []
    files = [p for p in sorted(path.rglob("*")) if p.is_file()] if path.is_dir() else [path]
    for f in files:
        try:
            results.append((f, import_file(case, f)))
        except ImportErrorUnknown:
            if not path.is_dir():
                results.append((f, "unknown format"))
        except Exception as e:  # keep going on bad files
            results.append((f, f"failed: {e}"))
    return results


# ---------------------------------------------------------------- nmap
def _nmap(case: Case, path: Path, imp_id: int, cmd_id: int | None) -> dict:
    root = _safe_xml(path.read_bytes())
    hosts = services = findings = 0
    for host in root.iter("host"):
        st = host.find("status")
        if st is not None and st.get("state") != "up":
            continue
        addr = None
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr")
                break
        if not addr:
            continue
        hosts += 1
        hn = host.find("hostnames/hostname")
        hostname = hn.get("name") if hn is not None else ""
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") not in ("open", "open|filtered"):
                continue
            svc = port.find("service")
            with case.tx() as c:
                c.execute(
                    "INSERT INTO services(host, hostname, port, proto, state, service, product, version, import_id)"
                    " VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(host, port, proto) DO UPDATE SET"
                    " state=excluded.state, service=COALESCE(NULLIF(excluded.service,''), service),"
                    " product=COALESCE(NULLIF(excluded.product,''), product),"
                    " version=COALESCE(NULLIF(excluded.version,''), version), hostname=excluded.hostname",
                    (addr, hostname, int(port.get("portid")), port.get("protocol"), state.get("state"),
                     svc.get("name", "") if svc is not None else "",
                     svc.get("product", "") if svc is not None else "",
                     " ".join(x for x in [svc.get("version", ""), svc.get("extrainfo", "")] if x) if svc is not None else "",
                     imp_id),
                )
            services += 1
            for script in port.findall("script"):
                out = script.get("output", "")
                if "VULNERABLE" not in out.upper() or "NOT VULNERABLE" in out.upper():
                    continue
                sid = script.get("id", "nse")
                title_line = next((ln.strip() for ln in out.splitlines() if ln.strip() and "VULNERABLE" not in ln.upper()), sid)
                fix, sev = advise(f"{sid} {out}")
                refs = re.findall(r"https?://\S+", out)
                cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", out)))
                _, created = case.upsert_finding({
                    "key": f"nmap:{sid}:{addr}:{port.get('portid')}",
                    "title": f"{title_line} ({sid})" if title_line != sid else sid,
                    "severity": sev or ("high" if cves else "medium"),
                    "target": f"{addr}:{port.get('portid')}",
                    "description": out.strip(),
                    "remediation": fix,
                    "refs": refs,
                    "source": "nmap",
                    "import_id": imp_id,
                    "evidence": _evidence(cmd_id),
                    "extra": {"cves": cves},
                })
                findings += int(created)
    return {"hosts": hosts, "services": services, "findings": findings}


# ---------------------------------------------------------------- nuclei
def _nuclei_items(path: Path):
    text = path.read_text("utf-8", "replace").strip()
    if text.startswith("["):
        yield from json.loads(text)
        return
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _nuclei(case: Case, path: Path, imp_id: int, cmd_id: int | None) -> dict:
    created_n = merged = 0
    for it in _nuclei_items(path):
        info = it.get("info") or {}
        tid = it.get("template-id") or it.get("templateID") or "nuclei"
        host = it.get("host") or it.get("ip") or ""
        hostkey = urlsplit(host).netloc or host
        matcher = it.get("matcher-name") or it.get("matcher_name") or ""
        name = info.get("name") or tid
        if matcher:
            name = f"{name} [{matcher}]"
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        cls = info.get("classification") or {}
        cves = cls.get("cve-id") or []
        if isinstance(cves, str):
            cves = [cves]
        desc = (info.get("description") or "").strip()
        fix = (info.get("remediation") or "").strip()
        if not fix:
            fix, _ = advise(f"{name} {desc}")
        matched = it.get("matched-at") or it.get("matched") or host
        extracted = it.get("extracted-results") or []
        _, created = case.upsert_finding({
            "key": f"nuclei:{tid}:{matcher}:{hostkey}",
            "title": name,
            "severity": (info.get("severity") or "info").lower(),
            "target": hostkey,
            "description": desc,
            "remediation": fix,
            "refs": refs,
            "cvss": str(cls.get("cvss-score") or ""),
            "source": "nuclei",
            "import_id": imp_id,
            "evidence": _evidence(cmd_id),
            "extra": {"matched_at": [matched], "cves": [c.upper() for c in cves if c],
                      "extracted": [str(x) for x in extracted][:20], "template": tid,
                      "curl": it.get("curl-command", "")},
        })
        if created:
            created_n += 1
        else:
            merged += 1
    return {"findings": created_n, "merged": merged}


# ---------------------------------------------------------------- ffuf
def _ffuf(case: Case, path: Path, imp_id: int, cmd_id: int | None) -> dict:
    data = json.loads(path.read_text("utf-8", "replace"))
    endpoints = findings = 0
    for r in data.get("results") or []:
        url = r.get("url") or ""
        if not url:
            continue
        status = int(r.get("status") or 0)
        with case.tx() as c:
            c.execute(
                "INSERT INTO endpoints(url, status, length, words, import_id) VALUES (?,?,?,?,?)"
                " ON CONFLICT(url) DO UPDATE SET status=excluded.status, length=excluded.length,"
                " words=excluded.words",
                (url, status, r.get("length"), r.get("words"), imp_id),
            )
        endpoints += 1
        if status >= 400:
            continue
        parts = urlsplit(url)
        p = parts.path.lower().rstrip("/") or "/"
        for rx, title, sev in SENSITIVE_PATHS:
            if re.search(rx, p):
                fix, _ = advise(f"{title} {p}")
                _, created = case.upsert_finding({
                    "key": f"ffuf:{title}:{parts.netloc}",
                    "title": title,
                    "severity": sev if status < 300 else "low",
                    "target": parts.netloc,
                    "description": f"Content discovery found {title.lower()} reachable over HTTP.",
                    "remediation": fix,
                    "source": "ffuf",
                    "import_id": imp_id,
                    "evidence": _evidence(cmd_id),
                    "extra": {"matched_at": [f"{url}  [HTTP {status}]"]},
                })
                findings += int(created)
                break
    return {"endpoints": endpoints, "findings": findings}


# ---------------------------------------------------------------- nikto
def _nikto_rows(path: Path):
    raw = path.read_bytes()
    if raw.lstrip().startswith((b"{", b"[")):
        data = json.loads(raw.decode("utf-8", "replace"))
        for scan in data if isinstance(data, list) else [data]:
            host = scan.get("host") or scan.get("ip") or ""
            port = str(scan.get("port") or "")
            for v in scan.get("vulnerabilities") or []:
                yield host, port, v.get("id", ""), v.get("url", ""), v.get("msg", ""), v.get("OSVDB", "")
        return
    root = _safe_xml(raw)
    for sd in root.iter("scandetails"):
        host = sd.get("targethostname") or sd.get("targetip") or ""
        port = sd.get("targetport") or ""
        for item in sd.iter("item"):
            desc = (item.findtext("description") or "").strip()
            uri = (item.findtext("uri") or "").strip()
            yield host, port, item.get("id", ""), uri, desc, item.get("osvdbid", "")


def _nikto(case: Case, path: Path, imp_id: int, cmd_id: int | None) -> dict:
    findings = merged = 0
    for host, port, nid, uri, msg, osvdb in _nikto_rows(path):
        if not msg:
            continue
        target = f"{host}:{port}" if port else host
        title = re.sub(r"^/\S*:\s*", "", msg).split(". ")[0].rstrip(".")[:140]
        fix, sev = advise(msg)
        refs = re.findall(r"https?://\S+", msg)
        _, created = case.upsert_finding({
            "key": f"nikto:{nid or title}:{target}",
            "title": title,
            "severity": sev or "low",
            "target": target,
            "description": msg,
            "remediation": fix,
            "refs": [r.rstrip(".,)") for r in refs],
            "source": "nikto",
            "import_id": imp_id,
            "evidence": _evidence(cmd_id),
            "extra": {"matched_at": [uri] if uri else [], "osvdb": osvdb},
        })
        if created:
            findings += 1
        else:
            merged += 1
    return {"findings": findings, "merged": merged}
