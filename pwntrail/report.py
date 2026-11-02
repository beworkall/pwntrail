"""Build the evidence timeline and the pentest report from a case."""

from __future__ import annotations

import base64
import json
import mimetypes
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import __version__
from .db import SEVERITIES, Case, verify
from .scope import parse_scope

TEMPLATES = Path(__file__).parent / "templates"

THEMES = {
    "dark": {
        "bg": "#0b0e14", "panel": "#121722", "panel2": "#0f131c", "border": "#232a38", "text": "#e6e9ef",
        "muted": "#8a93a6", "accent": "#ff3b5c", "code_bg": "#080a0f", "code_text": "#c9d1d9",
        "critical": "#ff2d55", "high": "#ff7a1a", "medium": "#ffc21a", "low": "#3ea6ff", "info": "#8a93a6",
        "on_sev": "#0b0e14",
    },
    "light": {
        "bg": "#ffffff", "panel": "#f6f7f9", "panel2": "#fbfbfc", "border": "#e3e6eb", "text": "#14171f",
        "muted": "#5b6475", "accent": "#d61f45", "code_bg": "#f3f4f6", "code_text": "#1f2430",
        "critical": "#c8102e", "high": "#d9590b", "medium": "#a87700", "low": "#1f6fd1", "info": "#5b6475",
        "on_sev": "#ffffff",
    },
}

SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}

# shell noise that doesn't belong in a "tools used" list
NOISE_TOOLS = {"", "cd", "ls", "ll", "la", "cat", "echo", "clear", "pwd", "history", "vim", "vi", "nano",
               "less", "more", "grep", "head", "tail", "mkdir", "rm", "cp", "mv", "touch", "export",
               "source", ".", "for", "while", "if", "pwntrail", "which", "man", "printf", "true", "false",
               "sleep", "wc", "sort", "uniq", "cut", "awk", "sed", "tr", "tee", "chmod", "chown", "file",
               "exit", "unset", "alias", "type", "set", "fg", "bg", "jobs", "kill", "code", "open", "xdg-open"}


def _env(autoescape: bool) -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        autoescape=select_autoescape(["html"]) if autoescape else False,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["dt"] = _fmt_dt
    env.filters["short"] = lambda s, n=80: (s if len(s) <= n else s[: n - 1] + "…") if s else ""
    return env


def _fmt_dt(iso: str | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    if not iso:
        return ""
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone().strftime(fmt)
    except ValueError:
        return iso


def _data_uri(path: Path) -> str:
    if not path.exists():
        return ""
    mime = mimetypes.guess_type(path.name)[0] or "image/png"
    return f"data:{mime};base64,{base64.b64encode(path.read_bytes()).decode()}"


def _excerpt(output: str, max_lines: int = 40) -> tuple[str, bool]:
    lines = (output or "").splitlines()
    if len(lines) <= max_lines:
        return "\n".join(lines), False
    head = max_lines - 10
    return "\n".join(lines[:head] + [f"[... {len(lines) - max_lines} lines omitted ...]"] + lines[-10:]), True


def _host_of(target: str) -> str:
    t = target.strip()
    if t.startswith("["):
        return t.split("]")[0].strip("[")
    if t.count(":") == 1:
        return t.split(":")[0]
    return t


def _exec_summary(ctx: dict) -> list[str]:
    c = ctx["sev_counts"]
    total = ctx["total_findings"]
    paras = []
    span = ""
    if ctx["first_activity"] and ctx["last_activity"]:
        span = f" between {_fmt_dt(ctx['first_activity'], '%d %b %Y')} and {_fmt_dt(ctx['last_activity'], '%d %b %Y')}"
    paras.append(
        f"A security assessment of {ctx['client']} was carried out{span}. "
        f"{len(ctx['hosts'])} host{'s' if len(ctx['hosts']) != 1 else ''} in scope "
        f"{'were' if len(ctx['hosts']) != 1 else 'was'} assessed and "
        f"{ctx['command_count']} tester actions were recorded as evidence."
    )
    if total == 0:
        paras.append("No security findings were recorded during the engagement.")
        return paras
    parts = [f"{c[s]} {SEV_LABEL[s].lower()}" for s in SEVERITIES if c[s]]
    paras.append(f"The assessment identified {total} finding{'s' if total != 1 else ''}: " + ", ".join(parts) + ".")
    if c["critical"] or c["high"]:
        top = [f["title"] for f in ctx["findings"] if f["severity"] in ("critical", "high")][:3]
        paras.append(
            "The most urgent issues are " + "; ".join(top) + ". These should be fixed before anything else, "
            "as they give an attacker a realistic path to compromise."
        )
    else:
        paras.append("No critical or high severity issues were found. The remaining findings should be "
                     "addressed as part of normal hardening.")
    return paras


def build_context(case: Case, theme: str = "dark", company: str = "", logo: Path | None = None,
                  include_info: bool = True) -> dict:
    commands = {r["id"]: r for r in case.rows("SELECT * FROM commands ORDER BY id")}
    shots = {r["id"]: r for r in case.rows("SELECT * FROM shots ORDER BY id")}

    findings = []
    for i, f in enumerate(case.findings(), 1):
        if not include_info and f["severity"] == "info":
            continue
        ev = json.loads(f["evidence"] or "{}")
        extra = json.loads(f["extra"] or "{}")
        ev_cmds = []
        for cid in ev.get("commands") or []:
            c = commands.get(cid)
            if c:
                text, cut = _excerpt(c["output"])
                ev_cmds.append({"id": c["id"], "command": c["command"], "started": c["started"],
                                "exit_code": c["exit_code"], "output": text, "cut": cut or bool(c["truncated"])})
        ev_shots = []
        for sid in ev.get("shots") or []:
            s = shots.get(sid)
            if s:
                ev_shots.append({"id": s["id"], "note": s["note"], "src": _data_uri(case.dir / s["path"]),
                                 "sha256": s["sha256"], "ts": s["ts"]})
        findings.append({
            "id": f["id"], "ref": f"F-{len(findings) + 1:02d}", "title": f["title"], "severity": f["severity"],
            "target": f["target"], "description": f["description"], "remediation": f["remediation"],
            "refs": json.loads(f["refs"] or "[]"), "source": f["source"], "cvss": f["cvss"],
            "matched_at": extra.get("matched_at") or [], "cves": extra.get("cves") or [],
            "extracted": extra.get("extracted") or [], "commands": ev_cmds, "shots": ev_shots,
        })

    sev_counts = Counter(f["severity"] for f in findings)
    for s in SEVERITIES:
        sev_counts.setdefault(s, 0)

    services = [dict(r) for r in case.rows("SELECT * FROM services ORDER BY host, proto, port")]
    endpoints = [dict(r) for r in case.rows("SELECT * FROM endpoints ORDER BY url")]
    events = [dict(r) for r in case.rows("SELECT * FROM events ORDER BY id")]
    notes = [e for e in events if e["kind"] == "note"]
    scope_incidents = [e for e in events if e["kind"] in ("scope_block", "scope_override")]

    scope = parse_scope(case.scope) if case.scope else None
    in_entries = [e for e in case.scope if not e.startswith("!")]
    ex_entries = [e[1:] for e in case.scope if e.startswith("!")]

    hosts: set[str] = set()
    for c in commands.values():
        for t in json.loads(c["targets"] or "[]"):
            if "/" not in t:
                hosts.add(t)
    hosts.update(s["host"] for s in services)
    hosts.update(_host_of(f["target"]) for f in findings if f["target"])
    if scope and not scope.empty:
        from .scope import in_scope
        hosts = {h for h in hosts if in_scope(h, scope)}
    hosts.discard("127.0.0.1")
    hosts.discard("localhost")

    tool_counts = Counter(c["tool"] for c in commands.values() if c["tool"] not in NOISE_TOOLS)
    times = [c["started"] for c in commands.values()] + [e["ts"] for e in events if e["kind"] != "session_end"]
    times = sorted(t for t in times if t)

    ok, problems = verify(case)
    head = case.rows("SELECT hash, id FROM custody ORDER BY id DESC LIMIT 1")
    evidence_files = (
        [{"kind": "screenshot", "path": s["path"], "sha256": s["sha256"]} for s in shots.values()]
        + [{"kind": f"{i['kind']} import", "path": i["path"], "sha256": i["sha256"]}
           for i in case.rows("SELECT * FROM imports ORDER BY id")]
    )

    appendix_cmds = []
    for c in commands.values():
        appendix_cmds.append({"id": c["id"], "started": c["started"], "tool": c["tool"], "command": c["command"],
                              "exit_code": c["exit_code"], "targets": json.loads(c["targets"] or "[]")})

    ctx = {
        "version": __version__,
        "theme_name": theme,
        "t": THEMES.get(theme, THEMES["dark"]),
        "sev_label": SEV_LABEL,
        "severities": SEVERITIES,
        "case": case.slug,
        "name": case.name,
        "client": case.meta("client") or case.name,
        "tester": case.meta("tester"),
        "company": company or case.meta("company"),
        "logo": _data_uri(logo) if logo else "",
        "generated": datetime.now().astimezone().isoformat(timespec="minutes"),
        "first_activity": times[0] if times else "",
        "last_activity": times[-1] if times else "",
        "findings": findings,
        "total_findings": len(findings),
        "sev_counts": dict(sev_counts),
        "overall": next((s for s in SEVERITIES if sev_counts[s]), "info"),
        "services": services,
        "endpoints": endpoints,
        "notes": notes,
        "scope_in": in_entries,
        "scope_ex": ex_entries,
        "scope_incidents": scope_incidents,
        "hosts": sorted(hosts),
        "tools": tool_counts.most_common(),
        "command_count": len(commands),
        "commands": appendix_cmds,
        "integrity_ok": ok,
        "integrity_problems": problems,
        "chain_head": head[0]["hash"] if head else "",
        "custody_count": head[0]["id"] if head else 0,
        "evidence_files": evidence_files,
        "redacted": case.redact,
    }
    ctx["summary"] = _exec_summary(ctx)
    return ctx


def render_report_html(ctx: dict) -> str:
    return _env(True).get_template("report.html").render(**ctx)


def render_report_md(ctx: dict) -> str:
    md = _env(False).get_template("report.md").render(**ctx)
    return re.sub(r"\n{3,}", "\n\n", md)


def write_pdf(html: str, out: Path, base: Path) -> None:
    from weasyprint import HTML  # optional dependency

    HTML(string=html, base_url=str(base)).write_pdf(str(out))


# ------------------------------------------------------------------ timeline
def build_timeline(case: Case, theme: str = "dark") -> str:
    items = []
    for c in case.rows("SELECT * FROM commands ORDER BY id"):
        items.append({
            "type": "command", "ts": c["started"], "end": c["ended"], "id": c["id"], "tool": c["tool"],
            "targets": json.loads(c["targets"] or "[]"), "command": c["command"], "cwd": c["cwd"],
            "exit": c["exit_code"], "output": c["output"], "truncated": bool(c["truncated"]), "sha": c["sha256"],
        })
    for e in case.rows("SELECT * FROM events ORDER BY id"):
        items.append({"type": e["kind"], "ts": e["ts"], "id": e["id"], "text": e["text"],
                      "targets": [t.strip() for t in (e["target"] or "").split(",") if t.strip()]})
    for s in case.rows("SELECT * FROM shots ORDER BY id"):
        items.append({"type": "shot", "ts": s["ts"], "id": s["id"], "text": s["note"] or "",
                      "targets": [s["target"]] if s["target"] else [], "src": _data_uri(case.dir / s["path"]),
                      "sha": s["sha256"], "command_id": s["command_id"]})
    items.sort(key=lambda x: (x["ts"] or "", x["type"] != "session_start"))
    for it in items:
        it["time"] = _fmt_dt(it["ts"], "%H:%M:%S")
        it["day"] = _fmt_dt(it["ts"], "%a %d %b %Y")
    findings = case.findings()
    ok, problems = verify(case)
    data = {
        "case": case.slug, "name": case.name, "client": case.meta("client"), "scope": case.scope,
        "items": items, "findings": len(findings),
        "sev": {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES},
        "integrity": ok, "problems": problems, "version": __version__,
        "generated": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M"),
    }
    payload = json.dumps(data).replace("</", "<\\/")
    return _env(True).get_template("timeline.html").render(data_json=payload, name=case.name,
                                                          theme=theme, t=THEMES["dark"], tl=THEMES["light"])
