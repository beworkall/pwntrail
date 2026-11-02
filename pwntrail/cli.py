"""PwnTrail command line."""

from __future__ import annotations

import json
import os
import signal
import sys
import uuid
import webbrowser
import zipfile
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.markup import escape as E
from rich.panel import Panel
from rich.table import Table

from . import __version__, paths
from .db import SEVERITIES, Case, CaseNotFound, sha256_file, verify
from .scope import ScopeError, parse_scope

app = typer.Typer(
    name="pwntrail",
    help="Record your pentest while you hack. Get the evidence timeline and the report for free.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)
scope_app = typer.Typer(help="Show or change the engagement scope.", no_args_is_help=True)
finding_app = typer.Typer(help="Add, edit and list findings.", no_args_is_help=True)
app.add_typer(scope_app, name="scope")
app.add_typer(finding_app, name="finding")

con = Console()
err = Console(stderr=True)
ACCENT = "#ff3b5c"
SEV_STYLE = {"critical": "bold white on #c8102e", "high": "bold black on #ff7a1a", "medium": "bold black on #ffc21a",
             "low": "bold black on #3ea6ff", "info": "bold black on #8a93a6"}


def fail(msg: str, code: int = 1) -> None:
    err.print(f"[bold {ACCENT}]✖[/] {msg}")
    raise typer.Exit(code)


def ok(msg: str) -> None:
    con.print(f"[bold green]✔[/] {msg}")


def open_case(name: Optional[str] = None) -> Case:
    try:
        if name:
            return Case(paths.slugify(name))
        return Case.active()
    except CaseNotFound:
        if name:
            fail(f"no case called [bold]{name}[/]. See [bold]pwntrail list[/].")
        fail("no active case. Create one with [bold]pwntrail new <name> --scope <targets>[/]")
    raise AssertionError


def sev_badge(s: str) -> str:
    return f"[{SEV_STYLE.get(s, '')}] {s.upper()} [/]"


def short_ts(iso: str | None) -> str:
    if not iso:
        return ""
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%d %b %H:%M:%S")
    except ValueError:
        return iso


def _split_scope(values: List[str]) -> List[str]:
    out: List[str] = []
    for v in values:
        out += [x for x in v.replace(",", " ").split() if x]
    return out


def version_cb(value: bool) -> None:
    if value:
        con.print(f"pwntrail {__version__}")
        raise typer.Exit()


@app.callback()
def _root(version: bool = typer.Option(False, "--version", "-V", callback=version_cb, is_eager=True,
                                       help="Show the version and exit.")) -> None:
    pass


# ======================================================================= cases
@app.command()
def new(
    name: str = typer.Argument(..., help="Case name, e.g. acme-external"),
    scope: List[str] = typer.Option([], "--scope", "-s", help="Targets in scope: IPs, CIDRs, ranges, domains. "
                                    "Prefix with ! to exclude. Comma separated or repeat the flag."),
    client: str = typer.Option("", "--client", help="Client name shown on the report."),
    tester: str = typer.Option("", "--tester", help="Your name or handle."),
    company: str = typer.Option("", "--company", help="Your company / brand on the report."),
    guard: str = typer.Option("ask", "--guard", help="Out-of-scope behaviour: ask, block or log."),
    no_redact: bool = typer.Option(False, "--no-redact", help="Store secrets as typed (not recommended)."),
) -> None:
    """Create a new engagement and make it the active case."""
    entries = _split_scope(scope)
    try:
        parse_scope(entries)
    except ScopeError as e:
        fail(str(e))
    if guard not in ("ask", "block", "log"):
        fail("--guard must be ask, block or log")
    try:
        case = Case.create(name, entries, client=client, tester=tester, redact=not no_redact)
    except FileExistsError:
        fail(f"case [bold]{paths.slugify(name)}[/] already exists. Switch to it with [bold]pwntrail use {name}[/]")
    except ValueError as e:
        fail(str(e))
    case.set_meta("guard", guard)
    if company:
        case.set_meta("company", company)
    paths.set_active(case.slug)
    ok(f"case [bold]{case.slug}[/] created and active")
    if entries:
        con.print(f"  scope: [bold]{', '.join(entries)}[/]  ·  guard: {guard}")
    else:
        con.print("  [yellow]no scope set, the scope guard is off.[/] Add targets with [bold]pwntrail scope add <target>[/]")
    con.print("  next: [bold]pwntrail start[/] to begin recording")


@app.command("list")
def list_cases() -> None:
    """List all cases."""
    active = paths.get_active()
    cases = paths.list_cases()
    if not cases:
        con.print("No cases yet. Create one with [bold]pwntrail new <name> --scope <targets>[/]")
        return
    t = Table(box=None, header_style="dim")
    t.add_column("")
    t.add_column("case", style="bold")
    t.add_column("client")
    t.add_column("cmds", justify="right")
    t.add_column("findings", justify="right")
    t.add_column("created")
    for slug in cases:
        c = Case(slug)
        n_cmd = c.rows("SELECT COUNT(*) n FROM commands")[0]["n"]
        n_f = len(c.findings())
        t.add_row(f"[{ACCENT}]●[/]" if slug == active else "", slug, E(c.meta("client")), str(n_cmd), str(n_f),
                  short_ts(c.meta("created")))
        c.close()
    con.print(t)


@app.command()
def use(name: str = typer.Argument(..., help="Case to switch to.")) -> None:
    """Switch the active case."""
    case = open_case(name)
    paths.set_active(case.slug)
    ok(f"active case is now [bold]{case.slug}[/]")


@app.command()
def status() -> None:
    """Show the active case, its scope and what's been recorded."""
    case = open_case()
    q = lambda sql: case.rows(sql)[0]["n"]  # noqa: E731
    rec = os.environ.get("PWNTRAIL_SESSION")
    sev = {s: 0 for s in SEVERITIES}
    for f in case.findings():
        sev[f["severity"]] += 1
    n_cmd = q("SELECT COUNT(*) n FROM commands")
    n_note = q("SELECT COUNT(*) n FROM events WHERE kind='note'")
    n_shot = q("SELECT COUNT(*) n FROM shots")
    n_imp = q("SELECT COUNT(*) n FROM imports")
    body = (
        f"[bold]{E(case.name)}[/]  [dim]({case.slug})[/]\n"
        f"client   {E(case.meta('client'))}\n"
        f"scope    {', '.join(case.scope) or '[yellow]not set (guard off)[/]'}\n"
        f"guard    {case.meta('guard', 'ask')}   redaction {'on' if case.redact else '[yellow]off[/]'}\n"
        f"status   {'[bold ' + ACCENT + ']● recording[/]' if rec else 'not recording'}\n\n"
        f"commands {n_cmd}   notes {n_note}   shots {n_shot}   imports {n_imp}\n"
        f"findings " + "  ".join(f"{sev_badge(s)} {n}" for s, n in sev.items())
    )
    con.print(Panel(body, title="pwntrail", title_align="left", border_style=ACCENT))


# ======================================================================= recording
@app.command()
def start(shell: Optional[str] = typer.Option(None, "--shell", help="Shell to record (bash or zsh). "
                                                                     "Defaults to $SHELL.")) -> None:
    """Start recording: opens your shell with every command and its output captured."""
    if os.environ.get("PWNTRAIL_SESSION"):
        fail("already recording. Type [bold]exit[/] to stop this session first.")
    if not sys.stdin.isatty():
        fail("pwntrail start needs an interactive terminal.")
    if os.name != "posix":
        fail("recording needs Linux or macOS. On Windows, run PwnTrail inside WSL.")
    case = open_case()
    from .recorder import Recorder

    before = case.last_command_id() or 0
    rec = Recorder(case, shell)
    rec.run()
    n = case.rows("SELECT COUNT(*) n FROM commands WHERE id > ?", before)[0]["n"]
    con.print(f"\n[bold {ACCENT}]■[/] recording stopped · [bold]{n}[/] command{'s' if n != 1 else ''} saved to "
              f"case [bold]{case.slug}[/]")
    con.print("  next: [bold]pwntrail import <scan files>[/], [bold]pwntrail timeline --open[/], "
              "[bold]pwntrail report --open[/]")


@app.command()
def stop() -> None:
    """Stop the current recording (same as typing exit)."""
    if not os.environ.get("PWNTRAIL_SESSION"):
        fail("not recording right now.")
    con.print(f"[bold {ACCENT}]■[/] stopping…")
    os.kill(os.getppid(), signal.SIGHUP)


@app.command()
def note(
    text: List[str] = typer.Argument(..., help="The note."),
    target: str = typer.Option("", "--target", "-t", help="Host the note is about."),
) -> None:
    """Add a timestamped note to the timeline."""
    case = open_case()
    msg = " ".join(text)
    if case.redact:
        from .redact import redact_text

        msg = redact_text(msg)
    eid = case.event("note", msg, target=target)
    ok(f"note #{eid} saved")


@app.command()
def shot(
    note_: str = typer.Option("", "--note", "-n", help="Caption for the screenshot."),
    target: str = typer.Option("", "--target", "-t", help="Host it shows."),
    select: bool = typer.Option(False, "--select", "-s", help="Pick a region instead of the full screen."),
    file: Optional[Path] = typer.Option(None, "--file", "-f", exists=True, dir_okay=False,
                                        help="Add an existing image instead of taking a screenshot."),
) -> None:
    """Take a screenshot (or add an image) as evidence, linked to the last command."""
    case = open_case()
    if file:
        src = file
    else:
        from .shots import capture

        tmp = paths.home() / "run" / f"shot-{uuid.uuid4().hex[:8]}.png"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        try:
            tool = capture(tmp, select=select)
        except RuntimeError as e:
            fail(str(e))
        src = tmp
    sid = case.add_shot(src, note=note_, target=target)
    if not file:
        src.unlink(missing_ok=True)
    case.event("shot", note_ or f"Screenshot #{sid}", target=target, ref={"shot": sid})
    ok(f"screenshot #{sid} saved{'' if file else f' ({tool})'}")


# ======================================================================= evidence
@app.command("import")
def import_(paths_: List[Path] = typer.Argument(..., help="Scan files or folders (nmap XML, nuclei JSONL, "
                                                          "ffuf JSON, nikto XML/JSON).", exists=True)) -> None:
    """Import scanner output: findings are de-duplicated and linked to the command that made them."""
    from .importers import import_path

    case = open_case()
    any_ok = False
    for p in paths_:
        for f, res in import_path(case, p):
            if isinstance(res, str):
                con.print(f"[yellow]–[/] {E(str(f))}: {E(res)}")
                continue
            any_ok = True
            bits = ", ".join(f"{v} {k}" for k, v in res.items() if isinstance(v, int) and k != "linked_command" and v)
            link = f" · linked to command #{res['linked_command']}" if res.get("linked_command") else ""
            con.print(f"[bold green]✔[/] {E(f.name)} [dim]({res['kind']})[/] {bits or 'nothing new'}{link}")
    if not any_ok:
        fail("nothing imported. Supported: nmap -oX, nuclei -jsonl, ffuf -of json, nikto -Format xml/json")


@app.command()
def log(
    n: int = typer.Option(25, "-n", help="How many recent commands to show."),
    all_: bool = typer.Option(False, "--all", "-a", help="Show every command."),
    tool: str = typer.Option("", "--tool", help="Only commands from this tool."),
) -> None:
    """List recorded commands."""
    case = open_case()
    sql = "SELECT * FROM commands" + (" WHERE tool = ?" if tool else "") + " ORDER BY id DESC"
    rows = case.rows(sql, *( [tool] if tool else [] ))
    if not all_:
        rows = rows[:n]
    rows = list(reversed(rows))
    if not rows:
        con.print("No commands recorded yet. Start with [bold]pwntrail start[/]")
        return
    t = Table(box=None, header_style="dim", pad_edge=False)
    t.add_column("#", justify="right", style="dim")
    t.add_column("time", style="dim")
    t.add_column("command", overflow="fold")
    t.add_column("exit", justify="right")
    for r in rows:
        code = r["exit_code"]
        t.add_row(str(r["id"]), short_ts(r["started"]), E(r["command"]),
                  "" if code is None else (f"[red]{code}[/]" if code else "[green]0[/]"))
    con.print(t)


@app.command()
def show(command_id: int = typer.Argument(..., help="Command number from pwntrail log.")) -> None:
    """Show a recorded command with its full output."""
    case = open_case()
    r = case.rows("SELECT * FROM commands WHERE id=?", command_id)
    if not r:
        fail(f"no command #{command_id}")
    r = r[0]
    con.print(f"[dim]#{r['id']} · {short_ts(r['started'])} → {short_ts(r['ended'])} · {E(r['cwd'] or '')} · "
              f"exit {r['exit_code']}[/]")
    con.print(f"[bold {ACCENT}]$[/] [bold]{E(r['command'])}[/]")
    con.print(r["output"] or "[dim](no output)[/]", markup=False, highlight=False)
    con.print(f"[dim]sha256 {r['sha256']}[/]")


# ======================================================================= scope
@scope_app.command("show")
def scope_show() -> None:
    """Print the scope."""
    case = open_case()
    if not case.scope:
        con.print("[yellow]No scope set. The scope guard is off.[/]")
        return
    for e in case.scope:
        con.print(f"  [red]✖ exclude[/] {e[1:]}" if e.startswith("!") else f"  [green]✔[/] {e}")
    con.print(f"[dim]guard: {case.meta('guard', 'ask')}[/]")


@scope_app.command("add")
def scope_add(entries: List[str] = typer.Argument(..., help="Targets to add (prefix ! to exclude).")) -> None:
    """Add targets (or !exclusions) to the scope."""
    case = open_case()
    new_entries = case.scope + [e for e in _split_scope(entries) if e not in case.scope]
    try:
        parse_scope(new_entries)
    except ScopeError as e:
        fail(str(e))
    case.scope = new_entries
    ok(f"scope: {', '.join(new_entries)}")


@scope_app.command("rm")
def scope_rm(entries: List[str] = typer.Argument(..., help="Entries to remove, exactly as listed.")) -> None:
    """Remove entries from the scope."""
    case = open_case()
    drop = set(_split_scope(entries))
    case.scope = [e for e in case.scope if e not in drop]
    ok(f"scope: {', '.join(case.scope) or '(empty, guard off)'}")


@scope_app.command("guard")
def scope_guard(mode: str = typer.Argument(..., help="ask, block or log")) -> None:
    """Set what happens on an out-of-scope command: ask (default), block, or log only."""
    if mode not in ("ask", "block", "log"):
        fail("mode must be ask, block or log")
    case = open_case()
    case.set_meta("guard", mode)
    ok(f"scope guard set to [bold]{mode}[/]")


# ======================================================================= findings
def _ids(values: List[str]) -> List[int]:
    out = []
    for v in values:
        for p in v.replace(",", " ").split():
            if p.isdigit():
                out.append(int(p))
    return out


def _check_ids(case: Case, cmd_ids: List[int], shot_ids: List[int]) -> None:
    for i in cmd_ids:
        if not case.rows("SELECT id FROM commands WHERE id=?", i):
            fail(f"no command #{i} (see pwntrail log)")
    for i in shot_ids:
        if not case.rows("SELECT id FROM shots WHERE id=?", i):
            fail(f"no screenshot #{i}")


@finding_app.command("add")
def finding_add(
    title: Optional[str] = typer.Option(None, "--title", "-t"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="critical, high, medium, low, info"),
    target: Optional[str] = typer.Option(None, "--target"),
    desc: Optional[str] = typer.Option(None, "--desc", "-d", help="What the issue is and its impact."),
    fix: Optional[str] = typer.Option(None, "--fix", "-f", help="How to remediate."),
    cmd: List[str] = typer.Option([], "--cmd", "-c", help="Evidence command numbers (see pwntrail log)."),
    shot_: List[str] = typer.Option([], "--shot", help="Evidence screenshot numbers."),
    ref: List[str] = typer.Option([], "--ref", "-r", help="Reference URL. Repeatable."),
    cvss: str = typer.Option("", "--cvss"),
) -> None:
    """Add a manual finding (asks for anything you leave out)."""
    from .kb import advise

    case = open_case()
    interactive = sys.stdin.isatty()
    if not title:
        title = typer.prompt("Title") if interactive else fail("--title is required")
    if not severity:
        severity = typer.prompt("Severity (critical/high/medium/low/info)", default="medium") if interactive else "medium"
    severity = severity.lower()
    if severity not in SEVERITIES:
        fail(f"severity must be one of: {', '.join(SEVERITIES)}")
    last = case.last_command_id()
    if target is None:
        guess = ""
        if last:
            t = json.loads(case.rows("SELECT targets FROM commands WHERE id=?", last)[0]["targets"] or "[]")
            guess = t[0] if t else ""
        target = typer.prompt("Target", default=guess) if interactive else guess
    if desc is None:
        desc = typer.prompt("Description", default="") if interactive else ""
    if fix is None:
        suggested, _ = advise(f"{title} {desc}")
        fix = typer.prompt("Remediation", default=suggested) if interactive else suggested
    cmd_ids = _ids(cmd)
    if not cmd_ids and last and interactive:
        row = case.rows("SELECT command FROM commands WHERE id=?", last)[0]
        if typer.confirm(f"Attach last command #{last} ({row['command'][:60]}) as evidence?", default=True):
            cmd_ids = [last]
    shot_ids = _ids(shot_)
    if not shot_ids and interactive:
        ls = case.rows("SELECT id, note FROM shots ORDER BY id DESC LIMIT 1")
        if ls and typer.confirm(f"Attach last screenshot #{ls[0]['id']}?", default=False):
            shot_ids = [ls[0]["id"]]
    _check_ids(case, cmd_ids, shot_ids)
    fid, _ = case.upsert_finding({
        "key": f"manual:{uuid.uuid4().hex}", "title": title, "severity": severity, "target": target,
        "description": desc, "remediation": fix, "refs": ref, "source": "manual", "cvss": cvss,
        "evidence": {"commands": cmd_ids, "shots": shot_ids},
    })
    ok(f"finding #{fid} added {sev_badge(severity)} {E(title)}")


@finding_app.command("list")
def finding_list(min_sev: str = typer.Option("info", "--min", help="Lowest severity to show.")) -> None:
    """List findings, worst first."""
    case = open_case()
    if min_sev not in SEVERITIES:
        fail(f"--min must be one of: {', '.join(SEVERITIES)}")
    limit = SEVERITIES.index(min_sev)
    rows = [f for f in case.findings() if SEVERITIES.index(f["severity"]) <= limit]
    if not rows:
        con.print("No findings yet. Import scans with [bold]pwntrail import[/] or add one with [bold]pwntrail finding add[/]")
        return
    t = Table(box=None, header_style="dim")
    t.add_column("#", justify="right", style="dim")
    t.add_column("severity")
    t.add_column("title", overflow="fold")
    t.add_column("target", style="dim")
    t.add_column("source", style="dim")
    t.add_column("evidence", justify="right", style="dim")
    for f in rows:
        ev = json.loads(f["evidence"] or "{}")
        n_ev = len(ev.get("commands") or []) + len(ev.get("shots") or [])
        t.add_row(str(f["id"]), sev_badge(f["severity"]), E(f["title"]), E(f["target"] or ""), f["source"], str(n_ev or ""))
    con.print(t)


@finding_app.command("show")
def finding_show(fid: int = typer.Argument(...)) -> None:
    """Show one finding in full."""
    case = open_case()
    r = case.rows("SELECT * FROM findings WHERE id=?", fid)
    if not r:
        fail(f"no finding #{fid}")
    f = r[0]
    ev = json.loads(f["evidence"] or "{}")
    extra = json.loads(f["extra"] or "{}")
    lines = [f"{sev_badge(f['severity'])} [bold]{E(f['title'])}[/]",
             f"[dim]target[/] {E(f['target'] or '')}   [dim]source[/] {f['source']}   [dim]status[/] {f['status']}"]
    if f["cvss"]:
        lines.append(f"[dim]cvss[/] {f['cvss']}")
    if f["description"]:
        lines += ["", E(f["description"])]
    if extra.get("matched_at"):
        lines += ["", "[dim]affected[/]"] + [f"  {E(str(m))}" for m in extra["matched_at"][:10]]
    lines += ["", "[dim]remediation[/]", E(f["remediation"] or "-")]
    if ev.get("commands") or ev.get("shots"):
        lines += ["", f"[dim]evidence[/] commands {ev.get('commands') or '-'}  shots {ev.get('shots') or '-'}"]
    con.print(Panel("\n".join(lines), title=f"finding #{f['id']}", title_align="left", border_style=ACCENT))


@finding_app.command("edit")
def finding_edit(
    fid: int = typer.Argument(...),
    title: Optional[str] = typer.Option(None, "--title", "-t"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s"),
    target: Optional[str] = typer.Option(None, "--target"),
    desc: Optional[str] = typer.Option(None, "--desc", "-d"),
    fix: Optional[str] = typer.Option(None, "--fix", "-f"),
    cvss: Optional[str] = typer.Option(None, "--cvss"),
) -> None:
    """Change a finding's title, severity, target, description, fix or CVSS."""
    case = open_case()
    if not case.rows("SELECT id FROM findings WHERE id=?", fid):
        fail(f"no finding #{fid}")
    changes = {"title": title, "severity": severity, "target": target, "description": desc,
               "remediation": fix, "cvss": cvss}
    changes = {k: v for k, v in changes.items() if v is not None}
    if not changes:
        fail("nothing to change. Pass --title, --severity, --target, --desc, --fix or --cvss")
    if "severity" in changes:
        changes["severity"] = changes["severity"].lower()
        if changes["severity"] not in SEVERITIES:
            fail(f"severity must be one of: {', '.join(SEVERITIES)}")
    with case.tx() as c:
        c.execute(f"UPDATE findings SET {', '.join(k + '=?' for k in changes)} WHERE id=?", (*changes.values(), fid))
    from .db import sha256_text

    case.custody("finding_edit", f"finding:{fid}", sha256_text(json.dumps(changes, sort_keys=True)))
    ok(f"finding #{fid} updated ({', '.join(changes)})")


@finding_app.command("link")
def finding_link(
    fid: int = typer.Argument(...),
    cmd: List[str] = typer.Option([], "--cmd", "-c", help="Command numbers to attach."),
    shot_: List[str] = typer.Option([], "--shot", help="Screenshot numbers to attach."),
) -> None:
    """Attach more evidence (commands, screenshots) to a finding."""
    case = open_case()
    r = case.rows("SELECT evidence FROM findings WHERE id=?", fid)
    if not r:
        fail(f"no finding #{fid}")
    if not cmd and not shot_:
        fail("pass --cmd and/or --shot")
    cmd_ids, shot_ids = _ids(cmd), _ids(shot_)
    _check_ids(case, cmd_ids, shot_ids)
    ev = json.loads(r[0]["evidence"] or "{}")
    ev["commands"] = list(dict.fromkeys((ev.get("commands") or []) + cmd_ids))
    ev["shots"] = list(dict.fromkeys((ev.get("shots") or []) + shot_ids))
    with case.tx() as c:
        c.execute("UPDATE findings SET evidence=? WHERE id=?", (json.dumps(ev), fid))
    ok(f"finding #{fid} evidence: commands {ev['commands'] or '-'}, shots {ev['shots'] or '-'}")


@finding_app.command("rm")
def finding_rm(fid: int = typer.Argument(...)) -> None:
    """Remove a finding from the report (kept in the audit trail)."""
    case = open_case()
    if not case.rows("SELECT id FROM findings WHERE id=?", fid):
        fail(f"no finding #{fid}")
    with case.tx() as c:
        c.execute("UPDATE findings SET status='removed' WHERE id=?", (fid,))
    from .db import sha256_text

    case.custody("finding_removed", f"finding:{fid}", sha256_text(str(fid)))
    ok(f"finding #{fid} removed from the report")


# ======================================================================= outputs
def _open(path: Path) -> None:
    url = path.resolve().as_uri()
    if os.environ.get("WSL_DISTRO_NAME"):
        os.system(f"wslview '{path}' >/dev/null 2>&1 || explorer.exe \"$(wslpath -w '{path}')\" >/dev/null 2>&1")
    else:
        webbrowser.open(url)


@app.command()
def timeline(
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Where to write the HTML."),
    open_: bool = typer.Option(False, "--open", help="Open it in your browser."),
    theme: str = typer.Option("dark", "--theme", help="dark or light"),
) -> None:
    """Build the interactive evidence timeline (one self-contained HTML file)."""
    from .report import build_timeline

    case = open_case()
    path = out or case.dir / "reports" / "timeline.html"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_timeline(case, theme=theme), encoding="utf-8")
    ok(f"timeline → {path}")
    if open_:
        _open(path)


@app.command()
def report(
    fmt: List[str] = typer.Option(["html"], "--format", "-F", help="html, md, pdf or all. Repeatable."),
    pdf: bool = typer.Option(False, "--pdf", help="Shortcut for --format pdf."),
    theme: str = typer.Option("dark", "--theme", help="dark or light"),
    company: str = typer.Option("", "--company", help="Your company / brand on the cover."),
    logo: Optional[Path] = typer.Option(None, "--logo", exists=True, dir_okay=False, help="Logo image for the cover."),
    no_info: bool = typer.Option(False, "--no-info", help="Leave informational findings out."),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Output folder."),
    open_: bool = typer.Option(False, "--open", help="Open the report when done."),
) -> None:
    """Generate the pentest report."""
    from .report import build_context, render_report_html, render_report_md, write_pdf

    case = open_case()
    if theme not in ("dark", "light"):
        fail("--theme must be dark or light")
    formats = {f.lower() for v in fmt for f in v.replace(",", " ").split()}
    if pdf:
        formats.add("pdf")
    if "all" in formats:
        formats = {"html", "md", "pdf"}
    if pdf and fmt == ["html"]:
        formats = {"pdf"}
    bad = formats - {"html", "md", "pdf"}
    if bad:
        fail(f"unknown format: {', '.join(bad)}")
    ctx = build_context(case, theme=theme, company=company, logo=logo, include_info=not no_info)
    folder = out or case.dir / "reports"
    folder.mkdir(parents=True, exist_ok=True)
    stem = f"{case.slug}-report-{datetime.now().strftime('%Y%m%d')}"
    written: list[Path] = []
    html = render_report_html(ctx)
    if "html" in formats:
        p = folder / f"{stem}.html"
        p.write_text(html, encoding="utf-8")
        written.append(p)
    if "md" in formats:
        p = folder / f"{stem}.md"
        p.write_text(render_report_md(ctx), encoding="utf-8")
        written.append(p)
    if "pdf" in formats:
        p = folder / f"{stem}.pdf"
        try:
            write_pdf(html, p, case.dir)
            written.append(p)
        except ImportError:
            err.print("[yellow]PDF needs WeasyPrint:[/] pipx inject pwntrail weasyprint  "
                      "[dim](or open the HTML report and print to PDF)[/]")
    if not ctx["integrity_ok"]:
        err.print(f"[bold {ACCENT}]warning:[/] evidence integrity check FAILED, it is stated in the report. "
                  "Run [bold]pwntrail verify[/] for details.")
    for p in written:
        ok(f"{p.suffix[1:].upper():4} → {p}")
    c = ctx["sev_counts"]
    con.print(f"  {ctx['total_findings']} findings · " + " ".join(f"{sev_badge(s)} {c[s]}" for s in SEVERITIES if c[s]))
    if open_ and written:
        _open(written[0])


@app.command(name="verify")
def verify_cmd() -> None:
    """Check that no evidence was modified since it was recorded."""
    case = open_case()
    good, problems = verify(case)
    n = case.rows("SELECT COUNT(*) n FROM custody")[0]["n"]
    if good:
        ok(f"evidence intact · {n} custody entries verified")
        return
    err.print(f"[bold {ACCENT}]✖ evidence integrity FAILED[/]")
    for p in problems:
        err.print(f"  - {p}")
    raise typer.Exit(1)


@app.command()
def export(out: Optional[Path] = typer.Option(None, "--out", "-o", help="Zip file to write.")) -> None:
    """Pack the whole case (database, evidence, reports) into a zip with a SHA-256 manifest."""
    case = open_case()
    case.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    dest = out or Path.cwd() / f"{case.slug}-evidence-{datetime.now().strftime('%Y%m%d-%H%M')}.zip"
    files = sorted(p for p in case.dir.rglob("*") if p.is_file() and not p.name.endswith(("-wal", "-shm")))
    manifest = "\n".join(f"{sha256_file(p)}  {p.relative_to(case.dir)}" for p in files) + "\n"
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for p in files:
            z.write(p, f"{case.slug}/{p.relative_to(case.dir)}")
        z.writestr(f"{case.slug}/MANIFEST.sha256", manifest)
    ok(f"exported {len(files)} files → {dest}")
    con.print(f"  [dim]zip sha256 {sha256_file(dest)}[/]")


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:
        err.print("\ninterrupted")
        sys.exit(130)
