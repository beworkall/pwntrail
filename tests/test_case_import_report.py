import json
import sqlite3
from pathlib import Path

from pwntrail.db import Case, verify
from pwntrail.importers import import_path
from pwntrail.recorder import Recorder, clean_output
from pwntrail.report import build_context, build_timeline, render_report_html, render_report_md

SCANS = Path(__file__).resolve().parent.parent / "examples" / "scans"


def _case():
    return Case.create("Acme Web", ["10.10.10.0/24", "acme.htb"], client="Acme Corp", tester="tester")


def test_create_and_custody_chain():
    c = _case()
    c.add_command(None, "t0", "t1", "/tmp", "nmap 10.10.10.5", "nmap", ["10.10.10.5"], 0, "22/tcp open", False)
    c.event("note", "found ssh")
    ok, problems = verify(c)
    assert ok, problems


def test_tampering_is_detected():
    c = _case()
    cid = c.add_command(None, "t0", "t1", "/tmp", "id", "id", [], 0, "uid=1000", False)
    raw = sqlite3.connect(c.db_path)
    raw.execute("UPDATE commands SET output='uid=0(root)' WHERE id=?", (cid,))
    raw.commit()
    ok, problems = verify(c)
    assert not ok and any("command" in p for p in problems)


def test_deleting_custody_entry_breaks_chain():
    c = _case()
    for i in range(3):
        c.event("note", f"n{i}")
    raw = sqlite3.connect(c.db_path)
    raw.execute("DELETE FROM custody WHERE id=2")
    raw.commit()
    ok, problems = verify(c)
    assert not ok and any("chain broken" in p for p in problems)


def test_import_all_formats_and_dedupe():
    c = _case()
    c.add_command(None, "t0", "t1", "/tmp", "nmap -sC -sV -oX nmap-10.10.10.5.xml 10.10.10.5", "nmap",
                  ["10.10.10.5"], 0, "...", False)
    results = dict((p.name, r) for p, r in import_path(c, SCANS))
    assert results["nmap-10.10.10.5.xml"]["services"] == 4
    assert results["nmap-10.10.10.5.xml"]["linked_command"] == 1
    assert results["nuclei-web01.jsonl"]["merged"] == 1  # duplicate CVE match merged
    titles = {f["title"] for f in c.findings()}
    assert "Exposed .git directory" in titles
    assert any("SambaCry" in t for t in titles)
    crit = [f for f in c.findings() if f["severity"] == "critical"]
    assert len(crit) == 2
    # re-importing merges instead of duplicating
    n = len(c.findings())
    import_path(c, SCANS)
    assert len(c.findings()) == n
    assert verify(c)[0]


def test_reports_render():
    c = _case()
    import_path(c, SCANS)
    ctx = build_context(c)
    html = render_report_html(ctx)
    md = render_report_md(ctx)
    assert "Penetration Test Report" in html and "F-01" in html
    assert "## 3. Findings" in md
    assert ctx["sev_counts"]["critical"] == 2
    light = render_report_html(build_context(c, theme="light", include_info=False))
    assert "#ffffff" in light
    tl = build_timeline(c)
    data = json.loads(tl.split('type="application/json">')[1].split("</script>")[0].replace("<\\/", "</"))
    assert data["integrity"] is True and any(i["type"] == "import" for i in data["items"])


def test_clean_output_handles_colors_and_progress():
    raw = b"\x1b[32mok\x1b[0m\r\n10%\r50%\r100%\r\nab\x08c\r\n"
    assert clean_output(raw) == "ok\n100%\nac"


def test_recorder_slices_output_by_markers():
    c = _case()
    rec = Recorder(c, "/bin/bash")
    rec._emit = lambda data: rec.current and rec.current.feed(data)  # no terminal in tests
    import base64

    def mark(s):
        return b"\x1b]7777;" + s.encode() + b"\x07"

    cmd = base64.b64encode(b"curl -H 'Authorization: Bearer s3cr3t' http://10.10.10.5").decode()
    cwd = base64.b64encode(b"/root").decode()
    stream = b"prompt$ " + mark(f"S;{cmd};{cwd}") + b"hello\r\nworld\r\n" + mark("E;7") + b"prompt$ "
    # feed in tiny chunks to exercise partial-marker handling
    for i in range(0, len(stream), 3):
        rec.feed(stream[i:i + 3])
    row = c.rows("SELECT * FROM commands")[0]
    assert row["output"] == "hello\nworld"
    assert row["exit_code"] == 7
    assert "s3cr3t" not in row["command"]
    assert json.loads(row["targets"]) == ["10.10.10.5"]
