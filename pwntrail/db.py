"""Case storage: one SQLite file per engagement plus an evidence folder.

Every piece of evidence (command output, screenshot, imported scan, note) is also
written into a hash-chained custody log, so any later edit to the database or the
evidence files is detectable with `pwntrail verify`.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from . import paths

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY, started TEXT, ended TEXT, shell TEXT, transcript TEXT
);
CREATE TABLE IF NOT EXISTS commands (
  id INTEGER PRIMARY KEY, session_id INTEGER, started TEXT, ended TEXT, cwd TEXT,
  command TEXT, tool TEXT, targets TEXT, exit_code INTEGER, output TEXT,
  truncated INTEGER DEFAULT 0, sha256 TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts TEXT, kind TEXT, text TEXT, target TEXT, ref TEXT
);
CREATE TABLE IF NOT EXISTS shots (
  id INTEGER PRIMARY KEY, ts TEXT, path TEXT, sha256 TEXT, note TEXT, target TEXT, command_id INTEGER
);
CREATE TABLE IF NOT EXISTS imports (
  id INTEGER PRIMARY KEY, ts TEXT, path TEXT, original TEXT, kind TEXT, sha256 TEXT,
  command_id INTEGER, summary TEXT
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY, key TEXT UNIQUE, title TEXT, severity TEXT, target TEXT,
  description TEXT, remediation TEXT, refs TEXT, source TEXT, import_id INTEGER,
  evidence TEXT, cvss TEXT, status TEXT DEFAULT 'open', created TEXT, extra TEXT
);
CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY, host TEXT, hostname TEXT, port INTEGER, proto TEXT, state TEXT,
  service TEXT, product TEXT, version TEXT, import_id INTEGER, UNIQUE(host, port, proto)
);
CREATE TABLE IF NOT EXISTS endpoints (
  id INTEGER PRIMARY KEY, url TEXT UNIQUE, status INTEGER, length INTEGER, words INTEGER,
  import_id INTEGER
);
CREATE TABLE IF NOT EXISTS custody (
  id INTEGER PRIMARY KEY, ts TEXT, action TEXT, ref TEXT, content_sha TEXT,
  prev_hash TEXT, hash TEXT
);
"""

GENESIS = "0" * 64
SEVERITIES = ["critical", "high", "medium", "low", "info"]


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_text(s: str) -> str:
    return sha256_bytes(s.encode("utf-8", "replace"))


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def chain_hash(prev: str, ts: str, action: str, ref: str, content_sha: str) -> str:
    return sha256_text("|".join([prev, ts, action, ref, content_sha]))


def command_digest(command: str, output: str, exit_code: Any) -> str:
    return sha256_text(f"{command}\x00{output}\x00{exit_code}")


class CaseNotFound(Exception):
    pass


class Case:
    def __init__(self, slug: str):
        self.slug = slug
        self.dir = paths.case_dir(slug)
        self.db_path = self.dir / "case.db"
        if not self.db_path.exists():
            raise CaseNotFound(slug)
        self.conn = sqlite3.connect(str(self.db_path), timeout=10)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)

    # ---------- lifecycle ----------
    @classmethod
    def create(cls, name: str, scope: list[str], client: str = "", tester: str = "",
               redact: bool = True) -> "Case":
        slug = paths.slugify(name)
        d = paths.case_dir(slug)
        if (d / "case.db").exists():
            raise FileExistsError(slug)
        for sub in ("evidence/shots", "evidence/imports", "evidence/sessions", "reports"):
            (d / sub).mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(d / "case.db"))
        conn.executescript(SCHEMA)
        conn.close()
        case = cls(slug)
        case.set_meta("name", name)
        case.set_meta("client", client or name)
        case.set_meta("tester", tester)
        case.set_meta("created", now())
        case.set_meta("scope", json.dumps(scope))
        case.set_meta("redact", "1" if redact else "0")
        case.custody("case_created", slug, sha256_text(json.dumps({"name": name, "scope": scope})))
        return case

    @classmethod
    def active(cls) -> "Case":
        slug = paths.get_active()
        if not slug:
            raise CaseNotFound("no active case")
        return cls(slug)

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self.conn:
            yield self.conn

    # ---------- meta ----------
    def set_meta(self, key: str, value: str) -> None:
        with self.tx() as c:
            c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, value))

    def meta(self, key: str, default: str = "") -> str:
        r = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return r["value"] if r else default

    @property
    def name(self) -> str:
        return self.meta("name", self.slug)

    @property
    def scope(self) -> list[str]:
        return json.loads(self.meta("scope", "[]"))

    @scope.setter
    def scope(self, entries: list[str]) -> None:
        self.set_meta("scope", json.dumps(entries))
        self.custody("scope_changed", "scope", sha256_text(json.dumps(entries)))

    @property
    def redact(self) -> bool:
        return self.meta("redact", "1") == "1"

    # ---------- custody chain ----------
    def custody(self, action: str, ref: str, content_sha: str) -> str:
        with self.tx() as c:
            last = c.execute("SELECT hash FROM custody ORDER BY id DESC LIMIT 1").fetchone()
            prev = last["hash"] if last else GENESIS
            ts = now()
            h = chain_hash(prev, ts, action, ref, content_sha)
            c.execute(
                "INSERT INTO custody(ts, action, ref, content_sha, prev_hash, hash) VALUES (?,?,?,?,?,?)",
                (ts, action, ref, content_sha, prev, h),
            )
        return h

    # ---------- sessions & commands ----------
    def start_session(self, shell: str, transcript: str) -> int:
        with self.tx() as c:
            cur = c.execute("INSERT INTO sessions(started, shell, transcript) VALUES (?,?,?)",
                            (now(), shell, transcript))
            sid = cur.lastrowid
        self.event("session_start", f"Recording started ({Path(shell).name})", ref={"session": sid})
        return sid

    def end_session(self, sid: int) -> None:
        with self.tx() as c:
            c.execute("UPDATE sessions SET ended=? WHERE id=?", (now(), sid))
        row = self.conn.execute("SELECT transcript FROM sessions WHERE id=?", (sid,)).fetchone()
        tpath = self.dir / row["transcript"] if row and row["transcript"] else None
        if tpath and tpath.exists():
            self.custody("transcript", f"session:{sid}", sha256_file(tpath))
        self.event("session_end", "Recording stopped", ref={"session": sid})

    def add_command(self, session_id: int | None, started: str, ended: str, cwd: str,
                    command: str, tool: str, targets: list[str], exit_code: int | None,
                    output: str, truncated: bool) -> int:
        digest = command_digest(command, output, exit_code)
        with self.tx() as c:
            cur = c.execute(
                "INSERT INTO commands(session_id, started, ended, cwd, command, tool, targets,"
                " exit_code, output, truncated, sha256) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (session_id, started, ended, cwd, command, tool, json.dumps(targets), exit_code,
                 output, int(truncated), digest),
            )
            cid = cur.lastrowid
        self.custody("command", f"command:{cid}", digest)
        return cid

    def last_command_id(self) -> int | None:
        r = self.conn.execute("SELECT id FROM commands ORDER BY id DESC LIMIT 1").fetchone()
        return r["id"] if r else None

    # ---------- events / notes ----------
    def event(self, kind: str, text: str, target: str = "", ref: dict | None = None) -> int:
        ts = now()
        with self.tx() as c:
            cur = c.execute("INSERT INTO events(ts, kind, text, target, ref) VALUES (?,?,?,?,?)",
                            (ts, kind, text, target, json.dumps(ref or {})))
            eid = cur.lastrowid
        if kind in ("note", "scope_override", "scope_block"):
            self.custody(kind, f"event:{eid}", sha256_text(f"{ts}|{kind}|{text}|{target}"))
        return eid

    # ---------- evidence files ----------
    def store_file(self, src: Path, sub: str, name: str | None = None) -> tuple[str, str]:
        dest_dir = self.dir / "evidence" / sub
        dest_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        dest = dest_dir / f"{stamp}_{name or src.name}"
        i = 1
        while dest.exists():
            dest = dest_dir / f"{stamp}_{i}_{name or src.name}"
            i += 1
        shutil.copy2(src, dest)
        return str(dest.relative_to(self.dir)), sha256_file(dest)

    def add_shot(self, src: Path, note: str = "", target: str = "") -> int:
        rel, digest = self.store_file(src, "shots")
        cid = self.last_command_id()
        with self.tx() as c:
            cur = c.execute("INSERT INTO shots(ts, path, sha256, note, target, command_id) VALUES (?,?,?,?,?,?)",
                            (now(), rel, digest, note, target, cid))
            sid = cur.lastrowid
        self.custody("screenshot", f"shot:{sid}", digest)
        return sid

    # ---------- findings ----------
    def upsert_finding(self, f: dict) -> tuple[int, bool]:
        """Insert a finding, or merge into the existing one with the same key. Returns (id, created)."""
        existing = self.conn.execute("SELECT * FROM findings WHERE key=?", (f["key"],)).fetchone()
        if existing:
            ev = json.loads(existing["evidence"] or "{}")
            new_ev = f.get("evidence") or {}
            for k, v in new_ev.items():
                merged = list(dict.fromkeys((ev.get(k) or []) + list(v)))
                ev[k] = merged
            extra = json.loads(existing["extra"] or "{}")
            for k, v in (f.get("extra") or {}).items():
                if isinstance(v, list):
                    extra[k] = list(dict.fromkeys((extra.get(k) or []) + v))
                else:
                    extra.setdefault(k, v)
            with self.tx() as c:
                c.execute("UPDATE findings SET evidence=?, extra=? WHERE id=?",
                          (json.dumps(ev), json.dumps(extra), existing["id"]))
            return existing["id"], False
        sev = (f.get("severity") or "info").lower()
        if sev not in SEVERITIES:
            sev = "info"
        with self.tx() as c:
            cur = c.execute(
                "INSERT INTO findings(key, title, severity, target, description, remediation, refs,"
                " source, import_id, evidence, cvss, created, extra) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (f["key"], f["title"], sev, f.get("target", ""), f.get("description", ""),
                 f.get("remediation", ""), json.dumps(f.get("refs") or []), f.get("source", "manual"),
                 f.get("import_id"), json.dumps(f.get("evidence") or {}), f.get("cvss", ""), now(),
                 json.dumps(f.get("extra") or {})),
            )
            fid = cur.lastrowid
        self.custody("finding", f"finding:{fid}", sha256_text(json.dumps(f, sort_keys=True, default=str)))
        return fid, True

    def findings(self) -> list[sqlite3.Row]:
        order = " ".join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(SEVERITIES))
        return self.conn.execute(
            f"SELECT * FROM findings WHERE status != 'removed' ORDER BY CASE severity {order} END, id"
        ).fetchall()

    # ---------- generic ----------
    def rows(self, sql: str, *args: Any) -> list[sqlite3.Row]:
        return self.conn.execute(sql, args).fetchall()


def verify(case: Case) -> tuple[bool, list[str]]:
    """Re-walk the custody chain and recompute every evidence hash."""
    problems: list[str] = []
    prev = GENESIS
    rows = case.rows("SELECT * FROM custody ORDER BY id")
    for r in rows:
        if r["prev_hash"] != prev:
            problems.append(f"custody #{r['id']}: chain broken (entry removed or reordered)")
        expect = chain_hash(r["prev_hash"], r["ts"], r["action"], r["ref"], r["content_sha"])
        if expect != r["hash"]:
            problems.append(f"custody #{r['id']}: entry was modified")
        prev = r["hash"]

    custody_by_ref = {r["ref"]: r["content_sha"] for r in rows}

    for c in case.rows("SELECT * FROM commands"):
        d = command_digest(c["command"], c["output"], c["exit_code"])
        if d != c["sha256"] or custody_by_ref.get(f"command:{c['id']}") != d:
            problems.append(f"command #{c['id']}: content does not match its recorded hash")
    for s in case.rows("SELECT * FROM shots"):
        p = case.dir / s["path"]
        if not p.exists():
            problems.append(f"screenshot #{s['id']}: file missing ({s['path']})")
        elif sha256_file(p) != s["sha256"] or custody_by_ref.get(f"shot:{s['id']}") != s["sha256"]:
            problems.append(f"screenshot #{s['id']}: file was altered")
    for i in case.rows("SELECT * FROM imports"):
        p = case.dir / i["path"]
        if not p.exists():
            problems.append(f"import #{i['id']}: file missing ({i['path']})")
        elif sha256_file(p) != i["sha256"] or custody_by_ref.get(f"import:{i['id']}") != i["sha256"]:
            problems.append(f"import #{i['id']}: file was altered")
    for e in case.rows("SELECT * FROM events WHERE kind IN ('note','scope_override','scope_block')"):
        d = sha256_text(f"{e['ts']}|{e['kind']}|{e['text']}|{e['target']}")
        if custody_by_ref.get(f"event:{e['id']}") != d:
            problems.append(f"{e['kind']} #{e['id']}: content does not match its recorded hash")
    for s in case.rows("SELECT * FROM sessions WHERE ended IS NOT NULL"):
        ref = f"session:{s['id']}"
        p = case.dir / (s["transcript"] or "")
        if ref in custody_by_ref and p.is_file() and sha256_file(p) != custody_by_ref[ref]:
            problems.append(f"session #{s['id']}: transcript was altered")
    return (not problems), problems
