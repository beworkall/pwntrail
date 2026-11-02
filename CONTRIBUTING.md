# Contributing to PwnTrail

Thanks for helping. Bug reports, new importers, redaction rules and report templates are all welcome.

## Dev setup

```bash
git clone https://github.com/beworkall/pwntrail && cd pwntrail
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,pdf]"
pytest -q
```

Use a throwaway home so you don't touch your real cases:

```bash
export PWNTRAIL_HOME=/tmp/pt-dev
pwntrail new dev --scope 10.10.10.0/24
pwntrail import examples/scans
pwntrail report -F all
```

## Project layout

```
pwntrail/
  cli.py         Typer commands
  recorder.py    pty recorder + per-command output slicing
  hooks.py       bash / zsh hook scripts injected into the recorded shell
  guard.py       scope-guard prompt (kept import-light, it runs before commands)
  scope.py       scope parsing and target extraction
  redact.py      secret redaction
  db.py          SQLite case storage + chain of custody
  importers.py   nmap / nuclei / ffuf / nikto parsers
  kb.py          built-in remediation advice
  report.py      report + timeline context builders
  templates/     report.html, report.md, timeline.html
```

## Adding an importer

1. Add detection to `detect()` in `importers.py`.
2. Write a `_toolname(case, path, imp_id, cmd_id)` parser that calls `case.upsert_finding(...)` with a stable
   `key` so re-imports merge instead of duplicating.
3. Drop a small sample file in `examples/scans/` and add a test in `tests/`.

## Pull requests

- Keep PRs focused on one thing.
- Add or update tests. `pytest -q` must pass.
- Never commit real client data, real credentials or real scan results. Use the lab-style samples.
- Update `CHANGELOG.md` under an `Unreleased` heading.

## Code of conduct

Be respectful. This project is for **authorised** security testing only. Contributions aimed at evading
detection, attacking systems without permission or weakening the scope guard and redaction won't be merged.
