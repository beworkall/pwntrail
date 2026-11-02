"""Where PwnTrail keeps its cases on disk."""

from __future__ import annotations

import os
import re
from pathlib import Path


def home() -> Path:
    base = os.environ.get("PWNTRAIL_HOME")
    p = Path(base).expanduser() if base else Path.home() / ".pwntrail"
    p.mkdir(parents=True, exist_ok=True)
    return p


def cases_dir() -> Path:
    p = home() / "cases"
    p.mkdir(parents=True, exist_ok=True)
    return p


def slugify(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", name.strip()).strip("-.").lower()
    if not s:
        raise ValueError("case name must contain letters or numbers")
    return s[:64]


def case_dir(slug: str) -> Path:
    return cases_dir() / slug


def active_file() -> Path:
    return home() / "active"


def get_active() -> str | None:
    # A running recorded session always wins, so commands inside it hit the right case.
    env = os.environ.get("PWNTRAIL_CASE")
    if env:
        return env
    f = active_file()
    if f.exists():
        v = f.read_text().strip()
        return v or None
    return None


def set_active(slug: str) -> None:
    active_file().write_text(slug + "\n")


def list_cases() -> list[str]:
    return sorted(p.name for p in cases_dir().iterdir() if (p / "case.db").exists())
