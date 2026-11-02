"""The scope-guard prompt the shell hooks call before running a command.

Kept free of typer/rich imports so it starts fast (it runs inline before commands).
Exit code 0 = let the command run, 1 = block it.
"""

from __future__ import annotations

import os
import sys

from .db import Case, CaseNotFound
from .scope import ScopeError, check

RED = "\033[1;31m"
YEL = "\033[1;33m"
DIM = "\033[2m"
B = "\033[1m"
R = "\033[0m"


def run_check(cmd: str) -> int:
    try:
        case = Case.active()
    except CaseNotFound:
        return 0
    try:
        targets, bad = check(cmd, case.scope)
    except ScopeError as e:
        print(f"{YEL}pwntrail: scope config error: {e}{R}")
        return 0
    if not bad:
        return 0

    mode = (os.environ.get("PWNTRAIL_GUARD") or case.meta("guard", "ask")).lower()
    shown = ", ".join(bad)
    print(f"\n{RED}⚠  OUT OF SCOPE{R}  {B}{shown}{R}")
    print(f"{DIM}   scope: {', '.join(case.scope)}{R}")

    if mode == "log":
        case.event("scope_override", f"Ran out-of-scope command (guard=log): {cmd}", target=shown,
                   ref={"targets": bad})
        return 0
    if mode == "block":
        print(f"{RED}   blocked.{R} Change the scope with: pwntrail scope add <target>\n")
        case.event("scope_block", f"Blocked out-of-scope command: {cmd}", target=shown, ref={"targets": bad})
        return 1

    try:
        sys.stdout.write(f"   Run it anyway? {B}[y/N]{R} ")
        sys.stdout.flush()
        answer = sys.stdin.readline().strip().lower()
    except (KeyboardInterrupt, EOFError):
        answer = ""
    if answer in ("y", "yes"):
        case.event("scope_override", f"Ran out-of-scope command after confirming: {cmd}", target=shown,
                   ref={"targets": bad})
        print()
        return 0
    case.event("scope_block", f"Blocked out-of-scope command: {cmd}", target=shown, ref={"targets": bad})
    print(f"{DIM}   skipped.{R}\n")
    return 1
