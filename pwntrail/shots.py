"""Take a screenshot with whatever tool this system has."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def _candidates(out: Path, select: bool) -> list[list[str]]:
    o = str(out)
    if sys.platform == "darwin":
        return [["screencapture", "-i" if select else "-x", o]]
    wayland = bool(os.environ.get("WAYLAND_DISPLAY"))
    c: list[list[str]] = []
    if wayland:
        if select and shutil.which("slurp") and shutil.which("grim"):
            c.append(["sh", "-c", f'grim -g "$(slurp)" "{o}"'])
        c.append(["grim", o])
        c.append(["spectacle", "-b", "-n", "-r" if select else "-f", "-o", o])
        c.append(["gnome-screenshot", "-a" if select else "", "-f", o])
    c += [
        ["maim", "-s", o] if select else ["maim", o],
        ["scrot", "-s", o] if select else ["scrot", o],
        ["flameshot", "gui", "-p", o] if select else ["flameshot", "full", "-p", o],
        ["xfce4-screenshooter", "-r" if select else "-f", "-s", o],
        ["gnome-screenshot", "-a" if select else "", "-f", o],
        ["spectacle", "-b", "-n", "-r" if select else "-f", "-o", o],
        ["import", o] if select else ["import", "-window", "root", o],
    ]
    return [[a for a in cmd if a] for cmd in c]


def capture(out: Path, select: bool = False) -> str:
    """Capture to `out`. Returns the tool used. Raises RuntimeError if nothing worked."""
    tried = []
    for cmd in _candidates(out, select):
        tool = cmd[0] if cmd[0] != "sh" else "grim+slurp"
        if cmd[0] != "sh" and not shutil.which(cmd[0]):
            continue
        tried.append(tool)
        try:
            subprocess.run(cmd, check=True, timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (subprocess.SubprocessError, OSError):
            continue
        if out.exists() and out.stat().st_size > 0:
            return tool
    if not tried:
        raise RuntimeError("no screenshot tool found. Install one: grim (Wayland), maim or scrot (X11), "
                           "or pass an existing image with --file")
    raise RuntimeError(f"screenshot failed (tried: {', '.join(tried)}). No display? Use --file instead.")
