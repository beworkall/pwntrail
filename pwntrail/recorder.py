"""Records a shell session through a pseudo-terminal.

The user's shell runs inside a pty we own. Everything it prints flows through
us: we pass it to the real terminal untouched (minus our invisible markers),
append it to the raw session transcript, and slice it per command using the
markers the shell hooks emit.
"""

from __future__ import annotations

import base64
import errno
import fcntl
import os
import pty
import re
import select
import shutil
import signal
import sys
import termios
import tty
from pathlib import Path

from . import hooks, paths
from .db import Case, now
from .redact import redact_command, redact_text
from .scope import extract_targets, tool_of

MARK = b"\x1b]7777;"
BEL = b"\x07"
ALT_SCREEN = b"\x1b[?1049h"

HEAD_CAP = 4 * 1024 * 1024     # raw bytes kept from the start of a command's output
TAIL_CAP = 2 * 1024 * 1024     # raw bytes kept from the end
TEXT_CAP = 1024 * 1024         # cleaned text stored per command

ANSI = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"      # OSC
    r"|\x1b\[[0-9;?<=>!]*[ -/]*[@-~]"           # CSI
    r"|\x1b[PX^_][^\x1b]*\x1b\\"                # DCS/SOS/PM/APC
    r"|\x1b[@-Z\\-_]"                           # 2-char escapes
    r"|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"        # stray control chars (keeps \t \n \r)
)


def clean_output(raw: bytes) -> str:
    """Turn raw terminal bytes into readable text: no colors, no progress-bar spam."""
    text = raw.decode("utf-8", "replace")
    # apply backspaces before stripping control chars
    while "\b" in text:
        new = re.sub(r"[^\n\x08]\x08", "", text)
        if new == text:
            break
        text = new
    text = text.replace("\b", "")
    text = ANSI.sub("", text.replace("\r\n", "\n"))
    lines = []
    for line in text.split("\n"):
        if "\r" in line:  # carriage-return redraws (progress bars): keep the final state
            parts = [p for p in line.split("\r") if p.strip()]
            line = parts[-1] if parts else ""
        lines.append(line.rstrip())
    out = "\n".join(lines).strip("\n")
    return out


class _CommandCapture:
    def __init__(self, command: str, cwd: str):
        self.command = command
        self.cwd = cwd
        self.started = now()
        self.head = bytearray()
        self.tail = bytearray()
        self.dropped = 0
        self.alt_screen = False

    def feed(self, data: bytes) -> None:
        if ALT_SCREEN in data:
            self.alt_screen = True
        room = HEAD_CAP - len(self.head)
        if room > 0:
            self.head += data[:room]
            data = data[room:]
        if data:
            self.tail += data
            if len(self.tail) > TAIL_CAP:
                cut = len(self.tail) - TAIL_CAP
                self.dropped += cut
                del self.tail[:cut]

    def text(self) -> tuple[str, bool]:
        if self.alt_screen:
            return "[full-screen interactive program: output not captured here, see the session transcript]", False
        truncated = bool(self.tail)
        body = clean_output(bytes(self.head))
        if self.tail:
            body += f"\n\n[... {self.dropped + len(self.tail)} bytes omitted ...]\n\n" if self.dropped else "\n"
            body += clean_output(bytes(self.tail))
        if len(body) > TEXT_CAP:
            half = TEXT_CAP // 2
            body = body[:half] + "\n\n[... output truncated ...]\n\n" + body[-half:]
            truncated = True
        return body, truncated


def _b64(s: str) -> str:
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return ""


def _partial_suffix(buf: bytes, marker: bytes) -> int:
    """Length of the longest suffix of buf that is a prefix of marker."""
    for n in range(min(len(marker) - 1, len(buf)), 0, -1):
        if buf.endswith(marker[:n]):
            return n
    return 0


class Recorder:
    def __init__(self, case: Case, shell: str | None = None):
        self.case = case
        self.shell = shell or os.environ.get("SHELL") or "/bin/bash"
        self.kind = Path(self.shell).name
        if self.kind not in ("bash", "zsh"):
            fallback = shutil.which("bash") or "/bin/bash"
            print(f"pwntrail: {self.kind} isn't supported yet, recording with bash instead.", file=sys.stderr)
            self.shell, self.kind = fallback, "bash"
        self.pending = b""
        self.current: _CommandCapture | None = None
        self.session_id: int | None = None
        self.transcript = None
        self.run_dir: Path | None = None

    # ---------- marker handling ----------
    def _emit(self, data: bytes) -> None:
        if not data:
            return
        _write_all(sys.stdout.fileno(), data)
        if self.transcript:
            self.transcript.write(data)
        if self.current:
            self.current.feed(data)

    def _marker(self, payload: bytes) -> None:
        parts = payload.decode("ascii", "replace").split(";")
        kind = parts[0]
        if kind == "S" and len(parts) >= 3:
            if self.current:  # previous command never got its end marker
                self._finish(None)
            cmd, cwd = _b64(parts[1]), _b64(parts[2])
            self.current = _CommandCapture(cmd, cwd)
            if self.transcript:
                self.transcript.write(f"\n\x1b[2m### {self.current.started}  $ {cmd}\x1b[0m\n".encode())
        elif kind == "E" and self.current:
            try:
                code = int(parts[1]) if len(parts) > 1 else None
            except ValueError:
                code = None
            self._finish(code)

    def _finish(self, exit_code: int | None) -> None:
        cap = self.current
        self.current = None
        if cap is None or cap.command.strip() in ("", "exit", "logout"):
            return
        output, truncated = cap.text()
        if self.kind == "zsh":
            # zsh prints its PROMPT_SP end-of-line mark (% or #) before precmd runs
            lines = output.split("\n")
            if lines and lines[-1].strip() in ("%", "#"):
                output = "\n".join(lines[:-1]).rstrip("\n")
        command = cap.command
        targets = extract_targets(command)
        if self.case.redact:
            command = redact_command(command)
            output = redact_text(output)
        self.case.add_command(self.session_id, cap.started, now(), cap.cwd, command,
                              tool_of(cap.command), targets, exit_code, output, truncated)

    def feed(self, data: bytes) -> None:
        buf = self.pending + data
        self.pending = b""
        while buf:
            i = buf.find(MARK)
            if i == -1:
                keep = _partial_suffix(buf, MARK)
                self._emit(buf[: len(buf) - keep] if keep else buf)
                self.pending = buf[len(buf) - keep:] if keep else b""
                return
            self._emit(buf[:i])
            j = buf.find(BEL, i)
            if j == -1:
                if len(buf) - i > 65536:  # not really ours, flush it
                    self._emit(buf[i:])
                else:
                    self.pending = buf[i:]
                return
            self._marker(buf[i + len(MARK): j])
            buf = buf[j + 1:]

    # ---------- shell setup ----------
    def _prepare(self) -> tuple[list[str], dict]:
        self.run_dir = paths.home() / "run" / f"{self.case.slug}-{os.getpid()}"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ)
        env.update({
            "PWNTRAIL_CASE": self.case.slug,
            "PWNTRAIL_SESSION": str(self.session_id),
            "PWNTRAIL_PY": sys.executable,
        })
        if self.kind == "zsh":
            (self.run_dir / ".zshenv").write_text(hooks.ZSH_ENV)
            (self.run_dir / ".zshrc").write_text(hooks.zsh_rc())
            if os.environ.get("ZDOTDIR"):
                env["PWNTRAIL_ORIG_ZDOTDIR"] = os.environ["ZDOTDIR"]
            env["ZDOTDIR"] = str(self.run_dir)
            argv = [self.shell, "-i"]
        else:
            rc = self.run_dir / "bashrc"
            rc.write_text(hooks.bash_rc())
            argv = [self.shell, "--rcfile", str(rc), "-i"]
        return argv, env

    # ---------- main loop ----------
    def run(self) -> int:
        rel = f"evidence/sessions/session-{now()[:19].replace(':', '').replace('-', '')}.log"
        tpath = self.case.dir / rel
        tpath.parent.mkdir(parents=True, exist_ok=True)
        self.session_id = self.case.start_session(self.shell, rel)
        self.transcript = open(tpath, "ab", buffering=0)
        argv, env = self._prepare()

        pid, fd = pty.fork()
        if pid == 0:  # child
            try:
                os.execvpe(argv[0], argv, env)
            finally:
                os._exit(127)

        stdin_fd = sys.stdin.fileno()
        is_tty = os.isatty(stdin_fd)
        old_attr = termios.tcgetattr(stdin_fd) if is_tty else None

        def resize(*_):
            if is_tty:
                try:
                    size = fcntl.ioctl(stdin_fd, termios.TIOCGWINSZ, b"\0" * 8)
                    fcntl.ioctl(fd, termios.TIOCSWINSZ, size)
                except OSError:
                    pass

        resize()
        old_winch = signal.signal(signal.SIGWINCH, resize)
        status = 0
        try:
            if is_tty:
                tty.setraw(stdin_fd)
            stdin_open = True
            while True:
                rfds = [fd] + ([stdin_fd] if stdin_open else [])
                try:
                    r, _, _ = select.select(rfds, [], [])
                except InterruptedError:
                    continue
                if fd in r:
                    try:
                        data = os.read(fd, 65536)
                    except OSError as e:
                        if e.errno in (errno.EIO, errno.EBADF):
                            break
                        raise
                    if not data:
                        break
                    self.feed(data)
                if stdin_open and stdin_fd in r:
                    data = os.read(stdin_fd, 65536)
                    if not data:
                        stdin_open = False
                    else:
                        _write_all(fd, data)
        finally:
            if self.pending:
                self._emit(self.pending)
                self.pending = b""
            if old_attr is not None:
                termios.tcsetattr(stdin_fd, termios.TCSAFLUSH, old_attr)
            signal.signal(signal.SIGWINCH, old_winch)
            try:
                _, st = os.waitpid(pid, 0)
                status = os.waitstatus_to_exitcode(st) if hasattr(os, "waitstatus_to_exitcode") else 0
            except ChildProcessError:
                pass
            if self.current:
                self._finish(None)
            self.transcript.close()
            self.case.end_session(self.session_id)
            if self.run_dir:
                shutil.rmtree(self.run_dir, ignore_errors=True)
        return status


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        try:
            n = os.write(fd, view)
        except InterruptedError:
            continue
        except BlockingIOError:
            select.select([], [fd], [])
            continue
        view = view[n:]
