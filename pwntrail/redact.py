"""Mask passwords, tokens and keys before anything is written to the case file."""

from __future__ import annotations

import re

from .scope import tool_of

MASK = "[REDACTED]"
_Q = r"""(?:"[^"]*"|'[^']*'|[^\s"']+)"""

GENERIC = [
    # PEM private keys (multi-line)
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), MASK),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), MASK),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"), MASK),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), MASK),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), MASK),
    (re.compile(r"\b[rs]k_live_[0-9A-Za-z]{16,}\b"), MASK),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED JWT]"),
    # Authorization headers
    (re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic|token|negotiate|ntlm)\s+)[A-Za-z0-9._~+/=-]+"),
     r"\1" + MASK),
    # creds inside URLs: scheme://user:pass@host
    (re.compile(r"([a-z][a-z0-9+.-]*://[^\s:/@]+):([^\s@/]+)@", re.I), r"\1:" + MASK + "@"),
    # key=value / key: value
    (re.compile(r"(?i)\b(\w*(?:password|passwd|passwort|pwd|secret|api[_-]?key|access[_-]?token|"
                r"auth[_-]?token|client[_-]?secret|private[_-]?key)\w*)(\s*[=:]\s*)" + _Q),
     r"\1\2" + MASK),
    # impacket style  DOMAIN/user:pass@host
    (re.compile(r"\b([\w.-]+/[\w.$-]+):([^@\s]+)@"), r"\1:" + MASK + "@"),
]

# tools where -p is a literal password (not a port or a file)
PASSWORD_FLAG_TOOLS = {"hydra", "medusa", "nxc", "netexec", "crackmapexec", "cme", "evil-winrm",
                       "smbmap", "sshpass", "kerbrute", "rpcclient", "winrm", "ncrack", "patator",
                       "bloodhound-python", "certipy", "certipy-ad", "ldapsearch", "mssqlclient.py",
                       "impacket-mssqlclient", "sqsh", "enum4linux", "enum4linux-ng"}
HASH_FLAG_TOOLS = {"nxc", "netexec", "crackmapexec", "cme", "evil-winrm", "smbmap", "certipy",
                   "certipy-ad"}


def redact_command(cmd: str) -> str:
    tool = tool_of(cmd)
    out = cmd
    if tool in PASSWORD_FLAG_TOOLS:
        out = re.sub(r"(\s-(?:p|w)\s+)" + _Q, r"\1" + MASK, out)
        out = re.sub(r"(\s--pass(?:word)?[=\s]+)" + _Q, r"\1" + MASK, out)
    if tool in HASH_FLAG_TOOLS:
        out = re.sub(r"(\s-H\s+)" + _Q, r"\1" + MASK, out)
        out = re.sub(r"(\s--hashes?[=\s]+)" + _Q, r"\1" + MASK, out)
    if tool in ("mysql", "mariadb", "mysqldump"):
        out = re.sub(r"(\s-p)(?!\s)\S+", r"\1" + MASK, out)
    if tool in ("smbclient", "rpcclient", "net"):
        out = re.sub(r"(-U\s*\S*?%)" + _Q, r"\1" + MASK, out)
    if tool in ("xfreerdp", "xfreerdp3", "wlfreerdp"):
        out = re.sub(r"(/p:)" + _Q, r"\1" + MASK, out)
    return redact_text(out)


def redact_text(text: str) -> str:
    for rx, repl in GENERIC:
        text = rx.sub(repl, text)
    return text
