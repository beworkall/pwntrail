"""Scope guard: figure out which hosts a command touches and whether they're in scope.

Scope entries:
  10.10.10.5            single IP
  10.10.10.0/24         CIDR
  10.10.10.1-50         range (last octet)  /  10.10.10.1-10.10.11.20
  acme.com              domain + all subdomains
  *.acme.com            same as above
  !10.10.10.13          exclusion (wins over everything)
  !dev.acme.com         excluded host (and its subdomains)

No DNS lookups are ever made, so the check is instant and leaks nothing.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, field
from urllib.parse import urlsplit

IPV4 = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
IP_TOKEN = re.compile(rf"^({IPV4})(/\d{{1,2}})?(?::\d{{1,5}})?$")
DOMAIN = re.compile(
    r"^(?:\*\.)?((?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+([a-z][a-z0-9-]{1,62}))\.?(?::\d{1,5})?$",
    re.I,
)
SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)

# Generic TLDs we accept (plus every two-letter country code). Lab TLDs included on purpose.
TLDS = set(
    """
    com net org io co ai dev app edu gov mil int info biz me tv xyz online site tech cloud store
    shop page lan local internal corp htb thm vl test example invalid localdomain home arpa
    academy agency bank blog business center club company digital email finance global group
    host inc link live ltd media network news one pro security services solutions space systems
    team tools web website work world zone name mobi asia jobs travel museum aero coop cat tel
    post health care cafe city tokyo london nyc berlin
    """.split()
)

# Things that look like domains but are almost always files or python modules.
FILE_EXTS = set(
    """
    txt xml json py sh gz zip log html htm php asp aspx jsp js css csv md conf cfg ini yaml yml
    nse rb pl c h go rs exe dll so ko out lst list pcap pcapng nmap gnmap db sqlite key pem crt
    cer ovpn jpg jpeg png gif bak old tar tgz bz2 xz 7z rar deb rpm apk jar war ps1 bat txt
    jsonl tmp swp toml lock env pyc docx xlsx pdf
    """.split()
)

LOOPBACK_V4 = ipaddress.ip_network("127.0.0.0/8")
WRAPPERS = {"sudo", "proxychains", "proxychains4", "time", "nohup", "env", "doas", "torsocks",
            "timeout", "stdbuf", "nice", "command", "exec", "builtin", "unbuffer"}


@dataclass
class Scope:
    nets: list = field(default_factory=list)          # ip_network objects
    ranges: list = field(default_factory=list)        # (start_ip, end_ip)
    domains: list = field(default_factory=list)       # lowercase domains
    ex_nets: list = field(default_factory=list)
    ex_ranges: list = field(default_factory=list)
    ex_domains: list = field(default_factory=list)
    raw: list = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.nets or self.ranges or self.domains)


class ScopeError(ValueError):
    pass


def _parse_range(entry: str):
    a, b = entry.split("-", 1)
    start = ipaddress.ip_address(a.strip())
    b = b.strip()
    if b.isdigit() and start.version == 4:
        parts = str(start).split(".")
        end = ipaddress.ip_address(".".join(parts[:3] + [b]))
    else:
        end = ipaddress.ip_address(b)
    if int(end) < int(start):
        raise ScopeError(f"bad range: {entry}")
    return start, end


def parse_scope(entries: list[str]) -> Scope:
    s = Scope(raw=list(entries))
    for raw in entries:
        for item in re.split(r"[,\s]+", raw.strip()):
            if not item:
                continue
            exclude = item.startswith("!")
            e = item[1:] if exclude else item
            nets, ranges, doms = (s.ex_nets, s.ex_ranges, s.ex_domains) if exclude else (s.nets, s.ranges, s.domains)
            try:
                if "-" in e and re.match(r"^[0-9a-f.:]+-[0-9a-f.:]+$", e, re.I):
                    ranges.append(_parse_range(e))
                    continue
                nets.append(ipaddress.ip_network(e, strict=False))
                continue
            except ValueError:
                pass
            d = e.lower().lstrip("*.").rstrip(".")
            if DOMAIN.match(d) or re.match(r"^[a-z0-9_-]+$", d):
                doms.append(d)
            else:
                raise ScopeError(f"can't understand scope entry: {item}")
    return s


def _host_from_token(tok: str) -> str | None:
    tok = tok.strip().strip("'\"()[]{}<>;")
    if not tok or tok.startswith("-"):
        return None
    if SCHEME.match(tok):
        try:
            host = urlsplit(tok).hostname
        except ValueError:
            return None
        return host.lower() if host else None
    if "@" in tok:
        tok = tok.rsplit("@", 1)[1]
    # impacket style: domain/user:pass@host already handled; strip smb style \\host\share
    if tok.startswith("\\\\"):
        tok = tok[2:].split("\\", 1)[0]
    m = IP_TOKEN.match(tok)
    if m:
        return m.group(1) + (m.group(2) or "")
    if "/" in tok:
        return None  # a file path
    m = DOMAIN.match(tok)
    if m:
        host, tld = m.group(1).lower(), m.group(2).lower()
        if tld in FILE_EXTS:
            return None
        if tld in TLDS or (len(tld) == 2 and tld.isalpha()):
            return host
    return None


def tokenize(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def tool_of(command: str) -> str:
    toks = tokenize(command)
    i = 0
    while i < len(toks):
        t = toks[i]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t):  # FOO=bar cmd
            i += 1
            continue
        base = t.rsplit("/", 1)[-1]
        if base in WRAPPERS:
            i += 1
            # skip wrapper flags like `timeout 30` / `sudo -u root`
            while i < len(toks) and (toks[i].startswith("-") or toks[i].isdigit()):
                i += 1
            continue
        return base
    return ""


def extract_targets(command: str) -> list[str]:
    toks = tokenize(command)
    if toks and toks[0].rsplit("/", 1)[-1] == "pwntrail":
        return []
    found: list[str] = []
    for tok in toks:
        pieces = re.split(r"[=,|;&]", tok)
        for p in pieces:
            h = _host_from_token(p)
            if h and h not in found:
                found.append(h)
    return found


def _ip_in(ip, nets, ranges) -> bool:
    if any(ip.version == n.version and ip in n for n in nets):
        return True
    return any(ip.version == a.version and int(a) <= int(ip) <= int(b) for a, b in ranges)


def _net_in(net, nets, ranges) -> bool:
    if any(net.version == n.version and net.subnet_of(n) for n in nets):
        return True
    return any(net.version == a.version and int(a) <= int(net.network_address)
               and int(net.broadcast_address) <= int(b) for a, b in ranges)


def _dom_in(host: str, doms) -> bool:
    return any(host == d or host.endswith("." + d) for d in doms)


def in_scope(target: str, scope: Scope) -> bool:
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            if net.version == 4 and net.subnet_of(LOOPBACK_V4):
                return True
            if any(net.version == n.version and net.overlaps(n) for n in scope.ex_nets):
                return False
            return _net_in(net, scope.nets, scope.ranges)
        ip = ipaddress.ip_address(target)
        if ip.is_loopback or ip.is_unspecified:
            return True
        if _ip_in(ip, scope.ex_nets, scope.ex_ranges):
            return False
        return _ip_in(ip, scope.nets, scope.ranges)
    except ValueError:
        pass
    host = target.lower()
    if host in ("localhost",):
        return True
    if _dom_in(host, scope.ex_domains):
        return False
    return _dom_in(host, scope.domains)


def check(command: str, scope_entries: list[str]) -> tuple[list[str], list[str]]:
    """Return (all_targets, out_of_scope_targets). Empty scope = guard disabled."""
    targets = extract_targets(command)
    scope = parse_scope(scope_entries)
    if scope.empty:
        return targets, []
    return targets, [t for t in targets if not in_scope(t, scope)]
