# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-02

First public release.

### Added
- `pwntrail start` / `stop`: pty-based session recorder for bash and zsh that captures every command with its
  output, exit code, working directory and timestamps, sliced per command via invisible OSC markers.
- Scope guard with `ask`, `block` and `log` modes. Supports IPs, CIDRs, ranges, domains, wildcards and
  `!` exclusions. No DNS lookups.
- Automatic redaction of passwords, hashes, tokens, JWTs, private keys and URL credentials, with tool-aware
  rules for hydra, nxc/netexec, crackmapexec, evil-winrm, impacket, mysql, smbclient and xfreerdp.
- SHA-256 hash-chained chain of custody for commands, notes, screenshots, imports and findings, plus
  `pwntrail verify`.
- Importers for nmap XML, nuclei JSONL/JSON, ffuf JSON and nikto XML/JSON with de-duplication, built-in fix
  advice and automatic linking to the command that produced each file.
- Manual findings: `finding add/list/show/edit/link/rm`.
- Notes and screenshots (grim, maim, scrot, flameshot, spectacle, gnome-screenshot, xfce4-screenshooter,
  ImageMagick, macOS screencapture).
- Interactive, self-contained HTML timeline with search, filters and a dark/light toggle.
- Report generator: HTML, Markdown and PDF (via optional WeasyPrint), dark and light themes, custom logo and
  company name.
- `pwntrail export`: zips a case with a SHA-256 manifest.

[0.1.0]: https://github.com/beworkall/pwntrail/releases/tag/v0.1.0
