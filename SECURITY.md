# Security Policy

PwnTrail stores sensitive engagement data, so security bugs in it matter.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through [GitHub Security Advisories](https://github.com/beworkall/pwntrail/security/advisories/new)
or by email to **beworkall07@gmail.com** with:

- a description of the issue and its impact
- steps to reproduce (a minimal case file or command sequence helps)
- the PwnTrail version and your OS / shell

You will get an acknowledgement within 72 hours and a fix or mitigation plan as soon as possible.

## Things that count as security bugs

- Secrets that slip past redaction into the case database, transcripts or reports
- Ways to modify recorded evidence without `pwntrail verify` detecting it
- Code execution or file writes triggered by importing a malicious scan file
- HTML/script injection in the generated report or timeline
- The scope guard being bypassed by a command it should have caught

## Handling your own data

Case folders (`~/.pwntrail/cases/`) contain client data. Encrypt the disk they live on, never commit them to
git, and share them only through `pwntrail export` over a secure channel.
