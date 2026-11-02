"""Built-in fix advice for common findings, used when the scanner gives none."""

from __future__ import annotations

# (keywords that must ALL appear, suggested severity or None, remediation)
KB: list[tuple[tuple[str, ...], str | None, str]] = [
    (("sql", "injection"), "high",
     "Use parameterised queries / prepared statements everywhere user input reaches the database. "
     "Never build SQL with string concatenation. Apply least-privilege to the database account."),
    (("cross-site scripting",), "medium",
     "Encode output for the context it lands in (HTML, attribute, JS, URL). Validate input and add a "
     "strict Content-Security-Policy as defence in depth."),
    (("xss",), "medium",
     "Encode output for the context it lands in (HTML, attribute, JS, URL). Validate input and add a "
     "strict Content-Security-Policy as defence in depth."),
    (("remote code execution",), "critical",
     "Patch or upgrade the affected component immediately. Restrict network access to it until patched."),
    (("command injection",), "critical",
     "Never pass user input to a shell. Use safe APIs with argument arrays and strict allow-lists."),
    (("default", "credential"), "high",
     "Change all default credentials, enforce a strong password policy and enable MFA where possible."),
    (("default", "login"), "high",
     "Change all default credentials, enforce a strong password policy and enable MFA where possible."),
    ((".git",), "high",
     "Block web access to the .git directory and remove it from the web root. Rotate any secrets that "
     "were ever committed to the repository."),
    ((".env",), "high",
     "Remove .env files from the web root, block dotfiles at the web server, and rotate every secret it contained."),
    (("directory", "listing"), "medium",
     "Disable directory listing on the web server (Options -Indexes on Apache, autoindex off on nginx)."),
    (("directory", "indexing"), "medium",
     "Disable directory listing on the web server (Options -Indexes on Apache, autoindex off on nginx)."),
    (("phpinfo",), "medium",
     "Remove phpinfo() pages from production; they leak paths, versions and configuration."),
    (("server-status",), "medium",
     "Restrict /server-status to localhost or trusted admin IPs, or disable mod_status."),
    (("backup",), "medium",
     "Remove backup and archive files from the web root and block common backup extensions."),
    (("swagger",), "low",
     "Restrict API documentation endpoints to internal users, or require authentication."),
    (("actuator",), "medium",
     "Disable or authenticate Spring Boot actuator endpoints; expose only /health if needed."),
    (("x-frame-options",), "low",
     "Send X-Frame-Options: DENY (or a frame-ancestors CSP directive) to prevent clickjacking."),
    (("clickjacking",), "low",
     "Send X-Frame-Options: DENY (or a frame-ancestors CSP directive) to prevent clickjacking."),
    (("strict-transport-security",), "low",
     "Enable HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains."),
    (("content-security-policy",), "low",
     "Define a Content-Security-Policy that restricts script sources to trusted origins."),
    (("x-content-type-options",), "low",
     "Send X-Content-Type-Options: nosniff on all responses."),
    (("missing", "header"), "low",
     "Add the recommended security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, "
     "Referrer-Policy) at the web server or application layer."),
    (("cookie", "httponly"), "low",
     "Set the HttpOnly and Secure flags (and SameSite) on session cookies."),
    (("cookie", "secure"), "low",
     "Set the Secure and HttpOnly flags (and SameSite) on session cookies."),
    (("tls",), None,
     "Disable SSLv3/TLS 1.0/1.1 and weak ciphers; allow TLS 1.2+ with modern AEAD cipher suites only."),
    (("ssl",), None,
     "Disable SSLv3/TLS 1.0/1.1 and weak ciphers; allow TLS 1.2+ with modern AEAD cipher suites only."),
    (("certificate",), "low",
     "Replace the certificate with a valid one from a trusted CA, matching the hostname, and monitor expiry."),
    (("smb", "signing"), "medium",
     "Require SMB signing on all hosts (Group Policy: Microsoft network server: Digitally sign communications (always))."),
    (("smbv1",), "high",
     "Disable SMBv1 on every host; it is obsolete and exploitable (e.g. MS17-010)."),
    (("ms17-010",), "critical",
     "Apply MS17-010 patches immediately and disable SMBv1."),
    (("anonymous", "ftp"), "medium",
     "Disable anonymous FTP access, or restrict it to a read-only directory with no sensitive files."),
    (("open redirect",), "low",
     "Only redirect to relative paths or an allow-list of destinations; never trust a URL parameter as-is."),
    (("cors",), "medium",
     "Do not reflect arbitrary Origins; allow-list trusted origins and never combine * with credentials."),
    (("outdated",), "medium",
     "Upgrade the component to a supported version and subscribe to its security advisories."),
    (("version", "disclosure"), "info",
     "Hide detailed version banners (ServerTokens Prod / server_tokens off) to slow down reconnaissance."),
    (("server", "banner"), "info",
     "Hide detailed version banners (ServerTokens Prod / server_tokens off) to slow down reconnaissance."),
    (("trace",), "low",
     "Disable the HTTP TRACE method at the web server."),
    (("admin",), "medium",
     "Restrict administrative interfaces to a VPN or trusted IPs and require strong authentication with MFA."),
]

GENERIC_FIX = ("Validate the issue, apply the vendor's patch or configuration fix, and re-test. "
               "Restrict exposure of the affected service to only the networks that need it.")


def advise(text: str) -> tuple[str, str | None]:
    """Return (remediation, suggested_severity) for a finding's title + description."""
    t = text.lower()
    for keys, sev, fix in KB:
        if all(k in t for k in keys):
            return fix, sev
    return GENERIC_FIX, None
