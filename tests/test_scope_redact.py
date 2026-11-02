import pytest

from pwntrail.redact import redact_command, redact_text
from pwntrail.scope import ScopeError, check, extract_targets, parse_scope, tool_of

SCOPE = ["10.10.10.0/24", "acme.com", "!10.10.10.13", "!dev.acme.com", "192.168.5.1-20"]


@pytest.mark.parametrize("cmd,bad", [
    ("nmap -sV -p 80,443 10.10.10.5", []),
    ("nmap 10.10.11.5", ["10.10.11.5"]),
    ("ffuf -u http://app.acme.com/FUZZ -w /usr/share/wordlists/dirb/common.txt", []),
    ("curl https://dev.acme.com/x", ["dev.acme.com"]),
    ("gobuster dir -u https://evil.org", ["evil.org"]),
    ("ssh root@192.168.5.10", []),
    ("ssh root@192.168.5.30", ["192.168.5.30"]),
    ("nxc smb 10.10.10.13 -u a -p b", ["10.10.10.13"]),
    ("nmap 10.10.10.0/16", ["10.10.10.0/16"]),
    ("ping 127.0.0.1", []),
    ("curl http://10.10.10.5:8080/admin", []),
])
def test_scope_check(cmd, bad):
    assert check(cmd, SCOPE)[1] == bad


def test_files_and_modules_are_not_targets():
    assert extract_targets("python3 -m http.server 8000") == []
    assert extract_targets("cat notes.txt scan.xml report.json") == []
    assert extract_targets("pwntrail note 'checked github.com'") == []


def test_lab_tlds_detected():
    assert extract_targets("evil-winrm -i dc01.corp.htb -u admin") == ["dc01.corp.htb"]


def test_empty_scope_disables_guard():
    assert check("nmap 8.8.8.8", [])[1] == []


def test_bad_scope_entry():
    with pytest.raises(ScopeError):
        parse_scope(["not a ~~ target"])


def test_tool_of_skips_wrappers():
    assert tool_of("sudo -E proxychains nmap 10.0.0.1") == "nmap"
    assert tool_of("FOO=1 timeout 30 ffuf -u x") == "ffuf"


@pytest.mark.parametrize("cmd,secret", [
    ("hydra -l admin -p Winter2026! ssh://10.10.10.5", "Winter2026!"),
    ("nxc smb 10.10.10.5 -u admin -p 'P@ss w' -H aad3b435b51404ee", "aad3b435b51404ee"),
    ("curl -H 'Authorization: Bearer abc.def.ghi' https://acme.com", "abc.def.ghi"),
    ("curl https://bob:hunter2@acme.com/", "hunter2"),
    ("impacket-psexec ACME/admin:Passw0rd@10.10.10.5", "Passw0rd"),
    ("mysql -u root -pS3cret -h 10.10.10.5", "S3cret"),
    ("xfreerdp /u:admin /p:Spring2026 /v:10.10.10.5", "Spring2026"),
])
def test_redact_command(cmd, secret):
    out = redact_command(cmd)
    assert secret not in out
    assert "[REDACTED]" in out


def test_nmap_ports_untouched():
    assert redact_command("nmap -p 22,80 10.10.10.5") == "nmap -p 22,80 10.10.10.5"


def test_redact_output():
    out = redact_text("DB_PASSWORD=hunter2\ntoken ghp_q8Zr2LxW7vKp4mN9sT1yB6cD3eF0hJ5aG2iU end\n"
                      "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----")
    assert "hunter2" not in out and "ghp_" not in out and "MIIabc" not in out
