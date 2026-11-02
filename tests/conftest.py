import pytest


@pytest.fixture(autouse=True)
def pwntrail_home(tmp_path, monkeypatch):
    home = tmp_path / "pthome"
    monkeypatch.setenv("PWNTRAIL_HOME", str(home))
    monkeypatch.delenv("PWNTRAIL_CASE", raising=False)
    monkeypatch.delenv("PWNTRAIL_SESSION", raising=False)
    return home
