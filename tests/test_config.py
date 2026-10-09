from __future__ import annotations

from pathlib import Path

import pytest

from rutern.config import CLOUD_BASE, Config, discover_reference, valid_reference, write_private
from rutern.errors import ConfigError


@pytest.mark.parametrize(
    "host", ["8.8.8.8", "wifi.example.com", "10.0.0.1/x", "10.0.0.1:8080", "127.0.0.1", ""]
)
def test_local_host_must_be_a_private_lan_ip(host: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RUTERN_HOST", host)
    with pytest.raises(ConfigError, match="RUTERN_HOST"):
        Config()


def test_local_host_accepts_lan_ips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RUTERN_HOST", " 192.168.1.1 ")
    assert Config().local_url == "http://192.168.1.1"


def test_cloud_base_ignores_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RUTERN_CLOUD", "http://evil.example")
    assert Config().cloud_base == CLOUD_BASE == "https://wifi.telenor.no"


@pytest.mark.parametrize("ref", ["²", "٣٣٣", "123abc", "12 34", "1" * 21, "-1"])
def test_reference_must_be_ascii_digits(ref: str, monkeypatch: pytest.MonkeyPatch) -> None:
    assert not valid_reference(ref)
    monkeypatch.setenv("RUTERN_REFERENCE", ref)
    with pytest.raises(ConfigError):
        Config()


def test_discover_reference_ignores_unicode_digits() -> None:
    assert discover_reference('reference:"٣٣٣"') is None
    assert discover_reference('reference: "12345678"') == "12345678"


def test_write_private_tightens_an_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "d" / "f"
    path.parent.mkdir()
    path.write_text("old")
    path.chmod(0o644)
    write_private(path, "new")
    write_private(path, "+", append=True)
    assert path.read_text() == "new+" and path.stat().st_mode & 0o777 == 0o600
