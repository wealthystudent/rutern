from __future__ import annotations

import json
from pathlib import Path

import pytest

from rutern.cli import duration, main
from tests.fakes import FakeCloud, make_router

KNOWN = "02:00:00:00:00:11"


def run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], *argv: str, cloud: FakeCloud | None = None
) -> tuple[int, str, str, FakeCloud]:
    r, fake = make_router(tmp_path, cloud=cloud)
    code = main(list(argv), router=lambda: r)
    out, err = capsys.readouterr()
    return code, out, err, fake


def test_status(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _, _ = run(tmp_path, capsys, "status")
    assert code == 0
    assert "TEL-HGW-1" in out and "1.2.66.0" in out and "╭" in out


def test_status_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _, _ = run(tmp_path, capsys, "status", "--json")
    data = json.loads(out)
    assert code == 0 and data["source"] == "local" and len(data["vaps"]) == 9


def test_devices(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _, _ = run(tmp_path, capsys, "devices")
    assert code == 0 and "active" in out and "total" not in out and "○" not in out
    code, out, _, _ = run(tmp_path, capsys, "devices", "--all")
    assert code == 0 and "26 total" in out and "○" in out


def test_wifi_hides_keys_by_default(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cloud = FakeCloud()
    for n in cloud.data["wlan"]["non_volatile"]:
        n["encryption_key"] = "s3cret-wifi-pass"
    for argv in (["wifi"], ["wifi", "--json"]):
        code, out, err, _ = run(tmp_path, capsys, *argv, cloud=cloud)
        assert code == 0 and "s3cret" not in out + err


def test_wifi_show_secrets(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cloud = FakeCloud()
    cloud.data["wlan"]["non_volatile"][0]["encryption_key"] = "s3cret-wifi-pass"
    _, out, _, _ = run(tmp_path, capsys, "wifi", "--show-secrets", cloud=cloud)
    assert "s3cret-wifi-pass" in out
    _, out, _, _ = run(tmp_path, capsys, "wifi", "--json", "--show-secrets", cloud=cloud)
    assert json.loads(out)[0]["encryption_key"] == "s3cret-wifi-pass"


def test_alias_dry_run_writes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _, fake = run(tmp_path, capsys, "host", "alias", "set", KNOWN, "Den", "--dry-run")
    assert code == 0 and "dry run" in out and fake.posts == []


def test_alias_refuses_without_tty_or_yes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, err, fake = run(tmp_path, capsys, "host", "alias", "set", KNOWN, "Den")
    assert code == 1 and "not confirmed" in err and fake.posts == []


def test_alias_yes_writes_and_verifies(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _, fake = run(
        tmp_path, capsys, "host", "alias", "set", KNOWN, "Den", "--yes", "--json"
    )
    assert code == 0 and json.loads(out)["verified"] is True and len(fake.posts) == 1


def test_errors_go_to_stderr(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err, _ = run(tmp_path, capsys, "host", "alias", "set", "zz", "x", "--yes")
    assert code == 1 and out == "" and "not a MAC" in err


def test_duration() -> None:
    assert duration(133723) == "1d 13h"
    assert duration(3700) == "1h 1m"
    assert duration(0) == "-"
