from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from rutern import audit
from rutern.cli import main
from rutern.errors import ApiError, WriteRefused
from tests.fakes import WRITABLE, FakeCloud, make_router

KNOWN = "02:00:00:00:00:11"


def lines() -> list[dict[str, Any]]:
    return [json.loads(x) for x in audit.path().read_text().splitlines()]


def test_write_records_intent_backup_and_outcome(tmp_path: Path) -> None:
    r, cloud = make_router(tmp_path)
    r.channel = "cli"
    before = list(cloud.data["static-dhcp-leases"]["non_volatile"])
    r.apply(r.plan_lease(KNOWN, "10.0.0.200"), by="--yes")
    intent, result = lines()
    assert intent["event"] == "write" and intent["channel"] == "cli" and intent["by"] == "--yes"
    assert intent["list_before"] == before and intent["after"]["ip_address"] == "10.0.0.200"
    assert result == {**result, "event": "result", "outcome": "verified"}
    assert intent["write_id"] == result["write_id"]
    assert audit.path().stat().st_mode & 0o777 == 0o600


def test_failed_read_back_is_recorded(tmp_path: Path) -> None:
    r, _ = make_router(tmp_path, cloud=FakeCloud(ignore_writes=True))
    with pytest.raises(ApiError):
        r.apply(r.plan_alias(KNOWN, "Den"))
    assert str(lines()[-1]["outcome"]).startswith("failed: ApiError")


def test_no_audit_no_write(tmp_path: Path) -> None:
    r, cloud = make_router(tmp_path)
    audit.path().parent.mkdir(parents=True, exist_ok=True)
    audit.path().mkdir()  # a directory where the log should be: cannot append
    with pytest.raises(WriteRefused, match="cannot record"):
        r.apply(r.plan_alias(KNOWN, "Den"))
    assert cloud.posts == []


def test_noop_records_nothing(tmp_path: Path) -> None:
    r, cloud = make_router(tmp_path)
    first = cloud.data["static-dhcp-leases"]["non_volatile"][0]
    r.apply(r.plan_lease(first["mac"], first["ip_address"]))
    assert not audit.path().exists()


def test_history_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["history"]) == 0
    assert "no writes recorded" in capsys.readouterr().out
    r, _ = make_router(tmp_path)
    assert (
        main(["host", "alias", "set", KNOWN, "Den", "--yes"], router=lambda: r, pol=WRITABLE) == 0
    )
    capsys.readouterr()
    assert main(["history"]) == 0
    out = capsys.readouterr().out
    assert "add alias" in out and KNOWN in out and "Den" in out and "verified" in out
    assert main(["history", "--json", "-n", "1"]) == 0
    (event,) = json.loads(capsys.readouterr().out)
    assert event["by"] == "--yes" and event["outcome"] == "verified"


def test_history_skips_damaged_lines() -> None:
    audit.path().parent.mkdir(parents=True, exist_ok=True)
    audit.path().write_text('not json\n{"event": "write", "write_id": 5}\n[]\n')
    assert audit.recent() == []


@pytest.mark.parametrize("n", ["0", "-3", "x"])
def test_history_needs_a_positive_count(n: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as e:
        main(["history", "-n", n])
    assert e.value.code == 2 and "-n" in capsys.readouterr().err
