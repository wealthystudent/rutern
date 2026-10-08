from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from rutern.cli import duration, main
from rutern.cloud import COOKIE, CloudClient, LoginGuard, ReferencePin
from rutern.config import Config
from rutern.local import LocalClient
from rutern.router import Router
from tests.fakes import (
    WRITABLE,
    FakeCloud,
    MemoryStore,
    local_handler,
    make_router,
    unreachable,
)

KNOWN = "02:00:00:00:00:11"


def run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], *argv: str, cloud: FakeCloud | None = None
) -> tuple[int, str, str, FakeCloud]:
    r, fake = make_router(tmp_path, cloud=cloud)
    code = main(list(argv), router=lambda: r, pol=WRITABLE)
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


def test_wifi_show_secrets(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("rutern.cli.human_terminal", lambda: True)
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


def _login_router(tmp_path: Path, local_up: bool) -> tuple[Router, list[str]]:
    seen: list[str] = []

    def portal(req: httpx.Request) -> httpx.Response:
        seen.append(f"{req.method} {req.url.path}")
        if req.method == "GET" and req.url.path == "/login/admin":
            return httpx.Response(200, text='x,model:"ex5700",reference:"12345678",y')
        if req.method == "POST" and req.url.path == "/login/admin":
            return httpx.Response(
                200, json={"type": "redirect"}, headers={"set-cookie": f"{COOKIE}=s; Path=/"}
            )
        return httpx.Response(404)

    cfg = Config(reference=None)
    local = LocalClient(
        cfg, transport=httpx.MockTransport(local_handler if local_up else unreachable)
    )
    cloud = CloudClient(
        cfg,
        transport=httpx.MockTransport(portal),
        password=lambda: "pw",
        store=MemoryStore(None),  # type: ignore[arg-type]
        guard=LoginGuard(tmp_path / "guard"),
        pin=ReferencePin(tmp_path / "reference"),
    )
    return Router(cfg, local=local, cloud=cloud), seen


def test_login_away_from_home_never_asks_the_portal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    r, seen = _login_router(tmp_path, local_up=False)
    assert main(["login"], router=lambda: r) == 1
    assert "at home" in capsys.readouterr().err and seen == []


def test_login_at_home_discovers_and_pins(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    r, seen = _login_router(tmp_path, local_up=True)
    assert main(["login"], router=lambda: r) == 0
    assert seen == ["GET /login/admin", "POST /login/admin"]
    assert (tmp_path / "reference").read_text().strip() == "12345678"


def test_bad_env_is_a_clean_error(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RUTERN_HOST", "evil.example")
    assert main(["status"]) == 1
    assert "RUTERN_HOST" in capsys.readouterr().err


def test_surrogate_hostname_does_not_break_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class EscapedSurrogate(FakeCloud):
        """The portal sends a lone surrogate as a JSON escape."""

        def __call__(self, req: httpx.Request) -> httpx.Response:
            res = super().__call__(req)
            body = res.content.replace(b"SURROGATE", b"\\ud800")
            return httpx.Response(res.status_code, content=body)

    cloud = EscapedSurrogate()
    cloud.data["lan-hosts"]["hosts"][0]["hostname"] = "evilSURROGATEname"
    for argv in (["devices", "--all"], ["devices", "--all", "--json"]):
        code, out, _, _ = run(tmp_path, capsys, *argv, cloud=cloud)
        assert code == 0 and "evilname" in out


def test_unexpected_errors_are_one_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    r, _ = make_router(tmp_path)

    def boom(**_: object) -> None:
        raise KeyError("raw router text")

    monkeypatch.setattr(r, "hosts", boom)
    assert main(["devices"], router=lambda: r) == 1
    err = capsys.readouterr().err
    assert "unexpected error (KeyError)" in err and "raw router text" not in err
    monkeypatch.setenv("RUTERN_DEBUG", "1")
    with pytest.raises(KeyError):
        main(["devices"], router=lambda: r)


def test_odd_upnp_response_is_an_api_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cloud = FakeCloud()
    cloud.data["upnp/mappings"] = {"upnp_mappings": "nope"}
    code, _, err, _ = run(tmp_path, capsys, "forwards", cloud=cloud)
    assert code == 1 and "upnp_mappings" in err
