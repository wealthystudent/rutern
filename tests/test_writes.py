from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from rutern.cli import main
from rutern.errors import ApiError, WriteRefused
from rutern.mcp_server import build
from tests.fakes import MCP_WRITES, WRITABLE, FakeCloud, make_router
from tests.test_mcp import call

KNOWN = "02:00:00:00:00:11"  # online, no fixed IP in the fixture
FREE_IP = "10.0.0.200"


def saved(cloud: FakeCloud, ep: str) -> list[dict[str, object]]:
    return list(cloud.data[ep]["non_volatile"])


# fixed IPs


def test_lease_add_sends_full_list_and_verifies(tmp_path: Path) -> None:
    r, cloud = make_router(tmp_path)
    before = saved(cloud, "static-dhcp-leases")
    plan = r.plan_lease(KNOWN, FREE_IP)
    assert plan.before is None and plan.after == {
        "srcservice": "",
        "mac": KNOWN,
        "ip_address": FREE_IP,
    }
    assert cloud.posts == []
    r.apply(plan)
    ep, body = cloud.posts[-1]
    assert ep == "static-dhcp-leases" and len(body["leases"]) == len(before) + 1
    assert body["leases"][:-1] == before


def test_lease_change_keeps_position_and_remove(tmp_path: Path) -> None:
    r, cloud = make_router(tmp_path)
    first = saved(cloud, "static-dhcp-leases")[0]
    r.apply(r.plan_lease(str(first["mac"]), FREE_IP))
    assert cloud.posts[-1][1]["leases"][0]["ip_address"] == FREE_IP
    r.apply(r.plan_lease(str(first["mac"]), None))
    assert first["mac"] not in {x["mac"] for x in cloud.posts[-1][1]["leases"]}


@pytest.mark.parametrize(
    ("ip", "match"),
    [
        ("10.0.1.5", "not a host address in the LAN"),
        ("10.0.0.255", "not a host address"),
        ("10.0.0.138", "router itself"),
        ("nope", "not an IPv4"),
        ("10.0.0.12", "already reserved"),
    ],
)
def test_lease_refuses(tmp_path: Path, ip: str, match: str) -> None:
    r, cloud = make_router(tmp_path)
    with pytest.raises(WriteRefused, match=match):
        r.plan_lease(KNOWN, ip)
    assert cloud.posts == []


def test_remove_missing_lease_refused(tmp_path: Path) -> None:
    r, _ = make_router(tmp_path)
    with pytest.raises(WriteRefused, match="no fixed IP"):
        r.plan_lease(KNOWN, None)


# static routes


def test_route_add_and_remove(tmp_path: Path) -> None:
    r, cloud = make_router(tmp_path)
    plan = r.plan_route("lab", "10.9.0.7/24", "10.0.0.42")
    assert plan.after == {"name": "lab", "destination": "10.9.0.0/24", "next_hop": "10.0.0.42"}
    r.apply(plan)
    assert cloud.posts[-1] == ("static-routes", {"rules": [plan.after]})
    r.apply(r.plan_route("lab"))
    assert cloud.posts[-1] == ("static-routes", {"rules": []})


@pytest.mark.parametrize(
    ("dest", "hop", "match"),
    [
        ("0.0.0.0/0", "10.0.0.42", "not a private network"),
        ("0.0.0.0/1", "10.0.0.42", "not a private network"),
        ("128.0.0.0/1", "10.0.0.42", "not a private network"),
        ("1.1.1.1/32", "10.0.0.42", "not a private network"),
        ("224.0.0.0/4", "10.0.0.42", "not a private network"),
        ("10.0.0.0/25", "10.0.0.42", "overlaps the LAN"),
        ("10.0.0.0/8", "10.0.0.42", "overlaps the LAN"),
        ("bogus", "10.0.0.42", "not an IPv4 network"),
        ("10.9.0.0/24", "192.168.1.1", "not a host address in the LAN"),
        ("10.9.0.0/24", None, "needs a next hop"),
    ],
)
def test_route_refuses(tmp_path: Path, dest: str, hop: str | None, match: str) -> None:
    r, cloud = make_router(tmp_path)
    with pytest.raises(WriteRefused, match=match):
        r.plan_route("lab", dest, hop)
    assert cloud.posts == []


# port forwards


def test_forward_add_and_remove(tmp_path: Path) -> None:
    r, cloud = make_router(tmp_path)
    plan = r.plan_forward("web", "TCP", "8000-8002", "10.0.0.5", "9000-9002")
    assert plan.after == {
        "name": "web",
        "protocol": "tcp",
        "lan_ip": "10.0.0.5",
        "wan_port_start": 8000,
        "wan_port_end": 8002,
        "lan_port_start": 9000,
        "lan_port_end": 9002,
    }
    r.apply(plan)
    assert cloud.posts[-1] == ("nat-rules", {"rules": [plan.after]})
    r.apply(r.plan_forward("web"))
    assert cloud.posts[-1] == ("nat-rules", {"rules": []})


@pytest.mark.parametrize(
    ("proto", "wan", "lan_port", "match"),
    [
        ("icmp", "22", None, "tcp or udp"),
        ("tcp", "0", None, "between 1 and 65535"),
        ("tcp", "70000", None, "between 1 and 65535"),
        ("tcp", "90-80", None, "low to high"),
        ("tcp", "80-81", "80", "same size"),
        ("tcp", "x", None, "like 443"),
        ("tcp", "1-65535", None, "more than 100 ports"),
        ("tcp", "1000-1100", None, "more than 100 ports"),
    ],
)
def test_forward_refuses(
    tmp_path: Path, proto: str, wan: str, lan_port: str | None, match: str
) -> None:
    r, cloud = make_router(tmp_path)
    with pytest.raises(WriteRefused, match=match):
        r.plan_forward("web", proto, wan, "10.0.0.5", lan_port)
    assert cloud.posts == []


# shared safety


def test_noop_writes_nothing(tmp_path: Path) -> None:
    r, cloud = make_router(tmp_path)
    first = saved(cloud, "static-dhcp-leases")[0]
    plan = r.plan_lease(str(first["mac"]), str(first["ip_address"]))
    assert plan.noop
    r.apply(plan)
    assert cloud.posts == []


def test_write_that_does_not_stick_is_reported(tmp_path: Path) -> None:
    r, _ = make_router(tmp_path, cloud=FakeCloud(ignore_writes=True))
    with pytest.raises(ApiError, match="read-back"):
        r.apply(r.plan_route("lab", "10.9.0.0/24", "10.0.0.42"))


def test_write_that_touches_other_entries_is_reported(tmp_path: Path) -> None:
    cloud = FakeCloud()
    r, _ = make_router(tmp_path, cloud=cloud)
    plan = r.plan_lease(KNOWN, FREE_IP)
    cloud.after_post = lambda c: c.data["static-dhcp-leases"]["non_volatile"].pop(0)
    with pytest.raises(ApiError, match="other entries"):
        r.apply(plan)


# CLI


def run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], *argv: str
) -> tuple[int, str, str, FakeCloud]:
    r, cloud = make_router(tmp_path)
    code = main(list(argv), router=lambda: r, pol=WRITABLE)
    out, err = capsys.readouterr()
    return code, out, err, cloud


def test_cli_lease_set_dry_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _, cloud = run(tmp_path, capsys, "leases", "set", KNOWN, FREE_IP, "--dry-run")
    assert code == 0 and "add fixed ip" in out and FREE_IP in out and cloud.posts == []


def test_cli_route_add_yes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _, cloud = run(
        tmp_path, capsys, "routes", "add", "lab", "10.9.0.0/24", "10.0.0.42", "--yes", "--json"
    )
    assert code == 0 and json.loads(out)["verified"] is True and len(cloud.posts) == 1


def test_cli_forward_warns_and_needs_confirmation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err, cloud = run(
        tmp_path,
        capsys,
        "forwards",
        "add",
        "ssh",
        "tcp",
        "2222",
        "10.0.0.5",
        "--lan-port",
        "22",
        "--yes",
    )
    assert code == 1 and "internet" in out and "22 (ssh)" in out
    assert "interactive terminal" in err and cloud.posts == []


def test_cli_list_still_works_without_action(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _, _ = run(tmp_path, capsys, "routes")
    assert code == 0 and "no static routes" in out


# MCP


def test_mcp_write_tools(tmp_path: Path) -> None:
    r, cloud = make_router(tmp_path)
    s = build(writes=MCP_WRITES, router=lambda: r)
    names = {t.name for t in asyncio.run(s.list_tools())}
    assert {"set_device_alias", "set_fixed_ip", "set_static_route"} <= names
    assert not any("forward" in n or "nat" in n for n in names)
    args = {"name": "lab", "destination": "10.9.0.0/24", "next_hop": "10.0.0.42"}
    assert call(s, "set_static_route", args)["data"]["written"] is False
    assert cloud.posts == []
