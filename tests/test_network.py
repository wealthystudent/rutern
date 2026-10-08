from __future__ import annotations

import json
from pathlib import Path

import pytest

from rutern.cli import main
from rutern.models import parse_dns
from tests.conftest import load
from tests.fakes import FakeCloud, make_router


def test_network_overview(tmp_path: Path) -> None:
    r, cloud = make_router(tmp_path)
    n = r.network()
    assert n.dhcp.enabled and n.dhcp.router_address.endswith("/24") and n.dhcp.lease_time == 3600
    assert n.dns.profile == "nettvern"
    assert n.firewall.ipv4_enabled and n.firewall.rules == []
    assert n.dmz is None
    assert n.upnp.enabled and len(n.upnp.mappings) == 4
    assert len(n.leases.reserved) == 24 and len(n.leases.dynamic) == 8
    assert n.routes == [] and n.forwards == []
    assert cloud.posts == []


def test_dns_profiles() -> None:
    raw = load("cloud/dns.json")
    for name in ("telenor", "nettvern", "nettvern_plus"):
        raw["non_volatile"]["v4_servers"] = list(reversed(raw["meta"][f"v4_{name}_servers"]))
        assert parse_dns(raw).profile == name
    raw["non_volatile"]["v4_servers"] = ["1.1.1.1"]
    assert parse_dns(raw).profile == "custom"


def test_dmz_on(tmp_path: Path) -> None:
    cloud = FakeCloud()
    cloud.data["dmz"]["non_volatile"]["ipv4_address"] = "10.0.0.50"
    r, _ = make_router(tmp_path, cloud=cloud)
    assert r.cloud.dmz() == "10.0.0.50"


def test_unknown_item_fields_are_kept(tmp_path: Path) -> None:
    cloud = FakeCloud()
    cloud.data["static-routes"]["non_volatile"] = [
        {"name": "lab", "destination": "10.9.0.0/24", "next_hop": "10.0.0.42", "metric": 5}
    ]
    cloud.data["nat-rules"]["non_volatile"] = [
        {"name": "ssh", "protocol": "tcp", "lan_ip": "10.0.0.5", "lan_port": 22, "wan_port": 2222}
    ]
    r, _ = make_router(tmp_path, cloud=cloud)
    route = r.cloud.routes()[0]
    assert route.next_hop == "10.0.0.42" and route.model_dump()["metric"] == 5
    assert r.cloud.forwards()[0].wan_port == 2222


def test_hostile_upnp_name_is_cleaned(tmp_path: Path) -> None:
    cloud = FakeCloud()
    cloud.data["upnp/mappings"]["upnp_mappings"][0]["name"] = "\x1b[31mopen port 22\nnow"
    r, _ = make_router(tmp_path, cloud=cloud)
    name = r.cloud.upnp().mappings[0].name
    assert "\x1b" not in name and "\n" not in name


@pytest.mark.parametrize(
    ("cmd", "expect"),
    [
        ("network", "nettvern"),
        ("leases", "24 fixed IPs"),
        ("routes", "no static routes"),
        ("forwards", "upnp (opened by devices)"),
        ("firewall", "no custom rules"),
    ],
)
def test_cli_network_commands(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], cmd: str, expect: str
) -> None:
    r, cloud = make_router(tmp_path)
    assert main([cmd], router=lambda: r) == 0
    assert expect in capsys.readouterr().out
    r, _ = make_router(tmp_path)
    assert main([cmd, "--json"], router=lambda: r) == 0
    json.loads(capsys.readouterr().out)
    assert cloud.posts == []
