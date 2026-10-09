from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from rutern.config import Config
from rutern.errors import ApiError, WriteRefused
from rutern.local import LocalClient
from tests.fakes import FakeCloud, make_router

KNOWN = "02:00:00:00:00:11"  # a host with no alias in the fixture


def test_status_local(tmp_path: Path) -> None:
    r, cloud = make_router(tmp_path)
    s = r.status()
    assert s.source == "local"
    assert s.device and s.wan and len(s.vaps) == 9
    assert cloud.posts == []


def test_status_falls_back_to_cloud(tmp_path: Path) -> None:
    r, _ = make_router(tmp_path, local_up=False)
    s = r.status()
    assert s.source == "cloud"
    assert s.uptime and s.uptime.os > 0


def test_hosts_sorted_active_first(tmp_path: Path) -> None:
    r, _ = make_router(tmp_path)
    hosts = r.hosts()
    assert len(hosts) == 26
    flags = [h.active for h in hosts]
    assert flags == sorted(flags, reverse=True)
    assert all(h.active for h in r.hosts(active_only=True))


def test_plan_alias_is_read_only(tmp_path: Path) -> None:
    r, cloud = make_router(tmp_path)
    plan = r.plan_alias(KNOWN.upper(), "Living room TV")
    assert plan.id == KNOWN and plan.before is None
    assert plan.after == {"mac": KNOWN, "hostname": "Living room TV"}
    assert cloud.posts == []


@pytest.mark.parametrize("merge", [False, True])
def test_apply_alias_sends_full_list_and_reads_back(tmp_path: Path, merge: bool) -> None:
    r, cloud = make_router(tmp_path, cloud=FakeCloud(merge_aliases=merge))
    before = {e["mac"]: e["hostname"] for e in cloud.data["lan-hosts/alias"]["non_volatile"]}
    r.apply(r.plan_alias(KNOWN, "Den"))
    ep, body = cloud.posts[-1]
    assert ep == "lan-hosts/alias"
    sent = {e["mac"]: e["hostname"] for e in body["hosts"]}
    assert sent == {**before, KNOWN: "Den"}


def test_clear_alias(tmp_path: Path) -> None:
    r, cloud = make_router(tmp_path)
    target = cloud.data["lan-hosts/alias"]["non_volatile"][0]["mac"]
    plan = r.plan_alias(target, "")
    assert plan.before and plan.after is None
    r.apply(plan)
    assert target not in {e["mac"] for e in cloud.posts[-1][1]["hosts"]}


def test_write_without_effect_is_reported(tmp_path: Path) -> None:
    r, _ = make_router(tmp_path, cloud=FakeCloud(ignore_writes=True))
    with pytest.raises(ApiError, match="read-back"):
        r.apply(r.plan_alias(KNOWN, "Den"))


def test_stale_plan_is_refused(tmp_path: Path) -> None:
    r, cloud = make_router(tmp_path)
    plan = r.plan_alias(KNOWN, "Den")
    cloud.data["lan-hosts/alias"]["non_volatile"].append({"mac": KNOWN, "hostname": "Other"})
    with pytest.raises(WriteRefused, match="changed"):
        r.apply(plan)
    assert cloud.posts == []


@pytest.mark.parametrize(
    ("mac", "alias"),
    [
        ("02:00:00:00:00:99", "x"),  # unknown device
        ("not-a-mac", "x"),
        (KNOWN, "bad\x1b[31m"),
        (KNOWN, "x" * 64),
    ],
)
def test_plan_alias_refuses_bad_input(tmp_path: Path, mac: str, alias: str) -> None:
    r, cloud = make_router(tmp_path)
    with pytest.raises(WriteRefused):
        r.plan_alias(mac, alias)
    assert cloud.posts == []


@pytest.mark.parametrize("status", [404, 401])
def test_status_falls_back_when_something_else_answers(tmp_path: Path, status: int) -> None:
    r, _ = make_router(tmp_path)
    r._local = LocalClient(
        Config(), transport=httpx.MockTransport(lambda req: httpx.Response(status))
    )
    assert r.status().source == "cloud"
