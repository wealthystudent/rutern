from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from rutern.config import Config
from rutern.local import LocalClient
from tests.fakes import make_router


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


@pytest.mark.parametrize("status", [404, 401])
def test_status_falls_back_when_something_else_answers(tmp_path: Path, status: int) -> None:
    r, _ = make_router(tmp_path)
    r._local = LocalClient(
        Config(), transport=httpx.MockTransport(lambda req: httpx.Response(status))
    )
    assert r.status().source == "cloud"
