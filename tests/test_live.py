"""Smoke check against the real router. Run explicitly: `make live`.

Uses the cached session or makes at most one login. Asserts shapes only and
prints no router values.
"""

from __future__ import annotations

import pytest

from rutern.router import Router

pytestmark = pytest.mark.live


@pytest.fixture(autouse=True)
def _real_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.undo()  # undo the offline guards from conftest


def test_live_reads() -> None:
    with Router() as r:
        s = r.status()
        assert s.source == "local" and s.device and s.wan and s.vaps
        hosts = r.hosts()
        assert hosts and all(h.mac.count(":") == 5 for h in hosts)
        wifi = r.wifi()
        assert wifi.non_volatile and all(n.encryption_key is not None for n in wifi.non_volatile)
        assert "<redacted>" in wifi.model_dump_json()
        assert r.uptime().os > 0
