"""Offline stand-ins for the router, built from recorded fixtures."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from rutern.cloud import COOKIE, CloudClient, LoginGuard
from rutern.config import Config
from rutern.local import LocalClient
from rutern.policy import Policy
from rutern.router import Router
from rutern.writes import KINDS, Kind
from tests.conftest import load

# A policy that allows every write, for tests about the write flow itself.
WRITABLE = Policy(cli_writes=frozenset(KINDS), mcp_writes=frozenset(KINDS) - {"forward"})
MCP_WRITES = WRITABLE.mcp_writes

LOCAL_CALLS = {
    ("DeviceInfo", "get"): "local/deviceinfo.json",
    ("NMC", "getWANStatus"): "local/wanstatus.json",
    ("NeMo.Intf.lan", "getMIBs"): "local/wlanvap.json",
}


CLOUD_ENDPOINTS = (
    "uptime",
    "lan-hosts",
    "wlan",
    "lan-hosts/alias",
    "static-dhcp-leases",
    "static-routes",
    "dhcp",
    "nat-rules",
    "dmz",
    "dns",
    "firewall-status",
    "firewall-rules",
    "upnp",
    "upnp/mappings",
)


BODY_KEYS = {
    "lan-hosts/alias": "hosts",
    "static-dhcp-leases": "leases",
    "static-routes": "rules",
    "nat-rules": "rules",
}


def local_handler(req: httpx.Request) -> httpx.Response:
    assert req.headers["content-type"] == "application/x-sah-ws-4-call+json"
    body = json.loads(req.content)
    name = LOCAL_CALLS.get((body["service"], body["method"]))
    if name is None:
        return httpx.Response(
            200,
            json={"status": None, "errors": [{"error": 13, "description": "Permission denied"}]},
        )
    return httpx.Response(200, json=load(name))


def unreachable(req: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("no route to host", request=req)


class FakeCloud:
    """Serves cloud fixtures and keeps alias writes in memory."""

    def __init__(self, *, merge_aliases: bool = False, ignore_writes: bool = False):
        self.data = {ep: load(f"cloud/{ep.replace('/', '-')}.json") for ep in CLOUD_ENDPOINTS}
        self.merge_aliases = merge_aliases
        self.ignore_writes = ignore_writes
        self.posts: list[tuple[str, Any]] = []
        self.after_post: Callable[[FakeCloud], None] | None = None

    def __call__(self, req: httpx.Request) -> httpx.Response:
        if COOKIE not in req.headers.get("cookie", ""):
            return httpx.Response(401, json={"message": "10000"})
        prefix = "/v1/12345678/"
        assert req.url.path.startswith(prefix), req.url.path
        ep = req.url.path[len(prefix) :]
        if req.method == "POST":
            body = json.loads(req.content)
            self.posts.append((ep, body))
            key = BODY_KEYS.get(ep)
            if key is None:
                return httpx.Response(404)
            if not isinstance(body.get(key), list):
                return httpx.Response(
                    400, json={"statusCode": 400, "message": f"{key.title()} must be an array"}
                )
            if not self.ignore_writes:
                cur = self.data[ep]
                if self.merge_aliases:
                    merged = {e["mac"]: e for e in cur["non_volatile"]}
                    merged.update({e["mac"]: e for e in body[key]})
                    cur["non_volatile"] = list(merged.values())
                else:
                    cur["non_volatile"] = copy.deepcopy(body[key])
            if self.after_post:
                self.after_post(self)
            return httpx.Response(201, json={"non_volatile": True, "volatile": True})
        if ep not in self.data:
            return httpx.Response(404)
        return httpx.Response(200, json=self.data[ep])


class MemoryStore:
    def __init__(self, value: str | None = "session") -> None:
        self.value = value

    def load(self) -> str | None:
        return self.value

    def save(self, value: str) -> None:
        self.value = value

    def clear(self) -> None:
        self.value = None


def make_router(
    tmp_path: Path,
    *,
    cloud: FakeCloud | None = None,
    local_up: bool = True,
    writes: frozenset[Kind] = frozenset(KINDS),
) -> tuple[Router, FakeCloud]:
    cfg = Config(reference="12345678")
    fake = cloud or FakeCloud()
    local = LocalClient(
        cfg, transport=httpx.MockTransport(local_handler if local_up else unreachable)
    )
    cc = CloudClient(
        cfg,
        transport=httpx.MockTransport(fake),
        password=lambda: "never-used",
        store=MemoryStore(),  # type: ignore[arg-type]
        guard=LoginGuard(tmp_path / "guard"),
        writable=bool(writes),
    )
    return Router(cfg, local=local, cloud=cc, writes=writes), fake
