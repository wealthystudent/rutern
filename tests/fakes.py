"""Offline stand-ins for the router, built from recorded fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from rutern.cloud import COOKIE, CloudClient, LoginGuard
from rutern.config import Config
from rutern.local import LocalClient
from rutern.router import Router
from tests.conftest import load

LOCAL_CALLS = {
    ("DeviceInfo", "get"): "local/deviceinfo.json",
    ("NMC", "getWANStatus"): "local/wanstatus.json",
    ("NeMo.Intf.lan", "getMIBs"): "local/wlanvap.json",
}


CLOUD_ENDPOINTS = (
    "uptime",
    "lan-hosts",
    "wlan",
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
    """Serves cloud fixtures. rutern only ever reads, so anything but a GET is
    recorded in `posts` and refused."""

    def __init__(self) -> None:
        self.data = {ep: load(f"cloud/{ep.replace('/', '-')}.json") for ep in CLOUD_ENDPOINTS}
        self.posts: list[tuple[str, str]] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        if COOKIE not in req.headers.get("cookie", ""):
            return httpx.Response(401, json={"message": "10000"})
        prefix = "/v1/12345678/"
        assert req.url.path.startswith(prefix), req.url.path
        ep = req.url.path[len(prefix) :]
        if req.method != "GET":
            self.posts.append((req.method, ep))
            return httpx.Response(405)
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
    )
    return Router(cfg, local=local, cloud=cc), fake
