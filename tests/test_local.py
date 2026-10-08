from __future__ import annotations

import httpx
import pytest

from rutern.config import Config
from rutern.errors import ApiError, PermissionDenied, Unreachable
from rutern.local import LocalClient
from tests.fakes import local_handler, unreachable


def client(handler: object = local_handler) -> LocalClient:
    return LocalClient(Config(local_host="10.0.0.138"), transport=httpx.MockTransport(handler))  # type: ignore[arg-type]


def test_reads() -> None:
    c = client()
    assert c.device_info().firmware == "1.2.66.0"
    assert c.wan_status().link_state == "up"
    assert len(c.vaps()) == 9


def test_permission_denied_maps_from_error_13() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": None, "errors": [{"error": 13}]})

    with pytest.raises(PermissionDenied):
        client(h).device_info()


def test_calls_outside_the_allowlist_are_never_sent() -> None:
    sent: list[httpx.Request] = []

    def h(req: httpx.Request) -> httpx.Response:
        sent.append(req)
        return local_handler(req)

    for service, method in (("Devices", "get"), ("NMC", "reboot"), ("NMC", "reset")):
        with pytest.raises(ApiError, match="not a call rutern makes"):
            client(h).call(service, method)
    assert sent == []


def test_unreachable() -> None:
    with pytest.raises(Unreachable):
        client(unreachable).device_info()


def test_other_router_error() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": None, "errors": [{"error": 196618}]})

    with pytest.raises(ApiError):
        client(h).device_info()


def test_non_json() -> None:
    with pytest.raises(ApiError):
        client(lambda req: httpx.Response(200, text="<html>")).device_info()
