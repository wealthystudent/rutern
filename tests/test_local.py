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


def test_gated_service_maps_to_permission_denied() -> None:
    with pytest.raises(PermissionDenied):
        client().call("Devices", "get")


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
