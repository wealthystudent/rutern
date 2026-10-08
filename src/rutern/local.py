"""LocalClient: the unauthenticated sysbus at http://<router>/ws.

Only the calls the router's own landing page uses work without auth. The
host list, NMC.get, Firewall and DHCPv4.Server answer error 13 and must go
through the cloud.
"""

from __future__ import annotations

from typing import Any

import httpx

from rutern import net
from rutern.config import Config
from rutern.errors import ApiError, PermissionDenied, Unreachable
from rutern.models import DeviceInfo, Vap, WanStatus, parse, parse_vaps

CONTENT_TYPE = "application/x-sah-ws-4-call+json"
PERMISSION_DENIED = 13
# The only calls rutern makes; anything else is refused before it is sent.
CALLS = frozenset({("DeviceInfo", "get"), ("NMC", "getWANStatus"), ("NeMo.Intf.lan", "getMIBs")})


class LocalClient:
    def __init__(self, config: Config | None = None, transport: httpx.BaseTransport | None = None):
        self.config = config or Config()
        self._http = httpx.Client(
            base_url=self.config.local_url, timeout=self.config.timeout, transport=transport
        )

    def close(self) -> None:
        self._http.close()

    def call(self, service: str, method: str, parameters: dict[str, Any] | None = None) -> Any:
        """Run one sysbus call and return the whole success envelope."""
        if (service, method) not in CALLS:
            raise ApiError(f"{service}.{method} is not a call rutern makes")
        body = {"service": service, "method": method, "parameters": parameters or {}}
        req = self._http.build_request(
            "POST", "/ws", json=body, headers={"Content-Type": CONTENT_TYPE}
        )
        try:
            r = net.send(self._http, req)
        except httpx.HTTPError as e:
            raise Unreachable(f"router at {self.config.local_host} did not answer") from e
        if r.status_code == 401:
            raise PermissionDenied(f"{service}.{method} needs auth the local API does not offer")
        if r.status_code != 200:
            raise ApiError(f"{service}.{method}: HTTP {r.status_code}")
        try:
            env = r.json()
        except ValueError as e:
            raise ApiError(f"{service}.{method}: response is not JSON") from e
        if not isinstance(env, dict):
            raise ApiError(f"{service}.{method}: unexpected envelope")
        errors = env.get("errors") or []
        if errors:
            codes = [e.get("error") for e in errors if isinstance(e, dict)]
            if PERMISSION_DENIED in codes:
                raise PermissionDenied(f"{service}.{method}: permission denied (error 13)")
            shown = [c for c in codes if isinstance(c, int) and not isinstance(c, bool)][:5]
            raise ApiError(f"{service}.{method}: router error {shown or '(no code)'}")
        return env

    # reads

    def device_info(self) -> DeviceInfo:
        return parse(DeviceInfo, self.call("DeviceInfo", "get").get("status"), "DeviceInfo")

    def wan_status(self) -> WanStatus:
        return parse(WanStatus, self.call("NMC", "getWANStatus").get("data"), "NMC.getWANStatus")

    def vaps(self) -> list[Vap]:
        env = self.call("NeMo.Intf.lan", "getMIBs", {"mibs": "wlanvap"})
        status = env.get("status")
        wlanvap = status.get("wlanvap") if isinstance(status, dict) else None
        if not isinstance(wlanvap, dict):
            raise ApiError("NeMo.Intf.lan getMIBs: no wlanvap in response")
        return parse_vaps(wlanvap)
