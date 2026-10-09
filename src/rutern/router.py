"""Router: one object over the local and cloud backends.

Local answers when it can (fast, offline, no credentials). Cloud is created
lazily, so commands that stay local never read the password or log in.
Everything here reads; rutern changes nothing on the router.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from rutern.cloud import CloudClient
from rutern.config import Config
from rutern.errors import ApiError, PermissionDenied, Unreachable
from rutern.local import LocalClient
from rutern.models import (
    DeviceInfo,
    Host,
    Model,
    Network,
    Uptime,
    Vap,
    WanStatus,
    Wifi,
)


class Status(Model):
    source: Literal["local", "cloud"]
    device: DeviceInfo | None = None
    wan: WanStatus | None = None
    vaps: list[Vap] = Field(default_factory=list)
    uptime: Uptime | None = None


class Router:
    def __init__(
        self,
        config: Config | None = None,
        *,
        local: LocalClient | None = None,
        cloud: CloudClient | None = None,
    ):
        self.config = config or Config()
        self._local = local
        self._cloud = cloud

    @property
    def local(self) -> LocalClient:
        if self._local is None:
            self._local = LocalClient(self.config)
        return self._local

    @property
    def cloud(self) -> CloudClient:
        if self._cloud is None:
            self._cloud = CloudClient(self.config)
        return self._cloud

    def close(self) -> None:
        for c in (self._local, self._cloud):
            if c is not None:
                c.close()

    def __enter__(self) -> Router:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # reads

    def status(self) -> Status:
        """Device, WAN and WiFi from the LAN; falls back to cloud uptime when away,
        including on a network where something else answers at the router's address."""
        try:
            return Status(
                source="local",
                device=self.local.device_info(),
                wan=self.local.wan_status(),
                vaps=self.local.vaps(),
            )
        except (Unreachable, ApiError, PermissionDenied):
            return Status(source="cloud", uptime=self.cloud.uptime())

    def hosts(self, *, active_only: bool = False) -> list[Host]:
        hosts = self.cloud.hosts()
        if active_only:
            hosts = [h for h in hosts if h.active]
        return sorted(hosts, key=lambda h: (not h.active, h.interface, h.name.lower()))

    def wifi(self) -> Wifi:
        return self.cloud.wifi()

    def uptime(self) -> Uptime:
        return self.cloud.uptime()

    def network(self) -> Network:
        c = self.cloud
        return Network(
            dhcp=c.dhcp(),
            dns=c.dns(),
            firewall=c.firewall(),
            dmz=c.dmz(),
            upnp=c.upnp(),
            leases=c.leases(),
            routes=c.routes(),
            forwards=c.forwards(),
        )
