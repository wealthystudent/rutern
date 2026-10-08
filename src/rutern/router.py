"""Router: one object over the local and cloud backends.

Local answers when it can (fast, offline, no credentials). Cloud is created
lazily, so commands that stay local never read Keychain or log in.
"""

from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import Field

from rutern import writes
from rutern.cloud import CloudClient
from rutern.config import Config
from rutern.errors import Unreachable, WriteRefused
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
from rutern.writes import Change


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
        """Device, WAN and WiFi from the LAN; falls back to cloud uptime when away."""
        try:
            return Status(
                source="local",
                device=self.local.device_info(),
                wan=self.local.wan_status(),
                vaps=self.local.vaps(),
            )
        except Unreachable:
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

    # writes: plan_* never write; apply() writes one planned change and verifies it

    def _device_label(self, mac: str) -> str:
        host = next((h for h in self.cloud.hosts() if h.mac == mac), None)
        return host.name if host else "unknown device"

    def _lan(self) -> tuple[ipaddress.IPv4Network, str]:
        router = self.cloud.dhcp().router_address
        return writes.lan_network(router), router

    def plan_alias(self, mac: str, alias: str) -> Change:
        """Set the name the router shows for a device; an empty alias clears it."""
        mac = writes.mac(mac)
        host = next((h for h in self.cloud.hosts() if h.mac == mac), None)
        if host is None:
            raise WriteRefused(f"no known device with MAC {mac}")
        after = {"mac": mac, "hostname": writes.name(alias, "alias")} if alias.strip() else None
        return Change(
            kind="alias",
            id=mac,
            label=host.hostname or host.vendor or mac,
            before=writes.current(self.cloud, "alias", mac),
            after=after,
        )

    def plan_lease(self, mac: str, ip: str | None) -> Change:
        """Give a device a fixed IP, or with ip=None remove its reservation."""
        mac = writes.mac(mac)
        before = writes.current(self.cloud, "lease", mac)
        after = None
        if ip is not None:
            lan, router = self._lan()
            ip = writes.lan_ip(ip, lan, router)
            taken = [
                x
                for x in writes.saved(self.cloud, "lease")
                if x.get("ip_address") == ip and writes.mac(str(x.get("mac"))) != mac
            ]
            if taken:
                raise WriteRefused(f"{ip} is already reserved for another device")
            after = {**(before or {"srcservice": ""}), "mac": mac, "ip_address": ip}
        elif before is None:
            raise WriteRefused(f"{mac} has no fixed IP")
        return Change(
            kind="lease", id=mac, label=self._device_label(mac), before=before, after=after
        )

    def plan_route(
        self, name: str, destination: str | None = None, next_hop: str | None = None
    ) -> Change:
        """Add or replace a static route; without destination it removes the route."""
        name = writes.name(name)
        before = writes.current(self.cloud, "route", name)
        after = None
        if destination is not None:
            if next_hop is None:
                raise WriteRefused("a route needs a next hop")
            lan, router = self._lan()
            after = {
                "name": name,
                "destination": writes.network(destination),
                "next_hop": writes.lan_ip(next_hop, lan, router, "next hop"),
            }
        elif before is None:
            raise WriteRefused(f"no static route named {name!r}")
        return Change(kind="route", id=name, label=name, before=before, after=after)

    def plan_forward(
        self,
        name: str,
        protocol: str | None = None,
        wan_port: str | None = None,
        lan_ip: str | None = None,
        lan_port: str | None = None,
    ) -> Change:
        """Add or replace a port forward; without protocol it removes the forward."""
        name = writes.name(name)
        before = writes.current(self.cloud, "forward", name)
        after = None
        if protocol is not None:
            if wan_port is None or lan_ip is None:
                raise WriteRefused("a port forward needs a WAN port and a LAN IP")
            proto = protocol.strip().lower()
            if proto not in ("tcp", "udp"):
                raise WriteRefused("protocol must be tcp or udp")
            wan = writes.port_range(wan_port, "WAN port")
            lan = writes.port_range(lan_port, "LAN port") if lan_port else wan
            if lan[1] - lan[0] != wan[1] - wan[0]:
                raise WriteRefused("WAN and LAN port ranges must be the same size")
            net, router = self._lan()
            after = {
                "name": name,
                "protocol": proto,
                "lan_ip": writes.lan_ip(lan_ip, net, router, "LAN IP"),
                "wan_port_start": wan[0],
                "wan_port_end": wan[1],
                "lan_port_start": lan[0],
                "lan_port_end": lan[1],
            }
        elif before is None:
            raise WriteRefused(f"no port forward named {name!r}")
        return Change(kind="forward", id=name, label=name, before=before, after=after)

    def apply(self, change: Change) -> Change:
        if not change.noop:
            writes.apply(self.cloud, change)
        return change
