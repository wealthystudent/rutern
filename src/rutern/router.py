"""Router: one object over the local and cloud backends.

Local answers when it can (fast, offline, no credentials). Cloud is created
lazily, so commands that stay local never read Keychain or log in.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from rutern.cloud import CloudClient
from rutern.config import Config
from rutern.errors import ApiError, Unreachable, WriteRefused
from rutern.local import LocalClient
from rutern.models import (
    AliasEntry,
    DeviceInfo,
    Host,
    Model,
    Text,
    Uptime,
    Vap,
    WanStatus,
    Wifi,
    clean,
    normalise_mac,
)

MAX_ALIAS = 63


class Status(Model):
    source: Literal["local", "cloud"]
    device: DeviceInfo | None = None
    wan: WanStatus | None = None
    vaps: list[Vap] = Field(default_factory=list)
    uptime: Uptime | None = None


class AliasChange(Model):
    """A planned alias write: what it touches, before and after."""

    mac: str
    device: Text
    before: Text
    after: Text

    @property
    def noop(self) -> bool:
        return self.before == self.after


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

    # writes

    def plan_alias(self, mac: str, alias: str) -> AliasChange:
        """Validate and describe an alias change without writing anything."""
        try:
            mac = normalise_mac(mac)
        except ValueError as e:
            raise WriteRefused(str(e)) from e
        new = clean(alias)
        if new != alias.strip() or len(new) > MAX_ALIAS:
            raise WriteRefused(f"alias must be printable text of at most {MAX_ALIAS} characters")
        host = next((h for h in self.cloud.hosts() if h.mac == mac), None)
        if host is None:
            raise WriteRefused(f"no known device with MAC {mac}")
        current = {a.mac: a.alias for a in self.cloud.aliases()}
        return AliasChange(
            mac=mac,
            device=host.hostname or host.vendor or mac,
            before=current.get(mac, ""),
            after=new,
        )

    def apply_alias(self, change: AliasChange) -> AliasChange:
        """Write the full alias list with one entry changed, then read it back."""
        entries = {a.mac: a.alias for a in self.cloud.aliases()}
        if entries.get(change.mac, "") != change.before:
            raise WriteRefused("the alias changed since the plan was made; plan again")
        if change.after:
            entries[change.mac] = change.after
        else:
            entries.pop(change.mac, None)
        self.cloud.set_aliases([AliasEntry(mac=m, alias=a) for m, a in entries.items()])

        after = {a.mac: a.alias for a in self.cloud.aliases()}
        if after.get(change.mac, "") != change.after:
            raise ApiError("write sent but the read-back does not show the new alias")
        lost = {m for m in entries if m != change.mac and after.get(m) != entries[m]}
        if lost:
            raise ApiError(f"write changed {len(lost)} other alias(es); check the portal")
        return change
