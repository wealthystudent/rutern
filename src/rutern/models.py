"""Typed router data.

Every string that comes from the router passes through `clean`, because
devices pick their own hostnames and anyone on the WiFi can set one: no
terminal escapes, no bidi tricks, bounded length. The values stay untrusted
data; cleaning only makes them safe to display.

Secrets (`encryption_key`) are SecretStr: hidden in repr, and serialised as
"<redacted>" unless the caller passes context={"show_secrets": True}.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Annotated, Any

from pydantic import (
    AfterValidator,
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    SerializationInfo,
    ValidationError,
    field_serializer,
    field_validator,
    model_validator,
)

from rutern.errors import ApiError

REDACTED = "<redacted>"
MAX_TEXT = 128
MAX_ITEMS = 64
_INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
# Format (bidi, zero width, tags), lone surrogates (they crash UTF-8 output),
# private use and unassigned code points: none of them belong in a name.
_DROP = ("Cf", "Cs", "Co", "Cn")


def clean(value: str) -> str:
    """Strip control, format and other unprintable characters and bound the length."""
    value = _INVISIBLE.sub("", value)
    value = "".join(
        " " if unicodedata.category(c) in ("Cc", "Zl", "Zp") else c
        for c in value
        if unicodedata.category(c) not in _DROP
    )
    value = " ".join(value.split())
    return value[:MAX_TEXT]


def scrub(value: Any, depth: int = 0) -> Any:
    """Clean every string in a value of unknown shape, with nesting and size capped."""
    if isinstance(value, str):
        return clean(value)
    if value is None or isinstance(value, bool | int | float):
        return value
    if depth >= 3:
        return None
    if isinstance(value, list):
        return [scrub(v, depth + 1) for v in value[:MAX_ITEMS]]
    if isinstance(value, dict):
        return {clean(str(k)): scrub(v, depth + 1) for k, v in list(value.items())[:MAX_ITEMS]}
    return None


def parse[M: BaseModel](model: type[M], data: Any, what: str) -> M:
    """Validate router data; a mismatch is an ApiError that never repeats the values."""
    try:
        return model.model_validate(data)
    except ValidationError as e:
        raise ApiError(f"{what}: unexpected response shape ({e.error_count()} field(s))") from e


Text = Annotated[str, AfterValidator(clean)]


def normalise_mac(mac: str) -> str:
    """aa:bb:cc:dd:ee:ff from any common spelling, or ValueError."""
    hexdigits = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(hexdigits) != 12 or not re.fullmatch(r"[0-9A-Fa-f:\-. ]+", mac.strip()):
        raise ValueError(f"not a MAC address: {clean(mac)!r}")
    return ":".join(hexdigits[i : i + 2] for i in range(0, 12, 2)).lower()


class Model(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore", frozen=True)


# Local (sysbus)


class DeviceInfo(Model):
    product_class: Text = Field(validation_alias="ProductClass")
    serial: Text = Field(validation_alias="SerialNumber")
    firmware: Text = Field(validation_alias="SoftwareVersion")
    uptime: int = Field(validation_alias="UpTime")
    base_mac: Text = Field(validation_alias="BaseMAC")


class WanStatus(Model):
    link_state: Text = Field(validation_alias="LinkState")
    ipv4: Text = Field(validation_alias="IPAddress")
    ipv6: Text = Field("", validation_alias="IPv6Address")
    ipv6_prefix: Text = Field("", validation_alias="IPv6DelegatedPrefix")


ROLES = {"0": "main", "1": "guest", "2": "iot", "3": "tv"}
BANDS = {"2g": "2.4", "5g": "5", "6g": "6"}
_VAP = re.compile(r"^vap(2g|5g|6g)\d+_(\d+)$")


class Vap(Model):
    """One local WiFi access point (band x role) and its associated stations."""

    vap: str
    band: str
    role: str
    ssid: Text
    stations: list[str]


def parse_vaps(wlanvap: dict[str, Any]) -> list[Vap]:
    out = []
    for name, data in sorted(wlanvap.items()):
        m = _VAP.match(name)
        if not m or not isinstance(data, dict):
            continue
        stations = sorted(_macs(data.get("AssociatedDevice")))
        out.append(
            Vap(
                vap=name,
                band=BANDS[m.group(1)],
                role=ROLES.get(m.group(2), m.group(2)),
                ssid=str(data.get("SSID", "")),
                stations=stations,
            )
        )
    return out


def _macs(devices: Any) -> list[str]:
    """Station MACs, skipping keys that are not MACs (the local API is plain HTTP)."""
    out = []
    for k in devices if isinstance(devices, dict) else ():
        try:
            out.append(normalise_mac(str(k)))
        except ValueError:
            continue
    return out


# Cloud (/v1)


class Uptime(Model):
    os: int
    wan: int
    localtime: Text = ""
    last_seen: Text = ""


SNR_SENTINEL = 1_000_000


class Host(Model):
    mac: Text
    hostname: Text = ""
    alias: Text = Field("", validation_alias=AliasChoices("hostname_alias", "alias"))
    ipv4: Text = Field("", validation_alias=AliasChoices("ipv4_address", "ipv4"))
    ipv4_static: Text = Field(
        "", validation_alias=AliasChoices("ipv4_address_static", "ipv4_static")
    )
    ipv6: Text = Field("", validation_alias=AliasChoices("ipv6_address", "ipv6"))
    device_type: Text = ""
    vendor: Text = ""
    interface: Text = ""
    active: bool = False
    speculative: bool = False
    uptime: int | None = None
    phy_rate: int | None = None
    snr: int | None = None
    eth_port: Text | None = None
    wlan_band: Text | None = None
    wlan_ssid: Text | None = None
    wlan_signal_strength: int | None = None
    wlan_signal_quality: Text | None = None

    @field_validator("mac", mode="after")
    @classmethod
    def _mac(cls, v: str) -> str:
        return normalise_mac(v)

    @field_validator("snr", mode="after")
    @classmethod
    def _snr(cls, v: int | None) -> int | None:
        return None if v is None or v >= SNR_SENTINEL else v

    @field_validator("eth_port", mode="before")
    @classmethod
    def _port(cls, v: Any) -> Any:
        return None if v is None else str(v)

    @property
    def name(self) -> str:
        return self.alias or self.hostname or self.vendor or self.mac


class AliasEntry(Model):
    mac: Text
    alias: Text = Field(validation_alias=AliasChoices("hostname", "alias"))

    @field_validator("mac", mode="after")
    @classmethod
    def _mac(cls, v: str) -> str:
        return normalise_mac(v)


class WifiNetwork(Model):
    band: Text
    ssid: Text
    enabled: bool
    encryption: Text = ""
    encryption_key: SecretStr | None = None
    guest: bool = False
    hidden: bool = False
    group: int = 0
    rate_limit_up: int = 0
    rate_limit_down: int = 0

    @property
    def role(self) -> str:
        return ROLES.get(str(self.group), str(self.group))

    @field_serializer("encryption_key")
    def _key(self, v: SecretStr | None, info: SerializationInfo) -> str | None:
        if v is None:
            return None
        if info.context and info.context.get("show_secrets"):
            return v.get_secret_value()
        return REDACTED


class Wifi(Model):
    """`non_volatile` is the saved config, `volatile` the live radio state."""

    non_volatile: list[WifiNetwork]
    volatile: list[WifiNetwork]


# Network configuration (cloud). Each endpoint returns `non_volatile` (saved)
# and `volatile` (live); the saved side is what the portal edits.


class Open(BaseModel):
    """Items whose full field set is not known yet keep unknown fields, cleaned
    like every other router string and capped in size."""

    model_config = ConfigDict(populate_by_name=True, extra="allow", frozen=True)

    @model_validator(mode="before")
    @classmethod
    def _scrub_unknown(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        known = set(cls.model_fields)
        return {
            k if k in known else clean(str(k)): v if k in known else scrub(v)
            for k, v in list(data.items())[:MAX_ITEMS]
        }


class StaticLease(Model):
    """A fixed IP for a device (DHCP reservation)."""

    mac: Text
    ip: Text = Field(validation_alias=AliasChoices("ip_address", "ip"))

    @field_validator("mac", mode="after")
    @classmethod
    def _mac(cls, v: str) -> str:
        return normalise_mac(v)


class Leases(Model):
    reserved: list[StaticLease]
    active_reserved: list[StaticLease] = Field(default_factory=list)
    dynamic: list[StaticLease] = Field(default_factory=list)


class StaticRoute(Open):
    name: Text = ""
    destination: Text = ""
    next_hop: Text = ""


class PortForward(Open):
    name: Text = ""
    protocol: Text = ""
    lan_ip: Text = ""
    wan_port_start: int | None = None
    wan_port_end: int | None = None
    lan_port_start: int | None = None
    lan_port_end: int | None = None


class FirewallRule(Open):
    name: Text = ""
    protocol: Text = ""
    ip_version: Text | int | None = None
    src_ip_net: Text = ""
    src_port: Text | int | None = None
    dst_ip_net: Text = ""
    dst_port: Text | int | None = None


class Firewall(Model):
    ipv4_enabled: bool
    ipv6_enabled: bool
    rules: list[FirewallRule] = Field(default_factory=list)


class Dhcp(Model):
    enabled: bool
    router_address: Text = Field(validation_alias=AliasChoices("ipv4_address", "router_address"))
    first_address: Text
    last_address: Text
    lease_time: int


class Dns(Model):
    profile: str
    v4_servers: list[Text]
    v6_servers: list[Text] = Field(default_factory=list)


DNS_PROFILES = ("telenor", "nettvern", "nettvern_plus")


def parse_dns(data: dict[str, Any]) -> Dns:
    saved = data.get("non_volatile") or {}
    meta = data.get("meta") or {}
    v4 = [str(s) for s in saved.get("v4_servers") or []]
    profile = "custom"
    for name in DNS_PROFILES:
        if v4 and sorted(v4) == sorted(meta.get(f"v4_{name}_servers") or []):
            profile = name
            break
    return Dns(profile=profile, v4_servers=v4, v6_servers=saved.get("v6_servers") or [])


class UpnpMapping(Model):
    name: Text = ""
    protocol: Text = ""
    lan_ip: Text = ""
    lan_port_start: int = 0
    lan_port_end: int = 0
    wan_port_start: int = 0
    wan_port_end: int = 0


class Upnp(Model):
    enabled: bool
    mappings: list[UpnpMapping] = Field(default_factory=list)


class Network(Model):
    """The router's LAN-side configuration in one read."""

    dhcp: Dhcp
    dns: Dns
    firewall: Firewall
    dmz: Text | None
    upnp: Upnp
    leases: Leases
    routes: list[StaticRoute]
    forwards: list[PortForward]
