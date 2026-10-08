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
    field_serializer,
    field_validator,
)

REDACTED = "<redacted>"
MAX_TEXT = 128
_INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")


def clean(value: str) -> str:
    """Strip control and format characters and bound the length."""
    value = _INVISIBLE.sub("", value)
    value = "".join(
        " " if unicodedata.category(c) in ("Cc", "Zl", "Zp") else c
        for c in value
        if unicodedata.category(c) != "Cf"
    )
    value = " ".join(value.split())
    return value[:MAX_TEXT]


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
        stations = sorted(normalise_mac(k) for k in (data.get("AssociatedDevice") or {}))
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
