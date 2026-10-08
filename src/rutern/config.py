"""Where the router lives and which reference id it has."""

from __future__ import annotations

import ipaddress
import os
import pwd
import re
from dataclasses import dataclass, field
from pathlib import Path

from rutern.errors import ConfigError

LOCAL_HOST = "10.0.0.138"
# Fixed on purpose: the admin password and the session cookie only ever go here.
CLOUD_BASE = "https://wifi.telenor.no"

_REFERENCE_RE = re.compile(r'reference:\s*"([0-9]+)"')
_DIGITS = re.compile(r"[0-9]{1,20}")
_LAN_RANGES = tuple(
    ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def valid_reference(value: str | None) -> bool:
    """ASCII digits only; str.isdigit and \\d also accept digits like '²' and '٣'."""
    return value is not None and _DIGITS.fullmatch(value) is not None


def discover_reference(html: str) -> str | None:
    """Pull the reference id out of the landing page HTML."""
    m = _REFERENCE_RE.search(html)
    return m.group(1) if m else None


def home() -> Path:
    """The account's home from the password database. HOME and the XDG_* variables
    are ignored on purpose: whoever sets env for a command could otherwise point
    rutern at their own policy, an empty login guard or a hidden audit log."""
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def state_dir() -> Path:
    """Per user state (login guard, pinned reference, audit log)."""
    return home() / ".local" / "state" / "rutern"


def write_private(path: Path, text: str, *, append: bool = False) -> None:
    """Write a file only the user can read, in a directory only the user can enter."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, text.encode())
    finally:
        os.close(fd)


def _local_host(value: str) -> str:
    try:
        ip = ipaddress.IPv4Address(value.strip())
    except ValueError:
        raise ConfigError("RUTERN_HOST must be the router's LAN IPv4 address") from None
    if not any(ip in n for n in _LAN_RANGES):
        raise ConfigError("RUTERN_HOST must be a private LAN address (10/8, 172.16/12, 192.168/16)")
    return str(ip)


@dataclass(frozen=True)
class Config:
    local_host: str = field(default_factory=lambda: os.environ.get("RUTERN_HOST", LOCAL_HOST))
    reference: str | None = field(
        default_factory=lambda: os.environ.get("RUTERN_REFERENCE") or None
    )
    timeout: float = 10.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "local_host", _local_host(self.local_host))
        if self.reference is not None and not valid_reference(self.reference):
            raise ConfigError("RUTERN_REFERENCE must be the router's numeric reference id")

    @property
    def cloud_base(self) -> str:
        return CLOUD_BASE

    @property
    def local_url(self) -> str:
        return f"http://{self.local_host}"
