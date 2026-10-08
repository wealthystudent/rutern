"""Where the router lives and which reference id it has."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

LOCAL_HOST = "10.0.0.138"
CLOUD_BASE = "https://wifi.telenor.no"

_REFERENCE_RE = re.compile(r'reference:\s*"(\d+)"')


def discover_reference(html: str) -> str | None:
    """Pull the reference id out of the landing page HTML."""
    m = _REFERENCE_RE.search(html)
    return m.group(1) if m else None


def state_dir() -> Path:
    """Per user state (login guard). Created on first use with private permissions."""
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "rutern"


@dataclass(frozen=True)
class Config:
    local_host: str = field(default_factory=lambda: os.environ.get("RUTERN_HOST", LOCAL_HOST))
    cloud_base: str = field(default_factory=lambda: os.environ.get("RUTERN_CLOUD", CLOUD_BASE))
    reference: str | None = field(default_factory=lambda: os.environ.get("RUTERN_REFERENCE"))
    timeout: float = 10.0

    @property
    def local_url(self) -> str:
        return f"http://{self.local_host}"
