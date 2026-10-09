"""Record router responses as scrubbed test fixtures.

    uv run python scripts/record_fixtures.py local
    uv run python scripts/record_fixtures.py cloud   # one login via Keychain

Raw responses are scrubbed in memory before anything is written. Nothing
raw is printed: the script reports file names and a key/type outline only.
Secrets (keys, passphrases, serials), MACs, hostnames, vendors, SSIDs,
public IPv4 and IPv6 addresses are replaced with stable placeholders.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"

SECRET_KEY = re.compile(r"key|pass|secret|psk|pin|token|cookie|credential", re.I)
SERIAL_KEY = re.compile(r"serial", re.I)
NAME_KEY = re.compile(r"^(hostname|hostname_alias|name|alias|devicename|friendlyname)$", re.I)
SSID_KEY = re.compile(r"ssid$", re.I)
VENDOR_KEY = re.compile(r"^vendor$", re.I)
MAC_RE = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b")
V4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
V6_RE = re.compile(r"\b[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:/\d{1,3})?")
NOT_SECRET = {"encryption", "keepalive", "pincode_enabled"}


class Scrubber:
    def __init__(self) -> None:
        self.maps: dict[str, dict[str, str]] = {}
        self.secrets: set[str] = set()

    def _sub(self, kind: str, value: str, fmt: str) -> str:
        m = self.maps.setdefault(kind, {})
        if value not in m:
            m[value] = fmt.format(len(m) + 1)
        return m[value]

    def mac(self, value: str) -> str:
        return self._sub("mac", value.lower(), "02:00:00:00:00:{:02x}")

    def text(self, s: str) -> str:
        s = MAC_RE.sub(lambda m: self.mac(m.group(0)), s)

        def v4(m: re.Match[str]) -> str:
            try:
                ip = ipaddress.IPv4Address(m.group(0))
            except ValueError:
                return m.group(0)
            if ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_link_local:
                return m.group(0)
            return self._sub("v4", str(ip), "203.0.113.{}")

        def v6(m: re.Match[str]) -> str:
            raw = m.group(0)
            addr, _, plen = raw.partition("/")
            try:
                ip = ipaddress.IPv6Address(addr)
            except ValueError:
                return raw
            if ip.is_link_local or ip.is_loopback or ip.is_unspecified:
                out = self._sub("v6ll", str(ip), "fe80::{:x}")
            else:
                out = self._sub("v6", str(ip), "2001:db8::{:x}")
            return f"{out}/{plen}" if plen else out

        s = V4_RE.sub(v4, s)
        return V6_RE.sub(v6, s)

    def walk(self, obj: Any, key: str = "") -> Any:
        if isinstance(obj, dict):
            return {self.text(k): self.walk(v, k) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.walk(v, key) for v in obj]
        if not isinstance(obj, str) or obj == "":
            return obj
        if SECRET_KEY.search(key) and key.lower() not in NOT_SECRET:
            self.secrets.add(obj)
            return "REDACTED"
        if SERIAL_KEY.search(key):
            return "S000000000000"
        if SSID_KEY.search(key):
            return self._sub("ssid", obj, "ssid-{}")
        if NAME_KEY.match(key):
            return self._sub("name", obj, "device-{}")
        if VENDOR_KEY.match(key):
            return self._sub("vendor", obj, "vendor-{}")
        if "version" in key.lower():
            return obj
        return self.text(obj)


def outline(obj: Any, path: str = "", out: list[str] | None = None, depth: int = 0) -> list[str]:
    """Key paths and value types, no values."""
    out = [] if out is None else out
    if depth > 6:
        return out
    if isinstance(obj, dict):
        for k, v in list(obj.items())[:40]:
            outline(v, f"{path}.{k}", out, depth + 1)
    elif isinstance(obj, list):
        out.append(f"{path}[] len={len(obj)}")
        if obj:
            outline(obj[0], f"{path}[0]", out, depth + 1)
    else:
        out.append(f"{path}: {type(obj).__name__}")
    return out


def write(name: str, data: Any) -> None:
    path = FIXTURES / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {path.relative_to(FIXTURES.parent.parent)}")


def leak_check(secrets: set[str]) -> None:
    """Fail if any captured secret value appears in any fixture file."""
    hits = 0
    for f in FIXTURES.rglob("*.json"):
        text = f.read_text()
        for s in secrets:
            if len(s) >= 4 and s in text:
                print(f"LEAK in {f.name}")
                hits += 1
    if hits:
        sys.exit(1)
    print(f"leak check ok ({len(secrets)} secret values checked)")


CLOUD_READS = (
    "uptime",
    "lan-hosts",
    "wlan",
    "lan-hosts/alias",
    "static-dhcp-leases",
    "static-routes",
    "dhcp",
    "nat-rules",
    "dmz",
    "dns",
    "firewall-status",
    "firewall-rules",
    "upnp",
    "upnp/mappings",
)


def record_local(sc: Scrubber) -> None:
    from rutern.local import LocalClient

    calls = {
        "deviceinfo.json": ("DeviceInfo", "get", {}),
        "wanstatus.json": ("NMC", "getWANStatus", {}),
        "wlanvap.json": ("NeMo.Intf.lan", "getMIBs", {"mibs": "wlanvap"}),
    }
    c = LocalClient()
    try:
        for name, (svc, method, params) in calls.items():
            write(f"local/{name}", sc.walk(c.call(svc, method, params)))
    finally:
        c.close()


def record_cloud(sc: Scrubber) -> None:
    from rutern.cloud import CloudClient
    from rutern.errors import ApiError

    c = CloudClient()
    try:
        for ep in CLOUD_READS:
            name = ep.replace("/", "-") + ".json"
            try:
                write(f"cloud/{name}", sc.walk(c.get(ep)))
            except ApiError as e:
                print(f"{ep}: {e}")
    finally:
        c.close()


def main() -> None:
    which = sys.argv[1:] or ["local"]
    sc = Scrubber()
    if "local" in which:
        record_local(sc)
    if "cloud" in which:
        record_cloud(sc)
    leak_check(sc.secrets | set(sc.maps.get("ssid", {})))
    for f in sorted(FIXTURES.rglob("*.json")):
        print(f"\n# {f.relative_to(FIXTURES)}")
        print("\n".join(outline(json.loads(f.read_text()))))


if __name__ == "__main__":
    main()
