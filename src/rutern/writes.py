"""Edits to the router's saved lists: aliases, fixed IPs, static routes, port forwards.

Every list endpoint takes the whole list back on POST, so one edit is: read
the saved list, change one entry, send the full list, read it back and check
that the entry changed and nothing else did. A plan records the entry as it
was; if it moved on before the write, the write is refused.

Untouched entries go back exactly as read. A list holding a field rutern does
not know is refused outright, since nothing proves the portal keeps that
field on the round trip. The read-back compares whole entries, not a subset.

Verified live: the body keys (from the API's validation errors) and, for
aliases and fixed IPs, the item fields (by writing the saved list back
unchanged). Route and port forward item fields come from validation errors;
no real route or forward has been written yet.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import Field

from rutern import audit
from rutern.cloud import CloudClient
from rutern.errors import ApiError, WriteRefused
from rutern.models import Model, Text, clean, normalise_mac

Kind = Literal["alias", "lease", "route", "forward"]
KINDS: tuple[Kind, ...] = ("alias", "lease", "route", "forward")
MAX_NAME = 63
MAX_FORWARD_PORTS = 100

# Routes may only point at private space, so no route can pull internet
# traffic (all of it, or one resolver) through a device on the LAN.
ROUTABLE = tuple(
    ipaddress.IPv4Network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
)

# Services that are common targets when exposed to the internet.
RISKY_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    111: "rpcbind",
    135: "msrpc",
    137: "netbios",
    138: "netbios",
    139: "netbios",
    161: "snmp",
    389: "ldap",
    445: "smb",
    1433: "mssql",
    1900: "upnp",
    2049: "nfs",
    2375: "docker",
    2376: "docker",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm",
    6379: "redis",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}


@dataclass(frozen=True)
class ListSpec:
    endpoint: str
    body_key: str
    id_field: str
    fields: tuple[str, ...]


LISTS: dict[Kind, ListSpec] = {
    "alias": ListSpec("lan-hosts/alias", "hosts", "mac", ("mac", "hostname")),
    "lease": ListSpec("static-dhcp-leases", "leases", "mac", ("mac", "ip_address", "srcservice")),
    "route": ListSpec("static-routes", "rules", "name", ("name", "destination", "next_hop")),
    "forward": ListSpec(
        "nat-rules",
        "rules",
        "name",
        (
            "name",
            "protocol",
            "lan_ip",
            "wan_port_start",
            "wan_port_end",
            "lan_port_start",
            "lan_port_end",
        ),
    ),
}


class Change(Model):
    """One planned edit: which entry, how it looks before and after."""

    kind: Kind
    id: str
    label: Text
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    warnings: list[str] = Field(default_factory=list)

    @property
    def noop(self) -> bool:
        return self.before == self.after


def _id(spec: ListSpec, value: Any) -> str:
    text = str(value)
    if spec.id_field == "mac":
        try:
            return normalise_mac(text)
        except ValueError:
            return text
    return text


def _read(cloud: CloudClient, spec: ListSpec) -> list[dict[str, Any]]:
    raw = cloud.get(spec.endpoint)
    items = raw.get("non_volatile") if isinstance(raw, dict) else None
    if not isinstance(items, list) or not all(isinstance(x, dict) for x in items):
        raise ApiError(f"{spec.endpoint}: no saved list")
    return items


def saved(cloud: CloudClient, kind: Kind) -> list[dict[str, Any]]:
    """The saved list exactly as stored, refused when an entry has a field
    rutern does not know (sending it back could drop that field)."""
    spec = LISTS[kind]
    items = _read(cloud, spec)
    unknown = sorted({k for x in items for k in x} - set(spec.fields))
    if unknown:
        names = ", ".join(clean(str(k)) for k in unknown[:5])
        raise WriteRefused(
            f"saved {spec.endpoint} entries have fields rutern does not know ({names}); "
            "writing the list back could drop them, so rutern will not write it"
        )
    return items


def _ids(spec: ListSpec, items: list[dict[str, Any]]) -> list[str]:
    return [_id(spec, x.get(spec.id_field)) for x in items]


def _one(ids: list[str], entry_id: str) -> None:
    if ids.count(entry_id) > 1:
        raise WriteRefused(
            f"{ids.count(entry_id)} saved entries share {entry_id}; fix that in the portal first"
        )


def current(cloud: CloudClient, kind: Kind, entry_id: str) -> dict[str, Any] | None:
    spec = LISTS[kind]
    items = saved(cloud, kind)
    ids = _ids(spec, items)
    _one(ids, entry_id)
    return items[ids.index(entry_id)] if entry_id in ids else None


def _bag(items: list[dict[str, Any]]) -> list[str]:
    return sorted(json.dumps(x, sort_keys=True) for x in items)


def apply(cloud: CloudClient, change: Change, *, channel: str = "library", by: str = "") -> None:
    """Write the full list with one entry changed, then verify by read-back.
    The audit log gets the intent (with the list as it was) first, then the outcome."""
    spec = LISTS[change.kind]
    items = saved(cloud, change.kind)
    ids = _ids(spec, items)
    _one(ids, change.id)
    found = items[ids.index(change.id)] if change.id in ids else None
    if found != change.before:
        raise WriteRefused("the entry changed since the plan was made; plan again")

    if change.after is None:
        new = [x for x, i in zip(items, ids, strict=True) if i != change.id]
    elif change.id in ids:
        new = [change.after if i == change.id else x for x, i in zip(items, ids, strict=True)]
    else:
        new = [*items, change.after]
    write_id = audit.intent(
        {
            "channel": channel,
            "by": by,
            "kind": change.kind,
            "id": change.id,
            "endpoint": spec.endpoint,
            "before": change.before,
            "after": change.after,
            "list_before": items,
        }
    )
    try:
        cloud.post(spec.endpoint, {spec.body_key: new})
        _verify(cloud, spec, change, items, ids)
    except Exception as e:
        audit.outcome(write_id, f"failed: {type(e).__name__}: {e}")
        raise
    audit.outcome(write_id, "verified")


def _verify(
    cloud: CloudClient,
    spec: ListSpec,
    change: Change,
    items: list[dict[str, Any]],
    ids: list[str],
) -> None:
    back = _read(cloud, spec)
    back_ids = _ids(spec, back)
    got = [x for x, i in zip(back, back_ids, strict=True) if i == change.id]
    if change.after is None:
        if got:
            raise ApiError("write sent but the entry is still there on read-back")
    elif len(got) != 1 or any(got[0].get(k) != v for k, v in change.after.items()):
        raise ApiError("write sent but the read-back does not show the change")
    others = [x for x, i in zip(items, ids, strict=True) if i != change.id]
    back_others = [x for x, i in zip(back, back_ids, strict=True) if i != change.id]
    if _bag(back_others) != _bag(others):
        raise ApiError("write changed other entries too; check the portal")


# validation helpers


def name(value: str, what: str = "name") -> str:
    out = clean(value)
    if not out or out != value.strip() or len(out) > MAX_NAME:
        raise WriteRefused(f"{what} must be printable text of 1 to {MAX_NAME} characters")
    return out


def mac(value: str) -> str:
    """A single device's MAC: not zero, broadcast or multicast."""
    try:
        out = normalise_mac(value)
    except ValueError as e:
        raise WriteRefused(str(e)) from e
    if out == "00:00:00:00:00:00" or int(out[:2], 16) & 1:
        raise WriteRefused(f"{out} is not a device address (zero, broadcast or multicast)")
    return out


def lan_network(router_address: str) -> ipaddress.IPv4Network:
    try:
        return ipaddress.IPv4Interface(router_address).network
    except ValueError as e:
        raise ApiError(f"router LAN address is not usable: {router_address!r}") from e


def lan_ip(value: str, lan: ipaddress.IPv4Network, router: str, what: str = "IP") -> str:
    try:
        ip = ipaddress.IPv4Address(value.strip())
    except ValueError as e:
        raise WriteRefused(f"{what} {clean(value)!r} is not an IPv4 address") from e
    if ip not in lan or ip in (lan.network_address, lan.broadcast_address):
        raise WriteRefused(f"{what} {ip} is not a host address in the LAN {lan}")
    if str(ip) == router.split("/")[0]:
        raise WriteRefused(f"{what} {ip} is the router itself")
    return str(ip)


def network(value: str, lan: ipaddress.IPv4Network) -> str:
    """A route destination: private, and clear of the LAN itself."""
    try:
        net = ipaddress.IPv4Network(value.strip(), strict=False)
    except ValueError as e:
        raise WriteRefused(
            f"destination {clean(value)!r} is not an IPv4 network like 10.1.0.0/24"
        ) from e
    if not any(net.subnet_of(r) for r in ROUTABLE):
        raise WriteRefused(
            f"destination {net} is not a private network; routes may only point at "
            "10/8, 172.16/12, 192.168/16 or 100.64/10"
        )
    if net.overlaps(lan):
        raise WriteRefused(f"destination {net} overlaps the LAN {lan}")
    return str(net)


def port_range(value: str, what: str) -> tuple[int, int]:
    """'443' or '8000-8010'."""
    start_s, _, end_s = value.strip().partition("-")
    try:
        start, end = int(start_s), int(end_s or start_s)
    except ValueError as e:
        raise WriteRefused(f"{what} must be a port like 443 or a range like 8000-8010") from e
    if not 1 <= start <= end <= 65535:
        raise WriteRefused(f"{what} must be between 1 and 65535, low to high")
    if end - start + 1 > MAX_FORWARD_PORTS:
        raise WriteRefused(f"{what} spans more than {MAX_FORWARD_PORTS} ports")
    return start, end


def risky(*ranges: tuple[int, int]) -> list[str]:
    """Names of well known services inside the given port ranges."""
    hits = {
        f"{port} ({svc})"
        for lo, hi in ranges
        for port, svc in RISKY_PORTS.items()
        if lo <= port <= hi
    }
    return sorted(hits, key=lambda s: int(s.split()[0]))


def describe(kind: Kind, entry: dict[str, Any] | None) -> str:
    """One line for a before/after entry. Values pass through clean, since a
    saved list can hold anything the portal accepted."""
    if entry is None:
        return ""

    def v(key: str) -> str:
        return clean(str(entry.get(key, "")))

    if kind == "alias":
        return v("hostname")
    if kind == "lease":
        return v("ip_address")
    if kind == "route":
        return f"{v('destination')} via {v('next_hop')}"
    wan = _ports(v("wan_port_start"), v("wan_port_end"))
    lan = _ports(v("lan_port_start"), v("lan_port_end"))
    return f"{v('protocol')} {wan} to {v('lan_ip')}:{lan}"


def _ports(start: str, end: str) -> str:
    return start if end in ("", start) else f"{start}-{end}"
