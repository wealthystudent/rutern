"""Edits to the router's saved lists: aliases, fixed IPs, static routes, port forwards.

Every list endpoint takes the whole list back on POST, so one edit is: read
the saved list, change one entry, send the full list, read it back and check
that the entry changed and nothing else did. A plan records the entry as it
was; if it moved on before the write, the write is refused.

Verified live: the body keys (from the API's validation errors) and, for
aliases and fixed IPs, the item fields (by writing the saved list back
unchanged). Route and port forward item fields come from validation errors;
no real route or forward has been written yet.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Literal

from rutern.cloud import CloudClient
from rutern.errors import ApiError, WriteRefused
from rutern.models import Model, Text, clean, normalise_mac

Kind = Literal["alias", "lease", "route", "forward"]
MAX_NAME = 63


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


def saved(cloud: CloudClient, kind: Kind) -> list[dict[str, Any]]:
    """The saved list, trimmed to the fields rutern sends back."""
    spec = LISTS[kind]
    raw = cloud.get(spec.endpoint)
    items = raw.get("non_volatile") if isinstance(raw, dict) else None
    if not isinstance(items, list):
        raise ApiError(f"{spec.endpoint}: no saved list")
    return [{f: x[f] for f in spec.fields if f in x} for x in items if isinstance(x, dict)]


def current(cloud: CloudClient, kind: Kind, entry_id: str) -> dict[str, Any] | None:
    spec = LISTS[kind]
    return next(
        (x for x in saved(cloud, kind) if _id(spec, x.get(spec.id_field)) == entry_id), None
    )


def apply(cloud: CloudClient, change: Change) -> None:
    """Write the full list with one entry changed, then verify by read-back."""
    spec = LISTS[change.kind]
    items = saved(cloud, change.kind)
    ids = [_id(spec, x.get(spec.id_field)) for x in items]
    found = items[ids.index(change.id)] if change.id in ids else None
    if found != change.before:
        raise WriteRefused("the entry changed since the plan was made; plan again")

    if change.after is None:
        new = [x for x, i in zip(items, ids, strict=True) if i != change.id]
    elif change.id in ids:
        new = [change.after if i == change.id else x for x, i in zip(items, ids, strict=True)]
    else:
        new = [*items, change.after]
    cloud.post(spec.endpoint, {spec.body_key: new})

    after = {_id(spec, x.get(spec.id_field)): x for x in saved(cloud, change.kind)}
    got = after.get(change.id)
    if change.after is None:
        if got is not None:
            raise ApiError("write sent but the entry is still there on read-back")
    elif got is None or any(got.get(k) != v for k, v in change.after.items()):
        raise ApiError("write sent but the read-back does not show the change")
    others = [x for x, i in zip(items, ids, strict=True) if i != change.id]
    if any(after.get(_id(spec, x.get(spec.id_field))) != x for x in others):
        raise ApiError("write changed other entries too; check the portal")


# validation helpers


def name(value: str, what: str = "name") -> str:
    out = clean(value)
    if not out or out != value.strip() or len(out) > MAX_NAME:
        raise WriteRefused(f"{what} must be printable text of 1 to {MAX_NAME} characters")
    return out


def mac(value: str) -> str:
    try:
        return normalise_mac(value)
    except ValueError as e:
        raise WriteRefused(str(e)) from e


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


def network(value: str) -> str:
    try:
        net = ipaddress.IPv4Network(value.strip(), strict=False)
    except ValueError as e:
        raise WriteRefused(
            f"destination {clean(value)!r} is not an IPv4 network like 10.1.0.0/24"
        ) from e
    if net.prefixlen == 0:
        raise WriteRefused("a default route (0.0.0.0/0) is not allowed")
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
    return start, end


def describe(kind: Kind, entry: dict[str, Any] | None) -> str:
    """One line for a before/after entry."""
    if entry is None:
        return ""
    if kind == "alias":
        return str(entry.get("hostname", ""))
    if kind == "lease":
        return str(entry.get("ip_address", ""))
    if kind == "route":
        return f"{entry.get('destination')} via {entry.get('next_hop')}"
    wan = _ports(entry.get("wan_port_start"), entry.get("wan_port_end"))
    lan = _ports(entry.get("lan_port_start"), entry.get("lan_port_end"))
    return f"{entry.get('protocol')} {wan} to {entry.get('lan_ip')}:{lan}"


def _ports(start: Any, end: Any) -> str:
    return str(start) if end in (None, start) else f"{start}-{end}"
