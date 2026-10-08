"""rutern command line."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from typing import Any

from pydantic import BaseModel

from rutern import __version__, look, writes
from rutern.errors import ConfigError, RuternError, WriteRefused
from rutern.models import (
    Firewall,
    Host,
    Leases,
    Network,
    PortForward,
    StaticRoute,
    Upnp,
    Wifi,
    WifiNetwork,
)
from rutern.router import Router, Status
from rutern.writes import Change


def duration(seconds: int | None) -> str:
    if not seconds:
        return "-"
    d, rem = divmod(int(seconds), 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    parts = [f"{d}d"] if d else []
    if d or h:
        parts.append(f"{h}h")
    if not d:
        parts.append(f"{m}m")
    return " ".join(parts)


def dump(data: Any, show_secrets: bool = False) -> str:
    def conv(x: Any) -> Any:
        if isinstance(x, BaseModel):
            return x.model_dump(mode="json", context={"show_secrets": show_secrets})
        if isinstance(x, list):
            return [conv(i) for i in x]
        if isinstance(x, dict):
            return {k: conv(v) for k, v in x.items()}
        return x

    return json.dumps(conv(data), indent=2, ensure_ascii=False)


# renderers


def render_status(s: Status) -> str:
    out = []
    if s.device:
        d = s.device
        pairs = [
            ("model", f"{d.product_class}"),
            ("firmware", d.firmware),
            ("serial", d.serial),
            ("uptime", duration(d.uptime)),
        ]
        if s.wan:
            state = look.fg(look.OK if s.wan.link_state == "up" else look.ERROR, s.wan.link_state)
            pairs += [("wan", state), ("ipv4", s.wan.ipv4), ("ipv6", s.wan.ipv6 or "-")]
            pairs.append(("prefix", s.wan.ipv6_prefix or "-"))
        out.append(look.frame("router", look.kv(pairs)))
    if s.vaps:
        rows = [
            [
                v.role,
                f"{v.band} GHz",
                v.ssid or look.fg(look.DIM, "-"),
                str(len(v.stations)) if v.stations else look.fg(look.DIM, "0"),
            ]
            for v in sorted(s.vaps, key=lambda v: (v.role != "main", v.role, float(v.band)))
        ]
        out.append(look.frame("wifi", look.table(["role", "band", "ssid", "clients"], rows)))
    if s.uptime:
        out.append(
            look.frame(
                "router (cloud)",
                look.kv([("uptime", duration(s.uptime.os)), ("seen", s.uptime.last_seen)]),
            )
        )
    if s.source == "local":
        out.append(
            look.fg(look.DIM, "local only. `rutern devices` lists names and IPs via the cloud")
        )
    else:
        out.append(look.fg(look.DIM, "router not reachable on the LAN; showing cloud data"))
    return "\n".join(out)


def link(h: Host) -> str:
    if h.interface == "wlan":
        parts = [f"{h.wlan_band} GHz" if h.wlan_band else "wifi"]
        if h.wlan_signal_strength is not None and h.active:
            q = h.wlan_signal_quality or ""
            role = {"strong": look.OK, "fair": look.KEY, "weak": look.ERROR}.get(q, look.DIM)
            parts.append(look.fg(role, f"{h.wlan_signal_strength}%"))
        return " ".join(parts)
    if h.interface == "ethernet":
        return f"eth {h.eth_port}" if h.eth_port else "ethernet"
    return h.interface or "-"


def render_hosts(hosts: list[Host]) -> str:
    rows = []
    for h in hosts:
        dot = look.fg(look.OK, "●") if h.active else look.fg(look.DIM, "○")
        name = h.name if h.active else look.fg(look.DIM, h.name)
        ip = h.ipv4 or "-"
        if h.ipv4_static:
            ip += look.fg(look.INFO, " s")
        rows.append([dot, name, ip, h.mac, h.device_type or "-", link(h)])
    n_active = sum(h.active for h in hosts)
    lines = look.table(["", "name", "ipv4", "mac", "type", "link"], rows)
    summary = (
        f"{n_active} active" if n_active == len(hosts) else f"{n_active} active, {len(hosts)} total"
    )
    lines.append(look.fg(look.DIM, summary))
    return look.frame("devices", lines)


def render_wifi(wifi: Wifi, live: bool, show_secrets: bool) -> str:
    nets: list[WifiNetwork] = wifi.volatile if live else wifi.non_volatile
    rows = []
    for n in sorted(nets, key=lambda n: (n.group, float(n.band))):
        if n.encryption_key is None:
            key = look.fg(look.DIM, "-")
        elif show_secrets:
            key = n.encryption_key.get_secret_value()
        else:
            key = look.fg(look.DIM, "••••••••")
        flags = [f for f, on in (("guest", n.guest), ("hidden ssid", n.hidden)) if on]
        rows.append(
            [
                n.role,
                f"{n.band} GHz",
                n.ssid if n.enabled else look.fg(look.DIM, n.ssid),
                look.fg(look.OK, "on") if n.enabled else look.fg(look.DIM, "off"),
                n.encryption or "-",
                key,
                ", ".join(flags),
            ]
        )
    heading = "wifi (live)" if live else "wifi (saved)"
    lines = look.table(["role", "band", "ssid", "", "security", "key", ""], rows, max_col=64)
    if not show_secrets:
        lines.append(look.fg(look.DIM, "keys hidden; --show-secrets reveals them"))
    return look.frame(heading, lines)


TITLES = {"alias": "alias", "lease": "fixed ip", "route": "static route", "forward": "port forward"}


def render_change(c: Change) -> str:
    before, after = writes.describe(c.kind, c.before), writes.describe(c.kind, c.after)
    action = "add" if c.before is None else "remove" if c.after is None else "change"
    what = f"{c.label}  {look.fg(look.DIM, c.id)}" if c.label != c.id else c.label
    return look.frame(
        f"{action} {TITLES[c.kind]}",
        look.kv(
            [
                ("entry", what),
                ("before", look.fg(look.ERROR, before) if before else look.fg(look.DIM, "(none)")),
                ("after", look.fg(look.OK, after) if after else look.fg(look.DIM, "(none)")),
            ]
        ),
    )


def on_off(on: bool) -> str:
    return look.fg(look.OK, "on") if on else look.fg(look.DIM, "off")


def none_row(text: str) -> list[str]:
    return [look.fg(look.DIM, text)]


def render_network(n: Network) -> str:
    d = n.dhcp
    lease = duration(d.lease_time)
    pairs = [
        ("lan", d.router_address),
        ("dhcp", f"{on_off(d.enabled)}  {d.first_address} to {d.last_address}, lease {lease}"),
        ("dns", f"{n.dns.profile}  " + look.fg(look.DIM, ", ".join(n.dns.v4_servers))),
        (
            "firewall",
            f"ipv4 {on_off(n.firewall.ipv4_enabled)}  ipv6 {on_off(n.firewall.ipv6_enabled)}  "
            f"{len(n.firewall.rules)} custom rule(s)",
        ),
        ("dmz", n.dmz or look.fg(look.DIM, "off")),
        ("upnp", f"{on_off(n.upnp.enabled)}  {len(n.upnp.mappings)} mapping(s)"),
        ("fixed ips", str(len(n.leases.reserved))),
        ("routes", str(len(n.routes))),
        ("forwards", str(len(n.forwards))),
    ]
    more = look.fg(look.DIM, "details: ") + look.hint(
        ("leases", "fixed IPs"),
        ("routes", "static routes"),
        ("forwards", "ports"),
        ("firewall", "rules"),
    )
    return look.frame("network", look.kv(pairs)) + "\n" + more


def render_leases(leases: Leases, hosts: list[Host]) -> str:
    by_mac = {h.mac: h for h in hosts}
    rows = []
    for lease in sorted(
        leases.reserved, key=lambda x: tuple(int(p) for p in x.ip.split(".") if p.isdigit())
    ):
        h = by_mac.get(lease.mac)
        online = h is not None and h.active
        dot = look.fg(look.OK, "●") if online else look.fg(look.DIM, "○")
        name = h.name if h else look.fg(look.DIM, "unknown device")
        rows.append([dot, lease.ip, name, lease.mac])
    lines = look.table(["", "ip", "device", "mac"], rows)
    lines.append(
        look.fg(look.DIM, f"{len(leases.reserved)} fixed IPs, {len(leases.dynamic)} dynamic leases")
    )
    return look.frame("fixed ips", lines)


def render_routes(routes: list[StaticRoute]) -> str:
    rows = [[r.name, r.destination, r.next_hop] for r in routes]
    lines = (
        look.table(["name", "destination", "next hop"], rows)
        if rows
        else none_row("no static routes")
    )
    return look.frame("static routes", lines)


def ports(start: int, end: int) -> str:
    return str(start) if start == end else f"{start}-{end}"


def render_forwards(forwards: list[PortForward], upnp: Upnp) -> str:
    rows = [
        [f.name, f.protocol, str(f.wan_port or "-"), f.lan_ip, str(f.lan_port or "-")]
        for f in forwards
    ]
    head = ["name", "proto", "wan port", "to ip", "port"]
    out = [
        look.frame(
            "port forwards", look.table(head, rows) if rows else none_row("no port forwards")
        )
    ]
    if upnp.enabled:
        urows = [
            [
                m.name,
                m.protocol,
                ports(m.wan_port_start, m.wan_port_end),
                m.lan_ip,
                ports(m.lan_port_start, m.lan_port_end),
            ]
            for m in upnp.mappings
        ]
        lines = look.table(head, urows) if urows else none_row("no mappings")
        out.append(look.frame("upnp (opened by devices)", lines))
    else:
        out.append(look.fg(look.DIM, "upnp off"))
    return "\n".join(out)


def render_firewall(fw: Firewall) -> str:
    lines = look.kv([("ipv4", on_off(fw.ipv4_enabled)), ("ipv6", on_off(fw.ipv6_enabled))])
    rows = [
        [
            r.name,
            r.protocol,
            str(r.ip_version or "-"),
            r.src_ip_net or "any",
            str(r.src_port or "any"),
            r.dst_ip_net or "any",
            str(r.dst_port or "any"),
        ]
        for r in fw.rules
    ]
    lines.append("")
    if rows:
        lines += look.table(["name", "proto", "ip", "from", "port", "to", "port"], rows)
    else:
        lines.append(look.fg(look.DIM, "no custom rules"))
    return look.frame("firewall", lines)


# commands


def cmd_status(r: Router, a: argparse.Namespace) -> str:
    s = r.status()
    return dump(s) if a.json else render_status(s)


def cmd_devices(r: Router, a: argparse.Namespace) -> str:
    hosts = r.hosts(active_only=not a.all)
    return dump(hosts) if a.json else render_hosts(hosts)


def cmd_wifi(r: Router, a: argparse.Namespace) -> str:
    w = r.wifi()
    if a.json:
        nets = w.volatile if a.live else w.non_volatile
        return dump(nets, show_secrets=a.show_secrets)
    return render_wifi(w, a.live, a.show_secrets)


def cmd_network(r: Router, a: argparse.Namespace) -> str:
    n = r.network()
    return dump(n) if a.json else render_network(n)


def cmd_leases(r: Router, a: argparse.Namespace) -> str:
    leases = r.cloud.leases()
    if a.json:
        return dump(leases)
    return render_leases(leases, r.hosts())


def cmd_routes(r: Router, a: argparse.Namespace) -> str:
    routes = r.cloud.routes()
    return dump(routes) if a.json else render_routes(routes)


def cmd_forwards(r: Router, a: argparse.Namespace) -> str:
    forwards, upnp = r.cloud.forwards(), r.cloud.upnp()
    if a.json:
        return dump({"forwards": forwards, "upnp": upnp})
    return render_forwards(forwards, upnp)


def cmd_firewall(r: Router, a: argparse.Namespace) -> str:
    fw = r.cloud.firewall()
    return dump(fw) if a.json else render_firewall(fw)


def confirm(prompt: str) -> bool:
    if not sys.stdin.isatty():
        return False
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        return False


def run_change(r: Router, a: argparse.Namespace, change: Change) -> str:
    """The shared write flow: show, dry run or confirm, write, verify."""
    shown = render_change(change)
    if change.noop:
        return dump({"changed": False, **change.model_dump()}) if a.json else shown + "\nno change"
    if a.dry_run:
        if a.json:
            return dump({"dry_run": True, **change.model_dump()})
        return shown + "\ndry run, nothing written"
    if change.kind == "forward" and change.after and not a.json:
        shown += "\n" + look.fg(look.KEY, "this opens a port on your public IP to the internet")
    if not a.yes:
        if not a.json:
            print(shown)
        if not confirm(f"apply? {look.fg(look.KEY, 'y')}/{look.fg(look.KEY, 'N')} "):
            raise WriteRefused("not confirmed; nothing written (pass --yes when not interactive)")
    r.apply(change)
    if a.json:
        return dump({"changed": True, "verified": True, **change.model_dump()})
    return (shown + "\n" if a.yes else "") + look.fg(look.OK, "written and verified by read-back")


def cmd_alias(r: Router, a: argparse.Namespace) -> str:
    return run_change(r, a, r.plan_alias(a.mac, "" if a.action == "clear" else a.name))


def cmd_lease_write(r: Router, a: argparse.Namespace) -> str:
    return run_change(r, a, r.plan_lease(a.mac, a.ip if a.action == "set" else None))


def cmd_route_write(r: Router, a: argparse.Namespace) -> str:
    if a.action == "remove":
        return run_change(r, a, r.plan_route(a.name))
    return run_change(r, a, r.plan_route(a.name, a.destination, a.next_hop))


def cmd_forward_write(r: Router, a: argparse.Namespace) -> str:
    if a.action == "remove":
        return run_change(r, a, r.plan_forward(a.name))
    return run_change(r, a, r.plan_forward(a.name, a.protocol, a.wan_port, a.lan_ip, a.lan_port))


def cmd_login(r: Router, a: argparse.Namespace) -> str:
    if not r.cloud.has_reference:
        # The portal names the router by public IP, which only means this
        # router when you are on its LAN. Away from home it names someone else's.
        try:
            r.local.device_info()
        except RuternError as e:
            raise ConfigError(
                "the router does not answer on this LAN, so its reference cannot be "
                "found safely; run `rutern login` at home or set RUTERN_REFERENCE"
            ) from e
        r.cloud.find_reference()
    r.cloud.login()
    return look.fg(look.OK, "logged in; session cached in Keychain, router reference saved")


def cmd_logout(r: Router, a: argparse.Namespace) -> str:
    r.cloud.logout()
    return "session forgotten and login guard cleared"


def cmd_mcp(r: Router, a: argparse.Namespace) -> str:
    from rutern.mcp_server import serve

    r.close()
    serve(allow_writes=a.allow_writes)
    return ""


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rutern", description="Read and configure a Telenor EX5700 router."
    )
    p.add_argument("--version", action="version", version=f"rutern {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="machine readable output")
    common.add_argument("--no-color", action="store_true", help="plain output")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="command")

    s = sub.add_parser("status", parents=[common], help="device, WAN and WiFi (local first)")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("devices", parents=[common], help="devices online now, with names and IPs")
    s.add_argument("--all", action="store_true", help="include devices that are offline")
    s.set_defaults(fn=cmd_devices)

    s = sub.add_parser("wifi", parents=[common], help="WiFi networks (keys hidden)")
    s.add_argument("--live", action="store_true", help="live radio state instead of saved config")
    s.add_argument("--show-secrets", action="store_true", help="reveal WiFi keys")
    s.set_defaults(fn=cmd_wifi)

    write = argparse.ArgumentParser(add_help=False, parents=[common])
    write.add_argument("--dry-run", action="store_true", help="show the change, write nothing")
    write.add_argument("--yes", action="store_true", help="apply without asking")

    def section(name: str, fn: Callable[..., str], text: str) -> Any:
        s = sub.add_parser(name, parents=[common], help=text)
        s.set_defaults(fn=fn)
        return s.add_subparsers(dest="action", metavar="action")

    s = sub.add_parser(
        "network", parents=[common], help="LAN, DHCP, DNS, firewall, DMZ and UPnP overview"
    )
    s.set_defaults(fn=cmd_network)

    acts = section("leases", cmd_leases, "fixed IPs (DHCP reservations)")
    s = acts.add_parser("set", parents=[write], help="give a device a fixed IP")
    s.add_argument("mac")
    s.add_argument("ip")
    s.set_defaults(fn=cmd_lease_write)
    s = acts.add_parser("remove", parents=[write], help="remove a device's fixed IP")
    s.add_argument("mac")
    s.set_defaults(fn=cmd_lease_write)

    acts = section("routes", cmd_routes, "static routes")
    s = acts.add_parser("add", parents=[write], help="add or replace a static route")
    s.add_argument("name")
    s.add_argument("destination", help="network, e.g. 10.1.0.0/24")
    s.add_argument("next_hop", metavar="next-hop", help="LAN IP of the gateway, e.g. 10.0.0.42")
    s.set_defaults(fn=cmd_route_write)
    s = acts.add_parser("remove", parents=[write], help="remove a static route")
    s.add_argument("name")
    s.set_defaults(fn=cmd_route_write)

    acts = section("forwards", cmd_forwards, "port forwards and UPnP mappings")
    s = acts.add_parser("add", parents=[write], help="add or replace a port forward")
    s.add_argument("name")
    s.add_argument("protocol", choices=["tcp", "udp"])
    s.add_argument(
        "wan_port", metavar="wan-port", help="public port or range, e.g. 443 or 8000-8010"
    )
    s.add_argument("lan_ip", metavar="lan-ip")
    s.add_argument("--lan-port", help="port on the device (default: same as wan-port)")
    s.set_defaults(fn=cmd_forward_write)
    s = acts.add_parser("remove", parents=[write], help="remove a port forward")
    s.add_argument("name")
    s.set_defaults(fn=cmd_forward_write)

    s = sub.add_parser("firewall", parents=[common], help="firewall status and custom rules")
    s.set_defaults(fn=cmd_firewall)

    host = sub.add_parser("host", help="change a device's settings")
    hsub = host.add_subparsers(dest="host_cmd", required=True, metavar="setting")
    alias = hsub.add_parser("alias", help="the name the router shows for a device")
    asub = alias.add_subparsers(dest="action", required=True, metavar="action")
    s = asub.add_parser("set", parents=[write], help="set an alias")
    s.add_argument("mac")
    s.add_argument("name")
    s.set_defaults(fn=cmd_alias)
    s = asub.add_parser("clear", parents=[write], help="remove an alias")
    s.add_argument("mac")
    s.set_defaults(fn=cmd_alias)

    s = sub.add_parser(
        "login", parents=[common], help="log in to the cloud once and cache the session"
    )
    s.set_defaults(fn=cmd_login)
    s = sub.add_parser(
        "logout", parents=[common], help="forget the session and clear the login guard"
    )
    s.set_defaults(fn=cmd_logout)

    s = sub.add_parser("mcp", help="run the MCP server on stdio")
    s.add_argument("--allow-writes", action="store_true", help="expose write tools")
    s.set_defaults(fn=cmd_mcp)
    return p


def main(argv: Sequence[str] | None = None, router: Callable[[], Router] = Router) -> int:
    a = parser().parse_args(argv)
    if getattr(a, "no_color", False) or getattr(a, "json", False):
        look.set_color(False)
    r: Router | None = None
    try:
        r = router()
        out = a.fn(r, a)
    except RuternError as e:
        print(look.error(str(e)), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    finally:
        if r is not None:
            r.close()
    if out:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
