"""rutern command line."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from typing import Any

from pydantic import BaseModel

from rutern import __version__, look
from rutern.errors import RuternError, WriteRefused
from rutern.models import Host, Wifi, WifiNetwork
from rutern.router import AliasChange, Router, Status


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
    lines.append(look.fg(look.DIM, f"{n_active} active, {len(hosts)} total"))
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


def render_change(c: AliasChange) -> str:
    before = c.before or look.fg(look.DIM, "(none)")
    after = c.after or look.fg(look.DIM, "(none)")
    return look.frame(
        "alias change",
        look.kv(
            [
                ("device", f"{c.device}  {look.fg(look.DIM, c.mac)}"),
                ("before", look.fg(look.ERROR, before) if c.before else before),
                ("after", look.fg(look.OK, after) if c.after else after),
            ]
        ),
    )


# commands


def cmd_status(r: Router, a: argparse.Namespace) -> str:
    s = r.status()
    return dump(s) if a.json else render_status(s)


def cmd_devices(r: Router, a: argparse.Namespace) -> str:
    hosts = r.hosts(active_only=a.active)
    return dump(hosts) if a.json else render_hosts(hosts)


def cmd_wifi(r: Router, a: argparse.Namespace) -> str:
    w = r.wifi()
    if a.json:
        nets = w.volatile if a.live else w.non_volatile
        return dump(nets, show_secrets=a.show_secrets)
    return render_wifi(w, a.live, a.show_secrets)


def confirm(prompt: str) -> bool:
    if not sys.stdin.isatty():
        return False
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        return False


def cmd_alias(r: Router, a: argparse.Namespace) -> str:
    alias = "" if a.alias_cmd == "clear" else a.name
    change = r.plan_alias(a.mac, alias)
    shown = render_change(change)
    if change.noop:
        return dump({"changed": False, **change.model_dump()}) if a.json else shown + "\nno change"
    if a.dry_run:
        return (
            dump({"dry_run": True, **change.model_dump()})
            if a.json
            else shown + "\ndry run, nothing written"
        )
    if not a.yes:
        if not a.json:
            print(shown)
        if not confirm(f"apply? {look.fg(look.KEY, 'y')}/{look.fg(look.KEY, 'N')} "):
            raise WriteRefused("not confirmed; nothing written (pass --yes when not interactive)")
    r.apply_alias(change)
    if a.json:
        return dump({"changed": True, "verified": True, **change.model_dump()})
    return (shown + "\n" if a.yes else "") + look.fg(look.OK, "written and verified by read-back")


def cmd_login(r: Router, a: argparse.Namespace) -> str:
    r.cloud.login()
    return look.fg(look.OK, "logged in; session cached in Keychain")


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

    s = sub.add_parser("devices", parents=[common], help="connected devices with names and IPs")
    s.add_argument("--active", action="store_true", help="only devices online now")
    s.set_defaults(fn=cmd_devices)

    s = sub.add_parser("wifi", parents=[common], help="WiFi networks (keys hidden)")
    s.add_argument("--live", action="store_true", help="live radio state instead of saved config")
    s.add_argument("--show-secrets", action="store_true", help="reveal WiFi keys")
    s.set_defaults(fn=cmd_wifi)

    host = sub.add_parser("host", help="change a device's settings")
    hsub = host.add_subparsers(dest="host_cmd", required=True, metavar="setting")
    alias = hsub.add_parser("alias", help="the name the router shows for a device")
    asub = alias.add_subparsers(dest="alias_cmd", required=True, metavar="action")
    write = argparse.ArgumentParser(add_help=False, parents=[common])
    write.add_argument("--dry-run", action="store_true", help="show the change, write nothing")
    write.add_argument("--yes", action="store_true", help="apply without asking")
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
    r = router()
    try:
        out = a.fn(r, a)
    except RuternError as e:
        print(look.error(str(e)), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    finally:
        r.close()
    if out:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
