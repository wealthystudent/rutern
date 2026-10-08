# rutern

Read and configure a Telenor home router (Zyxel EX5700, "WiFi Ruter II") from a CLI, and expose the same capability as an MCP server for an AI agent.

Status: reads work end to end (CLI and MCP) against a real router. Writes for aliases, fixed IPs, static routes and port forwards are built; alias and fixed IP bodies are verified live, route and port forward bodies come from the API's validation messages. WiFi writes are not built.

## Why it exists

Telenor gives no supported local or public API for these routers. The web portal at wifi.telenor.no is the only management surface. `rutern` wraps the two interfaces the router actually exposes so you can list devices and IPs, read WiFi settings and (later) change configuration from a script or an agent, instead of clicking through the portal.

## How it works

Two backends, combined behind one client (the hybrid design):

| | Local `10.0.0.138/ws` (no auth) | Cloud `wifi.telenor.no/v1` (your admin password) |
|---|---|---|
| Device, firmware, serial | yes | yes |
| Public IP / IPv6 | yes | yes |
| WiFi SSIDs | yes | yes, full config incl. keys |
| Connected devices | MAC addresses only | **names and IP addresses** |
| Configuration / writes | no (locked by firmware) | yes |

Local covers fast, offline, read-only status. The cloud path covers the full host list and all configuration. Local-only cannot list device names/IPs or change anything, because Telenor's firmware exposes no local admin authentication (see `docs/api-reference.md`).

## Docs

- `docs/architecture.md` — the hybrid design and planned module layout
- `docs/api-reference.md` — the verified API: local sysbus calls, cloud login flow, endpoints, response shapes
- `docs/security.md` — secrets, redaction, untrusted input, excluded destructive endpoints

## Run

Needs macOS, [uv](https://docs.astral.sh/uv/), and the admin password in Keychain (service `telenor-router`, account `telenor`):

```
security add-generic-password -s telenor-router -a telenor -T "" -w   # prompts for the password
uv run rutern login                  # once, at home: finds and saves your router's reference
```

`-T ""` makes macOS ask before any program reads the password; rutern only reads it to log in. Answer Allow, not Always Allow.

```
uv run rutern status                 # device, WAN, WiFi; local, no login
uv run rutern devices [--all]        # online devices: names, IPs, MACs, link (cloud); --all adds offline
uv run rutern wifi [--live] [--show-secrets]
uv run rutern network                # LAN, DHCP, DNS, firewall, DMZ, UPnP overview
uv run rutern leases                 # fixed IPs with device names
uv run rutern leases set <mac> <ip> | remove <mac>
uv run rutern routes                 # static routes
uv run rutern routes add <name> <destination> <next-hop> | remove <name>
uv run rutern forwards               # port forwards and UPnP mappings
uv run rutern forwards add <name> tcp|udp <wan-port> <lan-ip> [--lan-port N] | remove <name>
uv run rutern firewall
uv run rutern host alias set <mac> <name> | clear <mac>
uv run rutern login | logout         # logout at a terminal also clears the failed-login guard
uv run rutern policy [init]          # what this machine allows; init writes a read-only file to edit
uv run rutern history [-n N]         # recent writes; the log keeps a full backup of each list
```

rutern is read-only until you allow writes in `~/.config/rutern/policy.toml` (`cli_writes`, `mcp_writes`). Every command takes `--json`. Writes show a before/after diff, ask y/N, take `--dry-run` and `--yes`, and verify by reading back. Opening a port and `--show-secrets` only work for a person at an interactive terminal. Install globally with `uv tool install --editable .`.

MCP server (stdio), for example in Claude Code:

```
claude mcp add rutern -- uv --directory /path/to/rutern run rutern mcp
```

Add `--allow-writes` after `mcp` (or `--allow-writes alias,lease`) to expose the write tools the policy's `mcp_writes` allows: `set_device_alias`, `set_fixed_ip`, `set_static_route`. Port forwards are CLI only. With `confirm=true` a write tool asks you to approve the change in your MCP client; clients without that (elicitation) get no writes.

## Develop

```
make check      # ruff, mypy, pytest (offline, fixtures only)
make live       # smoke check against the real router
make fixtures   # re-record scrubbed fixtures
```
