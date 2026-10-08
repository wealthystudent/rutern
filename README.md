# rutern

Read and configure a Telenor home router (Zyxel EX5700, "WiFi Ruter II") from a CLI, and expose the same capability as an MCP server for an AI agent.

Status: reads work end to end (CLI and MCP) against a real router. The alias write is built and tested offline but its live body is only partly verified, so it needs `RUTERN_UNVERIFIED_WRITES=1`. WiFi writes are not built.

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
security add-generic-password -s telenor-router -a telenor -w   # prompts for the password
```

```
uv run rutern status                 # device, WAN, WiFi; local, no login
uv run rutern devices [--active]     # names, IPs, MACs, link (cloud)
uv run rutern wifi [--live] [--show-secrets]
uv run rutern host alias set <mac> <name> [--dry-run] [--yes]
uv run rutern host alias clear <mac>
uv run rutern login | logout         # logout also clears the failed-login guard
```

Every command takes `--json`. Install globally with `uv tool install .`.

MCP server (stdio), for example in Claude Code:

```
claude mcp add rutern -- uv --directory /path/to/rutern run rutern mcp
```

Add `--allow-writes` after `mcp` to expose `set_device_alias`.

## Develop

```
make check      # ruff, mypy, pytest (offline, fixtures only)
make live       # smoke check against the real router
make fixtures   # re-record scrubbed fixtures
```
