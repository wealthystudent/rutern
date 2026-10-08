# Architecture

`rutern` is a Python package with one client core and two interfaces on top of it: a CLI for a human and an MCP server for an agent. The core talks to the router over two backends and merges them.

## The hybrid model

```
            CLI  ───┐                 ┌─── MCP server
                    ├──►  Router  ◄────┤
                    │   (facade)       │
                    └──────┬───────────┘
                           │
              ┌────────────┴────────────┐
       LocalClient                 CloudClient
   http://10.0.0.138/ws       https://wifi.telenor.no/v1
   sysbus, no auth,           session cookie, admin password,
   fast, offline,             full host list + all config
   read-only subset
```

`Router` decides which backend answers a request: local when it is sufficient (device info, WAN/public IP, WiFi SSIDs, connected MACs) and cloud when it is not (host names + IPs, DHCP, firewall, any write). The two never need to run in lockstep; local works with no internet and no credentials, cloud is lazily logged in on first need.

Why hybrid and not one backend: local is instant and private but firmware-limited to a read-only subset with no device names/IPs and no writes; cloud is complete but needs Telenor's relay and a login. See `docs/api-reference.md` for the hard limits behind this split.

## Module layout

```
src/rutern/
  config.py       host, base URLs, reference (env or discovered), state dir
  keychain.py     Keychain read of the admin password; session cookie cache
  errors.py       Unreachable, PermissionDenied, AuthRequired, LoginFailed, LoginBlocked, ApiError, WriteRefused
  models.py       Pydantic models; router strings cleaned, secrets redacted
  local.py        LocalClient: /ws transport + unauthenticated reads
  cloud.py        CloudClient: login guard, session, /v1 reads and the alias write
  router.py       Router facade, alias plan/apply with read-back
  look.py         the shared tool look (palette, frame, table) for CLI output
  cli.py          `rutern` command line
  mcp_server.py   MCP server on stdio (read tools; alias write behind --allow-writes)
scripts/record_fixtures.py   re-record scrubbed fixtures from the live router
tests/
  fixtures/       recorded /ws and /v1 JSON, scrubbed; tests run offline
```

## Build order

Phased, each phase ends green and committed before the next (full tasks in `TODO.md`):

0. Package scaffold (uv, pytest, ruff, mypy, fixtures dir)
1. Local read client + models, tested against fixtures
2. Cloud session + read client (Keychain login, cookie, auto re-login, redaction)
3. `Router` facade + CLI reads (`status`, `devices`, `wifi`)
4. Writes, safest first (`hostname_alias`), with dry-run, diff and read-back
5. MCP server: read tools, then gated writes, with untrusted-input handling

## Testing approach

No test may require a live router. Record real responses once, scrub secrets, and commit them as fixtures. Live calls are confined to a small, explicitly-run smoke check (`make live`) that re-verifies the login flow and a couple of reads, so firmware drift surfaces as a clear failure rather than silent wrong data.
