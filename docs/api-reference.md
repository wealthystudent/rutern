# API reference

Everything here was verified against a live Telenor Zyxel EX5700 on 2026-10-08. It exists so no one has to re-probe the router. Treat the router as the source of truth if anything here drifts; firmware updates can change it.

## The router

- Model `ex5700` ("WiFi Ruter II"), product class `TEL-HGW-1`, firmware `1.2.66.0`
- SoftAtHome / prpl firmware, "sysbus" datamodel
- Local address `10.0.0.138`, reference id: 8 digits, unique per router
- Open TCP ports on the LAN: 53, 80, 443, 5000 (5000 is `nuttcp`, a speed-test daemon, not admin)

The reference id is discoverable from the cloud, not the router: `GET https://wifi.telenor.no/login/admin` from behind the router returns HTML containing `reference:"<digits>"` and `model:"ex5700"` (the portal knows the router by your public IP). The local `http://10.0.0.138/` page does not carry it. With a live session that page redirects instead: `/login/admin` → `/` → `/<reference>`.

## Local interface: `POST http://10.0.0.138/ws`

SoftAtHome sysbus. Request body is JSON `{"service","method","parameters"}`, with header `Content-Type: application/x-sah-ws-4-call+json`. Response envelope is either `{"status": ...}` on success or `{"status": null, "errors": [{"error": 13, "description": "Permission denied", ...}]}`.

**Unauthenticated reads that work** (the router's own landing page uses these):

```
{"service":"DeviceInfo","method":"get","parameters":{}}
  -> status: ProductClass, SerialNumber, SoftwareVersion, UpTime, BaseMAC

{"service":"NMC","method":"getWANStatus","parameters":{}}
  -> data: LinkState, IPAddress (public v4), IPv6Address, IPv6DelegatedPrefix

{"service":"NeMo.Intf.lan","method":"getMIBs","parameters":{"mibs":"wlanvap"}}
  -> status.wlanvap.<vap>: SSID + AssociatedDevice{MAC:{...}} per radio
     vaps: vap2g0_0/_2/_3, vap5g0_0/_2/_3, vap6g0_0/_2/_3 (main / iot / tv)

{"service":"NeMo.Intf.lan","method":"getMIBs","parameters":{"mibs":"base"}}
  -> LAN bridge topology (LLIntf members)
```

**Gated locally** — return `error 13 Permission denied`, use the cloud path instead:
`Devices` (the host list with names + IPs), `NMC.get`, `Firewall`, `DHCPv4.Server`.

The local `wlanvap` MIB does not expose WiFi keys (`Security` is empty).

**No local admin auth exists.** `sah.Device.Information.createContext` (plaintext login) returns HTTP 401; `createContextWithSRP` returns permission denied; there is no `/login` or `/authenticate` endpoint (404) and no local login UI. This is a firmware limitation, confirmed, not a credential problem. All privileged access must go through the cloud.

## Cloud interface: `https://wifi.telenor.no`

Internal API mount is `/mitt-wifi/v1`, reachable as `/v1`. Cookie-based auth (`credentials: same-origin`, no auth header). Auth failure is HTTP 401 with message `10000`.

### Login (one attempt — repeated failures can lock the router)

```
POST https://wifi.telenor.no/login/admin?/login
Headers: Origin: https://wifi.telenor.no ; x-sveltekit-action: true
Body (multipart/form-data):
  username     = <reference id>
  password     = <admin password from Keychain>
  redirect_to  = /
Success: HTTP 200, body {"type":"redirect","status":303,"location":"/"},
         Set-Cookie: __Host-session=...
```

This is a SvelteKit form action; the action path is relative to the `/login/admin` page. The old `/login?/login=` used by kivattt/cpe-insight is dead and returns HTTP 500 ("No form actions exist for this page").

The admin password is the same one used to sign in to wifi.telenor.no. rutern keeps it in the macOS Keychain or the Linux keyring (service `telenor-router`, account `telenor`), or a private file on headless Linux. Read it at runtime, never embed or log it.

### Reads (GET `/v1/{reference}/<endpoint>`, send the session cookie)

```
/uptime     -> { os, wan, localtime, last_seen }
/lan-hosts  -> { hosts: [ {hostname, hostname_alias, ipv4_address, ipv6_address,
                           mac, device_type, interface, phy_rate, snr, active,
                           parent, speculative}, ... ], errors: [] }   (26 on the test unit)
               also: type, vendor, uptime, ipv4_address_static (set when reserved),
               eth_port (wired), wlan_band, wlan_ssid, wlan_interop,
               wlan_signal_strength, wlan_signal_quality (wifi).
               snr 2147483643 means "no reading".
/lan-hosts/alias -> { non_volatile: [{mac, hostname}], volatile: [{mac, hostname, active}] }
               hostname here is the alias.
/wlan       -> { non_volatile: [net...], volatile: [net...] }
               net = {band, ssid, enabled, encryption, encryption_key, guest,
                      hidden, group, rate_limit_up, rate_limit_down, ...}
               12 networks: 2.4/5/6 GHz x group. group 0 main, 1 guest, 2 iot, 3 tv
               (the local vap suffix _0/_2/_3 uses the same numbers).
               encryption_key is CLEARTEXT — treat as a secret, redact by default.
```

Note: `/v1/{ref}/status` does not exist (404). Use `/uptime` for status-like data. Every /v1 response carries an `errors` list; non-empty means the call failed.

### Writes

rutern is read-only and sends none of these; they are recorded for when writes return.

The portal never calls write endpoints from the browser: its pages post SvelteKit form actions (fields like `hostname_alias.<mac>`) and the portal server calls /v1. The frontend API client (`lanHostsAliasSet`, `wlanSet`, …) shows `POST /{ref}/<endpoint>` with a JSON body and an optional `x-tn-txn-id` header.

Every list endpoint replaces the whole saved list. Success is HTTP 201 `{"non_volatile": true, "volatile": true}`; a bad body is HTTP 400 `{statusCode, message, timestamp, path}` and changes nothing. Validation reports one field at a time, with messages like `"Lan_ip must be an ip address"`.

| Endpoint | Body | Item fields | Verified |
|---|---|---|---|
| `lan-hosts/alias` | `{"hosts": [...]}` | `mac`, `hostname` (the alias) | saved list written back unchanged |
| `static-dhcp-leases` | `{"leases": [...]}` | `mac`, `ip_address`, `srcservice` (`""`) | saved list written back unchanged |
| `static-routes` | `{"rules": [...]}` | `name`, `destination` (string), `next_hop` (IP); all required | validation messages only |
| `nat-rules` | `{"rules": [...]}` | `name`, `protocol`, `lan_ip`, `wan_port_start` (0 to 65535) required; `wan_port_end`, `lan_port_start`, `lan_port_end` assumed from UPnP mappings | validation messages only |

- MACs are lowercase in every list.
- Port 0 passes validation, so a probe item with port 0 is a valid item that gets written.
- `GET /lan` answers HTTP 501; use `/dhcp` for the LAN address (`ipv4_address`, e.g. `10.0.0.138/24`).
- `POST /wlan`: shape unknown; not implemented.

### Endpoint surface

~70 endpoints are referenced by the portal frontend, most as `GET /{ref}/<name>` with several also accepting POST for writes. Known names include:
`lan`, `lan-hosts`, `lan-hosts/alias`, `lan-ipv6`, `wlan`, `wlan/radio`, `wlan/scan`, `wlan/wps`, `dhcp`, `static-dhcp-leases`, `dns`, `ddns`, `nat-rules`, `firewall-rules`, `firewall-status`, `upnp`, `upnp/mappings`, `ethernet-ports`, `status-from-sessions`, `sessions`, `bandwidth`, `uptime`, `firmware-version(s)`, `led`, `log`, `schedules`, `policies`, `wan-protocol`, `device-family`, `capabilities`.

**Destructive endpoints — never implement:** `factory-reset`, `reboot`, `msan/reset-ont`, `msan/reset-port`, `msan/reset-config`, `msan/dsl-reprovision`.

## Prior art (none usable)

- `kivattt/cpe-insight` (Go, read-only, Nov 2024): same cloud API idea, but its login flow is broken against current firmware. Endpoint list was a useful starting point.
- `sysbus` / `aiosysbus` (Orange Livebox), `jeroen-meijer/sah_cli` (KPN): same SoftAtHome sysbus protocol, different ISP, none target Telenor.
