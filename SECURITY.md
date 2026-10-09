# Security policy

rutern holds the admin login for a home router and can be driven by an AI agent, so security reports are very welcome.

## Reporting a vulnerability

Report it privately through GitHub: the repository's **Security** tab, then **Report a vulnerability**. Please do not open a public issue for it.

Include what an attacker needs (an agent over MCP, a device on the WiFi, a process on the Mac, a network position) and what they get. Leave out your router's reference id, serial number, MAC addresses, WiFi keys and public IP.

The answer comes in the private report. Fixes go out as a new release, and the advisory is published once that release is available.

## Supported versions

Only the latest release gets fixes.

## What counts

Anything that lets someone get past the guardrails described in [docs/security.md](docs/security.md), for example: rutern changing something on the router, WiFi keys or credentials reaching an agent, a log or error, router text that controls the terminal, or rutern logging in again and again.

Out of scope: a process that already runs as you with a shell. It can call the portal, `security` or `secret-tool` directly, which rutern cannot prevent ([trust boundary](docs/security.md#trust-boundary)).
