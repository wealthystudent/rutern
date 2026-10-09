# Development

## Checks

```
uv sync
make check      # ruff, ruff format --check, mypy --strict, pytest
```

Tests run offline against the recorded responses in `tests/fixtures/` (`tests/fakes.py` serves them as a fake router and portal). The autouse fixture in `tests/conftest.py` points home at a temp dir and makes any Keychain call fail, so no test can touch real state. CI runs `make check` on macOS for the oldest and newest supported Python (`.github/workflows/ci.yml`).

## Against the real router

Only with your own router, at home, and only when you mean to:

```
make live       # reads only: login (cached session or one attempt), status, devices, wifi, network
make fixtures   # re-record tests/fixtures from your router, scrubbed in memory
```

`make fixtures` replaces names, MACs, SSIDs, serials, keys, vendors and public IPs with placeholders, then fails if any captured secret or SSID still appears in a fixture. Several tests assert counts from the maintainer's router (26 hosts, 24 fixed IPs), so fixtures recorded elsewhere need those tests adjusted. Read the diff before committing.

## Adding to rutern

- A read: add the endpoint to `READS` in `cloud.py`, a model in `models.py` (`Text` for every router string, `Open` when the item shape is not fully known), a scrubbed fixture, and a CLI command or MCP tool. Record the shape in `docs/api-reference.md`.
- Writes: rutern is read-only until each write has been tested on a real router. Reverting the commit "Remove writes for the read-only release" brings back aliases, fixed IPs, routes and port forwards with their guardrails (owner policy, dry run, read-back, audit log, approval over MCP) and tests, as the starting point.
- Never: destructive endpoints (see `docs/security.md`), login retries, a network transport for the MCP server.

## Releasing

One-time setup:

1. On PyPI, add a pending trusted publisher for project `rutern`: owner `wealthystudent`, repository `rutern`, workflow `release.yml`, environment `pypi`.
2. On GitHub, create the environment `pypi` (Settings, Environments). Adding yourself as a required reviewer makes every release wait for a click.
3. On GitHub, turn on private vulnerability reporting and Dependabot alerts (Settings, Advanced Security), and protect `main` with a ruleset that requires the `ci` checks and blocks force pushes.

Each release:

```
uv version --bump patch          # or minor; updates pyproject.toml and uv.lock
git commit -am "Release v$(uv version --short)"
git push                         # wait for CI to pass on main
git tag -a "v$(uv version --short)" -m "v$(uv version --short)"
git push origin "v$(uv version --short)"
```

The tag starts `.github/workflows/release.yml`: it runs the checks, refuses a tag that does not match the version, builds, publishes to PyPI without any stored token, and creates the GitHub release with generated notes.

## Dependencies

Dependabot opens one grouped pull request a month for `uv.lock` and one for the GitHub Actions, each version at least 7 days old. Merge them when CI passes. `pyproject.toml` caps every dependency below its next major version, since users install the newest allowed versions rather than `uv.lock`; raise a cap only after the tests pass on the new major.

## When the portal changes

The cloud API is undocumented. A change shows up as `unexpected response shape` or an HTTP error naming the endpoint. Run `make live`, compare with `docs/api-reference.md`, then update the model, the reference and the fixture together.
