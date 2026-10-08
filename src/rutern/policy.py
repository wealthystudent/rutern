"""The owner's ceiling on what rutern may do.

The file is `$XDG_CONFIG_HOME/rutern/policy.toml` (default `~/.config`). With no
file rutern is read-only everywhere. Flags and env vars can only narrow what
the file allows, never widen it: `rutern mcp --allow-writes` still needs the
kind listed under `mcp_writes`, and RUTERN_READ_ONLY=1 turns every write off.

The file decides what may change on the router, so it must belong to the
user and not be writable by anyone else, and a file rutern cannot fully
understand is an error rather than a guess.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from rutern.config import write_private
from rutern.errors import ConfigError
from rutern.writes import KINDS, Kind

TEMPLATE = """\
# rutern policy: the most rutern may do on this machine.
# Flags and env vars can only narrow this, never widen it.
# Write kinds: alias, lease (fixed IP), route (static route), forward (port forward).

# Writes from the command line. Each one still shows its plan and asks first.
cli_writes = []

# Writes from an MCP agent. Each one is shown to you for approval in the MCP
# client. Port forwards are never available over MCP.
mcp_writes = []

# Most writes one MCP server may make before it has to be restarted.
mcp_max_writes = 10

# Only for MCP clients that cannot ask you to approve a write. true lets the
# agent's own confirm=true apply a write without asking anyone. Leave false.
mcp_trust_agent_confirm = false

# Allow `rutern wifi --show-secrets` on an interactive terminal.
reveal_secrets = true
"""

MAX_MCP_WRITES = 100


@dataclass(frozen=True)
class Policy:
    cli_writes: frozenset[Kind] = frozenset()
    mcp_writes: frozenset[Kind] = frozenset()
    mcp_max_writes: int = 10
    mcp_trust_agent_confirm: bool = False
    reveal_secrets: bool = True
    source: Path | None = field(default=None, compare=False)

    def describe(self) -> list[tuple[str, str]]:
        def kinds(k: frozenset[Kind]) -> str:
            return ", ".join(x for x in KINDS if x in k) or "none (read-only)"

        return [
            ("file", str(self.source) if self.source else f"none, defaults ({path()})"),
            ("cli writes", kinds(self.cli_writes)),
            ("mcp writes", kinds(self.mcp_writes)),
            ("mcp max writes", str(self.mcp_max_writes)),
            ("mcp trusts agent", "yes" if self.mcp_trust_agent_confirm else "no"),
            ("reveal secrets", "on a terminal" if self.reveal_secrets else "never"),
        ]


def path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "rutern" / "policy.toml"


def read_only_env() -> bool:
    return os.environ.get("RUTERN_READ_ONLY", "").strip() not in ("", "0")


def load(p: Path | None = None) -> Policy:
    """The effective policy: the file (or read-only defaults), narrowed by env."""
    p = p or path()
    try:
        st = p.stat()
    except FileNotFoundError:
        pol = Policy()
    else:
        for target, mode in ((p, st.st_mode), (p.parent, p.parent.stat().st_mode)):
            if mode & 0o022 or target.stat().st_uid != os.getuid():
                raise ConfigError(
                    f"{target} must belong to you and not be writable by others "
                    f"(chmod go-w {target})"
                )
        try:
            data = tomllib.loads(p.read_text())
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
            raise ConfigError(f"{p} is not valid TOML; fix or delete it") from e
        pol = _parse(data, p)
    if read_only_env():
        pol = replace(pol, cli_writes=frozenset(), mcp_writes=frozenset())
    return pol


def _kinds(data: dict[str, Any], key: str, p: Path) -> frozenset[Kind]:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ConfigError(f"{p}: {key} must be a list of write kinds")
    bad = [x for x in value if x not in KINDS]
    if bad:
        raise ConfigError(f"{p}: {key} has unknown kinds {bad}; use {', '.join(KINDS)}")
    return frozenset(k for k in KINDS if k in value)


def _bool(data: dict[str, Any], key: str, default: bool, p: Path) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{p}: {key} must be true or false")
    return value


def _parse(data: dict[str, Any], p: Path) -> Policy:
    known = {f for f in Policy.__dataclass_fields__ if f != "source"}
    unknown = sorted(set(data) - known)
    if unknown:
        raise ConfigError(f"{p}: unknown settings {unknown}")
    mcp = _kinds(data, "mcp_writes", p)
    if "forward" in mcp:
        raise ConfigError(f"{p}: port forwards are never allowed over MCP; remove 'forward'")
    limit = data.get("mcp_max_writes", 10)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= MAX_MCP_WRITES:
        raise ConfigError(f"{p}: mcp_max_writes must be a whole number from 0 to {MAX_MCP_WRITES}")
    return Policy(
        cli_writes=_kinds(data, "cli_writes", p),
        mcp_writes=mcp,
        mcp_max_writes=limit,
        mcp_trust_agent_confirm=_bool(data, "mcp_trust_agent_confirm", False, p),
        reveal_secrets=_bool(data, "reveal_secrets", True, p),
        source=p,
    )


def init(p: Path | None = None) -> Path:
    """Write the read-only template. Never overwrites an existing policy."""
    p = p or path()
    if p.exists():
        raise ConfigError(f"{p} already exists; edit it instead")
    write_private(p, TEMPLATE)
    return p
