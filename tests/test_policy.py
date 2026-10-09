from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any, NoReturn

import pytest

from rutern import cli, policy
from rutern.cli import main, parse_kinds
from rutern.errors import ConfigError, WriteRefused
from rutern.mcp_server import build
from rutern.policy import Policy
from tests.fakes import WRITABLE, FakeCloud, make_router
from tests.test_mcp import tools

KNOWN = "02:00:00:00:00:11"


def write_policy(text: str) -> Path:
    p = policy.path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    p.chmod(0o600)
    return p


def no_router() -> NoReturn:
    raise AssertionError("a refused write must not reach the router")


# the file


def test_no_file_is_read_only() -> None:
    pol = policy.load()
    assert pol.cli_writes == pol.mcp_writes == frozenset() and pol.source is None
    assert not pol.mcp_trust_agent_confirm and pol.mcp_max_writes == 10


def test_template_is_private_read_only_and_not_overwritten() -> None:
    p = policy.init()
    assert p.stat().st_mode & 0o777 == 0o600
    pol = policy.load()
    assert pol.source == p and pol.cli_writes == pol.mcp_writes == frozenset()
    with pytest.raises(ConfigError, match="already exists"):
        policy.init()


def test_file_grants_kinds() -> None:
    write_policy('cli_writes = ["alias", "forward"]\nmcp_writes = ["lease"]\nmcp_max_writes = 3\n')
    pol = policy.load()
    assert pol.cli_writes == {"alias", "forward"} and pol.mcp_writes == {"lease"}
    assert pol.mcp_max_writes == 3


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ('mcp_writes = ["forward"]', "never allowed over MCP"),
        ('cli_writes = ["reboot"]', "unknown kinds"),
        ('cli_writes = "alias"', "list of write kinds"),
        ('cli_write = ["alias"]', "unknown settings"),
        ("mcp_max_writes = true", "whole number"),
        ("mcp_max_writes = 1000", "whole number"),
        ('mcp_trust_agent_confirm = "yes"', "true or false"),
        ("cli_writes = [", "not valid TOML"),
    ],
)
def test_bad_files_are_errors(text: str, match: str) -> None:
    write_policy(text)
    with pytest.raises(ConfigError, match=match):
        policy.load()


@pytest.mark.parametrize("target", ["file", "dir"])
def test_writable_by_others_is_refused(target: str) -> None:
    p = write_policy('cli_writes = ["alias"]')
    (p if target == "file" else p.parent).chmod(0o666 if target == "file" else 0o777)
    with pytest.raises(ConfigError, match="not be writable by others"):
        policy.load()


def test_read_only_env_narrows(monkeypatch: pytest.MonkeyPatch) -> None:
    write_policy('cli_writes = ["alias"]\nmcp_writes = ["alias"]')
    monkeypatch.setenv("RUTERN_READ_ONLY", "1")
    pol = policy.load()
    assert pol.cli_writes == pol.mcp_writes == frozenset()


# CLI


def test_cli_write_refused_before_any_network_call(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["host", "alias", "set", KNOWN, "Den", "--yes"], router=no_router)
    assert code == 1 and "alias writes are off" in capsys.readouterr().err


def test_cli_dry_run_works_read_only(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    r, cloud = make_router(tmp_path, writes=frozenset())
    code = main(["leases", "set", KNOWN, "10.0.0.200", "--dry-run"], router=lambda: r)
    assert code == 0 and "dry run" in capsys.readouterr().out and cloud.posts == []


def test_router_without_the_kind_refuses_apply(tmp_path: Path) -> None:
    r, cloud = make_router(tmp_path, writes=frozenset({"lease"}))
    with pytest.raises(WriteRefused, match="not enabled"):
        r.apply(r.plan_alias(KNOWN, "Den"))
    assert cloud.posts == []


def test_policy_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["policy"]) == 0
    assert "none (read-only)" in capsys.readouterr().out
    assert main(["policy", "init"]) == 0
    assert policy.path().exists()
    capsys.readouterr()
    assert main(["policy", "--json"]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["file"] == str(policy.path()) and shown["cli writes"] == "none (read-only)"


def test_bad_policy_stops_every_command(capsys: pytest.CaptureFixture[str]) -> None:
    write_policy("cli_writes = [")
    assert main(["status"], router=no_router) == 1
    assert "not valid TOML" in capsys.readouterr().err


# high risk actions need a person at a terminal


def secret_cloud() -> FakeCloud:
    cloud = FakeCloud()
    cloud.data["wlan"]["non_volatile"][0]["encryption_key"] = "s3cret-wifi-pass"
    return cloud


def at_terminal(monkeypatch: pytest.MonkeyPatch, typed: str = "") -> None:
    monkeypatch.setattr(cli, "human_terminal", lambda: True)
    monkeypatch.setattr("sys.stdin", io.StringIO(typed))


def test_show_secrets_refused_without_terminal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    r, _ = make_router(tmp_path, cloud=secret_cloud())
    assert main(["wifi", "--show-secrets", "--json"], router=lambda: r) == 1
    captured = capsys.readouterr()
    assert "interactive terminal" in captured.err and "s3cret" not in captured.out


def test_show_secrets_refused_by_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    at_terminal(monkeypatch)
    r, _ = make_router(tmp_path, cloud=secret_cloud())
    pol = Policy(reveal_secrets=False)
    assert main(["wifi", "--show-secrets"], router=lambda: r, pol=pol) == 1
    assert "reveal_secrets" in capsys.readouterr().err


def test_show_secrets_on_a_terminal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    at_terminal(monkeypatch)
    r, _ = make_router(tmp_path, cloud=secret_cloud())
    assert main(["wifi", "--show-secrets"], router=lambda: r) == 0
    assert "s3cret-wifi-pass" in capsys.readouterr().out


def test_agent_shell_is_not_a_human_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("sys.stdin", Tty())
    assert cli.human_terminal()
    for var in cli.AGENT_ENV:
        monkeypatch.setenv(var, "0")
    assert cli.human_terminal()  # explicitly off
    for var, value in (("CLAUDECODE", "1"), ("AI_AGENT", "claude-code"), ("GEMINI_CLI", "1")):
        monkeypatch.setenv(var, value)
        assert not cli.human_terminal()
        monkeypatch.setenv(var, "")


FORWARD = ["forwards", "add", "web", "tcp", "8443", "10.0.0.5"]


@pytest.mark.parametrize(("typed", "written"), [("y\n", False), ("8443\n", True)])
def test_forward_needs_the_port_typed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    typed: str,
    written: bool,
) -> None:
    at_terminal(monkeypatch, typed)
    r, cloud = make_router(tmp_path)
    code = main([*FORWARD, "--yes"], router=lambda: r, pol=WRITABLE)
    assert (code == 0) is written and bool(cloud.posts) is written


def test_forward_removal_takes_yes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cloud = FakeCloud()
    r, _ = make_router(tmp_path, cloud=cloud)
    r.apply(r.plan_forward("web", "tcp", "8443", "10.0.0.5"))
    code = main(["forwards", "remove", "web", "--yes"], router=lambda: r, pol=WRITABLE)
    assert code == 0 and cloud.data["nat-rules"]["non_volatile"] == []


# MCP


def test_mcp_tools_follow_the_kinds(tmp_path: Path) -> None:
    r, _ = make_router(tmp_path)
    names = tools(build(writes=frozenset({"lease"}), router=lambda: r))
    assert "set_fixed_ip" in names and "set_device_alias" not in names
    names = tools(build(writes=frozenset({"forward"}), router=lambda: r))
    assert not any(n.startswith("set_") for n in names)


def test_mcp_allow_writes_is_narrowed_by_policy(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    served: list[Any] = []
    monkeypatch.setattr("rutern.mcp_server.serve", lambda pol, kinds: served.append(kinds))
    pol = Policy(mcp_writes=frozenset({"alias"}))
    assert main(["mcp", "--allow-writes"], pol=pol) == 0
    assert main(["mcp", "--allow-writes", "alias,route"], pol=pol) == 0
    assert main(["mcp"], pol=pol) == 0
    assert served == [{"alias"}, {"alias"}, frozenset()]
    assert "does not allow route" in capsys.readouterr().err


def test_parse_kinds() -> None:
    assert parse_kinds("all") == {"alias", "lease", "route", "forward"}
    assert parse_kinds(" alias , lease") == {"alias", "lease"}
    with pytest.raises(ConfigError):
        parse_kinds("alias,reboot")


@pytest.mark.parametrize(
    "argv", [["host", "alias", "set", KNOWN, "Den"], ["forwards", "remove", "web"]]
)
def test_agent_shell_cannot_write_with_yes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
) -> None:
    r, cloud = make_router(tmp_path)
    r.apply(r.plan_forward("web", "tcp", "8443", "10.0.0.5"))
    cloud.posts.clear()
    monkeypatch.setenv("CLAUDECODE", "1")
    assert main([*argv, "--yes"], router=lambda: r, pol=WRITABLE) == 1
    assert "rutern mcp" in capsys.readouterr().err and cloud.posts == []
    r, _ = make_router(tmp_path, cloud=cloud)
    assert main([*argv, "--dry-run"], router=lambda: r, pol=WRITABLE) == 0


def test_allow_writes_all_is_quiet(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    served: list[Any] = []
    monkeypatch.setattr("rutern.mcp_server.serve", lambda pol, kinds: served.append(kinds))
    assert main(["mcp", "--allow-writes"], pol=Policy(mcp_writes=frozenset({"lease"}))) == 0
    assert served == [{"lease"}] and capsys.readouterr().err == ""
    assert main(["mcp", "--allow-writes", "forward"], pol=Policy()) == 0
    assert "does not allow forward" in capsys.readouterr().err
    assert main(["mcp", "--allow-writes"], pol=Policy()) == 0
    assert "mcp_writes" in capsys.readouterr().err
