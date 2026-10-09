"""The password and session stores: Keychain (macOS), keyring and files (Linux)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from rutern import config, credentials
from rutern.credentials import Files, Keychain, SecretService, password_file
from rutern.errors import AuthRequired, ConfigError

REAL_STORE = credentials.store  # captured before the autouse fixture swaps it out


class Security:
    """Stands in for /usr/bin/security and secret-tool: records each call and
    answers with an exit code, or raises."""

    def __init__(self, answer: int | BaseException = 0, stdout: str = "", stderr: str = ""):
        self.answer, self.stdout, self.stderr = answer, stdout, stderr
        self.calls: list[tuple[list[str], str | None, float]] = []

    def __call__(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append((argv, kw.get("input"), kw["timeout"]))
        if isinstance(self.answer, BaseException):
            raise self.answer
        return subprocess.CompletedProcess(argv, self.answer, self.stdout, self.stderr)


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch) -> Security:
    fake = Security()
    monkeypatch.setattr(subprocess, "run", fake)
    return fake


# macOS Keychain


def test_keychain_reads_by_absolute_path_and_waits_for_the_prompt(run: Security) -> None:
    run.stdout = "pw\n"
    assert Keychain().password() == "pw"
    argv, _, timeout = run.calls[0]
    assert argv[0] == "/usr/bin/security" and "pw" not in argv and timeout >= 60


def test_keychain_missing_password_says_how_to_store_it(run: Security) -> None:
    run.answer = Keychain.NOT_FOUND
    with pytest.raises(AuthRequired, match="add-generic-password -s telenor-router"):
        Keychain().password()


@pytest.mark.parametrize("answer", [51, 128, subprocess.TimeoutExpired(["security"], 120)])
def test_keychain_refusal_is_not_a_missing_password(run: Security, answer: Any) -> None:
    run.answer = answer
    with pytest.raises(AuthRequired, match="did not hand over"):
        Keychain().password()
    assert Keychain().load_session() is None


def test_keychain_session_goes_in_on_stdin(run: Security) -> None:
    Keychain().save_session("abc123")
    argv, stdin, _ = run.calls[0]
    assert argv == ["/usr/bin/security", "-i"] and "abc123" not in " ".join(argv)
    assert stdin is not None and '-w "abc123"' in stdin
    Keychain().save_session('evil" -T /bin/sh')  # cannot be quoted: not stored at all
    assert len(run.calls) == 1


# Linux keyring (secret-tool)


@pytest.fixture
def secret_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "access", lambda p, mode: p == "/usr/bin/secret-tool")


def test_keyring_lookup(run: Security, secret_tool: None) -> None:
    run.stdout = "pw"
    assert SecretService().password() == "pw"
    argv, _, timeout = run.calls[0]
    assert argv == [
        "/usr/bin/secret-tool",
        "lookup",
        "service",
        "telenor-router",
        "account",
        "telenor",
    ]
    assert timeout >= 60


def test_keyring_missing_password_says_how_to_store_it(run: Security, secret_tool: None) -> None:
    run.answer = 1  # quiet exit 1: no such secret
    with pytest.raises(AuthRequired, match="secret-tool store"):
        SecretService().password()
    assert SecretService().load_session() is None


def test_keyring_not_running_is_a_refusal(run: Security, secret_tool: None) -> None:
    run.answer, run.stderr = 1, "Cannot autolaunch D-Bus without X11 $DISPLAY"
    with pytest.raises(AuthRequired, match=r"keyring did not hand over.*not running"):
        SecretService().password()


def test_keyring_session_goes_in_on_stdin(run: Security, secret_tool: None) -> None:
    SecretService().save_session("abc123")
    SecretService().clear_session()
    (store, stdin, _), (clear, _, _) = run.calls
    assert store[1] == "store" and "abc123" not in store and stdin == "abc123"
    assert clear[1:] == ["clear", "service", "telenor-router-session", "account", "telenor"]


def test_without_secret_tool_says_what_to_install(
    run: Security, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "access", lambda p, mode: False)
    with pytest.raises(ConfigError, match="libsecret-tools") as e:
        SecretService().password()
    assert str(password_file()) in str(e.value) and run.calls == []


# Linux files


def write_password(text: str, mode: int = 0o600) -> Path:
    p = password_file()
    p.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    p.write_text(text)
    p.chmod(mode)
    return p


def test_password_file(run: Security) -> None:
    write_password("pw with spaces \n")
    assert Files().password() == "pw with spaces "
    assert run.calls == []


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660])
def test_password_file_others_can_read_is_refused(mode: int) -> None:
    write_password("pw", mode)
    with pytest.raises(ConfigError, match="chmod 600"):
        Files().password()


def test_password_file_in_a_shared_dir_is_refused() -> None:
    p = write_password("pw")
    p.parent.chmod(0o777)
    with pytest.raises(ConfigError, match="chmod 700"):
        Files().password()


def test_password_file_link_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.write_text("pw")
    target.chmod(0o600)
    p = password_file()
    p.parent.mkdir(parents=True, mode=0o700)
    p.symlink_to(target)
    with pytest.raises(ConfigError, match="not a link"):
        Files().password()


def test_empty_password_file() -> None:
    write_password("\n")
    with pytest.raises(AuthRequired, match="empty"):
        Files().password()


def test_file_session_is_private() -> None:
    f = Files()
    assert f.load_session() is None
    f.save_session("abc123")
    path = config.state_dir() / "session"
    assert f.load_session() == "abc123" and path.stat().st_mode & 0o777 == 0o600
    f.clear_session()
    assert f.load_session() is None and not path.exists()


# which store


def test_store_per_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.platform", "darwin")
    write_password("pw")  # ignored on macOS
    assert isinstance(REAL_STORE(), Keychain)
    monkeypatch.setattr("sys.platform", "linux")
    assert isinstance(REAL_STORE(), Files)
    password_file().unlink()
    assert isinstance(REAL_STORE(), SecretService)
    monkeypatch.setattr("sys.platform", "win32")
    with pytest.raises(ConfigError, match="macOS and Linux"):
        REAL_STORE()
