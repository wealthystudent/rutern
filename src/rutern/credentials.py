"""Where the admin password and the session cookie live.

macOS keeps both in the Keychain, through /usr/bin/security. Linux keeps them
in the desktop keyring (the Secret Service: GNOME Keyring, KWallet) through
secret-tool, or, once the person has created ~/.config/rutern/password, in
files only they can read. rutern never falls back to files on its own.

The password is read at login only and never logged, printed, put in argv
or in an environment variable. Secrets reach `security` and `secret-tool` on
stdin, so they never show up in the process list.
"""

from __future__ import annotations

import contextlib
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Protocol

from rutern import config
from rutern.errors import AuthRequired, ConfigError

SERVICE = "telenor-router"
SESSION_SERVICE = "telenor-router-session"
ACCOUNT = "telenor"
# Long enough to answer the Keychain prompt or the keyring's unlock dialog.
PROMPT_TIMEOUT = 120


class _Refused(Exception):
    """The secret may exist, but the store did not hand it over."""


class _Missing(Exception):
    """The store answered: there is no such secret."""


class Store(Protocol):
    def password(self) -> str: ...
    def load_session(self) -> str | None: ...
    def save_session(self, value: str) -> None: ...
    def clear_session(self) -> None: ...


def _refused(where: str, why: str) -> AuthRequired:
    return AuthRequired(f"{where} did not hand over the admin password ({why})")


class Keychain:
    """macOS. By absolute path, so a `security` planted earlier in PATH never
    sees the secrets. The person creates the password item with -T "", so
    macOS asks before any program reads it."""

    SECURITY = "/usr/bin/security"
    NOT_FOUND = 44  # `security` exit status when no such item exists
    ADD = f'security add-generic-password -s {SERVICE} -a {ACCOUNT} -T "" -w'

    def _find(self, service: str, timeout: float = 10) -> str | None:
        try:
            out = subprocess.run(
                [self.SECURITY, "find-generic-password", "-s", service, "-a", ACCOUNT, "-w"],
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
            )
        except FileNotFoundError:
            raise ConfigError(
                f"{self.SECURITY} is missing, so the Keychain is out of reach"
            ) from None
        except (OSError, subprocess.TimeoutExpired):
            raise _Refused from None
        if out.returncode == self.NOT_FOUND:
            return None
        if out.returncode != 0:
            raise _Refused
        return out.stdout.rstrip("\n") or None

    def password(self) -> str:
        try:
            value = self._find(SERVICE, timeout=PROMPT_TIMEOUT)
        except _Refused:
            raise _refused(
                "the Keychain", "the prompt was denied or not answered in time"
            ) from None
        if value is None:
            raise AuthRequired(f"no admin password in the Keychain; store it once with: {self.ADD}")
        return value

    def load_session(self) -> str | None:
        try:
            return self._find(SESSION_SERVICE)
        except _Refused:
            return None

    def save_session(self, value: str) -> None:
        if any(c in value for c in '"\\\n\r') or not value.isprintable():
            return  # cannot be quoted for `security -i`; the next run logs in again
        cmd = f'add-generic-password -U -s {SESSION_SERVICE} -a {ACCOUNT} -w "{value}"\n'
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(
                [self.SECURITY, "-i"], input=cmd, capture_output=True, text=True, timeout=10
            )

    def clear_session(self) -> None:
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(
                [self.SECURITY, "delete-generic-password", "-s", SESSION_SERVICE, "-a", ACCOUNT],
                capture_output=True,
                timeout=10,
            )


class SecretService:
    """Linux desktop keyring (GNOME Keyring, KWallet) through secret-tool, found
    only in fixed system places so one planted earlier in PATH is never used."""

    PATHS = (
        "/usr/bin/secret-tool",
        "/bin/secret-tool",
        "/usr/local/bin/secret-tool",
        "/run/current-system/sw/bin/secret-tool",
    )
    ADD = (
        "secret-tool store --label='Telenor router admin password' "
        f"service {SERVICE} account {ACCOUNT}"
    )

    def _tool(self) -> str:
        for path in self.PATHS:
            if os.access(path, os.X_OK):
                return path
        raise ConfigError(
            "secret-tool is not installed (libsecret-tools on Debian and Ubuntu, libsecret "
            "elsewhere). On a machine without a keyring, put the password in "
            f"{password_file()} instead"
        )

    def _run(self, *args: str, stdin: str | None = None, timeout: float = 10) -> str:
        try:
            out = subprocess.run(
                [self._tool(), *args],
                input=stdin,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise _Refused from None
        if out.returncode != 0:
            # Not found is a quiet exit 1; no keyring or a refused unlock says why.
            if out.stderr.strip():
                raise _Refused
            raise _Missing
        return out.stdout

    def _lookup(self, service: str, timeout: float = 10) -> str | None:
        try:
            return (
                self._run("lookup", "service", service, "account", ACCOUNT, timeout=timeout).rstrip(
                    "\n"
                )
                or None
            )
        except _Missing:
            return None

    def password(self) -> str:
        try:
            value = self._lookup(SERVICE, timeout=PROMPT_TIMEOUT)
        except _Refused:
            raise _refused("the keyring", "it is locked or not running") from None
        if value is None:
            raise AuthRequired(f"no admin password in the keyring; store it once with: {self.ADD}")
        return value

    def load_session(self) -> str | None:
        try:
            return self._lookup(SESSION_SERVICE)
        except _Refused:
            return None

    def save_session(self, value: str) -> None:
        with contextlib.suppress(_Refused, _Missing, ConfigError):
            self._run(
                "store",
                "--label=rutern session",
                "service",
                SESSION_SERVICE,
                "account",
                ACCOUNT,
                stdin=value,
            )

    def clear_session(self) -> None:
        with contextlib.suppress(_Refused, _Missing, ConfigError):
            self._run("clear", "service", SESSION_SERVICE, "account", ACCOUNT)


def password_file() -> Path:
    return config.home() / ".config" / "rutern" / "password"


class Files:
    """Linux without a keyring (a server, a Raspberry Pi): the password in a file
    the person created, the session in the state dir. Like ~/.ssh, a file
    others could read or replace is refused."""

    def password(self) -> str:
        path = password_file()
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            raise ConfigError(f"cannot read {path}; it must be a file, not a link") from None
        try:
            st, parent = os.fstat(fd), path.parent.stat()
            safe = (
                stat.S_ISREG(st.st_mode)
                and st.st_uid == os.getuid()
                and not st.st_mode & 0o077
                and parent.st_uid == os.getuid()
                and not parent.st_mode & 0o022
            )
            if not safe:
                raise ConfigError(
                    f"{path} must be yours and readable only by you (chmod 600 {path}, "
                    f"chmod 700 {path.parent})"
                )
            with os.fdopen(fd, encoding="utf-8") as f:
                fd = -1
                value = f.read().removesuffix("\n").removesuffix("\r")
        finally:
            if fd != -1:
                os.close(fd)
        if not value:
            raise AuthRequired(f"{path} is empty; put the admin password on its first line")
        return value

    @staticmethod
    def _session() -> Path:
        return config.state_dir() / "session"

    def load_session(self) -> str | None:
        try:
            return self._session().read_text().strip() or None
        except OSError:
            return None

    def save_session(self, value: str) -> None:
        with contextlib.suppress(OSError):
            config.write_private(self._session(), value + "\n")

    def clear_session(self) -> None:
        with contextlib.suppress(OSError):
            self._session().unlink(missing_ok=True)


def store() -> Store:
    """The Keychain on macOS. On Linux the password file once the person made
    one, else the keyring."""
    if sys.platform == "darwin":
        return Keychain()
    if sys.platform.startswith("linux"):
        return Files() if os.path.lexists(password_file()) else SecretService()
    raise ConfigError("rutern runs on macOS and Linux")


def admin_password() -> str:
    return store().password()


def load_session() -> str | None:
    return store().load_session()


def save_session(value: str) -> None:
    store().save_session(value)


def clear_session() -> None:
    store().clear_session()
