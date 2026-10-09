"""Keychain access. The password is read at login time only and never logged,
printed, put in argv or in an environment variable.

The session cookie is cached in Keychain too. It is written through
`security -i` on stdin so it never shows up in the process list.
"""

from __future__ import annotations

import contextlib
import subprocess

from rutern.errors import AuthRequired, ConfigError

# By absolute path, so a `security` planted earlier in PATH never sees the session.
SECURITY = "/usr/bin/security"
SERVICE = "telenor-router"
ACCOUNT = "telenor"
SESSION_SERVICE = "telenor-router-session"
ADD_COMMAND = f'security add-generic-password -s {SERVICE} -a {ACCOUNT} -T "" -w'
NOT_FOUND = 44  # `security` exit status when no such item exists

# Long enough to answer the macOS prompt when the item trusts no app (see README).
PROMPT_TIMEOUT = 120


class _Refused(Exception):
    """The item may exist, but Keychain did not hand it over."""


def _find(service: str, timeout: float = 10) -> str | None:
    """The item's secret, or None when there is no such item. Raises _Refused
    when the prompt is denied or not answered in time."""
    try:
        out = subprocess.run(
            [SECURITY, "find-generic-password", "-s", service, "-a", ACCOUNT, "-w"],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise ConfigError(
            "rutern keeps the admin password in the macOS Keychain, so it needs macOS"
        ) from None
    except (OSError, subprocess.TimeoutExpired):
        raise _Refused from None
    if out.returncode == NOT_FOUND:
        return None
    if out.returncode != 0:
        raise _Refused
    value = out.stdout.rstrip("\n")
    return value or None


def admin_password() -> str:
    """The admin password from Keychain (service telenor-router, account telenor)."""
    try:
        value = _find(SERVICE, timeout=PROMPT_TIMEOUT)
    except _Refused:
        raise AuthRequired(
            "Keychain did not hand over the admin password (the prompt was denied or not "
            "answered in time)"
        ) from None
    if value is None:
        raise AuthRequired(f"no admin password in Keychain; store it once with: {ADD_COMMAND}")
    return value


def load_session() -> str | None:
    try:
        return _find(SESSION_SERVICE)
    except _Refused:
        return None


def _quote(value: str) -> str:
    if any(c in value for c in '"\\\n\r') or not value.isprintable():
        raise ValueError("session value has characters that cannot be stored safely")
    return f'"{value}"'


def store_session(value: str) -> None:
    cmd = f"add-generic-password -U -s {SESSION_SERVICE} -a {ACCOUNT} -w {_quote(value)}\n"
    with contextlib.suppress(OSError, subprocess.TimeoutExpired):
        subprocess.run(
            [SECURITY, "-i"], input=cmd, capture_output=True, text=True, check=False, timeout=10
        )


def clear_session() -> None:
    with contextlib.suppress(OSError, subprocess.TimeoutExpired):
        subprocess.run(
            [SECURITY, "delete-generic-password", "-s", SESSION_SERVICE, "-a", ACCOUNT],
            capture_output=True,
            check=False,
            timeout=10,
        )
