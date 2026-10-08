"""CloudClient: the authenticated portal API at https://wifi.telenor.no/v1.

Login is a SvelteKit form action that sets the `__Host-session` cookie. It
runs at most once per process, and a rejected login writes a guard file
that blocks further attempts for a while, because repeated failures can
lock the router. The cookie is cached in Keychain so most runs need no
login at all; a cached cookie that turns out stale costs one fresh login.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from rutern import keychain
from rutern.config import Config, discover_reference, state_dir
from rutern.errors import (
    ApiError,
    AuthRequired,
    LoginBlocked,
    LoginFailed,
    Unreachable,
)
from rutern.models import (
    AliasEntry,
    Dhcp,
    Dns,
    Firewall,
    FirewallRule,
    Host,
    Leases,
    PortForward,
    StaticLease,
    StaticRoute,
    Upnp,
    UpnpMapping,
    Uptime,
    Wifi,
    parse_dns,
)

COOKIE = "__Host-session"
AUTH_FAILED_MESSAGE = "10000"
GUARD_SECONDS = 15 * 60
LOGIN_INTERVAL = 60.0


class LoginGuard:
    """A file that records a rejected login so later runs do not retry it."""

    def __init__(self, path: Path | None = None, clock: Callable[[], float] = time.time):
        self.path = path or state_dir() / "login-failed"
        self.clock = clock

    def check(self) -> None:
        try:
            failed_at = float(self.path.read_text().strip())
        except (OSError, ValueError):
            return
        left = GUARD_SECONDS - (self.clock() - failed_at)
        if left > 0:
            raise LoginBlocked(
                f"last login was rejected; not retrying for {int(left // 60) + 1} min "
                "to avoid locking the router. Check the Keychain password, then run "
                "`rutern logout` to clear this guard"
            )

    def record_failure(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.write_text(f"{self.clock()}\n")

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)


class SessionStore:
    """Where the session cookie is cached between runs (Keychain by default)."""

    def load(self) -> str | None:
        return keychain.load_session()

    def save(self, value: str) -> None:
        keychain.store_session(value)

    def clear(self) -> None:
        keychain.clear_session()


class CloudClient:
    def __init__(
        self,
        config: Config | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        password: Callable[[], str] = keychain.admin_password,
        store: SessionStore | None = None,
        guard: LoginGuard | None = None,
        reference: Callable[[], str] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.config = config or Config()
        self._password = password
        self._store = store if store is not None else SessionStore()
        self._guard = guard or LoginGuard()
        self._reference_fn = reference
        self._reference: str | None = self.config.reference
        self._http = httpx.Client(
            base_url=self.config.cloud_base,
            timeout=self.config.timeout,
            transport=transport,
            follow_redirects=False,
            headers={"Accept": "application/json"},
        )
        self._clock = clock
        self._login_failed = False
        self._last_login: float | None = None

    def close(self) -> None:
        self._http.close()

    # reference id

    @property
    def reference(self) -> str:
        if self._reference is None:
            ref = self._reference_fn() if self._reference_fn else self.discover_reference()
            if not ref or not ref.isdigit():
                raise ApiError("no reference id; set RUTERN_REFERENCE")
            self._reference = ref
        return self._reference

    def discover_reference(self) -> str | None:
        """The portal's admin login page names the router it sees you behind.
        With a live session it redirects instead: /login/admin -> / -> /<reference>.
        """
        path = "/login/admin"
        for _ in range(3):
            try:
                r = self._http.get(path, headers={"Accept": "text/html"})
            except httpx.HTTPError as e:
                raise Unreachable("wifi.telenor.no did not answer") from e
            if r.status_code == 200:
                return discover_reference(r.text)
            if not r.is_redirect:
                return None
            path = str(r.headers.get("location", ""))
            if path.strip("/").isdigit():
                return path.strip("/")
            if not path.startswith("/"):
                return None
        return None

    # session

    def _set_cookie(self, value: str) -> None:
        host = httpx.URL(self.config.cloud_base).host
        self._http.cookies.set(COOKIE, value, domain=host, path="/")

    def _has_cookie(self) -> bool:
        return any(c.name == COOKIE for c in self._http.cookies.jar)

    def _cookie(self) -> str | None:
        for c in self._http.cookies.jar:
            if c.name == COOKIE:
                return c.value
        return None

    def login(self) -> None:
        """One login attempt. A failure is never retried in this process, and
        successful logins are at least LOGIN_INTERVAL apart."""
        if self._login_failed:
            raise AuthRequired("login already failed in this run; not retrying")
        now = self._clock()
        if self._last_login is not None and now - self._last_login < LOGIN_INTERVAL:
            raise AuthRequired("logged in moments ago and the session is still refused")
        self._guard.check()
        self._last_login = now
        self._http.cookies.clear()
        files = {
            "username": (None, self.reference),
            "password": (None, self._password()),
            "redirect_to": (None, "/"),
        }
        headers = {"Origin": self.config.cloud_base, "x-sveltekit-action": "true"}
        try:
            r = self._http.post("/login/admin?/login", files=files, headers=headers)
        except httpx.HTTPError as e:
            self._login_failed = True
            raise Unreachable("wifi.telenor.no did not answer the login") from e
        ok = False
        if r.status_code == 200:
            try:
                ok = r.json().get("type") == "redirect"
            except (ValueError, AttributeError):
                ok = False
        cookie = self._cookie()
        if not ok or not cookie:
            self._login_failed = True
            self._guard.record_failure()
            raise LoginFailed(f"login rejected (HTTP {r.status_code}); not retrying")
        self._guard.clear()
        self._store.save(cookie)

    def logout(self) -> None:
        """Forget the cached session and clear the login guard."""
        self._store.clear()
        self._guard.clear()
        self._http.cookies.clear()

    def _ensure_session(self) -> bool:
        """Make sure a cookie is set. True when that took a fresh login."""
        if self._has_cookie():
            return False
        cached = self._store.load()
        if cached:
            self._set_cookie(cached)
            return False
        self.login()
        return True

    # requests

    def _send(self, method: str, endpoint: str, body: Any = None) -> httpx.Response:
        path = f"/v1/{self.reference}/{endpoint.lstrip('/')}"
        headers = {"Origin": self.config.cloud_base} if method != "GET" else None
        try:
            return self._http.request(method, path, json=body, headers=headers)
        except httpx.HTTPError as e:
            raise Unreachable(f"wifi.telenor.no did not answer {method} {endpoint}") from e

    @staticmethod
    def _is_auth_failure(r: httpx.Response) -> bool:
        if r.status_code == 401:
            return True
        if r.is_redirect and "login" in r.headers.get("location", ""):
            return True
        return r.status_code in (400, 403) and AUTH_FAILED_MESSAGE in r.text[:200]

    def request(self, method: str, endpoint: str, body: Any = None) -> Any:
        fresh = self._ensure_session()
        r = self._send(method, endpoint, body)
        if self._is_auth_failure(r):
            if fresh:
                raise AuthRequired(f"{endpoint}: session rejected right after login")
            # The session went stale. Log in once and retry once.
            self._store.clear()
            self.login()
            r = self._send(method, endpoint, body)
            if self._is_auth_failure(r):
                raise AuthRequired(f"{endpoint}: session rejected right after login")
        if r.status_code == 404:
            raise ApiError(f"{endpoint}: not found (HTTP 404)")
        if r.status_code >= 400 or r.is_redirect:
            raise ApiError(f"{method} {endpoint}: HTTP {r.status_code}")
        if not r.content:
            return None
        try:
            data = r.json()
        except ValueError as e:
            raise ApiError(f"{endpoint}: response is not JSON") from e
        if isinstance(data, dict) and data.get("errors"):
            raise ApiError(f"{method} {endpoint}: router reported {len(data['errors'])} error(s)")
        return data

    def get(self, endpoint: str) -> Any:
        return self.request("GET", endpoint)

    def post(self, endpoint: str, body: Any) -> Any:
        return self.request("POST", endpoint, body)

    # reads

    def uptime(self) -> Uptime:
        return Uptime.model_validate(self.get("uptime"))

    def hosts(self) -> list[Host]:
        data = self.get("lan-hosts")
        return [Host.model_validate(h) for h in _list(data, "hosts")]

    def wifi(self) -> Wifi:
        return Wifi.model_validate(self.get("wlan"))

    def aliases(self) -> list[AliasEntry]:
        """Saved aliases (non_volatile). Entries with an empty alias are dropped."""
        data = self.get("lan-hosts/alias")
        return [
            a
            for a in (AliasEntry.model_validate(x) for x in _list(data, "non_volatile"))
            if a.alias
        ]

    def leases(self) -> Leases:
        data = self.get("static-dhcp-leases")
        return Leases(
            reserved=[StaticLease.model_validate(x) for x in _list(data, "non_volatile")],
            active_reserved=[StaticLease.model_validate(x) for x in data.get("volatile") or []],
            dynamic=[StaticLease.model_validate(x) for x in data.get("dynamic_leases") or []],
        )

    def routes(self) -> list[StaticRoute]:
        return [
            StaticRoute.model_validate(x) for x in _list(self.get("static-routes"), "non_volatile")
        ]

    def forwards(self) -> list[PortForward]:
        return [PortForward.model_validate(x) for x in _list(self.get("nat-rules"), "non_volatile")]

    def firewall(self) -> Firewall:
        status = _dict(self.get("firewall-status"), "non_volatile")
        rules = _list(self.get("firewall-rules"), "non_volatile")
        return Firewall(
            ipv4_enabled=bool(status.get("ipv4_enabled")),
            ipv6_enabled=bool(status.get("ipv6_enabled")),
            rules=[FirewallRule.model_validate(x) for x in rules],
        )

    def dhcp(self) -> Dhcp:
        saved = _list(self.get("dhcp"), "non_volatile")
        if not saved:
            raise ApiError("dhcp: no saved config")
        return Dhcp.model_validate(saved[0])

    def dns(self) -> Dns:
        return parse_dns(self.get("dns"))

    def dmz(self) -> str | None:
        """The DMZ host, or None when DMZ is off (0.0.0.0)."""
        ip = str(_dict(self.get("dmz"), "non_volatile").get("ipv4_address") or "")
        return None if ip in ("", "0.0.0.0") else ip

    def upnp(self) -> Upnp:
        enabled = bool(_dict(self.get("upnp"), "non_volatile").get("enabled"))
        mappings = self.get("upnp/mappings").get("upnp_mappings") or [] if enabled else []
        return Upnp(enabled=enabled, mappings=[UpnpMapping.model_validate(m) for m in mappings])


def _dict(data: Any, key: str) -> dict[str, Any]:
    value = data.get(key) if isinstance(data, dict) else None
    if not isinstance(value, dict):
        raise ApiError(f"response has no {key!r} object")
    return value


def _list(data: Any, key: str) -> list[Any]:
    value = data.get(key) if isinstance(data, dict) else None
    if not isinstance(value, list):
        raise ApiError(f"response has no {key!r} list")
    return value
