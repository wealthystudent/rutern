from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from rutern.cloud import COOKIE, CloudClient, LoginGuard
from rutern.config import Config
from rutern.errors import ApiError, AuthRequired, LoginBlocked, LoginFailed

Handler = Callable[[httpx.Request], httpx.Response]
PASSWORD = "hunter2-not-real"


class MemoryStore:
    def __init__(self, value: str | None = None):
        self.value = value
        self.saves = 0

    def load(self) -> str | None:
        return self.value

    def save(self, value: str) -> None:
        self.value = value
        self.saves += 1

    def clear(self) -> None:
        self.value = None


class FakePortal:
    """Just enough of wifi.telenor.no: the login action and cookie-checked /v1 reads."""

    def __init__(self, *, accept_login: bool = True, valid: str = "good-session"):
        self.accept_login = accept_login
        self.valid = valid
        self.logins = 0
        self.login_bodies: list[bytes] = []
        self.seen: list[str] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.seen.append(f"{req.method} {req.url.path}")
        if req.url.path == "/login/admin":
            self.logins += 1
            assert req.url.query == b"/login"
            assert req.headers["x-sveltekit-action"] == "true"
            assert req.headers["origin"] == "https://wifi.telenor.no"
            assert req.headers["content-type"].startswith("multipart/form-data")
            body = req.read()
            self.login_bodies.append(body)
            if not self.accept_login:
                return httpx.Response(200, json={"type": "failure", "status": 400})
            return httpx.Response(
                200,
                json={"type": "redirect", "status": 303, "location": "/"},
                headers={"set-cookie": f"{COOKIE}={self.valid}; Path=/; Secure; HttpOnly"},
            )
        if req.url.path.startswith("/v1/12345678/"):
            if f"{COOKIE}={self.valid}" not in req.headers.get("cookie", ""):
                return httpx.Response(401, json={"message": "10000"})
            if req.url.path.endswith("/uptime"):
                return httpx.Response(200, json={"os": 10, "wan": 5})
            if req.url.path.endswith("/lan-hosts/alias") and req.method == "POST":
                return httpx.Response(200, json={})
            return httpx.Response(404)
        return httpx.Response(404)


def client(portal: FakePortal, store: MemoryStore, tmp_path: Path) -> CloudClient:
    return CloudClient(
        Config(reference="12345678"),
        transport=httpx.MockTransport(portal),
        password=lambda: PASSWORD,
        store=store,  # type: ignore[arg-type]
        guard=LoginGuard(tmp_path / "guard"),
    )


def test_login_once_then_reuse_session(tmp_path: Path) -> None:
    portal, store = FakePortal(), MemoryStore()
    c = client(portal, store, tmp_path)
    assert c.get("uptime") == {"os": 10, "wan": 5}
    assert c.get("uptime") == {"os": 10, "wan": 5}
    assert portal.logins == 1
    assert store.value == "good-session"
    body = portal.login_bodies[0]
    assert b'name="username"\r\n\r\n12345678' in body
    assert b'name="redirect_to"\r\n\r\n/' in body
    assert PASSWORD.encode() in body


def test_cached_session_skips_login(tmp_path: Path) -> None:
    portal, store = FakePortal(), MemoryStore("good-session")
    c = client(portal, store, tmp_path)
    assert c.get("uptime")["os"] == 10
    assert portal.logins == 0


def test_stale_cached_session_relogs_in_once(tmp_path: Path) -> None:
    portal, store = FakePortal(), MemoryStore("stale")
    c = client(portal, store, tmp_path)
    assert c.get("uptime")["os"] == 10
    assert portal.logins == 1
    assert store.value == "good-session"


def test_rejected_login_is_not_retried_and_sets_guard(tmp_path: Path) -> None:
    portal, store = FakePortal(accept_login=False), MemoryStore()
    c = client(portal, store, tmp_path)
    with pytest.raises(LoginFailed) as e:
        c.get("uptime")
    assert PASSWORD not in str(e.value)
    with pytest.raises(AuthRequired):
        c.get("uptime")
    assert portal.logins == 1

    # A new process is blocked by the guard file and never reaches the portal.
    c2 = client(portal, MemoryStore(), tmp_path)
    with pytest.raises(LoginBlocked):
        c2.get("uptime")
    assert portal.logins == 1


def test_guard_expires(tmp_path: Path) -> None:
    now = [1000.0]
    guard = LoginGuard(tmp_path / "g", clock=lambda: now[0])
    guard.record_failure()
    with pytest.raises(LoginBlocked):
        guard.check()
    now[0] += 16 * 60
    guard.check()


def test_session_rejected_after_fresh_login_does_not_loop(tmp_path: Path) -> None:
    portal, store = FakePortal(), MemoryStore()
    portal.valid = "something-else"

    def handler(req: httpx.Request) -> httpx.Response:
        r = portal(req)
        if req.url.path == "/login/admin":
            return httpx.Response(
                200,
                json={"type": "redirect"},
                headers={"set-cookie": f"{COOKIE}=wrong; Path=/; Secure"},
            )
        return r

    c = CloudClient(
        Config(reference="12345678"),
        transport=httpx.MockTransport(handler),
        password=lambda: PASSWORD,
        store=store,  # type: ignore[arg-type]
        guard=LoginGuard(tmp_path / "guard"),
    )
    with pytest.raises(AuthRequired):
        c.get("uptime")
    assert portal.logins == 1


def test_post_sends_json_and_origin(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []
    portal = FakePortal()

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return portal(req)

    c = CloudClient(
        Config(reference="12345678"),
        transport=httpx.MockTransport(handler),
        password=lambda: PASSWORD,
        store=MemoryStore("good-session"),  # type: ignore[arg-type]
        guard=LoginGuard(tmp_path / "guard"),
    )
    c.post("lan-hosts/alias", {"mac": "aa"})
    req = seen[-1]
    assert req.method == "POST"
    assert req.headers["origin"] == "https://wifi.telenor.no"
    assert json.loads(req.content) == {"mac": "aa"}


def test_404_is_api_error(tmp_path: Path) -> None:
    c = client(FakePortal(), MemoryStore("good-session"), tmp_path)
    with pytest.raises(ApiError):
        c.get("status")


def test_long_running_client_relogs_in_after_expiry(tmp_path: Path) -> None:
    now = [0.0]
    portal, store = FakePortal(), MemoryStore()
    c = CloudClient(
        Config(reference="12345678"),
        transport=httpx.MockTransport(portal),
        password=lambda: PASSWORD,
        store=store,  # type: ignore[arg-type]
        guard=LoginGuard(tmp_path / "guard"),
        clock=lambda: now[0],
    )
    c.get("uptime")
    portal.valid = "rotated"  # server side expiry
    with pytest.raises(AuthRequired):
        c.get("uptime")  # too soon after the last login
    now[0] += 120
    assert c.get("uptime")["os"] == 10
    assert portal.logins == 2


def test_password_never_in_errors_or_repr(tmp_path: Path) -> None:
    portal = FakePortal(accept_login=False)
    c = client(portal, MemoryStore(), tmp_path)
    with pytest.raises(LoginFailed) as e:
        c.get("uptime")
    text = f"{e.value!r} {e.value} {c!r} {vars(c)!r}"
    assert PASSWORD not in text


def test_discover_reference_from_login_page_and_redirects(tmp_path: Path) -> None:
    from rutern.config import discover_reference

    assert discover_reference('x,model:"ex5700",reference:"87654321",y') == "87654321"
    assert discover_reference("<html>") is None

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/login/admin":
            return httpx.Response(303, headers={"location": "/"})
        if req.url.path == "/":
            return httpx.Response(303, headers={"location": "/87654321"})
        return httpx.Response(404)

    c = CloudClient(Config(reference=None), transport=httpx.MockTransport(handler))
    assert c.reference == "87654321"


def test_login_refuses_without_reference(tmp_path: Path) -> None:
    portal = FakePortal()
    c = CloudClient(
        Config(reference=None),
        transport=httpx.MockTransport(lambda req: httpx.Response(200, text="<html>")),
        password=lambda: PASSWORD,
        store=MemoryStore(),  # type: ignore[arg-type]
        guard=LoginGuard(tmp_path / "guard"),
    )
    with pytest.raises(ApiError, match="reference"):
        c.login()
    assert portal.logins == 0
