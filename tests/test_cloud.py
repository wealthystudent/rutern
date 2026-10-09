from __future__ import annotations

import ssl
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from rutern.cloud import COOKIE, CloudClient, LoginGuard, ReferencePin
from rutern.config import Config
from rutern.errors import (
    ApiError,
    AuthRequired,
    ConfigError,
    LoginBlocked,
    LoginFailed,
    Unreachable,
)
from rutern.local import LocalClient

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
    guard.record_attempt()
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
    assert not c.has_reference
    assert c.find_reference() == "87654321"
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
    with pytest.raises(ConfigError, match="reference"):
        c.login()
    assert portal.logins == 0


# hardening


def test_only_allowlisted_endpoints_reach_the_portal(tmp_path: Path) -> None:
    portal = FakePortal()
    c = client(portal, MemoryStore("good-session"), tmp_path)
    for ep in (
        "reboot",
        "factory-reset",
        "msan/reset-ont",
        "../../reboot",
        "uptime/../reboot",
        "uptime?x=1",
        "/uptime",
        "log",
    ):
        with pytest.raises(ApiError, match="not an endpoint"):
            c.get(ep)
    assert portal.seen == []


def test_only_gets_reach_v1(tmp_path: Path) -> None:
    portal = FakePortal()
    c = client(portal, MemoryStore("good-session"), tmp_path)
    for name in ("post", "put", "patch", "delete", "request"):
        assert not hasattr(c, name)
    c.get("uptime")
    assert [x for x in portal.seen if "/v1/" in x] == ["GET /v1/12345678/uptime"]


def test_cloud_base_cannot_be_redirected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RUTERN_CLOUD", "http://evil.example")
    hosts: list[str] = []
    portal = FakePortal()

    def handler(req: httpx.Request) -> httpx.Response:
        hosts.append(f"{req.url.scheme}://{req.url.host}")
        return portal(req)

    c = CloudClient(
        Config(),
        transport=httpx.MockTransport(handler),
        password=lambda: PASSWORD,
        store=MemoryStore(),  # type: ignore[arg-type]
        guard=LoginGuard(tmp_path / "guard"),
    )
    c.get("uptime")
    assert set(hosts) == {"https://wifi.telenor.no"}


def test_login_pins_the_reference(tmp_path: Path) -> None:
    pin = ReferencePin(tmp_path / "state" / "reference")
    portal = FakePortal()
    c = CloudClient(
        Config(reference="12345678"),
        transport=httpx.MockTransport(portal),
        password=lambda: PASSWORD,
        store=MemoryStore(),  # type: ignore[arg-type]
        guard=LoginGuard(tmp_path / "guard"),
        pin=pin,
    )
    c.get("uptime")
    assert pin.load() == "12345678"
    assert pin.path.stat().st_mode & 0o777 == 0o600
    later = CloudClient(Config(reference=None), transport=httpx.MockTransport(portal), pin=pin)
    assert later.has_reference and later.reference == "12345678"


def test_no_reference_sends_nothing(tmp_path: Path) -> None:
    portal = FakePortal()
    c = CloudClient(
        Config(reference=None),
        transport=httpx.MockTransport(portal),
        password=lambda: PASSWORD,
        store=MemoryStore("good-session"),  # type: ignore[arg-type]
        guard=LoginGuard(tmp_path / "guard"),
    )
    with pytest.raises(ConfigError, match="rutern login"):
        c.get("uptime")
    assert portal.seen == []


def test_validation_error_mentioning_10000_is_not_an_auth_failure(tmp_path: Path) -> None:
    portal = FakePortal()

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/nat-rules"):
            return httpx.Response(400, json={"message": "Wan_port_start must not exceed 10000"})
        return portal(req)

    c = CloudClient(
        Config(reference="12345678"),
        transport=httpx.MockTransport(handler),
        password=lambda: PASSWORD,
        store=MemoryStore("good-session"),  # type: ignore[arg-type]
        guard=LoginGuard(tmp_path / "guard"),
    )
    with pytest.raises(ApiError, match="HTTP 400"):
        c.get("nat-rules")
    assert portal.logins == 0


def test_exact_10000_message_is_an_auth_failure(tmp_path: Path) -> None:
    portal = FakePortal()
    stale = [True]

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/uptime") and stale[0]:
            stale[0] = False
            return httpx.Response(403, json={"message": 10000})
        return portal(req)

    c = CloudClient(
        Config(reference="12345678"),
        transport=httpx.MockTransport(handler),
        password=lambda: PASSWORD,
        store=MemoryStore("good-session"),  # type: ignore[arg-type]
        guard=LoginGuard(tmp_path / "guard"),
    )
    assert c.get("uptime")["os"] == 10
    assert portal.logins == 1


@pytest.mark.parametrize("content", ["garbage", "nan", "inf"])
def test_damaged_guard_blocks_login(tmp_path: Path, content: str) -> None:
    guard = LoginGuard(tmp_path / "g")
    guard.path.write_text(content)
    with pytest.raises(LoginBlocked, match="damaged"):
        guard.check()


def test_guard_file_is_private(tmp_path: Path) -> None:
    guard = LoginGuard(tmp_path / "state" / "g")
    guard.record_attempt()
    assert guard.path.stat().st_mode & 0o777 == 0o600
    assert guard.path.parent.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize(
    ("exc", "guarded"), [(httpx.ConnectError, False), (httpx.ReadTimeout, True)]
)
def test_login_cut_off_after_sending_counts_as_attempt(
    tmp_path: Path, exc: type[httpx.TransportError], guarded: bool
) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise exc("boom", request=req)

    guard = LoginGuard(tmp_path / "guard")
    c = CloudClient(
        Config(reference="12345678"),
        transport=httpx.MockTransport(handler),
        password=lambda: PASSWORD,
        store=MemoryStore(),  # type: ignore[arg-type]
        guard=guard,
    )
    with pytest.raises(Unreachable):
        c.login()
    assert guard.path.exists() is guarded


def test_oversized_response_is_refused(tmp_path: Path) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"[" + b"0," * (2 * 1024 * 1024) + b"0]")

    c = CloudClient(
        Config(reference="12345678"),
        transport=httpx.MockTransport(handler),
        password=lambda: PASSWORD,
        store=MemoryStore("good-session"),  # type: ignore[arg-type]
        guard=LoginGuard(tmp_path / "guard"),
    )
    with pytest.raises(ApiError, match="larger"):
        c.get("uptime")


def test_refused_keychain_prompt_is_not_asked_again_at_once(tmp_path: Path) -> None:
    portal, asked = FakePortal(), [0]

    def password() -> str:
        asked[0] += 1
        raise AuthRequired("Keychain did not hand over the admin password")

    c = CloudClient(
        Config(reference="12345678"),
        transport=httpx.MockTransport(portal),
        password=password,
        store=MemoryStore(),  # type: ignore[arg-type]
        guard=LoginGuard(tmp_path / "guard"),
    )
    with pytest.raises(AuthRequired, match="did not hand over"):
        c.get("uptime")
    with pytest.raises(AuthRequired, match="less than a minute ago"):
        c.get("uptime")
    assert asked[0] == 1 and portal.logins == 0
    assert not (tmp_path / "guard").exists()


def test_env_cannot_proxy_or_weaken_tls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "all_proxy"):
        monkeypatch.setenv(var, "http://127.0.0.1:9")
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "attacker-ca.pem"))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))
    monkeypatch.setenv("SSLKEYLOGFILE", str(tmp_path / "keys.log"))
    cloud = CloudClient(Config(reference="12345678"))
    local = LocalClient(Config())
    for http in (cloud._http, local._http):
        assert http.trust_env is False and not http._mounts  # no proxy transport
    pool = cloud._http._transport._pool  # type: ignore[attr-defined]
    ctx = pool._ssl_context
    assert ctx.keylog_filename is None and ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname and ctx.get_ca_certs()  # certifi's roots, not the env's


def test_offline_login_does_not_end_logins_for_the_server(tmp_path: Path) -> None:
    now, online = [0.0], [False]
    portal = FakePortal()

    def handler(req: httpx.Request) -> httpx.Response:
        if not online[0]:
            raise httpx.ConnectError("offline", request=req)
        return portal(req)

    guard = LoginGuard(tmp_path / "guard")
    c = CloudClient(
        Config(reference="12345678"),
        transport=httpx.MockTransport(handler),
        password=lambda: PASSWORD,
        store=MemoryStore(),  # type: ignore[arg-type]
        guard=guard,
        clock=lambda: now[0],
    )
    with pytest.raises(Unreachable):
        c.get("uptime")
    assert not guard.path.exists()
    online[0], now[0] = True, 61.0
    assert c.get("uptime")["os"] == 10 and portal.logins == 1


def test_guard_is_written_before_the_password_goes_out(tmp_path: Path) -> None:
    guard = LoginGuard(tmp_path / "guard")

    def handler(req: httpx.Request) -> httpx.Response:
        assert guard.path.exists()  # already counted while the request is in flight
        raise KeyboardInterrupt

    c = CloudClient(
        Config(reference="12345678"),
        transport=httpx.MockTransport(handler),
        password=lambda: PASSWORD,
        store=MemoryStore(),  # type: ignore[arg-type]
        guard=guard,
    )
    with pytest.raises(KeyboardInterrupt):
        c.login()
    with pytest.raises(LoginBlocked, match="rejected or cut off"):
        guard.check()


def test_unwritable_guard_blocks_the_login(tmp_path: Path) -> None:
    portal = FakePortal()
    state = tmp_path / "state"
    state.mkdir(mode=0o500)
    try:
        c = CloudClient(
            Config(reference="12345678"),
            transport=httpx.MockTransport(portal),
            password=lambda: PASSWORD,
            store=MemoryStore(),  # type: ignore[arg-type]
            guard=LoginGuard(state / "guard"),
        )
        with pytest.raises(LoginBlocked, match="cannot write"):
            c.get("uptime")
    finally:
        state.chmod(0o700)
    assert portal.logins == 0
