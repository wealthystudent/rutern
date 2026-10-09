"""HTTP sends that read at most MAX_BODY bytes of a response.

The local API is plain HTTP on the LAN, so anyone able to intercept it could
answer with an endless body; the cloud gets the same cap.

Clients ignore the environment (proxies, CA bundles, key logs): whoever sets
env for a command could otherwise route the password through a proxy that
can read it.
"""

from __future__ import annotations

import ssl

import certifi
import httpx

from rutern.errors import ApiError

MAX_BODY = 2 * 1024 * 1024


def tls_context() -> ssl.SSLContext:
    """Certificates checked against certifi's roots. SSL_CERT_FILE and SSL_CERT_DIR
    cannot swap in another CA, and SSLKEYLOGFILE cannot record the session keys."""
    ctx = ssl.create_default_context(cafile=certifi.where())
    ctx.keylog_filename = None  # type: ignore[assignment]
    return ctx


def send(client: httpx.Client, request: httpx.Request) -> httpx.Response:
    """Send and read the body, refusing anything over MAX_BODY (after decompression)."""
    r = client.send(request, stream=True)
    try:
        declared = r.headers.get("content-length", "")
        if declared.isascii() and declared.isdigit() and int(declared) > MAX_BODY:
            raise ApiError("response is larger than rutern accepts")
        body = bytearray()
        for chunk in r.iter_bytes():
            body += chunk
            if len(body) > MAX_BODY:
                raise ApiError("response is larger than rutern accepts")
    finally:
        r.close()
    # The body is already decoded, so drop the headers that describe the wire form.
    headers = [
        (k, v)
        for k, v in r.headers.multi_items()
        if k not in ("content-encoding", "content-length")
    ]
    return httpx.Response(r.status_code, headers=headers, content=bytes(body), request=request)
