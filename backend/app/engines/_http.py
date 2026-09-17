"""One pinned HTTP request.

Deliberately built on ``http.client`` rather than a convenience client, because
the one thing that must be visible in the code is exactly where the bytes go:

* the socket connects to the **pinned IP**, never to the hostname, so a name
  that re-resolves after authorization cannot move the request;
* the TLS handshake still presents the **hostname** as SNI, and the request
  still carries it in ``Host``, so name-based virtual hosts behave normally;
* the body is read under a byte cap and the connection is closed, because a
  target that streams forever must not be able to fill the worker's disk;
* there is no redirect following here at all. The caller sees the 3xx and
  decides - and the only redirect that may be followed is a same-host one,
  handled by re-entering this function with a new pinned request.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field

from app.engines.context import EngineError, TargetView

USER_AGENT = "Valtros/0.1 (+local control validation)"
CONNECT_TIMEOUT_SECONDS = 10.0


@dataclass(slots=True)
class HttpResponse:
    status: int
    reason: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    http_version: str = "1.1"
    elapsed_ms: int = 0
    body_truncated: bool = False
    url: str = ""

    def header(self, name: str) -> str | None:
        """First value of ``name``, case-insensitively."""
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return None

    def all_headers(self, name: str) -> list[str]:
        wanted = name.lower()
        return [value for key, value in self.headers if key.lower() == wanted]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def redirect_to(self) -> str | None:
        if 300 <= self.status < 400:
            return self.header("location")
        return None


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to one address, handshake as another."""

    def __init__(self, ip: str, hostname: str, port: int, timeout: float) -> None:
        context = ssl.create_default_context()
        # The lab and most internal targets use self-signed certificates. A
        # verification failure is a *fact* the tls_config engine reports; it
        # must not stop this engine from reporting headers.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        super().__init__(host=hostname, port=port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self) -> None:  # type: ignore[override]
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Plain HTTP: connect to the pinned address, present the hostname in Host."""

    def __init__(self, ip: str, hostname: str, port: int, timeout: float) -> None:
        super().__init__(host=hostname, port=port, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:  # type: ignore[override]
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


def scheme_for(target: TargetView, default: str = "http") -> str:
    """Pick http or https from the port, since the target record carries no scheme."""
    if target.port in (443, 8443, 9443):
        return "https"
    return default


def fetch(
    target: TargetView,
    *,
    scheme: str,
    path: str,
    method: str = "GET",
    max_body_bytes: int = 512 * 1024,
    timeout_seconds: float = CONNECT_TIMEOUT_SECONDS,
    extra_headers: dict[str, str] | None = None,
) -> HttpResponse:
    """Issue one request to the pinned address and return what came back."""
    if method not in ("GET", "HEAD"):
        raise ValueError(f"{method} is not an allowed probe method")

    default_port = 443 if scheme == "https" else 80
    authority = target.authority(default_port=default_port)

    headers = {
        "Host": authority,
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Connection": "close",
    }
    if extra_headers:
        headers.update(extra_headers)

    if scheme == "https":
        connection: http.client.HTTPConnection = _PinnedHTTPSConnection(
            target.ip, target.hostname, target.port or 443, timeout_seconds
        )
    else:
        connection = _PinnedHTTPConnection(
            target.ip, target.hostname, target.port or 80, timeout_seconds
        )

    started = time.monotonic()
    try:
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        raw = response.read(max_body_bytes + 1)
    except ssl.SSLError as exc:
        raise EngineError(f"TLS handshake with {target.ip}:{target.port} failed: {exc}") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise EngineError(f"{method} {path} against {target.ip}:{target.port} failed: {exc}") from exc
    finally:
        connection.close()

    elapsed_ms = int((time.monotonic() - started) * 1000)
    return HttpResponse(
        status=response.status,
        reason=response.reason or "",
        headers=[(str(k), str(v)) for k, v in response.getheaders()],
        body=raw[:max_body_bytes],
        http_version={10: "1.0", 11: "1.1", 20: "2"}.get(response.version, "1.1"),
        elapsed_ms=elapsed_ms,
        body_truncated=len(raw) > max_body_bytes,
        url=f"{scheme}://{authority}{path}",
    )
