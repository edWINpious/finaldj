"""Production entrypoint: uvicorn with a header-completion deadline (security fix F1).

    python -m web_decoy.serve                      (container: 0.0.0.0:8080)
    WEB_DECOY_HOST=127.0.0.1 WEB_DECOY_PORT=8081 python -m web_decoy.serve   (local)

ALWAYS start the decoy this way, locally too. Plain `uvicorn web_decoy.app:app`
trusts X-Forwarded-For from 127.0.0.1 by default and rewrites the client IP
before the app sees it, so a faked header would be logged as the source IP
(PLAN P13).

Why not plain `uvicorn ...`: uvicorn has no deadline for receiving request headers.
Its keep-alive timer is cancelled on every received byte, so a client trickling
header bytes holds a connection (and a --limit-concurrency slot) forever. Enough
such clients make the decoy answer 503 to everyone, and because the app never
runs, nothing is recorded. `HeaderDeadlineH11Protocol` closes any connection whose
request headers are not complete within HEADER_TIMEOUT_S of the first wait,
however slowly the bytes arrive. The request BODY deadline lives in the telemetry
middleware (Settings.body_timeout_s).
"""

from __future__ import annotations

import os

import h11
import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol

HEADER_TIMEOUT_S = float(os.environ.get("HEADER_TIMEOUT_S", "10"))


class HeaderDeadlineH11Protocol(H11Protocol):
    _header_deadline = None

    def connection_made(self, transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        self._arm_header_deadline()

    def data_received(self, data: bytes) -> None:
        super().data_received(data)
        if self.conn.their_state is h11.IDLE:
            self._arm_header_deadline()      # still waiting for (the next request's) headers
        else:
            self._cancel_header_deadline()   # headers complete; body deadline is the app's job

    def connection_lost(self, exc) -> None:
        self._cancel_header_deadline()
        super().connection_lost(exc)

    def _arm_header_deadline(self) -> None:
        if self._header_deadline is None:     # absolute: NOT reset by further bytes
            self._header_deadline = self.loop.call_later(HEADER_TIMEOUT_S, self._header_timeout)

    def _cancel_header_deadline(self) -> None:
        if self._header_deadline is not None:
            self._header_deadline.cancel()
            self._header_deadline = None

    def _header_timeout(self) -> None:
        self._header_deadline = None
        if self.conn.their_state is h11.IDLE and not self.transport.is_closing():
            self.transport.close()


def build_config(host: str | None = None, port: int | None = None, **overrides) -> uvicorn.Config:
    """The one hardened server configuration (also used by the tests)."""
    options = dict(
        app="web_decoy.app:create_app",
        factory=True,               # settings read from env at start, not at import
        host=host or os.environ.get("WEB_DECOY_HOST", "0.0.0.0"),
        port=int(os.environ.get("WEB_DECOY_PORT", "8080")) if port is None else port,
        http=HeaderDeadlineH11Protocol,
        proxy_headers=False,        # never trust X-Forwarded-For (PLAN P2, P13)
        server_header=False,        # app sets "Server: nginx"
        access_log=False,           # uvicorn's log would hold unredacted query strings
        limit_concurrency=200,
        timeout_keep_alive=5,
    )
    options.update(overrides)
    return uvicorn.Config(**options)


def main() -> None:
    uvicorn.Server(build_config()).run()


if __name__ == "__main__":
    main()
