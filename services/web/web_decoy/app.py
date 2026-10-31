"""FastAPI application factory for the Halden Freight decoy."""

from __future__ import annotations

import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import Settings
from .errors import nginx_error
from .routes import api, auth, health, pages, traps
from .sessions import SessionStore

SECURITY_HEADERS = {
    "Server": "nginx",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'none'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
}


def create_app(settings: Settings | None = None) -> FastAPI:
    # docs/redoc/openapi disabled: they would reveal FastAPI and the real attack surface.
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings or Settings.from_env()
    app.state.sessions = SessionStore(app.state.settings.max_sessions)
    app.state.started_at = time.monotonic()

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers[k] = v
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        return nginx_error(exc.status_code if exc.status_code in (400, 401, 403, 404, 405, 413) else 500)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        return nginx_error(400)  # never FastAPI's JSON 422

    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
    for r in (pages.router, auth.router, api.router, traps.router, health.router):
        app.include_router(r)
    return app


app = create_app()
