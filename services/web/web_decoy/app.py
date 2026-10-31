"""FastAPI application factory for the Halden Freight decoy."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import Settings
from .detection import default_detectors
from .errors import SECURITY_HEADERS, nginx_error
from .routes import api, auth, health, pages, traps
from .sessions import SessionStore
from .telemetry.emitter import Emitter
from .telemetry.middleware import TelemetryMiddleware


def create_app(settings: Settings | None = None, emitter: Emitter | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    emitter = emitter or Emitter(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await emitter.start()
        try:
            yield
        finally:
            await emitter.stop()

    # docs/redoc/openapi disabled: they would reveal FastAPI and the real attack surface.
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.settings = settings
    app.state.sessions = SessionStore(settings.max_sessions)
    app.state.started_at = time.monotonic()
    app.state.emitter = emitter
    app.state.detectors = default_detectors(settings)   # signatures + per-source behaviour
    app.state.telemetry_errors = 0

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers[k] = v
        return response

    # Outermost user middleware: sees every request, including ones rejected for size.
    app.add_middleware(TelemetryMiddleware)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        return nginx_error(exc.status_code if exc.status_code in (400, 401, 403, 404, 405, 413) else 500)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        return nginx_error(400)  # never FastAPI's JSON 422

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        resp = nginx_error(500)  # never a Python traceback or Starlette's plain-text 500
        resp.headers.update(SECURITY_HEADERS)
        return resp

    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
    for r in (pages.router, auth.router, api.router, traps.router, health.router):
        app.include_router(r)
    return app


app = create_app()
