"""Shared request helpers."""

from __future__ import annotations

from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

from .sessions import COOKIE_NAME, Session

TEMPLATES_DIR = Path(__file__).parent / "templates"

# Jinja2Templates enables autoescaping for .html templates. Templates must never use |safe.
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def current_session(request: Request) -> Session | None:
    return request.app.state.sessions.get(request.cookies.get(COOKIE_NAME))


def parse_int_id(raw: str) -> int | None:
    """Parse a numeric path id without letting FastAPI emit a JSON 422 (fingerprint)."""
    if not raw.isdigit() or len(raw) > 9:
        return None
    return int(raw)
