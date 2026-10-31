"""Public and logged-in portal pages."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from .. import fixtures
from ..deps import current_session, parse_int_id, templates
from ..errors import nginx_error

router = APIRouter()


@router.get("/")
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"session": current_session(request)})


@router.get("/search")
def search(request: Request, q: str = ""):
    # q is reflected ONLY through Jinja2 autoescaping. No real search runs.
    return templates.TemplateResponse(
        request, "search.html", {"q": q[:200], "session": current_session(request)}
    )


@router.get("/portal")
def portal(request: Request):
    sess = current_session(request)
    if sess is None:
        return RedirectResponse("/login", status_code=302)
    shipments = [s for s in fixtures.SHIPMENTS.values() if s["owner_id"] == sess.user_id]
    user = fixtures.USERS[sess.user_id]
    return templates.TemplateResponse(
        request, "portal.html", {"session": sess, "user": user, "shipments": shipments}
    )


@router.get("/portal/shipments/{shipment_id}")
def shipment(request: Request, shipment_id: str):
    sess = current_session(request)
    if sess is None:
        return RedirectResponse("/login", status_code=302)
    sid = parse_int_id(shipment_id)
    record = fixtures.SHIPMENTS.get(sid) if sid is not None else None
    if record is None:
        return nginx_error(404)
    return templates.TemplateResponse(request, "shipment.html", {"session": sess, "s": record})
