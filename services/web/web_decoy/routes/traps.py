"""Bait routes: backup/config, fake downloads, upload. Nothing here touches the filesystem."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from .. import fixtures
from ..deps import current_session, templates
from ..errors import nginx_error

router = APIRouter()


@router.get("/backup")
@router.get("/backup/")
@router.get("/config")
def forbidden():
    return nginx_error(403)


@router.get("/download")
def download(file: str = ""):
    # Exact dict lookup only. Traversal strings simply miss and return 404.
    entry = fixtures.FAKE_FILES.get(file)
    if entry is None:
        return nginx_error(404)
    media_type, body = entry  # `file` is now known to be one of our own fixed keys
    return Response(
        body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{file}"'},
    )


@router.get("/upload")
def upload_page(request: Request):
    return templates.TemplateResponse(request, "upload.html", {"session": current_session(request)})


@router.post("/upload")
async def upload(request: Request):
    """Read the body under a hard cap, then discard it. Content is never stored,
    served or executed. Metadata capture (size/sha256/type) arrives in Phase 3."""
    cap = request.app.state.settings.max_upload_bytes
    declared = request.headers.get("content-length")
    if declared is not None:
        if not declared.isdigit() or int(declared) > cap:
            return nginx_error(413)
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > cap:  # also catches chunked bodies with no Content-Length
            return nginx_error(413)
    return JSONResponse({"status": "received", "message": "File queued for review."})
