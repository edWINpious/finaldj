"""Bait routes: backup/config, fake downloads, upload. Nothing here touches the filesystem."""

from __future__ import annotations

import hashlib

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from starlette.datastructures import UploadFile as StarletteUploadFile

from .. import fixtures
from ..deps import current_session, templates
from ..errors import nginx_error
from ..telemetry import redact

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


# Magic-byte signatures -> label. Content is classified, never executed or stored.
_MAGIC = (
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF8", "image/gif"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x7fELF", "application/x-elf"),
    (b"MZ", "application/x-msdownload"),
    (b"#!", "text/x-script"),
    (b"<?php", "application/x-php"),
    (b"<%", "text/x-server-page"),
)


def _sniff(head: bytes) -> str:
    stripped = head.lstrip()
    for sig, label in _MAGIC:
        if head.startswith(sig) or stripped.startswith(sig):
            return label
    return "application/octet-stream"


def _safe_filename(raw: str | None) -> str | None:
    if not raw:
        return None
    base = raw.replace("\\", "/").rsplit("/", 1)[-1]  # basename for "/" and "\\" style paths
    return redact.safe_value(base, 255) or None


@router.post("/upload")
async def upload(request: Request):
    """Parse one file, record metadata (name, size, sha256, sniffed type), discard content.

    The telemetry middleware has already capped the whole body at
    max_upload_bytes + multipart overhead, so the part stays in memory (Starlette
    spools to disk only above 1 MiB). Nothing is stored, served or executed."""
    cap = request.app.state.settings.max_upload_bytes
    form = await request.form(max_files=1, max_fields=5, max_part_size=cap)
    part = next((v for v in form.values() if isinstance(v, StarletteUploadFile)), None)
    if part is None:
        request.state.telemetry = {"action": "upload_attempt"}
        return JSONResponse({"error": "no file"}, status_code=400)

    digest = hashlib.sha256()
    size = 0
    head = b""
    too_big = False
    while chunk := await part.read(65536):
        if not head:
            head = chunk[:16]
        size += len(chunk)
        if size > cap:
            too_big = True
            break
        digest.update(chunk)
    await part.close()  # content discarded here

    file_name = _safe_filename(part.filename)
    meta = {
        "file_name": file_name,
        "declared_type": redact.safe_value(part.content_type or "", 100) or None,
        "sniffed_type": _sniff(head),
        "size_bytes": size,
        "sha256": None if too_big else digest.hexdigest(),
        "stored": False,
    }
    request.state.telemetry = {"upload": meta, "file_name": file_name,
                               "outcome": "blocked" if too_big else "observed"}
    if too_big:
        return nginx_error(413)
    return JSONResponse({"status": "received", "message": "File queued for review."})
