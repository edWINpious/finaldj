"""Detailed health for the lab/integrator only. Everyone else gets the normal site 404."""

from __future__ import annotations

import time

from fastapi import APIRouter, Request

from .. import __version__
from ..config import ip_in
from ..errors import nginx_error

router = APIRouter()


@router.get("/health")
def health(request: Request):
    settings = request.app.state.settings
    host = request.client.host if request.client else None
    if not ip_in(host, settings.health_allowed):
        return nginx_error(404)  # byte-identical to an unknown path
    # Telemetry fields are placeholders until Phase 3 wires the emitter.
    return {
        "status": "ok",
        "sensor_id": settings.sensor_id,
        "service": "web",
        "version": __version__,
        "uptime_s": int(time.monotonic() - request.app.state.started_at),
        "collector": {"url": settings.collector_url, "reachable": None,
                      "last_success": None, "last_error": None},
        "queue": {"depth": 0, "capacity": 10000, "dropped_events": 0},
        "spool": {"pending_events": 0},
        "events_emitted_total": 0,
        "detections_total": {},
        "event_log_path": None,
        "active_sessions": len(request.app.state.sessions),
    }
