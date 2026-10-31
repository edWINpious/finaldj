"""Environment-driven configuration. All defaults are synthetic lab values."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _parse_cidrs(raw: str) -> tuple[Network, ...]:
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            nets.append(ipaddress.ip_network(part, strict=False))
    return tuple(nets)


def _bool(raw: str | None, default: bool) -> bool:
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    sensor_id: str = "web-01"
    port: int = 8080
    # Synthetic decoy credential: intentionally guessable, protects nothing real.
    decoy_user: str = "j.miller"
    decoy_password: str = "Halden#Spring26"
    # Single hosts only (PLAN §0.1 P9): published-port traffic arrives from the lab gateway.
    health_allowed: tuple[Network, ...] = field(default_factory=lambda: _parse_cidrs("127.0.0.1/32"))
    simulator_cidrs: tuple[Network, ...] = field(default_factory=lambda: _parse_cidrs("172.28.0.50/32"))
    campaign_header: str = "x-campaign-id"
    trust_proxy: bool = False

    # Telemetry. Empty collector_url = JSONL only (no network delivery).
    collector_url: str = "http://collector:8000/api/events"
    event_log_path: str = "data/web-events.jsonl"
    spool_path: str = "data/web-spool.jsonl"
    queue_capacity: int = 10_000
    batch_size: int = 50
    flush_interval_s: float = 1.0
    post_timeout_s: float = 2.0
    max_log_bytes: int = 50 * 1024 * 1024
    max_spool_bytes: int = 50 * 1024 * 1024

    # Request limits.
    max_body_bytes: int = 64 * 1024              # all non-upload requests
    # file + overhead must stay <= Starlette's 1 MiB spool threshold, so an upload
    # part is never spilled to a temp file (security fix F5).
    max_upload_bytes: int = 960 * 1024           # the uploaded file itself
    multipart_overhead_bytes: int = 64 * 1024    # boundaries + headers around the file
    body_timeout_s: float = 15.0                 # whole request body must arrive within this (F1)
    max_sessions: int = 5000

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ
        d = cls()
        return cls(
            sensor_id=env.get("SENSOR_ID", d.sensor_id),
            port=int(env.get("WEB_DECOY_PORT", d.port)),
            decoy_user=env.get("DECOY_USER", d.decoy_user),
            decoy_password=env.get("DECOY_PASSWORD", d.decoy_password),
            health_allowed=_parse_cidrs(env.get("HEALTH_ALLOWED_CIDRS", "127.0.0.1/32")),
            simulator_cidrs=_parse_cidrs(env.get("SIMULATOR_SOURCE_CIDRS", "172.28.0.50/32")),
            campaign_header=env.get("CAMPAIGN_HEADER", d.campaign_header).lower(),
            trust_proxy=_bool(env.get("TRUST_PROXY"), d.trust_proxy),
            collector_url=env.get("COLLECTOR_URL", d.collector_url),
            event_log_path=env.get("EVENT_LOG_PATH", d.event_log_path),
            spool_path=env.get("SPOOL_PATH", d.spool_path),
        )


def ip_in(host: str | None, networks: tuple[Network, ...]) -> bool:
    """True only if host is a valid IP inside one of the networks. Non-IPs are rejected."""
    if not host:
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(addr in net for net in networks)
