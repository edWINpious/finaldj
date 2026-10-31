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


@dataclass(frozen=True)
class Settings:
    sensor_id: str = "web-01"
    port: int = 8080
    # Synthetic decoy credential: intentionally guessable, protects nothing real.
    decoy_user: str = "j.miller"
    decoy_password: str = "Halden#Spring26"
    health_allowed: tuple[Network, ...] = field(
        default_factory=lambda: _parse_cidrs("127.0.0.1/32")
    )
    collector_url: str = "http://collector:8000/api/events"
    max_upload_bytes: int = 1024 * 1024
    max_sessions: int = 5000

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ
        default = cls()
        return cls(
            sensor_id=env.get("SENSOR_ID", default.sensor_id),
            port=int(env.get("WEB_DECOY_PORT", default.port)),
            decoy_user=env.get("DECOY_USER", default.decoy_user),
            decoy_password=env.get("DECOY_PASSWORD", default.decoy_password),
            health_allowed=_parse_cidrs(
                env.get("HEALTH_ALLOWED_CIDRS", "127.0.0.1/32")
            ),
            collector_url=env.get("COLLECTOR_URL", default.collector_url),
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
