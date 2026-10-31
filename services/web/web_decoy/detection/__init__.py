"""Safe, signature- and behaviour-based classification (PLAN.md §5).

Nothing here evaluates, executes, opens or fetches request input. Every
detection describes an ATTEMPT that was observed; none claims success.
"""

from __future__ import annotations

from ..config import Settings
from .behavior import BehaviorEngine
from .signatures import detect_signatures


def default_detectors(settings: Settings) -> list:
    engine = BehaviorEngine()
    return [detect_signatures, engine.detect]
