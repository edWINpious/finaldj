"""Rule catalogue: one place for labels, OWASP categories, ATT&CK candidates.

ATT&CK discipline (HANDOFF §10, PLAN §9 decision 6):
- Every ATT&CK entry is status "candidate"; the collector's alert layer decides.
- T1190 only for SQLi-like input (an exploitation ATTEMPT against a public app).
- T1505.003 is NEVER emitted: a webshell path probe or upload is not a deployed webshell.
- Rules without a defensible technique carry an empty `attack` list (OWASP only).
"""

from __future__ import annotations

from typing import Any

NO_SUCCESS = "attempt observed; no evidence of success"

A01 = "A01:2021-Broken Access Control"
A03 = "A03:2021-Injection"
A04 = "A04:2021-Insecure Design"
A05 = "A05:2021-Security Misconfiguration"
A07 = "A07:2021-Identification and Authentication Failures"
A10 = "A10:2021-Server-Side Request Forgery"

RULES: dict[str, dict[str, Any]] = {
    "W-ENUM-01": {"label": "enum:sensitive_path", "category": "probe_detected", "owasp": A05,
                  "confidence": "low", "attack": []},
    "W-ENUM-02": {"label": "enum:route_scan", "category": "behavior_detected", "owasp": A05,
                  "confidence": "medium",
                  "attack": [("T1595.003", "medium", "many distinct missing/forbidden paths from one source: "
                                                     "wordlist scanning pattern")]},
    "W-AUTH-01": {"label": "auth:failed", "category": "behavior_detected", "owasp": A07,
                  "confidence": "low", "attack": []},
    "W-AUTH-02": {"label": "auth:bruteforce", "category": "behavior_detected", "owasp": A07,
                  "confidence": "medium",
                  "attack": [("T1110.001", None, "repeated failed passwords for one username from one source")]},
    "W-AUTH-03": {"label": "auth:spraying", "category": "behavior_detected", "owasp": A07,
                  "confidence": "medium",
                  "attack": [("T1110.003", "medium", "few attempts each across many usernames from one source")]},
    "W-AUTH-04": {"label": "auth:decoy_success", "category": "decoy_interaction", "owasp": A07,
                  "confidence": "high", "attack": []},
    "W-SQLI-01": {"label": "probe:sqli", "category": "probe_detected", "owasp": A03,
                  "confidence": "medium",
                  "attack": [("T1190", "medium", "SQL injection-like input to a public-facing application; "
                                                 + NO_SUCCESS)]},
    "W-XSS-01": {"label": "probe:xss", "category": "probe_detected", "owasp": A03,
                 "confidence": "medium", "attack": []},
    "W-PATH-01": {"label": "probe:path_traversal", "category": "probe_detected", "owasp": A01,
                  "confidence": "medium", "attack": []},
    "W-SSRF-01": {"label": "probe:ssrf", "category": "probe_detected", "owasp": A10,
                  "confidence": "medium", "attack": []},
    "W-UPL-01": {"label": "upload:suspicious", "category": "probe_detected", "owasp": A04,
                 "confidence": "medium", "attack": []},
    "W-IDOR-01": {"label": "authz:idor_attempt", "category": "probe_detected", "owasp": A01,
                  "confidence": "medium", "attack": []},
    "W-SHELL-01": {"label": "probe:webshell_path", "category": "probe_detected", "owasp": A05,
                   "confidence": "low", "attack": []},
}


def make(rule: str, field: str, rationale: str, confidence: str | None = None,
         attack_confidence: str | None = None) -> dict[str, Any]:
    """Build a detection dict. Never pass request VALUES in `rationale`; describe them."""
    spec = RULES[rule]
    conf = confidence or spec["confidence"]
    return {
        "rule": rule,
        "category": spec["category"],
        "label": spec["label"],
        "field": field,
        "owasp": spec["owasp"],
        "confidence": conf,
        "rationale": rationale,
        "attack": [
            {"technique": tech, "status": "candidate", "rationale": why,
             "confidence": attack_confidence or tconf or conf}
            for tech, tconf, why in spec["attack"]
        ],
    }
