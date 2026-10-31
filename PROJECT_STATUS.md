# PROJECT_STATUS.md — Web Module

Statuses: `NOT STARTED`, `IN PROGRESS`, `IMPLEMENTED`, `TESTED`, `BLOCKED`.
`TESTED` requires evidence (command, result, event ID, log or screenshot). Code existing is not evidence.

| Phase / objective | Status | Evidence / notes |
|---|---|---|
| Phase 1 — Inspect and plan (`PLAN.md`) | IMPLEMENTED | Decisions recorded in PLAN.md §9; problems P1–P9 resolved in design (PLAN.md §0.1; P9 found during Phase 2); `docs/INTEGRATOR_NOTES.md` written. A plan has no test evidence, so not TESTED |
| Phase 2 — Realistic decoy (routes, login, fixtures, health, container) | TESTED | 2026-10-31: `pytest -q` → 86 passed on Python 3.12.3 (venv) and inside image `halden-web-decoy:dev` (Python 3.12.16). Mutation check: 6 injected vulns (traversal via open/pathlib, health open, `|safe` XSS, docs re-enabled, logout not invalidating) each caught. Container: `docker compose -f docker-compose.web.yml up` → healthy; port `127.0.0.1:8080` only; uid 10001, read-only rootfs, cap_drop ALL; host curl: `/`200 `/admin`302 `/backup`403 `/docs`404 `/health`404 (in-container `/health` → ok) |
| Phase 3 — Safe telemetry (middleware, redaction, emitter, JSONL fallback) | NOT STARTED | |
| Phase 4 — Detection logic (P0, then P1) | NOT STARTED | |
| Phase 5 — Integration, docs, demo script, isolation proof | NOT STARTED | Port and batch format decided; still need integrator's lab subnet, schema acceptance (INTEGRATOR_NOTES §7) |
