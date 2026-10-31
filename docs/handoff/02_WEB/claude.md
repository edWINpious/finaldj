# Claude Code Instructions --- Web Module

You are implementing only the web honeypot module. Read
`../00_MASTER/TEAM_INTEGRATION_CONTEXT.md` and this folder's
`context.md` first.

## Work in phases; do not one-shot the whole module

### Phase 1 --- Inspect and plan

-   Inspect repository and existing backend conventions.
-   Confirm shared schema, collector URL and port allocation with
    integrator.
-   Produce `PLAN.md` listing routes, middleware, event types, safety
    controls and tests.
-   Stop for human review before implementation.

### Phase 2 --- Build realistic decoy

-   Create FastAPI app with a convincing synthetic login page and fake
    application routes.
-   Add `/admin`, `/backup`, `/config`, `/api` and synthetic business
    pages.
-   Use fake users and synthetic records only.
-   Do not create a real admin backdoor or use real secrets.
-   Add a health endpoint.

### Phase 3 --- Safe telemetry

-   Add middleware for timestamp, source IP, method, path, status,
    user-agent and synthetic session/campaign IDs.
-   Log structured JSON.
-   Redact password fields, cookies, authorization headers and tokens.
-   Capture upload metadata safely with size limits; do not execute or
    serve uploaded content.
-   Normalize events to the agreed schema and POST to collector; include
    JSONL fallback.

### Phase 4 --- Detection logic

-   Implement P0 route enumeration, login failure thresholds, SQLi-like,
    XSS-like and path traversal-like probe detection.
-   P1: SSRF-like input, inert upload metadata, synthetic IDOR and
    webshell path probes.
-   Detection must be safe signature/behavior analysis only.
-   Never evaluate submitted content, access arbitrary files or make
    outbound SSRF requests.
-   Distinguish `probe_detected` from successful exploitation.

### Phase 5 --- Integration and tests

-   Add deterministic local tests for each P0 scenario.
-   Confirm normalized events appear in SOC dashboard.
-   Document mappings, rationale and confidence; leave technique
    unmapped if unsupported.
-   Update `PROJECT_STATUS.md` with status and test evidence.

## Acceptance criteria

-   Web decoy starts with documented commands.
-   P0 routes and login events are captured.
-   Suspicious inputs are logged safely without execution.
-   Passwords, cookies and tokens are redacted.
-   Normalized events reach collector and dashboard.
-   Upload/SSRF/path traversal controls are tested.
-   Network isolation and synthetic-data use are documented.
-   Tests pass.

## Working rules

-   Do not implement SSH, database, dashboard or attacker runner.
-   Do not change shared schema independently.
-   No real exploit execution or public-target testing.
-   At each phase report changed files, tests, blockers and next step;
    wait for human approval before continuing.
