# PLAN.md — Web Honeypot Module (Phase 1: Inspect and Plan)

Status: **APPROVED with decisions recorded in §9. All Phase 1 problems resolved
(see §0.1). No implementation has started; Phase 2 awaits go-ahead.**

Sources: `HANDOFF_FINAL.md` (authoritative), `docs/TEAM_INTEGRATION_CONTEXT.md`,
`docs/handoff/02_WEB/context.md`, `docs/handoff/02_WEB/claude.md`.

Scope: **web decoy only.** No SSH, database, collector, dashboard or attacker
simulator code. The shared event schema belongs to the integrator. This module
uses a read-only copy of it and never changes it on its own.

---

## 0. Phase 1 inspection findings

| Item | Finding |
|---|---|
| Repo | `RugvedHinge1/PS4---DJS` is the web owner's own repo. It contained only the vendored `security-audit` skill. There are no backend conventions to follow yet. |
| Python | Spec target **3.12**. Verified: `python3.12` = 3.12.3 on the dev box, and `python:3.12-slim` image (`sha256:aa943ce4…0d159`) runs 3.12.16. All tests run under 3.12; evidence comes from the container run. |
| Docker | Daemon was not running; started with `dockerd`. Docker 29.9.2 works, so container tests are possible here. |
| Shared schema | Taken from `HANDOFF_FINAL.md §6`. There is no `collector/schema.py` to import yet. |
| Collector URL / ports | Confirmed by the web owner: port 8080, batch ingest (see §1). |

### 0.1 Problems found in Phase 1 and how each is resolved

| # | Problem | Resolution | Owner |
|---|---|---|---|
| P1 | Anyone can forge `X-Campaign-Id`, which would merge real traffic into a demo campaign | Accept it only with a valid format **and** a source in `SIMULATOR_SOURCE_CIDRS`; otherwise `null` + tag `untrusted_campaign_header` (§4) | Web (here) |
| P2 | `X-Forwarded-For` lets anyone fake their source IP | Ignored unless `TRUST_PROXY=1` (§4) | Web (here) |
| P3 | Raw attacker strings in evidence can run as XSS in the Streamlit dashboard | Web side: evidence is bounded and control-char-stripped, and HTML-looking values get tag `contains_markup`. Dashboard side: must never use `unsafe_allow_html` on event data — written up in `docs/INTEGRATOR_NOTES.md` §3 | Web + integrator |
| P4 | FastAPI `/docs` and `/openapi.json` would reveal the decoy | Disabled; test asserts 404 (§3.4) | Web (here) |
| P5 | Redacting the password before detection would hide SQLi in the password field | Detection runs on the in-memory value first, then redaction; only rule + field name are stored (§4.1) | Web (here) |
| P6 | The schema has no field for detection results | Agreed: `raw_evidence_redacted.detections[]` + `tags`, with a fixed sub-shape documented in `docs/INTEGRATOR_NOTES.md` §2 | Web + integrator |
| P7 | Dev Python (3.13) ≠ spec (3.12) | Use `python3.12` locally and the pinned 3.12 image for evidence runs | Web (here) |
| P8 | A detailed `/health` on the attacker-facing port shows it's a honeypot (new conflict from decision Q5) | Detailed JSON only for sources in `HEALTH_ALLOWED_CIDRS`. Everyone else gets the site's normal 404 (§3.1, §6) | Web (here) |
| P12 | *(found in Phase 5 by a control test)* `internal: true` blocks the internet, but containers on that network could still reach **services listening on the Docker host** through the bridge gateway (`172.28.0.1`). A compromised decoy could reach dev servers, databases or a published collector port on the host | `com.docker.network.bridge.inhibit_ipv4: "true"` on `lab_net`: the host gets no address on that bridge. Verified: host listener CONNECTED before, TimeoutError after; lab peers still work. `isolation_check.py` adds a "no default route" check | Web + integrator (team compose must copy this) |
| P11 | *(found in Phase 4 by a detection test)* Detection labels were passed through secret redaction, so `auth:failed` matched the `auth: <secret>` pattern and became `auth:[REDACTED]`. Every brute-force and spraying tag would have reached the dashboard garbled | Fixed-vocabulary fields (rule, label, OWASP, ATT&CK ID) are checked against a strict charset instead of redacted; free text (rationale, field) is still redacted. Regression tests added | Web (here) |
| P10 | *(found in Phase 3 by a redaction test)* Secret patterns began with `\b`, so a secret glued to other text (`aaaeyJ…` JWT, `mypassword=…`, `xAKIA…`) has no word boundary and **was not redacted** | Leading boundaries removed; over-redaction is the safe failure mode. Regression tests `test_secret_glued_to_text_is_redacted` | Web (here) |
| P9 | *(found in Phase 2 container test)* Requests through the published port reach the app from the Docker gateway `172.28.0.1`. A `/16` allowlist therefore trusted every host-side request, and every host-run attack shares one source IP | Allowlists default to single `/32`s (health: `127.0.0.1/32`; simulator: `172.28.0.50/32`). **The simulator must run as a container on `lab_net` with its own fixed IP**, or attacker profiles collapse onto one IP. Written up in `docs/INTEGRATOR_NOTES.md` §4 | Web + integrator + simulator owner |

---

## 1. Configuration defaults (port + batch confirmed; CIDRs adjustable)

| Setting | Default | Env var |
|---|---|---|
| Web decoy listen address (container) | `0.0.0.0:8080` | `WEB_DECOY_PORT` |
| Published port (host) | `127.0.0.1:8080` only | Compose |
| Collector ingest URL | `http://collector:8000/api/events` | `COLLECTOR_URL` |
| Sensor ID | `web-01` | `SENSOR_ID` |
| Campaign ID header | `X-Campaign-Id` | `CAMPAIGN_HEADER` |
| Collector ingest format | JSON array (batch), ≤50 events | — |
| Simulator source allowlist (for trusting campaign IDs) | `172.28.0.50/32`: the simulator container's fixed IP on `lab_net` (172.28.0.0/16). Never the whole subnet (P9) | `SIMULATOR_SOURCE_CIDRS` |
| Detailed-health allowlist | `127.0.0.1/32` (container-local). Integrator adds the collector's fixed `/32` | `HEALTH_ALLOWED_CIDRS` |
| Synthetic login | `j.miller` / value set in `.env.example`, marked as fake | `DECOY_USER`, `DECOY_PASSWORD` |
| JSONL log path | `/data/web-events.jsonl` | `EVENT_LOG_PATH` |

---

## 2. Repository layout (this module)

```text
services/web/
  README.md               # run/stop/reset, ports, env vars, limitations, 2-min demo script
  Dockerfile              # python:3.12-slim (pinned digest after smoke test), non-root
  requirements.txt        # pinned: fastapi, uvicorn, jinja2, pydantic, httpx, python-multipart
  .env.example
  web_decoy/
    app.py                # FastAPI app, route registration, security headers
    routes/               # pages.py, auth.py, api.py, traps.py (fake files/upload/preview)
    templates/            # Jinja2, autoescape ON, no inline JS
    static/               # CSS only
    fixtures.py           # synthetic users / orders / fake files (in-memory)
    telemetry/
      middleware.py       # one event per request
      redact.py           # header/field/value redaction + length bounds
      schema.py           # READ-ONLY copy of HANDOFF §6; swapped for integrator's file later
      emitter.py          # bounded async queue → POST to collector; JSONL always; spool on failure
    detection/
      normalize.py        # decode, NFKC, lowercase, length cap
      signatures.py       # SQLi / XSS / traversal / SSRF / webshell-path patterns
      behavior.py         # sliding windows: route enumeration, brute force, spraying, IDOR
      mappings.py         # rule → OWASP / ATT&CK candidate + confidence + rationale
  tests/
  samples/web-events.sample.jsonl   # redacted sample events (Phase 5)
docker-compose.web.yml    # standalone dev only; the team Compose file is the integrator's
PROJECT_STATUS.md
```

`tests/mock_collector.py` is a **test fixture only**: a tiny in-process receiver
used to check what the emitter sends. It is not a second collector, and nothing
runs it in Compose.

---

## 3. Routes

Business theme: a fictional logistics company portal, **"Halden Freight —
Partner Portal"**. Every name, user, order and file is synthetic.

### 3.1 Decoy pages (Phase 2)

| Route | Method | Response | Event type |
|---|---|---|---|
| `/` | GET | Landing page, with a link to login | `http_request` |
| `/login` | GET | Login form | `http_request` |
| `/login` | POST | Wrong credentials → re-render with a generic error (401). Synthetic credentials → session cookie, 302 to `/portal` | `authentication` |
| `/logout` | POST | Clears session, 302 to `/` | `http_request` |
| `/portal` | GET | Synthetic shipments dashboard (requires session, otherwise 302 to `/login`) | `http_request` |
| `/portal/shipments/{id}` | GET | Synthetic shipment record | `http_request` |
| `/search?q=` | GET | "No results for {q}" with q **autoescaped** | `http_request` |
| `/health` | GET | From `HEALTH_ALLOWED_CIDRS`: detailed JSON (below). Any other source: the normal site 404, and a `route_probe` event is emitted | allowlisted: not emitted |

Detailed health response (Phase 2 returns the static fields; Phase 3 fills in
the telemetry ones):

```json
{
  "status": "ok | degraded",
  "sensor_id": "web-01",
  "service": "web",
  "version": "<git sha or semver>",
  "uptime_s": 1234,
  "collector": {"url": "http://collector:8000/api/events", "reachable": true,
                "last_success": "RFC3339|null", "last_error": "string|null"},
  "queue": {"depth": 0, "capacity": 10000, "dropped_events": 0},
  "spool": {"pending_events": 0},
  "events_emitted_total": 0,
  "detections_total": {"W-SQLI-01": 0},
  "event_log_path": "/data/web-events.jsonl"
}
```
`status` is `degraded` when the collector is unreachable or events are being dropped.

### 3.2 Bait routes (P0 enumeration targets)

| Route | Response | Notes |
|---|---|---|
| `/admin`, `/admin/` | 302 → `/admin/login` | |
| `/admin/login` | Admin login form (posts to `/login` handling, `realm=admin`) | No real admin backdoor |
| `/backup`, `/backup/` | 403 "Forbidden" (nginx-style page) | |
| `/config`, `/config.php`, `/.env`, `/.git/config` | 403 / 404 | Never returns real config |
| `/api` | JSON index of fake endpoints (`/api/v1/...`) | |
| `/api/v1/users` | 401 without session; synthetic list with session | |
| `/api/v1/users/{id}` | Synthetic record. Requesting another user's id while logged in → `idor_attempt` (P1) | |
| `/api/v1/orders` | 401 / synthetic list | |

### 3.3 Trap routes (P1)

| Route | Behaviour | Safety guarantee |
|---|---|---|
| `/download?file=` | Looks up an **in-memory** dict of fake filenames. Anything else → 404 | Never touches the filesystem |
| `/api/v1/preview?url=` | Always returns `{"status":"preview unavailable"}` | The routes module imports no HTTP client, and a test blocks sockets |
| `/upload` (POST, multipart) | Streams with a 1 MiB cap (413 beyond), computes size, sha256 and magic-byte type, then **discards the content** | Nothing is stored, served or executed |
| Webshell paths: `/shell.php`, `/cmd.php`, `/c99.php`, `/wp-content/uploads/*.php`, `/uploads/*.jsp`, etc. | 404 | Path probe only; never maps to T1505.003 |
| Any unknown path | 404 via catch-all handler; event still emitted | |

### 3.4 Disabled on purpose
FastAPI `/docs`, `/redoc` and `/openapi.json` are **disabled**. They would show
the app is FastAPI and give away the decoy's real attack surface.

---

## 4. Telemetry middleware (Phase 3)

One middleware runs on every request. It builds **one canonical event per
request**:

- login POST → `authentication` (HTTP fields filled in)
- upload → `file_transfer` (`file_direction="upload"`)
- everything else → `http_request`

| Schema field | Source |
|---|---|
| `event_id` | `uuid4()` |
| `timestamp` | Request start, UTC RFC3339 |
| `sensor_id` / `service` / `destination_service` | `web-01` / `web` / `web-decoy` |
| `source_ip`, `source_port` | `request.client`. `X-Forwarded-For` is **ignored** unless `TRUST_PROXY=1`, because the header is attacker-controlled. |
| `action` | `route_probe`, `login_attempt`, `page_view`, `upload_attempt`, `probe_detected:<rule>`, … |
| `outcome` | `observed` (most requests), `failed` / `succeeded` (login), `blocked` (413 or over-limit) |
| `username` | Login form field: sanitized, ≤64 chars, control chars removed |
| `session_id` | Server-side opaque UUID tied to the cookie. **The cookie value is never logged.** |
| `campaign_id` | `X-Campaign-Id`, only if it matches `^[A-Za-z0-9_-]{1,64}$` **and** the source IP is inside `SIMULATOR_SOURCE_CIDRS`. Otherwise `null`, plus tag `untrusted_campaign_header`. |
| `request_path`, `http_method`, `http_status`, `user_agent` | From the request/response; path ≤2048 chars, UA ≤512 |
| `file_name` | Upload filename: basename only, sanitized, ≤255 chars |
| `raw_evidence_redacted` | `{query:{…}, form:{…}, headers:{allowlisted}, detections:[…], upload:{size,sha256,mime}}`, capped at 4 KiB total |
| `tags` | e.g. `probe:sqli`, `owasp:A03`, `enum:sensitive_path`, `auth:bruteforce` |
| DB-only fields (`command`, `query_type`, `database_name`, `table_names`, `rows_returned`) | `null` / `[]`. Never fabricated. |

### 4.0 What is and isn't emitted (as built in Phase 3)
- **Not emitted:** successful `GET /static/*` (page assets), and `/health` from
  `HEALTH_ALLOWED_CIDRS` (lab polling). Failed static probes and `/health` from
  anyone else **are** emitted.
- `action` values: `page_view` (2xx/3xx), `route_probe` (401/403/404/405),
  `login_attempt`, `upload_attempt`. Phase 4 adds `probe_detected:*` labels as tags.
- Telemetry `tags` vocabulary in Phase 3: `authenticated_session`, `contains_markup`,
  `untrusted_campaign_header`, `body_rejected`, plus detection labels from Phase 4.

### 4.1 Redaction rules (`redact.py`)
1. **Headers:** allowlist only (`Host`, `User-Agent`, `Accept`,
   `Content-Type`, `Content-Length`, `Referer`). `Authorization`, `Cookie`,
   `Set-Cookie`, `Proxy-Authorization`, `X-Api-Key` and every other header are
   dropped.
2. **Field names** matching `pass|pwd|secret|token|api[_-]?key|auth|session|cookie|jwt|bearer|otp`
   (case-insensitive) → value replaced by `"[REDACTED]"`.
3. **Value patterns** (redacted in any field): JWTs, `Bearer …`, AWS access
   keys, `-----BEGIN … PRIVATE KEY-----`, and inline `password=...`.
4. **Bounds:** each value ≤512 chars (truncated, with a `…[truncated N]`
   marker); at most 50 keys; at most 4 KiB of evidence in total.
5. Control characters are stripped. Output is JSON-encoded, which prevents log
   injection.

**Detection runs before redaction, in memory.** A SQLi string typed into the
password field is still detected. The event records only that the rule fired
and which field (`field: "password"`), never the value.

### 4.2 Emitter (`emitter.py`)
- Each event is appended to `EVENT_LOG_PATH` (JSONL), which is the
  structured-JSON log the spec asks for.
- Delivery: a bounded `asyncio.Queue` (10,000). A background task POSTs to
  `COLLECTOR_URL` with a 2 s timeout, as a JSON array of 50 events or less,
  flushed at least every 1 s.
- When the collector is down, events go to `/data/web-spool.jsonl`. A
  `python -m web_decoy.telemetry.replay` command resends them later.
- When the queue is full, events are dropped and `dropped_events` goes up. The
  JSONL log still keeps them. Request handling never blocks on the collector.

### 4.3 Request body limits
- A global cap of 64 KiB for non-upload bodies (413 beyond). It checks both
  `Content-Length` and the size actually streamed, so it can't be bypassed
  with chunked encoding. A non-numeric `Content-Length` → 400.
- `POST /upload`: whole body capped at 1 MiB (file) + 64 KiB (multipart
  overhead) by the middleware; the route then rejects a file part over 1 MiB.
  A file of exactly 1 MiB is accepted.
- Bodies are parsed only for `application/x-www-form-urlencoded`,
  `multipart/form-data` (upload route only) and `application/json`. Anything
  else is recorded as metadata only.

---

## 5. Detection logic (Phase 4)

These are **signature and behaviour classifiers only.** Nothing submitted is
ever evaluated, executed, opened or fetched. Every detection produces
`{rule, category, owasp, attack_candidates[], confidence, rationale, field}`
inside `raw_evidence_redacted.detections`.

### 5.1 Normalization
URL-decode up to twice (catches double encoding), Unicode NFKC, lowercase,
strip NUL bytes, then **cap at 2 KiB before running any regex**. Patterns are
written without nested quantifiers to avoid ReDoS. A test feeds 2 KiB
pathological strings and checks the time budget.

### 5.2 Rules

| ID | Pri | Rule | Trigger | Label / mapping candidate | Confidence |
|---|---|---|---|---|---|
| W-ENUM-01 | P0 | Sensitive-path probe | Request to the bait list (§3.2) or webshell paths | `enum:sensitive_path`; OWASP A05; **ATT&CK: none on a single request** | low |
| W-ENUM-02 | P0 | Route enumeration | ≥8 distinct 404/403/bait paths from one source within 60 s | `enum:route_scan`; T1595.003 (wordlist scanning) as candidate | medium |
| W-AUTH-01 | P0 | Failed login | Each wrong credential | `auth:failed` | — |
| W-AUTH-02 | P0 | Brute force | ≥5 failures, same source + same username, within 60 s | T1110.001 | medium (≥5) / high (≥15) |
| W-AUTH-03 | P0 | Password spraying | ≥4 distinct usernames from one source, ≤2 tries each, within 5 min | T1110.003 | medium |
| W-AUTH-04 | P0 | Synthetic success | Synthetic credentials accepted | `auth:decoy_success`; later activity in the session tagged `post_auth` | high |
| W-SQLI-01 | P0 | SQLi-like input | `' or 1=1`, `union select`, `--`/`#` after a quote, `sleep(`, `benchmark(`, `information_schema`, stacked `;` + keyword | `probe:sqli`; OWASP A03; T1190 **candidate**, labelled "attempt, not success" | medium |
| W-XSS-01 | P0 | XSS-like input | `<script`, `on\w+=`, `javascript:`, `<svg`/`<img` + event handler, `alert(`/`document.cookie` | `probe:xss`; OWASP A03 | medium |
| W-PATH-01 | P0 | Path traversal-like | `../`, `..\`, `%2e%2e`, `..%2f`, `/etc/passwd`, `win.ini`, `%00` | `probe:path_traversal`; OWASP A01 | medium |
| W-SSRF-01 | P1 | SSRF-like param | URL-ish value pointing to loopback, link-local `169.254.169.254`, RFC1918, `localhost`, `file://`, `gopher://`, `dict://` | `probe:ssrf`; OWASP A10 | medium |
| W-UPL-01 | P1 | Suspicious upload | Extension or magic bytes say executable/script (`.php`, `.jsp`, `.sh`, ELF, PE) | `upload:suspicious`; **not** T1505.003 | medium |
| W-IDOR-01 | P1 | Synthetic IDOR | Logged-in user requests another synthetic user's `/api/v1/users/{id}` | `authz:idor_attempt`; OWASP A01 | medium |
| W-SHELL-01 | P1 | Webshell path probe | Request to known webshell paths | `probe:webshell_path`; **never** T1505.003 | low |

**As built (Phase 4):**
- `category` is `probe_detected` (input signatures and path probes), `behavior_detected`
  (scan, failed login, brute force, spraying) or `decoy_interaction` (decoy login accepted).
  No rule claims an exploit succeeded; probe events keep `outcome: observed`.
- `field` is where the match was found: `path`, `query.<name>`, `form.<name>`,
  `json.<dotted.name>` or `upload`. The matched value is never stored, not even in `rationale`.
- One detection per rule per request; if several fields match, the rationale says
  "matched in N fields". At most 10 detections per event.
- W-AUTH-04 carries no ATT&CK technique (a decoy login is not itself a technique).
  W-UPL-01 uses OWASP A04 (CWE-434, unrestricted upload).
- W-ENUM-02 fires once per source per 60 s window; W-AUTH-02 fires at 5 (medium) and
  15 (high) failures within 60 s; W-AUTH-03 fires once per 5 min window.

No rule claims an exploit succeeded. Behaviour windows live in memory, bounded by an LRU of 10k sources,
and reset when the container restarts. That limit is documented. Cross-service
correlation and alerting belong to the collector, not here.

---

## 6. Safety and containment controls

| Risk | Control | Test that proves it |
|---|---|---|
| Command execution | No `subprocess`/`os.system`/`eval`/`exec` anywhere in the module | Static grep test fails if any appear |
| Stored/reflected XSS on decoy | Jinja2 autoescape; no `|safe`; CSP `default-src 'self'; script-src 'none'` | Submitting `<script>` comes back escaped; CSP header present |
| XSS **into the SOC dashboard** | Evidence is bounded and stripped of control chars; HTML-looking values tagged `contains_markup`; `docs/INTEGRATOR_NOTES.md` §3 requires plain-text rendering | `test_redaction.py` checks the tag and bounds. The dashboard side is the integrator's to test |
| Detailed health leaks honeypot identity | Detailed JSON only for `HEALTH_ALLOWED_CIDRS`; everyone else gets the normal 404 | `test_routes.py`: allowlisted client gets JSON, other client gets 404 with the same body as an unknown path |
| Path traversal | `/download` uses a dict lookup; no `open()` on request input | `../../etc/passwd` returns 404 and no host contents |
| SSRF | No HTTP client in route modules; preview returns a canned answer | Test monkeypatches `socket.create_connection` to raise, then hits preview with `http://169.254.169.254/` |
| Upload execution | Content discarded after hashing; 1 MiB cap | Upload a `.php` → metadata event, 413 above cap, no file on disk |
| Secret leakage | Redaction rules in §4.1 | Tests send password, cookie, Authorization and JWT values, then grep the events and JSONL for those exact strings |
| Spoofed source IP / campaign | XFF ignored by default; campaign header gated by CIDR | Header from a non-allowlisted IP → `campaign_id=null` |
| Resource exhaustion | Body caps, bounded queue, bounded LRU, regex length cap | Oversized body → 413; 10k-event flood doesn't block requests |
| Fingerprinting | Docs disabled; `Server: nginx` header; generic errors | `/openapi.json` → 404 |
| Container breakout / pivot | Non-root user, `read_only: true`, tmpfs `/tmp`, `cap_drop: [ALL]`, `no-new-privileges`, only volume is `/data`, no host mounts, internal lab network with no egress, port bound to 127.0.0.1 | `docker inspect` check + an outbound-connect attempt from inside the container fails |
| Real credentials | Only synthetic values in `.env.example`; `.env` is gitignored | grep test on the repo |

---

## 7. Tests (pytest + FastAPI TestClient)

| File | Covers |
|---|---|
| `test_schema.py` | Every emitted event validates against the canonical model; no unknown fields; UTC timestamps; UUIDs |
| `test_routes.py` | Every route in §3 returns its documented status; docs disabled; health is minimal |
| `test_auth.py` | Wrong login → 401 + `authentication/failed`; synthetic login → cookie + `succeeded`; session-only pages |
| `test_redaction.py` | No password, cookie, Authorization, JWT or API key appears in any event or the JSONL |
| `test_detection_p0.py` | One deterministic test per P0 scenario: enumeration, brute force, spraying, SQLi, XSS, traversal |
| `test_detection_p1.py` | SSRF, upload, IDOR, webshell path |
| `test_safety.py` | No sockets opened, no file reads on traversal input, no dangerous calls (static), CSP, body caps |
| `test_emitter.py` | POST against the mock collector; collector down → spool + JSONL; queue-full drop counter; replay |
| `test_campaign.py` | Campaign ID accepted only with a valid format and an allowlisted source |
| `test_redos.py` | Pathological inputs finish within the time budget |

---

## 8. Phase plan and phase-exit tests

Each phase ends with a report (changed files, tests run with output,
blockers, next step) and **stops for your approval**.

| Phase | Builds | Exit test (must pass before asking for approval) |
|---|---|---|
| **1** (this) | `PLAN.md`, `PROJECT_STATUS.md`, `docs/INTEGRATOR_NOTES.md`, handoff docs committed | Questions answered (§9), problems resolved (§0.1) — done |
| **2** Realistic decoy | App, templates, fixtures, all routes in §3 (P1 traps return their canned responses; no telemetry yet), `/health`, Dockerfile, standalone compose | `test_routes.py`, `test_auth.py`; container starts and responds on 127.0.0.1:8080 |
| **3** Safe telemetry | Middleware, redaction, schema copy, emitter + JSONL + spool, body caps, campaign gating | `test_schema.py`, `test_redaction.py`, `test_emitter.py`, `test_campaign.py`; sample JSONL inspected by hand |
| **4** Detection | Normalization, P0 rules, then P1 rules, mappings | `test_detection_p0.py`, `test_detection_p1.py`, `test_redos.py`, `test_safety.py` |
| **5** Integration | Point at the integrator's collector, swap in their schema, README, demo script, network-isolation proof, status update | Events visible via the collector's `GET /api/events` and the dashboard; full suite green inside the 3.12 container. **As of 2026-10-31: isolation proof, README, demo runbook and simulator spec done; collector/schema/dashboard integration BLOCKED (nothing published by the integrator)** |

---

## 9. Decisions (answered by the web owner, 2026-10-31)

| # | Question | Decision | Decided by |
|---|---|---|---|
| 1 | Port / collector URL | Web decoy **8080** (host `127.0.0.1:8080`); collector `http://collector:8000/api/events` | Owner |
| 2 | Ingest format | **Batch**: JSON array, ≤50 events per POST | Owner |
| 3 | Detection metadata location | `raw_evidence_redacted.detections[]` + `tags`; shape fixed in `docs/INTEGRATOR_NOTES.md` §2 | Owner |
| 4 | Campaign header | `X-Campaign-Id`, trusted only from `172.28.0.50/32` (the simulator's fixed lab IP; see P9) | Owner (IP: Claude default) |
| 5 | Health | **Detailed.** To keep the decoy from exposing itself, it's served only to `HEALTH_ALLOWED_CIDRS` (see §0.1 P8 and §3.1) | Owner + Claude safeguard |
| 6 | ATT&CK on probes | **Candidate mappings with a label.** T1190 for SQLi/injection-like probes and T1595.003 for route scans, each with `status:"candidate"`, the rationale "attempt observed, no evidence of success", and confidence ≤ medium. T1505.003 is never used for a path probe | Claude (owner deferred) |
| 7 | Upload content | **Metadata only.** Content is hashed and then discarded, never stored | Claude (owner deferred) |
| 8 | Theme | **"Halden Freight — Partner Portal"** | Claude (owner deferred) |

The owner can reverse any decision marked "Claude" at any phase review.

---

## 10. Known limitations (stated up front)

- Behaviour windows are per-process and in memory. A restart resets brute-force counters.
- Following the `/admin` → `/admin/login` redirect counts as two bait hits toward the route-scan threshold.
- Signature rules are pattern-based: novel or heavily obfuscated payloads will be missed, and unusual benign input can trigger them (15 benign samples are tested as non-matching).
- Detection is signature-based. Encoded or obfuscated payloads beyond double URL-encoding may be missed.
- Without TLS in the lab, the decoy can't see HTTPS-only scanners. OpenCanary is not planned.
- Until the integrator publishes `collector/schema.py`, the local schema copy can drift from it. Phase 5 replaces it.
- `replay` runs as a separate process, so `/health` keeps showing `degraded` and does not count replayed events until the next live delivery succeeds.
- The spool is not replayed automatically when the collector comes back; run `python -m web_decoy.telemetry.replay`.
