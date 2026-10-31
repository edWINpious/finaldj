# PLAN.md — Web Honeypot Module (Phase 1: Inspect and Plan)

Status: **DRAFT — waiting for human review. No implementation has started.**

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
| Python | The plan targets **3.12** in the container, as the spec requires. The dev sandbox has 3.13. Tests must pass on both, and only the container result counts as evidence. |
| Docker | Available (29.x), so Compose-based tests are possible here. |
| Shared schema | Taken from `HANDOFF_FINAL.md §6`. There is no `collector/schema.py` to import yet. |
| Collector URL / ports | **Not agreed with the integrator yet.** The defaults below are marked `PENDING`. |

---

## 1. Proposed defaults (PENDING integrator confirmation)

| Setting | Default | Env var |
|---|---|---|
| Web decoy listen address (container) | `0.0.0.0:8080` | `WEB_DECOY_PORT` |
| Published port (host) | `127.0.0.1:8080` only | Compose |
| Collector ingest URL | `http://collector:8000/api/events` | `COLLECTOR_URL` |
| Sensor ID | `web-01` | `SENSOR_ID` |
| Campaign ID header | `X-Campaign-Id` | `CAMPAIGN_HEADER` |
| Simulator source allowlist (for trusting campaign IDs) | `172.28.0.0/16` (lab network) | `SIMULATOR_SOURCE_CIDRS` |
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
| `/health` | GET | `{"status":"ok"}` and nothing else (see Q5) | not emitted |

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
  `COLLECTOR_URL` with a 2 s timeout and batches of 50 or less, if the
  integrator accepts batches (Q2).
- When the collector is down, events go to `/data/web-spool.jsonl`. A
  `python -m web_decoy.telemetry.replay` command resends them later.
- When the queue is full, events are dropped and `dropped_events` goes up. The
  JSONL log still keeps them. Request handling never blocks on the collector.

### 4.3 Request body limits
- A global cap of 64 KiB for non-upload bodies (413 beyond). It checks both
  `Content-Length` and the size actually streamed, so it can't be bypassed
  with chunked encoding.
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
| W-ENUM-02 | P0 | Route enumeration | ≥8 distinct 404/403/bait paths from one source within 60 s | `enum:route_scan`; T1595.003 (wordlist scanning) as candidate only, pending integrator agreement (Q6) | medium |
| W-AUTH-01 | P0 | Failed login | Each wrong credential | `auth:failed` | — |
| W-AUTH-02 | P0 | Brute force | ≥5 failures, same source + same username, within 60 s | T1110.001 | medium (≥5) / high (≥15) |
| W-AUTH-03 | P0 | Password spraying | ≥4 distinct usernames from one source, ≤2 tries each, within 5 min | T1110.003 | medium |
| W-AUTH-04 | P0 | Synthetic success | Synthetic credentials accepted | `auth:decoy_success`; later activity in the session tagged `post_auth` | high |
| W-SQLI-01 | P0 | SQLi-like input | `' or 1=1`, `union select`, `--`/`#` after a quote, `sleep(`, `benchmark(`, `information_schema`, stacked `;` + keyword | `probe:sqli`; OWASP A03; T1190 **candidate**, labelled "attempt, not success" (Q6) | medium |
| W-XSS-01 | P0 | XSS-like input | `<script`, `on\w+=`, `javascript:`, `<svg`/`<img` + event handler, `alert(`/`document.cookie` | `probe:xss`; OWASP A03 | medium |
| W-PATH-01 | P0 | Path traversal-like | `../`, `..\`, `%2e%2e`, `..%2f`, `/etc/passwd`, `win.ini`, `%00` | `probe:path_traversal`; OWASP A01 | medium |
| W-SSRF-01 | P1 | SSRF-like param | URL-ish value pointing to loopback, link-local `169.254.169.254`, RFC1918, `localhost`, `file://`, `gopher://`, `dict://` | `probe:ssrf`; OWASP A10 | medium |
| W-UPL-01 | P1 | Suspicious upload | Extension or magic bytes say executable/script (`.php`, `.jsp`, `.sh`, ELF, PE) | `upload:suspicious`; **not** T1505.003 | medium |
| W-IDOR-01 | P1 | Synthetic IDOR | Logged-in user requests another synthetic user's `/api/v1/users/{id}` | `authz:idor_attempt`; OWASP A01 | medium |
| W-SHELL-01 | P1 | Webshell path probe | Request to known webshell paths | `probe:webshell_path`; **never** T1505.003 | low |

Every detection is labelled `probe_detected`. No rule claims an exploit
succeeded. Behaviour windows live in memory, bounded by an LRU of 10k sources,
and reset when the container restarts. That limit is documented. Cross-service
correlation and alerting belong to the collector, not here.

---

## 6. Safety and containment controls

| Risk | Control | Test that proves it |
|---|---|---|
| Command execution | No `subprocess`/`os.system`/`eval`/`exec` anywhere in the module | Static grep test fails if any appear |
| Stored/reflected XSS on decoy | Jinja2 autoescape; no `|safe`; CSP `default-src 'self'; script-src 'none'` | Submitting `<script>` comes back escaped; CSP header present |
| XSS **into the SOC dashboard** | Evidence holds raw attacker strings | Handoff note to integrator: never render evidence with `unsafe_allow_html` |
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
| **1** (this) | `PLAN.md`, `PROJECT_STATUS.md`, handoff docs committed | You review and answer the questions in §9 |
| **2** Realistic decoy | App, templates, fixtures, all routes in §3 (P1 traps return their canned responses; no telemetry yet), `/health`, Dockerfile, standalone compose | `test_routes.py`, `test_auth.py`; container starts and responds on 127.0.0.1:8080 |
| **3** Safe telemetry | Middleware, redaction, schema copy, emitter + JSONL + spool, body caps, campaign gating | `test_schema.py`, `test_redaction.py`, `test_emitter.py`, `test_campaign.py`; sample JSONL inspected by hand |
| **4** Detection | Normalization, P0 rules, then P1 rules, mappings | `test_detection_p0.py`, `test_detection_p1.py`, `test_redos.py`, `test_safety.py` |
| **5** Integration | Point at the integrator's collector, swap in their schema, README, demo script, network-isolation proof, status update | Events visible via the collector's `GET /api/events` and the dashboard; full suite green inside the 3.12 container |

---

## 9. Open questions — need answers before Phase 2

**For the integrator:**
1. **Port and URL:** are web decoy `8080` and collector `http://collector:8000/api/events` OK?
2. **Batch format:** does `POST /api/events` accept a JSON array, or one event per request?
3. **Where detection metadata goes:** the schema has no field for rule hits, OWASP labels or ATT&CK candidates. My plan puts them in `raw_evidence_redacted.detections[]` plus `tags`. Does the integrator agree, or will they add a schema field?
4. **Campaign header:** is the name `X-Campaign-Id` agreed with the simulator owner? What is the lab network CIDR?

**For you:**
5. **Health endpoint exposure:** `/health` is on the same port an attacker sees. My plan returns only `{"status":"ok"}` there and keeps detailed status (queue depth, collector reachability) out of the decoy. Is that acceptable? Or does the integrator's `GET /health` adapter status need more from this service?
6. **Mapping strictness:** the spec says T1190 only "if evidence supports an exploitation attempt". My reading is that an SQLi-like probe string *is* an attempt, so it gets a *candidate* T1190 with medium confidence and the label "attempt, not success". Stricter option: no ATT&CK for probes at all, OWASP only. Which do you want? The same question applies to T1595.003 for route scanning.
7. **Persist upload content?** My plan keeps metadata only and discards the content, which is the safest choice. Do you need inert storage of samples for the demo?
8. **Theme:** is "Halden Freight — Partner Portal" OK, or do you want a different fake business?

---

## 10. Known limitations (stated up front)

- Behaviour windows are per-process and in memory. A restart resets brute-force counters.
- Detection is signature-based. Encoded or obfuscated payloads beyond double URL-encoding may be missed.
- Without TLS in the lab, the decoy can't see HTTPS-only scanners. OpenCanary is not planned.
- Until the integrator publishes `collector/schema.py`, the local schema copy can drift from it. Phase 5 replaces it.
