# Web Decoy — Halden Freight Partner Portal

FastAPI web honeypot for the deception-driven SOC project. Everything in it is synthetic.
It never executes, evaluates, fetches or opens anything an attacker sends.

Every request becomes **one redacted canonical event** (HANDOFF_FINAL.md §6). It's written to a JSONL log
and POSTed in batches to the collector, with detections from 13 signature/behaviour rules.
Design: `../../PLAN.md`. Status and evidence: `../../PROJECT_STATUS.md`. Demo: `DEMO.md`.

## Run / stop / reset (from the repo root)

**Isolated (default, for the demo):** no internet, no access to the host, and no port published.
The simulator and collector reach the decoy at `172.28.0.10:8080` on `lab_net`.

```bash
docker compose -f docker-compose.web.yml up -d --build
docker compose -f docker-compose.web.yml ps          # wait for (healthy)
docker compose -f docker-compose.web.yml logs -f web-decoy
docker compose -f docker-compose.web.yml down
docker compose -f docker-compose.web.yml down -v     # destructive: also deletes the /data event log volume
```

**Browse mode (click-through testing from this machine):** publishes `127.0.0.1:8080`. It also
attaches an extra network, so **the container can reach the internet while browse mode is on**.

```bash
docker compose -f docker-compose.web.yml -f docker-compose.web.browse.yml up -d --build
docker compose -f docker-compose.web.yml -f docker-compose.web.browse.yml down
```

Synthetic login: `j.miller` / `Halden#Spring26`.

**Without Docker** (development; from `services/web`, with the venv active):
```bash
uvicorn web_decoy.app:app --host 127.0.0.1 --port 8081
```

## Containment proof

```bash
docker compose -f docker-compose.web.yml exec -T web-decoy python - < services/web/scripts/isolation_check.py
```
Windows PowerShell:
```bash
Get-Content services/web/scripts/isolation_check.py | docker compose -f docker-compose.web.yml exec -T web-decoy python -
```
It checks: no egress to `1.1.1.1` / `8.8.8.8`, no external DNS, no default route, non-root, no capabilities,
no-new-privileges, read-only `/app`. Isolated mode must print `RESULT: ALL PASS`; browse mode correctly fails the egress checks.

## Watching events

```bash
docker compose -f docker-compose.web.yml exec web-decoy tail -f /data/web-events.jsonl
```
Detailed health (only from inside the container or other allowlisted `/32`s):
```bash
docker compose -f docker-compose.web.yml exec web-decoy python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/health').read().decode())"
```
Resend events that were spooled while the collector was down:
```bash
docker compose -f docker-compose.web.yml exec web-decoy python -m web_decoy.telemetry.replay
```

## Tests

From `services/web`, with the venv active:
```bash
python -m pytest -q
```
If you see "Wrong Python environment", the venv isn't active.

## Ports and environment

| Item | Value |
|---|---|
| Container port | 8080 |
| Host binding | none (isolated); `127.0.0.1:8080` (browse mode) |
| Lab network | `lab_net` 172.28.0.0/16, `internal`, host address inhibited; decoy at 172.28.0.10 |

| Variable | Default | Purpose |
|---|---|---|
| `SENSOR_ID` | `web-01` | Sensor ID in events |
| `DECOY_USER` / `DECOY_PASSWORD` | `j.miller` / `Halden#Spring26` | Synthetic credential (protects nothing) |
| `HEALTH_ALLOWED_CIDRS` | `127.0.0.1/32` | Who sees detailed `/health`. Single `/32`s only; add the collector's IP |
| `COLLECTOR_URL` | `http://collector:8000/api/events` | Where batches are POSTed. Empty = JSONL only |
| `EVENT_LOG_PATH` | `/data/web-events.jsonl` (image), `data/web-events.jsonl` (local) | Every event, always |
| `SPOOL_PATH` | `/data/web-spool.jsonl` (image), `data/web-spool.jsonl` (local) | Undelivered batches |
| `SIMULATOR_SOURCE_CIDRS` | `172.28.0.50/32` | Who may set `X-Campaign-Id` |
| `CAMPAIGN_HEADER` | `X-Campaign-Id` | Campaign header name |
| `TRUST_PROXY` | `0` | Honour `X-Forwarded-For`, rightmost entry (keep 0) |

## Acceptance criteria (`docs/handoff/02_WEB/claude.md`)

| Criterion | Evidence | Status |
|---|---|---|
| Starts with documented commands | This README; container healthy in both modes | Met |
| P0 routes and login events captured | `tests/test_telemetry.py`, `tests/test_detection_p0.py`; samples | Met |
| Suspicious inputs logged safely, never executed | `tests/test_safety.py` (AST checks), `tests/test_routes.py` traps | Met |
| Passwords, cookies, tokens redacted | `tests/test_redaction.py`; end-to-end leak checks | Met |
| Normalized events reach collector **and dashboard** | Delivery proven against a throwaway mock collector only | **Blocked**: no integrator collector/dashboard yet |
| Upload / SSRF / path traversal controls tested | `tests/test_routes.py`, `tests/test_detection_p1.py` | Met |
| Network isolation and synthetic data documented | Containment proof above; `fixtures.py` is all synthetic | Met |
| Tests pass | 338 passed (Python 3.12, local + in image); owner: Windows | Met |

## Known limitations

- **Integration is not done.** There is no real collector or dashboard yet, and the event schema is a local copy of HANDOFF §6.
- Browse mode removes egress isolation (Docker can't publish ports from an internal network).
- Detection state (brute-force/scan windows) and sessions are in memory and reset on restart.
- Signature rules are pattern-based. Obfuscated payloads can be missed, and unusual benign input can match.
- `/health` stays `degraded` after a manual replay until the next live delivery succeeds. Spooled events are not auto-replayed.
- No TLS, so the session cookie has no `Secure` flag. Lab use only.
- Traffic sent from the host arrives from a Docker gateway IP, not a real client IP. The simulator must run on `lab_net` (PLAN.md P9).
- The isolation setup has been verified on Linux Docker 29.9. It hasn't yet been verified on Docker Desktop for Windows.
