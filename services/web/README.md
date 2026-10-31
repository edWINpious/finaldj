# Web Decoy — Halden Freight Partner Portal

FastAPI web honeypot for the deception-driven SOC project. Everything in it is synthetic.
It never executes, evaluates, fetches or opens anything an attacker sends.

**Status: Phase 3 (safe telemetry).** Every request becomes one redacted canonical event, written to
a JSONL log and POSTed to the collector. Detection rules (Phase 4) are not built yet, so
`detections` is always empty. See `../../PLAN.md` and `../../PROJECT_STATUS.md`.

## Watching events

```bash
docker compose -f docker-compose.web.yml exec web-decoy tail -f /data/web-events.jsonl
```

Running without Docker, the log is `services/web/data/web-events.jsonl`. If no collector is
running, events also pile up in the spool (`/data/web-spool.jsonl`). Resend them once the collector is up:

```bash
docker compose -f docker-compose.web.yml exec web-decoy python -m web_decoy.telemetry.replay
```

Set `COLLECTOR_URL=` (empty) to write the JSONL log only, with no delivery attempts.

## Run / stop / reset (from the repo root)

```bash
cp services/web/.env.example services/web/.env    # optional; defaults are the same synthetic values
docker compose -f docker-compose.web.yml up -d --build
docker compose -f docker-compose.web.yml ps         # wait for "healthy"
docker compose -f docker-compose.web.yml logs -f web-decoy
docker compose -f docker-compose.web.yml down
docker compose -f docker-compose.web.yml down -v    # destructive: also deletes the /data volume
```

Open http://127.0.0.1:8080. Synthetic login: `j.miller` / `Halden#Spring26`.

Detailed health is only served to allowlisted sources, and from the host you get 404 by design. To see it:

```bash
docker compose -f docker-compose.web.yml exec web-decoy python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/health').read().decode())"
```

### Building behind a TLS-intercepting proxy
Only needed when `pip` inside the build fails with `CERTIFICATE_VERIFY_FAILED`. Pass the proxy CA as a build
secret. It is never stored in the image.

```bash
docker build --network host --secret id=pip_ca,src=/path/to/proxy-ca.crt -t halden-web-decoy:dev services/web
```

## Tests

```bash
cd services/web
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

## Ports and environment

| Item | Value |
|---|---|
| Container port | 8080 |
| Host binding | `127.0.0.1:8080` only |
| Lab network | `lab_net` 172.28.0.0/16; decoy at 172.28.0.10 |

| Variable | Default | Purpose |
|---|---|---|
| `SENSOR_ID` | `web-01` | Sensor ID in events |
| `DECOY_USER` / `DECOY_PASSWORD` | `j.miller` / `Halden#Spring26` | Synthetic credential (protects nothing) |
| `HEALTH_ALLOWED_CIDRS` | `127.0.0.1/32` | Who sees detailed `/health`. Single `/32`s only |
| `COLLECTOR_URL` | `http://collector:8000/api/events` | Where batches are POSTed. Empty = JSONL only |
| `EVENT_LOG_PATH` | `/data/web-events.jsonl` (image), `data/web-events.jsonl` (local) | Every event, always |
| `SPOOL_PATH` | `/data/web-spool.jsonl` (image), `data/web-spool.jsonl` (local) | Undelivered batches |
| `SIMULATOR_SOURCE_CIDRS` | `172.28.0.50/32` | Who may set `X-Campaign-Id` |
| `CAMPAIGN_HEADER` | `X-Campaign-Id` | Campaign header name |
| `TRUST_PROXY` | `0` | Honour `X-Forwarded-For`, rightmost entry (keep 0) |

## Container hardening (verified 2026-10-31)

Non-root (uid 10001), read-only root filesystem, `/tmp` tmpfs, the only writable volume is `/data`,
`cap_drop: ALL`, `no-new-privileges`, 128 pids, 256 MB memory. Uvicorn runs with
`--no-proxy-headers` (no XFF trust), `--no-access-log` (its log would hold unredacted query strings)
and `--limit-concurrency 200`.

## Known limitations

- No detection rules yet (Phase 4).
- `/health` stays `degraded` after a manual replay until the next live delivery succeeds.
- `lab_net` is not `internal`, because Docker can't publish ports from an internal network. Egress blocking and the isolation proof are Phase 5.
- No TLS, so the session cookie has no `Secure` flag. Lab use on localhost only.
- Sessions live in memory. A restart logs everyone out.
- Traffic from the host arrives from the Docker gateway `172.28.0.1`. The simulator must run on `lab_net` with its own IP (PLAN.md P9).
