# Web Decoy — Halden Freight Partner Portal

FastAPI web honeypot for the deception-driven SOC project. Everything in it is synthetic.
It never executes, evaluates, fetches or opens anything an attacker sends.

**Status: Phase 2 (realistic decoy).** Telemetry (Phase 3) and detection (Phase 4) are not built yet,
so right now **no events are emitted.** See `../../PLAN.md` and `../../PROJECT_STATUS.md`.

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
| `COLLECTOR_URL` | `http://collector:8000/api/events` | Phase 3 |
| `SIMULATOR_SOURCE_CIDRS` | `172.28.0.50/32` | Phase 3: who may set `X-Campaign-Id` |
| `TRUST_PROXY` | `0` | Phase 3: honour `X-Forwarded-For` (keep 0) |

## Container hardening (verified 2026-10-31)

Non-root (uid 10001), read-only root filesystem, `/tmp` tmpfs, the only writable volume is `/data`,
`cap_drop: ALL`, `no-new-privileges`, 128 pids, 256 MB memory. Uvicorn runs with
`--no-proxy-headers` (no XFF trust), `--no-access-log` (its log would hold unredacted query strings)
and `--limit-concurrency 200`.

## Known limitations (Phase 2)

- No telemetry yet. Requests are served but not recorded.
- `lab_net` is not `internal`, because Docker can't publish ports from an internal network. Egress blocking and the isolation proof are Phase 5.
- No TLS, so the session cookie has no `Secure` flag. Lab use on localhost only.
- Sessions live in memory. A restart logs everyone out.
- Traffic from the host arrives from the Docker gateway `172.28.0.1`. The simulator must run on `lab_net` with its own IP (PLAN.md P9).
