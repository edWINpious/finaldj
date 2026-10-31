# syntax=docker/dockerfile:1
# Web honeypot decoy. Python 3.12, pinned by digest (verified 2026-10-31).
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    EVENT_LOG_PATH=/data/web-events.jsonl \
    SPOOL_PATH=/data/web-spool.jsonl

WORKDIR /app
COPY requirements.txt .
# Optional `pip_ca` secret: only for build environments behind a TLS-intercepting proxy.
# It is mounted for this step only and never stored in the image. Normal builds skip it.
RUN --mount=type=secret,id=pip_ca,required=false \
    if [ -f /run/secrets/pip_ca ]; then export PIP_CERT=/run/secrets/pip_ca; fi \
 && pip install -r requirements.txt \
 && groupadd --system --gid 10001 decoy \
 && useradd --system --uid 10001 --gid decoy --no-create-home --shell /usr/sbin/nologin decoy \
 && mkdir -p /data && chown decoy:decoy /data

COPY web_decoy ./web_decoy

USER 10001:10001
EXPOSE 8080

# --no-proxy-headers: never trust X-Forwarded-For (PLAN §0.1 P2)
# --no-server-header: app sets "Server: nginx" itself
# --no-access-log: uvicorn's access log would record raw query strings (tokens) unredacted;
#                  the redacted telemetry log replaces it in Phase 3.
CMD ["uvicorn", "web_decoy.app:app", "--host", "0.0.0.0", "--port", "8080", \
     "--no-proxy-headers", "--no-server-header", "--no-access-log", \
     "--limit-concurrency", "200", "--timeout-keep-alive", "5"]
