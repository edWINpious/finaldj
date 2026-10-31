# Integrator Notes — from the Web module

Audience: the integrator (owner of `collector/`, the canonical schema, detections and `dashboard/`).
The web module does not change the shared schema. Everything here is a request or a contract proposal for you to accept or reject.

## 1. Transport

- Endpoint: `POST http://collector:8000/api/events`
- Body: **JSON array** of canonical events (HANDOFF_FINAL.md §6), ≤50 per request, `Content-Type: application/json`.
- Web sends at least once a second while events are queued. Timeout 2 s.
- If the collector is unavailable, events are spooled to `/data/web-spool.jsonl` and resent later. **Please deduplicate on `event_id`**, because a resend after a timeout can deliver the same event twice.
- Expected response: `2xx` = accepted. Any other response means the batch is spooled and retried.

## 2. Detection metadata (schema gap)

The canonical schema has no field for rule hits. Until you add one, web puts them here:

```json
"raw_evidence_redacted": {
  "detections": [
    {
      "rule": "W-SQLI-01",
      "category": "probe_detected",
      "label": "probe:sqli",
      "field": "q",
      "owasp": "A03:2021-Injection",
      "attack": [
        {"technique": "T1190", "status": "candidate",
         "rationale": "SQLi-like input observed; no evidence of success",
         "confidence": "medium"}
      ],
      "confidence": "medium"
    }
  ]
},
"tags": ["probe:sqli", "owasp:A03"]
```

- `category`: `probe_detected` (input signatures, path probes), `behavior_detected` (route scan, failed login, brute force, spraying) or `decoy_interaction` (decoy credential accepted). Web never claims an exploit succeeded.
- `field`: `path`, `query.<name>`, `form.<name>`, `json.<dotted.name>` or `upload`. The matched value itself is never included.
- Rules and thresholds (all in the web module's PLAN.md §5): W-ENUM-01 sensitive path (low), W-ENUM-02 ≥8 distinct 403/404/bait paths in 60 s (T1595.003), W-AUTH-01 failed login, W-AUTH-02 ≥5 / ≥15 failures for one username in 60 s (T1110.001, medium / high), W-AUTH-03 ≥4 usernames with ≤2 tries each in 5 min (T1110.003), W-AUTH-04 decoy login accepted (high), W-SQLI-01 (T1190), W-XSS-01, W-PATH-01, W-SSRF-01, W-UPL-01, W-IDOR-01, W-SHELL-01.
- Full attack-campaign sample (24 events, one campaign ID, every rule firing): `services/web/samples/web-attack-campaign.sample.jsonl`.
- `attack[].status` is `candidate`. Your alert layer decides whether to promote a candidate to an alert mapping.
- `T1505.003` is never emitted for a webshell path probe.
- If you add a first-class schema field (e.g. `detections`), tell the web owner and the adapter will move the data there.

## 3. Dashboard XSS: action needed on your side

Event evidence contains **raw attacker-supplied strings** (`<script>…`, `javascript:` and so on). They're bounded to 512 chars, control-char-stripped, and tagged `contains_markup` when they look like HTML, but they are **not HTML-escaped**, because escaping would corrupt the evidence.

In Streamlit:
- **Never** pass event fields to `st.markdown(..., unsafe_allow_html=True)` or `st.html`, or into `components.html`.
- Plain `st.markdown` also interprets Markdown, including links. Show evidence with `st.code`, `st.text`, `st.json` or `st.dataframe`.
- In Plotly hover text, escape `<` and `>` (Plotly renders a subset of HTML tags).

## 4. Campaign IDs

- Header: `X-Campaign-Id`, value `^[A-Za-z0-9_-]{1,64}$`.
- Web trusts the header only from `SIMULATOR_SOURCE_CIDRS` (default `172.28.0.50/32`). From any other source it's discarded and the event is tagged `untrusted_campaign_header`.
- **The simulator must run as a container on `lab_net` with a fixed IP** (proposed `172.28.0.50`). Verified in the Phase 2 container test: anything sent from the host through a published `127.0.0.1:` port reaches the decoy from the Docker gateway (`172.28.0.1`). A host-run simulator would therefore (a) share one source IP with every other host process, breaking per-attacker profiles, and (b) be impossible to tell apart from other host traffic for campaign trust.

## 5. Source IP

Web uses the TCP peer address. `X-Forwarded-For` is ignored unless `TRUST_PROXY=1`, so don't put a reverse proxy in front of the decoy without telling the web owner.

## 6. Health for adapter status

- `GET http://web-decoy:8080/health` returns detailed JSON (sensor id, collector reachability, queue depth, dropped events, spool backlog, detection counters). Field list: PLAN.md §3.1.
- This only works from `HEALTH_ALLOWED_CIDRS` (default `127.0.0.1/32`). **Give the collector a fixed lab IP and tell the web owner**, so it can be added as a `/32`. Never the whole subnet (see §4: the gateway address would then be trusted). Other sources get a normal 404, so attackers can't tell the site is a honeypot.

## 7. Event vocabulary (as built, Phase 3)

Sample of 11 real events from an end-to-end container run: `services/web/samples/web-events.sample.jsonl`.

| Field | Values from web-01 |
|---|---|
| `event_type` | `http_request`, `authentication` (POST /login), `file_transfer` (POST /upload) |
| `action` | `page_view`, `route_probe`, `login_attempt`, `upload_attempt` |
| `outcome` | `observed`, `failed` / `succeeded` (login), `blocked` (size limit) |
| `tags` | `authenticated_session`, `contains_markup`, `untrusted_campaign_header`, `body_rejected`; Phase 4 adds `probe:*`, `enum:*`, `auth:*` labels |
| `session_id` | Opaque UUID, the same across one login session; **not** the cookie |
| `raw_evidence_redacted` | `headers` (allowlisted), `query`/`form`/`json` (redacted), `body` (type + size), `upload` (name, sizes, sha256, sniffed type, `stored:false`), `detections[]` |

Not emitted: successful static asset loads, and `/health` polls from `HEALTH_ALLOWED_CIDRS`.

## 8. Requests to you

1. Accept or reject the §2 detection shape.
2. Confirm the lab subnet, the collector's fixed IP (§6) and the simulator's fixed IP (§4).
3. Confirm the dashboard renders evidence as plain text only (§3).
4. Deduplicate on `event_id` (§1).
