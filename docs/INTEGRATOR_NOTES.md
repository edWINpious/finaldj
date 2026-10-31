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

- `category` is always `probe_detected` for input signatures. Web never claims an exploit succeeded.
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
- Web trusts the header only from `SIMULATOR_SOURCE_CIDRS` (default `172.28.0.0/16`). **Tell the web owner the real Compose lab subnet.** From any other source it's discarded and the event is tagged `untrusted_campaign_header`.

## 5. Source IP

Web uses the TCP peer address. `X-Forwarded-For` is ignored unless `TRUST_PROXY=1`, so don't put a reverse proxy in front of the decoy without telling the web owner.

## 6. Health for adapter status

- `GET http://web-decoy:8080/health` returns detailed JSON (sensor id, collector reachability, queue depth, dropped events, spool backlog, detection counters). Field list: PLAN.md §3.1.
- This only works from `HEALTH_ALLOWED_CIDRS` (default `127.0.0.1/32,172.28.0.0/16`). Other sources get a normal 404, so attackers can't tell the site is a honeypot.

## 7. Requests to you

1. Accept or reject the §2 detection shape.
2. Confirm the lab subnet (needed for §4 and §6).
3. Confirm the dashboard renders evidence as plain text only (§3).
4. Deduplicate on `event_id` (§1).
