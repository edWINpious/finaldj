# HANDOFF_FINAL.md --- Master Project Handoff

## 1. Project at a glance

**Project:** Deception-Driven Threat Detection and Response: A SOC
Dashboard Powered by a Honeypot Network

**Hackathon constraint:** approximately 24 hours. Optimize for a
working, repeatable end-to-end demonstration over production-scale
complexity.

Build three isolated decoy services---SSH, web login/application, and
database---that emit events into one shared collector. A fourth teammate
runs controlled attack simulations against those decoys. The SOC
dashboard presents live events, alerts, attacker profiles, cross-service
campaign timelines, ATT&CK evidence and safe response recommendations.

The project is one integrated detection product, not three unrelated
honeypots.

## 2. Easy-to-work-with technology stack

Use a deliberately small, mostly Python stack. Avoid Kubernetes, Kafka,
Elasticsearch, a complex React frontend, microservices sprawl or cloud
dependencies during the hackathon.

  -----------------------------------------------------------------------
  Layer                   Choice                  Why
  ----------------------- ----------------------- -----------------------
  Runtime                 Python 3.12             One language for
                                                  collector, web decoy,
                                                  adapters, simulator and
                                                  tests

  Local orchestration     Docker Compose          One command to
                                                  start/stop the lab

  SSH honeypot            Cowrie container        Mature SSH/Telnet
                                                  interaction capture

  Web decoy               FastAPI + Jinja2        Fast to build; captures
                          templates               request-level telemetry

  Database decoy          MariaDB container       Familiar
                                                  MySQL-compatible
                                                  database

  Database telemetry      MariaDB audit plugin if Keep query-level
                          available; otherwise a  visibility testable; do
                          small SQLAlchemy-based  not claim native audit
                          query gateway/logger    coverage unless
                          for all demo queries    verified

  Central collector/API   FastAPI                 Simple JSON ingestion
                                                  and query API

  Event store             SQLite via              No separate database
                          SQLModel/SQLAlchemy     service needed for the
                                                  SOC backend

  Dashboard               Streamlit + Plotly      Fast Python dashboard;
                                                  avoids separate
                                                  frontend build system

  Validation              Pydantic + pytest       Typed event contract
                                                  and repeatable tests

  Packaging               Docker Compose +        Reproducible local
                          `.env.example`          setup
  -----------------------------------------------------------------------

**Important database telemetry decision:** MariaDB server audit logging
availability/configuration varies by image and version. Prove it
captures the required query events early. If it does not, route
simulator queries through a tiny Python database gateway that logs each
query before executing only allowlisted read-only statements. Clearly
label this as gateway-observed telemetry, not native server audit. Do
not spend the hackathon debugging an unsupported plugin.

**Suggested versions:** Pin known-compatible versions in
`requirements.txt` / image tags after a smoke test. Do not chase newest
versions on demo day.

## 3. Simple architecture

``` text
                    ATTACKER SIMULATOR
               (fixed lab allowlist, campaign_id)
                    /       |       \
                   v        v        v
             Cowrie SSH   FastAPI Web   MariaDB
              decoy        decoy       decoy/gateway
                |             |            |
           Cowrie JSON    JSON events   Audit/gateway
                \             |            /
                 \            |           /
                  v           v          v
                    EVENT ADAPTERS
                   normalize to schema
                            |
                            v
                 CENTRAL FASTAPI COLLECTOR
                    POST /api/events
                            |
                            v
                    SQLite event store
                            |
                 detection + correlation
                            |
               FastAPI read APIs / Streamlit
                            |
                            v
                 SOC dashboard + simulated
                    response + IOC export
```

## 4. Repository layout

``` text
project/
  HANDOFF_FINAL.md
  PROJECT_STATUS.md
  docker-compose.yml
  .env.example
  requirements.txt
  services/
    ssh/                 # Cowrie config, adapter, tests
    web/                 # FastAPI decoy, middleware, tests
    database/            # MariaDB init, seed, telemetry adapter, tests
  collector/
    app.py               # FastAPI ingestion/read API
    schema.py            # canonical Pydantic event/alert models
    storage.py           # SQLite persistence
    detections.py        # transparent rules and correlation
  dashboard/
    app.py               # Streamlit UI
  simulator/
    cli.py               # safe scenario runner
    scenarios/
  tests/
  docs/
    TEAM_INTEGRATION_CONTEXT.md
```

## 5. One-command workflow

Target developer experience:

``` bash
cp .env.example .env
docker compose up --build
```

Dashboard should be reachable at `http://localhost:8501`, collector
health at `http://localhost:8000/health`, and web decoy on its
documented lab port. Cowrie and MariaDB ports must be explicitly
documented in Compose and bound to localhost for the demo.

Useful commands:

``` bash
docker compose ps
docker compose logs -f collector
docker compose logs -f web-decoy
docker compose down
docker compose down -v       # destructive: resets disposable lab data
pytest -q
python -m simulator.cli check
python -m simulator.cli run full-demo --dry-run
python -m simulator.cli run full-demo
```

Do not expose the dashboard, collector or decoys to the public internet.
Bind published ports to `127.0.0.1` where feasible.

## 6. Shared event contract

All services must emit the same canonical JSON event envelope. The
integrator owns this schema; service owners write adapters to it.

``` json
{
  "event_id": "uuid",
  "timestamp": "RFC3339 UTC",
  "sensor_id": "ssh-01 | web-01 | db-01",
  "service": "ssh | web | database",
  "source_ip": "string",
  "source_port": null,
  "destination_service": "string",
  "event_type": "connection | authentication | command | http_request | sql_query | file_transfer",
  "action": "string",
  "outcome": "observed | succeeded | failed | blocked | simulated",
  "username": null,
  "session_id": null,
  "campaign_id": null,
  "request_path": null,
  "http_method": null,
  "http_status": null,
  "command": null,
  "query_type": null,
  "database_name": null,
  "table_names": [],
  "rows_returned": null,
  "file_name": null,
  "file_direction": null,
  "user_agent": null,
  "raw_evidence_redacted": {},
  "tags": []
}
```

Contract rules: - UTC timestamps; stable sensor IDs; UUID event IDs. -
`campaign_id` only for traffic explicitly generated by the simulator.
Never group unrelated internet traffic by assumption. - Never store
passwords, cookies, tokens, API keys, private keys or authorization
headers. - Bound raw evidence and query lengths; redact credential
literals. - Missing fields are null or empty arrays, never fabricated. -
Preserve native session/connection identifiers where possible.

## 7. Central API contract

Minimum endpoints: - `POST /api/events` --- ingest one event or a
documented batch. - `GET /api/events` --- recent events with pagination
and filters. - `GET /api/alerts` --- prioritized alerts. -
`GET /api/attackers` --- source profiles. - `GET /api/attackers/{id}`
--- profile and event timeline. - `GET /api/coverage` --- coverage
status per scenario. - `GET /api/iocs` --- exportable indicators. -
`POST /api/response/block` --- simulated block action by default, with
audit trail. - `GET /health` --- health and adapter status.

The Streamlit dashboard consumes these APIs. It must not read Cowrie or
MariaDB storage directly.

## 8. Detection, severity and correlation

Start with a few explainable rules: - Repeated failed authentication
from one source in a short window: medium/high based on rate. - Same
explicitly tagged campaign touching multiple decoys: raise campaign
priority. - Successful decoy login followed by command/query/file
activity: high. - Synthetic sensitive-table read after database login:
high, but do not call it exfiltration without transfer evidence. -
Destructive SQL attempt: high; label `blocked` or `simulated`
accurately. - Low-signal route probes alone: low/medium, not critical by
default.

Every alert must include alert ID, title, severity, confidence,
first/last seen, source, related event IDs, rationale, ATT&CK IDs
(possibly empty), kill-chain stage (possibly empty), recommended action
and status.

Use low / medium / high / critical. Do not use arbitrary severity
without a rule rationale. Deduplicate repeated alerts and show the
threshold/window.

## 9. Attack catalogue and demo scenarios

### SSH / Cowrie

-   Service probing and connection attempts.
-   Repeated failed login/password guessing.
-   Password spraying only when pattern is supported.
-   Successful synthetic login.
-   Emulated `whoami`, `id`, `hostname`, `uname`.
-   Fake directory/file discovery and supported file-transfer metadata.

### Web / FastAPI

-   `/admin`, `/backup`, `/config`, `/api` enumeration.
-   Bounded login failures and synthetic success.
-   SQLi-like, XSS-like and path traversal-like input detection.
-   SSRF-like parameter detection without outbound fetch.
-   Upload metadata and webshell path probes without
    execution/deployment.

### Database / MariaDB

-   Connection and failed-login attempts.
-   Synthetic successful login.
-   Schema/table enumeration.
-   Bounded SELECT against synthetic records.
-   Privilege/destructive statements denied or simulated.
-   Query telemetry must be demonstrated, not assumed.

### Four deterministic demos

1.  SSH: failed credentials → synthetic login → harmless emulated
    discovery commands.
2.  Web: route enumeration → login attempts → inert injection/path probe
    strings.
3.  DB: authentication → metadata enumeration → bounded synthetic SELECT
    → denied destructive attempt.
4.  Main cross-service campaign: run all three under one
    simulator-generated `campaign_id`; show one coherent incident
    timeline, source profile, severity rationale, evidence-linked ATT&CK
    mapping and simulated response.

## 10. MITRE ATT&CK and kill-chain discipline

Candidate mappings: - T1110 and sub-techniques for credential attacks,
only when pattern supports them. - T1033 for system owner/user
discovery. - T1082 for system information discovery. - T1083 for
file/directory discovery. - T1059.004 for Unix shell execution when
evidenced. - T1105 only for observed ingress tool transfer. - T1190 only
for evidenced exploitation attempt against a public-facing
application. - T1505.003 only for actual web-shell deployment/use, not a
URL probe. - T1046 only for evidenced network-service discovery.

Do not force mappings. Store mapping rationale and confidence. A probe
string is not proof of exploitation. A webshell path request is not a
deployed webshell. A SELECT is not proof of exfiltration.

## 11. Safety and containment

-   Local authorized lab only; no public IPs or campus/production
    networks.
-   Cowrie must not proxy to real SSH servers.
-   No sensitive host mounts or secrets in containers.
-   Web input is never executed, evaluated, rendered as trusted HTML or
    fetched as an SSRF URL.
-   DB contains synthetic records only, least-privilege credentials and
    resettable volume.
-   Destructive SQL is denied or confined to a disposable seeded DB.
-   Simulator has explicit fixed target allowlist, bounded attempts,
    timeouts and dry-run mode.
-   Response action is simulated by default; no real firewall changes
    without explicit approval.
-   Redact passwords, tokens, cookies and API keys from logs and
    evidence.

## 12. Project objectives → implementation → evidence traceability

  ---------------------------------------------------------------------------
  Objective / deliverable Implementation location     Acceptance evidence
  ----------------------- --------------------------- -----------------------
  Three realistic decoys  `services/ssh`,             Each service starts;
                          `services/web`,             documented ports;
                          `services/database`         synthetic interaction
                                                      tests

  Real-time event         service adapters +          Events arrive at
  collection              `collector`                 `POST /api/events`;
                                                      timestamps and sensor
                                                      IDs visible

  Normalized SIEM-style   `collector/schema.py`,      Schema validation tests
  pipeline                adapters                    and sample JSONL

  Attack classification   `collector/detections.py`   P0 scenario tests
                                                      assert classifications

  ATT&CK + kill-chain     alert/event metadata        Evidence, confidence
  mapping                                             and rationale shown;
                                                      unsupported mappings
                                                      omitted

  Alert prioritization    detection rules             Severity tests,
                                                      thresholds, rationale
                                                      and deduplication

  Correlation / attacker  campaign IDs + source       Cross-service timeline
  profiling               profiles                    and profile in
                                                      full-demo

  Firewall/auth log       optional simulated events   Demonstrate correlation
  correlation             in collector                when available; label
                                                      simulated source
                                                      clearly

  Automated response /    simulated response API +    Audited simulated block
  threat intel            IOC export                  and downloadable IOC
                                                      JSON/CSV

  Containment and safety  Compose networks,           Negative tests:
                          allowlists, safe handlers   external target
                                                      rejected; no
                                                      egress/pivot;
                                                      destructive actions
                                                      blocked

  Functional honeypot     three service modules       Repeatable clean-start
  deliverable                                         demo

  SOC dashboard           Streamlit dashboard         Live/recent events,
  deliverable                                         prioritized alerts,
                                                      profiles, timeline and
                                                      ATT&CK

  Simulated attack demo   attacker simulator          Four scenarios, runbook
                                                      and evidence logs

  Documentation           README and module docs      Architecture,
  deliverable                                         isolation, detection
                                                      logic, limitations and
                                                      IR workflow
  ---------------------------------------------------------------------------

## 13. Coverage language

For each attack scenario display one of: - `SUPPORTED`: sensor can
capture the behavior. - `DETECTED`: event was actually observed and a
detection fired. - `SIMULATED`: a safe simulation was recorded, not a
real exploit. - `NOT OBSERVED`: sensor supports it, but it did not occur
in this run. - `UNSUPPORTED`: not implemented or not instrumented.

Never mark a scenario DETECTED merely because a detection rule exists.

## 14. 24-hour execution strategy

1.  First hour: agree stack, ports, schema, collector endpoint,
    campaign-ID plan and integrator.
2.  Early build: each module emits one normalized test event; collector
    stores and dashboard displays it.
3.  Midpoint: complete P0 behavior per service and run individual
    scenarios.
4.  Final third: freeze schema; complete cross-service campaign, alerts,
    profile, simulated response and demo evidence.
5.  Last hour: stability, screenshots, documentation and rehearsed demo.
    No new P2 features.

## 15. Status tracking

Maintain root `PROJECT_STATUS.md` with rows for each objective and
statuses: `NOT STARTED`, `IN PROGRESS`, `IMPLEMENTED`, `TESTED`,
`BLOCKED`.

A task may be `TESTED` only with evidence: command run, test result,
event ID/sample, screenshot or log reference. "Code exists" is not test
evidence.

## 16. Definition of done

-   One-command local startup works.
-   All three decoys produce normalized events.
-   Dashboard shows events, alerts, attacker profiles and ATT&CK
    evidence.
-   Attacker simulator runs the four P0 scenarios deterministically.
-   Cross-service campaign correlation is demonstrated.
-   Simulated response and IOC export work.
-   Safety checks pass.
-   Documentation and demo runbook are complete.
