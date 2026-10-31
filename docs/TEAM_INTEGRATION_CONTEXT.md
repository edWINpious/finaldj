# Team Integration Context

Read `../HANDOFF_FINAL.md` first. It is the authoritative project
specification, stack decision, architecture, event schema, API contract,
safety policy, acceptance criteria and objective traceability matrix.

## Team split

-   SSH owner: `../01_SSH/context.md` + `../01_SSH/claude.md`
-   Web owner: `../02_WEB/context.md` + `../02_WEB/claude.md`
-   Database owner: `../03_DATABASE/context.md` +
    `../03_DATABASE/claude.md`
-   Attacker/simulator owner: `../04_ATTACKER/context.md` +
    `../04_ATTACKER/claude.md`

## Stack

Python 3.12, Docker Compose, Cowrie, FastAPI, MariaDB, SQLite (central
event store), Streamlit + Plotly, Pydantic and pytest. Avoid extra
infrastructure unless a verified requirement demands it.

## Integration ownership

Designate one of the four people as integrator. That person owns
`collector/`, the canonical event schema, detection/correlation API and
`dashboard/`. Agree ports, schema and campaign ID before parallel
implementation. Service owners must not create separate competing
collectors.

## Shared event rules

-   Emit canonical events defined in `HANDOFF_FINAL.md`.
-   UTC timestamps, UUIDs, stable sensor IDs.
-   Redact secrets; never store plaintext passwords.
-   Only simulator-originated traffic receives a shared campaign ID.
-   Unsupported ATT&CK mapping remains empty/unmapped.

## Completion

Each owner must provide start/stop/reset commands, sample events, tests,
limitations and safety evidence. Update root `PROJECT_STATUS.md`; only
mark TESTED with reproducible evidence.
