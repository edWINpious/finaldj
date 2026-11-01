---
version: 1
slug: "frontend-src-app-tsx"
primary_target: "frontend/src/App.tsx"
related_targets: []
---

Scope: the TransNova SOC React console (all routes: Overview, All events, Alerts, Sources, Sensors, MITRE ATT&CK, OWASP web, Settings, Login). Visitor mode: Operate.

Audience and job: a SOC analyst at a desktop monitor and the owner presenting to judges on a projector. The job is to see whether the SOC is working, triage evidence-backed alerts, and investigate a source's history. Everything shown is live collector data; empty, stale and error states are first-class.

## Direction contract

THESIS: Every event is a catalogued specimen, and every classification is a determination slip added beside it, never written over it. The surface refuses the category default of a KPI-card row, a donut and a neon threat map.

OWN-WORLD: The rail is cabinet green (#24413a) on a pale stone ground (#eceae4). Panels are label stock (#fbfaf6) under one hairline border system (#cfccc2). Brass (#a8823a) marks new and selected items. Curator red (#9c3b2a) is used only for high and critical. Type is Atkinson Hyperlegible for text and JetBrains Mono with tabular figures for IDs, times and counts. There is one 4px module.

STORY: The analyst sees in one sentence whether the collector and sensors are working. They open an alert and read the evidence first, with the rule, confidence and AI interpretation stacked as separate slips. They record a disposition, which is added as a new slip.

FIRST VIEWPORT: Green 232px rail with the brand and eight routes, plus live counts. The page title and a one-line purpose. A full-width state strip with collector, sensor and last-event status as sentences. Below it, two columns: the newest events (left) and open alerts as determination slips (right).

FORM: Collection Cabinet, position 5 of 7 on the ordered list; seed:6e96b0468ecde173. Signature move: determination slips. Raises: a new item stays brass-marked until seen; the table head shows the first and last timestamp in view; strict 4px module and tabular figures; session bar length equals real duration; one hairline system; columns never move between refreshes.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
