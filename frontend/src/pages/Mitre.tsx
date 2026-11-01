import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMitre, useRules } from "../api/hooks";
import type { MitreRow } from "../api/types";
import { Empty, ErrorState, KV, Loading, PageHeader, Panel } from "../components/ui";
import { plural, SERVICE_LABEL, words } from "../lib/format";

const STATUS: Record<MitreRow["status"], { label: string; help: string }> = {
  evidence: { label: "Supported by evidence", help: "A sensor observed this technique directly in a stored event." },
  rule_inferred: { label: "Inferred by a rule", help: "A rule matched and names this technique as a candidate; the evidence does not prove it." },
  implemented_not_observed: { label: "Detection ready, not seen", help: "A rule can map this technique, but no stored event has triggered it." },
  gap: { label: "Known gap", help: "The decoys could plausibly see this technique, and no rule detects it." },
};

export function Mitre() {
  const mitre = useMitre();
  const rules = useRules();
  const [pick, setPick] = useState<string | null>(null);
  const [filter, setFilter] = useState<MitreRow["status"] | "">("");
  const grouped = useMemo(() => {
    if (!mitre.data) return [];
    return mitre.data.tactics.map((t) => ({
      tactic: t, rows: mitre.data!.techniques.filter((r) => r.tactics.includes(t.shortname) && (!filter || r.status === filter)),
    })).filter((g) => g.rows.length);
  }, [mitre.data, filter]);
  if (mitre.isLoading) return <div className="page"><PageHeader title="MITRE ATT&CK" /><Loading rows={8} /></div>;
  if (mitre.isError) return <div className="page"><PageHeader title="MITRE ATT&CK" /><Panel><ErrorState error={mitre.error} /></Panel></div>;
  const m = mitre.data!;
  const sel = m.techniques.find((r) => r.technique === pick);
  const counts = m.techniques.reduce<Record<string, number>>((a, r) => ({ ...a, [r.status]: (a[r.status] ?? 0) + 1 }), {});
  return (
    <div className="page">
      <PageHeader title="MITRE ATT&CK" lede={<>Coverage of the {m.total_techniques} techniques in ATT&amp;CK Enterprise v{m.attack_version}, validated against MITRE's STIX dataset. Only techniques a rule can map, or a known gap, are listed. This is not a claim to detect the framework.</>} />
      <Panel>
        <div className="row" role="group" aria-label="Filter by coverage">
          <button className="btn" aria-pressed={filter === ""} onClick={() => setFilter("")}>All ({m.techniques.length})</button>
          {(Object.keys(STATUS) as MitreRow["status"][]).map((k) => (
            <button key={k} className="btn" aria-pressed={filter === k} onClick={() => setFilter(k)} title={STATUS[k].help}>
              {STATUS[k].label} ({counts[k] ?? 0})
            </button>
          ))}
        </div>
      </Panel>
      <div className="grid-2">
        <Panel title="By tactic" id="matrix">
          {grouped.length === 0 ? <Empty title="No technique in this group" /> : (
            <div className="tactics">
              {grouped.map(({ tactic, rows }) => (
                <div className="tactic" key={tactic.id}>
                  <h3>{tactic.name} <span className="muted mono">{tactic.id}</span></h3>
                  {rows.map((r) => (
                    <button key={r.technique} className={`tech cov-${r.status}`} aria-pressed={pick === r.technique} onClick={() => setPick(r.technique)}>
                      <span className="tid">{r.technique}</span> {r.name}
                      <div className="small muted">{STATUS[r.status].label}{r.evidence_observed + r.evidence_candidate ? ` · ${plural(r.evidence_observed + r.evidence_candidate, "event")}` : ""}</div>
                    </button>
                  ))}
                </div>
              ))}
            </div>
          )}
        </Panel>
        <Panel title={sel ? `${sel.technique} ${sel.name}` : "Technique detail"} id="detail">
          {!sel ? <p className="small muted">Choose a technique to see the rules, tests and evidence behind its status.</p> : (
            <div className="stack">
              <p className="small">{STATUS[sel.status].help}</p>
              <KV rows={[
                ["Tactics", sel.tactics.map(words).join(", ")],
                ["Decoys", sel.services.map((s) => SERVICE_LABEL[s] ?? s).join(", ") || null],
                ["Rules", sel.rules.length ? sel.rules.join(", ") : "none"],
                ["Rules with tests", sel.rules_tested.length ? sel.rules_tested.join(", ") : "none"],
                ["Events (observed)", sel.evidence_observed],
                ["Events (rule candidate)", sel.evidence_candidate],
                ["Alerts", sel.alerts],
                ["Reference", sel.url && <a href={sel.url} target="_blank" rel="noreferrer noopener">attack.mitre.org</a>],
              ]} />
              {sel.gap_reason && <p className="notice">{sel.gap_reason}</p>}
              {sel.evidence_observed + sel.evidence_candidate > 0 && <Link className="btn" to={`/events?technique=${sel.technique}`}>Show the events</Link>}
              {rules.data?.rules.filter((r) => sel.rules.includes(r.rule_id)).map((r) => (
                <div className="slip kind-rule" key={r.rule_id}>
                  <div className="slip-top"><span className="slip-id">{r.rule_id}</span></div>
                  <div className="slip-title">{r.name}</div>
                  <div className="slip-det">{r.logic}<br />Tests: {r.tested_by.map((t) => `${t.path.split("/").pop()} (${t.kind})`).join(", ")}</div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
      <p className="small muted">Source: {m.source}, modified {m.modified?.slice(0, 10)}. AI explanations never add a mapping here.</p>
    </div>
  );
}
