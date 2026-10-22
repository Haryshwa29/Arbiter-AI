import { useEffect, useState } from "react";
import { Link } from "react-router";
import { getDay, getSummary, getRecords, parseDetail } from "../lib/api";
import type { DayBucket, SummaryResponse, RecordRow } from "../lib/api";
import { DASH_BASE } from "../lib/routing";
import { EventPanel } from "../components/EventPanel";
import { VolumeChart } from "../components/VolumeChart";
import { SignalMap, DecisionRing } from "../components/SignalMap";

export function Overview() {
  const [recent, setRecent] = useState<RecordRow[]>([]);
  const [eventId, setEventId] = useState<string | null>(null);
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [buckets, setBuckets] = useState<DayBucket[]>([]);
  const [hours, setHours] = useState<24 | 72 | 168>(24);
  const [error, setError] = useState("");
  const [updated, setUpdated] = useState("");
  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    async function refresh() {
      try {
        const [stats, day, records] = await Promise.all([getSummary(), getDay(hours), getRecords({limit: 100})]);
        if (active) {setSummary(stats); setBuckets(day.buckets); setRecent(records.rows); setError(""); setUpdated(new Date().toLocaleTimeString());}
      } catch {if (active) setError("Could not refresh analytics. Displayed values may be from the last successful update.");}
      if (active) timer = setTimeout(() => void refresh(), 5000);
    }
    void refresh();
    return () => {active = false; clearTimeout(timer);};
  }, [hours]);
  const suppressed = buckets.reduce((n, b) => n + b.suppressed, 0);
  const escalated = buckets.reduce((n, b) => n + b.escalated, 0);
  const total = suppressed + escalated;
  const share = summary?.today.today ? Math.round(summary.today.prefilter / summary.today.today * 100) : null;
  return <div className="overview-premium">
    <header className="overview-heading"><div><p className="eyebrow">SECURITY, IN PERSPECTIVE</p><h1>Your environment.<br/><span>Clarity in every signal.</span></h1><p>A clear view of the signals, the reasoning, and what needs you.</p></div><div className="overview-status"><span className="dot quiet-dot"/> {error ? "Refresh interrupted" : updated ? "Analytics connected" : "Connecting"}<small>{updated ? `Last updated ${updated}` : "Loading local records"}</small><Link to={`${DASH_BASE}/live`}>Open live workspace ↗</Link></div></header>
    {error && <p role="alert" className="text-sm text-amber-300">{error} Retrying automatically.</p>}
    <section className="metric-grid" aria-label="Today's security metrics">
      {[{label: "Events triaged", value: summary?.today.today, note: "Today · completed verdicts", color: "gold"}, {label: "Escalated for review", value: summary?.today.escalated, note: "Today · alerts, not actions", color: "coral"}, {label: "Prefilter share", value: share === null ? undefined : `${share}%`, note: "Today · deterministic decisions", color: "blue"}, {label: "Lifetime triaged", value: summary?.lifetime.triaged, note: "All recorded verdicts", color: "mint"}].map(metric => <article key={metric.label} className={`premium-panel metric metric-${metric.color}`}><p>{metric.label}</p><strong>{metric.value ?? "—"}</strong><span>{metric.note}</span></article>)}
    </section>
    <SignalMap events={recent.map(row => ({id: row.event_id, source: parseDetail(row)?.source || "Unknown", decision: row.decision}))} onInspect={setEventId}/>
    <div className="analytics-grid">
      <section className="premium-panel chart-panel"><div className="panel-heading"><div><p className="eyebrow">THE BIGGER PICTURE</p><h2>Signal volume</h2></div><div className="window-tabs" aria-label="Analytics time window">{([24,72,168] as const).map(h => <button key={h} aria-pressed={hours === h} onClick={() => {setHours(h); setBuckets([]);}}>{h === 168 ? "7d" : `${h}h`}</button>)}</div></div><p className="chart-summary"><strong>{total.toLocaleString()}</strong> verdicts in the selected window</p><VolumeChart buckets={buckets}/></section>
      <section className="premium-panel mix-panel"><p className="eyebrow">DECISION BALANCE</p><h2>Attention, where it matters</h2><DecisionRing suppressed={suppressed} escalated={escalated}/><div className="mix-legend"><span><i className="dot quiet-dot"/> Suppressed <strong>{suppressed}</strong></span><span><i className="dot alert-dot"/> Escalated <strong>{escalated}</strong></span></div><p className="text-xs text-neutral-400">Selected {hours === 168 ? "7-day" : `${hours}-hour`} window · suppression is a verdict, not a guarantee of safety.</p></section>
    </div>
    <div className="analytics-grid">
      <section className="premium-panel recent-panel"><div className="panel-heading"><div><p className="eyebrow">FROM SIGNAL TO EXPLANATION</p><h2>Latest decisions</h2></div><Link to={`${DASH_BASE}/audit`}>View audit ↗</Link></div>{recent.slice(0,5).map(row => <button key={row.id} className="decision-row" onClick={() => setEventId(row.event_id)}><span className={`decision-badge ${row.decision}`}>{row.decision === "escalate" ? "REVIEW" : "QUIET"}</span><span><strong>{row.host}</strong><small>{row.signature}</small><p>{row.rationale}</p></span><span className="row-arrow">↗</span></button>)}{!recent.length && <p className="empty-copy">{updated ? "No recorded decisions yet. Enable a data source to begin." : "Loading recent decisions…"}</p>}</section>
      <section className="premium-panel tier-panel"><p className="eyebrow">HOW DECISIONS WERE REACHED</p><h2>Analysis paths</h2><p className="text-xs text-neutral-400">Latest {recent.length} verdicts · independent of chart window</p>{[{id:"prefilter", name:"Deterministic screening",color:"#82b5f4"},{id:"llm", name:"Model analysis",color:"#b1a3ef"},{id:"guardrail", name:"Security guardrails",color:"#dcc080"}].map(t => {const count = recent.filter(r => r.tier === t.id).length;return <div className="tier-item" key={t.id}><div><span>{t.name}</span><strong>{count}</strong></div><div className="tier-track"><span style={{width:`${recent.length ? count/recent.length*100 : 0}%`, background:t.color}}/></div></div>;})}<p className="empty-copy">Open a decision to inspect its evidence, model provenance and recommended next steps.</p></section>
    </div>
    {eventId && <EventPanel id={eventId} onClose={() => setEventId(null)}/>}
  </div>;
}
