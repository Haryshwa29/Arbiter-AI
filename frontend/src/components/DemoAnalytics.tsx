import type { TelemetryRow } from "../lib/api";
import { DecisionRing } from "./SignalMap";

export function DemoAnalytics({events, delivered, completed}: {events: TelemetryRow[]; delivered: number; completed: number}) {
  const suppressed = events.filter(e => e.analysis?.decision === "suppress").length;
  const escalated = events.filter(e => e.analysis?.decision === "escalate").length;
  return <section className="demo-analytics" aria-label="Simulation analytics">
    <div className="metric-grid">
      {[{label:"Delivered",value:delivered,color:"gold"},{label:"Processed",value:completed,color:"blue"},{label:"Awaiting analysis",value:events.filter(e => !e.analysis && e.state !== "failed").length,color:"mint"},{label:"Analysis failures",value:events.filter(e => e.state === "failed").length,color:"coral"}].map((m,i) => <article key={m.label} className={`premium-panel metric metric-${m.color}`}><p>{m.label}</p><strong>{m.value.toLocaleString()}</strong><span>{i < 2 ? "Entire simulation run" : `Latest ${events.length} arrivals`}</span></article>)}
    </div>
    <div className="analytics-grid">
      <section className="premium-panel tier-panel"><p className="eyebrow">DECISION PATHS</p><h2>How the sample was analyzed</h2><p className="text-xs text-neutral-400">Latest {events.length} arrivals · pending events have no decision yet</p>{[{id:"prefilter",name:"Deterministic screening",color:"#82b5f4"},{id:"llm",name:"Model review / fallback",color:"#b1a3ef"},{id:"guardrail",name:"Security guardrails",color:"#dcc080"}].map(t => {const n=events.filter(e => e.analysis?.tier === t.id).length;return <div className="tier-item" key={t.id}><div><span>{t.name}</span><strong>{n}</strong></div><div className="tier-track"><span style={{width:`${events.length ? n/events.length*100 : 0}%`,background:t.color}}/></div></div>;})}<p className="empty-copy">Inspect an event for its evidence and actual AI provenance. Policy fallback is never counted as a successful AI request.</p></section>
      <section className="premium-panel mix-panel"><p className="eyebrow">SIMULATED DECISIONS</p><h2>Decision balance</h2><DecisionRing suppressed={suppressed} escalated={escalated}/><div className="mix-legend"><span><i className="dot quiet-dot"/>Suppressed<strong>{suppressed}</strong></span><span><i className="dot alert-dot"/>Escalated<strong>{escalated}</strong></span></div><p className="text-xs text-neutral-400">Completed verdicts among the latest {events.length} arrivals. These are sample events, not your device's security status.</p></section>
    </div>
  </section>;
}
