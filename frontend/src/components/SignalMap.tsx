import { useEffect, useRef, useState } from "react";
import type { CSSProperties } from "react";

export interface SignalEvent { id: string; source: string; decision?: string; }

/** A conceptual pipeline, not a geographic or network-topology claim. */
export function SignalMap({ events, demo = false, onInspect }: { events: SignalEvent[]; demo?: boolean; onInspect?: (id: string) => void }) {
  const seen = useRef<Set<string> | null>(null);
  const [pulses, setPulses] = useState<SignalEvent[]>([]);
  const [paused, setPaused] = useState(false);
  const [selected, setSelected] = useState("");
  const sources = [...new Set(events.map(e => e.source || "Unknown"))].slice(0, 5);
  const source = sources.includes(selected) ? selected : sources[0];
  const matches = events.filter(e => e.source === source);
  useEffect(() => {
    const incoming = seen.current ? events.filter(e => !seen.current!.has(e.id)) : [];
    seen.current = new Set(events.map(e => e.id));
    if (!incoming.length) return;
    setPulses(incoming.slice(0, 8));
  }, [events]);
  useEffect(() => {
    if (!pulses.length) return;
    const timer = setTimeout(() => setPulses([]), 2600);
    return () => clearTimeout(timer);
  }, [pulses]);
  return <section className={`signal-map premium-panel ${demo ? "signal-demo" : ""} ${paused ? "motion-paused" : ""}`} aria-label={demo ? "Simulation signal flow" : "Device signal flow"}
    onPointerMove={e => {const r = e.currentTarget.getBoundingClientRect(); e.currentTarget.style.setProperty("--pointer-x", `${e.clientX-r.left}px`); e.currentTarget.style.setProperty("--pointer-y", `${e.clientY-r.top}px`);}}>
    <div className="panel-heading"><div><p className="eyebrow">{demo ? "SIMULATION / ISOLATED" : "SIGNAL INTELLIGENCE"}</p><h2>{demo ? "A rehearsal in motion" : "Every signal. A considered decision."}</h2></div><button className="quiet-button" aria-pressed={paused} onClick={() => setPaused(!paused)}>{paused ? "Resume motion" : "Pause motion"}</button></div>
    <div className="signal-stage">
      <svg viewBox="0 0 900 240" preserveAspectRatio="none" aria-hidden="true" className="signal-paths">
        {sources.map((_, i) => <path key={i} d={`M 135 ${120+(i-(sources.length-1)/2)*43} C 310 ${120+(i-(sources.length-1)/2)*43}, 300 120, 450 120`} />)}
        <path d="M450 120 C610 120 610 65 765 65"/><path d="M450 120 C610 120 610 175 765 175"/>
        {!paused && pulses.map((event, i) => <circle className="signal-packet" key={event.id} r={demo ? "4" : "3"} fill={demo ? "#dfbf79" : "#85bdff"}><animateMotion dur={demo ? "2.1s" : "1.4s"} begin={`${i*.04}s`} calcMode="spline" keyTimes="0;1" keySplines={demo ? ".35 0 .2 1" : "0 0 1 1"} fill="freeze" path={`M135 ${120+(Math.max(0,sources.indexOf(event.source))-(sources.length-1)/2)*43} C310 ${120+(Math.max(0,sources.indexOf(event.source))-(sources.length-1)/2)*43} 300 120 450 120${event.decision ? ` C610 120 610 ${event.decision === "escalate" ? 65 : 175} 765 ${event.decision === "escalate" ? 65 : 175}` : ""}`}/></circle>)}
      </svg>
      <div className="signal-sources">{sources.length ? sources.map(s => <button key={s} aria-pressed={source === s} onClick={() => setSelected(s)}>{s}<span>{events.filter(e => e.source === s).length}</span></button>) : <span className="text-sm text-neutral-400">Awaiting sources</span>}</div>
      <div className="signal-core"><div className="core-orbit"/><span className="core-symbol">A</span><strong>ARBITER</strong><span>Context → decision</span></div>
      <div className="signal-outcomes"><div><i className="dot alert-dot"/> Escalated<strong>{events.filter(e => e.decision === "escalate").length}</strong></div><div><i className="dot quiet-dot"/> Suppressed<strong>{events.filter(e => e.decision === "suppress").length}</strong></div></div>
    </div>
    <div className="signal-footer"><p>{source ? <><strong>{source}</strong> · {matches.length} in this view</> : "Waiting for event data"}<span>Latest {events.length} records · {events.filter(e => !e.decision).length} without a verdict</span><span>Conceptual flow · pulses indicate new arrivals · up to 5 sources shown</span></p>{matches[0] && onInspect && <button className="quiet-button" onClick={() => onInspect(matches[0].id)}>Inspect latest ↗</button>}</div>
  </section>;
}

export function DecisionRing({ suppressed, escalated }: { suppressed: number; escalated: number }) {
  const total = suppressed + escalated;
  const percent = total ? Math.round(suppressed / total * 100) : 0;
  return <div className={`decision-ring ${total ? "" : "ring-empty"}`} style={{"--share": `${total ? percent : 0}%`} as CSSProperties} role="img" aria-label={`${suppressed} suppressed and ${escalated} escalated`}><div><strong>{total ? `${percent}%` : "—"}</strong><span>{total ? "suppressed" : "no verdicts"}</span></div></div>;
}
