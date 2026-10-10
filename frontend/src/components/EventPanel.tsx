import { useEffect, useRef, useState } from "react";
import { getEvent, getRecords, approveProtection, undoProtection } from "../lib/api";
import { eventStatus, eventProgress } from "../lib/eventStatus";
import { useAuth } from "../lib/auth";
import type { RecordRow, TelemetryRow } from "../lib/api";

export function EventPanel({id, onClose, demo = false}: {id: string; onClose: () => void; demo?: boolean}) {
  const {user} = useAuth();
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState("");
  const [event, setEvent] = useState<TelemetryRow | null>(null);
  const [verdict, setVerdict] = useState<RecordRow | null>(null);
  const [error, setError] = useState("");
  const close = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement;
    close.current?.focus();
    return () => previous?.focus();
  }, []);
  useEffect(() => {
    let active = true;
    const refresh = async () => {
      try { const row = await getEvent(id, demo); if (active) {setEvent(row); setError("");} }
      catch {
        if (demo) {if (active) setError("This simulation event is unavailable."); return;}
        try {const data = await getRecords({event_id: id}); if (active) {setVerdict(data.rows[0] ?? null); setError(data.rows.length ? "" : "Event details are unavailable.");}}
        catch {if (active) setError("Could not load event details.");}
      }
    };
    setEvent(null); setVerdict(null); void refresh();
    const timer = setInterval(() => void refresh(), 1000);
    return () => {active = false; clearInterval(timer);};
  }, [id, demo]);
  async function act(actionId?: string) {
    const target = event?.protection_proposal?.target;
    if (!window.confirm(actionId ? "Remove this Arbiter firewall block?" : `Block all inbound and outbound connections to ${target} on this PC for five minutes? Review the evidence first; legitimate connections to that address will also stop.`)) return;
    setBusy(true); setActionError("");
    try {if (actionId) await undoProtection(actionId); else await approveProtection(id); setEvent(await getEvent(id));}
    catch (e) {setActionError(e instanceof Error ? e.message : "Response failed.");}
    finally {setBusy(false);}
  }
  const analysis = event?.analysis ?? verdict;
  const status = event ? eventStatus(event) : verdict ? verdict.decision === "escalate" ? "Alerted · escalated for review" : "Suppressed" : "Loading…";
  return <div className="fixed inset-0 z-50 flex justify-end bg-black/60" onMouseDown={e => {if (e.target === e.currentTarget) onClose();}}>
    <section role="dialog" aria-modal="true" aria-label="Event details" className="flex h-full w-full max-w-2xl flex-col gap-4 overflow-y-auto border-l border-neutral-700 bg-neutral-950 p-6 text-neutral-100" onKeyDown={e => {
      if (e.key === "Escape") onClose();
      if (e.key === "Tab") {const nodes = e.currentTarget.querySelectorAll<HTMLElement>('button, a, summary, input, select, [tabindex="0"]'); const first = nodes[0], last = nodes[nodes.length - 1]; if (e.shiftKey && document.activeElement === first) {e.preventDefault(); last?.focus();} else if (!e.shiftKey && document.activeElement === last) {e.preventDefault(); first?.focus();}}
    }}>
      <div className="flex items-center justify-between gap-3"><h2 className="text-lg">{demo ? "Simulation event" : "Event details"}</h2><button ref={close} onClick={onClose} className="rounded border border-neutral-600 px-3 py-2">Close</button></div>
      <p className="break-all text-xs text-neutral-400">Event ID: {id}</p>
      {error ? <p role="alert">{error}</p> : !event && !verdict ? <p role="status">Loading…</p> : <>
        <h3>{event?.event.event_type ?? verdict?.signature} · {event?.event.hostname ?? verdict?.host}</h3>
        <p className="text-sm text-sky-300">{status}</p>{event && <p className="text-xs text-neutral-400">{eventProgress(event)}</p>}
        {event && <p className="text-xs text-neutral-400">Source: {event.event.source_type}<br/>Occurred: {new Date(event.event.timestamp).toLocaleString()}<br/>Received: {new Date(event.event.received_at).toLocaleString()}</p>}
        <h3 className="font-medium">Analysis</h3><p className="text-sm">{analysis?.rationale ?? event?.error ?? "Waiting for analysis."}</p>
        {analysis && <><p className="text-xs text-neutral-400">{analysis.tier === "llm" ? user?.backend === "mock" ? "Test reasoning heuristic" : "Local AI reasoning" : analysis.tier} · Score {analysis.score.toFixed(1)}</p><p className="text-sm">{analysis.evidence}</p></>}
        <h3 className="font-medium">Response</h3>
        <p className="text-sm text-neutral-400">{demo ? "Simulation only. No changes are made to your device." : event?.protection_actions?.some(a => a.status === "executed") ? "Approved firewall response recorded below." : "An alert is a detection decision. Review response status below."}</p>
        {actionError && <p role="alert" className="text-amber-300">{actionError}</p>}
        {!demo && event?.protection_proposal && <div className="rounded border border-amber-800 p-3 text-sm"><p>Awaiting approval: block {event.protection_proposal.target} for {event.protection_proposal.minutes} minutes.</p><p className="mt-2 text-xs text-neutral-400">{event.protection_proposal.reason}</p>{user?.role === "admin" && <button disabled={busy || event.protection_actions?.some(a => ["executed", "pending"].includes(a.status))} className="mt-3 rounded border border-neutral-600 px-3 py-2 disabled:opacity-40" onClick={() => void act()}>Approve temporary block</button>}</div>}
        {event?.protection_actions?.map(action => <div key={action.id} className="rounded border border-neutral-700 p-3 text-sm">{action.status} · {action.target}<p className="text-xs text-neutral-400">Approved by {action.actor} · Cleanup scheduled for {new Date(action.expires_at).toLocaleString()}{action.status === "expiry_due" ? " · Scheduled expiry is due; removal has not been verified by Arbiter." : ""}</p>{user?.role === "admin" && ["executed", "expiry_due", "failed", "pending"].includes(action.status) && <button disabled={busy} className="mt-2 rounded border border-neutral-600 px-3 py-2" onClick={() => void act(action.id)}>Undo block</button>}</div>)}
        {demo && event?.analysis && !event.analysis.responses?.length && <p className="text-sm text-neutral-400">No protective response selected for this event.</p>}
        {demo && event && !event.analysis && <p className="text-sm text-neutral-400">No simulated response recorded yet.</p>}
        {event?.analysis?.responses?.map((r, i) => <p key={i} className="rounded border border-neutral-700 p-3 text-sm">{r.status}: {r.kind} · {r.target}<br/>{r.reason}</p>)}
        <details open><summary className="cursor-pointer">Event record</summary><pre className="mt-2 overflow-auto rounded bg-neutral-900 p-3 text-xs">{JSON.stringify(event ? {...event.event, raw_event: undefined} : JSON.parse(verdict?.detail ?? "{}"), null, 2)}</pre></details>
        {event && <><details><summary className="cursor-pointer">Original payload</summary><pre className="mt-2 overflow-auto rounded bg-neutral-900 p-3 text-xs">{JSON.stringify(event.event.raw_event, null, 2)}</pre></details><p className="text-xs">Related events: {event.related.join(", ") || "None"}</p></>}
      </>}
    </section>
  </div>;
}
