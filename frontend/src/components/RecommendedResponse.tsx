import {useEffect, useState} from "react";
import {controlResponse, getEvent} from "../lib/api";
import type {TelemetryRow} from "../lib/api";
import {publicDemoApi} from "../lib/publicDemo";

const button = "rounded border border-neutral-600 px-3 py-2 text-sm focus-visible:ring-2 focus-visible:ring-sky-400 disabled:opacity-40";

export function RecommendedResponse({event, admin, demo, publicDemo, onUpdate, onApprove}: {
  event: TelemetryRow; admin: boolean; demo: boolean; publicDemo: boolean;
  onUpdate: (event: TelemetryRow) => void; onApprove: () => void;
}) {
  const [now, setNow] = useState(Date.now() / 1000);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [reason, setReason] = useState("");
  const [protectedNetworks, setProtectedNetworks] = useState("");
  useEffect(() => {const timer = setInterval(() => setNow(Date.now() / 1000), 1000); return () => clearInterval(timer);}, []);
  const review = event.response_case;
  const guidance = event.analysis?.guidance;
  const seconds = review?.deadline == null ? null : Math.max(0, Math.ceil(review.deadline - now));
  const countdown = seconds === null ? "No automatic deadline" : seconds ? `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")} remaining` : "Deadline passed";
  const closed = !!review && !["pending", "overdue"].includes(review.state);
  async function command(value: string) {
    if (value === "schedule" && !window.confirm(publicDemo ? "Approve this recommendation automatically at the deadline in simulation only? This changes browser demo state, not your device." : demo ? "Pre-authorize a simulated five-minute peer block at this deadline? Your device will not be changed." : `Pre-authorize a five-minute block of ${event.protection_proposal?.target} at this deadline? All connections to that peer will stop if fresh evidence and native checks still pass. Review protected service and management networks first.`)) return;
    if (["stop", "resume", "undo"].includes(value) && !window.confirm(value === "undo" ? publicDemo ? "Undo this simulated response? No device was changed." : "Undo this temporary block? This cannot restore interrupted connections." : value === "stop" ? "Cancel all pending timed actions? Existing blocks keep their expiry; use Undo to release them." : "Allow new timed-action enrollments? Cancelled schedules will not restart.")) return;
    setBusy(true); setError("");
    try {
      if (publicDemo) await publicDemoApi.controlResponse(event.event_id, value, reason);
      else await controlResponse(event.event_id, value, demo, reason, protectedNetworks.split(/[\s,]+/).filter(Boolean));
      onUpdate(await (publicDemo ? publicDemoApi.getEvent(event.event_id) : getEvent(event.event_id, demo))); setReason("");
    } catch (e) {setError(e instanceof Error ? e.message : "Could not update response.");}
    finally {setBusy(false);}
  }
  if (event.analysis?.decision !== "escalate") return null;
  return <section aria-label="Recommended next steps" className="space-y-4 border-t border-neutral-700 pt-4 text-sm">
    <h3 className="font-medium">Recommended next steps</h3>
    {guidance ? <><p className="text-xs text-neutral-400">{guidance.source === "model" ? "AI-suggested guidance" : "Policy-guided investigation"}</p><ol className="list-decimal space-y-2 pl-5">{guidance.steps.map((step, index) => <li key={index}>{step}</li>)}</ol><p className="text-xs text-neutral-400">{guidance.caution}</p></> : <p className="text-neutral-400">Verify the original evidence, check whether this activity was authorized, and record what you found. No AI next-step advice was recorded.</p>}
    <details><summary className="cursor-pointer text-sky-300">Take action manually</summary><p className="mt-2 text-neutral-300">Use the steps above in your approved security tools. Confirm the device, account and peer before making a change. Record your findings below. Opening these instructions executes nothing.</p></details>
    {event.protection_proposal && !demo && <div className="space-y-2"><p>Supported response: block <strong className="break-all">{event.protection_proposal.target}</strong> for five minutes.</p><p className="text-xs text-neutral-400">All connections to this address will stop. The model cannot select an arbitrary command. Undo removes the block, but cannot restore interrupted sessions.</p>{admin && <button className={button} disabled={busy || event.protection_actions?.some(a => ["pending", "executed", "cleanup_failed"].includes(a.status))} onClick={onApprove}>Approve temporary block now</button>}</div>}
    {review && <div className="space-y-3 border-l-2 border-amber-700 pl-3">
      <p className="font-medium">{review.severity} severity · {review.state.replaceAll("_", " ")}</p>
      {review.state === "pending" && <p role="timer" aria-label="Review deadline">{countdown}</p>}
      {review.deadline != null && <p className="text-xs text-neutral-400">Deadline: {new Date(review.deadline * 1000).toLocaleString()}. Severity comes from source severity and deterministic findings, not model confidence.</p>}
      <p>{review.note}</p>
      {review.state === "pending" && review.deadline !== null && <p className="text-xs text-neutral-400">{review.mode === "automatic" ? publicDemo ? "At expiry: record approval in this browser simulation only. No native operation is executed." : "At expiry: attempt only the explicitly pre-authorized peer block after fresh evidence and policy checks." : "At expiry: mark overdue for operator review. No device changes are authorized."}</p>}
      {demo && <p className="text-amber-300">Simulation only. Timers and response approvals cannot change your device.</p>}
      {review.expires_at && review.state === "executed" && <p>{publicDemo ? "Simulation expiry" : "Block expiry"}: {new Date(review.expires_at * 1000).toLocaleString()}{now >= review.expires_at ? publicDemo ? " · Simulation expired" : " · Expiry due; inspect the action record for verified removal." : ""}</p>}
      {publicDemo && <p className="text-xs text-neutral-400">Demo review state lives only in this browser session and resets on refresh. Background tabs can delay timer updates.</p>}
      {admin && <>
        {!closed && <><label className="flex flex-col gap-2">Review findings or deferral reason<textarea className="rounded border border-neutral-600 bg-neutral-900 p-2" rows={2} maxLength={1000} value={reason} onChange={e => setReason(e.target.value)} /></label><div className="flex flex-wrap gap-2"><button className={button} disabled={busy || !reason.trim()} onClick={() => void command("reviewed")}>Mark reviewed</button><button className={button} disabled={busy || !reason.trim()} onClick={() => void command("reject")}>Reject response</button><button className={button} disabled={busy || !reason.trim() || review.deferred || !seconds || review.state !== "pending"} onClick={() => void command("defer")}>Defer once</button></div></>}
        {!closed && review.state === "pending" && !!seconds && !event.response_stopped && event.response_schedule_available && <details><summary className="cursor-pointer text-amber-300">{publicDemo ? "Schedule a simulated response" : "Pre-authorize action at the deadline"}</summary><p className="mt-2 text-xs text-neutral-400">{publicDemo ? "This records the recommendation as approved when the demo deadline passes. It does not perform the recommended operation or contact any device." : "Only eligible repeated-login or verified malware/network correlations can schedule a temporary IP block. This is a separate approval for this incident; an alert alone grants no authority."}</p>{!demo && <label className="mt-3 flex flex-col gap-2">Protected management and service networks (CIDRs)<input placeholder="Enter your actual protected networks" className="rounded border border-neutral-600 bg-neutral-900 p-2" value={protectedNetworks} onChange={e => setProtectedNetworks(e.target.value)} /><span className="text-xs text-neutral-400">Required. Include remote administration and critical dependencies. A protected address cannot be blocked.</span></label>}<button className={`${button} mt-3`} disabled={busy || review.mode === "automatic" || (!demo && (!event.protection_proposal || !protectedNetworks.trim()))} onClick={() => void command("schedule")}>{publicDemo ? "Schedule simulated response" : demo ? "Schedule simulated block" : "Approve block at deadline"}</button></details>}
        {!event.response_schedule_available && !closed && <p className="text-xs text-neutral-400">No eligible timed device action for this alert. Follow the investigation steps and record your review.</p>}
        {demo && ["executed", "needs_review"].includes(review.state) && <button className={button} disabled={busy} onClick={() => void command("undo")}>{publicDemo ? "Undo simulated response" : "Undo simulated block"}</button>}
        <button className={button} disabled={busy} onClick={() => void command(event.response_stopped ? "resume" : "stop")}>{event.response_stopped ? "Allow new timed actions" : "Stop all pending timed actions"}</button>
      </>}
    </div>}
    {event.response_workflow_error && <p role="alert" className="text-amber-300">{event.response_workflow_error}</p>}
    {error && <p role="alert" className="text-amber-300">{error}</p>}
  </section>;
}
