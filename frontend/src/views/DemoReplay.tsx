import { Fragment, useEffect, useState } from "react";
import * as dashboardApi from "../lib/api";
import { ApiError } from "../lib/api";
import { publicDemoApi } from "../lib/publicDemo";
import type { DemoStatus, ImportSummary, TelemetryRow } from "../lib/api";
import { useOptionalAuth } from "../lib/auth";
import { EventPanel } from "../components/EventPanel";

import { eventStatus, eventProgress } from "../lib/eventStatus";

const control = "rounded border border-neutral-600 bg-neutral-900 px-3 py-2 text-sm focus-visible:ring-2 focus-visible:ring-sky-500 disabled:opacity-40";

function matchesHistory(row: TelemetryRow, filters: Record<string, string>) {
  const decision = row.state === "failed" ? "failed" : row.analysis?.decision ?? "pending";
  if (filters.decision && filters.decision !== decision) return false;
  for (const [key, field] of [["event_type", "event_type"], ["host", "hostname"], ["source", "source_type"]]) {
    if (filters[key] && !String(row.event[field]).toLowerCase().includes(filters[key].toLowerCase())) return false;
  }
  const response = row.analysis?.responses?.length ? "selected" : row.analysis ? "none" : "pending";
  if (filters.response && filters.response !== response) return false;
  return !filters.search || JSON.stringify([row.event, row.analysis]).toLowerCase().includes(filters.search.toLowerCase());
}

function InferenceStatus({session}: {session: DemoStatus | null}) {
  return <section className="rounded-lg border border-purple-800 p-4" aria-label="Live AI service">
      <p className="font-medium">{session?.inference?.model === "nemotron-3-nano:30b" ? "Nemotron 3 Nano · 30B" : session?.inference?.model ?? "Nemotron"} · Ollama Cloud</p>
      <p className="mt-2 text-sm" role="status">{!session?.inference ? "Checking AI configuration…" : session.inference.backend === "mock" ? "Test service: no AI model is connected" : !session.inference.configured ? "AI unavailable: the website operator must configure the cloud API key" : session.inference.active ? "Analyzing an event now…" : "Cloud AI configured · rules and context decide when model review is needed"}</p>
      {session?.inference?.succeeded !== undefined && <p className="mt-2 text-xs text-neutral-400">AI requests in this run: {session.inference.succeeded} successful · {session.inference.failed ?? 0} failed. Configuration alone does not confirm a working connection.</p>}
      {session?.inference?.error && <p role="alert" className="mt-2 text-sm text-amber-300">{session.inference.error}</p>}
      <p className="mt-2 text-xs text-neutral-400">Security rules run first. Ambiguous events receive asset context, scoped demo facts and verified session history before live AI analysis. Open an event to see its decision tier and evidence. This browser demo does not collect device activity or execute responses.</p>
    </section>;
}

export function DemoReplay({publicDemo = false}: {publicDemo?: boolean}) {
  const auth = useOptionalAuth();
  const user = publicDemo ? {role: "admin", backend: "mock"} : auth?.user;
  const {controlDemo, getDatasets, getDemo, startDemo, previewDemo, getDemoHistory} = publicDemo ? publicDemoApi : dashboardApi;
  const [preview, setPreview] = useState<ImportSummary[] | null>(null);
  const [datasets, setDatasets] = useState<string[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [cloudConsent, setCloudConsent] = useState(false);
  const [files, setFiles] = useState<File[]>([]);
  const [speed, setSpeed] = useState("1x");
  const [order, setOrder] = useState("mixed");
  const [seed, setSeed] = useState(0);
  const [session, setSession] = useState<DemoStatus | null>(null);
  const [history, setHistory] = useState(false);
  const [historyRows, setHistoryRows] = useState<TelemetryRow[]>([]);
  const [historyFilters, setHistoryFilters] = useState<Record<string, string>>({});
  const [historyTotal, setHistoryTotal] = useState<number | null>(null);
  const [historyOffset, setHistoryOffset] = useState(0);
  const [workspace, setWorkspace] = useState(false);
  const [detail, setDetail] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    getDatasets().then(r => setDatasets(r.datasets)).catch(e => setError(e instanceof Error ? e.message : "Could not load datasets."));
    let active = true;
    const refresh = async () => {try {const data = await getDemo(); if (active) setSession(data);} catch(e) {if (active) setError(e instanceof Error ? e.message : "Could not read simulation status.");}};
    void refresh(); const timer = setInterval(() => void refresh(), 750);
    return () => {active = false; clearInterval(timer);};
  }, [getDemo, getDatasets]);
  useEffect(() => {
    if (!workspace || !history) return;
    let active = true;
    async function refresh() {
      try {const data = await getDemoHistory(historyOffset, historyFilters); if (active) {setHistoryRows(data.events);setHistoryTotal(data.total ?? null);}}
      catch (error) {
        if (error instanceof ApiError && error.status === 404) {
          try {const data = await getDemo(); if (active) {const matches = data.events.filter(row => matchesHistory(row, historyFilters));setHistoryRows(matches.slice(historyOffset, historyOffset + 100));setHistoryTotal(matches.length);setError("Restart the dashboard server to enable full session history. Showing the latest 100 arrivals.");}}
          catch {if (active) setError("Could not load simulation history.");}
        } else if (active) setError("Could not load simulation history.");
      }
    }
    setHistoryRows([]); void refresh(); const timer = setInterval(() => void refresh(), 1000);
    return () => {active = false; clearInterval(timer);};
  }, [workspace, history, historyOffset, historyFilters, session?.session_id, getDemoHistory, getDemo]);
  function selectDatasets(names: string[]) {setSelected(names);setPreview(null);}
  async function start(validate = false) {
    setBusy(true); setError("");
    try {
      if (!selected.length && !files.length) throw new Error("Select datasets or upload files.");
      if (files.reduce((size, file) => size + file.size, 0) > 5 * 1024 * 1024) throw new Error("Combined upload limit is 5 MiB.");
      const uploads = await Promise.all(files.map(async file => ({filename: file.name, content: await file.text()})));
      if (validate) setPreview((await previewDemo({datasets: selected, uploads})).files);
      else {setSession(await startDemo({datasets: selected, uploads, speed, order, seed, traffic: "steady", cloud_consent: cloudConsent})); setWorkspace(true);setHistory(false);setHistoryOffset(0);setHistoryFilters({});setDetail(null);setPreview(null);}
    } catch (e) {setError(e instanceof Error ? e.message : "Could not start simulation.");}
    finally {setBusy(false);}
  }
  async function action(value: string) {
    setBusy(true);
    try {setSession(await controlDemo(value)); setError("");}
    catch {setError("Could not change simulation state.");}
    finally {setBusy(false);}
  }
  const currentEvents = session?.events ?? [];
  // Refresh the latest page from the same live records, retaining older pages.
  const historyEvents = historyOffset === 0 && !Object.values(historyFilters).some(Boolean)
    ? [...currentEvents, ...historyRows.filter(row => !currentEvents.some(event => event.event_id === row.event_id))].slice(0, 100)
    : historyRows.map(row => currentEvents.find(event => event.event_id === row.event_id) ?? row);
  const filteredHistory = historyEvents.filter(row => matchesHistory(row, historyFilters));
  function changeHistoryFilter(key: string, value: string) {setHistoryFilters({...historyFilters, [key]: value});setHistoryOffset(0);}
  const active = session && ["running", "paused"].includes(session.state);
  return <div className="flex max-w-3xl flex-col gap-5">
    <header><h1 className="text-lg font-medium">Demo & Replay</h1><p className="mt-2 text-sm text-neutral-400">A separate simulation workspace. Demo records never enter real monitoring, its counts, or device responses.</p></header>
    {publicDemo && <InferenceStatus session={session} />}
    {error && <p role="alert" className="text-amber-300">{error}</p>}
    <section className="rounded-lg border border-neutral-700 p-5">
      <h2 className="font-medium">Prepare a demonstration</h2>
      {publicDemo && <p className="mt-2 text-xs text-neutral-400">Cloud AI is used only for this website demo. Arbiter is designed to run locally on your own device and network.</p>}
      <div className="my-4 flex gap-3"><button className={control} onClick={() => selectDatasets(datasets)}>Select all</button><button className={control} onClick={() => selectDatasets([])}>Clear selection</button></div>
      <fieldset className="flex max-h-72 flex-col gap-2 overflow-y-auto"><legend className="mb-2 text-sm">Datasets</legend>{datasets.map(name => <label key={name} className="flex gap-3 text-sm"><input type="checkbox" checked={selected.includes(name)} onChange={e => selectDatasets(e.target.checked ? [...selected, name] : selected.filter(n => n !== name))}/>{name}</label>)}</fieldset>
      <label className="mt-4 flex flex-col gap-2 text-sm">Or add dataset files<input className={control} type="file" multiple accept=".json,.jsonl,.csv" onChange={e => {setFiles(Array.from(e.target.files ?? []));setPreview(null);}}/></label>
      {publicDemo && <label className="mt-3 flex items-start gap-2 text-sm"><input type="checkbox" checked={cloudConsent} onChange={e => setCloudConsent(e.target.checked)} />I understand that selected sample or sanitized events are sent to Ollama Cloud.</label>}
      <p className="mt-2 text-xs text-neutral-400">{publicDemo ? "Cloud demo: at most 500 events per run; shared AI limits may stop large selections. " : ""}Choose your own JSON, JSONL or CSV event files. Up to 5 MiB combined. {publicDemo ? "500" : "5,000"} events per session. Arbitrary documents and executable files are not event datasets.</p>
      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        <label className="flex flex-col gap-2 text-sm">Playback<select className={control} value={speed} onChange={e => setSpeed(e.target.value)}>{["1x", "2x"].map(value => <option key={value}>{value}</option>)}</select></label>
        <label className="flex flex-col gap-2 text-sm">Event order<select className={control} value={order} onChange={e => setOrder(e.target.value)}><option value="mixed">Mix datasets, preserve each sequence</option><option value="random">Shuffle all events</option></select></label>
        <label className="flex flex-col gap-2 text-sm">Random seed<input className={control} type="number" min="0" max="4294967296" value={seed} onChange={e => setSeed(Number(e.target.value))}/></label>
      </div>
      <p className="mt-3 text-xs text-neutral-400">Playback is capped at 2×. Arbiter waits for the current event to finish analysis before delivering another. 1× uses a three-second minimum interval; 2× uses 1.5 seconds. Original timestamps remain available for analysis.</p>
      <div className="mt-4 flex gap-3"><button className={control} disabled={busy || user?.role !== "admin"} onClick={() => void start(true)}>Validate selection</button><button className={control} disabled={busy || !!active || user?.role !== "admin" || (publicDemo && (!session?.inference?.configured || !cloudConsent))} onClick={() => void start(false)}>Start simulation</button>{session?.session_id && <button className={control} onClick={() => setWorkspace(true)}>Open simulation workspace</button>}</div>
    </section>
    {preview && <section aria-label="Dataset validation" className="rounded border border-neutral-700 p-4"><h2 className="mb-3">Selection preview · no events delivered</h2>{preview.map((file, i) => <div key={i} className="mb-2 text-sm">{file.filename}: {file.valid_events} valid · {file.invalid_events} invalid{file.errors.map((error, j) => <p key={j} className="text-xs text-amber-300">{error}</p>)}</div>)}</section>}
    {workspace && <div className="fixed inset-0 z-40 flex justify-end bg-black/60">
      <section role="dialog" aria-modal="true" aria-label="Simulation workspace" className="h-full w-full max-w-5xl overflow-y-auto border-l border-neutral-600 bg-neutral-950 p-6 text-neutral-100" onKeyDown={e => {
          if(e.key === "Escape" && !detail) setWorkspace(false);
          if(e.key === "Tab" && !detail) {const nodes = e.currentTarget.querySelectorAll<HTMLElement>('button:not(:disabled), input, select, [tabindex="0"]'); const first = nodes[0], last = nodes[nodes.length-1]; if(e.shiftKey && document.activeElement === first) {e.preventDefault();last?.focus();} else if(!e.shiftKey && document.activeElement === last) {e.preventDefault();first?.focus();}}
        }}>
        <div className="flex items-center justify-between gap-3"><h2 className="text-lg">Simulation workspace</h2><button autoFocus className={control} onClick={() => setWorkspace(false)}>Close workspace</button></div>
        <p className="mt-2 text-xs text-neutral-400">Analysis engine: {publicDemo ? `${session?.inference?.model ?? "unavailable"} via Ollama Cloud; live AI preview` : user?.backend === "mock" ? "test heuristics; no AI model is connected" : "local AI with deterministic guardrails"}</p>
        <p className="mt-2 text-sm text-amber-300">SIMULATION · Responses are simulated. Your PC is never modified by demo events.</p>
        <p className="mt-4 text-sm" role="status">{session?.state} · {session?.delivered ?? 0} / {session?.total ?? 0} delivered · {session?.completed ?? 0} processed</p>
        <p className="mt-2 text-sm text-neutral-300">{currentEvents.filter(e => e.analysis?.decision === "suppress").length} suppressed · {currentEvents.filter(e => e.analysis?.decision === "escalate").length} escalated for review · {currentEvents.filter(e => !e.analysis && e.state !== "failed").length} awaiting analysis · {currentEvents.filter(e => e.state === "failed").length} failed</p>
        <progress className="mt-2 w-full" max={session?.total || 1} value={session?.delivered ?? 0}/>
        {user?.role === "admin" && <div className="my-4 flex gap-3"><button className={control} disabled={busy || session?.state !== "running"} onClick={() => void action("pause")}>Pause delivery</button><button className={control} disabled={busy || session?.state !== "paused"} onClick={() => void action("resume")}>Resume</button><button className={control} disabled={busy || !active} onClick={() => void action("stop")}>Stop delivery</button></div>}
        <p className="mb-4 text-xs text-neutral-400">Pause and Stop halt new arrivals; analysis already queued can finish. Session history lasts until a new simulation; hosted preview history is also cleared on page refresh.</p>
        {publicDemo && <InferenceStatus session={session} />}
    {error && <p role="alert">{error}</p>}{session?.error && <p role="alert">{session.error}</p>}
        <div className="mb-4 flex flex-wrap gap-3" aria-label="Simulation views"><button className={control} aria-pressed={!history} onClick={() => setHistory(false)}>Live simulation</button><button className={control} aria-pressed={history} onClick={() => {setHistory(true);setHistoryOffset(0);}}>Verdicts & history</button></div>
        <h3 className="mb-2 font-medium">{history ? "Simulation verdicts & history" : "Live simulation timeline"}</h3>
        <p className="mb-4 text-xs text-neutral-400">{history ? "The same events and decisions as Live simulation, with the full recorded reasons and evidence below each row. Pending events update as analysis finishes." : "The latest 20 arrivals, with each decision and response on the same row. Older events are available in Verdicts & history."}</p>
        {history && <section aria-label="Simulation history filters" className="mb-4 rounded border border-neutral-700 p-4">
          <div className="grid gap-3 sm:grid-cols-3">
            <label className="flex flex-col gap-2 text-xs text-neutral-400">Decision<select aria-label="Decision" className={control} value={historyFilters.decision ?? ""} onChange={e => changeHistoryFilter("decision", e.target.value)}><option value="">All decisions</option><option value="suppress">Suppressed</option><option value="escalate">Alerted / escalated</option><option value="pending">Awaiting analysis</option><option value="failed">Analysis failed</option></select></label>
            {[['event_type', 'Event type'], ['source', 'Source'], ['host', 'Host']].map(([key, label]) => <label key={key} className="flex flex-col gap-2 text-xs text-neutral-400">{label}<input aria-label={label} className={control} value={historyFilters[key] ?? ""} placeholder="Any · type to filter" onChange={e => changeHistoryFilter(key, e.target.value)}/></label>)}
            <label className="flex flex-col gap-2 text-xs text-neutral-400">Response<select aria-label="Response" className={control} value={historyFilters.response ?? ""} onChange={e => changeHistoryFilter("response", e.target.value)}><option value="">All responses</option><option value="selected">Simulated response selected</option><option value="none">No protective response</option><option value="pending">Awaiting decision</option></select></label>
            <label className="flex flex-col gap-2 text-xs text-neutral-400">Search events & reasons<input className={control} value={historyFilters.search ?? ""} placeholder="Event ID, evidence, action…" onChange={e => changeHistoryFilter("search", e.target.value)}/></label>
          </div><div className="mt-3 flex items-center gap-3"><button className={control} onClick={() => {setHistoryFilters({});setHistoryOffset(0);}}>Clear filters</button><p role="status" className="text-xs text-neutral-400">{historyTotal === null ? `${filteredHistory.length} shown` : `${historyTotal} matching events`} · filters combine</p></div>
        </section>}
        <div className="overflow-x-auto rounded border border-neutral-700"><table className="w-full table-fixed text-left text-sm"><thead className="bg-neutral-900 text-xs text-neutral-400"><tr><th className="w-1/3 p-3">Incoming event</th><th className="w-1/3 p-3">Decision & reason</th><th className="w-1/3 p-3">Simulated response</th></tr></thead><tbody>{(history ? filteredHistory : currentEvents.slice(0, 20)).map(row => <Fragment key={row.event_id}><tr className="cursor-pointer border-t border-neutral-700 align-top hover:bg-neutral-900" onClick={() => setDetail(row.event_id)}>
          <td className="break-words p-3"><button className="text-left text-sky-300 underline focus-visible:ring-2" onClick={() => setDetail(row.event_id)}>{row.event.event_type} · {row.event.hostname}</button><p className="mt-2 text-xs text-neutral-400">{new Date(row.event.received_at).toLocaleTimeString()}</p><p className="mt-1 break-all text-xs text-neutral-500">{row.event_id}</p></td>
          <td className="break-words p-3"><p className={row.state === "failed" ? "text-amber-300" : row.analysis?.decision === "escalate" ? "text-red-300" : row.analysis ? "text-emerald-300" : "text-sky-300"}>{eventStatus(row)}</p><p className="mt-2 text-xs text-neutral-400">{eventProgress(row)}</p><p className="mt-2 text-xs text-neutral-300">{row.analysis?.rationale ?? (row.error || "Waiting for analysis.")}</p></td>
          <td className="break-words p-3 text-xs">{row.analysis ? row.analysis.responses?.length ? row.analysis.responses.map((response, index) => <div key={index} className="mb-2"><p className="text-amber-300">{response.status === "awaiting-approval" ? "Awaiting approval" : response.status === "approved-simulation" ? "Approved (simulation only)" : response.status === "reviewed" ? "Reviewed · action deferred" : "Simulated"}: {response.kind} ({response.target})</p><p className="mt-1 text-neutral-400">{response.reason}</p></div>) : <p className="text-neutral-400">No protective response selected.</p> : <p className="text-neutral-400">{row.state === "failed" ? "No simulated response recorded." : "Awaiting decision."}</p>}</td>
        </tr>{history && <tr className="border-t border-neutral-800 bg-neutral-900/40"><td colSpan={3} className="p-4 text-sm">
          <div className="grid gap-4 sm:grid-cols-2">
            <section><h4 className="font-medium">Why this decision was made</h4><p className="mt-2 whitespace-pre-wrap text-neutral-300">{row.analysis?.rationale ?? (row.error || "Analysis has not finished. No final decision has been made.")}</p>
              <h4 className="mt-4 font-medium">Supporting evidence</h4><p className="mt-2 whitespace-pre-wrap text-neutral-300">{row.analysis?.evidence || "No evidence summary recorded yet. Open event details to inspect the original data."}</p>
            </section>
            <section><h4 className="font-medium">How the decision was reached</h4>{row.analysis ? <><p className="mt-2 text-neutral-300">{row.analysis.tier === "guardrail" ? "Security guardrail: a mandatory safety rule determined this verdict." : row.analysis.tier === "prefilter" ? "Deterministic screening: rules, source severity and available context determined this verdict." : row.analysis.backend === "policy-fallback" ? "AI unavailable: this event was escalated by safety policy, without an AI verdict." : row.analysis.backend === "ollama-cloud" ? `Live cloud AI reasoning: ${row.analysis.model} assessed this event.` : user?.backend === "mock" ? "Test reasoning heuristic: the mock analysis backend produced this verdict. No AI model is connected." : "Local AI reasoning: the local model assessed the event after deterministic screening."}</p><p className="mt-2 text-xs text-neutral-400">Analysis score: {row.analysis.score.toFixed(1)} · Source severity: {row.event.severity} (these are scores, not probabilities)</p></> : <p className="mt-2 text-neutral-400">{eventStatus(row)}</p>}
              <h4 className="mt-4 font-medium">Why this response was selected</h4><p className="mt-2 whitespace-pre-wrap text-neutral-300">{row.analysis?.responses?.length ? row.analysis.responses.map(response => `${response.kind} (${response.target}): ${response.reason}`).join("\n\n") : row.analysis?.decision === "suppress" ? "The event was suppressed, so the response policy selected no protective action." : publicDemo ? "This hosted AI preview does not run the installed response planner or execute protective actions." : row.analysis ? "The response planner produced no eligible action for this event. The escalation remains available for review; an alert does not automatically trigger a protective response." : "Response selection is waiting for a decision."}</p><p className="mt-2 text-xs text-amber-300">All responses shown here are simulated. No device changes were executed.</p>
            </section>
          </div>
          <p className="mt-4 text-xs text-neutral-400">Source: {row.event.source_type} · Received: {new Date(row.event.received_at).toLocaleString()} · Occurred: {row.event.timestamp ? new Date(row.event.timestamp).toLocaleString() : "Unknown (not supplied)"}</p>
          <button className={`${control} mt-3`} onClick={() => setDetail(row.event_id)}>Inspect original event & full details</button>
        </td></tr>}</Fragment>)}</tbody></table>{!(history ? filteredHistory.length : currentEvents.length) && <p className="p-6 text-sm text-neutral-400">{history ? "No simulation events match these filters." : "Waiting for the first event…"}</p>}</div>
        {history && <div className="mt-4 flex items-center gap-3"><button className={control} disabled={!historyOffset} onClick={() => setHistoryOffset(Math.max(0, historyOffset - 100))}>Newer</button><span className="text-xs">{filteredHistory.length ? `${historyOffset + 1}–${historyOffset + filteredHistory.length}` : "0 events"}</span><button className={control} disabled={historyTotal !== null ? historyOffset + 100 >= historyTotal : filteredHistory.length < 100} onClick={() => setHistoryOffset(historyOffset + 100)}>Older</button></div>}

      </section>
    </div>}
    {detail && <EventPanel id={detail} demo publicDemo={publicDemo} onClose={() => setDetail(null)}/>}
  </div>;
}
