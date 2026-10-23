import { useEffect, useState } from "react";

import { getEvents, getResponseStatus } from "../lib/api";

import { SignalMap } from "../components/SignalMap";

import { EventPanel } from "../components/EventPanel";

import { eventStatus, eventProgress } from "../lib/eventStatus";

import type { TelemetryRow, ResponseCase } from "../lib/api";



const control = "rounded border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm focus-visible:ring-2 focus-visible:ring-sky-500";



export function LiveEvents() {

  const [rows, setRows] = useState<TelemetryRow[]>([]);

  const [filters, setFilters] = useState<Record<string, string>>({});

  const [hours, setHours] = useState("24");

  const [offset, setOffset] = useState(0);

  const [detail, setDetail] = useState<string | null>(null);

  const [error, setError] = useState("");

  const [loading, setLoading] = useState(true);

  const [reviews, setReviews] = useState<ResponseCase[]>([]);

  const [responseError, setResponseError] = useState("");

  useEffect(() => {

    let active = true;

    let timer: ReturnType<typeof setTimeout>;

    async function refresh() {

      const query: Record<string, string> = {...filters, limit: "100", offset: String(offset)};

      if (hours) query.since = new Date(Date.now() - Number(hours) * 3600000).toISOString();

      try { const data = await getEvents(query); if (active) { setRows(data.events); setError(""); setLoading(false); } }

      catch { if (active) { setError("Could not load events. Check the connection."); setLoading(false); } }

      try {const data = await getResponseStatus(); if (active) {setReviews(data.cases); setResponseError(data.error);}}

      catch {if (active) setResponseError("Response deadlines unavailable. Review alerts manually.");}

      if (active) timer = setTimeout(() => void refresh(), 1000);

    }

    void refresh();

    return () => { active = false; clearTimeout(timer); };

  }, [filters, hours, offset]);

  function filter(key: string, value: string) { setFilters({...filters, [key]: value}); setOffset(0); }

  return <div className="operations-view flex max-w-6xl flex-col gap-5">

    <header><h1 className="text-lg font-medium">Live</h1><p className="mt-1 text-sm text-neutral-400">Follow each event from arrival through analysis to its decision. Click any event for evidence, reasoning and response.</p><p className="mt-2 text-xs text-neutral-500">Under observation means analysis is pending or running. Suppressed means no alert was raised. Alerted events are escalated for review; this does not mean a protective action was executed. Updates every second.</p></header>

    <SignalMap key={JSON.stringify([filters,hours,offset])} events={rows.map(row => ({id: row.event_id, source: row.event.source_type, decision: row.analysis?.decision}))} onInspect={setDetail} />

    {responseError && <p role="alert" className="text-sm text-amber-300">{responseError}</p>}

    {!!reviews.length && <section aria-label="Response review queue" className="space-y-3 border-l-2 border-amber-700 pl-4"><h2 className="font-medium">Response reviews · {reviews.length}{reviews.length === 50 ? "+" : ""}</h2><p className="text-xs text-neutral-400">Deadlines run independently of AI analysis. Only explicitly approved timed actions can change the device.</p><div className="flex flex-wrap gap-2">{reviews.slice(0, 8).map(review => <button key={review.event_id} className={control} onClick={() => setDetail(review.event_id)}>{review.severity} · {review.state === "pending" && review.deadline && review.deadline < Date.now() / 1000 ? "deadline passed" : review.state.replaceAll("_", " ")} · {review.mode === "automatic" ? "action scheduled" : "review required"} · {review.event_id.slice(0, 8)}</button>)}</div></section>}

    <section aria-label="Event filters" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">

      <label className="flex flex-col gap-1 text-xs text-neutral-400">Source<select className={control} value={filters.source ?? ""} onChange={e => filter("source", e.target.value)}><option value="">All sources</option>{["windows", "sysmon", "defender", "windows_security", "osquery", "suricata", "wazuh", "syslog", "cloudtrail", "guardduty", "sshd", "auditd"].map(s => <option key={s}>{s}</option>)}</select></label>

      {[['host', 'Host'], ['username', 'Username'], ['ip', 'IP address'], ['category', 'Event category']].map(([key, label]) => <label key={key} className="flex flex-col gap-1 text-xs text-neutral-400">{label}<input className={control} value={filters[key] ?? ""} onChange={e => filter(key, e.target.value)} placeholder="Any" /></label>)}

      <label className="flex flex-col gap-1 text-xs text-neutral-400">Minimum source severity<select className={control} value={filters.severity ?? ""} onChange={e => filter("severity", e.target.value)}><option value="">Any</option>{[0, 3, 5, 7, 9].map(n => <option key={n} value={n}>{n}</option>)}</select></label>

      <label className="flex flex-col gap-1 text-xs text-neutral-400">Time<select className={control} value={hours} onChange={e => {setHours(e.target.value); setOffset(0);}}><option value="1">Last hour</option><option value="24">Last 24 hours</option><option value="168">Last 7 days</option><option value="">All retained events</option></select></label>

    </section>

    {error && <p role="alert" className="text-sm text-amber-300">{error}</p>}

    {loading ? <p role="status">Loading events…</p> : <div className="overflow-x-auto rounded-lg border border-neutral-800"><table className="w-full text-left text-sm"><thead className="bg-neutral-900 text-xs text-neutral-400"><tr>{["Received", "Source", "Host", "Event", "Status & progress"].map(h => <th key={h} className="p-3">{h}</th>)}</tr></thead><tbody>{rows.map(row => <tr key={row.event_id} className="cursor-pointer border-t border-neutral-800 hover:bg-neutral-900" onClick={() => setDetail(row.event_id)}><td className="whitespace-nowrap p-3 text-xs text-neutral-400">{new Date(row.event.received_at).toLocaleString()}</td><td className="p-3">{row.event.source_type}</td><td className="max-w-48 truncate p-3" title={row.event.hostname}>{row.event.hostname}</td><td className="p-3"><button className="text-sky-300 underline focus-visible:ring-2" onClick={() => setDetail(row.event_id)}>{row.event.event_type}</button></td><td className={`p-3 ${row.state === "failed" ? "text-amber-300" : row.analysis?.decision === "escalate" ? "text-red-300" : row.analysis?.decision === "suppress" ? "text-emerald-300" : "text-sky-300"}`}>{eventStatus(row)}<p className="mt-1 text-xs text-neutral-400">{eventProgress(row)}</p>{row.analysis && <p className="mt-1 max-w-md text-xs text-neutral-400 line-clamp-2">{row.analysis.rationale}</p>}</td></tr>)}</tbody></table>{!rows.length && <p className="p-6 text-center text-sm text-neutral-400">No events match these filters. Enable a real source in Data Sources.</p>}</div>}

    <div className="flex items-center gap-3 text-sm"><button className={control} disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 100))}>Newer</button><span>{rows.length ? `${offset + 1}–${offset + rows.length}` : "0 events"}</span><button className={control} disabled={rows.length < 100} onClick={() => setOffset(offset + 100)}>Older</button></div>

    {detail && <EventPanel id={detail} onClose={() => setDetail(null)} />}

  </div>;

}
