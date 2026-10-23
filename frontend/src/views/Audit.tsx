import { useEffect, useState } from "react";
import {
  acknowledge,
  getEvent,
  getEstate,
  getRecords,
  parseDetail,
  labelSignature,
} from "../lib/api";
import type { Decision, RecordRow, Tier, TelemetryRow } from "../lib/api";
import { DECISION_STYLE, TIER_STYLE, formatTime } from "../lib/theme";
import { EventPanel } from "../components/EventPanel";
import { ErrorNotice } from "../components/ErrorNotice";

const PAGE_SIZE = 25;

export function Audit() {
  const [briefs, setBriefs] = useState<Record<string, TelemetryRow["analysis"]>>({});
  const [eventId, setEventId] = useState<string | null>(null);
  const [rows, setRows] = useState<RecordRow[]>([]);
  const [hosts, setHosts] = useState<string[]>([]);
  const [decision, setDecision] = useState<Decision | "">("");
  const [tier, setTier] = useState<Tier | "">("");
  const [host, setHost] = useState("");
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    getEstate()
      .then((r) => setHosts(r.assets.map((a) => a.host)))
      .catch(() => {});
  }, []);

  function load() {
    setLoading(true);
    setError(false);
    getRecords({
      decision: decision || undefined,
      tier: tier || undefined,
      host: host || undefined,
      limit: PAGE_SIZE,
      offset,
    })
      .then((r) => setRows(r.rows))
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(load, [decision, tier, host, offset]);

  async function handleAcknowledge(id: number) {
    await acknowledge(id);
    load();
  }

  async function handleLabel(signature: string, label: "confirmed" | "overruled") {
    await labelSignature(signature, label);
    load();
  }

  return (
    <div className="flex max-w-5xl flex-col gap-4">
      <div>
        <h1 className="text-lg font-medium text-neutral-900 dark:text-neutral-100">Verdicts & audit</h1>
        <p className="mt-1 text-sm text-neutral-500">Every verdict, filterable and reviewable.</p>
      </div>

      {eventId && <EventPanel id={eventId} onClose={() => setEventId(null)} />}
      <div className="flex flex-wrap items-center gap-3">
        <select
          value={decision}
          onChange={(e) => {
            setOffset(0);
            setDecision(e.target.value as Decision | "");
          }}
          className="rounded-md border border-neutral-300 bg-white px-2.5 py-1.5 text-sm text-neutral-900 outline-none focus-visible:border-neutral-500 focus-visible:ring-2 focus-visible:ring-neutral-500/40 dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-200"
        >
          <option value="">Any decision</option>
          <option value="escalate">Escalated</option>
          <option value="suppress">Suppressed</option>
        </select>

        <select
          value={tier}
          onChange={(e) => {
            setOffset(0);
            setTier(e.target.value as Tier | "");
          }}
          className="rounded-md border border-neutral-300 bg-white px-2.5 py-1.5 text-sm text-neutral-900 outline-none focus-visible:border-neutral-500 focus-visible:ring-2 focus-visible:ring-neutral-500/40 dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-200"
        >
          <option value="">Any tier</option>
          <option value="prefilter">Prefilter</option>
          <option value="llm">LLM</option>
          <option value="guardrail">Guardrail</option>
        </select>

        <input
          list="audit-hosts"
          placeholder="Host (any)"
          value={host}
          onChange={(e) => {
            setOffset(0);
            setHost(e.target.value);
          }}
          className="rounded-md border border-neutral-300 bg-white px-2.5 py-1.5 text-sm text-neutral-900 outline-none placeholder:text-neutral-400 focus-visible:border-neutral-500 focus-visible:ring-2 focus-visible:ring-neutral-500/40 dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-200 dark:placeholder:text-neutral-600"
        />
        <datalist id="audit-hosts">
          {hosts.map((h) => (
            <option key={h} value={h} />
          ))}
        </datalist>
      </div>

      <div className="flex flex-col gap-1.5">
        {loading && <p className="py-8 text-center text-sm text-neutral-500">Loading…</p>}
        {!loading && error && <ErrorNotice message="Couldn't load verdicts." onRetry={load} />}
        {!loading && !error && rows.length === 0 && (
          <p className="py-8 text-center text-sm text-neutral-500">No matching verdicts.</p>
        )}
        {!loading &&
          !error &&
          rows.map((row) => {
            const d = DECISION_STYLE[row.decision];
            const t = TIER_STYLE[row.tier];
            const isOpen = expanded === row.id;
            const detail = parseDetail(row);
            return (
              <div
                key={row.id}
                className="rounded-lg border border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900/40"
              >
                <button
                  type="button"
                  onClick={() => {setExpanded(isOpen ? null : row.id); if (!isOpen && !briefs[row.event_id]) void getEvent(row.event_id).then(event => setBriefs(current => ({...current, [row.event_id]: event.analysis}))).catch(() => setBriefs(current => ({...current, [row.event_id]: null})));}}
                  className="flex w-full items-center justify-between gap-3 px-4 py-2.5 text-left"
                >
                  <div className="flex min-w-0 items-center gap-2">
                    <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${d.dot}`} />
                    <span className={`text-sm font-medium ${d.text}`}>{d.label}</span>
                    <span className="truncate text-sm text-neutral-600 dark:text-neutral-400">{row.host}</span>
                    <span className={`shrink-0 text-xs ${t.text}`}>{t.label}</span>
                    {row.actor && (
                      <span className="shrink-0 text-xs text-neutral-500">
                        reviewed by {row.actor}
                      </span>
                    )}
                  </div>
                  <span className="shrink-0 text-xs text-neutral-500">{formatTime(row.ts)}</span>
                </button>

                {isOpen && (
                  <div className="border-t border-neutral-200 px-4 py-3 text-sm dark:border-neutral-800">
                    <button className="mb-3 text-sky-300 underline" onClick={() => setEventId(row.event_id)}>Inspect original event · {row.event_id}</button>
                    {briefs[row.event_id]?.brief ? <section aria-label="Alert explanation" className="mb-4 space-y-3 rounded border border-neutral-700 p-3">
                      {briefs[row.event_id]?.brief?.observed && <><h3 className="font-medium">What was recorded</h3><p className="whitespace-pre-wrap break-words">{briefs[row.event_id]?.brief?.observed}</p></>}
                      <h3 className="font-medium">Why this triggered</h3><p>{briefs[row.event_id]?.brief?.why}</p>
                      <dl className="space-y-2">{Object.entries(briefs[row.event_id]?.brief?.origin ?? {}).map(([label, value]) => <div key={label}><dt className="text-xs text-neutral-500">{label}</dt><dd className="max-h-28 overflow-auto whitespace-pre-wrap break-all">{value}</dd></div>)}</dl>
                      <h3 className="font-medium">What still needs checking</h3><p>{briefs[row.event_id]?.brief?.uncertainty}</p>
                      <h3 className="font-medium">Recommended next steps</h3><p className="text-xs text-neutral-500">{briefs[row.event_id]?.brief?.guidance?.source === "model" ? "AI-suggested guidance" : "Policy-guided investigation"}</p>
                      <ol className="list-decimal space-y-2 pl-5">{briefs[row.event_id]?.brief?.guidance?.steps.map((step, index) => <li key={index}>{step}</li>)}</ol><p className="text-xs text-neutral-500">{briefs[row.event_id]?.brief?.guidance?.caution}</p>
                    </section> : row.decision === "escalate" && <p role="status" className="mb-3 text-neutral-500">{row.event_id in briefs ? "Detailed explanation unavailable. Inspect the original event, verify its origin and authorization, then acknowledge after review." : "Loading alert explanation and recommended steps…"}</p>}
                    <p className="text-xs text-neutral-500">Signature</p>
                    <p className="mb-2 break-all text-neutral-700 dark:text-neutral-300">{row.signature}</p>

                    {row.rationale && (
                      <>
                        <p className="text-xs text-neutral-500">Rationale</p>
                        <p className="mb-2 text-neutral-700 dark:text-neutral-300">{row.rationale}</p>
                      </>
                    )}
                    {row.evidence && (
                      <>
                        <p className="text-xs text-neutral-500">Evidence</p>
                        <p className="mb-2 text-neutral-700 dark:text-neutral-300">{row.evidence}</p>
                      </>
                    )}
                    {detail && (
                      <>
                        <p className="text-xs text-neutral-500">Event</p>
                        <p className="mb-2 text-neutral-700 dark:text-neutral-300">
                          [{detail.source}] {detail.message} (severity {detail.severity})
                        </p>
                        {Object.keys(detail.fields).length > 0 && (
                          <pre className="mb-2 overflow-x-auto rounded bg-neutral-100 p-2 text-xs text-neutral-700 dark:bg-neutral-950 dark:text-neutral-400">
                            {JSON.stringify(detail.fields, null, 2)}
                          </pre>
                        )}
                      </>
                    )}

                    <div className="mt-3 flex flex-wrap gap-2">
                      {!row.actor && (
                        <button
                          type="button"
                          onClick={() => handleAcknowledge(row.id)}
                          className="rounded-md border border-neutral-300 px-2.5 py-1.5 text-xs text-neutral-700 transition-colors hover:bg-neutral-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-500/40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                        >
                          Acknowledge
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => handleLabel(row.signature, "confirmed")}
                        className="rounded-md border border-neutral-300 px-2.5 py-1.5 text-xs text-neutral-700 transition-colors hover:bg-neutral-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-500/40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                      >
                        Confirm this was correct
                      </button>
                      <button
                        type="button"
                        onClick={() => handleLabel(row.signature, "overruled")}
                        className="rounded-md border border-neutral-300 px-2.5 py-1.5 text-xs text-neutral-700 transition-colors hover:bg-neutral-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-500/40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                      >
                        {row.decision === "escalate"
                          ? "This was a false alarm"
                          : "This should have been escalated"}
                      </button>
                    </div>
                    <p className="mt-2 text-xs text-neutral-500">
                      Applies to every verdict sharing this signature, not just this one.
                    </p>
                  </div>
                )}
              </div>
            );
          })}
      </div>

      <div className="flex items-center justify-between pt-2">
        <button
          type="button"
          disabled={offset === 0}
          onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          className="rounded-md border border-neutral-300 px-3 py-1.5 text-sm text-neutral-700 transition-colors hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
        >
          Previous
        </button>
        <span className="text-xs text-neutral-500">
          {rows.length === 0 ? "No rows" : `Rows ${offset + 1}–${offset + rows.length}`}
        </span>
        <button
          type="button"
          disabled={rows.length < PAGE_SIZE}
          onClick={() => setOffset(offset + PAGE_SIZE)}
          className="rounded-md border border-neutral-300 px-3 py-1.5 text-sm text-neutral-700 transition-colors hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
        >
          Next
        </button>
      </div>
    </div>
  );
}
