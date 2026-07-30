import { useEffect, useState } from "react";
import {
  acknowledge,
  getEstate,
  getRecords,
  parseDetail,
  labelSignature,
} from "../lib/api";
import type { Decision, RecordRow, Tier } from "../lib/api";
import { DECISION_STYLE, TIER_STYLE, formatTime } from "../lib/theme";

const PAGE_SIZE = 25;

export function Audit() {
  const [rows, setRows] = useState<RecordRow[]>([]);
  const [hosts, setHosts] = useState<string[]>([]);
  const [decision, setDecision] = useState<Decision | "">("");
  const [tier, setTier] = useState<Tier | "">("");
  const [host, setHost] = useState("");
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getEstate()
      .then((r) => setHosts(r.assets.map((a) => a.host)))
      .catch(() => {});
  }, []);

  function load() {
    setLoading(true);
    getRecords({
      decision: decision || undefined,
      tier: tier || undefined,
      host: host || undefined,
      limit: PAGE_SIZE,
      offset,
    })
      .then((r) => setRows(r.rows))
      .catch(() => setRows([]))
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
        <h1 className="text-lg font-medium text-neutral-100">Verdicts & audit</h1>
        <p className="mt-1 text-sm text-neutral-500">Every verdict, filterable and reviewable.</p>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <select
          value={decision}
          onChange={(e) => {
            setOffset(0);
            setDecision(e.target.value as Decision | "");
          }}
          className="rounded-md border border-neutral-700 bg-neutral-950 px-2.5 py-1.5 text-sm text-neutral-200 outline-none focus-visible:border-neutral-500 focus-visible:ring-2 focus-visible:ring-neutral-500/40"
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
          className="rounded-md border border-neutral-700 bg-neutral-950 px-2.5 py-1.5 text-sm text-neutral-200 outline-none focus-visible:border-neutral-500 focus-visible:ring-2 focus-visible:ring-neutral-500/40"
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
          className="rounded-md border border-neutral-700 bg-neutral-950 px-2.5 py-1.5 text-sm text-neutral-200 outline-none placeholder:text-neutral-600 focus-visible:border-neutral-500 focus-visible:ring-2 focus-visible:ring-neutral-500/40"
        />
        <datalist id="audit-hosts">
          {hosts.map((h) => (
            <option key={h} value={h} />
          ))}
        </datalist>
      </div>

      <div className="flex flex-col gap-1.5">
        {loading && <p className="py-8 text-center text-sm text-neutral-500">Loading…</p>}
        {!loading && rows.length === 0 && (
          <p className="py-8 text-center text-sm text-neutral-500">No matching verdicts.</p>
        )}
        {!loading &&
          rows.map((row) => {
            const d = DECISION_STYLE[row.decision];
            const t = TIER_STYLE[row.tier];
            const isOpen = expanded === row.id;
            const detail = parseDetail(row);
            return (
              <div
                key={row.id}
                className="rounded-lg border border-neutral-800 bg-neutral-900/40"
              >
                <button
                  type="button"
                  onClick={() => setExpanded(isOpen ? null : row.id)}
                  className="flex w-full items-center justify-between gap-3 px-4 py-2.5 text-left"
                >
                  <div className="flex min-w-0 items-center gap-2">
                    <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${d.dot}`} />
                    <span className={`text-sm font-medium ${d.text}`}>{d.label}</span>
                    <span className="truncate text-sm text-neutral-400">{row.host}</span>
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
                  <div className="border-t border-neutral-800 px-4 py-3 text-sm">
                    <p className="text-xs text-neutral-500">Signature</p>
                    <p className="mb-2 break-all text-neutral-300">{row.signature}</p>

                    {row.rationale && (
                      <>
                        <p className="text-xs text-neutral-500">Rationale</p>
                        <p className="mb-2 text-neutral-300">{row.rationale}</p>
                      </>
                    )}
                    {row.evidence && (
                      <>
                        <p className="text-xs text-neutral-500">Evidence</p>
                        <p className="mb-2 text-neutral-300">{row.evidence}</p>
                      </>
                    )}
                    {detail && (
                      <>
                        <p className="text-xs text-neutral-500">Event</p>
                        <p className="mb-2 text-neutral-300">
                          [{detail.source}] {detail.message} (severity {detail.severity})
                        </p>
                        {Object.keys(detail.fields).length > 0 && (
                          <pre className="mb-2 overflow-x-auto rounded bg-neutral-950 p-2 text-xs text-neutral-400">
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
                          className="rounded-md border border-neutral-700 px-2.5 py-1.5 text-xs text-neutral-300 transition-colors hover:bg-neutral-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-500/40"
                        >
                          Acknowledge
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => handleLabel(row.signature, "confirmed")}
                        className="rounded-md border border-neutral-700 px-2.5 py-1.5 text-xs text-neutral-300 transition-colors hover:bg-neutral-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-500/40"
                      >
                        Confirm this was correct
                      </button>
                      <button
                        type="button"
                        onClick={() => handleLabel(row.signature, "overruled")}
                        className="rounded-md border border-neutral-700 px-2.5 py-1.5 text-xs text-neutral-300 transition-colors hover:bg-neutral-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-500/40"
                      >
                        {row.decision === "escalate"
                          ? "This was a false alarm"
                          : "This should have been escalated"}
                      </button>
                    </div>
                    <p className="mt-2 text-xs text-neutral-600">
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
          className="rounded-md border border-neutral-700 px-3 py-1.5 text-sm text-neutral-300 transition-colors hover:bg-neutral-800 disabled:cursor-not-allowed disabled:opacity-40"
        >
          Previous
        </button>
        <span className="text-xs text-neutral-500">Rows {offset + 1}–{offset + rows.length}</span>
        <button
          type="button"
          disabled={rows.length < PAGE_SIZE}
          onClick={() => setOffset(offset + PAGE_SIZE)}
          className="rounded-md border border-neutral-700 px-3 py-1.5 text-sm text-neutral-300 transition-colors hover:bg-neutral-800 disabled:cursor-not-allowed disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  );
}
