import { useEffect, useState } from "react";
import { getDay, getSummary } from "../lib/api";
import type { DayBucket, SummaryResponse } from "../lib/api";
import { StatTile } from "../components/StatTile";
import { VolumeChart } from "../components/VolumeChart";

const WINDOWS = [
  { hours: 24 as const, label: "24h" },
  { hours: 72 as const, label: "72h" },
  { hours: 168 as const, label: "7d" },
];

export function Overview() {
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [buckets, setBuckets] = useState<DayBucket[]>([]);
  const [hours, setHours] = useState<24 | 72 | 168>(24);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getSummary()
      .then(setSummary)
      .catch(() => {});
  }, []);

  useEffect(() => {
    setLoading(true);
    getDay(hours)
      .then((r) => setBuckets(r.buckets))
      .catch(() => setBuckets([]))
      .finally(() => setLoading(false));
  }, [hours]);

  const prefilterShare =
    summary && summary.today.today > 0
      ? Math.round((summary.today.prefilter / summary.today.today) * 100)
      : null;

  return (
    <div className="flex max-w-4xl flex-col gap-8">
      <div>
        <h1 className="text-lg font-medium text-neutral-900 dark:text-neutral-100">Overview</h1>
        <p className="mt-1 text-sm text-neutral-500">
          How much this handled for you, and how much needed you.
        </p>
      </div>

      <section>
        <h2 className="mb-3 text-xs font-medium uppercase tracking-wide text-neutral-500">Today</h2>
        <div className="grid grid-cols-3 gap-3">
          <StatTile label="Verdicts today" value={summary?.today.today ?? "—"} />
          <StatTile label="Escalated today" value={summary?.today.escalated ?? "—"} accent="red" />
          <StatTile
            label="Prefilter share"
            value={prefilterShare !== null ? `${prefilterShare}%` : "—"}
          />
        </div>
      </section>

      <section>
        <h2 className="mb-3 text-xs font-medium uppercase tracking-wide text-neutral-500">Lifetime</h2>
        <div className="grid grid-cols-3 gap-3">
          <StatTile label="Triaged" value={summary?.lifetime.triaged ?? "—"} />
          <StatTile label="Suppressed" value={summary?.lifetime.suppressed ?? "—"} />
          <StatTile label="Escalated" value={summary?.lifetime.escalated ?? "—"} accent="red" />
        </div>
      </section>

      <section>
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-xs font-medium uppercase tracking-wide text-neutral-500">Volume</h2>
          <div className="flex gap-1 rounded-md border border-neutral-200 p-0.5 dark:border-neutral-800">
            {WINDOWS.map((w) => (
              <button
                key={w.hours}
                type="button"
                onClick={() => setHours(w.hours)}
                className={`rounded px-2 py-1 text-xs transition-colors ${
                  hours === w.hours
                    ? "bg-neutral-200 text-neutral-900 dark:bg-neutral-800 dark:text-neutral-100"
                    : "text-neutral-500 hover:text-neutral-900 dark:hover:text-neutral-300"
                }`}
              >
                {w.label}
              </button>
            ))}
          </div>
        </div>
        <div className="rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900/40">
          {loading ? (
            <p className="py-12 text-center text-sm text-neutral-500">Loading…</p>
          ) : (
            <VolumeChart buckets={buckets} />
          )}
        </div>
      </section>
    </div>
  );
}
