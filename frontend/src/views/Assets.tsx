import { useEffect, useState } from "react";
import { getEstate } from "../lib/api";
import type { Asset, EnvironmentFact } from "../lib/api";

function any(value: string): string {
  return value.trim() === "" ? "any" : value;
}

function Constraint({ label, value }: { label: string; value: string }) {
  const isAny = value.trim() === "";
  return (
    <span
      className={`rounded border px-1.5 py-0.5 text-xs ${
        isAny
          ? "border-neutral-800 text-neutral-600"
          : "border-neutral-700 text-neutral-300"
      }`}
    >
      {label}: {any(value)}
    </span>
  );
}

export function Assets() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [facts, setFacts] = useState<EnvironmentFact[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getEstate()
      .then((r) => {
        setAssets(r.assets);
        setFacts(r.facts);
      })
      .finally(() => setLoading(false));
  }, []);

  const maxCriticality = Math.max(1, ...assets.map((a) => a.criticality));

  if (loading) {
    return <p className="py-8 text-center text-sm text-neutral-500">Loading…</p>;
  }

  return (
    <div className="flex max-w-4xl flex-col gap-8">
      <div>
        <h1 className="text-lg font-medium text-neutral-100">Assets & facts</h1>
        <p className="mt-1 text-sm text-neutral-500">
          What the engine knows about your environment.
        </p>
      </div>

      <section>
        <h2 className="mb-3 text-xs font-medium uppercase tracking-wide text-neutral-500">
          Assets
        </h2>
        {assets.length === 0 ? (
          <p className="text-sm text-neutral-500">No assets recorded yet.</p>
        ) : (
          <div className="flex flex-col gap-1.5">
            {assets.map((a) => (
              <div
                key={a.host}
                className="flex items-center gap-4 rounded-lg border border-neutral-800 bg-neutral-900/40 px-4 py-2.5"
              >
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium text-neutral-100">{a.host}</p>
                  <p className="truncate text-xs text-neutral-500">{a.role}</p>
                </div>
                <div className="flex w-32 shrink-0 items-center gap-2">
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-neutral-800">
                    <div
                      className="h-full rounded-full bg-neutral-400"
                      style={{ width: `${(a.criticality / maxCriticality) * 100}%` }}
                    />
                  </div>
                  <span className="w-10 shrink-0 text-right text-xs tabular-nums text-neutral-400">
                    {a.criticality.toFixed(1)}×
                  </span>
                </div>
                <span
                  className={`shrink-0 rounded px-2 py-0.5 text-xs ${
                    a.confirmed
                      ? "bg-emerald-500/10 text-emerald-400"
                      : "bg-neutral-800 text-neutral-500"
                  }`}
                >
                  {a.confirmed ? "confirmed" : "unconfirmed"}
                </span>
              </div>
            ))}
          </div>
        )}
      </section>

      <section>
        <h2 className="mb-3 text-xs font-medium uppercase tracking-wide text-neutral-500">
          Environment facts
        </h2>
        {facts.length === 0 ? (
          <p className="text-sm text-neutral-500">No environment facts recorded yet.</p>
        ) : (
          <div className="flex flex-col gap-1.5">
            {facts.map((f) => (
              <div
                key={f.id}
                className="rounded-lg border border-neutral-800 bg-neutral-900/40 px-4 py-3"
              >
                <div className="flex items-center justify-between gap-3">
                  <span className="text-sm font-medium text-neutral-100">{f.scope}</span>
                </div>
                <p className="mt-1 text-sm text-neutral-300">{f.fact}</p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  <Constraint label="user" value={f.user} />
                  <Constraint label="path" value={f.path} />
                  <Constraint label="process" value={f.process} />
                  <Constraint
                    label="event types"
                    value={f.event_types.length ? f.event_types.join(", ") : ""}
                  />
                  <Constraint label="window" value={f.window} />
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
