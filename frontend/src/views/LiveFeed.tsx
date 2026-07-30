import { useEffect, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import type { StreamRow } from "../lib/api";
import { connectVerdictStream } from "../lib/sseStream";
import { DECISION_STYLE, TIER_STYLE, formatTime } from "../lib/theme";

const MAX_ROWS = 300;

export function LiveFeed() {
  const [rows, setRows] = useState<StreamRow[]>([]);
  const [connected, setConnected] = useState(false);
  const [escalationsOnly, setEscalationsOnly] = useState(false);
  const reduceMotion = useReducedMotion();

  useEffect(() => {
    const disconnect = connectVerdictStream(
      (row) => setRows((prev) => [row, ...prev].slice(0, MAX_ROWS)),
      setConnected,
    );
    return disconnect;
  }, []);

  const visible = escalationsOnly ? rows.filter((r) => r.decision === "escalate") : rows;

  return (
    <div className="flex max-w-3xl flex-col gap-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-medium text-neutral-100">Live feed</h1>
          <p className="mt-1 text-sm text-neutral-500">Verdicts as they're triaged.</p>
        </div>
        <div className="flex items-center gap-4">
          <label className="flex items-center gap-2 text-sm text-neutral-400">
            <input
              type="checkbox"
              checked={escalationsOnly}
              onChange={(e) => setEscalationsOnly(e.target.checked)}
              className="h-3.5 w-3.5 rounded border-neutral-600 bg-neutral-950 accent-neutral-400"
            />
            Escalations only
          </label>
          <span className="flex items-center gap-1.5 text-xs text-neutral-500">
            <span
              className={`h-1.5 w-1.5 rounded-full ${connected ? "bg-emerald-500" : "bg-neutral-600"}`}
            />
            {connected ? "Connected" : "Reconnecting…"}
          </span>
        </div>
      </div>

      <ul className="flex flex-col gap-1.5">
        <AnimatePresence initial={false}>
          {visible.map((row) => {
            const decision = DECISION_STYLE[row.decision];
            const tier = TIER_STYLE[row.tier];
            return (
              <motion.li
                key={row.id}
                layout={!reduceMotion}
                initial={reduceMotion ? false : { opacity: 0, y: -6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.25, ease: "easeOut" }}
                className="rounded-lg border border-neutral-800 bg-neutral-900/40 px-4 py-2.5"
              >
                <div className="flex items-center justify-between gap-3">
                  <div className="flex min-w-0 items-center gap-2">
                    <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${decision.dot}`} />
                    <span className={`text-sm font-medium ${decision.text}`}>{decision.label}</span>
                    <span className="truncate text-sm text-neutral-400">{row.host}</span>
                    <span className={`shrink-0 text-xs ${tier.text}`}>{tier.label}</span>
                  </div>
                  <span className="shrink-0 text-xs text-neutral-500">{formatTime(row.ts)}</span>
                </div>
                {row.rationale && (
                  <p className="mt-1 truncate text-xs text-neutral-500">{row.rationale}</p>
                )}
              </motion.li>
            );
          })}
        </AnimatePresence>

        {visible.length === 0 && (
          <p className="py-12 text-center text-sm text-neutral-500">
            {escalationsOnly ? "No escalations yet." : "Waiting for verdicts…"}
          </p>
        )}
      </ul>
    </div>
  );
}
