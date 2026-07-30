import type { DayBucket } from "../lib/api";
import { formatHour, formatTime } from "../lib/theme";

const CHART_H = 140;
const BAR_W = 6;
const BAR_GAP = 2;

export function VolumeChart({ buckets }: { buckets: DayBucket[] }) {
  const max = Math.max(1, ...buckets.map((b) => b.escalated + b.suppressed));
  const width = buckets.length * (BAR_W + BAR_GAP);

  if (buckets.length === 0) {
    return <p className="py-12 text-center text-sm text-neutral-500">No data in this window.</p>;
  }

  const labelIdx = [0, Math.floor(buckets.length / 2), buckets.length - 1];

  return (
    <div>
      <svg
        viewBox={`0 0 ${width} ${CHART_H}`}
        preserveAspectRatio="none"
        className="h-36 w-full"
        role="img"
        aria-label="Verdict volume over time"
      >
        {buckets.map((b, i) => {
          const supH = (b.suppressed / max) * (CHART_H - 4);
          const escH = (b.escalated / max) * (CHART_H - 4);
          const x = i * (BAR_W + BAR_GAP);
          return (
            <g key={b.bucket}>
              <title>
                {formatTime(b.bucket)} — {b.escalated} escalated, {b.suppressed} suppressed
              </title>
              <rect
                x={x}
                y={CHART_H - supH - escH}
                width={BAR_W}
                height={supH}
                className="fill-[#2E8B67]/60 dark:fill-[#5DCAA5]/60"
              />
              <rect
                x={x}
                y={CHART_H - escH}
                width={BAR_W}
                height={escH}
                className="fill-[#C2402F]/80 dark:fill-[#E2574B]/80"
              />
            </g>
          );
        })}
      </svg>
      <div className="mt-1 flex justify-between text-xs text-neutral-500">
        {labelIdx.map((i) => (
          <span key={i}>{formatHour(buckets[i].bucket)}</span>
        ))}
      </div>
      <div className="mt-3 flex items-center gap-4 text-xs text-neutral-600 dark:text-neutral-400">
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-[#C2402F] dark:bg-[#E2574B]" /> Escalated
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-[#2E8B67] dark:bg-[#5DCAA5]" /> Suppressed
        </span>
      </div>
    </div>
  );
}
