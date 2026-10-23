import { useState } from "react";
import type { DayBucket } from "../lib/api";
import { formatHour, formatTime } from "../lib/theme";

export function VolumeChart({ buckets }: { buckets: DayBucket[] }) {
  const [selected, setSelected] = useState<number | null>(null);
  const max = Math.max(1, ...buckets.map(b => b.escalated + b.suppressed));
  if (!buckets.length) return <p className="empty-copy">No volume data loaded for this window.</p>;
  const active = selected === null ? null : buckets[selected];
  return <div className="volume-chart">
    <div className="volume-scale"><span>{max}</span><span>{Math.round(max/2)}</span><span>0</span></div>
    <div className="volume-bars" role="group" aria-label="Hourly verdict counts. Use left and right arrows to explore.">
      {buckets.map((b,i) => <button key={b.bucket} className="volume-bar" tabIndex={i === (selected ?? 0) ? 0 : -1} onKeyDown={e => {if (!["ArrowLeft","ArrowRight","Home","End"].includes(e.key)) return; e.preventDefault(); const next = e.key === "Home" ? 0 : e.key === "End" ? buckets.length-1 : Math.max(0,Math.min(buckets.length-1,i+(e.key === "ArrowRight" ? 1 : -1))); setSelected(next); (e.currentTarget.parentElement?.children[next] as HTMLElement)?.focus();}} onMouseEnter={() => setSelected(i)} onFocus={() => setSelected(i)} onClick={() => setSelected(i)} aria-label={`${formatTime(b.bucket)}: ${b.escalated} escalated, ${b.suppressed} suppressed`}><span className="volume-stack"><i style={{height:`${b.suppressed/max*100}%`,background:'#81c8b0'}}/><i style={{height:`${b.escalated/max*100}%`,background:'#ed958a'}}/></span></button>)}
    </div>
    <div className="volume-times"><span>{formatHour(buckets[0].bucket)}</span><span>{formatHour(buckets[buckets.length-1].bucket)}</span></div>
    <p className="volume-detail" aria-live="polite">{active ? `${formatTime(active.bucket)} · ${active.escalated} escalated · ${active.suppressed} suppressed` : 'Hover a bar or use arrow keys to explore hourly counts.'}</p>
    <div className="volume-legend"><span><i className="dot alert-dot"/>Escalated</span><span><i className="dot quiet-dot"/>Suppressed</span></div>
  </div>;
}
