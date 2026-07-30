import type { Decision, Tier } from "./api";

// Color reserved to mean something (design language, FRONTEND-BRIEF.md §6):
// red=escalate, green=suppressed, blue=prefilter tier, purple=LLM tier,
// amber=guardrail tier (proposed in the brief — a guardrail firing is a
// stronger statement than a tier attribution, so it gets its own color
// rather than reusing red/blue/purple).
export const DECISION_STYLE: Record<Decision, { text: string; dot: string; label: string }> = {
  escalate: { text: "text-red-400", dot: "bg-red-500", label: "Escalated" },
  suppress: { text: "text-emerald-400", dot: "bg-emerald-500", label: "Suppressed" },
};

export const TIER_STYLE: Record<Tier, { text: string; dot: string; label: string }> = {
  prefilter: { text: "text-blue-400", dot: "bg-blue-500", label: "Prefilter" },
  llm: { text: "text-purple-400", dot: "bg-purple-500", label: "LLM" },
  guardrail: { text: "text-amber-400", dot: "bg-amber-500", label: "Guardrail" },
};

export function formatTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatHour(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { hour: "2-digit", minute: "2-digit" });
}
