import type { Decision, Tier } from "./api";

// Color reserved to mean something (design language, FRONTEND-BRIEF.md §6):
// red=escalate, green=suppressed, blue=prefilter tier, purple=LLM tier,
// amber=guardrail tier (proposed in the brief — a guardrail firing is a
// stronger statement than a tier attribution, so it gets its own color
// rather than reusing red/blue/purple).
//
// Exact hexes, not Tailwind's default palette (THEME-BRIEF.md §2 tier table):
// the light variants are the ones contrast-checked against a white surface,
// and the default red-400/emerald-400/etc do not match them.
export const DECISION_STYLE: Record<Decision, { text: string; dot: string; label: string }> = {
  escalate: { text: "text-[#C2402F] dark:text-[#E2574B]", dot: "bg-[#C2402F] dark:bg-[#E2574B]", label: "Escalated" },
  suppress: { text: "text-[#2E8B67] dark:text-[#5DCAA5]", dot: "bg-[#2E8B67] dark:bg-[#5DCAA5]", label: "Suppressed" },
};

export const TIER_STYLE: Record<Tier, { text: string; dot: string; label: string }> = {
  prefilter: { text: "text-[#2168B8] dark:text-[#378ADD]", dot: "bg-[#2168B8] dark:bg-[#378ADD]", label: "Prefilter" },
  llm: { text: "text-[#5A50B8] dark:text-[#7F77DD]", dot: "bg-[#5A50B8] dark:bg-[#7F77DD]", label: "LLM" },
  guardrail: { text: "text-[#A76B12] dark:text-[#EF9F27]", dot: "bg-[#A76B12] dark:bg-[#EF9F27]", label: "Guardrail" },
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
