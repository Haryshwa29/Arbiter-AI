import type { TelemetryRow } from "./api";

// Arrival/analysis are processing stages; suppression/escalation are verdicts.
// Use the verdict, never analysis.kind (which historically called suppression
// an observation), so the list and inspector describe the same event.
export function eventStatus(row: Pick<TelemetryRow, "state" | "analysis">) {
  if (row.state === "failed") return "Analysis failed";
  if (row.analysis?.second_stage_status === 'pending-alert-visible') return 'Alert visible · second review pending';
  if (row.analysis?.second_stage_status === 'human-rejected-alert-retained') return 'Alert retained by a person';
  if (row.analysis?.second_stage_status?.includes('review-alert-retained') || row.analysis?.second_stage_status === 'failed-alert-retained') return 'Alert visible · second review unavailable';
  if (row.analysis?.decision === "escalate") return "Alerted · escalated for review";
  if (row.analysis?.decision === "suppress") return "Suppressed · no review needed";
  if (row.state === "processing") return "Analyzing";
  return row.state === "completed" ? "Analysis unavailable" : "Awaiting analysis";
}

export function eventProgress(row: Pick<TelemetryRow, "state" | "analysis">) {
  if (row.state === "failed") return "Received → Analysis failed";
  if (row.analysis?.second_stage_status) return `Received → First review → ${row.analysis.second_stage_status === 'complete' ? 'Second review → Final check → ' : ''}${eventStatus(row)}`;
  if (row.analysis) return `Received → Analyzed → ${eventStatus(row)}`;
  return `Received → ${eventStatus(row)}`;
}
