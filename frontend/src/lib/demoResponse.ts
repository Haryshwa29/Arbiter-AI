import type {TelemetryRow} from "./api";

// Browser-only demonstration state. These functions never fetch or invoke an actuator.
export function initializeDemoResponse(row: TelemetryRow, now = Date.now() / 1000) {
  if (row.analysis?.decision !== "escalate") return;
  const severity = row.analysis.tier === "guardrail" || row.event.severity >= 9 ? "critical" : row.event.severity >= 7 ? "high" : row.event.severity >= 4 ? "medium" : "low";
  const window = {critical: 60, high: 300, medium: 1800, low: null}[severity];
  row.response_case = {event_id: row.event_id, severity, deadline: window === null ? null : now + window,
    state: "pending", mode: "review", deferred: false, simulation: true,
    note: window === null ? "Low severity has no automatic deadline. Review the event and record your findings; no device changes are made." : "Review required. Deadline expiry marks this demo case overdue; no device changes are made."};
  row.response_schedule_available = !!row.analysis.responses?.length && window !== null;
  if (!row.analysis.guidance) {
    const packageUpdate = /package|update/.test(row.event.event_type);
    row.analysis.guidance = {source: "policy", steps: packageUpdate ? [
      "Check the approved maintenance record and identify who initiated this update.",
      "Verify the package source and installed version against your approved release.",
      "Check service health. An update alone does not establish malicious activity or justify automatic rollback.",
    ] : ["Verify the affected device, actor and time in the original event and related records.",
      "Check whether this activity matches an approved change; identify what remains unknown.",
      row.analysis.responses?.[0]?.reason ?? "Investigate unexplained activity before choosing a scoped response."],
      caution: "Policy-guided investigation, not an AI-generated action plan. Demo approvals change browser state only."};
  }
}

export function refreshDemoResponse(row: TelemetryRow, now = Date.now() / 1000) {
  const review = row.response_case;
  if (!review) return;
  if (review.state === "pending" && review.deadline !== null && now >= review.deadline) {
    review.state = review.mode === "automatic" ? "executed" : "overdue";
    review.note = review.mode === "automatic" ? "Scheduled recommendation approved in simulation only. Nothing was executed on a device." : "Review deadline passed. No simulated response was pre-authorized.";
    if (review.state === "executed") {
      review.expires_at = review.deadline + 300;
      row.analysis?.responses?.forEach(r => {r.status = "approved-simulation";});
    }
  }
  if (review.state === "executed" && review.expires_at && now >= review.expires_at) {
    review.state = "expired"; review.note = "The simulated five-minute response expired. No device changes were made.";
    row.analysis?.responses?.forEach(r => {r.status = "expired-simulation";});
  }
}

export function controlDemoResponse(rows: TelemetryRow[], id: string, command: string, reason = "", now = Date.now() / 1000) {
  rows.forEach(row => refreshDemoResponse(row, now));
  if (command === "stop" || command === "resume") {
    rows.forEach(row => {
      row.response_stopped = command === "stop";
      if (command === "stop" && row.response_case?.state === "pending" && row.response_case.mode === "automatic") {
        row.response_case.mode = "review";
        row.response_case.note = "Scheduled simulation cancelled. Resume does not re-arm it.";
      }
    });
    return;
  }
  const row = rows.find(row => row.event_id === id), review = row?.response_case;
  if (!row || !review) throw new Error("No completed escalation to review.");
  if (command === "undo") {
    if (review.state !== "executed") throw new Error("No active simulated response to undo.");
    review.state = "undone"; review.note = "Simulated response undone. No device was changed.";
    row.analysis?.responses?.forEach(r => {r.status = "undone-simulation";});
    return;
  }
  if (!["pending", "overdue"].includes(review.state)) throw new Error("This review is already closed.");
  if (command === "reviewed" || command === "reject") {
    if (!reason.trim()) throw new Error("Record a reason.");
    review.state = command === "reviewed" ? "reviewed" : "rejected";
    review.mode = "review"; review.note = reason.slice(0, 1000);
    row.analysis?.responses?.forEach(r => {r.status = review.state;});
  } else if (command === "defer") {
    if (!reason.trim() || review.state !== "pending" || review.deadline === null || review.deferred) throw new Error("A reason and an unused future deadline are required.");
    review.deadline += {critical:60, high:300, medium:1800}[review.severity as "critical" | "high" | "medium"];
    review.deferred = true; review.note = reason.slice(0, 1000);
  } else if (command === "schedule") {
    if (row.response_stopped || !row.response_schedule_available || review.state !== "pending") throw new Error("This response cannot be scheduled.");
    review.mode = "automatic"; review.note = "At the deadline, record the recommendation as approved in this browser simulation only. No native action is executed.";
  } else if (command === "approve") {
    if (!row.analysis?.responses?.length) throw new Error("No recommendation to approve.");
    review.state = "executed"; review.mode = "manual"; review.expires_at = now + 300;
    review.note = "Recommendation approved in simulation only. Your device is unchanged; Undo resets this simulated response.";
    row.analysis.responses.forEach(r => {r.status = "approved-simulation";});
  } else throw new Error("Unknown demo response command.");
}
