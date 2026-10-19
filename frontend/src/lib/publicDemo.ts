import type { DemoStatus, ImportSummary, TelemetryEvent, TelemetryRow } from "./api";
import { sampleDatasets } from "./cloudDemoSamples.ts";
type Configuration = NonNullable<DemoStatus["inference"]>;
let configuration: Configuration | null = null;
let run: DemoStatus = {state: "ready", total: 0, delivered: 0, completed: 0, events: []};
let generation = 0, succeeded = 0, failed = 0, active = 0;
let historyToken: string | undefined;
let timer: ReturnType<typeof setTimeout> | undefined;
let controller: AbortController | undefined;
async function request<T>(path: string, body?: unknown, signal?: AbortSignal, attempt = 0): Promise<T> {
  let response: Response;
  try { response = await fetch(`/public-demo/${path}`, {
    method: body === undefined ? "GET" : "POST", credentials: "same-origin",
    headers: {"X-Arbiter-Demo": "1", ...(body === undefined ? {} : {"Content-Type": "application/json"})},
    body: body === undefined ? undefined : JSON.stringify(body), signal: signal ?? AbortSignal.timeout(55000),
  }); } catch { throw new Error("AI service could not be reached. No AI decision was produced."); }
  if (!response.headers.get("content-type")?.includes("application/json")) throw new Error("The live AI function is not deployed on this website yet.");
  const data = await response.json();
  if (!response.ok) {
    if (path === "analyze" && [429, 502, 503, 504].includes(response.status) && data.code !== "demo_rate_limit" && attempt < 4) {
      const wait = Math.min(60, Math.max(2, Number(data.retry_after) || 2 ** (attempt + 1)));
      run.error = `AI temporarily unavailable. Retrying this event in ${wait}s (${attempt + 1}/4).`;
      await new Promise<void>((resolve, reject) => {
        if (signal?.aborted) {reject(new Error("Request stopped.")); return;}
        const stop = () => {clearTimeout(handle); reject(new Error("Request stopped."));};
        const handle = setTimeout(() => {signal?.removeEventListener("abort", stop); resolve();}, wait * 1000);
        signal?.addEventListener("abort", stop, {once: true});
      });
      return request<T>(path, body, signal, attempt + 1);
    }
    throw new Error(data.error || "The cloud AI request failed.");
  }
  if (path === "analyze") run.error = undefined;
  return data as T;
}
function normalize(raw: unknown): TelemetryEvent {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("Each record must be an event object.");
  const record = raw as Record<string, unknown>;
  const v = (record.event && typeof record.event === "object" ? record.event : record) as Record<string, unknown>;
  const hostname = v.hostname ?? v.host, event_type = v.event_type ?? v.type, source_type = v.source_type ?? v.source;
  if ([hostname, event_type, source_type, v.message].some(x => typeof x !== "string" || !x.trim())) throw new Error("Events require host/hostname, event_type, source/source_type and message.");
  const severity = Number(v.severity ?? 5);
  if (!Number.isFinite(severity) || severity < 0 || severity > 10) throw new Error("Severity must be between 0 and 10.");
  const event = {...v, event_id: crypto.randomUUID(), hostname, event_type, source_type, severity,
    message: v.message, timestamp: String(v.timestamp || ""), received_at: new Date().toISOString(),
    event_category: String(v.event_category || "demo"), username: String(v.username || ""), metadata: {}, raw_event: v,
    fields: v.fields ?? (v.raw_event as Record<string, unknown> | undefined)?.fields ?? {}} as TelemetryEvent;
  if (new TextEncoder().encode(JSON.stringify(event)).length > 12000) throw new Error("Each preview event must fit within 12 KiB.");
  return event;
}
function csv(content: string): Record<string, string>[] {
  const rows: string[][] = []; let row: string[] = [], field = "", quoted = false;
  for (let i = 0; i <= content.length; i++) {
    const c = content[i];
    if (c === '"') {if (quoted && content[i + 1] === '"') {field += '"'; i++;} else quoted = !quoted;}
    else if (!quoted && (c === "," || c === "\n" || c === undefined)) {
      row.push(field.replace(/\r$/, "")); field = "";
      if (c !== ",") {if (row.some(Boolean)) rows.push(row); row = [];}
    } else if (c !== undefined) field += c;
  }
  if (quoted) throw new Error("Unclosed CSV quotation.");
  const keys = rows.shift() ?? [];
  return rows.map(values => Object.fromEntries(keys.map((key, i) => [key, values[i] ?? ""])));
}
function prepare(body: Record<string, unknown>) {
  const groups: {filename: string; records: unknown[]}[] = [];
  for (const name of body.datasets as string[] ?? []) {
    if (!Object.hasOwn(sampleDatasets, name)) throw new Error("Unknown sample dataset.");
    groups.push({filename: name, records: sampleDatasets[name]});
  }
  const uploads = body.uploads as {filename: string; content: string}[] ?? [];
  if (uploads.length > 20 || uploads.reduce((n, f) => n + new TextEncoder().encode(f.content).length, 0) > 5 * 1024 * 1024) throw new Error("Upload limit exceeded.");
  for (const file of uploads) {
    const ext = file.filename.split(".").pop()?.toLowerCase(); let records: unknown[];
    if (ext === "json") {const data = JSON.parse(file.content); records = Array.isArray(data) ? data : [data];}
    else if (ext === "jsonl") records = file.content.split(/\r?\n/).filter(line => line.trim() && !line.trim().startsWith("#")).map(line => JSON.parse(line));
    else if (ext === "csv") records = csv(file.content);
    else throw new Error("Use JSON, JSONL or CSV event files.");
    groups.push({filename: file.filename, records});
  }
  if (groups.reduce((n, g) => n + g.records.length, 0) > 500) throw new Error("Choose at most 500 events for the cloud demo.");
  const events: TelemetryEvent[] = [], files: ImportSummary[] = [];
  for (const group of groups) {
    const errors: string[] = []; let valid = 0;
    for (const raw of group.records) {try {events.push(normalize(raw)); valid++;} catch (e) {if (errors.length < 20) errors.push(e instanceof Error ? e.message : "Invalid event");}}
    files.push({filename: group.filename, detected_format: group.filename.split(".").pop() || "json", number_of_events: group.records.length,
      valid_events: valid, invalid_events: group.records.length - valid, accepted_events: valid, import_status: errors.length ? "invalid" : "valid", errors});
  }
  return {events, files};
}
function recommendResponse(event: TelemetryEvent, decision: string) {
  if (decision !== "escalate") return [];
  const text = `${event.event_type} ${event.message}`.toLowerCase();
  let kind = "Investigate and preserve evidence", reason = "Review source logs and nearby events, verify the affected asset with its owner, and preserve evidence before choosing containment.";
  if (/ransom|encrypt|mass.*rename/.test(text)) {kind = "Isolate affected host after verification"; reason = "Verify unexpected encryption, preserve process and file evidence, then isolate the affected host and check backup integrity. Do not delete evidence.";}
  else if (/disk|hardware|smart/.test(text)) {kind = "Protect data and inspect disk health"; reason = "Verify disk health alerts, check recoverable backups, reduce nonessential writes and arrange replacement with the asset owner.";}
  else if (/firewall|expos|0\.0\.0\.0/.test(text)) {kind = "Review and restrict the exposed rule"; reason = "Compare the changed rule with approved access, identify required clients and propose a scoped rollback. Confirm service impact before applying it.";}
  else if (/login|auth|brute|travel|credential|root.user/.test(text)) {kind = "Verify identity and revoke suspicious access"; reason = "Confirm the activity with the account owner and inspect authentication logs. If unauthorized, revoke affected sessions and reset credentials; verify impact before locking an account.";}
  else if (/flood|syn|slowloris|ddos/.test(text)) {kind = "Validate traffic and apply scoped rate limits"; reason = "Identify offending traffic and distinguish legitimate demand. Review a temporary rate limit or narrowly scoped source block, preserving access for legitimate clients.";}
  else if (/process|exec|privilege|tamper|mining|smb/.test(text)) {kind = "Investigate execution and contain affected access"; reason = "Inspect the process tree, signer, account and peer connections. Verify authorization, then propose stopping the specific process or restricting the affected account or host. Preserve evidence first.";}
  return [{status: "awaiting-approval", kind, target: event.hostname, reason}];
}
function snapshot(): DemoStatus {return {...run, events: [...run.events], inference: configuration ? {...configuration, active, succeeded, failed} : undefined};}
export const publicDemoApi = {
  getDatasets: async () => ({datasets: Object.keys(sampleDatasets)}),
  getDemo: async () => {configuration ??= await request<Configuration>("status"); return snapshot();},
  previewDemo: async (body: Record<string, unknown>) => ({files: prepare(body).files}),
  startDemo: async (body: Record<string, unknown>) => {
    const prepared = prepare(body);
    if (!prepared.events.length || prepared.files.some(f => f.invalid_events)) throw new Error("Validate and fix your selected events first.");
    if (body.cloud_consent !== true) throw new Error("Confirm that selected events may be sent to Ollama Cloud.");
    configuration = await request<Configuration>("status");
    if (!configuration.configured) throw new Error("The website operator must configure OLLAMA_API_KEY.");
    if (["running", "paused"].includes(run.state)) throw new Error("Stop the active run first.");
    clearTimeout(timer); controller?.abort(); const version = ++generation; succeeded = failed = active = 0; historyToken = undefined;
    const speed = {"1x": 1, "2x": 2, "5x": 5, "10x": 10}[String(body.speed)] ?? 1, delay = 3000 / speed;
    let seed = Number(body.seed) >>> 0;
    const random = () => {seed = (1664525 * seed + 1013904223) >>> 0; return seed / 4294967296;};
    if (body.order === "random") for (let i = prepared.events.length - 1; i > 0; i--) {const j = Math.floor(random() * (i + 1)); [prepared.events[i], prepared.events[j]] = [prepared.events[j], prepared.events[i]];}
    run = {state: "running", session_id: crypto.randomUUID(), total: prepared.events.length, delivered: 0, completed: 0, interval_seconds: delay / 1000, events: []};
    async function next() {
      if (version !== generation || run.state === "stopped") return;
      if (run.state === "paused") {timer = setTimeout(() => void next(), 250); return;}
      const event = prepared.events[run.delivered];
      if (!event) {run.state = "completed"; return;}
      const row: TelemetryRow = {id: ++run.delivered, event_id: event.event_id, event: {...event, received_at: new Date().toISOString()}, state: "processing", error: "", related: [], analysis: null};
      run.events.unshift(row); active = 1; controller = new AbortController(); const currentController = controller;
      const timeout = setTimeout(() => currentController.abort(), 300000);
      try {
        const result = await request<NonNullable<TelemetryRow["analysis"]> & {state?: string}>("analyze", {event: {hostname: event.hostname, source_type: event.source_type,
          event_type: event.event_type, message: event.message, severity: event.severity, timestamp: event.timestamp, fields: event.fields ?? {}}, cloud_consent: true, state: historyToken}, currentController.signal);
        const {state: nextToken, ...analysis} = result;
        row.analysis = {...analysis, responses: recommendResponse(event, analysis.decision)};
        if (version === generation) historyToken = nextToken;
        row.state = "completed"; if (version === generation && row.analysis.backend === "ollama-cloud") succeeded++;
      } catch (e) {row.state = "failed"; row.error = e instanceof Error ? e.message : "AI failed"; if (version === generation) {failed++; run.error = row.error;}}
      finally {clearTimeout(timeout); if (version === generation) {active = 0; run.completed++;}}
      if (version !== generation || run.state === "stopped") return;
      if (row.state === "failed") {run.state = "failed"; return;}
      if (run.completed === run.total) {run.state = "completed"; return;}
      const gap = body.traffic === "delayed" ? delay * (.5 + random() * 2.5) : body.traffic === "bursts" ? delay * (run.delivered % 5 ? .25 : 4) : delay;
      timer = setTimeout(() => void next(), gap);
    }
    timer = setTimeout(() => void next(), delay); return snapshot();
  },
  controlDemo: async (action: string) => {
    if (action === "pause" && run.state === "running") run.state = "paused";
    else if (action === "resume" && run.state === "paused") run.state = "running";
    else if (action === "stop") {run.state = "stopped"; clearTimeout(timer); controller?.abort();}
    else throw new Error("Invalid demo transition.");
    return snapshot();
  },
  getDemoHistory: async (offset = 0, filters: Record<string, string> = {}) => {
    const events = run.events.filter(row => {
      if (filters.decision && filters.decision !== (row.analysis?.decision ?? (row.state === "failed" ? "failed" : "pending"))) return false;
      for (const [key, field] of [["host", "hostname"], ["event_type", "event_type"], ["source", "source_type"]]) if (filters[key] && !String(row.event[field]).toLowerCase().includes(filters[key].toLowerCase())) return false;
      if (filters.response && filters.response !== (row.analysis?.responses?.length ? "selected" : row.analysis ? "none" : "pending")) return false;
      return !filters.search || JSON.stringify([row.event, row.analysis]).toLowerCase().includes(filters.search.toLowerCase());
    }); return {events: events.slice(offset, offset + 100), total: events.length};
  },
  reviewResponse: async (id: string, choice: "approved-simulation" | "reviewed") => {
    const row = run.events.find(row => row.event_id === id);
    if (!row?.analysis?.responses?.length) throw new Error("No response recommendation available.");
    if (row.analysis.responses[0].status !== "awaiting-approval") throw new Error("This recommendation has already been reviewed.");
    row.analysis.responses[0].status = choice;
    return {...row};
  },
  getEvent: async (id: string) => {const row = run.events.find(row => row.event_id === id); if (!row) throw new Error("This event is not in the current browser session."); return {...row};},
};
