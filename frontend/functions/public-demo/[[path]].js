import prompt from "../../server/cloudPrompt.js";

// Best-effort per-isolate limits, not a distributed spending cap. No payload logs.
const callers = new Map();
let windowStart = 0, used = 0, active = 0;
const headers = {"Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"};
const reply = (status, body) => new Response(JSON.stringify(body), {status, headers});
export function resetLimitsForTest() { callers.clear(); windowStart = used = active = 0; }

async function boundedText(stream, max) {
  const reader = stream?.getReader();
  if (!reader) throw new Error("Missing body");
  const chunks = []; let size = 0;
  try {
    for (;;) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > max) { await reader.cancel(); throw new Error("Body exceeds limit"); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder().decode(bytes);
}

export async function onRequest({request, env}) {
  const url = new URL(request.url);
  const model = env.OLLAMA_MODEL || "nemotron-3-nano:30b";
  if (url.pathname === "/public-demo/status" && request.method === "GET") {
    return reply(200, {backend: "ollama-cloud", model, configured: Boolean(env.OLLAMA_API_KEY)});
  }
  if (url.pathname !== "/public-demo/analyze") return reply(404, {error: "Unknown demo route."});
  if (request.method !== "POST") return reply(405, {error: "Use POST."});
  if (request.headers.get("Origin") !== url.origin || request.headers.get("X-Arbiter-Demo") !== "1") {
    return reply(403, {error: "Run the demo from this website."});
  }
  if (!env.OLLAMA_API_KEY) return reply(503, {error: "The website operator must configure OLLAMA_API_KEY."});
  if (!request.headers.get("Content-Type")?.startsWith("application/json")) return reply(415, {error: "Send JSON event data."});
  let event;
  try {
    const body = JSON.parse(await boundedText(request.body, 16384));
    if (body.cloud_consent !== true) return reply(400, {error: "Confirm cloud processing before starting."});
    const raw = body.event;
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error();
    for (const key of ["hostname", "event_type", "message", "source_type"]) {
      if (typeof raw[key] !== "string" || !raw[key].trim() || raw[key].length > 6000) throw new Error();
    }
    const severity = Number(raw.severity ?? 5);
    if (!Number.isFinite(severity) || severity < 0 || severity > 10) throw new Error();
    event = {host: raw.hostname, type: raw.event_type, message: raw.message,
      source: raw.source_type, severity, timestamp: String(raw.timestamp || ""),
      fields: raw.fields && typeof raw.fields === "object" ? raw.fields : {}};
  } catch { return reply(400, {error: "Invalid event or event exceeds the 16 KiB request limit."}); }

  const stamp = Date.now();
  if (stamp - windowStart >= 3600000) { windowStart = stamp; used = 0; callers.clear(); }
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const count = callers.get(ip) || 0;
  if (used >= 100 || count >= 25 || active >= 1) return reply(429, {error: "Free AI demo is busy or its allowance is used. Please try later."});
  used++; callers.set(ip, count + 1); active++;
  let phase = "connecting";
  const abort = new AbortController();
  const timeout = setTimeout(() => abort.abort(), 45000);
  try {
    const response = await fetch("https://ollama.com/api/chat", {
      method: "POST", redirect: "manual", signal: abort.signal,
      headers: {"Content-Type": "application/json", Authorization: `Bearer ${env.OLLAMA_API_KEY.trim()}`},
      body: JSON.stringify({model, stream: false, think: false, format: "json",
        options: {temperature: .1, num_predict: 512}, messages: [
          {role: "system", content: prompt.system},
          {role: "user", content: JSON.stringify({event, asset_criticality: 1,
            signature_history: "Hosted preview: no installed-device history is available.", environment_facts: []})},
        ]}),
    });
    if (!response.ok) {
      await response.body?.cancel();
      return reply(response.status === 429 ? 429 : 502, {error: response.status === 429
        ? "Ollama's free allowance is exhausted or busy. No AI decision was produced."
        : "Ollama could not run this model. Check the server key and model access. No AI decision was produced."});
    }
    phase = "reading response";
    const result = JSON.parse(await boundedText(response.body, 65536));
    const content = result.message?.content;
    phase = "reading model answer";
    if (typeof content !== "string") throw new Error();
    phase = "parsing model answer";
    const answer = JSON.parse(content.slice(content.indexOf("{"), content.lastIndexOf("}") + 1));
    phase = "validating model answer";
    if (!["escalate", "suppress"].includes(answer.decision) || typeof answer.confidence !== "number"
      || !Number.isFinite(answer.confidence) || answer.confidence < 0 || answer.confidence > 1
      || typeof answer.rationale !== "string" || !answer.rationale.trim()
      || typeof answer.evidence !== "string" || (answer.decision === "escalate" && !answer.evidence.trim())) throw new Error();
    const lowConfidence = answer.decision === "suppress" && answer.confidence < .7;
    return reply(200, {decision: lowConfidence ? "escalate" : answer.decision, tier: "llm", score: event.severity,
      backend: "ollama-cloud", model, rationale: lowConfidence ? `Low-confidence suppression escalated for review. ${answer.rationale}` : answer.rationale,
      evidence: answer.evidence || (lowConfidence ? `Review ${event.host}: ${event.message}` : ""),
      kind: lowConfidence || answer.decision === "escalate" ? "alert" : "observation", responses: []});
  } catch (error) {
    const reason = abort.signal.aborted ? "request timed out" : String(error?.message).toLowerCase().includes("header")
      ? "invalid server credential header" : String(error?.message).toLowerCase().includes("redirect") ? "provider redirect rejected" : "provider connection or answer unavailable";
    return reply(502, {error: `AI failed while ${phase}: ${reason}. No AI decision was produced.`});
  }
  finally { clearTimeout(timeout); active--; }
}
