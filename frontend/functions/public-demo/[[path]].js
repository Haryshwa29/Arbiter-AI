import prompt from "../../server/cloudPrompt.js";
import {guardrail, downgrade, scopedContext, screening, signature} from "../../server/demoPolicy.js";
import {readHistory, advanceHistory} from "../../server/demoHistory.js";

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
  let event, stateToken;
  try {
    const body = JSON.parse(await boundedText(request.body, 65536));
    if (body.cloud_consent !== true) return reply(400, {error: "Confirm cloud processing before starting."});
    stateToken = body.state;
    const raw = body.event;
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error();
    for (const key of ["hostname", "event_type", "message", "source_type"]) {
      if (typeof raw[key] !== "string" || !raw[key].trim() || raw[key].length > 6000) throw new Error();
    }
    const severity = Number(raw.severity ?? 5);
    if (!Number.isFinite(severity) || severity < 0 || severity > 10) throw new Error();
    event = {host: raw.hostname, type: raw.event_type, message: raw.message,
      source: raw.source_type, severity, timestamp: String(raw.timestamp || ""),
      fields: raw.fields && typeof raw.fields === "object" && !Array.isArray(raw.fields) ? Object.fromEntries(Object.entries(raw.fields).filter(([name]) => !name.startsWith("_"))) : {}};
    if (JSON.stringify(event.fields).length > 12000) throw new Error();
  } catch { return reply(400, {error: "Invalid event or event exceeds the demo request limit."}); }

  let state;
  try { state = await readHistory(stateToken, env.OLLAMA_API_KEY); }
  catch { return reply(400, {error: "Demo history is invalid or expired. Start a new run."}); }
  const sig = signature(event);
  const history = Object.hasOwn(state.histories, sig) ? state.histories[sig] : {total:0,suppressed:0,escalated:0};
  const context = scopedContext(event);
  const pre = screening(event, history), hit = guardrail(event), standingFact = downgrade(hit,event);
  async function finish(analysis) {
    return reply(200, {...analysis, state: await advanceHistory(state,sig,analysis.decision,env.OLLAMA_API_KEY)});
  }
  if (hit && !standingFact) return finish({decision:"escalate",tier:"guardrail",score:10,backend:"deterministic",model:"",
    rationale:`Security guardrail [${hit.code}]: ${hit.reason}.`,evidence:`Non-suppressible signal: ${event.message}`,kind:"alert",responses:[]});
  if (!standingFact && pre.decision !== "ambiguous") return finish({...pre,tier:"prefilter",backend:"deterministic",model:"",
    evidence:pre.decision === "escalate" ? `Auto-escalated by prefilter: ${event.message}` : "",kind:pre.decision === "escalate" ? "alert" : "observation",responses:[]});

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
          {role: "user", content: JSON.stringify({event, asset_criticality: context.criticality,
            signature_history: history.total ? `seen ${history.total}x before: ${history.suppressed} suppressed, ${history.escalated} escalated, 0 human-overruled` : "first occurrence of this signature", environment_facts: context.facts})},
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
    return finish({decision: lowConfidence ? "escalate" : answer.decision, tier: "llm", score: pre.score,
      backend: "ollama-cloud", model, rationale: (standingFact ? `[guardrail ${hit.name} downgraded to LLM decision by standing fact: "${standingFact}"] ` : "") + (lowConfidence ? `Low-confidence suppression escalated for review. ${answer.rationale}` : answer.rationale),
      evidence: answer.evidence || (lowConfidence ? `Review ${event.host}: ${event.message}` : ""),
      kind: lowConfidence || answer.decision === "escalate" ? "alert" : "observation", responses: []});
  } catch (error) {
    const reason = abort.signal.aborted ? "request timed out" : String(error?.message).toLowerCase().includes("header")
      ? "invalid server credential header" : String(error?.message).toLowerCase().includes("redirect") ? "provider redirect rejected" : "provider connection or answer unavailable";
    return reply(502, {error: `AI failed while ${phase}: ${reason}. No AI decision was produced.`});
  }
  finally { clearTimeout(timeout); active--; }
}
