import {test, afterEach} from "node:test";
import assert from "node:assert/strict";
import {onRequest, resetLimitsForTest} from "../functions/public-demo/[[path]].js";
import {publicDemoApi} from "../src/lib/publicDemo.ts";

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; resetLimitsForTest(); });
const event = {hostname: "synthetic-host", source_type: "sample", event_type: "process_exec", severity: 5, message: "Unknown process started"};
function call(path = "analyze", body = {event, cloud_consent: true}, env = {OLLAMA_API_KEY: "secret-test"}, extra = {}) {
  return onRequest({env, request: new Request(`https://arbiter-ai.pages.dev/public-demo/${path}`, {
    method: body === undefined || path === "status" ? "GET" : "POST",
    headers: {Origin: "https://arbiter-ai.pages.dev", "Content-Type": "application/json", "X-Arbiter-Demo": "1", ...extra},
    body: path === "status" ? undefined : JSON.stringify(body),
  })});
}
const answer = {decision: "escalate", confidence: .9, rationale: "Unexpected process needs review", evidence: "Review synthetic-host"};
function provider(data = answer) {
  globalThis.fetch = async (url, options) => {
    assert.equal(url, "https://ollama.com/api/chat");
    assert.equal(options.headers.Authorization, "Bearer secret-test");
    const payload = JSON.parse(options.body);
    assert.equal(payload.model, "nemotron-3-nano:30b");
    assert.equal(payload.messages.length, 2);
    return Response.json({message: {content: JSON.stringify(data)}});
  };
}
test("server secret stays private; missing key disables inference", async () => {
  const status = await (await call("status")).json();
  assert.equal(status.configured, true);
  assert.ok(!JSON.stringify(status).includes("secret-test"));
  assert.equal((await call("analyze", {event, cloud_consent: true}, {})).status, 503);
});
test("same origin, consent and event limits are enforced before inference", async () => {
  globalThis.fetch = () => {throw new Error("must not call provider");};
  assert.equal((await call("analyze", {event, cloud_consent: true}, undefined, {Origin: "https://other.test"})).status, 403);
  assert.equal((await call("analyze", {event})).status, 400);
  assert.equal((await call("analyze", {event: {...event, severity: "NaN"}, cloud_consent: true})).status, 400);
  assert.equal((await call("analyze", {event: {...event, message: "x".repeat(17000)}, cloud_consent: true})).status, 400);
});
test("live answer carries model provenance without actions", async () => {
  provider(); const result = await (await call()).json();
  assert.equal(result.backend, "ollama-cloud");
  assert.equal(result.model, "nemotron-3-nano:30b");
  assert.deepEqual(result.responses, []);
  assert.equal(result.rationale, answer.rationale);
});
test("uncertain suppression is escalated with evidence", async () => {
  provider({...answer, decision: "suppress", confidence: .5, evidence: ""});
  const result = await (await call()).json();
  assert.equal(result.decision, "escalate"); assert.ok(result.evidence.includes("synthetic-host"));
});
test("provider limits and malformed answers do not become mock verdicts", async () => {
  globalThis.fetch = async () => new Response("secret remote diagnostic", {status: 429});
  const response = await call(); assert.equal(response.status, 429);
  assert.ok(!(await response.text()).includes("secret"));
  provider({decision: "suppress", confidence: true});
  assert.equal((await call()).status, 502);
});
test("request allowance blocks repeated calls", async () => {
  provider();
  for (let i = 0; i < 25; i++) assert.equal((await call()).status, 200);
  assert.equal((await call()).status, 429);
});
test("browser validates files without an AI call and processes fresh events", async () => {
  let calls = 0;
  globalThis.fetch = async url => {
    if (String(url).endsWith("status")) return Response.json({configured: true, model: "nemotron-3-nano:30b", backend: "ollama-cloud"});
    calls++; return Response.json({...answer, backend: "ollama-cloud", model: "nemotron-3-nano:30b", tier: "llm", score: 5, kind: "alert", responses: []});
  };
  const body = {datasets: [], uploads: [{filename: "one.jsonl", content: JSON.stringify(event)}], speed: "10x", cloud_consent: true};
  assert.equal((await publicDemoApi.previewDemo(body)).files[0].valid_events, 1); assert.equal(calls, 0);
  await assert.rejects(publicDemoApi.startDemo({...body, cloud_consent: false}));
  await publicDemoApi.startDemo(body);
  await new Promise(resolve => setTimeout(resolve, 700));
  const state = await publicDemoApi.getDemo(); assert.equal(state.completed, 1); assert.equal(calls, 1);
  assert.equal((await publicDemoApi.getDemoHistory()).total, 1);
  assert.equal((await publicDemoApi.getEvent(state.events[0].event_id)).analysis.backend, "ollama-cloud");
  await publicDemoApi.controlDemo("stop");
});
