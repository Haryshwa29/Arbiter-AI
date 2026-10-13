import { useEffect, useState } from "react";
import { configureConnector, getIngestionStatus, requestPermissions, getModels, connectModel } from "../lib/api";
import type { Connector, IngestionStatus } from "../lib/api";
import { useAuth } from "../lib/auth";
import { StatTile } from "../components/StatTile";

const control = "rounded border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500";
const labels: Record<string, string> = {path: "Local file or executable path", region: "AWS region", profile: "AWS profile (blank uses default credentials)", detector_id: "GuardDuty detector ID (optional)", host: "Listen address", port: "UDP port", interval: "Inventory interval in seconds", allowed_senders: "Allowed sender networks, separated by commas"};

export function DataSources() {
  const { user } = useAuth();
  const [models, setModels] = useState<string[]>([]);
  const [model, setModel] = useState("");
  const [modelChecked, setModelChecked] = useState(false);
  const [status, setStatus] = useState<IngestionStatus | null>(null);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<Connector | null>(null);
  const [config, setConfig] = useState<Record<string, unknown>>({});
  const [enabled, setEnabled] = useState(true);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    async function refresh() {
      try { const result = await getIngestionStatus(); if (active) { setStatus(result); setError(""); } }
      catch { if (active) setError("Could not load data sources. Check the connection and retry."); }
      if (active) timer = setTimeout(() => void refresh(), 3000);
    }
    void refresh();
    return () => { active = false; clearTimeout(timer); };
  }, []);
  function select(source: Connector) {
    setSelected(source); setConfig({...source.configuration}); setEnabled(source.enabled || source.status === "Available"); setError("");
  }
  async function save() {
    if (!selected) return;
    setBusy(true);
    try {
      await configureConnector(selected.name, enabled, config);
      setStatus(await getIngestionStatus()); setSelected(null); setError("");
    } catch (e) { setError(e instanceof Error ? e.message : "Could not save source configuration."); }
    finally { setBusy(false); }
  }
  const active = status?.connectors.filter(c => c.category !== "Demo" && c.name !== "api" && ["Connected", "Listening"].includes(c.status));
  return <div className="flex max-w-6xl flex-col gap-6">
    <header><h1 className="text-lg font-medium">Data Sources</h1><p className="mt-1 text-sm text-neutral-400">Installed Windows tools are connected automatically: Sysmon activity, osquery inventory and Microsoft Defender detections. Explicitly disabled sources stay disabled.</p></header>
    {error && <p role="alert" className="text-sm text-amber-300">{error}</p>}
    {!status && !error && <p role="status">Loading sources…</p>}
    {status && <>
      <section className="rounded-lg border border-neutral-700 p-5"><h2 className="font-medium">Device monitoring · {status.device}</h2>
        <p className="mt-2 text-sm text-neutral-300">{status.connectors.some(c => c.enabled && c.error) ? "Needs permission or configuration" : active?.length ? "Monitoring" : "Setup needed"} · {status.elevated ? "Approved temporary IP blocking is available for supported detections" : "Protection requires Windows administrator access"}. Automatic actions are disabled.</p>
        <p className="mt-2 text-xs text-neutral-400">{status.coverage}. Analysis: {status.backend === "mock" ? "Test backend; local AI is not connected" : `Local AI (${status.model})`}.</p>
        {status.connectors.some(c => c.name === "windows" && c.enabled && c.error) && <p className="mt-3 text-sm text-amber-300">A selected Windows channel is unavailable or access was denied. Check the source error below. Administrator access can allow Security log reading; it does not enable automatic protective actions.</p>}
        {user?.role === "admin" && <div className="mt-3 flex flex-wrap gap-3"><button className={control} onClick={async () => {try {const result = await getModels(); setModels(result.models); setModel(result.models[0] ?? ""); setModelChecked(true);} catch {setError("Could not check local model availability.");}}}>Check local AI models</button>{models.length > 0 && <><select className={control} value={model} onChange={e => setModel(e.target.value)} aria-label="Local model">{models.map(name => <option key={name}>{name}</option>)}</select><button className={control} disabled={busy} onClick={async () => {setBusy(true); try {await connectModel(model); setStatus(await getIngestionStatus()); window.location.reload();} catch(e) {setError(e instanceof Error ? e.message : "Could not connect local AI.");} finally {setBusy(false);}}}>Connect local AI</button></>}</div>}
        {modelChecked && !models.length && <p className="mt-2 text-xs text-amber-300">No installed local model is available. Start your local Ollama service with a model installed, then check again. Arbiter remains on the displayed backend.</p>}
        {!status.elevated && status.can_request_permission && user?.role === "admin" && <button className={`${control} mt-3`} disabled={busy} onClick={async () => {
          if (!window.confirm("Restart Arbiter with administrator access to read Windows Security logs? Windows will ask for approval. An active demo will stop. Automatic protection remains disabled.")) return;
          setBusy(true);
          try {await requestPermissions(); setError("Permission approved. Arbiter is restarting; refresh this page shortly.");}
          catch (e) {setError(e instanceof Error ? e.message : "Permission request failed.");}
          finally {setBusy(false);}
        }}>Request Windows log access</button>}
      </section>
      <section aria-label="Ingestion metrics" className="grid grid-cols-2 gap-3 lg:grid-cols-3">
        {[['Events ingested', 'events_ingested'], ['Routine observations', 'events_filtered'], ['Deterministic decisions', 'events_handled_deterministically'], ['Sent to AI tier', 'events_escalated_to_ai'], ['Alerts created', 'alerts_created'], ['Queue depth', 'queue_depth']].map(([label, key]) => <StatTile key={key} label={label} value={status.metrics[key] ?? 0} />)}
      </section>
      <p role="status" className="text-sm text-neutral-400">{active?.length ? `${active.length} live sources connected.` : "No data sources connected."} Worker: {status.worker_alive ? "Running" : "Stopped"}. Mean analysis: {Math.round(status.metrics.processing_latency_ms ?? 0)} ms. Normalization failures: {status.metrics.normalization_failures ?? 0}.</p>
      {user?.role === "admin" && <label className="flex max-w-md flex-col gap-2 text-sm">Add Data Source
        <select className={control} value={selected?.name ?? ""} onChange={e => { const source = status.connectors.find(c => c.name === e.target.value); if (source) select(source); }}>
          <option value="">Choose a source…</option>{status.connectors.filter(c => c.implemented && Object.keys(c.configuration).length).map(c => <option key={c.name} value={c.name}>{c.label}</option>)}
        </select></label>}
      {selected && <section className="rounded-lg border border-neutral-700 p-5" aria-label={`${selected.label} configuration`}>
        <h2 className="font-medium">{selected.label}</h2><p className="mt-1 text-sm text-neutral-400">{selected.description}</p>
        <form className="mt-4 grid gap-4 md:grid-cols-2" onSubmit={e => { e.preventDefault(); void save(); }}>
          {Object.entries(config).map(([key, value]) => key === "channels" ? <fieldset key={key}><legend className="mb-2 text-sm">Windows channels</legend>{["Security", "System", "Application"].map(channel => <label key={channel} className="mr-4 inline-flex gap-2 text-sm"><input type="checkbox" checked={(value as string[]).includes(channel)} onChange={e => setConfig({...config, channels: e.target.checked ? [...value as string[], channel] : (value as string[]).filter(c => c !== channel)})} />{channel}</label>)}</fieldset> : typeof value === "boolean" ? <label key={key} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={value} onChange={e => setConfig({...config, [key]: e.target.checked})} />Read existing history on first connection</label> : <label key={key} className="flex flex-col gap-2 text-sm">{labels[key] ?? key}<input className={control} type={typeof value === "number" ? "number" : "text"} value={Array.isArray(value) ? value.join(", ") : String(value)} onChange={e => setConfig({...config, [key]: Array.isArray(value) ? e.target.value.split(",").map(s => s.trim()).filter(Boolean) : typeof value === "number" ? Number(e.target.value) : e.target.value})} /></label>)}
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />Enable collection</label>
          <div className="flex gap-3"><button disabled={busy} className={control}>{busy ? "Saving…" : "Save source"}</button><button type="button" className={control} onClick={() => setSelected(null)}>Cancel</button></div>
        </form>
      </section>}
      {["Endpoints", "Network", "Cloud", "Other", "Demo"].map(category => <section key={category}><h2 className="mb-3 text-xs uppercase tracking-wide text-neutral-400">{category}</h2>
        <div className="grid gap-3 md:grid-cols-2">{status.connectors.filter(c => c.category === category).map(c => <article key={c.name} className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-4">
          <div className="flex items-start justify-between gap-3"><h3 className="font-medium">{c.label}</h3><span className={`text-xs ${["Connected", "Listening"].includes(c.status) ? "text-emerald-300" : c.status === "Error" ? "text-amber-300" : "text-neutral-400"}`}>{c.status}</span></div>
          <p className="mt-2 text-xs text-neutral-400">{c.events_received} events · {c.events_per_minute ?? 0}/min · {c.errors} errors</p>
          <p className="mt-1 text-xs text-neutral-500">Last event: {c.last_event_received ? new Date(c.last_event_received).toLocaleString() : "None"}</p>
          {c.error && <p className="mt-2 text-xs text-amber-300">{c.error}</p>}
          {user?.role === "admin" && c.implemented && Object.keys(c.configuration).length > 0 && <button type="button" className="mt-3 text-sm text-sky-300 underline focus-visible:ring-2" onClick={() => select(c)}>Configure {c.label}</button>}
        </article>)}</div></section>)}
    </>}
  </div>;
}
