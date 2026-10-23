import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { ApiError, getEstate, previewBriefing, removeBriefing, saveBriefing } from "../lib/api";
import type { BriefingDraft, EnvironmentFact } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ErrorNotice } from "../components/ErrorNotice";

const input = "mt-2 min-h-11 w-full rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 text-base text-neutral-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-400 disabled:opacity-50";
const button = "min-h-11 rounded-md border border-neutral-700 px-4 py-2 text-sm text-neutral-100 hover:bg-neutral-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-400 disabled:cursor-not-allowed disabled:opacity-50";
const empty: BriefingDraft = { host: "", fact: "", role: "", priority: "unchanged", expires_at: "" };

export function BriefArbiter() {
  const { user } = useAuth();
  const admin = user?.role === "admin";
  const [draft, setDraft] = useState<BriefingDraft>(empty);
  const [review, setReview] = useState<BriefingDraft | null>(null);
  const [facts, setFacts] = useState<EnvironmentFact[]>([]);
  const [hosts, setHosts] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [removing, setRemoving] = useState<number | null>(null);
  const reviewHeading = useRef<HTMLHeadingElement>(null);
  const hostInput = useRef<HTMLInputElement>(null);

  async function load() {
    setLoading(true);
    setLoadError(false);
    try {
      const estate = await getEstate();
      setFacts(estate.facts.filter(f => f.created_by).reverse());
      setHosts(estate.assets.map(a => a.host));
    } catch { setLoadError(true); }
    finally { setLoading(false); }
  }
  useEffect(() => { void load(); }, []);
  useEffect(() => { if (review) reviewHeading.current?.focus(); }, [review]);

  function change<K extends keyof BriefingDraft>(key: K, value: BriefingDraft[K]) {
    setDraft(d => ({ ...d, [key]: value }));
    setError("");
    setNotice("");
  }
  async function preview(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setError(""); setNotice("");
    try {
      const expires_at = draft.expires_at ? new Date(draft.expires_at).toISOString() : "";
      setReview((await previewBriefing({ ...draft, expires_at })).briefing);
    } catch (e) { setError(e instanceof ApiError ? e.message : "Could not prepare the briefing. Check the connection and expiry, then retry."); }
    finally { setBusy(false); }
  }
  async function confirm() {
    if (!review || busy) return;
    setBusy(true); setError("");
    try {
      await saveBriefing(review);
      setReview(null); setDraft(empty);
      setNotice("Briefing saved. Arbiter will use this context for future matching events; earlier verdicts are unchanged.");
      hostInput.current?.focus();
      await load();
    } catch (e) { setError(e instanceof ApiError ? e.message : "Save could not be confirmed. Reload saved briefings before retrying to avoid duplicates."); }
    finally { setBusy(false); }
  }
  async function remove(id: number) {
    setBusy(true); setError(""); setNotice("");
    try {
      await removeBriefing(id); setRemoving(null);
      setNotice("Context removed. Asset role and priority remain as explicitly configured.");
      await load();
    } catch { setError("Could not confirm removal. Reload saved briefings and retry."); }
    finally { setBusy(false); }
  }

  return <div className="mx-auto flex max-w-5xl flex-col gap-6 text-neutral-200">
    <header>
      <h1 className="text-xl font-medium text-neutral-100">Brief Arbiter</h1>
      <p className="mt-2 max-w-2xl text-base leading-relaxed text-neutral-400">Tell Arbiter what a machine does, what matters most, and which behavior you expect. Review the exact context before adding it to memory.</p>
    </header>
    <p className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-4 text-sm leading-relaxed text-neutral-300">Briefings inform future analysis. They do not authorize actions, disable detection, or create exceptions. Notes are saved as written; this form does not interpret them with an AI model. Scope currently supports one exact host per briefing.</p>
    {!admin && <p role="status" className="text-sm text-neutral-300">You can read saved briefings. An administrator can add or remove context and change asset priority.</p>}
    {notice && <p role="status" className="rounded-lg border border-neutral-700 p-4 text-sm">{notice}</p>}
    {error && <p role="alert" className="rounded-lg border border-red-900 p-4 text-sm text-red-300">{error}</p>}
    <div className="grid min-w-0 gap-6 xl:grid-cols-2">
      {admin && <section className="min-w-0 rounded-lg border border-neutral-800 bg-neutral-900/40 p-5">
        {!review ? <form onSubmit={preview}>
          <h2 className="text-base font-medium">Explain your environment</h2>
          <fieldset disabled={busy} className="mt-5 flex min-w-0 flex-col gap-5">
            <label className="text-sm" htmlFor="brief-host">Exact hostname or IP
              <input ref={hostInput} id="brief-host" list="brief-hosts" required maxLength={255} value={draft.host} onChange={e => change("host", e.target.value)} className={input} placeholder="e.g. lab-vm-01" aria-describedby="host-help" />
            </label>
            <datalist id="brief-hosts">{hosts.map(h => <option key={h} value={h} />)}</datalist>
            <p id="host-help" className="-mt-3 text-sm text-neutral-400">Use the host identifier shown in events. Subnets and wildcards are not supported.</p>
            <label className="text-sm" htmlFor="brief-context">What should Arbiter know?
              <textarea id="brief-context" required maxLength={2000} rows={6} value={draft.fact} onChange={e => change("fact", e.target.value)} className={input} placeholder="This is a development VM used for testing. It should never contain customer data." />
            </label>
            <details><summary className="min-h-11 cursor-pointer py-2 text-sm focus-visible:outline focus-visible:outline-neutral-400">Asset details and expiry (optional)</summary>
              <div className="mt-3 flex flex-col gap-5">
                <label className="text-sm" htmlFor="brief-role">Asset role <input id="brief-role" maxLength={200} value={draft.role} onChange={e => change("role", e.target.value)} className={input} placeholder="Leave blank to keep the current role" /></label>
                <label className="text-sm" htmlFor="brief-priority">Protection priority
                  <select id="brief-priority" value={draft.priority} onChange={e => change("priority", e.target.value as BriefingDraft["priority"])} className={input}>
                    <option value="unchanged">Keep current priority</option><option value="standard">Standard · 1.3×</option><option value="important">Important · 1.6×</option><option value="critical">Critical · 2.0×</option>
                  </select>
                </label>
                <label className="text-sm" htmlFor="brief-expiry">Context expires (your local time)<input type="datetime-local" id="brief-expiry" value={draft.expires_at} onChange={e => change("expires_at", e.target.value)} className={input} /></label>
                <p className="text-sm text-neutral-400">Expiry applies to the note. Role and priority changes persist until explicitly changed.</p>
              </div>
            </details>
            <button className={`${button} bg-neutral-800`} type="submit">{busy ? "Preparing…" : "Review briefing"}</button>
          </fieldset>
        </form> : <div>
          <h2 ref={reviewHeading} tabIndex={-1} className="text-base font-medium focus-visible:outline focus-visible:outline-neutral-400">Review before saving</h2>
          <dl className="mt-5 space-y-4 break-words text-sm">
            <div><dt className="text-neutral-400">Applies only to</dt><dd className="mt-1">{review.host}</dd></div>
            <div><dt className="text-neutral-400">Context as written</dt><dd className="mt-1 whitespace-pre-wrap">{review.fact}</dd></div>
            <div><dt className="text-neutral-400">Asset role</dt><dd>{review.role || "Unchanged"}</dd></div>
            <div><dt className="text-neutral-400">Protection priority</dt><dd>{review.priority === "unchanged" ? "Unchanged" : review.priority}</dd></div>
            <div><dt className="text-neutral-400">Context expiry</dt><dd>{review.expires_at ? new Date(review.expires_at).toLocaleString() : "Until removed"}</dd></div>
          </dl>
          <div className="mt-6 flex flex-wrap gap-3"><button disabled={busy} onClick={() => { setReview(null); setError(""); }} className={button}>Back to edit</button><button disabled={busy} onClick={() => void confirm()} className={`${button} bg-neutral-800`}>{busy ? "Saving…" : "Confirm & save"}</button></div>
        </div>}
      </section>}
      <section className="min-w-0" aria-busy={loading}>
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3"><h2 className="text-base font-medium">Saved briefings</h2><button disabled={busy || loading} className={button} onClick={() => void load()}>Refresh</button></div>
        {loading ? <p role="status" className="text-sm text-neutral-400">Loading briefings…</p> : loadError ? <ErrorNotice message="Could not load saved briefings." onRetry={() => void load()} /> : !facts.length ? <p className="rounded-lg border border-dashed border-neutral-700 p-5 text-sm text-neutral-400">No briefings yet. Start with a machine’s purpose and what you need to protect.</p> : <ul className="space-y-3">{facts.map(f => <li key={f.id} className="break-words rounded-lg border border-neutral-800 bg-neutral-900/40 p-5">
          <h3 className="font-medium">{f.scope}</h3><p className="mt-2 whitespace-pre-wrap text-sm leading-relaxed">{f.fact}</p>
          <p className="mt-3 text-sm text-neutral-400">Saved by {f.created_by}{f.created_at && ` · ${new Date(f.created_at).toLocaleString()}`}</p>
          <p className="mt-2 text-sm text-neutral-400">{f.expires_at ? `${new Date(f.expires_at).getTime() <= Date.now() ? "Expired" : "Expires"} · ${new Date(f.expires_at).toLocaleString()}` : "Active until removed"}</p>
          {admin && <div className="mt-4">{removing === f.id ? <div className="space-y-3"><p className="text-sm">Remove this context from future analysis? Asset role and priority will remain.</p><div className="flex flex-wrap gap-3"><button disabled={busy} className={button} onClick={() => void remove(f.id)}>Confirm removal</button><button disabled={busy} className={button} onClick={() => setRemoving(null)}>Cancel</button></div></div> : <button disabled={busy} className={button} onClick={() => setRemoving(f.id)} aria-label={`Remove briefing for ${f.scope}`}>Remove</button>}</div>}
        </li>)}</ul>}
      </section>
    </div>
  </div>;
}
