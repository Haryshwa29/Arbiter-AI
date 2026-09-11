// Centralized API client. Every request to the backend goes through here so
// CSRF header attachment, retry-on-stale-token, and session-expiry handling
// are each implemented exactly once (see docs/FRONTEND-BRIEF.md §3-4).

export class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(status: number, message: string, body?: unknown) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

/**
 * The backend never answered at all — the request timed out (dead process
 * behind a proxy that still accepts the socket) or `fetch` itself failed
 * (server down, DNS, offline). Distinct from `ApiError`: an `ApiError` means
 * the backend responded, just with a status a view should treat as "empty"
 * or "denied". This means there is no data to read yet, which a view must
 * not render as if there were.
 */
export class UnreachableError extends Error {
  constructor(cause: unknown) {
    super("backend unreachable");
    this.cause = cause;
  }
}

export interface User {
  username: string;
  role: "analyst" | "admin";
  demo?: boolean;
}

// Set by AuthProvider on mount. Fires when an authenticated request comes
// back 401 mid-session (the 8h session TTL expired, or the cookie was
// cleared) — anything other than the bootstrap/login flows, which handle
// 401 as an expected outcome themselves.
type UnauthorizedHandler = () => void;
let unauthorizedHandler: UnauthorizedHandler | null = null;
export function setUnauthorizedHandler(fn: UnauthorizedHandler | null): void {
  unauthorizedHandler = fn;
}

/**
 * Every view has the same failure mode when the backend is unreachable, so
 * there is one shared signal for it rather than four separately-wired ones
 * (set by AuthProvider, read by AppShell for a page-level banner) — same
 * shape as `unauthorizedHandler` above. Views still catch `UnreachableError`
 * themselves too, for their own retry affordance: the banner says the
 * backend is down, the view says which of its own requests failed.
 */
type ReachabilityHandler = (reachable: boolean) => void;
let reachabilityHandler: ReachabilityHandler | null = null;
export function setReachabilityHandler(fn: ReachabilityHandler | null): void {
  reachabilityHandler = fn;
}

function readCookie(name: string): string | null {
  const match = document.cookie.match(
    new RegExp("(?:^|; )" + name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "=([^;]*)"),
  );
  return match ? decodeURIComponent(match[1]) : null;
}

interface RequestOptions {
  method?: "GET" | "POST";
  body?: unknown;
  // The bootstrap /api/me check and /api/login itself expect a 401 as a
  // normal outcome (not logged in / bad credentials) — they must not
  // trigger the global session-expiry redirect.
  skipAuthRedirect?: boolean;
}

/**
 * Every request is bounded. A dev proxy (or `arbiter serve` dying while a
 * page stays open) leaves the socket accepted but answers nothing, and a bare
 * fetch then never settles: the views sit on their initial state forever —
 * Overview's tiles show "—" because `summary` is still null, Audit shows
 * "Loading…" because its `.finally` never runs. That reads as a broken
 * dashboard rather than an unreachable backend, which is exactly how it was
 * first reported. `sseStream.ts` already carries a watchdog for the same
 * failure on the streaming endpoint; this is the request-side equivalent.
 */
const REQUEST_TIMEOUT_MS = 10_000;

async function rawFetch(path: string, opts: RequestOptions): Promise<Response> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = {};
  let body: string | undefined;
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }
  if (method !== "GET") {
    const csrf = readCookie("arb_csrf");
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }
  try {
    return await fetch(path, {
      method,
      headers,
      body,
      credentials: "same-origin",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (e) {
    // The timeout firing and a genuine network failure both land here as a
    // rejection, not a Response — there is no status code to branch on, so
    // this is where the two get folded into one thing a view can check for.
    throw new UnreachableError(e);
  }
}

/**
 * A dev proxy (or a production reverse proxy) in front of a dead `arbiter
 * serve` doesn't always hang — Vite's proxy, finding nothing on the upstream
 * port, answers immediately with 502. That's a real Response, so it would
 * otherwise sail straight past the try/catch below and read as "the backend
 * answered, just with an error", when the truth is the same as a timeout:
 * there is no backend to talk to. 503/504 are the same story for a
 * production proxy (upstream down / gateway timeout).
 */
function isGatewayFailure(status: number): boolean {
  return status === 502 || status === 503 || status === 504;
}

async function apiFetch<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  let res: Response;
  try {
    res = await rawFetch(path, opts);
  } catch (e) {
    reachabilityHandler?.(false);
    throw e;
  }
  if (isGatewayFailure(res.status)) {
    reachabilityHandler?.(false);
    throw new UnreachableError(new Error(`gateway status ${res.status}`));
  }
  reachabilityHandler?.(true);

  if (res.status === 403 && (opts.method ?? "GET") !== "GET") {
    const peek = await res
      .clone()
      .json()
      .catch(() => null);
    if (peek?.error === "csrf token missing or invalid") {
      // Every response ensures the arb_csrf cookie exists, so a fresh read
      // should now succeed — retry exactly once per §3.
      try {
        res = await rawFetch(path, opts);
      } catch (e) {
        reachabilityHandler?.(false);
        throw e;
      }
      if (isGatewayFailure(res.status)) {
        reachabilityHandler?.(false);
        throw new UnreachableError(new Error(`gateway status ${res.status}`));
      }
    }
  }

  if (res.status === 401 && !opts.skipAuthRedirect) {
    unauthorizedHandler?.();
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new ApiError(res.status, (data as { error?: string })?.error ?? res.statusText, data);
  }
  return data as T;
}

// -- auth --------------------------------------------------------------

/**
 * Must run once at app boot, before the login form is usable: GET /api/me
 * is what seeds the arb_csrf cookie on a cold client (see §3). Returns the
 * current user if a valid session cookie is already present, else null.
 */
export async function bootstrapSession(): Promise<User | null> {
  try {
    return await apiFetch<User>("/api/me", { skipAuthRedirect: true });
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return null;
    throw e;
  }
}

export async function login(username: string, password: string): Promise<User> {
  return apiFetch<User>("/api/login", {
    method: "POST",
    body: { username, password },
    skipAuthRedirect: true,
  });
}

export async function logout(): Promise<void> {
  await apiFetch("/api/logout", { method: "POST" });
}

export async function getMe(): Promise<User> {
  return apiFetch<User>("/api/me");
}

// -- overview ------------------------------------------------------------

export interface SummaryResponse {
  today: { today: number; escalated: number; prefilter: number };
  lifetime: { triaged: number; suppressed: number; escalated: number };
}

export async function getSummary(): Promise<SummaryResponse> {
  return apiFetch("/api/summary");
}

export interface DayBucket {
  bucket: string;
  escalated: number;
  suppressed: number;
}

export async function getDay(hours: 24 | 72 | 168 = 24): Promise<{ buckets: DayBucket[] }> {
  return apiFetch(`/api/day?hours=${hours}`);
}

// -- verdicts & audit ------------------------------------------------------

export type Decision = "escalate" | "suppress";
export type Tier = "prefilter" | "llm" | "guardrail";

export interface RecordRow {
  id: number;
  ts: string;
  kind: string;
  event_id: string;
  host: string;
  signature: string;
  decision: Decision;
  score: number;
  tier: Tier;
  rationale: string;
  evidence: string;
  actor: string | null;
  detail: string; // JSON-encoded EventDetail — parse with parseDetail()
}

export interface EventDetail {
  source: string;
  message: string;
  severity: number;
  fields: Record<string, unknown>;
}

export function parseDetail(row: RecordRow): EventDetail | null {
  try {
    return JSON.parse(row.detail) as EventDetail;
  } catch {
    return null;
  }
}

export interface RecordFilters {
  decision?: Decision;
  host?: string;
  tier?: Tier;
  limit?: number;
  offset?: number;
}

export async function getRecords(filters: RecordFilters = {}): Promise<{ rows: RecordRow[] }> {
  const params = new URLSearchParams();
  if (filters.decision) params.set("decision", filters.decision);
  if (filters.host) params.set("host", filters.host);
  if (filters.tier) params.set("tier", filters.tier);
  params.set("limit", String(filters.limit ?? 100));
  params.set("offset", String(filters.offset ?? 0));
  return apiFetch(`/api/record?${params.toString()}`);
}

export async function acknowledge(id: number): Promise<void> {
  await apiFetch("/api/acknowledge", { method: "POST", body: { id } });
}

// -- assets & facts --------------------------------------------------------

export interface Asset {
  host: string;
  criticality: number;
  role: string;
  confirmed: boolean;
}

export interface EnvironmentFact {
  id: number;
  scope: string;
  fact: string;
  user: string;
  path: string;
  process: string;
  event_types: string[];
  window: string;
}

export async function getEstate(): Promise<{ assets: Asset[]; facts: EnvironmentFact[] }> {
  return apiFetch("/api/estate");
}

// Direction-aware: overruling an escalation is "false alarm" (decays
// confidence); overruling a suppression is "missed attack" (boosts it).
// Applies to every verdict sharing the signature, not just the one in view.
export type Label = "confirmed" | "overruled";

export async function labelSignature(signature: string, label: Label): Promise<void> {
  await apiFetch("/api/label", { method: "POST", body: { signature, label } });
}

// -- live feed ---------------------------------------------------------
// GET /api/stream (SSE) is consumed directly with EventSource by the Live
// feed view, not through apiFetch (it isn't a single JSON response). Its
// auth-failure handling lives there: EventSource retries forever on its
// own even on a 401, so the view must detect that case itself (a getMe()
// call routed through apiFetch, which already fires the unauthorized
// handler on 401) and tear the stream down explicitly.

export interface StreamRow {
  id: number;
  ts: string;
  host: string;
  signature: string;
  decision: Decision;
  score: number;
  tier: Tier;
  rationale: string;
}
