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

export interface User {
  username: string;
  role: "analyst" | "admin";
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
  return fetch(path, { method, headers, body, credentials: "same-origin" });
}

async function apiFetch<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  let res = await rawFetch(path, opts);

  if (res.status === 403 && (opts.method ?? "GET") !== "GET") {
    const peek = await res
      .clone()
      .json()
      .catch(() => null);
    if (peek?.error === "csrf token missing or invalid") {
      // Every response ensures the arb_csrf cookie exists, so a fresh read
      // should now succeed — retry exactly once per §3.
      res = await rawFetch(path, opts);
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
