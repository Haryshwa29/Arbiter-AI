import type { DemoStatus, ImportSummary, TelemetryRow } from "./api";

async function request<T>(path: string, body?: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`/public-demo/${path}`, {
      method: body === undefined ? "GET" : "POST",
      credentials: "same-origin",
      headers: body === undefined ? {"X-Arbiter-Demo": "1"} : {"Content-Type": "application/json", "X-Arbiter-Demo": "1"},
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    });
  } catch { throw new Error("The website simulation service is unavailable. Try again when it is running."); }
  if (!response.headers.get("content-type")?.includes("application/json")) throw new Error("The website demo needs its separate simulation service. It is not available on a static-only host.");
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Could not run the website simulation.");
  return data as T;
}

export const publicDemoApi = {
  getDatasets: () => request<{datasets: string[]}>("datasets"),
  getDemo: () => request<DemoStatus>("status"),
  previewDemo: (body: Record<string, unknown>) => request<{files: ImportSummary[]}>("preview", body),
  startDemo: (body: Record<string, unknown>) => request<DemoStatus>("start", body),
  controlDemo: (action: string) => request<DemoStatus>("control", {action}),
  getDemoHistory: (offset = 0, filters: Record<string, string> = {}) => request<{events: TelemetryRow[]; total?: number}>(`history?${new URLSearchParams({...filters, offset: String(offset)})}`),
  getEvent: (id: string) => request<TelemetryRow>(`event?id=${encodeURIComponent(id)}`),
};
