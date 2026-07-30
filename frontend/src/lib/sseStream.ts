import { getMe } from "./api";
import type { StreamRow } from "./api";

const RECONNECT_DELAY_MS = 1500;
// Server sends a keepalive comment every 15s (FRONTEND-BRIEF.md §4). A
// dev-proxy (or a hard-killed backend) can leave the connection open with
// zero bytes flowing forever — EventSource's onerror never fires in that
// case, so a byte-level watchdog (not "no verdict for N seconds") is what
// actually detects it. 25s gives one missed keepalive of slack.
const WATCHDOG_MS = 25_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Consumes GET /api/stream by hand (fetch + ReadableStream) instead of
 * EventSource, specifically so a truly dead connection — no bytes at all,
 * not even keepalive comments — is detected and reconnected instead of
 * hanging open indefinitely. A 401 is read directly off the response
 * (the stream endpoint checks auth before switching to text/event-stream),
 * then routed through getMe() so the app's normal unauthorized handler
 * fires and drops the user to Login.
 */
export function connectVerdictStream(
  onMessage: (row: StreamRow) => void,
  onStatusChange: (connected: boolean) => void,
): () => void {
  let stopped = false;
  let controller: AbortController | null = null;

  async function loop() {
    while (!stopped) {
      controller = new AbortController();
      let watchdog: ReturnType<typeof setTimeout> | null = null;
      const armWatchdog = () => {
        if (watchdog) clearTimeout(watchdog);
        watchdog = setTimeout(() => controller?.abort(), WATCHDOG_MS);
      };

      try {
        const res = await fetch("/api/stream", {
          credentials: "same-origin",
          signal: controller.signal,
        });

        if (res.status === 401) {
          stopped = true;
          await getMe().catch(() => {});
          return;
        }
        if (!res.ok || !res.body) {
          throw new Error(`stream request failed: ${res.status}`);
        }

        onStatusChange(true);
        armWatchdog();

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          armWatchdog();
          buffer += decoder.decode(value, { stream: true });
          const events = buffer.split("\n\n");
          buffer = events.pop() ?? "";
          for (const evt of events) {
            for (const line of evt.split("\n")) {
              if (!line.startsWith("data:")) continue;
              try {
                onMessage(JSON.parse(line.slice(5).trim()) as StreamRow);
              } catch {
                // malformed message — ignore
              }
            }
          }
        }
      } catch {
        // Network error, watchdog-triggered abort, or a closed reader —
        // all mean the same thing here: reconnect.
      } finally {
        if (watchdog) clearTimeout(watchdog);
        onStatusChange(false);
      }

      if (stopped) return;
      await sleep(RECONNECT_DELAY_MS);
    }
  }

  loop();

  return () => {
    stopped = true;
    controller?.abort();
  };
}
