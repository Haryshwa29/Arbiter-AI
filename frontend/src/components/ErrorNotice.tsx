/**
 * Per-view "this specific request failed" state, shared by Overview, Audit
 * and Assets. AppShell's banner says the backend is unreachable; this says
 * which of a view's own requests came back empty because of it, and gives a
 * way to try that one request again without a full page reload.
 */
export function ErrorNotice({
  message = "Couldn't reach the server.",
  onRetry,
}: {
  message?: string;
  onRetry: () => void;
}) {
  return (
    <div className="flex flex-col items-center gap-2 py-8 text-center text-sm text-neutral-500">
      <p>{message}</p>
      <button
        type="button"
        onClick={onRetry}
        className="rounded-md border border-neutral-300 px-3 py-1.5 text-xs text-neutral-700 transition-colors hover:bg-neutral-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-500/40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
      >
        Retry
      </button>
    </div>
  );
}
