import { NavLink, Outlet } from "react-router";
import { useAuth } from "../lib/auth";
import { DASH_BASE } from "../lib/routing";
// Explicit DASH_BASE-prefixed paths — see the comment on RequireAuth in
// App.tsx for why bare relative targets aren't safe in this pathless
// layout-route context.
const NAV_ITEMS = [
  { to: `${DASH_BASE}/overview`, label: "Overview" },
  { to: `${DASH_BASE}/sources`, label: "Data Sources" },
  { to: `${DASH_BASE}/live`, label: "Live" },
  { to: `${DASH_BASE}/replay`, label: "Demo & Replay" },
  { to: `${DASH_BASE}/audit`, label: "Verdicts & audit" },
  { to: `${DASH_BASE}/assets`, label: "Assets & facts" },
  { to: `${DASH_BASE}/brief`, label: "Brief Arbiter" },
];
export function AppShell() {
  const { user, logout, reachable } = useAuth();
  return (
    <div className="premium-dashboard flex h-full flex-col">
      {user?.demo && (
        <div role="status" className="shrink-0 bg-amber-950 px-4 py-2 text-center text-sm text-amber-200">
          Sample replay active · Live sources collect only after you enable them in Data Sources
        </div>
      )}
      {!user?.demo && user?.backend === "mock" && (
        <div role="status" className="shrink-0 bg-sky-950 px-4 py-2 text-center text-sm text-sky-200">
          Test analysis backend · Local AI is not connected · Protective actions require explicit approval
        </div>
      )}
      {/* Every view has the same failure mode when the backend is
          unreachable — one banner here beats each view inventing its own.
          Views still show their own retry inline (see Overview/Audit/Assets)
          for which of their own requests failed; this just says why. */}
      {!reachable && (
        <div
          role="status"
          className="shrink-0 border-b border-[#A76B12]/30 bg-[#A76B12]/10 px-4 py-2 text-center text-sm text-[#A76B12] dark:border-[#EF9F27]/30 dark:bg-[#EF9F27]/10 dark:text-[#EF9F27]"
        >
          Can't reach the backend — check that <code className="font-mono">arbiter serve</code> is
          running, then retry below. This clears on its own once a request gets through again.
        </div>
      )}

      <div className="flex min-h-0 flex-1 flex-col md:flex-row">
        <aside className="premium-sidebar flex w-full shrink-0 flex-col border-b border-neutral-200 bg-white px-3 py-3 md:w-56 md:border-b-0 md:border-r md:py-4 dark:border-neutral-800 dark:bg-neutral-900/40">
          <p className="mb-2 px-2 text-sm font-medium tracking-wide text-neutral-600 md:mb-6 dark:text-neutral-400">
            <span className="brand-mark">A</span> ARBITER <span className="brand-ai">AI</span>
          </p>

          <nav aria-label="Dashboard" className="flex gap-1 overflow-x-auto md:flex-1 md:flex-col md:gap-0.5">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `flex min-h-11 shrink-0 items-center whitespace-nowrap rounded-md px-2 py-1.5 text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-400 ${
                    isActive
                      ? "bg-neutral-200 text-neutral-900 dark:bg-neutral-800 dark:text-neutral-100"
                      : "text-neutral-600 hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-neutral-900 dark:hover:text-neutral-200"
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
          {user && (
            <div className="mt-2 flex items-center justify-between gap-2 md:mt-0 md:flex-col md:items-stretch md:border-t md:border-neutral-800 md:pt-3">
              <p className="truncate px-2 text-xs text-neutral-500">
                {user.username} · {user.role}
              </p>
              {!user.local_access && <button
                type="button"
                onClick={() => void logout()}
                className="rounded-md px-2 py-1.5 text-left text-sm text-neutral-600 transition-colors hover:bg-neutral-100 hover:text-neutral-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-500/40 dark:text-neutral-400 dark:hover:bg-neutral-900 dark:hover:text-neutral-200"
              >
                {user.demo ? "Sign out & shut down" : "Sign out"}
              </button>}
            </div>
          )}
        </aside>

        <main className="premium-main min-h-0 min-w-0 flex-1 overflow-y-auto p-4 sm:p-6">
          <div className="workspace-bar"><span>PRIVATE INTELLIGENCE WORKSPACE</span><span>{reachable ? "Backend reachable" : "Connection interrupted"} · {user?.backend === "mock" ? "Test backend" : "Local workspace"}</span></div>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
