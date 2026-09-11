import { NavLink, Outlet } from "react-router";
import { useAuth } from "../lib/auth";
import { DASH_BASE } from "../lib/routing";

// Explicit DASH_BASE-prefixed paths — see the comment on RequireAuth in
// App.tsx for why bare relative targets aren't safe in this pathless
// layout-route context.
const NAV_ITEMS = [
  { to: `${DASH_BASE}/overview`, label: "Overview" },
  { to: `${DASH_BASE}/live`, label: "Live feed" },
  { to: `${DASH_BASE}/audit`, label: "Verdicts & audit" },
  { to: `${DASH_BASE}/assets`, label: "Assets & facts" },
];

export function AppShell() {
  const { user, logout, reachable } = useAuth();

  return (
    <div className="flex h-full flex-col">
      {user?.demo && (
        <div role="status" className="shrink-0 bg-amber-950 px-4 py-2 text-center text-sm text-amber-200">
          Sample event demonstration · Local AI analysis · This computer is not being monitored
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

      <div className="flex min-h-0 flex-1">
        <aside className="flex w-56 shrink-0 flex-col border-r border-neutral-200 bg-white px-3 py-4 dark:border-neutral-800 dark:bg-neutral-900/40">
          <p className="mb-6 px-2 text-sm font-medium tracking-wide text-neutral-600 dark:text-neutral-400">
            Arbiter AI
          </p>

          <nav className="flex flex-1 flex-col gap-0.5">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `rounded-md px-2 py-1.5 text-sm transition-colors ${
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
            <div className="flex flex-col gap-2 border-t border-neutral-200 pt-3 dark:border-neutral-800">
              <p className="truncate px-2 text-xs text-neutral-500">
                {user.username} · {user.role}
              </p>
              <button
                type="button"
                onClick={() => void logout()}
                className="rounded-md px-2 py-1.5 text-left text-sm text-neutral-600 transition-colors hover:bg-neutral-100 hover:text-neutral-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-500/40 dark:text-neutral-400 dark:hover:bg-neutral-900 dark:hover:text-neutral-200"
              >
                {user.demo ? "Sign out & shut down" : "Sign out"}
              </button>
            </div>
          )}
        </aside>

        <main className="min-w-0 flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
