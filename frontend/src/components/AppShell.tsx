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
  const { user, logout } = useAuth();

  return (
    <div className="flex min-h-full">
      <aside className="flex w-56 shrink-0 flex-col border-r border-neutral-800 bg-neutral-900/40 px-3 py-4">
        <p className="mb-6 px-2 text-sm font-medium tracking-wide text-neutral-400">Arbiter AI</p>

        <nav className="flex flex-1 flex-col gap-0.5">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `rounded-md px-2 py-1.5 text-sm transition-colors ${
                  isActive
                    ? "bg-neutral-800 text-neutral-100"
                    : "text-neutral-400 hover:bg-neutral-900 hover:text-neutral-200"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        {user && (
          <div className="flex flex-col gap-2 border-t border-neutral-800 pt-3">
            <p className="truncate px-2 text-xs text-neutral-500">
              {user.username} · {user.role}
            </p>
            <button
              type="button"
              onClick={() => void logout()}
              className="rounded-md px-2 py-1.5 text-left text-sm text-neutral-400 transition-colors hover:bg-neutral-900 hover:text-neutral-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-500/40"
            >
              Sign out
            </button>
          </div>
        )}
      </aside>

      <main className="min-w-0 flex-1 overflow-y-auto p-6">
        <Outlet />
      </main>
    </div>
  );
}
