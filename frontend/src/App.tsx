import { BrowserRouter, Navigate, Route, Routes } from "react-router";
import type { ReactNode } from "react";
import { AuthProvider, useAuth } from "./lib/auth";
import { DASH_BASE, PUBLIC_LANDING } from "./lib/routing";
import { Login } from "./views/Login";
import { AppShell } from "./components/AppShell";
import { Overview } from "./views/Overview";
import { LiveFeed } from "./views/LiveFeed";
import { Audit } from "./views/Audit";
import { Assets } from "./views/Assets";
import { Site } from "./site/Site";

function Loading() {
  return (
    <div className="flex min-h-full items-center justify-center text-sm text-neutral-500">
      Loading…
    </div>
  );
}

// Explicit DASH_BASE-prefixed paths, not bare relative strings: RequireAuth
// and LoginRoute render as the element of a *pathless* layout route (no
// path of its own, just nesting), and relative <Navigate> resolution there
// resolved against the full current pathname instead of the route pattern —
// e.g. signed-out at /app/assets produced /app/assets/login, then
// re-evaluated *that* as the new "current path" and appended login again,
// looping into /app/assets/login/login/login/... Explicit paths sidestep
// the ambiguity entirely.
function RequireAuth({ children }: { children: ReactNode }) {
  const { user, ready } = useAuth();
  if (!ready) return <Loading />;
  if (!user) return <Navigate to={`${DASH_BASE}/login`} replace />;
  return <>{children}</>;
}

function LoginRoute() {
  const { user, ready } = useAuth();
  if (!ready) return <Loading />;
  if (user) return <Navigate to={`${DASH_BASE}/overview`} replace />;
  return <Login />;
}

// Its own nested <Routes> so relative paths ("login", "overview", ...)
// resolve correctly whether this is mounted at "/app/*" (public-site build)
// or "/*" (customer install, default) — and so AuthProvider, which fires the
// CSRF-bootstrap /api/me call on mount, never wraps the landing route next
// to it in App(). The landing must make zero authenticated API calls
// (docs/LANDING-BRIEF.md §1) — scoping AuthProvider here is what guarantees
// that rather than relying on discipline elsewhere.
function Dashboard() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="login" element={<LoginRoute />} />
        <Route
          element={
            <RequireAuth>
              <AppShell />
            </RequireAuth>
          }
        >
          <Route path="overview" element={<Overview />} />
          <Route path="live" element={<LiveFeed />} />
          <Route path="audit" element={<Audit />} />
          <Route path="assets" element={<Assets />} />
          <Route index element={<Navigate to={`${DASH_BASE}/overview`} replace />} />
          <Route path="*" element={<Navigate to={`${DASH_BASE}/overview`} replace />} />
        </Route>
      </Routes>
    </AuthProvider>
  );
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        {PUBLIC_LANDING && <Route path="/" element={<Site />} />}
        <Route path={`${DASH_BASE}/*`} element={<Dashboard />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
