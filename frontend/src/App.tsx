import { BrowserRouter, Navigate, Route, Routes } from "react-router";
import type { ReactNode } from "react";
import { AuthProvider, useAuth } from "./lib/auth";
import { DASH_BASE } from "./lib/routing";
import { Login } from "./views/Login";
import { AppShell } from "./components/AppShell";
import { Overview } from "./views/Overview";
import { Audit } from "./views/Audit";
import { Assets } from "./views/Assets";
import { BriefArbiter } from "./views/BriefArbiter";
import { DataSources } from "./views/DataSources";
import { LiveEvents } from "./views/LiveEvents";
import { DemoReplay } from "./views/DemoReplay";

function Loading() {
  return (
    <div className="flex h-full items-center justify-center text-sm text-neutral-500">
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
//
// The wrapper is `h-full`, not `min-h-full`. index.css gives html/body/#root
// height:100%, but a percentage min-height resolves against the parent's
// *height*, and a box carrying only min-h-full is itself height:auto — so
// every min-h-full below it collapsed to nothing. That was one bug wearing
// two faces: AppShell's sidebar ended wherever the page content ended (a
// stub on Live feed, full-length on the audit table), and Login's
// items-center had no height to centre the card within, so it sat jammed
// at the top of the viewport. A definite height fixes both, and a fixed
// frame is what the dashboard wants anyway — AppShell's <main> already
// carries its own overflow-y-auto.
//
// `data-theme="dark"` is pinned here rather than on <html> (THEME-BRIEF.md
// §4): an incident surface is read at 3am, so the dashboard is dark in both
// system settings and at every position of the landing's toggle, not
// themed. index.css's `@custom-variant dark` binds every `dark:` utility in
// the five views to this attribute, so pinning it here — rather than
// relying on prefers-color-scheme — is what makes `dark:` fire
// unconditionally. The explicit bg/text classes (not the --bg/--ink tokens)
// cover the parts of the layout no view paints over — AppShell's <main> and
// Login's own wrapper are both bare — so the page never shows the toggle's
// light background through the gaps around a dark card.
function Dashboard() {
  return (
    <div data-theme="dark" className="h-full bg-neutral-950 text-neutral-100">
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
            <Route path="live" element={<LiveEvents />} />
            <Route path="audit" element={<Audit />} />
            <Route path="assets" element={<Assets />} />
            <Route path="brief" element={<BriefArbiter />} />
            <Route path="sources" element={<DataSources />} />
            <Route path="events" element={<Navigate to={`${DASH_BASE}/live`} replace />} />
            <Route path="replay" element={<DemoReplay />} />
            <Route index element={<Navigate to={`${DASH_BASE}/overview`} replace />} />
            <Route path="*" element={<Navigate to={`${DASH_BASE}/overview`} replace />} />
          </Route>
        </Routes>
      </AuthProvider>
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path={`${DASH_BASE}/*`} element={<Dashboard />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
