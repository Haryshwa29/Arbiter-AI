import { createContext, useContext, useEffect, useState, useCallback } from "react";
import type { ReactNode } from "react";
import {
  bootstrapSession,
  login as apiLogin,
  logout as apiLogout,
  setUnauthorizedHandler,
  setReachabilityHandler,
} from "./api";
import type { User } from "./api";

interface AuthContextValue {
  user: User | null;
  // null while the CSRF bootstrap / initial /api/me check is in flight
  ready: boolean;
  // False from the moment any request comes back as UnreachableError, true
  // again from the next one that gets an actual response — a 401 counts as
  // reachable (see api.ts), so this never flips on session expiry.
  reachable: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [ready, setReady] = useState(false);
  const [reachable, setReachable] = useState(true);

  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null));
    setReachabilityHandler(setReachable);
    bootstrapSession()
      .then(setUser)
      .catch(() => {
        // bootstrapSession only rethrows UnreachableError (a 401 resolves to
        // null, see api.ts) — `ready` still flips so Login/RequireAuth stop
        // showing their own "Loading…" and the reachability banner takes
        // over instead of a login form nobody can submit anyway.
      })
      .finally(() => setReady(true));
    return () => {
      setUnauthorizedHandler(null);
      setReachabilityHandler(null);
    };
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const u = await apiLogin(username, password);
    setUser(u);
  }, []);

  const logout = useCallback(async () => {
    await apiLogout();
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, ready, reachable, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
