import { useState, type FormEvent } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { useAuth } from "../lib/auth";
import { ApiError } from "../lib/api";

const GENERIC_FAILURE = "Sign-in failed. If you've tried several times, wait five minutes.";

const FIELD_CLASS =
  "rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 text-sm text-neutral-100 " +
  "transition-colors outline-none focus-visible:border-neutral-500 focus-visible:ring-2 " +
  "focus-visible:ring-neutral-500/40";

export function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const reduceMotion = useReducedMotion();

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(username, password);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setError(GENERIC_FAILURE);
      } else {
        setError("Couldn't reach the server. Check that it's running and try again.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-full items-center justify-center px-4">
      <motion.div
        initial={reduceMotion ? false : { opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, ease: "easeOut" }}
        className="w-full max-w-sm rounded-xl border border-neutral-800 bg-neutral-900/60 p-8 shadow-xl shadow-black/20"
      >
        <p className="mb-6 text-sm font-medium tracking-wide text-neutral-400">Arbiter AI</p>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4" noValidate>
          <div className="flex flex-col gap-1.5">
            <label htmlFor="username" className="text-sm text-neutral-400">
              Username
            </label>
            <input
              id="username"
              name="username"
              type="text"
              autoComplete="username"
              autoFocus
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className={FIELD_CLASS}
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <label htmlFor="password" className="text-sm text-neutral-400">
              Password
            </label>
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={FIELD_CLASS}
            />
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="mt-2 rounded-md bg-neutral-100 px-3 py-2.5 text-sm font-medium text-neutral-900 transition-colors hover:bg-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-400 focus-visible:ring-offset-2 focus-visible:ring-offset-neutral-900 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting ? "Signing in…" : "Sign in"}
          </button>

          <div className="min-h-[2.5rem] text-sm text-red-400" role="alert">
            {error}
          </div>
        </form>
      </motion.div>
    </div>
  );
}
