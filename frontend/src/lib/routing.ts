// Off by default: a customer install serves the dashboard at "/" exactly as
// before. Only the public-site build (VITE_PUBLIC_LANDING=true) moves it to
// "/app" so the landing can occupy "/". See docs/LANDING-BRIEF.md §1.
export const PUBLIC_LANDING = import.meta.env.VITE_PUBLIC_LANDING === "true";
export const DASH_BASE = PUBLIC_LANDING ? "/app" : "";
