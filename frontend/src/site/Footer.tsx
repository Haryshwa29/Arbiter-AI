/**
 * The landing's footer — three plain links, matching Nav.tsx and
 * Landing.tsx's inline-style convention. Same repo reference Landing.tsx's
 * own Install section already uses (Haryshwa29/Arbiter-AI).
 */
import { DASH_BASE } from "../lib/routing";

const REPO_URL = "https://github.com/Haryshwa29/Arbiter-AI";

const linkClass = "no-underline transition-colors duration-200 hover:text-[var(--ink)]";

export function Footer() {
  return (
    <footer style={bar}>
      {/* A gradient hairline rather than a flat stroke, so the last edge on
          the page still catches light the way the section dividers above do. */}
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-px"
        style={{ background: "linear-gradient(90deg, rgba(255,255,255,0.1), rgba(255,255,255,0.02) 60%, transparent)" }}
      />
      <span style={wordmark}>Arbiter</span>
      <div style={links}>
        <a href={REPO_URL} style={link} className={linkClass}>
          GitHub
        </a>
        <a href={`${REPO_URL}/blob/main/README.md`} style={link} className={linkClass}>
          Docs
        </a>
        <a href={`${DASH_BASE}/`} style={link} className={linkClass}>
          Sign in
        </a>
      </div>
    </footer>
  );
}

const bar: React.CSSProperties = {
  position: "relative",
  zIndex: 1,
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  flexWrap: "wrap",
  gap: "1rem",
  padding: "2.5rem var(--gutter) 3rem",
};

const wordmark: React.CSSProperties = {
  fontSize: "var(--fs-ui)",
  color: "var(--ink-4)",
};

const links: React.CSSProperties = {
  display: "flex",
  gap: "1.75rem",
};

const link: React.CSSProperties = {
  fontSize: "var(--fs-ui)",
  color: "var(--ink-3)",
  textDecoration: "none",
};
