/**
 * The landing's top bar: the mark, the wordmark, and the page's only CTAs.
 *
 * The hero deliberately carries no buttons — a visitor who has scrolled zero
 * pixels has been given no reason to press one — so Install and Sign in live
 * here and in the Install section, nowhere else.
 *
 * The mark's chord angle here is the source of truth: TransitField derives its
 * own LOGO constant from these two line endpoints, so every gate in the field
 * is this same shape at another scale.
 *
 * It sits in normal document flow (not fixed/sticky) — it scrolls away once
 * the pinned field takes over, which is the same behaviour any non-fixed nav
 * has above a sticky hero.
 *
 * The theme toggle sits immediately left of Sign in (THEME-BRIEF.md §1a): an
 * override on top of prefers-color-scheme, not a replacement for it — see
 * lib/scheme.ts for the System → Light → Dark cycle and the localStorage/
 * data-theme mechanics, and index.html's inline head script for the piece
 * that keeps a prerendered page from flashing the wrong theme once the
 * override can disagree with the media query.
 */
import { DASH_BASE } from "../lib/routing";
import { nextChoice, setThemeChoice, useThemeChoice } from "../lib/scheme";

const RELEASES_URL = "https://github.com/Haryshwa29/Arbiter-AI/releases";

const CHOICE_LABEL = { system: "System", light: "Light", dark: "Dark" } as const;

function ThemeToggle() {
  const choice = useThemeChoice();
  const label = CHOICE_LABEL[choice];
  return (
    <button
      type="button"
      onClick={() => setThemeChoice(nextChoice(choice))}
      style={themeToggle}
      aria-label={`Theme: ${label}. Click to switch to ${CHOICE_LABEL[nextChoice(choice)]}.`}
      title="Cycles System → Light → Dark"
    >
      {label}
    </button>
  );
}

export function Nav() {
  return (
    <header style={bar}>
      <span style={brand}>
        <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true">
          <circle cx="12" cy="12" r="9.2" fill="none" stroke="var(--mark)" strokeWidth="1.4" />
          <line x1="15" y1="3.6" x2="9" y2="20.4" stroke="var(--mark)" strokeWidth="1.4" />
        </svg>
        <span style={wordmark}>Arbiter</span>
      </span>
      <span style={actions}>
        <ThemeToggle />
        <a href={`${DASH_BASE}/`} style={ghost}>
          Sign in
        </a>
        <a href={RELEASES_URL} style={cta}>
          Install
        </a>
      </span>
    </header>
  );
}

const bar: React.CSSProperties = {
  position: "relative",
  zIndex: 5,
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  padding: "1.5rem var(--gutter)",
};

const brand: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: "0.6rem",
};

const wordmark: React.CSSProperties = {
  fontSize: "var(--fs-ui)",
  fontWeight: 500,
  letterSpacing: "-0.01em",
  color: "var(--ink)",
};

const actions: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: "1.4rem",
};

const themeToggle: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  padding: "0.5em 0.9em",
  borderRadius: 6,
  border: "1px solid var(--hair-2)",
  background: "transparent",
  fontSize: "var(--fs-tiny)",
  letterSpacing: "0.04em",
  color: "var(--ink-3)",
  cursor: "pointer",
  font: "inherit",
};

const ghost: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  padding: "0.7em 1.2em",
  borderRadius: 6,
  border: "1px solid var(--hair-2)",
  fontSize: "var(--fs-ui)",
  color: "var(--ink)",
  textDecoration: "none",
};

const cta: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  padding: "0.7em 1.2em",
  borderRadius: 6,
  background: "var(--cta-bg)",
  color: "var(--cta-ink)",
  fontWeight: 500,
  fontSize: "var(--fs-ui)",
  textDecoration: "none",
};
