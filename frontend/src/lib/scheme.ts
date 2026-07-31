/**
 * The theme override (docs/THEME-BRIEF.md §1a): prefers-color-scheme stays
 * the default, this is what layers a manual choice on top of it.
 *
 * Single source of truth, read from three places that must agree:
 *   - index.html's inline head script (can't import this — it runs before
 *     any module does, duplicated there by necessity, kept in sync by hand)
 *   - the nav's toggle button, which calls `setThemeChoice`
 *   - TransitField, via `useResolvedScheme`, since the canvas can't read
 *     `[data-theme]` or the media query itself
 *
 * The stored *choice* ("system" | "light" | "dark") and the *resolved*
 * scheme ("light" | "dark") are kept distinct on purpose. `data-theme` on
 * <html> always carries the resolved value, never omitted for System:
 * index.css's `@custom-variant dark` binds every Tailwind `dark:` utility to
 * this attribute rather than to prefers-color-scheme (THEME-BRIEF.md §4), so
 * an absent attribute would desync Tailwind-styled elements from the OS
 * setting while the CSS custom properties kept following it correctly. That
 * means a System choice still has to react to the OS changing — `apply` gets
 * called again on a matchMedia change, not just from `setThemeChoice`.
 */
import { useSyncExternalStore } from "react";

export type Scheme = "light" | "dark";
export type ThemeChoice = "system" | Scheme;

const STORAGE_KEY = "arbiter-theme";
const DARK_QUERY = "(prefers-color-scheme: dark)";

const listeners = new Set<() => void>();

function isChoice(v: string | null): v is Scheme {
  return v === "light" || v === "dark";
}

function readChoice(): ThemeChoice {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return isChoice(v) ? v : "system";
  } catch {
    return "system";
  }
}

function systemScheme(): Scheme {
  return window.matchMedia(DARK_QUERY).matches ? "dark" : "light";
}

function resolve(choice: ThemeChoice): Scheme {
  return choice === "system" ? systemScheme() : choice;
}

/** Always writes a resolved value — see the module doc for why System can't
 * mean "no attribute" once Tailwind's `dark:` depends on it. */
function apply(choice: ThemeChoice) {
  document.documentElement.setAttribute("data-theme", resolve(choice));
}

/** System → Light → Dark → System. */
export function nextChoice(choice: ThemeChoice): ThemeChoice {
  return choice === "system" ? "light" : choice === "light" ? "dark" : "system";
}

export function setThemeChoice(choice: ThemeChoice) {
  try {
    if (choice === "system") localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, choice);
  } catch {
    // Storage can be unavailable (private mode, quota). The attribute still
    // gets set for this session; it just won't survive a reload.
  }
  apply(choice);
  listeners.forEach((l) => l());
}

/** Covers a system-scheme change and this tab's own `setThemeChoice` calls.
 * `storage` only fires in *other* tabs, so a local pub-sub is what makes the
 * toggle's own tab re-render immediately. A media-query change re-applies
 * the attribute only when the current choice is System — an explicit Light
 * or Dark choice must not be nudged by the OS. */
function subscribe(onChange: () => void) {
  const mq = window.matchMedia(DARK_QUERY);
  const onMediaChange = () => {
    if (readChoice() === "system") apply("system");
    onChange();
  };
  mq.addEventListener("change", onMediaChange);
  listeners.add(onChange);
  window.addEventListener("storage", onChange);
  return () => {
    mq.removeEventListener("change", onMediaChange);
    listeners.delete(onChange);
    window.removeEventListener("storage", onChange);
  };
}

function getChoiceSnapshot(): ThemeChoice {
  return readChoice();
}

function getResolvedSnapshot(): Scheme {
  return resolve(readChoice());
}

/** index.css's :root block is light-first, so SSR/prerender must agree. */
function getServerChoice(): ThemeChoice {
  return "system";
}
function getServerScheme(): Scheme {
  return "light";
}

/** The toggle's own displayed state: "system" | "light" | "dark". */
export function useThemeChoice(): ThemeChoice {
  return useSyncExternalStore(subscribe, getChoiceSnapshot, getServerChoice);
}

/** What's actually painted right now — what the canvas needs. */
export function useResolvedScheme(): Scheme {
  return useSyncExternalStore(subscribe, getResolvedSnapshot, getServerScheme);
}
