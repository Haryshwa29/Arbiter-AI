import { renderToString } from "react-dom/server";
import { Site } from "./site/Site";

// SSR entry for the public-site build only (docs/LANDING-BRIEF.md §1's
// prerender requirement). Renders Site (Nav + Landing + Footer) alone, not
// the whole <App/> — the dashboard is auth-gated and has no SEO value.
// Landing.tsx renders its Stacked layout whenever the viewport-match effect
// hasn't run yet (i.e. during SSR, and on first client paint before
// hydration), so this renders every layer's copy at full opacity as ordinary
// prose — no five-blocks-at-opacity-0 gap for a crawler to discount.
export const LANDING_META = {
  // No category name and no pricing claim in the title either — the landing
  // does not position against a category the visitor may already own.
  title: "Arbiter AI — a shield you can raise before you can afford an army",
  description:
    "A self-hosted AI security analyst for companies with real log volume and no security team. Nothing leaves your network, and every decision comes with a written rationale you can read.",
};

export function render() {
  return { html: renderToString(<Site />), meta: LANDING_META };
}
