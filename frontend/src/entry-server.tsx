import { renderToString } from "react-dom/server";
import { Site } from "./site/Site";

// SSR entry for the public-site build only (docs/LANDING-BRIEF.md §1's
// prerender requirement). Renders Site (Nav + Landing + Footer) alone, not
// the whole <App/> — the dashboard is auth-gated and has no SEO value.
// All product copy renders as ordinary prose, including without JavaScript.
export const LANDING_META = {
  // No category name and no pricing claim in the title either — the landing
  // does not position against a category the visitor may already own.
  title: "Arbiter AI — Your security. Understood.",
  description:
    "Understand Arbiter AI: local security monitoring, rules, context and optional local reasoning. Explore an animated walkthrough, decision architecture, current capabilities and Windows setup.",
};

export function render() {
  return { html: renderToString(<Site />), meta: LANDING_META };
}
