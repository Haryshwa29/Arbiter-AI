// Runs after the public-site build (client + SSR). Splices the SSR-rendered
// Site (Nav + Landing + Footer) into dist/index.html's #root, sets its
// title/meta/OG tags, and moves the original plain SPA shell to
// dist/app/index.html so /app/* keeps getting a bare shell (it hydrates
// client-side; there is no SEO reason to prerender an auth-gated
// dashboard). See docs/LANDING-BRIEF.md §1.
//
// Only ever invoked by `npm run build:public` — the default `npm run build`
// never runs this, so a customer install's dist/index.html stays the plain
// dashboard shell it already was.
import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dirname, "..");
const dist = resolve(root, "dist");
const shellPath = resolve(dist, "index.html");
const ssrEntry = resolve(dist, "server", "entry-server.js");

if (!existsSync(ssrEntry)) {
  throw new Error(
    `${ssrEntry} not found — run "vite build --ssr src/entry-server.tsx --mode public" before this script.`,
  );
}

const shell = readFileSync(shellPath, "utf-8");

// dist/app/index.html: the untouched plain shell, for /app/* to hydrate
// into fresh (no prerendered content to reconcile against).
mkdirSync(resolve(dist, "app"), { recursive: true });
writeFileSync(resolve(dist, "app", "index.html"), shell);

const { render } = await import(pathToFileURL(ssrEntry).href);
const { html, meta } = render();

const withRoot = shell.replace('<div id="root"></div>', `<div id="root">${html}</div>`);
const withTitle = withRoot.replace(/<title>.*?<\/title>/, `<title>${meta.title}</title>`);
const withMeta = withTitle.replace(
  "</head>",
  [
    `<meta name="description" content="${meta.description}" />`,
    `<meta property="og:type" content="website" />`,
    `<meta property="og:title" content="${meta.title}" />`,
    `<meta property="og:description" content="${meta.description}" />`,
    "</head>",
  ].join("\n    "),
);

writeFileSync(shellPath, withMeta);
rmSync(resolve(dist, "server"), { recursive: true, force: true });

console.log("dist/index.html      -> prerendered landing (site/), title/description/OG set");
console.log("dist/app/index.html  -> plain dashboard shell (basename /app)");
