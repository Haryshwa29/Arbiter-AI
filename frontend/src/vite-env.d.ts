/// <reference types="vite/client" />

interface ImportMetaEnv {
  // Off by default. See docs/LANDING-BRIEF.md — gates whether the public
  // marketing landing (site/) is built in, and moves the dashboard to /app
  // when it is.
  readonly VITE_PUBLIC_LANDING?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
