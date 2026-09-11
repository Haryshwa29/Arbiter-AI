import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig(({ isSsrBuild, mode }) => ({
  plugins: [react(), tailwindcss(), {
    name: 'arbiter-build-target',
    generateBundle() {
      this.emitFile({ type: 'asset', fileName: 'arbiter-build.json',
        source: JSON.stringify({ target: mode === 'public' ? 'public' : 'self-hosted' }) });
    },
  }],
  // Same-origin so SameSite=Strict cookies (session + CSRF) work. Do not add
  // CORS to the backend instead — see docs/FRONTEND-BRIEF.md.
  //
  // `preview` needs its own copy: it does NOT inherit `server.proxy`. Without
  // this, `npm run preview` serves the built app but every /api call 404s at
  // the static server, so signing in silently does nothing — which is exactly
  // how it looked the first time.
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8787',
        changeOrigin: false,
      },
    },
  },
  preview: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8787',
        changeOrigin: false,
      },
    },
  },
  build: {
    // The SSR build (scripts/prerender.mjs, --ssr src/entry-server.tsx) needs
    // its own outDir so it never clobbers the client build it runs after —
    // see docs/LANDING-BRIEF.md §1's prerender requirement.
    outDir: isSsrBuild ? 'dist/server' : 'dist',
  },
}))
