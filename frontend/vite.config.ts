import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig(({ isSsrBuild }) => ({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      // Same-origin in dev so SameSite=Strict cookies (session + CSRF) work.
      // Do not add CORS to the backend instead — see docs/FRONTEND-BRIEF.md.
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
