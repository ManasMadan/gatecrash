import { fileURLToPath } from 'node:url'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Built straight into the Go binary's embed directory, so `pnpm build` followed by
// `go build` produces one static file with the apps inside it. There is no step
// between them and nothing to keep in sync.
export default defineConfig({
  plugins: [react()],
  base: '/attendee/',
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  build: {
    outDir: fileURLToPath(new URL('../../internal/webassets/dist/attendee', import.meta.url)),
    emptyOutDir: true,
    // es2020 rather than the default: the target market is cheap Android phones
    // with old Chrome builds, and a bundle they cannot parse is a blank screen at a
    // gate.
    target: 'es2020',
    // No sourcemaps in the shipped binary. They would roughly double its size for
    // something nobody can use on a Pi in a cupboard.
    sourcemap: false,
    // One chunk. Code splitting means extra requests, and on a saturated venue
    // network every request is a chance to fail.
    rollupOptions: {
      output: { manualChunks: undefined },
    },
  },
  server: {
    // The dev server proxies to a box running locally, so the apps can be developed
    // against real data rather than fixtures.
    proxy: {
      '/v1': { target: 'http://127.0.0.1:8080', changeOrigin: true },
      '/ca.crt': { target: 'http://127.0.0.1:8080', changeOrigin: true },
    },
  },
})
