import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      // Dev-only: the SPA always calls relative /api/... paths so the same
      // build works behind nginx at 127.0.0.1 and on the LAN address.
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: false,
        // Run-log SSE must not be buffered by the dev proxy.
        ws: false,
      },
    },
  },
})
