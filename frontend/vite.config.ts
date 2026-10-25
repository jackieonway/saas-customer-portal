import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: { sourcemap: false },
  server: {
    proxy: {
      '/auth': 'http://127.0.0.1:3101',
      '/api': 'http://127.0.0.1:3101',
      '/health': 'http://127.0.0.1:3101',
    },
  },
})
