import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // No proxy needed - using Tauri IPC for backend communication
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
})
