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
    rolldownOptions: {
      output: {
        codeSplitting: {
          includeDependenciesRecursively: false,
          minSize: 30_000,
          maxSize: 500_000,
          groups: [
            {
              name: 'rapier-physics',
              test: /node_modules[\\/](@dimforge|@react-three[\\/]rapier)/,
              priority: 50,
            },
            {
              name: 'three-effects',
              test: /node_modules[\\/](@react-three[\\/]postprocessing|postprocessing)/,
              priority: 40,
            },
            {
              name: 'three-runtime',
              test: /node_modules[\\/](three|@react-three[\\/](fiber|drei)|three-stdlib|maath)/,
              priority: 30,
            },
            {
              name: 'workflow-canvas',
              test: /node_modules[\\/](@xyflow|d3-)/,
              priority: 20,
            },
            {
              name: 'motion',
              test: /node_modules[\\/](@gsap|gsap)/,
              priority: 20,
            },
          ],
        },
      },
    },
  },
})
