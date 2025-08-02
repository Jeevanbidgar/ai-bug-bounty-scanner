import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import { resolve } from "path";

export default defineConfig({
  plugins: [
    vue({
      // Enable hot module replacement for Vue components
      reactivityTransform: true,
    }),
  ],
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
    },
  },
  server: {
    port: 3000,
    host: true, // Allow external connections
    open: false, // Don't auto-open browser
    strictPort: true, // Exit if port is already in use

    // Enhanced Hot Module Replacement
    hmr: {
      port: 3001, // Use different port for HMR
      overlay: true, // Show error overlay
    },

    // File watching configuration
    watch: {
      // Watch for changes in these directories
      include: [
        "src/**",
        "public/**",
        "index.html",
        "package.json",
        "vite.config.js",
        "tailwind.config.js",
        "postcss.config.js",
      ],
      // Enable polling for better file change detection
      usePolling: true,
      interval: 100,
    },

    // API and WebSocket proxying
    proxy: {
      "/api": {
        target: "http://localhost:5000",
        changeOrigin: true,
        secure: false,
        ws: false,
        configure: (proxy, _options) => {
          proxy.on("error", (err, _req, _res) => {
            console.log("API proxy error", err);
          });
          proxy.on("proxyReq", (proxyReq, req, _res) => {
            console.log("Sending Request to API:", req.method, req.url);
          });
          proxy.on("proxyRes", (proxyRes, req, _res) => {
            console.log(
              "Received Response from API:",
              proxyRes.statusCode,
              req.url
            );
          });
        },
      },
      "/socket.io": {
        target: "http://localhost:5000",
        changeOrigin: true,
        ws: true,
        secure: false,
        configure: (proxy, _options) => {
          proxy.on("error", (err, _req, _res) => {
            console.log("Socket proxy error", err);
          });
        },
      },
    },
  },

  // Development optimizations
  optimizeDeps: {
    include: ["vue", "vue-router", "pinia", "axios", "socket.io-client"],
    force: true, // Force re-optimization
  },

  // CSS configuration for hot reload
  css: {
    devSourcemap: true,
    preprocessorOptions: {
      scss: {
        additionalData: `@import "@/styles/variables.scss";`,
      },
    },
  },

  build: {
    outDir: "dist",
    assetsDir: "assets",
    sourcemap: true, // Enable source maps for debugging
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ["vue", "vue-router", "pinia"],
          utils: ["axios", "socket.io-client"],
        },
      },
    },
  },

  // Define environment variables
  define: {
    __VUE_OPTIONS_API__: true,
    __VUE_PROD_DEVTOOLS__: false,
  },
});
