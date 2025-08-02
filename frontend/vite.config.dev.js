import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import { resolve } from "path";

// Development-specific Vite configuration
export default defineConfig({
  plugins: [
    vue({
      reactivityTransform: true,
      template: {
        compilerOptions: {
          // Enable better error reporting in development
          onError: (err) => {
            console.error("Vue Template Error:", err);
          },
        },
      },
    }),
  ],

  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
    },
  },

  server: {
    port: 3000,
    host: "0.0.0.0",
    open: false,
    strictPort: false,

    // Enhanced HMR for development
    hmr: {
      port: 3001,
      overlay: true,
      clientPort: 3001,
    },

    // Aggressive file watching
    watch: {
      include: [
        "src/**",
        "public/**",
        "index.html",
        "package.json",
        "vite.config.js",
        "tailwind.config.js",
        "postcss.config.js",
        ".env*",
      ],
      usePolling: true,
      interval: 50, // More frequent polling
      binaryInterval: 300,
      ignoreInitial: false,
      ignored: [
        "**/node_modules/**",
        "**/.git/**",
        "**/dist/**",
        "**/.DS_Store",
        "**/Thumbs.db",
      ],
    },

    // Development middleware
    middlewareMode: false,

    // CORS configuration for development
    cors: {
      origin: "*",
      methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
      credentials: true,
    },

    // Proxy configuration with enhanced logging
    proxy: {
      "/api": {
        target: "http://localhost:5000",
        changeOrigin: true,
        secure: false,
        ws: false,
        timeout: 10000,
        configure: (proxy, _options) => {
          proxy.on("error", (err, req, res) => {
            console.log("🚨 API Proxy Error:", err.message);
            if (res && !res.headersSent) {
              res.writeHead(500, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: "Backend connection failed" }));
            }
          });

          proxy.on("proxyReq", (proxyReq, req, res) => {
            console.log("📤 Proxying API Request:", req.method, req.url);
          });

          proxy.on("proxyRes", (proxyRes, req, res) => {
            console.log("📥 API Response:", proxyRes.statusCode, req.url);
          });
        },
      },

      "/socket.io": {
        target: "http://localhost:5000",
        changeOrigin: true,
        ws: true,
        secure: false,
        timeout: 10000,
        configure: (proxy, _options) => {
          proxy.on("error", (err, req, res) => {
            console.log("🚨 Socket Proxy Error:", err.message);
          });

          proxy.on("open", (proxySocket) => {
            console.log("🔌 Socket connection opened");
          });

          proxy.on("close", (res, socket, head) => {
            console.log("🔌 Socket connection closed");
          });
        },
      },
    },
  },

  // Optimized dependencies for faster reloads
  optimizeDeps: {
    include: [
      "vue",
      "vue-router",
      "pinia",
      "axios",
      "socket.io-client",
      "@headlessui/vue",
      "@heroicons/vue/24/outline",
      "@heroicons/vue/24/solid",
      "chart.js",
      "vue-chartjs",
      "date-fns",
      "vue-toastification",
    ],
    exclude: [],
    force: false, // Only force when needed
    esbuildOptions: {
      target: "esnext",
    },
  },

  // CSS configuration for hot reload
  css: {
    devSourcemap: true,
    modules: {
      localsConvention: "camelCase",
    },
    preprocessorOptions: {
      scss: {
        additionalData: `@import "@/styles/variables.scss";`,
      },
    },
    postcss: {
      plugins: [require("tailwindcss"), require("autoprefixer")],
    },
  },

  // Build configuration optimized for development
  build: {
    outDir: "dist",
    assetsDir: "assets",
    sourcemap: true,
    minify: false, // Disable minification for faster builds
    target: "esnext",
    cssCodeSplit: false,

    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ["vue", "vue-router", "pinia"],
          utils: ["axios", "socket.io-client"],
          ui: ["@headlessui/vue", "@heroicons/vue/24/outline"],
        },
      },
    },

    // Watch mode for build
    watch: {
      include: "src/**",
      exclude: "node_modules/**",
    },
  },

  // Environment variables
  define: {
    __VUE_OPTIONS_API__: true,
    __VUE_PROD_DEVTOOLS__: true, // Enable devtools in development
    __DEV__: true,
  },

  // Logging configuration
  logLevel: "info",
  clearScreen: false, // Keep previous logs visible

  // Enable experimental features
  experimental: {
    renderBuiltUrl(filename, { hostType }) {
      if (hostType === "js") {
        return { js: `/${filename}` };
      }
      return { relative: true };
    },
  },
});
