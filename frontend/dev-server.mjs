#!/usr/bin/env node

/**
 * Development Server Startup Script
 * Enhanced development experience with automatic restarts and monitoring
 */

import { spawn } from "child_process";
import { watch } from "chokidar";
import { existsSync } from "fs";
import { resolve } from "path";
import chalk from "chalk";

const CONFIG_FILES = [
  "vite.config.js",
  "vite.config.dev.js",
  "package.json",
  "tailwind.config.js",
  "postcss.config.js",
  ".env",
  ".env.local",
  ".env.development",
];

let viteProcess = null;
let isRestarting = false;

function log(message, type = "info") {
  const timestamp = new Date().toLocaleTimeString();
  const colors = {
    info: chalk.blue,
    success: chalk.green,
    warning: chalk.yellow,
    error: chalk.red,
  };

  console.log(`${chalk.gray(timestamp)} ${colors[type]("●")} ${message}`);
}

function startVite() {
  if (viteProcess) {
    viteProcess.kill();
  }

  log("Starting Vite development server...", "info");

  const useDevConfig = existsSync(resolve(process.cwd(), "vite.config.dev.js"));
  const configFlag = useDevConfig ? "--config vite.config.dev.js" : "";

  viteProcess = spawn(
    "npx",
    ["vite", ...configFlag.split(" ").filter(Boolean), "--host", "0.0.0.0"],
    {
      stdio: "inherit",
      shell: true,
    }
  );

  viteProcess.on("exit", (code) => {
    if (code !== null && !isRestarting) {
      log(
        `Vite process exited with code ${code}`,
        code === 0 ? "success" : "error"
      );
    }
  });

  viteProcess.on("error", (err) => {
    log(`Vite process error: ${err.message}`, "error");
  });
}

function restartVite() {
  if (isRestarting) return;

  isRestarting = true;
  log("Configuration change detected, restarting...", "warning");

  setTimeout(() => {
    startVite();
    isRestarting = false;
    log("Development server restarted successfully", "success");
  }, 1000);
}

// Watch configuration files for changes
const watcher = watch(CONFIG_FILES, {
  ignored: /node_modules/,
  persistent: true,
});

watcher.on("change", (path) => {
  log(`Configuration file changed: ${path}`, "warning");
  restartVite();
});

// Handle process termination
process.on("SIGINT", () => {
  log("Shutting down development server...", "warning");
  if (viteProcess) {
    viteProcess.kill();
  }
  watcher.close();
  process.exit(0);
});

process.on("SIGTERM", () => {
  if (viteProcess) {
    viteProcess.kill();
  }
  watcher.close();
  process.exit(0);
});

// Start the development server
log("🚀 Starting AI Bug Bounty Scanner Frontend Development Server", "success");
log("📁 Working directory: " + process.cwd(), "info");
log("⚡ Hot reload enabled with enhanced configuration monitoring", "info");
startVite();
