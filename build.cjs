/**
 * Build script for AC3 Dashboard
 * Runs as: node build.cjs
 * 
 * This script handles both scenarios:
 * 1. Pre-built dist/ exists (skip build)
 * 2. No dist/ (run full vite + esbuild build)
 * 
 * Designed to be resilient in Docker environments where
 * env vars may contain special characters.
 */
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const ROOT = __dirname;
const DIST = path.join(ROOT, "dist");
const DIST_INDEX = path.join(DIST, "index.js");
const DIST_ASSETS = path.join(DIST, "public", "assets");

function log(msg) {
  console.log(`[build] ${msg}`);
}

function fileCount(dir) {
  try {
    if (!fs.existsSync(dir)) return 0;
    return fs.readdirSync(dir).filter(f => f.endsWith(".js") || f.endsWith(".css")).length;
  } catch { return 0; }
}

// Check if dist is already built
if (fs.existsSync(DIST_INDEX) && fileCount(DIST_ASSETS) > 10) {
  log(`Pre-built dist found (${fileCount(DIST_ASSETS)} assets). Skipping build.`);
  process.exit(0);
}

log("dist not found or incomplete. Running full build...");

// Ensure dist directories exist
try {
  fs.mkdirSync(path.join(DIST, "public"), { recursive: true });
} catch (e) {
  log(`Warning: Could not create dist dirs: ${e.message}`);
}

// Helper to run a command with error handling
function run(cmd, label) {
  log(`Starting ${label}...`);
  try {
    execSync(cmd, {
      cwd: ROOT,
      stdio: "inherit",
      env: {
        ...process.env,
        NODE_OPTIONS: "--max-old-space-size=4096",
      },
      timeout: 300000, // 5 min timeout
    });
    log(`${label} completed successfully.`);
    return true;
  } catch (err) {
    log(`${label} failed: ${err.message}`);
    return false;
  }
}

// Step 1: Build client with Vite
const viteOk = run("npx vite build", "Vite client build");
if (!viteOk) {
  log("FATAL: Vite build failed. Exiting.");
  process.exit(1);
}

// Step 2: Build server with esbuild
const esbuildOk = run(
  "npx esbuild server/_core/index.ts --bundle --platform=node --target=node20 --outfile=dist/index.js --format=esm --packages=external",
  "esbuild server build"
);
if (!esbuildOk) {
  log("FATAL: esbuild failed. Exiting.");
  process.exit(1);
}

// Verify output
if (fs.existsSync(DIST_INDEX) && fileCount(DIST_ASSETS) > 10) {
  log(`Build complete! ${fileCount(DIST_ASSETS)} client assets + server bundle.`);
  process.exit(0);
} else {
  log("FATAL: Build output verification failed.");
  process.exit(1);
}
