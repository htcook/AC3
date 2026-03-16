/**
 * Build script for AC3 Dashboard
 * Runs as: node build.cjs
 * 
 * This script handles both scenarios:
 * 1. Pre-built dist/ exists → exit 0 immediately (no build needed)
 * 2. No dist/ → run full vite + esbuild build
 * 
 * Designed to be resilient in Docker/CI environments where
 * env vars may contain special characters or memory is limited.
 */
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const ROOT = __dirname;
const DIST = path.join(ROOT, "dist");
const DIST_INDEX = path.join(DIST, "index.js");
const DIST_PUBLIC = path.join(DIST, "public");
const DIST_HTML = path.join(DIST_PUBLIC, "index.html");
const DIST_ASSETS = path.join(DIST_PUBLIC, "assets");

function log(msg) {
  console.log(`[build] ${msg}`);
}

function fileCount(dir) {
  try {
    if (!fs.existsSync(dir)) return 0;
    return fs.readdirSync(dir).filter(f => f.endsWith(".js") || f.endsWith(".css")).length;
  } catch { return 0; }
}

// ─── FAST PATH: Pre-built dist exists ───────────────────────────────────────
// This is the expected path for Manus publish (dist/ is committed to git)
if (fs.existsSync(DIST_INDEX)) {
  const assetCount = fileCount(DIST_ASSETS);
  if (assetCount > 0) {
    log(`Pre-built dist found (${assetCount} assets). Build skipped — nothing to do.`);
    process.exit(0);
  }
  // dist/index.js exists but no assets — check if index.html exists
  if (fs.existsSync(DIST_HTML)) {
    log(`Pre-built dist found (server bundle + index.html). Build skipped.`);
    process.exit(0);
  }
}

// ─── SLOW PATH: Build from source ──────────────────────────────────────────
log("dist not found or incomplete. Running full build...");
log(`NODE_ENV=${process.env.NODE_ENV || "not set"}`);
log(`Available memory: ${Math.round(require("os").freemem() / 1024 / 1024)}MB free of ${Math.round(require("os").totalmem() / 1024 / 1024)}MB`);

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
        // Limit memory to avoid OOM in constrained environments
        NODE_OPTIONS: "--max-old-space-size=3072",
      },
      timeout: 300000, // 5 min timeout
    });
    log(`${label} completed successfully.`);
    return true;
  } catch (err) {
    log(`${label} failed: ${err.message}`);
    if (err.status === 137 || err.signal === "SIGKILL") {
      log("Process was killed (likely OOM). Try increasing memory limit.");
    }
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
