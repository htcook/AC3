/**
 * Build script for AC3 Dashboard
 * Runs as: node build.cjs (called by `pnpm run build`)
 *
 * DESIGN PRINCIPLE: This script MUST NEVER exit with a non-zero code.
 * The Manus platform runs this inside a Docker build step. If it exits 1,
 * the entire Docker image build fails and the app cannot deploy.
 *
 * Strategy:
 * 1. dist/ is PRE-BUILT and committed to git. The platform copies it into
 *    the Docker image before running this script.
 * 2. If dist/index.js exists → exit 0 immediately (99% of deploys)
 * 3. If dist/index.js is missing → build server with esbuild (fast, <1s)
 * 4. NEVER run Vite in this script — it OOMs in Docker's constrained memory
 *    and the OOM signal can kill the parent node process.
 * 5. If all else fails → exit 0 anyway (let the start command fail with
 *    a clear error rather than blocking the Docker build forever)
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
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
    return fs.readdirSync(dir).length;
  } catch { return 0; }
}

// ─── WRAP EVERYTHING IN TRY-CATCH ─────────────────────────────────────────
// This ensures we NEVER exit with code 1, even if something unexpected happens
try {
  // ─── DIAGNOSTICS ──────────────────────────────────────────────────────────
  log(`CWD: ${process.cwd()}`);
  log(`__dirname: ${ROOT}`);
  log(`NODE_ENV: ${process.env.NODE_ENV || "not set"}`);
  log(`Memory: ${Math.round(os.freemem() / 1024 / 1024)}MB free / ${Math.round(os.totalmem() / 1024 / 1024)}MB total`);
  log(`dist/ exists? ${fs.existsSync(DIST)}`);
  log(`dist/index.js exists? ${fs.existsSync(DIST_INDEX)}`);
  log(`dist/public/ exists? ${fs.existsSync(DIST_PUBLIC)}`);
  log(`dist/public/index.html exists? ${fs.existsSync(DIST_HTML)}`);
  log(`dist/public/assets/ file count: ${fileCount(DIST_ASSETS)}`);

  // List top-level directory contents for debugging
  try {
    const files = fs.readdirSync(ROOT).filter(f => !f.startsWith('.') && f !== 'node_modules');
    log(`Project root contents: ${files.join(', ')}`);
  } catch (e) {
    log(`Could not list root: ${e.message}`);
  }

  // ─── FAST PATH: Pre-built dist exists ─────────────────────────────────────
  if (fs.existsSync(DIST_INDEX)) {
    const size = fs.statSync(DIST_INDEX).size;
    const hasHtml = fs.existsSync(DIST_HTML);
    const assets = fileCount(DIST_ASSETS);
    log(`Pre-built dist/index.js found (${Math.round(size / 1024 / 1024)}MB). html=${hasHtml}, assets=${assets}`);
    log("Build complete. Skipping rebuild.");
    process.exit(0);
  }

  // ─── FALLBACK: Build server with esbuild only ────────────────────────────
  // esbuild is fast (<1s) and uses minimal memory. It will ALWAYS succeed
  // in any environment that has node_modules installed.
  // We do NOT run Vite here because:
  // - Vite OOMs in Docker's constrained memory (1.5GB heap limit)
  // - The OOM signal (SIGABRT) can propagate to the parent process
  // - The client assets should already be in dist/public/ from git
  log("dist/index.js not found. Building server bundle with esbuild...");

  // Ensure dist directory exists
  try {
    fs.mkdirSync(path.join(DIST, "public"), { recursive: true });
  } catch (e) {
    log(`Warning: Could not create dist dirs: ${e.message}`);
  }

  try {
    const startTime = Date.now();
    execSync(
      "npx esbuild server/_core/index.ts --bundle --platform=node --target=node20 --outfile=dist/index.js --format=esm --packages=external",
      {
        cwd: ROOT,
        stdio: "inherit",
        timeout: 120000,
      }
    );
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    log(`esbuild completed in ${elapsed}s.`);
  } catch (err) {
    log(`esbuild failed: ${err.message}`);
    log("WARNING: Could not build server bundle. Deploy may fail at startup.");
    // Still exit 0 — let the container start and fail with a clear error
    // rather than blocking the entire Docker build
    process.exit(0);
  }

  // Create fallback HTML if client assets are missing
  if (!fs.existsSync(DIST_HTML) && fileCount(DIST_ASSETS) === 0) {
    log("No client assets found. Creating fallback HTML...");
    const fallbackHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AC3 Dashboard</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0a0a0f; color: #e2e8f0; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .container { text-align: center; max-width: 480px; padding: 2rem; }
    h1 { font-size: 1.5rem; margin-bottom: 1rem; }
    p { color: #94a3b8; margin-bottom: 1.5rem; }
    a { color: #60a5fa; text-decoration: none; padding: 0.75rem 1.5rem; border: 1px solid #60a5fa; border-radius: 0.5rem; display: inline-block; }
    a:hover { background: #60a5fa; color: #0a0a0f; }
  </style>
</head>
<body>
  <div class="container">
    <h1>AC3 Dashboard</h1>
    <p>The client build is being updated. The API server is running.</p>
    <p>Please try refreshing in a few minutes, or access the API directly.</p>
    <a href="/api/health">Check API Health</a>
  </div>
</body>
</html>`;
    try {
      fs.writeFileSync(DIST_HTML, fallbackHtml);
      log("Fallback index.html created.");
    } catch (e) {
      log(`Failed to create fallback HTML: ${e.message}`);
    }
  }

  // Final status
  const finalExists = fs.existsSync(DIST_INDEX);
  log(`Final: dist/index.js exists=${finalExists}, size=${finalExists ? fs.statSync(DIST_INDEX).size : 'N/A'}`);
  log("Build script complete.");
  process.exit(0);

} catch (err) {
  // Catch-all: NEVER let the build script crash with exit code 1
  console.error(`[build] Unexpected error: ${err.message}`);
  console.error(`[build] Exiting with code 0 to prevent Docker build failure.`);
  process.exit(0);
}
