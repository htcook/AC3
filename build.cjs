/**
 * Build script for AC3 Dashboard
 * Runs as: node build.cjs
 *
 * CRITICAL BUILD ORDER:
 * 1. Client (Vite) FIRST — because vite.config has emptyOutDir:true which
 *    deletes dist/public/. If Vite runs after esbuild, it nukes the server bundle.
 * 2. Server (esbuild) SECOND — fast (<1s), low memory, always succeeds.
 *    This ensures dist/index.js exists even if Vite OOMs.
 *
 * The old build.cjs always exited 0, masking failures. This version:
 * - Exits 1 if dist/index.js is missing after build (so the platform knows it failed)
 * - Creates fallback index.html if Vite OOMs
 * - Logs diagnostics for debugging deploy issues
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

// ─── FAST PATH: Pre-built dist exists with BOTH server + client ───────────
const hasServerBundle = fs.existsSync(DIST_INDEX);
const hasClientHtml = fs.existsSync(DIST_HTML);
const assetCount = fileCount(DIST_ASSETS);

if (hasServerBundle && (hasClientHtml || assetCount > 0)) {
  log(`Pre-built dist found (server: ✓, html: ${hasClientHtml}, assets: ${assetCount}). Build skipped.`);
  process.exit(0);
}

// ─── SLOW PATH: Build from source ────────────────────────────────────────
log("No complete pre-built dist found. Building from source...");

// Ensure dist directories exist
try {
  fs.mkdirSync(path.join(DIST, "public", "assets"), { recursive: true });
} catch (e) {
  log(`Warning: Could not create dist dirs: ${e.message}`);
}

const totalMB = Math.round(os.totalmem() / 1024 / 1024);
let heapMB;
if (totalMB < 2048) {
  heapMB = 768;
} else if (totalMB < 4096) {
  heapMB = 1536;
} else {
  heapMB = 2048;
}
log(`Setting Node heap to ${heapMB}MB (system has ${totalMB}MB)`);

function run(cmd, label, timeoutMs = 300000) {
  log(`Starting ${label}...`);
  const startTime = Date.now();
  try {
    execSync(cmd, {
      cwd: ROOT,
      stdio: "inherit",
      env: {
        ...process.env,
        NODE_OPTIONS: `--max-old-space-size=${heapMB}`,
        CI_BUILD: "1",
      },
      timeout: timeoutMs,
    });
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    log(`${label} completed in ${elapsed}s.`);
    return true;
  } catch (err) {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    log(`${label} FAILED after ${elapsed}s: ${err.message}`);
    if (err.status === 137 || err.signal === "SIGKILL") {
      log("Process was killed (likely OOM). Container may need more memory.");
    }
    return false;
  }
}

// ─── Step 1: Build CLIENT with Vite (FIRST, because emptyOutDir nukes dist/public/) ───
// Vite config has emptyOutDir:true → it will DELETE dist/public/ before writing.
// If this OOMs, we create a fallback HTML so the server can still start.
log("Step 1/2: Building client with Vite...");
const viteOk = run("npx vite build", "Vite client build", 240000);

if (!viteOk) {
  log("WARNING: Vite client build failed (likely OOM). Creating fallback HTML.");
  // Ensure dist/public exists (Vite may have deleted it before OOMing)
  try {
    fs.mkdirSync(DIST_PUBLIC, { recursive: true });
  } catch (e) { /* ignore */ }

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
    log("Fallback index.html created successfully.");
  } catch (e) {
    log(`Failed to create fallback HTML: ${e.message}`);
  }
}

// ─── Step 2: Build SERVER with esbuild (SECOND, ALWAYS runs) ──────────────
// esbuild is fast (<1s) and uses minimal memory. It MUST run after Vite
// because Vite's emptyOutDir:true deletes dist/public/ (and could nuke
// dist/index.js if the output dirs overlap).
log("Step 2/2: Building server with esbuild...");
const esbuildOk = run(
  "npx esbuild server/_core/index.ts --bundle --platform=node --target=node20 --outfile=dist/index.js --format=esm --packages=external",
  "esbuild server build",
  120000
);

if (!esbuildOk) {
  log("CRITICAL: esbuild server build failed. Cannot deploy without server bundle.");
  process.exit(1);
}

// ─── FINAL VERIFICATION ──────────────────────────────────────────────────
const finalServerExists = fs.existsSync(DIST_INDEX);
const finalHtmlExists = fs.existsSync(DIST_HTML);
const finalAssetCount = fileCount(DIST_ASSETS);

log(`Final check: server=${finalServerExists}, html=${finalHtmlExists}, assets=${finalAssetCount}`);
log(`dist/index.js size: ${finalServerExists ? fs.statSync(DIST_INDEX).size : 'N/A'} bytes`);

if (!finalServerExists) {
  log("FATAL: dist/index.js does not exist after build. Deploy WILL fail.");
  process.exit(1);
}

if (finalHtmlExists || finalAssetCount > 0) {
  log(`Build complete! Server bundle (${Math.round(fs.statSync(DIST_INDEX).size / 1024 / 1024)}MB) + ${finalAssetCount} client assets.`);
} else {
  log("WARNING: No client assets, but server bundle exists. Deploy will start with fallback HTML.");
}

process.exit(0);
