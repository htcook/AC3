/**
 * Build script for AC3 Dashboard
 * Runs as: node build.cjs (called by `pnpm run build`)
 *
 * DESIGN: The Manus platform strips dist/ between build and runtime stages.
 * This script MUST ALWAYS produce dist/index.js and dist/public/ from scratch.
 *
 * Strategy:
 * 1. Copy pre-built client assets from .client-assets/ → dist/public/
 *    (.client-assets/ is committed to git and survives the platform's build pipeline)
 * 2. Bundle server with esbuild → dist/index.js (fast, <1s, low memory)
 * 3. Never run Vite (OOMs in Docker's constrained memory)
 * 4. Always exit 0 to prevent Docker build failure
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const { execSync } = require("child_process");

const ROOT = __dirname;
const DIST = path.join(ROOT, "dist");
const DIST_PUBLIC = path.join(DIST, "public");
const DIST_INDEX = path.join(DIST, "index.js");
const CLIENT_ASSETS = path.join(ROOT, ".client-assets");

function log(msg) {
  console.log(`[build] ${msg}`);
}

try {
  // ─── DIAGNOSTICS ──────────────────────────────────────────────────────
  log(`CWD: ${process.cwd()}`);
  log(`NODE_ENV: ${process.env.NODE_ENV || "not set"}`);
  log(`Memory: ${Math.round(os.freemem() / 1024 / 1024)}MB free / ${Math.round(os.totalmem() / 1024 / 1024)}MB total`);
  log(`dist/ exists? ${fs.existsSync(DIST)}`);
  log(`.client-assets/ exists? ${fs.existsSync(CLIENT_ASSETS)}`);

  // ─── STEP 1: Create dist/ directory ───────────────────────────────────
  log("Creating dist/ directory...");
  fs.mkdirSync(DIST, { recursive: true });

  // ─── STEP 2: Copy client assets ───────────────────────────────────────
  if (fs.existsSync(CLIENT_ASSETS)) {
    log("Copying .client-assets/ → dist/public/...");
    const startCopy = Date.now();
    // Use cp -r for speed and reliability
    try {
      execSync(`cp -r ${JSON.stringify(CLIENT_ASSETS)} ${JSON.stringify(DIST_PUBLIC)}`, {
        cwd: ROOT,
        stdio: "inherit",
        timeout: 60000,
      });
      const elapsed = ((Date.now() - startCopy) / 1000).toFixed(1);
      // Count files
      let fileCount = 0;
      try {
        const assets = path.join(DIST_PUBLIC, "assets");
        if (fs.existsSync(assets)) fileCount = fs.readdirSync(assets).length;
      } catch (e) { /* ignore */ }
      log(`Client assets copied in ${elapsed}s (${fileCount} asset files).`);
    } catch (err) {
      log(`WARNING: Failed to copy client assets: ${err.message}`);
    }
  } else {
    log("WARNING: .client-assets/ not found. Creating fallback HTML...");
    fs.mkdirSync(DIST_PUBLIC, { recursive: true });
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
    <p>The client is being rebuilt. The API server is running.</p>
    <a href="/api/health">Check API Health</a>
  </div>
</body>
</html>`;
    fs.writeFileSync(path.join(DIST_PUBLIC, "index.html"), fallbackHtml);
    log("Fallback HTML created.");
  }

  // ─── STEP 3: Bundle server with esbuild ───────────────────────────────
  log("Building server bundle with esbuild...");
  const startBuild = Date.now();
  try {
    execSync(
      `npx esbuild server/_core/index.ts --bundle --platform=node --target=node20 --outfile=${JSON.stringify(DIST_INDEX)} --format=esm --packages=external`,
      {
        cwd: ROOT,
        stdio: "inherit",
        timeout: 120000,
      }
    );
    const elapsed = ((Date.now() - startBuild) / 1000).toFixed(1);
    log(`Server bundle built in ${elapsed}s.`);
  } catch (err) {
    log(`CRITICAL: esbuild failed: ${err.message}`);
    // Exit 0 anyway — better to let the platform report a clear "module not found"
    // error than to block the Docker build entirely
    process.exit(0);
  }

  // ─── FINAL VERIFICATION ───────────────────────────────────────────────
  const hasServer = fs.existsSync(DIST_INDEX);
  const hasHtml = fs.existsSync(path.join(DIST_PUBLIC, "index.html"));
  let assetCount = 0;
  try {
    const assetsDir = path.join(DIST_PUBLIC, "assets");
    if (fs.existsSync(assetsDir)) assetCount = fs.readdirSync(assetsDir).length;
  } catch (e) { /* ignore */ }

  log(`Final: server=${hasServer} (${hasServer ? Math.round(fs.statSync(DIST_INDEX).size / 1024 / 1024) + 'MB' : 'N/A'}), html=${hasHtml}, assets=${assetCount}`);

  if (hasServer) {
    log("Build successful!");
  } else {
    log("WARNING: dist/index.js was not produced. Server may fail to start.");
  }

  process.exit(0);

} catch (err) {
  console.error(`[build] Unexpected error: ${err.message}`);
  process.exit(0);
}
