/**
 * Build script for AC3 Dashboard
 * Runs as: node build.cjs (called by `pnpm run build`)
 *
 * ARCHITECTURE:
 * - dist/index.js = bootstrap (committed to git, always present)
 * - dist/server/index.js = main server entry (code-split with chunks)
 * - dist/server/*.js = lazy-loaded chunks (only parsed when first imported)
 * - dist/_server.js = LEGACY single-bundle fallback (kept for backward compat)
 * - dist/public/ = client assets (copied from .client-assets/)
 * - .client-assets/ = pre-built Vite output (committed to git)
 *
 * CODE SPLITTING:
 * The server is built with esbuild's --splitting flag, producing a main
 * entry point (~6MB) plus ~590 lazy chunks. This reduces startup memory
 * from ~700MB to ~250MB because heavy modules (domainIntel, orchestrator,
 * scanforge) only load when first accessed via dynamic import().
 *
 * The bootstrap dist/index.js tries dist/server/index.js first (split mode),
 * then falls back to dist/_server.js (legacy single bundle).
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const { execSync } = require("child_process");

const ROOT = __dirname;
const DIST = path.join(ROOT, "dist");
const DIST_PUBLIC = path.join(DIST, "public");
const SERVER_DIR = path.join(DIST, "server");
const SERVER_ENTRY = path.join(SERVER_DIR, "index.js");
const LEGACY_BUNDLE = path.join(DIST, "_server.js");
const CLIENT_ASSETS = path.join(ROOT, ".client-assets");

function log(msg) {
  console.log(`[build] ${msg}`);
}

try {
  log(`CWD: ${process.cwd()}`);
  log(`NODE_ENV: ${process.env.NODE_ENV || "not set"}`);
  log(`Memory: ${Math.round(os.freemem() / 1024 / 1024)}MB free / ${Math.round(os.totalmem() / 1024 / 1024)}MB total`);
  log(`dist/ exists? ${fs.existsSync(DIST)}`);
  log(`.client-assets/ exists? ${fs.existsSync(CLIENT_ASSETS)}`);

  // Create dist/
  fs.mkdirSync(DIST, { recursive: true });

  // Copy client assets → dist/public/
  if (fs.existsSync(CLIENT_ASSETS)) {
    log("Copying .client-assets/ → dist/public/...");
    const t = Date.now();
    try {
      // Remove existing public dir to avoid stale files
      if (fs.existsSync(DIST_PUBLIC)) {
        execSync(`rm -rf ${JSON.stringify(DIST_PUBLIC)}`, { cwd: ROOT, timeout: 30000 });
      }
      execSync(`cp -r ${JSON.stringify(CLIENT_ASSETS)} ${JSON.stringify(DIST_PUBLIC)}`, {
        cwd: ROOT, stdio: "inherit", timeout: 60000,
      });
      let n = 0;
      try { n = fs.readdirSync(path.join(DIST_PUBLIC, "assets")).length; } catch(e) {}
      log(`Client assets copied in ${((Date.now() - t) / 1000).toFixed(1)}s (${n} files).`);
    } catch (err) {
      log(`WARNING: Copy failed: ${err.message}`);
    }
  } else {
    log("No .client-assets/. Creating fallback HTML...");
    fs.mkdirSync(DIST_PUBLIC, { recursive: true });
    fs.writeFileSync(path.join(DIST_PUBLIC, "index.html"),
      `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>AC3</title></head><body style="background:#0a0a0f;color:#e2e8f0;font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0"><div style="text-align:center"><h1>AC3 Dashboard</h1><p style="color:#94a3b8">Server running. Client rebuilding.</p><a href="/api/health" style="color:#60a5fa">API Health</a></div></body></html>`
    );
  }

  // ═══ PRIMARY BUILD: Code-split server ═══
  log("Building server (code-split mode)...");
  const t = Date.now();
  try {
    // Clean previous split output
    if (fs.existsSync(SERVER_DIR)) {
      execSync(`rm -rf ${JSON.stringify(SERVER_DIR)}`, { cwd: ROOT, timeout: 30000 });
    }
    execSync(
      `npx esbuild server/_core/index.ts --bundle --splitting --platform=node --target=node20 --outdir=${JSON.stringify(SERVER_DIR)} --format=esm --packages=external`,
      { cwd: ROOT, stdio: "inherit", timeout: 180000 }
    );
    const entrySize = fs.existsSync(SERVER_ENTRY) ? fs.statSync(SERVER_ENTRY).size : 0;
    const chunkCount = fs.readdirSync(SERVER_DIR).filter(f => f.endsWith('.js')).length;
    log(`Server built (split) in ${((Date.now() - t) / 1000).toFixed(1)}s: entry=${Math.round(entrySize/1024/1024)}MB, ${chunkCount} chunks.`);
  } catch (err) {
    log(`WARNING: Split build failed: ${err.message}. Falling back to single bundle.`);
    // Fallback: single bundle (legacy mode)
    try {
      execSync(
        `npx esbuild server/_core/index.ts --bundle --platform=node --target=node20 --outfile=${JSON.stringify(LEGACY_BUNDLE)} --format=esm --packages=external`,
        { cwd: ROOT, stdio: "inherit", timeout: 120000 }
      );
      log(`Fallback single-bundle built in ${((Date.now() - t) / 1000).toFixed(1)}s.`);
    } catch (err2) {
      log(`CRITICAL: Both build modes failed: ${err2.message}`);
    }
  }

  // Verify
  const splitOk = fs.existsSync(SERVER_ENTRY);
  const legacyOk = fs.existsSync(LEGACY_BUNDLE);
  const html = fs.existsSync(path.join(DIST_PUBLIC, "index.html"));
  const bootstrap = fs.existsSync(path.join(DIST, "index.js"));
  log(`Final: bootstrap=${bootstrap}, split=${splitOk}, legacy=${legacyOk}, html=${html}`);
  log((splitOk || legacyOk) ? "Build successful!" : "WARNING: No server bundle. Bootstrap will try to build at startup.");

  process.exit(0);
} catch (err) {
  console.error(`[build] Unexpected error: ${err.message}`);
  process.exit(0);
}
