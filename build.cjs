/**
 * Build script for AC3 Dashboard
 * Runs as: node build.cjs (called by `pnpm run build`)
 *
 * ARCHITECTURE:
 * - dist/index.js = bootstrap (committed to git, always present)
 * - dist/_server.js = real server bundle (built by esbuild)
 * - dist/public/ = client assets (copied from .client-assets/)
 * - .client-assets/ = pre-built Vite output (committed to git)
 *
 * The bootstrap dist/index.js imports dist/_server.js and can also
 * self-build if _server.js is missing. This build.cjs is the primary
 * build path called during Docker image creation.
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const { execSync } = require("child_process");

const ROOT = __dirname;
const DIST = path.join(ROOT, "dist");
const DIST_PUBLIC = path.join(DIST, "public");
const SERVER_BUNDLE = path.join(DIST, "_server.js");
const CLIENT_ASSETS = path.join(ROOT, ".client-assets");

function log(msg) {
  console.log(`[build] ${msg}`);
}

try {
  log(`CWD: ${process.cwd()}`);
  log(`NODE_ENV: ${process.env.NODE_ENV || "not set"}`);
  log(`Memory: ${Math.round(os.freemem() / 1024 / 1024)}MB free / ${Math.round(os.totalmem() / 1024 / 1024)}MB total`);
  log(`dist/ exists? ${fs.existsSync(DIST)}`);
  log(`dist/_server.js exists? ${fs.existsSync(SERVER_BUNDLE)}`);
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

  // Build server bundle → dist/_server.js
  log("Building server bundle...");
  const t = Date.now();
  try {
    execSync(
      `npx esbuild server/_core/index.ts --bundle --platform=node --target=node20 --outfile=${JSON.stringify(SERVER_BUNDLE)} --format=esm --packages=external`,
      { cwd: ROOT, stdio: "inherit", timeout: 120000 }
    );
    log(`Server built in ${((Date.now() - t) / 1000).toFixed(1)}s.`);
  } catch (err) {
    log(`CRITICAL: esbuild failed: ${err.message}`);
    // Don't exit non-zero — let the bootstrap handle it at runtime
  }

  // Verify
  const ok = fs.existsSync(SERVER_BUNDLE);
  const html = fs.existsSync(path.join(DIST_PUBLIC, "index.html"));
  const bootstrap = fs.existsSync(path.join(DIST, "index.js"));
  log(`Final: bootstrap=${bootstrap}, server=${ok}${ok ? ` (${Math.round(fs.statSync(SERVER_BUNDLE).size/1024/1024)}MB)` : ""}, html=${html}`);
  log(ok ? "Build successful!" : "WARNING: _server.js missing. Bootstrap will try to build at startup.");

  process.exit(0);
} catch (err) {
  console.error(`[build] Unexpected error: ${err.message}`);
  process.exit(0);
}
