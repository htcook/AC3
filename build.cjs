const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const distIndex = path.join(__dirname, "dist", "index.js");
const distAssets = path.join(__dirname, "dist", "public", "assets");

if (fs.existsSync(distIndex) && fs.existsSync(distAssets)) {
  console.log("Pre-built dist found, skipping build");
  process.exit(0);
}

console.log("dist not found, running full build...");

try {
  // Ensure dist directories exist
  fs.mkdirSync(path.join(__dirname, "dist", "public"), { recursive: true });

  // Step 1: Build client with Vite (run from project root - vite.config.ts uses __dir)
  console.log("Building client with Vite...");
  execSync("npx vite build", {
    cwd: __dirname,
    stdio: "inherit",
    env: { ...process.env, NODE_OPTIONS: "--max-old-space-size=2048" },
  });

  // Step 2: Build server with esbuild
  console.log("Building server with esbuild...");
  execSync(
    "npx esbuild server/_core/index.ts --bundle --platform=node --target=node20 --outfile=dist/index.js --format=esm --packages=external",
    {
      cwd: __dirname,
      stdio: "inherit",
    }
  );

  console.log("Build completed successfully");
  process.exit(0);
} catch (err) {
  console.error("Build failed:", err.message);
  process.exit(1);
}
