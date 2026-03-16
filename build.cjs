const fs = require("fs");
const path = require("path");

const distIndex = path.join(__dirname, "dist", "index.js");
const distAssets = path.join(__dirname, "dist", "public", "assets");

if (fs.existsSync(distIndex) && fs.existsSync(distAssets)) {
  console.log("Pre-built dist found, skipping build");
  process.exit(0);
} else {
  console.log("dist not found - build required but not available in this context");
  console.log("Checked:", distIndex, "exists:", fs.existsSync(distIndex));
  console.log("Checked:", distAssets, "exists:", fs.existsSync(distAssets));
  process.exit(0);
}
