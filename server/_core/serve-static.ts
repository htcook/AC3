import express, { type Express } from "express";
import fs from "fs";
import path from "path";

export function serveStatic(app: Express) {
  // In development: resolve from server/_core/ up to project root
  // In production split-mode: server runs from dist/server/, public is at dist/public/ (sibling)
  // In production legacy: server runs from dist/, public is at dist/public/ (child)
  let distPath: string;
  if (process.env.NODE_ENV === "development") {
    distPath = path.resolve(import.meta.dirname, "../..", "dist", "public");
  } else {
    // Try sibling "public" first (split-mode: dist/server/ -> dist/public/)
    const siblingPublic = path.resolve(import.meta.dirname, "..", "public");
    // Then try child "public" (legacy: dist/ -> dist/public/)
    const childPublic = path.resolve(import.meta.dirname, "public");
    distPath = fs.existsSync(siblingPublic) ? siblingPublic : childPublic;
  }
  if (!fs.existsSync(distPath)) {
    console.error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }

  // Serve static files with proper cache headers
  // Assets with hash in filename get long cache, others get no-cache
  app.use(
    express.static(distPath, {
      maxAge: "1y",
      immutable: true,
      index: false, // Don't serve index.html for directory requests
      setHeaders: (res, filePath) => {
        // HTML files should not be cached
        if (filePath.endsWith(".html")) {
          res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        }
      },
    })
  );

  // Return 404 for missing static assets (prevents SPA fallback from serving
  // index.html with text/html MIME type for JS/CSS requests, which causes
  // "Expected a JavaScript module" errors in the browser)
  app.use("/assets/*", (_req, res) => {
    res.status(404).send("Asset not found");
  });

  // fall through to index.html if the file doesn't exist (SPA routing)
  // Inject CSP nonce into inline script tags so they pass the Content-Security-Policy
  app.use("*", (req, res) => {
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    const indexPath = path.resolve(distPath, "index.html");
    const nonce = (req as any).cspNonce;
    if (nonce) {
      let html = fs.readFileSync(indexPath, "utf-8");
      // Add nonce to all inline script tags (those without src attribute)
      html = html.replace(/<script(?![^>]*\bsrc\b)([^>]*)>/g, `<script nonce="${nonce}"$1>`);
      // Also add nonce to module script tags with src (for CSP compliance)
      html = html.replace(/<script(\s+type="module"\s+crossorigin\s+src=)/g, `<script nonce="${nonce}"$1`);
      res.status(200).set({ "Content-Type": "text/html" }).end(html);
    } else {
      res.sendFile(indexPath);
    }
  });
}
