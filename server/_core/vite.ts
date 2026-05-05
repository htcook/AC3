import express, { type Express } from "express";
import fs from "fs";
import { type Server } from "http";
import { nanoid } from "nanoid";
import path from "path";
import { createServer as createViteServer } from "vite";
import viteConfig from "../../vite.config";

export async function setupVite(app: Express, server: Server) {
  // Respect hmr setting from vite.config.ts — if hmr is explicitly false,
  // don't override it (needed when running behind a proxy that doesn't support WebSocket)
  const configHmr = (viteConfig as any).server?.hmr;
  const serverOptions: Record<string, any> = {
    middlewareMode: true,
    allowedHosts: true as const,
    hmr: configHmr === false ? false : { server },
  };

  const vite = await createViteServer({
    ...viteConfig,
    configFile: false,
    server: serverOptions,
    appType: "custom",
  });

  app.use(vite.middlewares);
  app.use("*", async (req, res, next) => {
    const url = req.originalUrl;

    try {
      const clientTemplate = path.resolve(
        import.meta.dirname,
        "../..",
        "client",
        "index.html"
      );

      // always reload the index.html file from disk incase it changes
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e as Error);
      next(e);
    }
  });
}

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
  app.use("*", (_req, res) => {
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    res.sendFile(path.resolve(distPath, "index.html"));
  });
}
