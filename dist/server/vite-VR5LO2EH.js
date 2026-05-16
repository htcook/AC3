import "./chunk-KFQGP6VL.js";

// server/_core/vite.ts
import express from "express";
import fs from "fs";
import { nanoid } from "nanoid";
import path2 from "path";
import { createServer as createViteServer } from "vite";

// vite.config.ts
import { jsxLocPlugin } from "@builder.io/vite-plugin-jsx-loc";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import path from "path";
import { defineConfig } from "vite";
import { vitePluginManusRuntime } from "vite-plugin-manus-runtime";
var __dir = import.meta.dirname;
function shikiSubsetPlugin() {
  const subsetPath = path.resolve(__dir, "client", "src", "lib", "shiki-subset.ts");
  return {
    name: "shiki-subset-redirect",
    enforce: "pre",
    resolveId(source) {
      if (source === "shiki") {
        return subsetPath;
      }
      return null;
    }
  };
}
function katexCdnPlugin() {
  return {
    name: "katex-cdn-redirect",
    enforce: "pre",
    resolveId(source) {
      if (source === "katex/dist/katex.css" || source === "katex/dist/katex.min.css") {
        return "\0katex-cdn-stub";
      }
      return null;
    },
    load(id) {
      if (id === "\0katex-cdn-stub") {
        return "/* KaTeX CSS loaded via CDN in index.html */";
      }
      return null;
    }
  };
}
var CDN_MAP = {
  // Previously: mermaid, jspdf, jspdf-autotable → all removed
};
function cdnExternalPlugin() {
  const virtualPrefix = "\0cdn-external:";
  return {
    name: "cdn-external",
    enforce: "pre",
    // Only active during production build
    apply: "build",
    resolveId(source) {
      if (source in CDN_MAP) {
        return virtualPrefix + source;
      }
      return null;
    },
    load(id) {
      if (id.startsWith(virtualPrefix)) {
        const pkg = id.slice(virtualPrefix.length);
        const cdnUrl = CDN_MAP[pkg];
        return `export * from "${cdnUrl}";
export { default } from "${cdnUrl}";`;
      }
      return null;
    }
  };
}
var plugins = [
  shikiSubsetPlugin(),
  katexCdnPlugin(),
  cdnExternalPlugin(),
  react(),
  tailwindcss(),
  jsxLocPlugin(),
  vitePluginManusRuntime()
];
var vite_config_default = defineConfig({
  plugins,
  resolve: {
    alias: {
      "@": path.resolve(__dir, "client", "src"),
      "@shared": path.resolve(__dir, "shared"),
      "@assets": path.resolve(__dir, "attached_assets")
    }
  },
  envDir: path.resolve(__dir),
  root: path.resolve(__dir, "client"),
  publicDir: path.resolve(__dir, "client", "public"),
  build: {
    outDir: path.resolve(__dir, "dist/public"),
    emptyOutDir: true,
    minify: "esbuild",
    sourcemap: "hidden",
    cssCodeSplit: false,
    chunkSizeWarningLimit: 5e3,
    rollupOptions: {
      // Mark CDN URLs as external so Rollup doesn't try to bundle them
      external: (id) => {
        if (id.startsWith("https://esm.sh/")) return true;
        return false;
      },
      output: {
        // Preserve dynamic imports to CDN URLs in the output
        paths: (id) => {
          if (id.startsWith("https://esm.sh/")) return id;
          return id;
        },
        manualChunks(id) {
          if (id.includes("node_modules/lucide-react")) {
            return "vendor-lucide";
          }
          if (id.includes("node_modules/react/") || id.includes("node_modules/react-dom/") || id.includes("node_modules/scheduler/") || id.includes("node_modules/react-is/") || id.includes("node_modules/@radix-ui")) {
            return "vendor-react";
          }
          if (id.includes("node_modules/shiki") || id.includes("node_modules/streamdown") || id.includes("node_modules/@shikijs")) {
            return "vendor-shiki";
          }
        }
      }
    }
  },
  server: {
    host: true,
    hmr: false,
    allowedHosts: [
      ".manuspre.computer",
      ".manus.computer",
      ".manus-asia.computer",
      ".manuscomputer.ai",
      ".manusvm.computer",
      "localhost",
      "127.0.0.1"
    ],
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// server/_core/vite.ts
async function setupVite(app, server) {
  const configHmr = vite_config_default.server?.hmr;
  const serverOptions = {
    middlewareMode: true,
    allowedHosts: true,
    hmr: configHmr === false ? false : { server }
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    server: serverOptions,
    appType: "custom"
  });
  app.use(vite.middlewares);
  app.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        import.meta.dirname,
        "../..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app) {
  let distPath;
  if (process.env.NODE_ENV === "development") {
    distPath = path2.resolve(import.meta.dirname, "../..", "dist", "public");
  } else {
    const siblingPublic = path2.resolve(import.meta.dirname, "..", "public");
    const childPublic = path2.resolve(import.meta.dirname, "public");
    distPath = fs.existsSync(siblingPublic) ? siblingPublic : childPublic;
  }
  if (!fs.existsSync(distPath)) {
    console.error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app.use(
    express.static(distPath, {
      maxAge: "1y",
      immutable: true,
      index: false,
      // Don't serve index.html for directory requests
      setHeaders: (res, filePath) => {
        if (filePath.endsWith(".html")) {
          res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        }
      }
    })
  );
  app.use("/assets/*", (_req, res) => {
    res.status(404).send("Asset not found");
  });
  app.use("*", (req, res) => {
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    const indexPath = path2.resolve(distPath, "index.html");
    const nonce = req.cspNonce;
    if (nonce) {
      let html = fs.readFileSync(indexPath, "utf-8");
      html = html.replace(/<script(?![^>]*\bsrc\b)([^>]*)>/g, `<script nonce="${nonce}"$1>`);
      html = html.replace(/<script(\s+type="module"\s+crossorigin\s+src=)/g, `<script nonce="${nonce}"$1`);
      res.status(200).set({ "Content-Type": "text/html" }).end(html);
    } else {
      res.sendFile(indexPath);
    }
  });
}
export {
  serveStatic,
  setupVite
};
