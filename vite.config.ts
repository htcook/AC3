import { jsxLocPlugin } from "@builder.io/vite-plugin-jsx-loc";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import fs from "node:fs";
import path from "path";
import { defineConfig, type Plugin } from "vite";
import { vitePluginManusRuntime } from "vite-plugin-manus-runtime";

// Path to our shiki subset module that only includes ~29 languages instead of 327
const shikiSubsetPath = path.resolve(
  import.meta.dirname,
  "client",
  "src",
  "lib",
  "shiki-subset.mjs"
);

/**
 * Vite plugin that redirects bare `import ... from "shiki"` to our subset module
 * while preserving sub-path imports like `shiki/engine/javascript`, `shiki/core`, etc.
 * This reduces the shiki language grammars from 327 (~8.4MB) to 29 (~800KB).
 */
function shikiSubsetPlugin(): Plugin {
  return {
    name: "shiki-subset",
    enforce: "pre",
    resolveId(source, importer) {
      // Only intercept the bare "shiki" import, not sub-paths like "shiki/core"
      if (source === "shiki") {
        return shikiSubsetPath;
      }
      return null;
    },
  };
}

const isProduction = process.env.NODE_ENV === "production";
const plugins = [
  react(),
  tailwindcss(),
  jsxLocPlugin(),
  vitePluginManusRuntime(),
  // Only apply shiki subset in production builds
  ...(isProduction ? [shikiSubsetPlugin()] : []),
];

export default defineConfig({
  plugins,
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets"),

    },
  },
  envDir: path.resolve(import.meta.dirname),
  root: path.resolve(import.meta.dirname, "client"),
  publicDir: path.resolve(import.meta.dirname, "client", "public"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true,
    chunkSizeWarningLimit: 600,
    // Reduce memory usage during build
    minify: "esbuild",
    sourcemap: false,
    // Target modern browsers only to reduce polyfills
    target: "es2022",
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return;

          // ── Shiki: split into core + langs + themes ──────────────────
          if (id.includes("@shikijs/langs")) return "vendor-shiki-langs";
          if (id.includes("@shikijs/themes")) return "vendor-shiki-themes";
          if (
            id.includes("shiki") ||
            id.includes("@shikijs/core") ||
            id.includes("@shikijs/engine") ||
            id.includes("@shikijs/vscode-textmate")
          )
            return "vendor-shiki-core";

          // ── Mermaid (lazy-loaded by streamdown) ───────────────────────
          if (id.includes("mermaid")) return "vendor-mermaid";

          // ── Cytoscape (attack graph visualization) ────────────────────
          if (id.includes("cytoscape")) return "vendor-cytoscape";

          // ── KaTeX math renderer ───────────────────────────────────────
          if (id.includes("katex")) return "vendor-katex";

          // ── Charts: split recharts from d3 ────────────────────────────
          if (id.includes("recharts")) return "vendor-recharts";
          if (id.includes("d3-")) return "vendor-d3";

          // ── UI framework: Radix ───────────────────────────────────────
          if (id.includes("@radix-ui")) return "vendor-radix";

          // ── Icons ─────────────────────────────────────────────────────
          if (id.includes("lucide-react")) return "vendor-icons";

          // ── Code editor (CodeMirror) ──────────────────────────────────
          if (
            id.includes("codemirror") ||
            id.includes("@codemirror") ||
            id.includes("@lezer")
          )
            return "vendor-editor";

          // ── PDF generation ────────────────────────────────────────────
          if (id.includes("jspdf") || id.includes("jspdf-autotable"))
            return "vendor-pdf";

          // ── Markdown / streaming markdown ─────────────────────────────
          if (
            id.includes("streamdown") ||
            id.includes("react-markdown") ||
            id.includes("remark-") ||
            id.includes("rehype-") ||
            id.includes("marked") ||
            id.includes("unified") ||
            id.includes("unist") ||
            id.includes("mdast") ||
            id.includes("hast") ||
            id.includes("micromark")
          )
            return "vendor-markdown";

          // ── html2canvas ───────────────────────────────────────────────
          if (id.includes("html2canvas")) return "vendor-html2canvas";

          // ── React core ────────────────────────────────────────────────
          if (id.includes("react-dom") || id.includes("react/") || id.includes("/react."))
            return "vendor-react";

          // ── tRPC + tanstack query ─────────────────────────────────────
          if (id.includes("@trpc") || id.includes("@tanstack"))
            return "vendor-trpc";

          // ── Remaining small deps → single vendor chunk ────────────────
          return "vendor-misc";
        },
      },
    },
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
      "127.0.0.1",
    ],
    fs: {
      strict: true,
      deny: ["**/.*"],
    },
  },
});
