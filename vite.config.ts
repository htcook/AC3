import { jsxLocPlugin } from "@builder.io/vite-plugin-jsx-loc";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import fs from "node:fs";
import path from "path";
import { defineConfig, type Plugin } from "vite";
import { vitePluginManusRuntime } from "vite-plugin-manus-runtime";

/**
 * Vite plugin: redirect bare `import ... from "shiki"` to our subset module.
 * Sub-path imports like "shiki/engine/javascript" and "shiki/wasm" are NOT affected.
 */
function shikiSubsetPlugin(): Plugin {
  const subsetPath = path.resolve(
    import.meta.dirname,
    "client/src/lib/shiki-subset.ts"
  );
  return {
    name: "shiki-subset",
    enforce: "pre",
    resolveId(source) {
      // Only intercept the exact bare "shiki" import, not sub-paths
      if (source === "shiki") {
        return subsetPath;
      }
      return null;
    },
  };
}

const plugins = [
  shikiSubsetPlugin(),
  react(),
  tailwindcss(),
  jsxLocPlugin(),
  vitePluginManusRuntime(),
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
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return;

          // ── Heavy visualization libs (lazy-loaded via page routes) ──────
          // mermaid + its cytoscape dep (~2.1 MB combined)
          if (id.includes('mermaid')) return 'vendor-mermaid';
          if (id.includes('cytoscape')) return 'vendor-cytoscape';

          // Shiki code highlighter — split into langs, themes, core
          if (id.includes('@shikijs/langs') || id.match(/shiki\/dist\/langs/)) return 'vendor-shiki-langs';
          if (id.includes('@shikijs/themes') || id.match(/shiki\/dist\/themes/)) return 'vendor-shiki-themes';
          if (id.includes('shiki') || id.includes('@shikijs')) return 'vendor-shiki-core';

          // KaTeX math renderer + fonts (~1 MB)
          if (id.includes('katex')) return 'vendor-katex';

          // ── Charts (recharts + d3 ecosystem) ───────────────────────────
          if (id.includes('recharts') || id.includes('d3-')) return 'vendor-charts';

          // ── UI framework chunks ────────────────────────────────────────
          if (id.includes('@radix-ui')) return 'vendor-radix';
          if (id.includes('lucide-react')) return 'vendor-icons';

          // ── Code editor (CodeMirror) ───────────────────────────────────
          if (id.includes('codemirror') || id.includes('@codemirror') || id.includes('@lezer')) return 'vendor-editor';

          // ── PDF generation (jsPDF + autoTable) ─────────────────────────
          if (id.includes('jspdf') || id.includes('jspdf-autotable')) return 'vendor-pdf';

          // ── Markdown / streaming markdown ──────────────────────────────
          if (id.includes('streamdown') || id.includes('react-markdown') || id.includes('remark-') || id.includes('rehype-') || id.includes('marked')) return 'vendor-markdown';

          // ── React core (shared across all routes) ──────────────────────
          if (id.includes('react-dom')) return 'vendor-react';

          // NOTE: No catch-all "vendor-misc" — let Vite handle remaining
          // modules naturally to avoid CJS/ESM interop issues.
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
