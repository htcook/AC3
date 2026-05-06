import { jsxLocPlugin } from "@builder.io/vite-plugin-jsx-loc";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import path from "path";
import { defineConfig, type Plugin } from "vite";
import { vitePluginManusRuntime } from "vite-plugin-manus-runtime";

const __dir = import.meta.dirname;

/**
 * Custom plugin to redirect bare `import ... from "shiki"` to our 25-language subset.
 * Without this, streamdown pulls in all 327 shiki language grammars (~700 chunks / 19.6MB).
 * Sub-path imports like `shiki/core`, `shiki/engine/*`, `shiki/dist/langs/*` are NOT affected.
 */
function shikiSubsetPlugin(): Plugin {
  const subsetPath = path.resolve(__dir, "client", "src", "lib", "shiki-subset.ts");
  return {
    name: "shiki-subset-redirect",
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

/**
 * Redirect katex CSS imports to a CDN version.
 * This eliminates 59 KaTeX font files (woff/woff2/ttf) from the build output,
 * saving ~1.2MB and 59 files from the deployment payload.
 */
function katexCdnPlugin(): Plugin {
  return {
    name: "katex-cdn-redirect",
    enforce: "pre",
    resolveId(source) {
      if (source === "katex/dist/katex.css" || source === "katex/dist/katex.min.css") {
        // Return a virtual module that imports nothing — the CDN link in index.html handles it
        return "\0katex-cdn-stub";
      }
      return null;
    },
    load(id) {
      if (id === "\0katex-cdn-stub") {
        return "/* KaTeX CSS loaded via CDN in index.html */";
      }
      return null;
    },
  };
}

/**
 * CDN externalization for heavy libraries that are only used via dynamic import.
 *
 * These libraries are already lazy-loaded (dynamic `import("mermaid")` in streamdown,
 * dynamic `import("jspdf")` in export-utils). This plugin rewrites those dynamic imports
 * to load from esm.sh CDN at runtime, completely removing them from the build output.
 *
 * Savings: ~1.3MB (mermaid 393K + cytoscape 433K + jspdf 382K + jspdf-autotable 31K + dagre 12K)
 *
 * How it works:
 *   - In PRODUCTION BUILD only (not dev), intercepts `import("mermaid")` etc.
 *   - Resolves them to a tiny virtual module that re-exports from the CDN URL.
 *   - The browser fetches the library from esm.sh on first use (cached by browser).
 *   - In DEV mode, the plugin is inactive — local node_modules are used as normal.
 */
// NOTE: CDN externals completely disabled.
// esm.sh is unreliable (CORS/network failures on production),
// causing dynamic imports to hang indefinitely with no error.
// All libraries (jspdf, jspdf-autotable, mermaid) are now bundled directly.
const CDN_MAP: Record<string, string> = {
  // Previously: mermaid, jspdf, jspdf-autotable → all removed
};

function cdnExternalPlugin(): Plugin {
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
        // Re-export everything from the CDN URL.
        // Rollup treats the URL as an external dependency and emits it as-is.
        return `export * from "${cdnUrl}";\nexport { default } from "${cdnUrl}";`;
      }
      return null;
    },
  };
}

const plugins = [
  shikiSubsetPlugin(),
  katexCdnPlugin(),
  cdnExternalPlugin(),
  react(),
  tailwindcss(),
  jsxLocPlugin(),
  vitePluginManusRuntime(),
];

export default defineConfig({
  plugins,
  resolve: {
    alias: {
      "@": path.resolve(__dir, "client", "src"),
      "@shared": path.resolve(__dir, "shared"),
      "@assets": path.resolve(__dir, "attached_assets"),
    },
  },
  envDir: path.resolve(__dir),
  root: path.resolve(__dir, "client"),
  publicDir: path.resolve(__dir, "client", "public"),
  build: {
    outDir: path.resolve(__dir, "dist/public"),
    emptyOutDir: true,
    minify: "esbuild",
    sourcemap: false,
    cssCodeSplit: false,
    chunkSizeWarningLimit: 5000,
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
          // Consolidate all lucide-react icons into a single chunk (~170 icons → 1 file)
          if (id.includes("node_modules/lucide-react")) {
            return "vendor-lucide";
          }
          // Group React + React-DOM + react-is + Radix UI together in ONE chunk.
          // CRITICAL: Radix and React MUST be in the same chunk because Rollup's
          // CJS interop helper (getDefaultExportFromCjs) gets defined in whichever
          // chunk first needs it. If Radix is separate, vendor-react imports the
          // helper from vendor-radix while vendor-radix imports React from
          // vendor-react → circular TDZ error → black screen in production.
          if (
            id.includes("node_modules/react/") ||
            id.includes("node_modules/react-dom/") ||
            id.includes("node_modules/scheduler/") ||
            id.includes("node_modules/react-is/") ||
            id.includes("node_modules/@radix-ui")
          ) {
            return "vendor-react";
          }
          // NOTE: recharts/d3/victory are NOT manually chunked.
          // Putting them in a separate "vendor-charts" chunk causes a circular
          // TDZ error: vendor-charts needs React from vendor-react, but
          // vendor-react needs Rollup's CJS interop helper from vendor-charts.
          // Letting Rollup split them naturally avoids the circular dependency.
          // Group shiki/streamdown
          if (
            id.includes("node_modules/shiki") ||
            id.includes("node_modules/streamdown") ||
            id.includes("node_modules/@shikijs")
          ) {
            return "vendor-shiki";
          }
          // NOTE: mermaid/cytoscape/dagre are now loaded from CDN via cdnExternalPlugin.
          // They are completely excluded from the build output.
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
