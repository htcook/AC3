import "./chunk-KFQGP6VL.js";

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
    sourcemap: false,
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
export {
  vite_config_default as default
};
