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
    // No manualChunks — let Rollup handle splitting naturally via React.lazy.
    // jspdf is now dynamically imported in export-utils.ts to reduce module count.
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
