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
    rollupOptions: {
      output: {
        manualChunks(id) {
          // Consolidate all lucide-react icons into a single chunk (~170 icons → 1 file)
          if (id.includes("node_modules/lucide-react")) {
            return "vendor-lucide";
          }
          // Group Radix UI primitives together (must stay with React)
          if (id.includes("node_modules/@radix-ui")) {
            return "vendor-radix";
          }
          // Group React + React-DOM together (prevents TDZ errors)
          if (
            id.includes("node_modules/react/") ||
            id.includes("node_modules/react-dom/") ||
            id.includes("node_modules/scheduler/")
          ) {
            return "vendor-react";
          }
          // Group charting libs
          if (
            id.includes("node_modules/recharts") ||
            id.includes("node_modules/d3-") ||
            id.includes("node_modules/victory")
          ) {
            return "vendor-charts";
          }
          // Group shiki/streamdown
          if (
            id.includes("node_modules/shiki") ||
            id.includes("node_modules/streamdown") ||
            id.includes("node_modules/@shikijs")
          ) {
            return "vendor-shiki";
          }
          // Group mermaid + cytoscape (large visualization libs)
          if (
            id.includes("node_modules/mermaid") ||
            id.includes("node_modules/cytoscape") ||
            id.includes("node_modules/dagre") ||
            id.includes("node_modules/elkjs")
          ) {
            return "vendor-viz";
          }
          // Let page chunks split naturally via React.lazy
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
