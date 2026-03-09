import { jsxLocPlugin } from "@builder.io/vite-plugin-jsx-loc";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import path from "path";
import { defineConfig } from "vite";
import { vitePluginManusRuntime } from "vite-plugin-manus-runtime";

const __dir = import.meta.dirname;

const plugins = [
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
    // Memory optimization for deployment (Node 20.15.1 with 4GB heap)
    minify: "esbuild",
    sourcemap: false,
    cssCodeSplit: false,
    chunkSizeWarningLimit: 5000,
    rollupOptions: {
      output: {
        // STRATEGY: Keep ALL node_modules in ONE vendor chunk to prevent
        // React loading order issues (forwardRef undefined errors).
        // Only split page components into groups to reduce chunk count
        // from 209 lazy chunks to ~9 total chunks.
        manualChunks(id) {
          // ALL node_modules go into a single vendor chunk
          // This prevents any loading order issues between React and
          // libraries that depend on it (radix-ui, lucide-react, etc.)
          if (id.includes("node_modules")) {
            return "vendor";
          }
          // Group page components by first letter to reduce chunk count
          if (id.includes("/pages/")) {
            const filename = id.split("/pages/")[1]?.split(/[./]/)[0] || "";
            const first = filename.charAt(0).toUpperCase();
            if (first <= "C") return "pages-ac";
            if (first <= "E") return "pages-de";
            if (first <= "G") return "pages-fg";
            if (first <= "K") return "pages-hk";
            if (first <= "O") return "pages-lo";
            if (first <= "R") return "pages-pr";
            if (first <= "T") return "pages-st";
            return "pages-uz";
          }
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
