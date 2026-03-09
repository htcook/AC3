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
    // Let Rollup handle chunk splitting naturally via React.lazy dynamic imports.
    // DO NOT use manualChunks — it causes:
    //   1. forwardRef undefined (when React split from Radix/lucide)
    //   2. TDZ errors (when pages split alphabetically create circular refs)
    minify: "esbuild",
    sourcemap: false,
    cssCodeSplit: false,
    chunkSizeWarningLimit: 5000,
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
