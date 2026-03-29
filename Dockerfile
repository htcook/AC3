FROM node:22-slim

# Install build dependencies needed by native modules (ssh2, node-gyp)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Install exact pnpm version matching packageManager in package.json
RUN corepack enable && corepack prepare pnpm@10.4.1 --activate

WORKDIR /usr/src/app

# Copy package files for dependency caching
COPY package.json pnpm-lock.yaml postinstall.cjs ./
COPY patches/ ./patches/

# Install ALL dependencies (including devDependencies for build + vite runtime import)
RUN pnpm install --no-frozen-lockfile

# Copy all source files
COPY . .

# Run build (produces dist/_server.js and copies .client-assets/ to dist/public/)
RUN pnpm run build

# Verify build output exists
RUN test -f dist/index.js && echo "OK: dist/index.js (bootstrap)" || (echo "FAIL: dist/index.js MISSING" && exit 1)
RUN test -f dist/_server.js && echo "OK: dist/_server.js (server bundle)" || echo "WARN: dist/_server.js missing (will build at startup)"
RUN test -f dist/public/index.html && echo "OK: dist/public/index.html" || echo "WARN: dist/public/index.html missing"

# NOTE: We do NOT prune devDependencies because the esbuild server bundle
# uses packages: "external" and the server has a static import of "vite"
# (in server/_core/vite.ts) that resolves at module load time even in production.
# Removing vite causes ERR_MODULE_NOT_FOUND at startup.

# Remove build dependencies to reduce image size
RUN apt-get purge -y python3 make g++ && apt-get autoremove -y

# Expose port (platform uses PORT env var, default 8080)
EXPOSE 8080

ENV NODE_ENV=production

# Set V8 heap ceiling for predictable OOM behavior in containers
# Default 2048MB (2GB) is tuned for DO App Platform professional-m (4GB RAM)
# Override via DO App Platform env vars for larger instances:
#   professional-l (8GB):  NODE_OPTIONS="--max-old-space-size=4096 --expose-gc"
#   s-8vcpu-32gb (32GB):   NODE_OPTIONS="--max-old-space-size=8192 --expose-gc"
# --expose-gc allows the memory watchdog to trigger manual garbage collection under pressure
ENV NODE_OPTIONS="--max-old-space-size=2048 --expose-gc"

# Start the server
CMD ["node", "dist/index.js"]
