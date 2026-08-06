FROM node:22-slim

# Install build dependencies needed by native modules (ssh2, node-gyp)
# AND Chromium + dependencies for server-side PDF generation via puppeteer-core
# openssh-client is required for scan-server-executor child_process SSH fallback
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    openssh-client \
    chromium \
    fonts-liberation \
    fonts-noto-color-emoji \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    xdg-utils \
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

# Always run fresh Vite build to ensure client assets are up-to-date
# This avoids stale .client-assets/ from git causing deployment issues
RUN rm -rf .client-assets dist/public && \
    NODE_OPTIONS="--max-old-space-size=4096" npx vite build && \
    cp -r dist/public .client-assets && \
    echo "Fresh Vite build complete"

# Run server build (produces dist/_server.js and copies .client-assets/ to dist/public/)
RUN pnpm run build

# Verify build output exists
RUN test -f dist/index.js && echo "OK: dist/index.js (bootstrap)" || (echo "FAIL: dist/index.js MISSING" && exit 1)
RUN test -f dist/_server.js && echo "OK: dist/_server.js (server bundle)" || echo "WARN: dist/_server.js missing (will build at startup)"
RUN test -f dist/public/index.html && echo "OK: dist/public/index.html" || echo "WARN: dist/public/index.html missing"

# NOTE: We do NOT prune devDependencies because the esbuild server bundle
# uses packages: "external" and the server has a static import of "vite"
# (in server/_core/vite.ts) that resolves at module load time even in production.
# Removing vite causes ERR_MODULE_NOT_FOUND at startup.

# Remove build dependencies to reduce image size (keep chromium + runtime libs)
RUN apt-get purge -y python3 make g++ && apt-get autoremove -y

# Set Chromium path for puppeteer-core (Debian/slim uses /usr/bin/chromium)
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

# Expose port (platform uses PORT env var, default 8080)
EXPOSE 8080

ENV NODE_ENV=production

# Set V8 heap ceiling for predictable OOM behavior in containers
# With code splitting, startup memory is ~250MB instead of ~700MB.
# Default 768MB works for 1GB containers (Manus webdev / Cloud Run).
# Override via env vars for larger instances:
#   2GB container:  NODE_OPTIONS="--max-old-space-size=1536 --expose-gc"
#   8GB container:  NODE_OPTIONS="--max-old-space-size=6144 --expose-gc"
# --expose-gc allows the memory watchdog to trigger manual garbage collection under pressure
ENV NODE_OPTIONS="--max-old-space-size=768 --expose-gc"

# Start the server
CMD ["node", "dist/index.js"]
