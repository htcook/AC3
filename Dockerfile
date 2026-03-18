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
COPY package.json pnpm-lock.yaml ./
COPY patches/ ./patches/

# Install ALL dependencies (including devDependencies for esbuild)
RUN pnpm install --no-frozen-lockfile

# Copy all source files
COPY . .

# Run build (produces dist/_server.js and copies .client-assets/ to dist/public/)
RUN pnpm run build

# Verify build output exists
RUN test -f dist/index.js && echo "OK: dist/index.js (bootstrap)" || (echo "FAIL: dist/index.js MISSING" && exit 1)
RUN test -f dist/_server.js && echo "OK: dist/_server.js (server bundle)" || echo "WARN: dist/_server.js missing (will build at startup)"
RUN test -f dist/public/index.html && echo "OK: dist/public/index.html" || echo "WARN: dist/public/index.html missing"

# Prune dev dependencies for smaller image
RUN pnpm prune --prod

# Remove build dependencies to reduce image size
RUN apt-get purge -y python3 make g++ && apt-get autoremove -y

# Expose port (platform uses PORT env var, default 8080)
EXPOSE 8080

ENV NODE_ENV=production

# Start the server
CMD ["node", "dist/index.js"]
