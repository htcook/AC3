FROM node:22-slim

# Install pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

WORKDIR /usr/src/app

# Copy package files for dependency caching
COPY package.json pnpm-lock.yaml ./
COPY patches/ ./patches/

# Install ALL dependencies (including devDependencies for esbuild)
RUN pnpm install --frozen-lockfile

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

# Expose port (platform uses PORT env var, default 8080)
EXPOSE 8080

ENV NODE_ENV=production

# Start the server
CMD ["node", "dist/index.js"]
