# ─────────────────────────────────────────────────────────────────────────────
# Ace C3 Platform — Multi-Stage Docker Build
# 
# Produces a lean production image (~150 MB) from the 793 MB node_modules tree.
# Supports two targets:
#   docker build --target api  -t acec3-api .
#   docker build --target worker -t acec3-worker .
#
# Or build the default (api) target:
#   docker build -t acec3 .
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Base ────────────────────────────────────────────────────────────
FROM node:22-alpine AS base
RUN corepack enable && corepack prepare pnpm@latest --activate
WORKDIR /app

# ── Stage 2: Dependencies ────────────────────────────────────────────────────
FROM base AS deps
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --prod=false

# ── Stage 3: Build ───────────────────────────────────────────────────────────
FROM base AS build
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build the Vite frontend
RUN pnpm run build 2>/dev/null || npx vite build

# Build the server (TypeScript → JavaScript)
# tsx handles this at runtime in dev, but for prod we compile
RUN npx esbuild server/_core/index.ts \
      --bundle \
      --platform=node \
      --target=node22 \
      --outdir=dist/server \
      --external:better-sqlite3 \
      --external:pg-native \
      --external:@mapbox/node-pre-gyp \
      --packages=external \
      --format=esm \
      --sourcemap \
    || echo "esbuild server skipped — will use tsx in production"

# Build the worker entry point
RUN npx esbuild worker/index.ts \
      --bundle \
      --platform=node \
      --target=node22 \
      --outdir=dist/worker \
      --packages=external \
      --format=esm \
      --sourcemap \
    || echo "esbuild worker skipped"

# ── Stage 4: Production Dependencies Only ────────────────────────────────────
FROM base AS prod-deps
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --prod \
    && pnpm store prune

# ── Stage 5: API Server (default target) ─────────────────────────────────────
FROM node:22-alpine AS api
RUN corepack enable && corepack prepare pnpm@latest --activate
WORKDIR /app

# Security: run as non-root
RUN addgroup -g 1001 -S acec3 && adduser -S acec3 -u 1001 -G acec3

# Copy production node_modules
COPY --from=prod-deps /app/node_modules ./node_modules

# Copy built assets
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./

# Copy source for tsx fallback (if esbuild didn't produce server bundle)
COPY --from=build /app/server ./server
COPY --from=build /app/shared ./shared
COPY --from=build /app/drizzle ./drizzle
COPY --from=build /app/worker ./worker
COPY --from=build /app/tsconfig.json ./

# Copy drizzle config for migrations
COPY --from=build /app/drizzle.config.ts ./

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:${PORT:-3000}/api/trpc/auth.me || exit 1

USER acec3

# The port is set by the platform — never hardcode it
ENV NODE_ENV=production
EXPOSE 3000

# Prefer compiled bundle, fall back to tsx
CMD ["sh", "-c", "if [ -f dist/server/index.js ]; then node dist/server/index.js; else npx tsx server/_core/index.ts; fi"]

# ── Stage 6: Worker Process ──────────────────────────────────────────────────
FROM node:22-alpine AS worker
RUN corepack enable && corepack prepare pnpm@latest --activate
WORKDIR /app

RUN addgroup -g 1001 -S acec3 && adduser -S acec3 -u 1001 -G acec3

COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./
COPY --from=build /app/server ./server
COPY --from=build /app/shared ./shared
COPY --from=build /app/drizzle ./drizzle
COPY --from=build /app/worker ./worker
COPY --from=build /app/tsconfig.json ./

USER acec3

ENV NODE_ENV=production

CMD ["sh", "-c", "if [ -f dist/worker/index.js ]; then node dist/worker/index.js; else npx tsx worker/index.ts; fi"]
