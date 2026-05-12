#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# AC3 Platform — Docker Entrypoint
# Runs database migrations and admin seeding before starting the application server.
# ─────────────────────────────────────────────────────────────────────────────
set -e

echo "[entrypoint] AC3 Platform starting..."
echo "[entrypoint] Build: $(cat dist/build-info.json 2>/dev/null || echo 'unknown')"

# Run database migrations if DATABASE_URL is set
if [ -n "$DATABASE_URL" ]; then
  echo "[entrypoint] Running database migrations..."
  npx drizzle-kit generate 2>&1 || echo "[entrypoint] WARN: drizzle-kit generate had issues (may be OK if no new migrations)"
  npx drizzle-kit migrate 2>&1 || echo "[entrypoint] WARN: drizzle-kit migrate had issues"
  echo "[entrypoint] Database migrations complete."

  # Seed admin account if AC3_ADMIN_PASSWORD is set
  if [ -n "$AC3_ADMIN_PASSWORD" ]; then
    echo "[entrypoint] Running admin account seeder..."
    node seed-admin.mjs 2>&1 || echo "[entrypoint] WARN: Admin seed had issues"
  fi
else
  echo "[entrypoint] WARN: DATABASE_URL not set, skipping migrations."
fi

echo "[entrypoint] Starting application server..."
exec node dist/index.js
