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

  # Use direct SQL runner instead of drizzle-kit CLI (more reliable in container)
  NODE_TLS_REJECT_UNAUTHORIZED=0 node run-migrations.mjs 2>&1 || {
    echo "[entrypoint] WARN: Migration runner had issues (exit $?)"
  }

  echo "[entrypoint] Database migrations complete."

  # Seed admin account if AC3_ADMIN_PASSWORD is set
  if [ -n "$AC3_ADMIN_PASSWORD" ]; then
    echo "[entrypoint] Running admin account seeder..."
    node seed-admin.mjs 2>&1 || echo "[entrypoint] WARN: Admin seed had issues"
  fi

  # Seed PBS Platform test accounts (white-label deployment)
  if [ -f "seed-pbs-accounts.mjs" ]; then
    echo "[entrypoint] Running PBS Platform account seeder..."
    node seed-pbs-accounts.mjs 2>&1 || echo "[entrypoint] WARN: PBS account seed had issues"
  fi
else
  echo "[entrypoint] WARN: DATABASE_URL not set, skipping migrations."
fi

echo "[entrypoint] Starting application server..."
exec node dist/index.js
