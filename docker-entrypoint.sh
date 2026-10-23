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

  # A production task must not serve with an unverifiable or partially applied
  # schema. The runner is locked, checksummed, and verification-backed.
  if ! NODE_TLS_REJECT_UNAUTHORIZED=0 node run-migrations.mjs; then
    echo "[entrypoint] ERROR: Migration verification failed; refusing to start the API."
    exit 1
  fi

  echo "[entrypoint] Database migrations verified."

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
