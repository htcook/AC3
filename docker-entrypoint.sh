#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# AC3 Platform — Docker Entrypoint
# Runs database migrations and admin seeding before starting the application server.
# ─────────────────────────────────────────────────────────────────────────────
set -e

echo "[entrypoint] AC3 Platform starting..."
echo "[entrypoint] Build: $(cat dist/build-info.json 2>/dev/null || echo 'unknown')"

# Preserve the established production secret layout: DATABASE_PASSWORD is
# injected independently and DATABASE_URL is derived in process memory only.
if [ -z "${DATABASE_URL:-}" ]; then
  DATABASE_URL="$(node --input-type=module -e '
    import { resolveDatabaseUrl } from "./database-runtime-config.mjs";
    const url = resolveDatabaseUrl();
    if (url) process.stdout.write(url);
  ')"
  export DATABASE_URL
fi

# Runtime migrations are opt-in. Production release tasks run the checked
# migration runner separately before this service task definition is deployed.
if [ "${AC3_RUNTIME_SCHEMA_MIGRATIONS_ENABLED:-false}" = "true" ]; then
  echo "[entrypoint] Running database migrations..."

  # A production task must not serve with an unverifiable or partially applied
  # schema. The runner is locked, checksummed, and verification-backed.
  if ! NODE_TLS_REJECT_UNAUTHORIZED=0 node run-migrations.mjs; then
    echo "[entrypoint] ERROR: Migration verification failed; refusing to start the API."
    exit 1
  fi

  echo "[entrypoint] Database migrations verified."
else
  echo "[entrypoint] Runtime migrations disabled; controlled release task is required."
fi

# Seed admin account if AC3_ADMIN_PASSWORD is set
if [ -n "${AC3_ADMIN_PASSWORD:-}" ]; then
  echo "[entrypoint] Running admin account seeder..."
  node seed-admin.mjs 2>&1 || echo "[entrypoint] WARN: Admin seed had issues"
fi

echo "[entrypoint] Starting application server..."
exec node dist/index.js
