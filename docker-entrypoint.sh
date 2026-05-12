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
  echo "[entrypoint] Drizzle dir contents: $(ls drizzle/*.sql 2>/dev/null | wc -l) SQL files"
  echo "[entrypoint] Meta dir: $(ls drizzle/meta/ 2>/dev/null)"

  # Allow self-signed certs for drizzle-kit CLI (RDS within VPC)
  export NODE_TLS_REJECT_UNAUTHORIZED=0

  # Run migrate and capture output to temp file
  MIGRATE_LOG=/tmp/migrate.log
  if NODE_TLS_REJECT_UNAUTHORIZED=0 npx drizzle-kit migrate > "$MIGRATE_LOG" 2>&1; then
    echo "[entrypoint] Migrations applied successfully"
    cat "$MIGRATE_LOG"
  else
    EXIT_CODE=$?
    echo "[entrypoint] WARN: drizzle-kit migrate failed with exit code: $EXIT_CODE"
    echo "[entrypoint] === FULL MIGRATE OUTPUT ==="
    cat "$MIGRATE_LOG"
    echo "[entrypoint] === END MIGRATE OUTPUT ==="
  fi

  # Reset TLS setting for the rest of the app
  unset NODE_TLS_REJECT_UNAUTHORIZED

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
