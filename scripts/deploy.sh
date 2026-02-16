#!/bin/bash
# ─── Caldera Dashboard Deploy Script ───────────────────────────────────
# This script is designed to be run on the DigitalOcean droplet.
# It can be triggered manually or via CI/CD pipeline.
#
# Usage: ./deploy.sh [tarball_path]
#   - If tarball_path is provided, extracts from it
#   - If no tarball, builds from the local source
#
# Prerequisites:
#   - Node.js 22+ and pnpm installed
#   - systemd service 'caldera-dashboard' configured
#   - App directory at /opt/caldera-dashboard

set -euo pipefail

APP_DIR="/opt/caldera-dashboard"
BACKUP_DIR="/opt/caldera-dashboard-backup"
TARBALL="${1:-}"

echo "═══════════════════════════════════════════════════"
echo "  Caldera Dashboard Deployment"
echo "  $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "═══════════════════════════════════════════════════"

# Step 1: Backup current deployment
echo ""
echo "→ Step 1: Backing up current deployment..."
if [ -d "$APP_DIR/dist" ]; then
  rm -rf "$BACKUP_DIR"
  cp -r "$APP_DIR/dist" "$BACKUP_DIR"
  echo "  ✓ Backup saved to $BACKUP_DIR"
else
  echo "  ⚠ No existing dist directory to backup"
fi

# Step 2: Deploy new build
echo ""
echo "→ Step 2: Deploying new build..."
if [ -n "$TARBALL" ] && [ -f "$TARBALL" ]; then
  echo "  Using provided tarball: $TARBALL"
  rm -rf "$APP_DIR/dist"
  tar xzf "$TARBALL" -C "$APP_DIR/"
  echo "  ✓ Extracted tarball to $APP_DIR/dist"
else
  echo "  No tarball provided — building from source..."
  cd "$APP_DIR"
  pnpm install --frozen-lockfile 2>/dev/null || pnpm install
  pnpm build
  echo "  ✓ Built from source"
fi

# Step 3: Install/update dependencies
echo ""
echo "→ Step 3: Installing dependencies..."
cd "$APP_DIR"
if [ -f "package.json" ]; then
  pnpm install 2>/dev/null || npm install
  echo "  ✓ Dependencies installed"
fi

# Step 4: Restart service
echo ""
echo "→ Step 4: Restarting caldera-dashboard service..."
systemctl daemon-reload
systemctl restart caldera-dashboard
sleep 3

# Step 5: Health check
echo ""
echo "→ Step 5: Running health check..."
STATUS=$(systemctl is-active caldera-dashboard)
if [ "$STATUS" = "active" ]; then
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/ 2>/dev/null || echo "000")
  if [ "$HTTP_CODE" = "200" ]; then
    echo "  ✓ Service is active and responding HTTP 200"
    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "  ✅ DEPLOYMENT SUCCESSFUL"
    echo "  Service: active | HTTP: 200"
    echo "═══════════════════════════════════════════════════"
    exit 0
  else
    echo "  ⚠ Service is active but HTTP returned $HTTP_CODE"
  fi
else
  echo "  ✗ Service is not active: $STATUS"
fi

# Step 6: Rollback on failure
echo ""
echo "→ Step 6: ROLLING BACK to previous version..."
if [ -d "$BACKUP_DIR" ]; then
  rm -rf "$APP_DIR/dist"
  cp -r "$BACKUP_DIR" "$APP_DIR/dist"
  systemctl restart caldera-dashboard
  sleep 3
  ROLLBACK_STATUS=$(systemctl is-active caldera-dashboard)
  echo "  Rollback status: $ROLLBACK_STATUS"
  echo ""
  echo "═══════════════════════════════════════════════════"
  echo "  ⚠ DEPLOYMENT FAILED — ROLLED BACK"
  echo "═══════════════════════════════════════════════════"
  exit 1
else
  echo "  ✗ No backup available for rollback!"
  echo ""
  echo "═══════════════════════════════════════════════════"
  echo "  ❌ DEPLOYMENT FAILED — NO ROLLBACK AVAILABLE"
  echo "═══════════════════════════════════════════════════"
  exit 2
fi
