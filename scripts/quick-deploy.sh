#!/bin/bash
# ─── Quick Deploy from Manus Sandbox ───────────────────────────────────
# Run this from the Manus sandbox to build and deploy to DigitalOcean.
# Usage: bash scripts/quick-deploy.sh
#
# Prerequisites:
#   - SSH key at /home/ubuntu/.ssh/do_deploy
#   - Droplet accessible at 137.184.7.224

set -euo pipefail

DROPLET_IP="137.184.7.224"
SSH_KEY="/home/ubuntu/.ssh/do_deploy"
PROJECT_DIR="/home/ubuntu/caldera-dashboard"
APP_DIR="/opt/caldera-dashboard"

echo "═══════════════════════════════════════════════════"
echo "  Quick Deploy to DigitalOcean"
echo "  $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "═══════════════════════════════════════════════════"

# Step 1: Build
echo ""
echo "→ Building project..."
cd "$PROJECT_DIR"
pnpm build
echo "  ✓ Build complete"

# Step 2: Package
echo ""
echo "→ Packaging build artifacts..."
tar czf /tmp/caldera-deploy.tar.gz dist/
echo "  ✓ Package created"

# Step 3: Transfer
echo ""
echo "→ Transferring to droplet..."
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no /tmp/caldera-deploy.tar.gz "root@${DROPLET_IP}:/tmp/"
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no package.json "root@${DROPLET_IP}:${APP_DIR}/"
echo "  ✓ Files transferred"

# Step 4: Deploy
echo ""
echo "→ Deploying on droplet..."
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "root@${DROPLET_IP}" << DEPLOY
  cd ${APP_DIR}
  # Backup
  [ -d dist ] && cp -r dist dist-backup-\$(date +%Y%m%d%H%M%S)
  # Extract
  rm -rf dist/
  tar xzf /tmp/caldera-deploy.tar.gz
  rm /tmp/caldera-deploy.tar.gz
  # Install deps
  pnpm install 2>/dev/null || npm install
  # Restart
  systemctl restart caldera-dashboard
  sleep 5
  # Health check
  STATUS=\$(systemctl is-active caldera-dashboard)
  HTTP=\$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/ 2>/dev/null || echo "000")
  echo "Service: \$STATUS | HTTP: \$HTTP"
  # Cleanup old backups (keep last 3)
  ls -dt dist-backup-* 2>/dev/null | tail -n +4 | xargs rm -rf 2>/dev/null || true
DEPLOY

echo ""
echo "═══════════════════════════════════════════════════"
echo "  ✅ Deployment complete!"
echo "  https://dashboard.aceofcloud.io"
echo "═══════════════════════════════════════════════════"
