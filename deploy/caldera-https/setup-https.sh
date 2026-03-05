#!/bin/bash
# ============================================================
# Caldera & GoPhish HTTPS Setup Script
# ============================================================
# This script installs Caddy as a reverse proxy to provide
# FIPS 140-3 compliant TLS termination for Caldera and GoPhish.
#
# Run on the app server (134.199.213.248) as root:
#   bash setup-https.sh
#
# Prerequisites:
#   - DNS records for caldera.aceofcloud.io and gophish.aceofcloud.io
#     pointing to 134.199.213.248
#   - Caldera running on port 8888 (HTTP)
#   - GoPhish running on port 3333 (HTTPS with self-signed cert)
# ============================================================

set -euo pipefail

echo "=== Caldera & GoPhish HTTPS Setup ==="
echo "Server: $(hostname) ($(curl -s ifconfig.me))"
echo ""

# Step 1: Install Caddy
echo "[1/5] Installing Caddy..."
apt-get update -qq
apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt-get update -qq
apt-get install -y -qq caddy
echo "  Caddy installed: $(caddy version)"

# Step 2: Create log directory
echo "[2/5] Creating log directories..."
mkdir -p /var/log/caddy
chown caddy:caddy /var/log/caddy

# Step 3: Copy Caddyfile
echo "[3/5] Installing Caddyfile..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "${SCRIPT_DIR}/Caddyfile" /etc/caddy/Caddyfile
echo "  Caddyfile installed to /etc/caddy/Caddyfile"

# Step 4: Open firewall ports
echo "[4/5] Configuring firewall..."
if command -v ufw &>/dev/null; then
    ufw allow 80/tcp comment "HTTP (Caddy redirect)"
    ufw allow 443/tcp comment "HTTPS (Caddy TLS)"
    echo "  UFW rules added for ports 80 and 443"
else
    echo "  UFW not found, skipping firewall config"
fi

# Step 5: Start Caddy
echo "[5/5] Starting Caddy..."
systemctl enable caddy
systemctl restart caddy
sleep 3

# Verify
echo ""
echo "=== Verification ==="
if systemctl is-active --quiet caddy; then
    echo "  Caddy: RUNNING"
else
    echo "  Caddy: FAILED"
    journalctl -u caddy --no-pager -n 20
    exit 1
fi

# Test HTTPS endpoints
echo ""
echo "Testing HTTPS endpoints (may take a moment for cert issuance)..."
sleep 5

if curl -s --connect-timeout 5 "https://caldera.aceofcloud.io/api/v2/health" -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q "200\|401"; then
    echo "  Caldera HTTPS: OK"
else
    echo "  Caldera HTTPS: Pending (cert may still be issuing)"
fi

if curl -s --connect-timeout 5 "https://gophish.aceofcloud.io/" -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q "200\|302"; then
    echo "  GoPhish HTTPS: OK"
else
    echo "  GoPhish HTTPS: Pending (cert may still be issuing)"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Verify DNS records point to this server"
echo "  2. Wait for Let's Encrypt certs to be issued (usually < 1 min)"
echo "  3. Update dashboard secrets:"
echo "     CALDERA_BASE_URL=https://caldera.aceofcloud.io"
echo "     GOPHISH_BASE_URL=https://gophish.aceofcloud.io"
echo "  4. Capture new cert pins for enforce mode"
echo "  5. Optionally block direct access to ports 8888/3333 via UFW"
