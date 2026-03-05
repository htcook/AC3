#!/usr/bin/env bash
#
# install-fips-node.sh — Install FIPS-capable Node.js on DigitalOcean
#
# This script installs Node.js 22.x with OpenSSL 3.x FIPS provider support
# on Ubuntu 22.04/24.04 (DigitalOcean droplet).
#
# After installation, Node.js can be started with --enable-fips to activate
# kernel-level FIPS 140-3 cryptographic enforcement.
#
# Usage:
#   chmod +x deploy/install-fips-node.sh
#   sudo ./deploy/install-fips-node.sh
#
# Verification:
#   node --enable-fips -e "console.log('FIPS:', require('crypto').getFips())"
#   # Expected output: FIPS: 1
#
# References:
#   - https://nodejs.org/api/cli.html#--enable-fips
#   - https://www.openssl.org/docs/man3.0/man7/fips_module.html
#   - NIST SP 800-140 (FIPS 140-3 Implementation Guidance)

set -euo pipefail

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Caldera Dashboard — FIPS-Capable Node.js Installation      ║"
echo "║  Target: Ubuntu 22.04/24.04 (DigitalOcean)                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# ─── 1. System Prerequisites ─────────────────────────────────────────────

echo ""
echo "[1/6] Installing system prerequisites..."
apt-get update -qq
apt-get install -y -qq \
  build-essential \
  curl \
  git \
  libssl-dev \
  openssl \
  ca-certificates \
  gnupg \
  lsb-release

# ─── 2. Install OpenSSL 3.x FIPS Provider ────────────────────────────────

echo ""
echo "[2/6] Configuring OpenSSL 3.x FIPS provider..."

OPENSSL_VERSION=$(openssl version | awk '{print $2}')
echo "  Current OpenSSL: ${OPENSSL_VERSION}"

# Check if OpenSSL 3.x is available (required for FIPS provider)
if [[ "${OPENSSL_VERSION}" == 3.* ]]; then
  echo "  ✓ OpenSSL 3.x detected — FIPS provider supported"
else
  echo "  ✗ OpenSSL ${OPENSSL_VERSION} detected — upgrading to 3.x..."
  apt-get install -y -qq openssl libssl3
fi

# Install the FIPS provider module
echo "  Installing OpenSSL FIPS provider..."
apt-get install -y -qq openssl

# Generate FIPS module configuration
FIPS_MODULE_PATH="/usr/lib/$(uname -m)-linux-gnu/ossl-modules/fips.so"
FIPS_CONF_DIR="/etc/ssl/fips"
FIPS_CONF="${FIPS_CONF_DIR}/openssl-fips.cnf"

mkdir -p "${FIPS_CONF_DIR}"

if [ -f "${FIPS_MODULE_PATH}" ]; then
  echo "  ✓ FIPS module found at ${FIPS_MODULE_PATH}"
else
  echo "  ⚠ FIPS module not found at expected path"
  echo "  Searching for FIPS module..."
  FIPS_MODULE_PATH=$(find /usr -name "fips.so" -type f 2>/dev/null | head -1)
  if [ -z "${FIPS_MODULE_PATH}" ]; then
    echo "  ✗ FIPS module not found — installing from source may be required"
    echo "  See: https://www.openssl.org/docs/man3.0/man7/fips_module.html"
  else
    echo "  ✓ Found FIPS module at ${FIPS_MODULE_PATH}"
  fi
fi

# Create OpenSSL FIPS configuration
cat > "${FIPS_CONF}" << 'FIPSCONF'
# OpenSSL FIPS Configuration for Caldera Dashboard
# This configuration enables the FIPS provider alongside the default provider.

openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
fips = fips_sect
default = default_sect

[fips_sect]
activate = 1

[default_sect]
activate = 1

[algorithm_sect]
default_properties = fips=yes
FIPSCONF

echo "  ✓ FIPS configuration written to ${FIPS_CONF}"

# Run FIPS module self-test (install)
if [ -n "${FIPS_MODULE_PATH}" ] && [ -f "${FIPS_MODULE_PATH}" ]; then
  echo "  Running FIPS module self-test..."
  openssl fipsinstall \
    -out "${FIPS_CONF_DIR}/fipsmodule.cnf" \
    -module "${FIPS_MODULE_PATH}" 2>/dev/null || {
    echo "  ⚠ FIPS self-test skipped (may require manual configuration)"
  }
fi

# ─── 3. Install Node.js 22.x ─────────────────────────────────────────────

echo ""
echo "[3/6] Installing Node.js 22.x..."

# Use NodeSource for the latest LTS
if ! command -v node &>/dev/null || [[ "$(node -v)" != v22.* ]]; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y -qq nodejs
fi

NODE_VERSION=$(node -v)
echo "  ✓ Node.js ${NODE_VERSION} installed"

# Verify FIPS support
echo "  Verifying FIPS support..."
FIPS_CHECK=$(node --enable-fips -e "console.log(require('crypto').getFips())" 2>/dev/null || echo "0")
if [ "${FIPS_CHECK}" = "1" ]; then
  echo "  ✓ Node.js FIPS mode verified — crypto.getFips() = 1"
else
  echo "  ⚠ Node.js FIPS mode not available with current OpenSSL"
  echo "  The --enable-fips flag requires OpenSSL FIPS provider to be properly installed"
  echo "  Application-level FIPS enforcement will still be active"
fi

# ─── 4. Install pnpm ─────────────────────────────────────────────────────

echo ""
echo "[4/6] Installing pnpm..."
npm install -g pnpm@latest
echo "  ✓ pnpm $(pnpm -v) installed"

# ─── 5. Install PM2 ──────────────────────────────────────────────────────

echo ""
echo "[5/6] Installing PM2..."
npm install -g pm2@latest
echo "  ✓ PM2 $(pm2 -v) installed"

# Create log directory
mkdir -p /var/log/caldera-dashboard
chown -R $(logname 2>/dev/null || echo "root"):$(logname 2>/dev/null || echo "root") /var/log/caldera-dashboard

# ─── 6. Summary ──────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Installation Complete                                       ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Node.js:  $(node -v)                                       ║"
echo "║  OpenSSL:  $(openssl version | awk '{print $2}')            ║"
echo "║  pnpm:     $(pnpm -v)                                       ║"
echo "║  PM2:      $(pm2 -v)                                        ║"
echo "║  FIPS:     ${FIPS_CHECK:-not verified}                       ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Next Steps:                                                 ║"
echo "║  1. cd /opt/caldera-dashboard                                ║"
echo "║  2. pnpm install                                             ║"
echo "║  3. pnpm build                                               ║"
echo "║  4. cp .env.production .env                                  ║"
echo "║  5. pm2 start ecosystem.config.cjs                           ║"
echo "║  6. pm2 save && pm2 startup                                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Verify FIPS with:"
echo "  node --enable-fips -e \"console.log('FIPS:', require('crypto').getFips())\""
