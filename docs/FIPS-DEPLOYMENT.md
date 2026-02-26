# FIPS 140-2/3 Deployment Guide

This guide covers installing, configuring, and validating FIPS 140-2/3 compliant cryptography for the Ace C3 platform. FIPS compliance is required for federal government deployments and recommended for any environment handling sensitive data.

## Overview

The Ace C3 platform includes a built-in FIPS compliance layer (`server/lib/fips-compliance.ts`) that enforces FIPS-approved algorithms, manages cryptographic keys, and maintains a full audit trail. However, the underlying OpenSSL library must also be configured to run in FIPS mode for true FIPS 140-2/3 validation.

### Architecture

```
┌─────────────────────────────────────────────────┐
│  Ace C3 Application Layer                       │
│  ┌───────────────────────────────────────────┐  │
│  │  fips-compliance.ts                       │  │
│  │  • Algorithm enforcement (whitelist)      │  │
│  │  • Key management (AES-256, RSA, ECDSA)   │  │
│  │  • Audit trail (all crypto operations)    │  │
│  │  • Compliance reporting                   │  │
│  └───────────────────────────────────────────┘  │
│                      │                          │
│  ┌───────────────────────────────────────────┐  │
│  │  Node.js crypto module                    │  │
│  │  • Wraps OpenSSL via libcrypto            │  │
│  │  • FIPS mode toggle: crypto.setFips(1)    │  │
│  └───────────────────────────────────────────┘  │
│                      │                          │
│  ┌───────────────────────────────────────────┐  │
│  │  OpenSSL 3.x FIPS Provider (fips.so)      │  │
│  │  • NIST-validated crypto implementation   │  │
│  │  • Self-test on load                      │  │
│  │  • Integrity verification                 │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

## Prerequisites

| Requirement | Minimum Version | Notes |
|---|---|---|
| OpenSSL | 3.0.0+ | Required for FIPS provider architecture |
| Node.js | 18.0.0+ | Must be built with OpenSSL 3.x support |
| Operating System | Ubuntu 22.04+ / RHEL 8+ / Amazon Linux 2023 | FIPS packages available |
| Disk Space | 50 MB | For FIPS provider module and configuration |

## Installation

### Option 1: Ubuntu 22.04+ (Recommended)

Ubuntu 22.04 ships with OpenSSL 3.0.2 which supports the FIPS provider.

```bash
# Step 1: Install the FIPS provider module
sudo apt-get update
sudo apt-get install -y openssl libssl3

# Step 2: Generate the FIPS module configuration
# This runs the FIPS module self-tests and creates the integrity hash
sudo openssl fipsinstall \
  -out /etc/ssl/fipsmodule.cnf \
  -module /usr/lib/x86_64-linux-gnu/ossl-modules/fips.so

# Step 3: Verify the FIPS module was installed
ls -la /usr/lib/x86_64-linux-gnu/ossl-modules/fips.so
cat /etc/ssl/fipsmodule.cnf
```

If `fips.so` is not present, you may need to build OpenSSL from source with FIPS support:

```bash
# Download OpenSSL 3.x source
wget https://www.openssl.org/source/openssl-3.3.2.tar.gz
tar xzf openssl-3.3.2.tar.gz
cd openssl-3.3.2

# Configure with FIPS support
./Configure enable-fips --prefix=/usr/local/ssl --openssldir=/usr/local/ssl

# Build and install
make -j$(nproc)
sudo make install
sudo make install_fips

# Generate FIPS module configuration
sudo /usr/local/ssl/bin/openssl fipsinstall \
  -out /usr/local/ssl/fipsmodule.cnf \
  -module /usr/local/ssl/lib/ossl-modules/fips.so
```

### Option 2: RHEL 8+ / CentOS Stream 8+

RHEL provides FIPS as a system-wide crypto policy:

```bash
# Enable FIPS mode system-wide (requires reboot)
sudo fips-mode-setup --enable
sudo reboot

# Verify FIPS mode is active
fips-mode-setup --check
# Expected output: "FIPS mode is enabled."

# Verify OpenSSL FIPS provider
openssl list -providers
# Should show "fips" provider as active
```

### Option 3: Amazon Linux 2023

```bash
# Install FIPS packages
sudo dnf install -y openssl openssl-fips-provider

# Enable FIPS
sudo fips-mode-setup --enable
sudo reboot

# Verify
openssl list -providers
```

### Option 4: Docker Deployment

```dockerfile
FROM node:22-bookworm

# Install OpenSSL FIPS provider
RUN apt-get update && apt-get install -y openssl libssl3 && \
    openssl fipsinstall \
      -out /etc/ssl/fipsmodule.cnf \
      -module /usr/lib/x86_64-linux-gnu/ossl-modules/fips.so

# Configure OpenSSL for FIPS
COPY openssl-fips.cnf /etc/ssl/openssl.cnf

# Enable FIPS in Node.js
ENV OPENSSL_CONF=/etc/ssl/openssl.cnf
ENV NODE_OPTIONS="--enable-fips"

WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile
CMD ["node", "server/_core/index.ts"]
```

## Configuration

### Step 1: Configure OpenSSL to Load FIPS Provider

Edit `/etc/ssl/openssl.cnf` (or create a custom config):

```ini
# /etc/ssl/openssl.cnf (or /etc/ssl/openssl-fips.cnf)

openssl_conf = openssl_init

# Load the FIPS module configuration
.include /etc/ssl/fipsmodule.cnf

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
fips = fips_sect
default = default_sect
base = base_sect

[default_sect]
# Deactivate default provider in strict FIPS mode
# activate = 0
# Or keep active for non-crypto operations:
activate = 1

[base_sect]
activate = 1

[fips_sect]
activate = 1

[algorithm_sect]
default_properties = fips=yes
```

### Step 2: Configure Node.js for FIPS

There are three ways to enable FIPS in Node.js:

**Method A: Environment Variable (Recommended for Production)**

```bash
# Set in your systemd service file or .env
export OPENSSL_CONF=/etc/ssl/openssl.cnf
export NODE_OPTIONS="--enable-fips"
```

**Method B: Command Line Flag**

```bash
node --enable-fips server/_core/index.ts
```

**Method C: Runtime Toggle (for conditional FIPS)**

```typescript
// In server startup code
import crypto from "crypto";

if (process.env.FIPS_MODE === "true") {
  try {
    crypto.setFips(1);
    console.log("[FIPS] FIPS mode enabled successfully");
  } catch (err) {
    console.error("[FIPS] Failed to enable FIPS mode:", err);
    process.exit(1);
  }
}
```

### Step 3: Configure Ace C3 Platform

Add the following environment variables to your deployment:

```bash
# Enable FIPS enforcement in the application layer
FIPS_MODE=true

# Optional: Set FIPS strictness level
# "strict" = reject all non-FIPS operations (recommended for federal)
# "warn" = log warnings but allow non-FIPS operations (for transition)
FIPS_ENFORCEMENT=strict

# Optional: Enable FIPS audit logging to external SIEM
FIPS_AUDIT_LOG=/var/log/ace-c3/fips-audit.log
```

### Step 4: Configure TLS for FIPS

The platform's FIPS compliance layer already enforces TLS 1.2+ with FIPS-approved cipher suites. Verify your reverse proxy (nginx/HAProxy) also uses FIPS-compliant TLS:

```nginx
# nginx FIPS-compliant TLS configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers on;
ssl_ecdh_curve secp384r1:secp256r1;
```

## Verification

### Runtime FIPS Status Check

The platform includes a built-in FIPS readiness endpoint:

```bash
# Check FIPS status via API
curl -s https://your-server/api/trpc/abilityGraph.fipsStatus | jq .

# Expected output when FIPS is fully enabled:
# {
#   "result": {
#     "fipsEnabled": true,
#     "openSSLVersion": "3.0.2",
#     "fipsProvider": "active",
#     "complianceLevel": "FIPS 140-3",
#     "approvedAlgorithms": ["AES-256-GCM", "SHA-256", ...],
#     "keyStoreStatus": "healthy"
#   }
# }
```

### Self-Test Verification

```bash
# Run OpenSSL FIPS self-tests manually
openssl fipsinstall -verify \
  -in /etc/ssl/fipsmodule.cnf \
  -module /usr/lib/x86_64-linux-gnu/ossl-modules/fips.so

# Verify Node.js FIPS mode
node --enable-fips -e "
  const crypto = require('crypto');
  console.log('FIPS mode:', crypto.getFips());
  console.log('OpenSSL:', process.versions.openssl);
  
  // Test FIPS-approved algorithm
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.update('test', 'utf8');
  cipher.final();
  console.log('AES-256-GCM: PASS');
  
  // Test that non-FIPS algorithm is rejected
  try {
    crypto.createHash('md5').update('test').digest();
    console.log('MD5: ALLOWED (FIPS not enforcing)');
  } catch {
    console.log('MD5: BLOCKED (FIPS enforcing correctly)');
  }
"
```

### Compliance Report

The platform generates FIPS compliance reports accessible from the dashboard:

```bash
# Generate compliance report via API
curl -s -X POST https://your-server/api/trpc/abilityGraph.fipsReport | jq .
```

The report includes:

- Algorithm usage statistics (approved vs. non-approved)
- Key management audit trail
- TLS configuration assessment
- Entropy source validation
- Non-compliant operation warnings

## Approved Algorithms

The following algorithms are approved for use in FIPS mode:

| Category | Algorithm | Key Size | Status |
|---|---|---|---|
| Symmetric Encryption | AES-256-GCM | 256-bit | Approved |
| Symmetric Encryption | AES-128-GCM | 128-bit | Approved |
| Symmetric Encryption | AES-256-CBC | 256-bit | Approved (GCM preferred) |
| Hash | SHA-256 | - | Approved |
| Hash | SHA-384 | - | Approved |
| Hash | SHA-512 | - | Approved |
| Hash | SHA3-256 | - | Approved |
| MAC | HMAC-SHA-256 | 256-bit | Approved |
| MAC | HMAC-SHA-384 | 384-bit | Approved |
| Key Derivation | PBKDF2-SHA-256 | 256-bit | Approved (≥100k iterations) |
| Key Derivation | HKDF-SHA-256 | 256-bit | Approved |
| Asymmetric | RSA-2048 | 2048-bit | Approved (4096 recommended) |
| Asymmetric | RSA-4096 | 4096-bit | Approved |
| Asymmetric | ECDSA P-256 | 256-bit | Approved |
| Asymmetric | ECDSA P-384 | 384-bit | Approved |
| Key Exchange | ECDHE P-256 | 256-bit | Approved |
| Key Exchange | ECDHE P-384 | 384-bit | Approved |
| TLS | TLS 1.2 | - | Approved |
| TLS | TLS 1.3 | - | Approved |

### Rejected Algorithms (Non-FIPS)

| Algorithm | Reason |
|---|---|
| MD5 | Cryptographically broken |
| SHA-1 | Deprecated, collision attacks known |
| DES / 3DES | Insufficient key length |
| RC4 | Stream cipher with known biases |
| Blowfish | Not NIST-approved |
| ChaCha20 | Not in FIPS 140-2 (approved in 140-3 draft) |
| TLS 1.0 / 1.1 | Deprecated protocols |

## Troubleshooting

### FIPS Provider Not Found

```
Error: digital envelope routines::unsupported
```

**Solution:** Ensure the FIPS provider module is installed and the OpenSSL config points to it:

```bash
# Check if fips.so exists
find / -name "fips.so" 2>/dev/null

# If not found, install it
sudo openssl fipsinstall -out /etc/ssl/fipsmodule.cnf \
  -module $(find / -name "fips.so" 2>/dev/null | head -1)
```

### Node.js FIPS Mode Fails to Enable

```
Error: Cannot set FIPS mode: FIPS provider not available
```

**Solution:** Node.js must be built with OpenSSL 3.x support. Check your Node.js build:

```bash
node -e "console.log(process.versions.openssl)"
# Must be 3.0.0 or higher
```

If using an older Node.js, upgrade to Node.js 18+ which ships with OpenSSL 3.x.

### Self-Test Failure

```
Error: FIPS self-test failed
```

**Solution:** The FIPS module integrity check failed. Regenerate the configuration:

```bash
sudo rm /etc/ssl/fipsmodule.cnf
sudo openssl fipsinstall -out /etc/ssl/fipsmodule.cnf \
  -module /usr/lib/x86_64-linux-gnu/ossl-modules/fips.so
```

### Performance Impact

FIPS mode typically adds 5-15% overhead to cryptographic operations due to:

- Self-tests on provider load (~200ms startup)
- Algorithm restrictions (no hardware-accelerated non-FIPS algorithms)
- Key validation checks on every operation

For high-throughput scenarios, consider:

- Using connection pooling to amortize TLS handshake costs
- Caching encrypted data where appropriate
- Using AES-GCM (hardware-accelerated on modern CPUs via AES-NI)

## Systemd Service Configuration

Example systemd service file with FIPS enabled:

```ini
[Unit]
Description=Ace C3 Platform (FIPS Mode)
After=network.target

[Service]
Type=simple
User=ace-c3
WorkingDirectory=/opt/ace-c3
Environment=NODE_ENV=production
Environment=OPENSSL_CONF=/etc/ssl/openssl.cnf
Environment=NODE_OPTIONS=--enable-fips
Environment=FIPS_MODE=true
Environment=FIPS_ENFORCEMENT=strict
ExecStart=/usr/bin/node server/_core/index.ts
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/ace-c3 /var/log/ace-c3

[Install]
WantedBy=multi-user.target
```

## Compliance Checklist

Use this checklist before declaring FIPS compliance:

- [ ] OpenSSL 3.x FIPS provider (`fips.so`) installed
- [ ] `openssl fipsinstall` completed successfully (self-tests pass)
- [ ] OpenSSL configuration loads FIPS provider
- [ ] Node.js started with `--enable-fips` flag
- [ ] `crypto.getFips()` returns `1` at runtime
- [ ] Application FIPS compliance layer enabled (`FIPS_MODE=true`)
- [ ] TLS 1.2+ enforced with FIPS-approved cipher suites
- [ ] No MD5, SHA-1, DES, RC4, or Blowfish usage in application
- [ ] Key sizes meet minimums (AES-128+, RSA-2048+, ECDSA P-256+)
- [ ] PBKDF2 iterations ≥ 100,000
- [ ] Audit logging enabled for all cryptographic operations
- [ ] Compliance report generated and reviewed
- [ ] FIPS status endpoint returning healthy
- [ ] Reverse proxy (nginx/HAProxy) configured with FIPS TLS
- [ ] Database connections using TLS 1.2+ with FIPS ciphers

## References

- [NIST FIPS 140-3 Standard](https://csrc.nist.gov/publications/detail/fips/140/3/final)
- [OpenSSL 3.x FIPS Provider](https://www.openssl.org/docs/man3.0/man7/fips_module.html)
- [Node.js FIPS Support](https://nodejs.org/api/crypto.html#cryptosetfipsbool)
- [NIST Cryptographic Module Validation Program](https://csrc.nist.gov/projects/cryptographic-module-validation-program)
