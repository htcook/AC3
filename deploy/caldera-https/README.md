# Caldera & GoPhish HTTPS Deployment

This directory contains everything needed to enable FIPS 140-3 compliant HTTPS on the Caldera C2 and GoPhish servers using Caddy as a TLS-terminating reverse proxy.

## Architecture

```
Internet → Caddy (TLS 1.2/1.3, FIPS ciphers) → Caldera (HTTP :8888)
                                                → GoPhish (HTTPS :3333)
```

Caddy handles:
- Automatic Let's Encrypt certificate issuance and renewal
- TLS termination with FIPS 140-3 approved cipher suites only
- HSTS headers and security hardening
- Access logging in JSON format

## Prerequisites

1. **DNS Records**: Create A records pointing to the app server (134.199.213.248):
   - `caldera.aceofcloud.io → 134.199.213.248`
   - `gophish.aceofcloud.io → 134.199.213.248`

2. **SSH Access**: You need root SSH access to the app server

3. **Services Running**: Caldera on port 8888, GoPhish on port 3333

## Installation

```bash
# SSH into the app server
ssh root@134.199.213.248

# Copy the deploy directory or clone the repo
# Then run:
cd deploy/caldera-https
bash setup-https.sh
```

## Post-Installation

After HTTPS is working, update the dashboard secrets:

| Secret | Old Value | New Value |
|--------|-----------|-----------|
| `CALDERA_BASE_URL` | `http://134.199.213.248:8888` | `https://caldera.aceofcloud.io` |
| `GOPHISH_BASE_URL` | `https://134.199.213.248:3333` | `https://gophish.aceofcloud.io` |

Then capture new certificate SPKI pins:
```bash
# From the dashboard server or any machine:
openssl s_client -connect caldera.aceofcloud.io:443 -servername caldera.aceofcloud.io </dev/null 2>/dev/null | \
  openssl x509 -pubkey -noout | \
  openssl pkey -pubin -outform DER | \
  openssl dgst -sha256 -binary | base64
```

Update the pins in `server/lib/cert-pinning.ts` and switch Caldera to enforce mode.

## FIPS 140-3 Cipher Suites

The Caddyfile restricts TLS to these NIST SP 800-52 Rev. 2 approved suites:

| Suite | Protocol |
|-------|----------|
| TLS_AES_256_GCM_SHA384 | TLS 1.3 |
| TLS_AES_128_GCM_SHA256 | TLS 1.3 |
| TLS_CHACHA20_POLY1305_SHA256 | TLS 1.3 |
| TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | TLS 1.2 |
| TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | TLS 1.2 |
| TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 | TLS 1.2 |
| TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 | TLS 1.2 |

## Firewall Hardening

After verifying HTTPS works, block direct access to backend ports:

```bash
ufw deny 8888/tcp comment "Block direct Caldera HTTP"
ufw deny 3333/tcp comment "Block direct GoPhish HTTPS"
```

## Troubleshooting

```bash
# Check Caddy status
systemctl status caddy

# View Caddy logs
journalctl -u caddy -f

# Test TLS configuration
openssl s_client -connect caldera.aceofcloud.io:443 -tls1_2

# Verify FIPS cipher negotiation
openssl s_client -connect caldera.aceofcloud.io:443 -cipher 'ECDHE+AESGCM'
```
