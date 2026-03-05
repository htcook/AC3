/**
 * PM2 Ecosystem Configuration for Caldera Dashboard
 *
 * Production deployment with FIPS 140-3 kernel-level enforcement.
 *
 * Prerequisites:
 *   1. Install a FIPS-capable Node.js build (see deploy/install-fips-node.sh)
 *   2. Set all required environment variables (see .env.production.example)
 *   3. Build the project: pnpm build
 *   4. Start with PM2: pm2 start ecosystem.config.cjs
 *
 * FIPS Activation:
 *   The --enable-fips flag activates the OpenSSL FIPS provider at the
 *   Node.js runtime level. This ensures ALL cryptographic operations
 *   (not just application-level) route through FIPS-validated modules.
 *
 * Reference: https://nodejs.org/api/cli.html#--enable-fips
 */

module.exports = {
  apps: [
    {
      name: "caldera-dashboard",
      script: "dist/server/_core/index.js",

      // ─── FIPS 140-3 Kernel-Level Enforcement ──────────────────────
      node_args: "--enable-fips --max-old-space-size=2048",

      // ─── Process Management ───────────────────────────────────────
      instances: 1,
      exec_mode: "fork",
      autorestart: true,
      watch: false,
      max_memory_restart: "2G",

      // ─── Logging ──────────────────────────────────────────────────
      log_date_format: "YYYY-MM-DD HH:mm:ss Z",
      error_file: "/var/log/caldera-dashboard/error.log",
      out_file: "/var/log/caldera-dashboard/out.log",
      merge_logs: true,
      log_type: "json",

      // ─── Environment ──────────────────────────────────────────────
      env: {
        NODE_ENV: "production",
        PORT: 3000,

        // FIPS 140-3: Force OpenSSL FIPS provider
        // This is redundant with --enable-fips but serves as documentation
        OPENSSL_CONF: "/etc/ssl/fips/openssl-fips.cnf",

        // Certificate pinning (GoPhish — captured 2026-03-04)
        CERT_PIN_GOPHISH:
          "sha256/AR9f8u5V/V79+uX66CqJJQXzy3RcHsqJmqB+ZpcKq7A=",

        // Certificate pinning (Caldera — set after enabling HTTPS)
        // CERT_PIN_CALDERA: "sha256/<pin-after-https-enabled>",
      },

      // ─── Graceful Shutdown ────────────────────────────────────────
      kill_timeout: 10000,
      listen_timeout: 15000,
      shutdown_with_message: true,
    },
  ],
};
