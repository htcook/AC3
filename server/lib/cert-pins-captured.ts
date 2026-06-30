/**
 * Captured Certificate Pins
 *
 * These pins were captured from live servers on 2026-03-04.
 * They are used for certificate pinning enforcement.
 *
 * To recapture pins after certificate rotation, run:
 *   node -e "require('./server/lib/cert-pinning').validateCertPin('hostname', port)"
 */

// ─── GoPhish (Self-Signed) ───────────────────────────────────────────────
// Server: 134.199.213.248:3333
// Subject: O=Gophish
// Issuer: O=Gophish (self-signed)
// Valid: Feb 16 2026 - Feb 14 2036
// Protocol: TLSv1.3 (TLS_AES_128_GCM_SHA256)

export const GOPHISH_PINS = {
  /** SPKI pin — SHA-256 of the server's public key */
  primary: "AR9f8u5V/V79+uX66CqJJQXzy3RcHsqJmqB+ZpcKq7A=",
  /** Raw cert pin — SHA-256 of the full DER certificate (backup) */
  backup: "NBSn9zhwtJgPhs7wadWdNUv6/6f41HxuSoPNLZMQ7LQ=",
  /** Certificate fingerprint (SHA-256) for reference */
  fingerprint256: "34:14:A7:F7:38:70:B4:98:0F:86:CE:F0:69:D5:9D:35:4B:FA:FF:A7:F8:D4:7C:6E:4A:83:CD:2D:93:10:EC:B4",
  /** When pins were captured */
  capturedAt: "2026-03-04T21:15:00Z",
  /** Certificate expiry */
  certExpiresAt: "2036-02-14T20:03:51Z",
};

// ─── Caldera ─────────────────────────────────────────────────────────────
// Server: 134.199.213.248:8888
// Status: Running on HTTP (not HTTPS) — cert pinning not applicable
// Action Required: Enable HTTPS on the Caldera server to enable cert pinning
//
// To enable HTTPS on Caldera:
//   1. Generate a TLS certificate: openssl req -x509 -newkey rsa:4096 -keyout caldera.key -out caldera.crt -days 365
//   2. In Caldera's conf/local.yml, set:
//        app.contact.tunnel.protocol: https
//        app.contact.tunnel.cert_file: caldera.crt
//        app.contact.tunnel.key_file: caldera.key
//   3. Restart Caldera
//   4. Update CALDERA_BASE_URL to https://...
//   5. Re-run pin capture to get the certificate pin

export const CALDERA_PINS = {
  /** Not available — Caldera is running on HTTP */
  primary: null as string | null,
  backup: null as string | null,
  fingerprint256: null as string | null,
  capturedAt: "2026-03-04T21:15:00Z",
  certExpiresAt: null as string | null,
  /** Reason cert pinning is not active */
  note: "Caldera is running on HTTP (port 8888). Enable HTTPS to activate cert pinning.",
};
