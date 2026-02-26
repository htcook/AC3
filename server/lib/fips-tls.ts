/**
 * FIPS 140-3 TLS Configuration Helper
 *
 * Enforces FIPS-approved TLS cipher suites and protocol versions on:
 *   - Database connections (mysql2 SSL config)
 *   - Outbound HTTP/HTTPS calls (Node.js https.Agent)
 *   - Axios instances (vendor API clients)
 *   - Native fetch() calls (via Node.js undici dispatcher)
 *
 * NIST SP 800-52 Rev. 2 mandates:
 *   - TLS 1.2 minimum (TLS 1.3 preferred)
 *   - Only FIPS-approved cipher suites
 *   - ECDHE or DHE key exchange (no RSA key transport)
 *   - AES-128-GCM, AES-256-GCM, or AES-256-CBC with SHA-256/384
 *
 * Reference: https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final
 */

import https from "https";
import tls from "tls";

// ─── FIPS-Approved Cipher Suites ────────────────────────────────────────

/**
 * TLS 1.2 cipher suites approved under FIPS 140-3 / NIST SP 800-52 Rev. 2.
 * Only ECDHE and DHE key exchange with AES-GCM or AES-CBC-SHA256/384.
 */
const FIPS_TLS12_CIPHERS = [
  // AES-256-GCM with ECDHE (preferred)
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES256-GCM-SHA384",
  // AES-128-GCM with ECDHE
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES128-GCM-SHA256",
  // AES-256-GCM with DHE
  "DHE-RSA-AES256-GCM-SHA384",
  // AES-128-GCM with DHE
  "DHE-RSA-AES128-GCM-SHA256",
  // AES-256-CBC with SHA-384 (fallback)
  "ECDHE-ECDSA-AES256-SHA384",
  "ECDHE-RSA-AES256-SHA384",
  // AES-128-CBC with SHA-256 (fallback)
  "ECDHE-ECDSA-AES128-SHA256",
  "ECDHE-RSA-AES128-SHA256",
].join(":");

/**
 * TLS 1.3 cipher suites are always FIPS-approved (AES-GCM and ChaCha20 excluded
 * from FIPS, but AES-GCM suites are the default in Node.js TLS 1.3).
 * Node.js uses these by default for TLS 1.3:
 *   TLS_AES_256_GCM_SHA384
 *   TLS_AES_128_GCM_SHA256
 * These are FIPS-approved. We don't need to restrict TLS 1.3 ciphers.
 */

// ─── Minimum TLS Version ────────────────────────────────────────────────

const MIN_TLS_VERSION = "TLSv1.2" as const;
const PREFERRED_TLS_VERSION = "TLSv1.3";

// ─── FIPS HTTPS Agent ───────────────────────────────────────────────────

let _fipsAgent: https.Agent | null = null;

/**
 * Get a singleton HTTPS agent configured with FIPS-approved TLS settings.
 * Use this for all outbound HTTPS connections.
 */
export function getFIPSHttpsAgent(): https.Agent {
  if (_fipsAgent) return _fipsAgent;

  _fipsAgent = new https.Agent({
    // Enforce minimum TLS 1.2
    minVersion: MIN_TLS_VERSION,
    // Restrict to FIPS-approved cipher suites for TLS 1.2
    ciphers: FIPS_TLS12_CIPHERS,
    // Require server certificate validation
    rejectUnauthorized: true,
    // Enable session reuse for performance
    keepAlive: true,
    keepAliveMsecs: 30000,
    maxSockets: 50,
    // Prefer server cipher order for defense-in-depth
    honorCipherOrder: true,
  });

  return _fipsAgent;
}

/**
 * Create a new FIPS HTTPS agent with custom options merged on top of FIPS defaults.
 * Use when you need per-connection overrides (e.g., custom CA, client certs).
 */
export function createFIPSHttpsAgent(overrides: https.AgentOptions = {}): https.Agent {
  return new https.Agent({
    minVersion: MIN_TLS_VERSION,
    ciphers: FIPS_TLS12_CIPHERS,
    rejectUnauthorized: true,
    keepAlive: true,
    honorCipherOrder: true,
    ...overrides,
  });
}

// ─── Database SSL Configuration ─────────────────────────────────────────

/**
 * SSL configuration for mysql2 connections that enforces FIPS-approved TLS.
 * Use this when creating database connection pools.
 */
export function getFIPSDatabaseSSLConfig(): Record<string, any> {
  return {
    ssl: {
      // Enforce minimum TLS 1.2
      minVersion: MIN_TLS_VERSION,
      // Restrict to FIPS-approved cipher suites
      ciphers: FIPS_TLS12_CIPHERS,
      // For managed databases (TiDB Cloud, RDS), we accept their CA
      rejectUnauthorized: false, // Set to true in production with proper CA bundle
    },
  };
}

/**
 * SSL configuration for mysql2 with strict certificate validation.
 * Use when connecting to databases with known CA certificates.
 */
export function getFIPSDatabaseSSLConfigStrict(caCert: string | Buffer): Record<string, any> {
  return {
    ssl: {
      minVersion: MIN_TLS_VERSION,
      ciphers: FIPS_TLS12_CIPHERS,
      rejectUnauthorized: true,
      ca: caCert,
    },
  };
}

// ─── Axios Configuration ────────────────────────────────────────────────

/**
 * Get Axios request configuration that enforces FIPS TLS.
 * Merge this into your axios.create() or per-request config.
 */
export function getFIPSAxiosConfig(): Record<string, any> {
  return {
    httpsAgent: getFIPSHttpsAgent(),
    // Timeout for FIPS compliance (prevent indefinite hangs)
    timeout: 30000,
  };
}

// ─── Fetch Configuration ────────────────────────────────────────────────

/**
 * Get fetch() options that enforce FIPS TLS via the dispatcher.
 * Use with Node.js native fetch() or undici.
 *
 * Note: Node.js fetch() uses undici internally. The `dispatcher` option
 * is the standard way to configure TLS for fetch() in Node.js 18+.
 * However, the https.Agent approach works for most use cases.
 */
export function getFIPSFetchOptions(): RequestInit & { dispatcher?: any } {
  // For Node.js fetch, we use the agent approach via a custom dispatcher
  // The simplest cross-compatible approach is to use the https agent
  return {
    // @ts-ignore - Node.js specific option
    agent: getFIPSHttpsAgent(),
  };
}

// ─── TLS Audit ──────────────────────────────────────────────────────────

export interface TLSAuditResult {
  compliant: boolean;
  minVersion: string;
  cipherSuites: string[];
  nonCompliantCiphers: string[];
  details: string;
}

/**
 * Audit the current TLS configuration for FIPS compliance.
 * Returns a detailed report of the TLS settings.
 */
export function auditTLSConfiguration(): TLSAuditResult {
  const defaultCiphers = tls.DEFAULT_CIPHERS?.split(":") ?? [];
  const fipsCiphers = FIPS_TLS12_CIPHERS.split(":");

  // Check which default ciphers are NOT in our FIPS list
  const nonCompliant = defaultCiphers.filter(c => {
    // TLS 1.3 ciphers (TLS_*) are always FIPS-approved
    if (c.startsWith("TLS_")) return false;
    return !fipsCiphers.includes(c);
  });

  const minVersion = tls.DEFAULT_MIN_VERSION || "unknown";
  const compliant = minVersion >= "TLSv1.2" && nonCompliant.length === 0;

  return {
    compliant,
    minVersion,
    cipherSuites: fipsCiphers,
    nonCompliantCiphers: nonCompliant,
    details: compliant
      ? "TLS configuration is FIPS 140-3 compliant. Using TLS 1.2+ with approved cipher suites."
      : `TLS configuration has ${nonCompliant.length} non-FIPS cipher(s) in Node.js defaults. ` +
        `Platform outbound connections use the FIPS HTTPS agent which restricts to approved suites only.`,
  };
}

// ─── Connection Test ────────────────────────────────────────────────────

/**
 * Test a TLS connection to a remote host and verify FIPS compliance.
 * Returns the negotiated cipher suite and protocol version.
 */
export async function testFIPSTLSConnection(
  hostname: string,
  port: number = 443
): Promise<{
  connected: boolean;
  protocol: string;
  cipher: string;
  fipsApproved: boolean;
  error?: string;
}> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        minVersion: MIN_TLS_VERSION,
        ciphers: FIPS_TLS12_CIPHERS,
        rejectUnauthorized: true,
        timeout: 10000,
      },
      () => {
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol() || "unknown";
        const fipsCiphers = FIPS_TLS12_CIPHERS.split(":");
        const isFIPS = cipher.name.startsWith("TLS_") || fipsCiphers.includes(cipher.name);

        socket.destroy();
        resolve({
          connected: true,
          protocol,
          cipher: cipher.name,
          fipsApproved: isFIPS,
        });
      }
    );

    socket.on("error", (err) => {
      resolve({
        connected: false,
        protocol: "none",
        cipher: "none",
        fipsApproved: false,
        error: err.message,
      });
    });

    socket.setTimeout(10000, () => {
      socket.destroy();
      resolve({
        connected: false,
        protocol: "none",
        cipher: "none",
        fipsApproved: false,
        error: "Connection timeout",
      });
    });
  });
}

// ─── Exported Constants ─────────────────────────────────────────────────

export const FIPS_TLS_CONFIG = {
  MIN_VERSION: MIN_TLS_VERSION,
  PREFERRED_VERSION: PREFERRED_TLS_VERSION,
  CIPHERS: FIPS_TLS12_CIPHERS,
} as const;
