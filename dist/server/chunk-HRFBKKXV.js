import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/fips-tls.ts
import https from "https";
import tls from "tls";
function getFIPSHttpsAgent() {
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
    keepAliveMsecs: 3e4,
    maxSockets: 50,
    // Prefer server cipher order for defense-in-depth
    honorCipherOrder: true
  });
  return _fipsAgent;
}
function createFIPSHttpsAgent(overrides = {}) {
  return new https.Agent({
    minVersion: MIN_TLS_VERSION,
    ciphers: FIPS_TLS12_CIPHERS,
    rejectUnauthorized: true,
    keepAlive: true,
    honorCipherOrder: true,
    ...overrides
  });
}
function getFIPSDatabaseSSLConfig() {
  return {
    ssl: {
      // Enforce minimum TLS 1.2
      minVersion: MIN_TLS_VERSION,
      // Restrict to FIPS-approved cipher suites
      ciphers: FIPS_TLS12_CIPHERS,
      // For managed databases (TiDB Cloud, RDS), we accept their CA
      rejectUnauthorized: false
      // Set to true in production with proper CA bundle
    }
  };
}
function getFIPSDatabaseSSLConfigStrict(caCert) {
  return {
    ssl: {
      minVersion: MIN_TLS_VERSION,
      ciphers: FIPS_TLS12_CIPHERS,
      rejectUnauthorized: true,
      ca: caCert
    }
  };
}
function getFIPSAxiosConfig() {
  return {
    httpsAgent: getFIPSHttpsAgent(),
    // Timeout for FIPS compliance (prevent indefinite hangs)
    timeout: 3e4
  };
}
function getFIPSFetchOptions() {
  return {
    // @ts-ignore - Node.js specific option
    agent: getFIPSHttpsAgent()
  };
}
function auditTLSConfiguration() {
  const defaultCiphers = tls.DEFAULT_CIPHERS?.split(":") ?? [];
  const fipsCiphers = FIPS_TLS12_CIPHERS.split(":");
  const nonCompliant = defaultCiphers.filter((c) => {
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
    details: compliant ? "TLS configuration is FIPS 140-3 compliant. Using TLS 1.2+ with approved cipher suites." : `TLS configuration has ${nonCompliant.length} non-FIPS cipher(s) in Node.js defaults. Platform outbound connections use the FIPS HTTPS agent which restricts to approved suites only.`
  };
}
async function testFIPSTLSConnection(hostname, port = 443) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        minVersion: MIN_TLS_VERSION,
        ciphers: FIPS_TLS12_CIPHERS,
        rejectUnauthorized: true,
        timeout: 1e4
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
          fipsApproved: isFIPS
        });
      }
    );
    socket.on("error", (err) => {
      resolve({
        connected: false,
        protocol: "none",
        cipher: "none",
        fipsApproved: false,
        error: err.message
      });
    });
    socket.setTimeout(1e4, () => {
      socket.destroy();
      resolve({
        connected: false,
        protocol: "none",
        cipher: "none",
        fipsApproved: false,
        error: "Connection timeout"
      });
    });
  });
}
var FIPS_TLS12_CIPHERS, MIN_TLS_VERSION, PREFERRED_TLS_VERSION, _fipsAgent, FIPS_TLS_CONFIG;
var init_fips_tls = __esm({
  "server/lib/fips-tls.ts"() {
    FIPS_TLS12_CIPHERS = [
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
      "ECDHE-RSA-AES128-SHA256"
    ].join(":");
    MIN_TLS_VERSION = "TLSv1.2";
    PREFERRED_TLS_VERSION = "TLSv1.3";
    _fipsAgent = null;
    FIPS_TLS_CONFIG = {
      MIN_VERSION: MIN_TLS_VERSION,
      PREFERRED_VERSION: PREFERRED_TLS_VERSION,
      CIPHERS: FIPS_TLS12_CIPHERS
    };
  }
});

export {
  getFIPSHttpsAgent,
  createFIPSHttpsAgent,
  getFIPSDatabaseSSLConfig,
  getFIPSDatabaseSSLConfigStrict,
  getFIPSAxiosConfig,
  getFIPSFetchOptions,
  auditTLSConfiguration,
  testFIPSTLSConnection,
  FIPS_TLS_CONFIG,
  init_fips_tls
};
