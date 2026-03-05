/**
 * Certificate Pinning for Caldera and GoPhish Connections
 *
 * Implements TLS certificate pinning (HPKP-style) to prevent MITM attacks
 * on connections to internal security infrastructure. Pins are stored as
 * SHA-256 hashes of the Subject Public Key Info (SPKI) from the server
 * certificate.
 *
 * Pinning modes:
 *   - "enforce": Reject connections with non-matching pins (production)
 *   - "report": Log pin mismatches but allow connections (initial deployment)
 *   - "learn": Connect and record the pin for future enforcement
 *
 * References:
 *   - RFC 7469 (HTTP Public Key Pinning)
 *   - NIST SP 800-52 Rev. 2 (Certificate validation)
 *   - OWASP Certificate Pinning Cheat Sheet
 */

import tls from "tls";
import crypto from "crypto";
import https from "https";
import { FIPS_TLS_CONFIG } from "./fips-tls";

// ─── Types ─────────────────────────────────────────────────────────────

export type PinningMode = "enforce" | "report" | "learn";

export interface CertPin {
  /** SHA-256 hash of the SPKI (base64-encoded) */
  sha256: string;
  /** Human-readable label for the pin */
  label: string;
  /** When the pin was recorded */
  recordedAt: string;
  /** Expiry date (ISO 8601) — pins should be rotated */
  expiresAt?: string;
}

export interface PinConfig {
  /** Service name for logging */
  service: string;
  /** Hostname to pin */
  hostname: string;
  /** Port to pin */
  port: number;
  /** Pinning mode */
  mode: PinningMode;
  /** Accepted SPKI pins (SHA-256, base64) */
  pins: CertPin[];
  /** Backup pins for rotation (at least 1 backup recommended) */
  backupPins: CertPin[];
  /** Whether to allow self-signed certificates (GoPhish) */
  allowSelfSigned: boolean;
}

export interface PinValidationResult {
  service: string;
  hostname: string;
  valid: boolean;
  matchedPin?: string;
  actualPin: string;
  protocol: string;
  cipher: string;
  certSubject: string;
  certIssuer: string;
  certExpiry: string;
  error?: string;
}

// ─── Pin Storage ───────────────────────────────────────────────────────

/** In-memory pin store — loaded from env or learned at runtime */
const pinStore = new Map<string, PinConfig>();

/** Pin validation event log */
const pinEventLog: Array<{
  timestamp: string;
  service: string;
  result: "match" | "mismatch" | "error" | "learned";
  details: string;
}> = [];

// ─── Pin Computation ───────────────────────────────────────────────────

/**
 * Compute the SHA-256 SPKI pin from a TLS certificate.
 * This is the standard HPKP pin format (RFC 7469).
 */
export function computeSPKIPin(cert: tls.PeerCertificate): string {
  // The raw DER-encoded public key
  const pubkey = (cert as any).pubkey;
  if (pubkey && Buffer.isBuffer(pubkey)) {
    return crypto.createHash("sha256").update(pubkey).digest("base64");
  }

  // Fallback: hash the entire raw certificate DER
  const raw = (cert as any).raw;
  if (raw && Buffer.isBuffer(raw)) {
    return crypto.createHash("sha256").update(raw).digest("base64");
  }

  // Last resort: hash the fingerprint256 if available
  if (cert.fingerprint256) {
    return cert.fingerprint256;
  }

  throw new Error("Cannot compute SPKI pin: no public key or raw cert available");
}

// ─── Pin Configuration ─────────────────────────────────────────────────

/**
 * Register a service for certificate pinning.
 */
export function registerPinConfig(config: PinConfig): void {
  const key = `${config.hostname}:${config.port}`;
  pinStore.set(key, config);
  console.log(`[CertPin] Registered pin config for ${config.service} (${key}), mode: ${config.mode}, pins: ${config.pins.length}`);
}

/**
 * Get the pin configuration for a service.
 */
export function getPinConfig(hostname: string, port: number): PinConfig | undefined {
  return pinStore.get(`${hostname}:${port}`);
}

/**
 * Initialize certificate pinning from environment variables.
 * Format: CERT_PIN_{SERVICE}=sha256/base64hash1,sha256/base64hash2
 */
export function initCertPinning(): void {
  const calderaUrl = process.env.CALDERA_BASE_URL || "";
  const gophishUrl = process.env.GOPHISH_BASE_URL || "";

  // Parse Caldera URL
  if (calderaUrl) {
    try {
      const url = new URL(calderaUrl);
      const hostname = url.hostname;
      const port = parseInt(url.port) || (url.protocol === "https:" ? 443 : 8888);
      const envPins = process.env.CERT_PIN_CALDERA || "";

      registerPinConfig({
        service: "Caldera",
        hostname,
        port,
        mode: envPins ? "enforce" : "learn",
        pins: parsePinEnv(envPins, "Caldera"),
        backupPins: [],
        allowSelfSigned: false,
      });
    } catch (err: any) {
      console.log(`[CertPin] Cannot parse Caldera URL: ${err.message}`);
    }
  }

  // Parse GoPhish URL
  if (gophishUrl) {
    try {
      const url = new URL(gophishUrl);
      const hostname = url.hostname;
      const port = parseInt(url.port) || (url.protocol === "https:" ? 443 : 3333);
      const envPins = process.env.CERT_PIN_GOPHISH || "";

      registerPinConfig({
        service: "GoPhish",
        hostname,
        port,
        mode: envPins ? "enforce" : "learn",
        pins: parsePinEnv(envPins, "GoPhish"),
        backupPins: [],
        allowSelfSigned: true, // GoPhish uses self-signed certs
      });
    } catch (err: any) {
      console.log(`[CertPin] Cannot parse GoPhish URL: ${err.message}`);
    }
  }

  console.log(`[CertPin] Certificate pinning initialized for ${pinStore.size} service(s)`);
}

function parsePinEnv(envValue: string, label: string): CertPin[] {
  if (!envValue) return [];
  return envValue.split(",").map((pin, i) => ({
    sha256: pin.replace("sha256/", "").trim(),
    label: `${label} pin ${i + 1}`,
    recordedAt: new Date().toISOString(),
  }));
}

// ─── Pin Validation ────────────────────────────────────────────────────

/**
 * Validate a TLS connection against pinned certificates.
 * Returns the validation result with details.
 */
export async function validateCertPin(
  hostname: string,
  port: number
): Promise<PinValidationResult> {
  const config = getPinConfig(hostname, port);
  const service = config?.service || "unknown";

  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        minVersion: FIPS_TLS_CONFIG.MIN_VERSION,
        ciphers: FIPS_TLS_CONFIG.CIPHERS,
        rejectUnauthorized: config?.allowSelfSigned ? false : true,
        timeout: 10000,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const cipher = socket.getCipher();
          const protocol = socket.getProtocol() || "unknown";

          let actualPin: string;
          try {
            actualPin = computeSPKIPin(cert);
          } catch {
            actualPin = cert.fingerprint256 || "unknown";
          }

          const certSubject = cert.subject
            ? Object.entries(cert.subject).map(([k, v]) => `${k}=${v}`).join(", ")
            : "unknown";
          const certIssuer = cert.issuer
            ? Object.entries(cert.issuer).map(([k, v]) => `${k}=${v}`).join(", ")
            : "unknown";
          const certExpiry = cert.valid_to || "unknown";

          // Check pin match
          let valid = false;
          let matchedPin: string | undefined;

          if (config && config.pins.length > 0) {
            const allPins = [...config.pins, ...config.backupPins];
            const match = allPins.find(p => p.sha256 === actualPin);
            if (match) {
              valid = true;
              matchedPin = match.label;
              logPinEvent(service, "match", `Pin matched: ${match.label}`);
            } else {
              valid = false;
              logPinEvent(service, "mismatch",
                `Expected: ${config.pins.map(p => p.sha256.slice(0, 12) + "...").join(", ")} | ` +
                `Got: ${actualPin.slice(0, 12)}...`
              );

              if (config.mode === "report") {
                console.warn(`[CertPin] ⚠ PIN MISMATCH (report mode) for ${service}: connection allowed`);
                valid = true; // Allow in report mode
              } else if (config.mode === "enforce") {
                console.error(`[CertPin] ✗ PIN MISMATCH (enforce mode) for ${service}: connection BLOCKED`);
              }
            }
          } else if (config && config.mode === "learn") {
            // Learning mode: record the pin
            config.pins.push({
              sha256: actualPin,
              label: `${service} learned pin`,
              recordedAt: new Date().toISOString(),
            });
            valid = true;
            matchedPin = "learned";
            logPinEvent(service, "learned", `Learned pin: ${actualPin.slice(0, 16)}...`);
            console.log(`[CertPin] 📌 Learned pin for ${service}: sha256/${actualPin}`);
          } else {
            // No config — pass through
            valid = true;
          }

          socket.destroy();
          resolve({
            service,
            hostname,
            valid,
            matchedPin,
            actualPin,
            protocol,
            cipher: cipher.name,
            certSubject,
            certIssuer,
            certExpiry,
          });
        } catch (err: any) {
          socket.destroy();
          resolve({
            service,
            hostname,
            valid: false,
            actualPin: "error",
            protocol: "error",
            cipher: "error",
            certSubject: "error",
            certIssuer: "error",
            certExpiry: "error",
            error: err.message,
          });
        }
      }
    );

    socket.on("error", (err) => {
      logPinEvent(service, "error", err.message);
      resolve({
        service,
        hostname,
        valid: false,
        actualPin: "error",
        protocol: "none",
        cipher: "none",
        certSubject: "none",
        certIssuer: "none",
        certExpiry: "none",
        error: err.message,
      });
    });

    socket.setTimeout(10000, () => {
      socket.destroy();
      resolve({
        service,
        hostname,
        valid: false,
        actualPin: "timeout",
        protocol: "none",
        cipher: "none",
        certSubject: "none",
        certIssuer: "none",
        certExpiry: "none",
        error: "Connection timeout",
      });
    });
  });
}

// ─── Create Pinned HTTPS Agent ─────────────────────────────────────────

/**
 * Create an HTTPS agent that validates certificate pins on each connection.
 * Use this instead of the standard FIPS agent for pinned services.
 */
export function createPinnedHttpsAgent(
  hostname: string,
  port: number,
  options: https.AgentOptions = {}
): https.Agent {
  const config = getPinConfig(hostname, port);

  return new https.Agent({
    minVersion: FIPS_TLS_CONFIG.MIN_VERSION,
    ciphers: FIPS_TLS_CONFIG.CIPHERS,
    rejectUnauthorized: config?.allowSelfSigned ? false : true,
    keepAlive: true,
    honorCipherOrder: true,
    ...options,
    // checkServerIdentity is called for each TLS handshake
    checkServerIdentity: (servername: string, cert: tls.PeerCertificate) => {
      if (!config || config.pins.length === 0) {
        // No pins configured — fall back to standard validation
        return tls.checkServerIdentity(servername, cert);
      }

      let actualPin: string;
      try {
        actualPin = computeSPKIPin(cert);
      } catch {
        actualPin = cert.fingerprint256 || "";
      }

      const allPins = [...config.pins, ...config.backupPins];
      const match = allPins.find(p => p.sha256 === actualPin);

      if (match) {
        logPinEvent(config.service, "match", `Inline pin match: ${match.label}`);
        // Pin matched — proceed with standard identity check
        if (config.allowSelfSigned) return undefined; // Skip hostname check for self-signed
        return tls.checkServerIdentity(servername, cert);
      }

      // Pin mismatch
      if (config.mode === "enforce") {
        logPinEvent(config.service, "mismatch", `BLOCKED: pin mismatch for ${servername}`);
        return new Error(
          `[CertPin] Certificate pin mismatch for ${config.service} (${servername}). ` +
          `Expected: ${config.pins.map(p => p.sha256.slice(0, 12)).join(", ")} | ` +
          `Got: ${actualPin.slice(0, 12)}`
        );
      }

      // Report mode — log but allow
      logPinEvent(config.service, "mismatch", `REPORTED: pin mismatch for ${servername} (allowed)`);
      console.warn(`[CertPin] ⚠ Pin mismatch for ${config.service} — report mode, allowing connection`);
      if (config.allowSelfSigned) return undefined;
      return tls.checkServerIdentity(servername, cert);
    },
  });
}

// ─── Event Log ─────────────────────────────────────────────────────────

function logPinEvent(
  service: string,
  result: "match" | "mismatch" | "error" | "learned",
  details: string
): void {
  pinEventLog.push({
    timestamp: new Date().toISOString(),
    service,
    result,
    details,
  });
  // Keep last 1000 events
  if (pinEventLog.length > 1000) {
    pinEventLog.splice(0, pinEventLog.length - 1000);
  }
}

/**
 * Get the pin validation event log.
 */
export function getPinEventLog(limit = 50) {
  return pinEventLog.slice(-limit);
}

/**
 * Get all registered pin configurations (sanitized for API response).
 */
export function getAllPinConfigs(): Array<{
  service: string;
  hostname: string;
  port: number;
  mode: PinningMode;
  pinCount: number;
  backupPinCount: number;
  allowSelfSigned: boolean;
  pins: Array<{ label: string; sha256Prefix: string; recordedAt: string }>;
}> {
  return Array.from(pinStore.values()).map(config => ({
    service: config.service,
    hostname: config.hostname,
    port: config.port,
    mode: config.mode,
    pinCount: config.pins.length,
    backupPinCount: config.backupPins.length,
    allowSelfSigned: config.allowSelfSigned,
    pins: config.pins.map(p => ({
      label: p.label,
      sha256Prefix: p.sha256.slice(0, 16) + "...",
      recordedAt: p.recordedAt,
    })),
  }));
}
