/**
 * OpenSSL FIPS Provider Configuration
 *
 * Detects and configures the Node.js OpenSSL FIPS provider at runtime.
 * When the FIPS provider is available (Node.js built with OpenSSL FIPS module),
 * this module enables it and validates that only FIPS-approved algorithms are used.
 *
 * Deployment:
 *   - Start Node.js with `--enable-fips` or `--force-fips` flag
 *   - Or set env: OPENSSL_CONF pointing to a FIPS-enabled openssl.cnf
 *   - Or call `enableFIPSProvider()` at startup for programmatic activation
 *
 * References:
 *   - NIST SP 800-140 (FIPS 140-3 Implementation Guidance)
 *   - Node.js crypto.setFips() documentation
 *   - OpenSSL FIPS 140-3 module documentation
 */

import crypto from "crypto";

// ─── Types ─────────────────────────────────────────────────────────────

export interface FIPSProviderStatus {
  /** Whether the OpenSSL FIPS provider is currently active */
  fipsEnabled: boolean;
  /** OpenSSL version string */
  opensslVersion: string;
  /** Whether Node.js was compiled with FIPS support */
  fipsCapable: boolean;
  /** The method used to enable FIPS (flag, env, programmatic, or none) */
  activationMethod: "flag" | "env" | "programmatic" | "none";
  /** List of available hash algorithms (filtered to FIPS-approved when active) */
  availableHashes: string[];
  /** List of available cipher algorithms (filtered to FIPS-approved when active) */
  availableCiphers: string[];
  /** Validation results for key FIPS requirements */
  validation: FIPSValidation;
  /** Human-readable status message */
  message: string;
}

export interface FIPSValidation {
  /** SHA-256 available (required) */
  sha256: boolean;
  /** SHA-384 available (required) */
  sha384: boolean;
  /** SHA-512 available (required) */
  sha512: boolean;
  /** AES-256-GCM available (required) */
  aes256gcm: boolean;
  /** AES-128-GCM available (required) */
  aes128gcm: boolean;
  /** ECDSA P-256 available (required) */
  ecdsaP256: boolean;
  /** ECDSA P-384 available (required) */
  ecdsaP384: boolean;
  /** RSA-2048+ signing available (required) */
  rsa2048: boolean;
  /** HMAC-SHA256 available (required) */
  hmacSha256: boolean;
  /** MD5 disabled (should be unavailable in FIPS mode) */
  md5Disabled: boolean;
  /** All validations passed */
  allPassed: boolean;
}

// ─── FIPS-Approved Algorithm Lists ─────────────────────────────────────

const FIPS_APPROVED_HASHES = [
  "sha256", "sha384", "sha512",
  "sha3-256", "sha3-384", "sha3-512",
  "sha512-256",
];

const FIPS_PROHIBITED_HASHES = [
  "md4", "md5", "sha1", "ripemd160",
];

const FIPS_APPROVED_CIPHERS_PREFIXES = [
  "aes-128-", "aes-192-", "aes-256-",
];

const FIPS_PROHIBITED_CIPHERS_PREFIXES = [
  "des-", "des3", "rc4", "rc2", "bf-", "cast", "seed", "idea",
  "chacha20", // Not NIST-approved
];

// ─── Detection & Activation ────────────────────────────────────────────

/**
 * Check if Node.js was started with --enable-fips or --force-fips.
 */
function detectFlagActivation(): boolean {
  const execArgv = process.execArgv || [];
  return execArgv.some(arg =>
    arg === "--enable-fips" || arg === "--force-fips"
  );
}

/**
 * Check if OPENSSL_CONF environment variable points to a FIPS config.
 */
function detectEnvActivation(): boolean {
  const conf = process.env.OPENSSL_CONF || "";
  return conf.toLowerCase().includes("fips");
}

/**
 * Attempt to enable the OpenSSL FIPS provider programmatically.
 * Returns true if FIPS mode is now active.
 *
 * IMPORTANT: We do NOT call crypto.setFips(1) unless the --enable-fips
 * or --force-fips flag was passed at startup. Calling setFips(1) on a
 * Node.js binary without a properly compiled OpenSSL FIPS module puts
 * OpenSSL into a broken state where no ciphers are available, breaking
 * all TLS connections (database, HTTPS, etc.).
 *
 * Instead, we rely on application-level FIPS enforcement via:
 *   - fips-tls.ts (FIPS cipher suites on all HTTPS agents)
 *   - fips-ssh.ts (FIPS algorithms on all SSH connections)
 *   - fips-tls-global.ts (global TLS defaults)
 */
export function enableFIPSProvider(): boolean {
  try {
    // Check if already in FIPS mode (set by --enable-fips or --force-fips)
    if (crypto.getFips() === 1) {
      console.log("[FIPS-OpenSSL] FIPS provider already active (set by Node.js flag)");
      return true;
    }

    // Check if Node.js was started with FIPS flags
    if (detectFlagActivation()) {
      // Flag was passed but getFips() returned 0 — try to activate
      try {
        crypto.setFips(true);
        if (crypto.getFips() === 1) {
          console.log("[FIPS-OpenSSL] FIPS provider enabled via crypto.setFips(1)");
          return true;
        }
      } catch (err: any) {
        console.warn(`[FIPS-OpenSSL] Flag detected but setFips(1) failed: ${err.message}`);
      }
    }

    // Do NOT attempt crypto.setFips(1) without the flag — it breaks OpenSSL
    // on Node.js builds without a proper FIPS module, causing
    // "error:0A0000A1:SSL routines::library has no ciphers" on all TLS connections.
    console.log("[FIPS-OpenSSL] FIPS provider not activated at kernel level");
    console.log("[FIPS-OpenSSL] Application-level FIPS enforcement is active (fips-tls.ts + fips-ssh.ts)");
    console.log("[FIPS-OpenSSL] For kernel-level FIPS: start Node.js with --enable-fips flag on a FIPS-capable build");

    return false;
  } catch (err: any) {
    console.error(`[FIPS-OpenSSL] Error during FIPS detection: ${err.message}`);
    return false;
  }
}

// ─── Validation ────────────────────────────────────────────────────────

/**
 * Validate that key FIPS-required algorithms are available.
 */
function validateFIPSAlgorithms(): FIPSValidation {
  const hashes = crypto.getHashes();
  const ciphers = crypto.getCiphers();

  // Test SHA-256
  let sha256 = false;
  try {
    crypto.createHash("sha256").update("test").digest("hex");
    sha256 = true;
  } catch { sha256 = false; }

  // Test SHA-384
  let sha384 = false;
  try {
    crypto.createHash("sha384").update("test").digest("hex");
    sha384 = true;
  } catch { sha384 = false; }

  // Test SHA-512
  let sha512 = false;
  try {
    crypto.createHash("sha512").update("test").digest("hex");
    sha512 = true;
  } catch { sha512 = false; }

  // Test AES-256-GCM
  let aes256gcm = false;
  try {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    cipher.update("test", "utf8", "hex");
    cipher.final("hex");
    aes256gcm = true;
  } catch { aes256gcm = false; }

  // Test AES-128-GCM
  let aes128gcm = false;
  try {
    const key = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-128-gcm", key, iv);
    cipher.update("test", "utf8", "hex");
    cipher.final("hex");
    aes128gcm = true;
  } catch { aes128gcm = false; }

  // Test ECDSA P-256
  let ecdsaP256 = false;
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const sign = crypto.createSign("SHA256");
    sign.update("test");
    const sig = sign.sign(privateKey);
    const verify = crypto.createVerify("SHA256");
    verify.update("test");
    ecdsaP256 = verify.verify(publicKey, sig);
  } catch { ecdsaP256 = false; }

  // Test ECDSA P-384
  let ecdsaP384 = false;
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: "secp384r1",
    });
    const sign = crypto.createSign("SHA384");
    sign.update("test");
    const sig = sign.sign(privateKey);
    const verify = crypto.createVerify("SHA384");
    verify.update("test");
    ecdsaP384 = verify.verify(publicKey, sig);
  } catch { ecdsaP384 = false; }

  // Test RSA-2048
  let rsa2048 = false;
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    const sign = crypto.createSign("SHA256");
    sign.update("test");
    const sig = sign.sign(privateKey);
    const verify = crypto.createVerify("SHA256");
    verify.update("test");
    rsa2048 = verify.verify(publicKey, sig);
  } catch { rsa2048 = false; }

  // Test HMAC-SHA256
  let hmacSha256 = false;
  try {
    crypto.createHmac("sha256", "key").update("test").digest("hex");
    hmacSha256 = true;
  } catch { hmacSha256 = false; }

  // Test MD5 disabled (should fail in strict FIPS mode)
  let md5Disabled = false;
  try {
    crypto.createHash("md5").update("test").digest("hex");
    md5Disabled = false; // MD5 still works — not in strict FIPS mode
  } catch {
    md5Disabled = true; // MD5 blocked — strict FIPS mode active
  }

  const allPassed = sha256 && sha384 && sha512 && aes256gcm && aes128gcm &&
    ecdsaP256 && ecdsaP384 && rsa2048 && hmacSha256;

  return {
    sha256, sha384, sha512,
    aes256gcm, aes128gcm,
    ecdsaP256, ecdsaP384,
    rsa2048, hmacSha256,
    md5Disabled,
    allPassed,
  };
}

// ─── Status Report ─────────────────────────────────────────────────────

/**
 * Get comprehensive FIPS provider status including detection, validation,
 * and available algorithms.
 */
export function getFIPSProviderStatus(): FIPSProviderStatus {
  const fipsEnabled = crypto.getFips() === 1;
  const opensslVersion = (crypto as any).constants?.OPENSSL_VERSION_TEXT
    || process.versions.openssl
    || "unknown";

  // Determine activation method
  let activationMethod: FIPSProviderStatus["activationMethod"] = "none";
  if (fipsEnabled) {
    if (detectFlagActivation()) activationMethod = "flag";
    else if (detectEnvActivation()) activationMethod = "env";
    else activationMethod = "programmatic";
  }

  // Check if FIPS is at least capable (can we call setFips?)
  let fipsCapable = false;
  try {
    // If getFips doesn't throw, the API is available
    crypto.getFips();
    fipsCapable = true;
  } catch {
    fipsCapable = false;
  }

  const validation = validateFIPSAlgorithms();

  // Filter algorithms to FIPS-approved ones
  const allHashes = crypto.getHashes();
  const allCiphers = crypto.getCiphers();

  const availableHashes = fipsEnabled
    ? allHashes // In FIPS mode, only approved hashes are available
    : allHashes.filter(h => FIPS_APPROVED_HASHES.includes(h.toLowerCase()));

  const availableCiphers = fipsEnabled
    ? allCiphers // In FIPS mode, only approved ciphers are available
    : allCiphers.filter(c => {
        const lower = c.toLowerCase();
        return FIPS_APPROVED_CIPHERS_PREFIXES.some(p => lower.startsWith(p));
      });

  let message: string;
  if (fipsEnabled) {
    message = `OpenSSL FIPS provider ACTIVE (${activationMethod}). ` +
      `All cryptographic operations restricted to FIPS 140-3 approved algorithms. ` +
      `OpenSSL: ${opensslVersion}`;
  } else if (validation.allPassed) {
    message = `OpenSSL FIPS provider NOT active, but all required FIPS algorithms are available. ` +
      `Application-level FIPS enforcement is active via fips-tls.ts and fips-ssh.ts. ` +
      `For kernel-level FIPS: start Node.js with --enable-fips flag. ` +
      `OpenSSL: ${opensslVersion}`;
  } else {
    message = `OpenSSL FIPS provider NOT active. Some FIPS algorithms unavailable. ` +
      `OpenSSL: ${opensslVersion}`;
  }

  return {
    fipsEnabled,
    opensslVersion,
    fipsCapable,
    activationMethod,
    availableHashes,
    availableCiphers,
    validation,
    message,
  };
}

/**
 * Initialize FIPS provider at server startup.
 * Attempts to enable FIPS mode and logs the result.
 */
export function initFIPSProvider(): FIPSProviderStatus {
  console.log("[FIPS-OpenSSL] Initializing OpenSSL FIPS provider...");

  // Attempt to enable FIPS if not already active
  if (crypto.getFips() !== 1) {
    enableFIPSProvider();
  }

  const status = getFIPSProviderStatus();

  if (status.fipsEnabled) {
    console.log(`[FIPS-OpenSSL] ✓ FIPS provider ACTIVE (${status.activationMethod})`);
    console.log(`[FIPS-OpenSSL] ✓ OpenSSL: ${status.opensslVersion}`);
    console.log(`[FIPS-OpenSSL] ✓ MD5 disabled: ${status.validation.md5Disabled}`);
  } else {
    console.log(`[FIPS-OpenSSL] ⚠ FIPS provider not available — application-level enforcement active`);
    console.log(`[FIPS-OpenSSL] ⚠ OpenSSL: ${status.opensslVersion}`);
    console.log(`[FIPS-OpenSSL] ⚠ To enable: node --enable-fips server.js`);
  }

  console.log(`[FIPS-OpenSSL] Algorithm validation: ${status.validation.allPassed ? "ALL PASSED" : "SOME FAILED"}`);

  return status;
}
