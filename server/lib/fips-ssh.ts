/**
 * FIPS 140-3 SSH Configuration
 *
 * Enforces FIPS-approved algorithms for all SSH connections per:
 *   - NIST SP 800-52 Rev. 2 (Transport Layer Security)
 *   - NIST SP 800-131A Rev. 2 (Transitioning Crypto Algorithms)
 *   - CNSS Policy 15 (SSH algorithm requirements)
 *
 * Approved algorithms:
 *   Key Exchange (KEX): ecdh-sha2-nistp256/384/521, diffie-hellman-group14/16/18-sha256/512
 *   Ciphers: aes128-gcm, aes256-gcm, aes128-ctr, aes256-ctr (GCM preferred)
 *   MACs: hmac-sha2-256, hmac-sha2-512 (SHA-2 family only)
 *   Host Key: ecdsa-sha2-nistp256/384/521, rsa-sha2-256/512
 *
 * Explicitly EXCLUDED (non-FIPS):
 *   - ChaCha20-Poly1305 (not NIST-approved)
 *   - SHA-1 based MACs/KEX (deprecated)
 *   - 3DES, Blowfish, RC4, CAST (weak/non-approved)
 *   - Curve25519/Ed25519 (not NIST curves)
 *   - diffie-hellman-group1/group-exchange with SHA-1
 */

import type { Algorithms } from "ssh2";

// ─── FIPS-Approved SSH Algorithms ──────────────────────────────────────────

const FIPS_KEX: string[] = [
  "ecdh-sha2-nistp521",
  "ecdh-sha2-nistp384",
  "ecdh-sha2-nistp256",
  "diffie-hellman-group18-sha512",
  "diffie-hellman-group16-sha512",
  "diffie-hellman-group14-sha256",
];

const FIPS_CIPHERS: string[] = [
  "aes256-gcm@openssh.com",
  "aes128-gcm@openssh.com",
  "aes256-ctr",
  "aes192-ctr",
  "aes128-ctr",
];

const FIPS_MACS: string[] = [
  "hmac-sha2-512-etm@openssh.com",
  "hmac-sha2-256-etm@openssh.com",
  "hmac-sha2-512",
  "hmac-sha2-256",
];

const FIPS_HOST_KEY: string[] = [
  "ecdsa-sha2-nistp521",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp256",
  "rsa-sha2-512",
  "rsa-sha2-256",
];

// ─── Exported Configuration ────────────────────────────────────────────────

export const FIPS_SSH_ALGORITHMS: Algorithms = {
  kex: FIPS_KEX as any,
  cipher: FIPS_CIPHERS as any,
  serverHostKey: FIPS_HOST_KEY as any,
  hmac: FIPS_MACS as any,
};

export function isFIPSApprovedCipher(cipher: string): boolean {
  return FIPS_CIPHERS.includes(cipher);
}

export function isFIPSApprovedKex(kex: string): boolean {
  return FIPS_KEX.includes(kex);
}

export function isFIPSApprovedMac(mac: string): boolean {
  return FIPS_MACS.includes(mac);
}

export function getFIPSSSHSummary() {
  return {
    kex: [...FIPS_KEX],
    ciphers: [...FIPS_CIPHERS],
    macs: [...FIPS_MACS],
    hostKeys: [...FIPS_HOST_KEY],
  };
}

export const FIPS_SSH_CONFIG = {
  KEX: FIPS_KEX,
  CIPHERS: FIPS_CIPHERS,
  MACS: FIPS_MACS,
  HOST_KEY: FIPS_HOST_KEY,
} as const;
