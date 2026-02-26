/**
 * Credential Encryption/Decryption Helpers - FIPS 140-3 Compliant
 *
 * Uses the platform FIPSCryptoService (AES-256-GCM + HKDF-SHA256) for
 * at-rest encryption of:
 *   - Cloud provider credentials
 *   - LDAP bind passwords
 *   - Server credentials (passwords, API keys)
 *   - SSH private keys
 *
 * Key derivation: HKDF-SHA256 from master key, with per-context
 * sub-keys so that each credential category uses a distinct encryption key.
 *
 * Migration: A backwards-compatible decryptLegacy path reads old
 * hex-encoded ciphertext. New encryptions always use FIPS.
 */

import { getFIPSCrypto, type EncryptedPayload as FIPSEncryptedPayload } from "./fips-crypto";
import { createDecipheriv, createHash } from "crypto";

// --- Types ---

export interface EncryptedPayload {
  encryptedData: string;
  iv: string;
  tag: string;
  /** Marks this as FIPS-encrypted (absent in legacy payloads) */
  fips?: true;
  /** HKDF context used for key derivation */
  context?: string;
}

// --- FIPS Encryption Context Constants ---

const CONTEXT_CLOUD_CREDENTIAL = "cloud-credential-at-rest";
const CONTEXT_LDAP_BIND = "ldap-bind-password-at-rest";
const CONTEXT_SERVER_CREDENTIAL = "server-credential-at-rest";
const CONTEXT_SSH_KEY = "ssh-private-key-at-rest";
const CONTEXT_GENERIC = "credential-at-rest";

// --- Legacy Decryption (for migration) ---

function getLegacyEncryptionKey(): Buffer {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error("JWT_SECRET is required for credential encryption");
  }
  return createHash("sha256").update(secret).digest();
}

function decryptLegacy(payload: EncryptedPayload): string {
  const key = getLegacyEncryptionKey();
  const iv = Buffer.from(payload.iv, "hex");
  const tag = Buffer.from(payload.tag, "hex");
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(payload.encryptedData, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// --- FIPS Encryption Helpers ---

function fromFIPSPayload(fp: FIPSEncryptedPayload, context: string): EncryptedPayload {
  return { encryptedData: fp.ciphertext, iv: fp.iv, tag: fp.authTag, fips: true, context };
}

function toFIPSPayload(p: EncryptedPayload): FIPSEncryptedPayload {
  return { ciphertext: p.encryptedData, iv: p.iv, authTag: p.tag, algorithm: "aes-256-gcm", keyDerivation: "hkdf-sha256" };
}

// --- Public API ---

/**
 * Encrypt a plaintext credential using FIPS-approved AES-256-GCM + HKDF-SHA256.
 */
export function encryptCredential(plaintext: string, context: string = CONTEXT_GENERIC): EncryptedPayload {
  const fips = getFIPSCrypto();
  const encrypted = fips.encrypt(plaintext, context);
  return fromFIPSPayload(encrypted, context);
}

/**
 * Decrypt a credential. Automatically detects FIPS vs legacy format.
 */
export function decryptCredential(payload: EncryptedPayload): string {
  if (payload.fips) {
    const fips = getFIPSCrypto();
    const fipsPayload = toFIPSPayload(payload);
    const context = payload.context ?? CONTEXT_GENERIC;
    return fips.decrypt(fipsPayload, context).toString("utf-8");
  }
  return decryptLegacy(payload);
}

/**
 * Encrypt a JSON object and return the encrypted payload.
 */
export function encryptCredentialObject(obj: Record<string, any>, context: string = CONTEXT_CLOUD_CREDENTIAL): EncryptedPayload {
  return encryptCredential(JSON.stringify(obj), context);
}

/**
 * Decrypt an encrypted payload back to a JSON object.
 */
export function decryptCredentialObject<T = Record<string, any>>(payload: EncryptedPayload): T {
  return JSON.parse(decryptCredential(payload));
}

// --- Context-Specific Helpers ---

/** Encrypt a server credential (password or API key) for at-rest storage. */
export function encryptServerCredential(plaintext: string): EncryptedPayload {
  return encryptCredential(plaintext, CONTEXT_SERVER_CREDENTIAL);
}

/** Encrypt an SSH private key for at-rest storage. */
export function encryptSSHPrivateKey(privateKey: string): EncryptedPayload {
  return encryptCredential(privateKey, CONTEXT_SSH_KEY);
}

/** Encrypt an LDAP bind password for at-rest storage. */
export function encryptLDAPBindPassword(password: string): EncryptedPayload {
  return encryptCredential(password, CONTEXT_LDAP_BIND);
}

/** Encrypt cloud provider credentials for at-rest storage. */
export function encryptCloudCredential(obj: Record<string, any>): EncryptedPayload {
  return encryptCredentialObject(obj, CONTEXT_CLOUD_CREDENTIAL);
}

// --- Utility ---

/**
 * Mask a credential string for display (show first 4 and last 4 chars).
 */
export function maskCredential(value: string): string {
  if (value.length <= 8) return "****";
  return `${value.slice(0, 4)}${"*".repeat(Math.min(value.length - 8, 20))}${value.slice(-4)}`;
}

/**
 * Re-encrypt a legacy payload with FIPS crypto.
 */
export function migrateLegacyPayload(legacy: EncryptedPayload, context: string = CONTEXT_GENERIC): EncryptedPayload {
  const plaintext = decryptLegacy(legacy);
  return encryptCredential(plaintext, context);
}

export const FIPS_CONTEXTS = {
  CLOUD_CREDENTIAL: CONTEXT_CLOUD_CREDENTIAL,
  LDAP_BIND: CONTEXT_LDAP_BIND,
  SERVER_CREDENTIAL: CONTEXT_SERVER_CREDENTIAL,
  SSH_KEY: CONTEXT_SSH_KEY,
  GENERIC: CONTEXT_GENERIC,
} as const;
