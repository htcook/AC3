/**
 * Credential Encryption/Decryption Helpers
 * Uses AES-256-GCM for at-rest encryption of cloud provider credentials
 * and LDAP bind passwords.
 */
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 16;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;

/**
 * Derive a 256-bit encryption key from the JWT_SECRET environment variable.
 * Uses SHA-256 to normalize any-length secret into a fixed 32-byte key.
 */
function getEncryptionKey(): Buffer {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error("JWT_SECRET is required for credential encryption");
  }
  const { createHash } = require("crypto");
  return createHash("sha256").update(secret).digest();
}

export interface EncryptedPayload {
  encryptedData: string;   // hex-encoded ciphertext
  iv: string;              // hex-encoded IV
  tag: string;             // hex-encoded auth tag
}

/**
 * Encrypt a plaintext credential string using AES-256-GCM.
 * Returns hex-encoded ciphertext, IV, and authentication tag.
 */
export function encryptCredential(plaintext: string): EncryptedPayload {
  const key = getEncryptionKey();
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(plaintext, "utf8", "hex");
  encrypted += cipher.final("hex");
  const tag = cipher.getAuthTag();

  return {
    encryptedData: encrypted,
    iv: iv.toString("hex"),
    tag: tag.toString("hex"),
  };
}

/**
 * Decrypt an AES-256-GCM encrypted credential.
 * Returns the original plaintext string.
 */
export function decryptCredential(payload: EncryptedPayload): string {
  const key = getEncryptionKey();
  const iv = Buffer.from(payload.iv, "hex");
  const tag = Buffer.from(payload.tag, "hex");
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(payload.encryptedData, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

/**
 * Encrypt a JSON object (e.g., full credential set) and return the encrypted payload.
 */
export function encryptCredentialObject(obj: Record<string, any>): EncryptedPayload {
  return encryptCredential(JSON.stringify(obj));
}

/**
 * Decrypt an encrypted payload back to a JSON object.
 */
export function decryptCredentialObject<T = Record<string, any>>(payload: EncryptedPayload): T {
  return JSON.parse(decryptCredential(payload));
}

/**
 * Mask a credential string for display (show first 4 and last 4 chars).
 */
export function maskCredential(value: string): string {
  if (value.length <= 8) return "****";
  return `${value.slice(0, 4)}${"*".repeat(Math.min(value.length - 8, 20))}${value.slice(-4)}`;
}
