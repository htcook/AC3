import {
  getFIPSCrypto
} from "./chunk-5CE4P7TD.js";

// server/lib/credential-crypto.ts
import { createDecipheriv, createHash } from "crypto";
var CONTEXT_CLOUD_CREDENTIAL = "cloud-credential-at-rest";
var CONTEXT_LDAP_BIND = "ldap-bind-password-at-rest";
var CONTEXT_SERVER_CREDENTIAL = "server-credential-at-rest";
var CONTEXT_SSH_KEY = "ssh-private-key-at-rest";
var CONTEXT_GENERIC = "credential-at-rest";
function getLegacyEncryptionKey() {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error("JWT_SECRET is required for credential encryption");
  }
  return createHash("sha256").update(secret).digest();
}
function decryptLegacy(payload) {
  const key = getLegacyEncryptionKey();
  const iv = Buffer.from(payload.iv, "hex");
  const tag = Buffer.from(payload.tag, "hex");
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(payload.encryptedData, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}
function fromFIPSPayload(fp, context) {
  return { encryptedData: fp.ciphertext, iv: fp.iv, tag: fp.authTag, fips: true, context };
}
function toFIPSPayload(p) {
  return { ciphertext: p.encryptedData, iv: p.iv, authTag: p.tag, algorithm: "aes-256-gcm", keyDerivation: "hkdf-sha256" };
}
function encryptCredential(plaintext, context = CONTEXT_GENERIC) {
  const fips = getFIPSCrypto();
  const encrypted = fips.encrypt(plaintext, context);
  return fromFIPSPayload(encrypted, context);
}
function decryptCredential(payload) {
  if (payload.fips) {
    const fips = getFIPSCrypto();
    const fipsPayload = toFIPSPayload(payload);
    const context = payload.context ?? CONTEXT_GENERIC;
    return fips.decrypt(fipsPayload, context).toString("utf-8");
  }
  return decryptLegacy(payload);
}
function encryptCredentialObject(obj, context = CONTEXT_CLOUD_CREDENTIAL) {
  return encryptCredential(JSON.stringify(obj), context);
}
function decryptCredentialObject(payload) {
  return JSON.parse(decryptCredential(payload));
}
function encryptServerCredential(plaintext) {
  return encryptCredential(plaintext, CONTEXT_SERVER_CREDENTIAL);
}
function encryptSSHPrivateKey(privateKey) {
  return encryptCredential(privateKey, CONTEXT_SSH_KEY);
}
function encryptLDAPBindPassword(password) {
  return encryptCredential(password, CONTEXT_LDAP_BIND);
}
function encryptCloudCredential(obj) {
  return encryptCredentialObject(obj, CONTEXT_CLOUD_CREDENTIAL);
}
function maskCredential(value) {
  if (value.length <= 8) return "****";
  return `${value.slice(0, 4)}${"*".repeat(Math.min(value.length - 8, 20))}${value.slice(-4)}`;
}
function migrateLegacyPayload(legacy, context = CONTEXT_GENERIC) {
  const plaintext = decryptLegacy(legacy);
  return encryptCredential(plaintext, context);
}
var FIPS_CONTEXTS = {
  CLOUD_CREDENTIAL: CONTEXT_CLOUD_CREDENTIAL,
  LDAP_BIND: CONTEXT_LDAP_BIND,
  SERVER_CREDENTIAL: CONTEXT_SERVER_CREDENTIAL,
  SSH_KEY: CONTEXT_SSH_KEY,
  GENERIC: CONTEXT_GENERIC
};

export {
  encryptCredential,
  decryptCredential,
  encryptCredentialObject,
  decryptCredentialObject,
  encryptServerCredential,
  encryptSSHPrivateKey,
  encryptLDAPBindPassword,
  encryptCloudCredential,
  maskCredential,
  migrateLegacyPayload,
  FIPS_CONTEXTS
};
