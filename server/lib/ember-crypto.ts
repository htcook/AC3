/**
 * Ember C2 Traffic Encryption Module
 * 
 * Implements AES-256-GCM authenticated encryption for all Ember agent
 * communications. Features:
 * 
 * 1. ECDH Key Exchange — Initial session establishment using P-256 curve
 * 2. Per-Agent Session Keys — Each agent gets a unique AES-256 key derived
 *    from the ECDH shared secret via HKDF
 * 3. Key Rotation — Automatic re-keying on schedule or on-demand with
 *    seamless transition (old key valid during grace period)
 * 4. Message Authentication — GCM mode provides both confidentiality and
 *    integrity with 128-bit authentication tags
 * 5. Replay Protection — Monotonic sequence numbers prevent replay attacks
 * 6. Forward Secrecy — Ephemeral ECDH keys ensure past sessions can't be
 *    decrypted if long-term keys are compromised
 */

import crypto from "crypto";

// ── Constants ──────────────────────────────────────────────────────────────

const AES_KEY_LENGTH = 32; // 256 bits
const GCM_IV_LENGTH = 12;  // 96 bits (NIST recommended for GCM)
const GCM_TAG_LENGTH = 16; // 128 bits
const ECDH_CURVE = "prime256v1"; // P-256 / secp256r1
const HKDF_HASH = "sha384";
const HKDF_INFO = Buffer.from("ember-c2-session-v1");
const KEY_ROTATION_INTERVAL_MS = 3600_000; // 1 hour default
const KEY_GRACE_PERIOD_MS = 300_000; // 5 minutes — old key still valid after rotation
const MAX_SEQUENCE_GAP = 1000; // Max allowed gap in sequence numbers

// ── Types ──────────────────────────────────────────────────────────────────

export interface EmberKeyPair {
  /** ECDH public key (base64-encoded, uncompressed point) */
  publicKey: string;
  /** ECDH private key (base64-encoded) */
  privateKey: string;
  /** When this key pair was generated */
  createdAt: number;
}

export interface EmberSessionKey {
  /** Unique key identifier */
  keyId: string;
  /** AES-256 key (Buffer) */
  key: Buffer;
  /** When this key was derived */
  createdAt: number;
  /** When this key expires (after which only grace period reads are allowed) */
  expiresAt: number;
  /** Monotonic sequence counter for this key */
  sequenceCounter: number;
  /** Highest sequence number received (for replay protection) */
  highestSeenSequence: number;
  /** Set of recently seen sequence numbers (sliding window for replay detection) */
  recentSequences: Set<number>;
}

export interface EmberEncryptedMessage {
  /** Key ID used for encryption */
  kid: string;
  /** Base64-encoded IV (12 bytes) */
  iv: string;
  /** Base64-encoded ciphertext */
  ct: string;
  /** Base64-encoded GCM authentication tag (16 bytes) */
  tag: string;
  /** Monotonic sequence number */
  seq: number;
  /** Timestamp of encryption */
  ts: number;
}

export interface EmberKeyExchangeRequest {
  /** Agent's ephemeral ECDH public key (base64) */
  agentPublicKey: string;
  /** Agent ID for session binding */
  agentId: string;
  /** Registration token for initial auth */
  registrationToken?: string;
}

export interface EmberKeyExchangeResponse {
  /** Server's ephemeral ECDH public key (base64) */
  serverPublicKey: string;
  /** Key ID for this session */
  keyId: string;
  /** Key rotation interval in ms */
  rotationIntervalMs: number;
  /** Server timestamp for clock sync */
  serverTimestamp: number;
}

export interface EmberKeyRotationRequest {
  /** Current key ID being rotated from */
  currentKeyId: string;
  /** Agent's new ephemeral ECDH public key (base64) */
  newAgentPublicKey: string;
  /** Sequence number at time of rotation request */
  rotationSequence: number;
}

export interface EmberKeyRotationResponse {
  /** New key ID */
  newKeyId: string;
  /** Server's new ephemeral ECDH public key (base64) */
  newServerPublicKey: string;
  /** Grace period in ms during which old key is still accepted */
  gracePeriodMs: number;
}

export interface EmberAgentCryptoState {
  agentId: string;
  /** Current active session key */
  currentKey: EmberSessionKey;
  /** Previous key (still valid during grace period) */
  previousKey: EmberSessionKey | null;
  /** Server's current ECDH key pair for this agent */
  serverKeyPair: EmberKeyPair;
  /** Number of key rotations performed */
  rotationCount: number;
  /** Total messages encrypted */
  totalEncrypted: number;
  /** Total messages decrypted */
  totalDecrypted: number;
  /** Last activity timestamp */
  lastActivityAt: number;
  /** Custom rotation interval override (ms) */
  rotationIntervalMs: number;
}

// ── In-Memory Crypto State Store ───────────────────────────────────────────

const agentCryptoStates = new Map<string, EmberAgentCryptoState>();

// Server master key pair (regenerated on restart — provides forward secrecy)
let serverMasterKeyPair: EmberKeyPair | null = null;

// ── Key Generation ─────────────────────────────────────────────────────────

/**
 * Generate an ECDH key pair for key exchange.
 */
export function generateECDHKeyPair(): EmberKeyPair {
  const ecdh = crypto.createECDH(ECDH_CURVE);
  ecdh.generateKeys();
  return {
    publicKey: ecdh.getPublicKey("base64"),
    privateKey: ecdh.getPrivateKey("base64"),
    createdAt: Date.now(),
  };
}

/**
 * Derive an AES-256 session key from ECDH shared secret using HKDF.
 */
export function deriveSessionKey(
  serverPrivateKey: string,
  agentPublicKey: string,
  salt?: Buffer,
): Buffer {
  const ecdh = crypto.createECDH(ECDH_CURVE);
  ecdh.setPrivateKey(Buffer.from(serverPrivateKey, "base64"));
  const sharedSecret = ecdh.computeSecret(Buffer.from(agentPublicKey, "base64"));

  // HKDF: Extract-then-Expand
  const effectiveSalt = salt || crypto.randomBytes(32);
  const prk = crypto.createHmac(HKDF_HASH, effectiveSalt)
    .update(sharedSecret)
    .digest();

  // Expand phase — produce AES_KEY_LENGTH bytes
  const hmac = crypto.createHmac(HKDF_HASH, prk);
  hmac.update(Buffer.concat([HKDF_INFO, Buffer.from([1])]));
  const okm = hmac.digest();

  return okm.subarray(0, AES_KEY_LENGTH);
}

/**
 * Generate a unique key ID.
 */
function generateKeyId(): string {
  return `ek-${crypto.randomBytes(8).toString("hex")}`;
}

/**
 * Create a new session key object.
 */
function createSessionKey(key: Buffer, rotationIntervalMs: number = KEY_ROTATION_INTERVAL_MS): EmberSessionKey {
  const now = Date.now();
  return {
    keyId: generateKeyId(),
    key,
    createdAt: now,
    expiresAt: now + rotationIntervalMs,
    sequenceCounter: 0,
    highestSeenSequence: -1,
    recentSequences: new Set(),
  };
}

// ── Encryption / Decryption ────────────────────────────────────────────────

/**
 * Encrypt a message using AES-256-GCM.
 * Returns the encrypted message envelope with IV, ciphertext, tag, and metadata.
 */
export function encryptMessage(
  plaintext: string | Buffer,
  sessionKey: EmberSessionKey,
  aad?: Buffer,
): EmberEncryptedMessage {
  const iv = crypto.randomBytes(GCM_IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-gcm", sessionKey.key, iv, {
    authTagLength: GCM_TAG_LENGTH,
  });

  if (aad) {
    cipher.setAAD(aad);
  }

  const data = typeof plaintext === "string" ? Buffer.from(plaintext, "utf-8") : plaintext;
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Increment sequence counter
  sessionKey.sequenceCounter++;

  return {
    kid: sessionKey.keyId,
    iv: iv.toString("base64"),
    ct: encrypted.toString("base64"),
    tag: tag.toString("base64"),
    seq: sessionKey.sequenceCounter,
    ts: Date.now(),
  };
}

/**
 * Decrypt an AES-256-GCM encrypted message.
 * Validates authentication tag and checks for replay attacks.
 */
export function decryptMessage(
  message: EmberEncryptedMessage,
  sessionKey: EmberSessionKey,
  aad?: Buffer,
): Buffer {
  // Replay protection: check sequence number
  if (message.seq <= sessionKey.highestSeenSequence) {
    // Allow some out-of-order delivery within the sliding window
    if (sessionKey.recentSequences.has(message.seq)) {
      throw new EmberCryptoError("REPLAY_DETECTED", `Duplicate sequence number: ${message.seq}`);
    }
    if (sessionKey.highestSeenSequence - message.seq > MAX_SEQUENCE_GAP) {
      throw new EmberCryptoError("SEQUENCE_TOO_OLD", `Sequence ${message.seq} is too far behind ${sessionKey.highestSeenSequence}`);
    }
  }

  const iv = Buffer.from(message.iv, "base64");
  const ciphertext = Buffer.from(message.ct, "base64");
  const tag = Buffer.from(message.tag, "base64");

  const decipher = crypto.createDecipheriv("aes-256-gcm", sessionKey.key, iv, {
    authTagLength: GCM_TAG_LENGTH,
  });

  if (aad) {
    decipher.setAAD(aad);
  }

  decipher.setAuthTag(tag);

  let decrypted: Buffer;
  try {
    decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err: any) {
    throw new EmberCryptoError("AUTH_FAILED", "Authentication tag verification failed — message tampered or wrong key");
  }

  // Update replay protection state
  sessionKey.recentSequences.add(message.seq);
  if (message.seq > sessionKey.highestSeenSequence) {
    sessionKey.highestSeenSequence = message.seq;
    // Prune old sequence numbers from the sliding window
    const cutoff = sessionKey.highestSeenSequence - MAX_SEQUENCE_GAP;
    for (const seq of sessionKey.recentSequences) {
      if (seq < cutoff) sessionKey.recentSequences.delete(seq);
    }
  }

  return decrypted;
}

// ── Key Exchange Protocol ──────────────────────────────────────────────────

/**
 * Get or initialize the server master key pair.
 */
export function getServerMasterKeyPair(): EmberKeyPair {
  if (!serverMasterKeyPair) {
    serverMasterKeyPair = generateECDHKeyPair();
  }
  return serverMasterKeyPair;
}

/**
 * Perform server-side ECDH key exchange.
 * Called when an agent sends its public key during registration.
 * Returns the server's public key and establishes the session.
 */
export function performKeyExchange(
  agentId: string,
  agentPublicKey: string,
  rotationIntervalMs: number = KEY_ROTATION_INTERVAL_MS,
): EmberKeyExchangeResponse {
  // Generate ephemeral key pair for this agent (forward secrecy)
  const serverKeyPair = generateECDHKeyPair();

  // Derive the shared session key
  const sessionKeyBytes = deriveSessionKey(serverKeyPair.privateKey, agentPublicKey);
  const sessionKey = createSessionKey(sessionKeyBytes, rotationIntervalMs);

  // Store crypto state for this agent
  const state: EmberAgentCryptoState = {
    agentId,
    currentKey: sessionKey,
    previousKey: null,
    serverKeyPair,
    rotationCount: 0,
    totalEncrypted: 0,
    totalDecrypted: 0,
    lastActivityAt: Date.now(),
    rotationIntervalMs,
  };
  agentCryptoStates.set(agentId, state);

  return {
    serverPublicKey: serverKeyPair.publicKey,
    keyId: sessionKey.keyId,
    rotationIntervalMs,
    serverTimestamp: Date.now(),
  };
}

/**
 * Perform key rotation for an agent.
 * The old key enters a grace period during which it can still decrypt messages.
 */
export function performKeyRotation(
  agentId: string,
  newAgentPublicKey: string,
): EmberKeyRotationResponse {
  const state = agentCryptoStates.get(agentId);
  if (!state) {
    throw new EmberCryptoError("NO_SESSION", `No crypto session for agent ${agentId}`);
  }

  // Generate new ephemeral key pair
  const newServerKeyPair = generateECDHKeyPair();

  // Derive new session key
  const newSessionKeyBytes = deriveSessionKey(newServerKeyPair.privateKey, newAgentPublicKey);
  const newSessionKey = createSessionKey(newSessionKeyBytes, state.rotationIntervalMs);

  // Move current key to previous (grace period)
  state.previousKey = state.currentKey;
  // Extend the old key's expiry by the grace period
  state.previousKey.expiresAt = Date.now() + KEY_GRACE_PERIOD_MS;

  // Install new key
  state.currentKey = newSessionKey;
  state.serverKeyPair = newServerKeyPair;
  state.rotationCount++;
  state.lastActivityAt = Date.now();

  return {
    newKeyId: newSessionKey.keyId,
    newServerPublicKey: newServerKeyPair.publicKey,
    gracePeriodMs: KEY_GRACE_PERIOD_MS,
  };
}

// ── Agent Crypto Operations ────────────────────────────────────────────────

/**
 * Encrypt a message for a specific agent.
 */
export function encryptForAgent(
  agentId: string,
  plaintext: string | Buffer,
): EmberEncryptedMessage {
  const state = agentCryptoStates.get(agentId);
  if (!state) {
    throw new EmberCryptoError("NO_SESSION", `No crypto session for agent ${agentId}`);
  }

  // Use agent ID as AAD for channel binding
  const aad = Buffer.from(agentId, "utf-8");
  const message = encryptMessage(plaintext, state.currentKey, aad);

  state.totalEncrypted++;
  state.lastActivityAt = Date.now();

  return message;
}

/**
 * Decrypt a message from a specific agent.
 * Tries the current key first, then falls back to the previous key (grace period).
 */
export function decryptFromAgent(
  agentId: string,
  message: EmberEncryptedMessage,
): Buffer {
  const state = agentCryptoStates.get(agentId);
  if (!state) {
    throw new EmberCryptoError("NO_SESSION", `No crypto session for agent ${agentId}`);
  }

  const aad = Buffer.from(agentId, "utf-8");

  // Try current key first
  if (message.kid === state.currentKey.keyId) {
    const result = decryptMessage(message, state.currentKey, aad);
    state.totalDecrypted++;
    state.lastActivityAt = Date.now();
    return result;
  }

  // Try previous key (grace period)
  if (state.previousKey && message.kid === state.previousKey.keyId) {
    if (Date.now() > state.previousKey.expiresAt) {
      throw new EmberCryptoError("KEY_EXPIRED", `Key ${message.kid} has expired past grace period`);
    }
    const result = decryptMessage(message, state.previousKey, aad);
    state.totalDecrypted++;
    state.lastActivityAt = Date.now();
    return result;
  }

  throw new EmberCryptoError("UNKNOWN_KEY", `Unknown key ID: ${message.kid}`);
}

/**
 * Check if an agent's session key needs rotation.
 */
export function needsKeyRotation(agentId: string): boolean {
  const state = agentCryptoStates.get(agentId);
  if (!state) return false;
  return Date.now() >= state.currentKey.expiresAt;
}

/**
 * Get the crypto state for an agent (for diagnostics / UI).
 */
export function getAgentCryptoState(agentId: string): Omit<EmberAgentCryptoState, "currentKey" | "previousKey" | "serverKeyPair"> & {
  currentKeyId: string;
  currentKeyCreatedAt: number;
  currentKeyExpiresAt: number;
  currentKeySequence: number;
  previousKeyId: string | null;
  previousKeyExpiresAt: number | null;
  hasActiveSession: boolean;
} | null {
  const state = agentCryptoStates.get(agentId);
  if (!state) return null;

  return {
    agentId: state.agentId,
    rotationCount: state.rotationCount,
    totalEncrypted: state.totalEncrypted,
    totalDecrypted: state.totalDecrypted,
    lastActivityAt: state.lastActivityAt,
    rotationIntervalMs: state.rotationIntervalMs,
    currentKeyId: state.currentKey.keyId,
    currentKeyCreatedAt: state.currentKey.createdAt,
    currentKeyExpiresAt: state.currentKey.expiresAt,
    currentKeySequence: state.currentKey.sequenceCounter,
    previousKeyId: state.previousKey?.keyId || null,
    previousKeyExpiresAt: state.previousKey?.expiresAt || null,
    hasActiveSession: true,
  };
}

/**
 * Remove an agent's crypto session (on agent termination).
 */
export function destroyAgentSession(agentId: string): boolean {
  const state = agentCryptoStates.get(agentId);
  if (!state) return false;

  // Zero out key material
  state.currentKey.key.fill(0);
  if (state.previousKey) state.previousKey.key.fill(0);

  agentCryptoStates.delete(agentId);
  return true;
}

/**
 * List all active crypto sessions (for fleet management UI).
 */
export function listActiveSessions(): Array<{
  agentId: string;
  keyId: string;
  rotationCount: number;
  totalMessages: number;
  lastActivityAt: number;
  needsRotation: boolean;
}> {
  return Array.from(agentCryptoStates.entries()).map(([agentId, state]) => ({
    agentId,
    keyId: state.currentKey.keyId,
    rotationCount: state.rotationCount,
    totalMessages: state.totalEncrypted + state.totalDecrypted,
    lastActivityAt: state.lastActivityAt,
    needsRotation: Date.now() >= state.currentKey.expiresAt,
  }));
}

/**
 * Force rotation of all agent keys (emergency re-key).
 * Returns the number of agents re-keyed.
 * Note: Agents must send new ECDH public keys on their next beacon,
 * so this marks them as needing rotation. The actual re-key happens
 * when the agent checks in.
 */
export function forceGlobalRekey(): number {
  let count = 0;
  for (const [, state] of agentCryptoStates) {
    // Set the current key as expired to force rotation on next beacon
    state.currentKey.expiresAt = Date.now() - 1;
    count++;
  }
  return count;
}

// ── Utility Functions ──────────────────────────────────────────────────────

/**
 * Generate a registration token for agent enrollment.
 * This token is embedded in the payload and used during initial key exchange.
 */
export function generateRegistrationToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

/**
 * Validate a registration token format.
 */
export function isValidRegistrationToken(token: string): boolean {
  return /^[a-f0-9]{64}$/.test(token);
}

/**
 * Generate a fingerprint of a public key for verification.
 */
export function fingerprintPublicKey(publicKeyBase64: string): string {
  const hash = crypto.createHash("sha256").update(Buffer.from(publicKeyBase64, "base64")).digest("hex");
  // Format as colon-separated pairs (like SSH fingerprints)
  return hash.match(/.{2}/g)!.join(":").toUpperCase().slice(0, 47);
}

/**
 * Encrypt a JSON payload for an agent (convenience wrapper).
 */
export function encryptJsonForAgent(agentId: string, payload: object): EmberEncryptedMessage {
  return encryptForAgent(agentId, JSON.stringify(payload));
}

/**
 * Decrypt a JSON payload from an agent (convenience wrapper).
 */
export function decryptJsonFromAgent<T = any>(agentId: string, message: EmberEncryptedMessage): T {
  const plaintext = decryptFromAgent(agentId, message);
  return JSON.parse(plaintext.toString("utf-8")) as T;
}

// ── Error Class ────────────────────────────────────────────────────────────

export type EmberCryptoErrorCode =
  | "REPLAY_DETECTED"
  | "SEQUENCE_TOO_OLD"
  | "AUTH_FAILED"
  | "NO_SESSION"
  | "KEY_EXPIRED"
  | "UNKNOWN_KEY"
  | "INVALID_TOKEN"
  | "KEY_EXCHANGE_FAILED";

export class EmberCryptoError extends Error {
  code: EmberCryptoErrorCode;

  constructor(code: EmberCryptoErrorCode, message: string) {
    super(message);
    this.name = "EmberCryptoError";
    this.code = code;
  }
}

// ── Exports Summary ────────────────────────────────────────────────────────
// 
// Key Exchange:
//   generateECDHKeyPair()        — Generate ECDH P-256 key pair
//   performKeyExchange()         — Server-side key exchange (returns server pubkey + keyId)
//   performKeyRotation()         — Rotate session key with grace period
//   forceGlobalRekey()           — Emergency: expire all keys
//
// Encryption:
//   encryptMessage()             — Raw AES-256-GCM encrypt
//   decryptMessage()             — Raw AES-256-GCM decrypt with replay protection
//   encryptForAgent()            — Encrypt for a specific agent (with AAD binding)
//   decryptFromAgent()           — Decrypt from a specific agent (tries current + previous key)
//   encryptJsonForAgent()        — Convenience: encrypt JSON
//   decryptJsonFromAgent()       — Convenience: decrypt JSON
//
// Session Management:
//   getAgentCryptoState()        — Get agent's crypto diagnostics (safe for UI)
//   destroyAgentSession()        — Wipe agent's key material
//   listActiveSessions()         — List all active crypto sessions
//   needsKeyRotation()           — Check if agent needs re-key
//
// Utilities:
//   generateRegistrationToken()  — Generate 64-char hex enrollment token
//   isValidRegistrationToken()   — Validate token format
//   fingerprintPublicKey()       — SSH-style fingerprint of public key
//   deriveSessionKey()           — HKDF key derivation from ECDH shared secret
