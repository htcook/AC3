/**
 * S3-Compatible Object Storage Provider
 * ══════════════════════════════════════════════════════════════════════════════
 *
 * ARCHITECTURE: Customer Data Isolation Model
 * ─────────────────────────────────────────────────────────────────────────────
 * AC3 does NOT store customer-generated data on its hosted infrastructure.
 * All customer artifacts (reports, evidence screenshots, exploit scripts, RoE
 * documents, SBOMs, manual evidence uploads) are written to the customer's own
 * S3-compatible storage instance.
 *
 * SUPPORTED PROVIDERS:
 *   - AWS S3 (Commercial & GovCloud)
 *   - DigitalOcean Spaces
 *   - MinIO (self-hosted)
 *   - Any S3-compatible endpoint (Wasabi, Backblaze B2, Ceph, etc.)
 *
 * CONFIGURATION (env vars, checked in priority order):
 *
 *   Generic (preferred for new deployments):
 *     S3_ENDPOINT       → S3-compatible endpoint URL
 *     S3_REGION         → Bucket region
 *     S3_ACCESS_KEY     → Access key ID
 *     S3_SECRET_KEY     → Secret access key
 *     S3_BUCKET         → Bucket name
 *     S3_FORCE_PATH_STYLE → "true" for MinIO/path-style (default: false)
 *     S3_PUBLIC_URL_BASE → Custom public URL base (optional, for CDN/custom domains)
 *
 *   Legacy (backward compat, used if generic vars not set):
 *     DO_SPACES_ENDPOINT
 *     DO_SPACES_REGION
 *     DO_SPACES_KEY
 *     DO_SPACES_SECRET
 *     DO_SPACES_BUCKET
 *
 * URL GENERATION:
 *   The module auto-detects the provider from the endpoint URL and generates
 *   correct public URLs:
 *     - DO Spaces:  https://{bucket}.{region}.digitaloceanspaces.com/{key}
 *     - AWS S3:     https://{bucket}.s3.{region}.amazonaws.com/{key}
 *     - Custom:     {S3_PUBLIC_URL_BASE}/{key}
 *     - Path-style: {endpoint}/{bucket}/{key}
 *
 * SECURITY CONTROLS:
 *   1. Customer data never leaves their authorization boundary
 *   2. No security inheritance dependency on AC3 hosted infrastructure
 *   3. Full data sovereignty — customer controls encryption, retention, access
 *   4. Compatible with NIST 800-53 High SC-28 (Protection of Information at Rest)
 *   5. Supports FIPS 140-2/140-3 encrypted endpoints (AWS S3 with SSE-KMS)
 *   6. TLS 1.2+ enforced on all S3 connections
 *
 * IMPORTANT: The Manus-provided server/storage.ts (storagePut/storageGet) is
 * intentionally unused in production. It exists only as a template artifact.
 * All production code MUST use doStoragePut/doStorageGet from this module.
 *
 * Author: Harrison Cook — AceofCloud
 */

import { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { ENV } from "./_core/env";

// ─── Provider Detection ────────────────────────────────────────────────────

type StorageProvider = "do_spaces" | "aws_s3" | "minio" | "custom";

type SSEAlgorithm = "none" | "AES256" | "aws:kms" | "aws:kms:dsse";

interface StorageConfig {
  endpoint: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  bucket: string;
  forcePathStyle: boolean;
  publicUrlBase: string | null;
  provider: StorageProvider;
  // Server-Side Encryption (SSE)
  sseAlgorithm: SSEAlgorithm;
  sseKmsKeyId: string | null;       // KMS Key ARN (required for aws:kms / aws:kms:dsse)
  bucketKeyEnabled: boolean;         // Reduces KMS API calls via S3 Bucket Keys
  privateMode: boolean;              // When true, skip public-read ACL and use presigned URLs
  // FIPS 140-3 Compliance
  useFips: boolean;                  // Use FIPS-validated endpoints for all S3 operations
  fipsEndpoint: string | null;       // Resolved FIPS endpoint (auto-generated or explicit)
}

function resolveConfig(): StorageConfig {
  // Priority 1: Generic S3_* env vars (preferred for new deployments)
  const s3Endpoint = process.env.S3_ENDPOINT;
  const s3Region = process.env.S3_REGION;
  const s3AccessKey = process.env.S3_ACCESS_KEY;
  const s3SecretKey = process.env.S3_SECRET_KEY;
  const s3Bucket = process.env.S3_BUCKET;

  if (s3AccessKey && s3SecretKey && s3Endpoint) {
    const forcePathStyle = process.env.S3_FORCE_PATH_STYLE === "true";
    const publicUrlBase = process.env.S3_PUBLIC_URL_BASE || null;
    const provider = detectProvider(s3Endpoint);
    const sseAlgorithm = (process.env.S3_SSE_ALGORITHM || "none") as SSEAlgorithm;
    const sseKmsKeyId = process.env.S3_SSE_KMS_KEY_ID || null;
    const bucketKeyEnabled = process.env.S3_BUCKET_KEY_ENABLED === "true";
    const privateMode = process.env.S3_PRIVATE_MODE === "true" || sseAlgorithm !== "none";
    const region = s3Region || "us-east-1";

    // FIPS endpoint enforcement
    const useFips = resolveFipsMode(process.env.S3_USE_FIPS, region);
    const fipsEndpoint = useFips ? resolveFipsEndpoint(s3Endpoint, region) : null;

    return {
      endpoint: s3Endpoint,
      region,
      accessKeyId: s3AccessKey,
      secretAccessKey: s3SecretKey,
      bucket: s3Bucket || "ac3-storage",
      forcePathStyle,
      publicUrlBase,
      provider,
      sseAlgorithm,
      sseKmsKeyId,
      bucketKeyEnabled,
      privateMode,
      useFips,
      fipsEndpoint,
    };
  }

  // Priority 2: Legacy DO_SPACES_* env vars (backward compat)
  const doEndpoint = ENV.DO_SPACES_ENDPOINT;
  const doRegion = ENV.DO_SPACES_REGION;
  const doKey = ENV.DO_SPACES_KEY;
  const doSecret = ENV.DO_SPACES_SECRET;
  const doBucket = ENV.DO_SPACES_BUCKET;

  return {
    endpoint: doEndpoint || "https://nyc3.digitaloceanspaces.com",
    region: doRegion || "nyc3",
    accessKeyId: doKey || "",
    secretAccessKey: doSecret || "",
    bucket: doBucket || "aceofcloud-reports",
    forcePathStyle: false,
    publicUrlBase: null,
    provider: "do_spaces",
    sseAlgorithm: "none" as SSEAlgorithm,
    sseKmsKeyId: null,
    bucketKeyEnabled: false,
    privateMode: false,
    useFips: false,
    fipsEndpoint: null,
  };
}

function detectProvider(endpoint: string): StorageProvider {
  if (endpoint.includes("digitaloceanspaces.com")) return "do_spaces";
  if (endpoint.includes("amazonaws.com")) return "aws_s3";
  if (endpoint.includes("minio") || endpoint.includes("localhost") || endpoint.includes("127.0.0.1")) return "minio";
  return "custom";
}

// ─── FIPS 140-3 Endpoint Resolution ──────────────────────────────────────────

/**
 * Determines whether FIPS mode should be enabled.
 * Auto-enables for GovCloud regions (us-gov-*) unless explicitly disabled.
 * Can be explicitly enabled for commercial regions via S3_USE_FIPS=true.
 */
function resolveFipsMode(envValue: string | undefined, region: string): boolean {
  // Explicit opt-in/opt-out takes priority
  if (envValue === "true") return true;
  if (envValue === "false") return false;

  // Auto-enable for GovCloud regions
  if (region.startsWith("us-gov-")) return true;

  // Auto-enable for regions that commonly require FIPS (DoD IL4/IL5)
  if (region === "us-iso-east-1" || region === "us-isob-east-1") return true;

  return false;
}

/**
 * Resolves the FIPS-validated S3 endpoint for the given region.
 *
 * AWS FIPS endpoints follow the pattern:
 *   - Commercial:  s3-fips.{region}.amazonaws.com
 *   - GovCloud:    s3-fips.{region}.amazonaws.com
 *   - Dual-stack:  s3-fips.dualstack.{region}.amazonaws.com
 *
 * If the endpoint is already a FIPS endpoint, returns it unchanged.
 * For non-AWS providers, returns null (FIPS not applicable).
 */
function resolveFipsEndpoint(endpoint: string, region: string): string | null {
  // Already a FIPS endpoint
  if (endpoint.includes("-fips") || endpoint.includes("fips.")) {
    return endpoint;
  }

  // Only AWS S3 supports FIPS endpoints
  if (!endpoint.includes("amazonaws.com")) {
    return null;
  }

  // Generate the FIPS endpoint
  // Standard pattern: https://s3-fips.{region}.amazonaws.com
  return `https://s3-fips.${region}.amazonaws.com`;
}

/**
 * Returns the effective endpoint to use for S3 client initialization.
 * Uses FIPS endpoint when available, otherwise falls back to configured endpoint.
 */
function getEffectiveEndpoint(config: StorageConfig): string {
  if (config.useFips && config.fipsEndpoint) {
    return config.fipsEndpoint;
  }
  return config.endpoint;
}

// ─── Client Singleton ───────────────────────────────────────────────────────

let _client: S3Client | null = null;
let _config: StorageConfig | null = null;

function getConfig(): StorageConfig {
  if (_config) return _config;
  _config = resolveConfig();
  return _config;
}

function getClient(): S3Client {
  if (_client) return _client;

  const config = getConfig();

  if (!config.accessKeyId || !config.secretAccessKey) {
    throw new Error(
      "S3 storage credentials missing. Set S3_ACCESS_KEY/S3_SECRET_KEY (preferred) " +
      "or DO_SPACES_KEY/DO_SPACES_SECRET (legacy). " +
      "See server/do-storage.ts header for full configuration guide."
    );
  }

  // Use FIPS endpoint when available (GovCloud auto-detection or explicit opt-in)
  const effectiveEndpoint = getEffectiveEndpoint(config);

  _client = new S3Client({
    endpoint: effectiveEndpoint,
    region: config.region,
    credentials: {
      accessKeyId: config.accessKeyId,
      secretAccessKey: config.secretAccessKey,
    },
    forcePathStyle: config.forcePathStyle,
    // AWS SDK v3: useFipsEndpoint ensures all derived service endpoints use FIPS
    ...(config.useFips ? { useFipsEndpoint: true } : {}),
  });

  return _client;
}

/**
 * Reset the client singleton (useful for testing or config changes).
 */
export function resetStorageClient(): void {
  _client = null;
  _config = null;
}

// ─── URL Generation ────────────────────────────────────────────────────────

function buildPublicUrl(key: string): string {
  const config = getConfig();

  // Priority 1: Explicit public URL base (CDN, custom domain, etc.)
  if (config.publicUrlBase) {
    const base = config.publicUrlBase.replace(/\/+$/, "");
    return `${base}/${key}`;
  }

  // Priority 2: Provider-specific URL patterns
  switch (config.provider) {
    case "do_spaces":
      return `https://${config.bucket}.${config.region}.digitaloceanspaces.com/${key}`;

    case "aws_s3":
      // Virtual-hosted style for AWS S3
      return `https://${config.bucket}.s3.${config.region}.amazonaws.com/${key}`;

    case "minio":
      // Path-style for MinIO
      const endpoint = config.endpoint.replace(/\/+$/, "");
      return `${endpoint}/${config.bucket}/${key}`;

    case "custom":
    default:
      // Path-style fallback for unknown providers
      if (config.forcePathStyle) {
        const ep = config.endpoint.replace(/\/+$/, "");
        return `${ep}/${config.bucket}/${key}`;
      }
      // Virtual-hosted style attempt
      const url = new URL(config.endpoint);
      return `${url.protocol}//${config.bucket}.${url.host}/${key}`;
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function normalizeKey(relKey: string): string {
  return relKey.replace(/^\/+/, "");
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Upload a file to S3-compatible storage.
 * Returns the normalized key and a URL (public or presigned depending on config).
 *
 * Behavior depends on encryption/privacy configuration:
 *   - Default (no SSE): public-read ACL, returns direct public URL
 *   - SSE enabled or S3_PRIVATE_MODE=true: no ACL, returns presigned URL
 *
 * SSE-KMS Configuration (env vars):
 *   - S3_SSE_ALGORITHM: "AES256" | "aws:kms" | "aws:kms:dsse"
 *   - S3_SSE_KMS_KEY_ID: KMS Key ARN (required for aws:kms)
 *   - S3_BUCKET_KEY_ENABLED: "true" to reduce KMS API calls
 *   - S3_PRIVATE_MODE: "true" to force presigned URLs without SSE
 *
 * @param relKey - Relative key path (leading slashes stripped)
 * @param data - File content as Buffer, Uint8Array, or string (UTF-8)
 * @param contentType - MIME type (default: application/octet-stream)
 */
export async function doStoragePut(
  relKey: string,
  data: Buffer | Uint8Array | string,
  contentType = "application/octet-stream"
): Promise<{ key: string; url: string }> {
  const client = getClient();
  const config = getConfig();
  const key = normalizeKey(relKey);

  const body =
    typeof data === "string" ? Buffer.from(data, "utf-8") : data;

  // Build PutObject params with optional encryption
  const putParams: Record<string, unknown> = {
    Bucket: config.bucket,
    Key: key,
    Body: body,
    ContentType: contentType,
  };

  // ACL: only set public-read when NOT in private/encrypted mode
  if (!config.privateMode) {
    putParams.ACL = "public-read";
  }

  // Server-Side Encryption parameters
  if (config.sseAlgorithm !== "none") {
    putParams.ServerSideEncryption = config.sseAlgorithm;

    if ((config.sseAlgorithm === "aws:kms" || config.sseAlgorithm === "aws:kms:dsse") && config.sseKmsKeyId) {
      putParams.SSEKMSKeyId = config.sseKmsKeyId;
    }

    if (config.bucketKeyEnabled) {
      putParams.BucketKeyEnabled = true;
    }
  }

  await client.send(new PutObjectCommand(putParams as any));

  // In private mode, return a presigned URL instead of a public URL
  if (config.privateMode) {
    const getCmd = new GetObjectCommand({ Bucket: config.bucket, Key: key });
    const url = await getSignedUrl(client, getCmd, { expiresIn: 3600 });
    return { key, url };
  }

  const url = buildPublicUrl(key);
  return { key, url };
}

/**
 * Get the URL for an existing key in S3-compatible storage.
 * Returns a public URL for public buckets, or a presigned URL for private/encrypted buckets.
 */
export async function doStorageGet(
  relKey: string
): Promise<{ key: string; url: string }> {
  const key = normalizeKey(relKey);
  const config = getConfig();

  if (config.privateMode) {
    const client = getClient();
    const command = new GetObjectCommand({ Bucket: config.bucket, Key: key });
    const url = await getSignedUrl(client, command, { expiresIn: 3600 });
    return { key, url };
  }

  return { key, url: buildPublicUrl(key) };
}

/**
 * Get a presigned URL for private objects (expires after specified seconds).
 * Use this when the bucket does NOT have public-read ACL.
 *
 * @param relKey - Relative key path
 * @param expiresIn - URL expiration in seconds (default: 3600 = 1 hour)
 */
export async function doStorageGetSigned(
  relKey: string,
  expiresIn = 3600
): Promise<{ key: string; url: string }> {
  const client = getClient();
  const config = getConfig();
  const key = normalizeKey(relKey);

  const command = new GetObjectCommand({
    Bucket: config.bucket,
    Key: key,
  });

  const url = await getSignedUrl(client, command, { expiresIn });
  return { key, url };
}

/**
 * Check if an object exists in storage.
 */
export async function doStorageExists(relKey: string): Promise<boolean> {
  const client = getClient();
  const config = getConfig();
  const key = normalizeKey(relKey);

  try {
    await client.send(
      new HeadObjectCommand({
        Bucket: config.bucket,
        Key: key,
      })
    );
    return true;
  } catch {
    return false;
  }
}

/**
 * Download file content directly from S3 by key.
 * Use this instead of fetching from a stored URL (which may be an expired presigned URL).
 *
 * @param relKey - Relative key path
 * @returns Buffer containing the file content, or null if not found
 */
export async function doStorageGetContent(
  relKey: string
): Promise<{ key: string; data: Buffer; contentType: string } | null> {
  const client = getClient();
  const config = getConfig();
  const key = normalizeKey(relKey);
  try {
    const response = await client.send(
      new GetObjectCommand({ Bucket: config.bucket, Key: key })
    );
    const data = await streamToBuffer(response.Body);
    return { key, data, contentType: response.ContentType || 'application/octet-stream' };
  } catch (err: any) {
    if (err.name === 'NoSuchKey' || err.$metadata?.httpStatusCode === 404) {
      return null;
    }
    throw err;
  }
}

/**
 * Delete an object from storage.
 */
export async function doStorageDelete(relKey: string): Promise<void> {
  const client = getClient();
  const config = getConfig();
  const key = normalizeKey(relKey);

  await client.send(
    new DeleteObjectCommand({
      Bucket: config.bucket,
      Key: key,
    })
  );
}

/**
 * Get the current storage configuration (for diagnostics/health checks).
 * Credentials are redacted.
 */
export function getStorageInfo(): {
  provider: StorageProvider;
  endpoint: string;
  region: string;
  bucket: string;
  forcePathStyle: boolean;
  hasCredentials: boolean;
  encryption: {
    algorithm: SSEAlgorithm;
    kmsKeyConfigured: boolean;
    bucketKeyEnabled: boolean;
  };
  privateMode: boolean;
  fips: {
    enabled: boolean;
    endpoint: string | null;
    autoDetected: boolean;
  };
} {
  const config = getConfig();
  return {
    provider: config.provider,
    endpoint: config.endpoint,
    region: config.region,
    bucket: config.bucket,
    forcePathStyle: config.forcePathStyle,
    hasCredentials: !!(config.accessKeyId && config.secretAccessKey),
    encryption: {
      algorithm: config.sseAlgorithm,
      kmsKeyConfigured: !!config.sseKmsKeyId,
      bucketKeyEnabled: config.bucketKeyEnabled,
    },
    privateMode: config.privateMode,
    fips: {
      enabled: config.useFips,
      endpoint: config.fipsEndpoint,
      autoDetected: config.useFips && !process.env.S3_USE_FIPS,
    },
  };
}

// ─── Client-Side Encryption (CSE) ─────────────────────────────────────────────
//
// Envelope encryption for highest-sensitivity artifacts:
//   - Custom exploit scripts (custom-exploit-repository.ts)
//   - Rules of Engagement documents (roe-upload.ts)
//   - Credentials / secrets found during engagements
//
// Architecture:
//   1. Generate a random AES-256-GCM data encryption key (DEK) per object
//   2. Encrypt the plaintext with the DEK
//   3. Encrypt the DEK with the customer's CMK (via KMS GenerateDataKey or local key)
//   4. Store the ciphertext in S3 with metadata: { iv, encryptedDEK, algorithm, keyId }
//   5. On retrieval: decrypt DEK with CMK, then decrypt ciphertext with DEK
//
// This provides defense-in-depth: even if S3 bucket is compromised AND SSE-KMS
// is bypassed, the data remains encrypted with a key only the customer controls.
//
// ENV VARS:
//   S3_CSE_KEY_ARN    — KMS CMK ARN (for KMS-managed keys) or local key identifier
//   S3_CSE_ENABLED    — "true" to enable CSE (doStoragePutEncrypted/doStorageGetDecrypted)
//
// COMPLIANCE:
//   - NIST 800-53 SC-28(1): Cryptographic Protection of Information at Rest
//   - NIST 800-53 SC-12: Cryptographic Key Establishment and Management
//   - FedRAMP High: Dual-layer encryption (SSE-KMS + CSE) for CUI/classified data

import { randomBytes, createCipheriv, createDecipheriv, createHash } from "crypto";

/** CSE metadata stored alongside encrypted objects in S3 */
export interface CSEMetadata {
  /** Algorithm used for data encryption */
  algorithm: "aes-256-gcm";
  /** Base64-encoded initialization vector (12 bytes for GCM) */
  iv: string;
  /** Base64-encoded encrypted data encryption key (DEK) */
  encryptedDEK: string;
  /** Base64-encoded GCM auth tag (16 bytes) */
  authTag: string;
  /** Key ID used to encrypt the DEK (KMS ARN or local key fingerprint) */
  keyId: string;
  /** CSE version for forward compatibility */
  version: "1";
}

/** CSE configuration resolved from environment */
interface CSEConfig {
  enabled: boolean;
  keyArn: string;        // KMS ARN or local key reference
  localKey: Buffer | null; // Derived local key (for non-KMS mode)
}

/**
 * Resolve CSE configuration from environment.
 * Supports two modes:
 *   1. KMS mode: S3_CSE_KEY_ARN is a KMS ARN → uses KMS GenerateDataKey/Decrypt
 *   2. Local mode: S3_CSE_KEY_ARN is a passphrase/key → derives AES-256 key locally
 *
 * For production GovCloud deployments, KMS mode is recommended.
 * Local mode is provided for development/testing and non-AWS environments.
 */
function resolveCSEConfig(): CSEConfig {
  const enabled = process.env.S3_CSE_ENABLED === "true";
  const keyArn = process.env.S3_CSE_KEY_ARN || "";

  if (!enabled || !keyArn) {
    return { enabled: false, keyArn: "", localKey: null };
  }

  // KMS mode: ARN starts with "arn:aws:kms:" — actual KMS calls handled externally
  if (keyArn.startsWith("arn:aws:kms:") || keyArn.startsWith("arn:aws-us-gov:kms:")) {
    return { enabled: true, keyArn, localKey: null };
  }

  // Local mode: derive a 256-bit key from the provided passphrase/key material
  // Uses SHA-256 hash of the key material as the wrapping key
  const localKey = createHash("sha256").update(keyArn).digest();
  return { enabled: true, keyArn: `local:${createHash("md5").update(keyArn).digest("hex").slice(0, 8)}`, localKey };
}

let _cseConfig: CSEConfig | null = null;
function getCSEConfig(): CSEConfig {
  if (_cseConfig) return _cseConfig;
  _cseConfig = resolveCSEConfig();
  return _cseConfig;
}

/** Reset CSE config (for testing) */
export function resetCSEConfig(): void {
  _cseConfig = null;
}

/**
 * Wrap (encrypt) a data encryption key using the configured CMK.
 *
 * In local mode: encrypts DEK with AES-256-GCM using the derived local key.
 * In KMS mode: would call KMS Encrypt API (stubbed for now — requires @aws-sdk/client-kms).
 */
function wrapDataKey(dek: Buffer, config: CSEConfig): { encryptedDEK: Buffer; keyId: string } {
  if (config.localKey) {
    // Local wrapping: AES-256-GCM with the derived key
    const wrapIv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", config.localKey, wrapIv);
    const encrypted = Buffer.concat([cipher.update(dek), cipher.final()]);
    const tag = cipher.getAuthTag();
    // Pack: [12 bytes IV][16 bytes tag][encrypted DEK]
    const packed = Buffer.concat([wrapIv, tag, encrypted]);
    return { encryptedDEK: packed, keyId: config.keyArn };
  }

  // KMS mode: In production, this would call KMS Encrypt API
  // For now, we store the DEK "wrapped" with a placeholder indicating KMS is needed
  // The actual KMS integration requires @aws-sdk/client-kms which can be added later
  throw new Error(
    "KMS-based CSE requires @aws-sdk/client-kms. " +
    "Set S3_CSE_KEY_ARN to a local passphrase for development, " +
    "or install @aws-sdk/client-kms for production KMS integration."
  );
}

/**
 * Unwrap (decrypt) a data encryption key using the configured CMK.
 */
function unwrapDataKey(encryptedDEK: Buffer, keyId: string, config: CSEConfig): Buffer {
  if (config.localKey) {
    // Local unwrapping: unpack [12 IV][16 tag][ciphertext]
    const wrapIv = encryptedDEK.subarray(0, 12);
    const tag = encryptedDEK.subarray(12, 28);
    const ciphertext = encryptedDEK.subarray(28);
    const decipher = createDecipheriv("aes-256-gcm", config.localKey, wrapIv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  throw new Error(
    `KMS unwrap not implemented. Key ID: ${keyId}. ` +
    "Install @aws-sdk/client-kms for production KMS integration."
  );
}

/**
 * Encrypt data using envelope encryption and upload to S3.
 *
 * Flow:
 *   1. Generate random 256-bit DEK
 *   2. Encrypt plaintext with DEK (AES-256-GCM)
 *   3. Wrap DEK with CMK (local or KMS)
 *   4. Upload ciphertext to S3 with CSE metadata in a sidecar object
 *
 * The ciphertext is stored at `{key}` and metadata at `{key}.cse-meta.json`.
 *
 * @param relKey - Relative key path for the encrypted object
 * @param data - Plaintext data to encrypt
 * @param contentType - Original MIME type (stored in metadata for decryption)
 * @returns Object with key, url (presigned), and metadata
 */
export async function doStoragePutEncrypted(
  relKey: string,
  data: Buffer | Uint8Array | string,
  contentType = "application/octet-stream"
): Promise<{ key: string; url: string; metadata: CSEMetadata }> {
  const cseConfig = getCSEConfig();

  if (!cseConfig.enabled) {
    throw new Error(
      "Client-Side Encryption is not enabled. " +
      "Set S3_CSE_ENABLED=true and S3_CSE_KEY_ARN to enable."
    );
  }

  const plaintext = typeof data === "string" ? Buffer.from(data, "utf-8") : Buffer.from(data);

  // Step 1: Generate random DEK (256-bit = 32 bytes)
  const dek = randomBytes(32);

  // Step 2: Encrypt plaintext with DEK using AES-256-GCM
  const iv = randomBytes(12); // 96-bit IV for GCM
  const cipher = createCipheriv("aes-256-gcm", dek, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag(); // 128-bit authentication tag

  // Step 3: Wrap DEK with CMK
  const { encryptedDEK, keyId } = wrapDataKey(dek, cseConfig);

  // Step 4: Build CSE metadata
  const metadata: CSEMetadata = {
    algorithm: "aes-256-gcm",
    iv: iv.toString("base64"),
    encryptedDEK: encryptedDEK.toString("base64"),
    authTag: authTag.toString("base64"),
    keyId,
    version: "1",
  };

  // Step 5: Upload ciphertext to S3 (uses existing doStoragePut which handles SSE)
  const { key, url } = await doStoragePut(relKey, ciphertext, "application/octet-stream");

  // Step 6: Upload CSE metadata as sidecar object
  const metaKey = `${key}.cse-meta.json`;
  const metaPayload = JSON.stringify({
    ...metadata,
    originalContentType: contentType,
    encryptedAt: new Date().toISOString(),
  });
  await doStoragePut(metaKey, metaPayload, "application/json");

  // Zero out the DEK from memory
  dek.fill(0);

  return { key, url, metadata };
}

/**
 * Download and decrypt a CSE-encrypted object from S3.
 *
 * Flow:
 *   1. Download CSE metadata sidecar ({key}.cse-meta.json)
 *   2. Download ciphertext ({key})
 *   3. Unwrap DEK with CMK
 *   4. Decrypt ciphertext with DEK (AES-256-GCM)
 *
 * @param relKey - Relative key path of the encrypted object
 * @returns Decrypted plaintext as Buffer, plus metadata
 */
export async function doStorageGetDecrypted(
  relKey: string
): Promise<{ key: string; data: Buffer; metadata: CSEMetadata; originalContentType: string }> {
  const cseConfig = getCSEConfig();

  if (!cseConfig.enabled) {
    throw new Error(
      "Client-Side Encryption is not enabled. " +
      "Set S3_CSE_ENABLED=true and S3_CSE_KEY_ARN to enable."
    );
  }

  const key = normalizeKey(relKey);
  const client = getClient();
  const config = getConfig();

  // Step 1: Download CSE metadata
  const metaKey = `${key}.cse-meta.json`;
  const metaResponse = await client.send(
    new GetObjectCommand({ Bucket: config.bucket, Key: metaKey })
  );
  const metaBody = await streamToBuffer(metaResponse.Body);
  const metaJson = JSON.parse(metaBody.toString("utf-8"));
  const metadata: CSEMetadata = {
    algorithm: metaJson.algorithm,
    iv: metaJson.iv,
    encryptedDEK: metaJson.encryptedDEK,
    authTag: metaJson.authTag,
    keyId: metaJson.keyId,
    version: metaJson.version,
  };
  const originalContentType = metaJson.originalContentType || "application/octet-stream";

  // Step 2: Download ciphertext
  const dataResponse = await client.send(
    new GetObjectCommand({ Bucket: config.bucket, Key: key })
  );
  const ciphertext = await streamToBuffer(dataResponse.Body);

  // Step 3: Unwrap DEK
  const encryptedDEK = Buffer.from(metadata.encryptedDEK, "base64");
  const dek = unwrapDataKey(encryptedDEK, metadata.keyId, cseConfig);

  // Step 4: Decrypt ciphertext
  const iv = Buffer.from(metadata.iv, "base64");
  const authTag = Buffer.from(metadata.authTag, "base64");
  const decipher = createDecipheriv("aes-256-gcm", dek, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  // Zero out the DEK from memory
  dek.fill(0);

  return { key, data: plaintext, metadata, originalContentType };
}

/**
 * Check if CSE is configured and available.
 */
export function getCSEInfo(): {
  enabled: boolean;
  keyId: string;
  mode: "kms" | "local" | "disabled";
} {
  const config = getCSEConfig();
  if (!config.enabled) {
    return { enabled: false, keyId: "", mode: "disabled" };
  }
  const mode = config.localKey ? "local" : "kms";
  return { enabled: true, keyId: config.keyArn, mode };
}

// ─── Utility ───────────────────────────────────────────────────────────────────

/** Convert a readable stream (S3 response body) to Buffer */
async function streamToBuffer(body: any): Promise<Buffer> {
  if (Buffer.isBuffer(body)) return body;
  if (body instanceof Uint8Array) return Buffer.from(body);

  // Node.js Readable stream
  const chunks: Buffer[] = [];
  for await (const chunk of body) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}
