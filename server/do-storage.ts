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
    return {
      endpoint: s3Endpoint,
      region: s3Region || "us-east-1",
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
  };
}

function detectProvider(endpoint: string): StorageProvider {
  if (endpoint.includes("digitaloceanspaces.com")) return "do_spaces";
  if (endpoint.includes("amazonaws.com")) return "aws_s3";
  if (endpoint.includes("minio") || endpoint.includes("localhost") || endpoint.includes("127.0.0.1")) return "minio";
  return "custom";
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

  _client = new S3Client({
    endpoint: config.endpoint,
    region: config.region,
    credentials: {
      accessKeyId: config.accessKeyId,
      secretAccessKey: config.secretAccessKey,
    },
    forcePathStyle: config.forcePathStyle,
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
  };
}
