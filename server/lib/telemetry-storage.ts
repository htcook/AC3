/**
 * Telemetry Cloud Storage Providers
 *
 * Provider-agnostic payload archival for full telemetry payloads.
 * Supports:
 *   - DigitalOcean Spaces (S3-compatible)
 *   - AWS S3
 *   - Local filesystem (dev/test fallback)
 *
 * Full request/response payloads > 2KB are stored in cloud storage
 * and referenced by key in the engagement_telemetry table.
 *
 * @module telemetry-storage
 * @author Harrison Cook
 */

import * as crypto from "crypto";
import * as fs from "fs/promises";
import * as path from "path";
import type { StorageProvider, StorageProviderConfig, TelemetryContext } from "./telemetry-logger";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface StorageResult {
  key: string;
  url?: string;
  provider: StorageProvider;
  sizeBytes: number;
  contentHash: string;
}

export interface StorageClient {
  provider: StorageProvider;
  put(key: string, data: Buffer | string, contentType?: string): Promise<StorageResult>;
  get(key: string): Promise<Buffer | null>;
  exists(key: string): Promise<boolean>;
  delete(key: string): Promise<boolean>;
  listPrefix(prefix: string, limit?: number): Promise<string[]>;
}

// ─── DO Spaces Client ───────────────────────────────────────────────────────

/**
 * DigitalOcean Spaces storage client (S3-compatible API).
 * Uses raw HTTPS requests with AWS Signature V4 for zero-dependency operation.
 */
export class DOSpacesClient implements StorageClient {
  provider: StorageProvider = "do_spaces";
  private endpoint: string;
  private bucket: string;
  private region: string;
  private accessKey: string;
  private secretKey: string;

  constructor(config: NonNullable<StorageProviderConfig["doSpaces"]>) {
    this.endpoint = config.endpoint;
    this.bucket = config.bucket;
    this.region = config.region;
    this.accessKey = config.accessKey;
    this.secretKey = config.secretKey;
  }

  async put(key: string, data: Buffer | string, contentType = "application/json"): Promise<StorageResult> {
    const body = typeof data === "string" ? Buffer.from(data, "utf-8") : data;
    const contentHash = crypto.createHash("sha256").update(body).digest("hex");
    const now = new Date();

    const url = `https://${this.bucket}.${this.endpoint}/${key}`;
    const headers = this.signRequest("PUT", key, body, contentType, now);

    const res = await fetch(url, {
      method: "PUT",
      headers: { ...headers, "Content-Type": contentType },
      body,
    });

    if (!res.ok) {
      const errBody = await res.text();
      throw new Error(`DO Spaces PUT failed (${res.status}): ${errBody.substring(0, 200)}`);
    }

    return {
      key,
      url: `https://${this.bucket}.${this.endpoint}/${key}`,
      provider: "do_spaces",
      sizeBytes: body.length,
      contentHash,
    };
  }

  async get(key: string): Promise<Buffer | null> {
    const url = `https://${this.bucket}.${this.endpoint}/${key}`;
    const headers = this.signRequest("GET", key, Buffer.alloc(0), "", new Date());

    const res = await fetch(url, { method: "GET", headers });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`DO Spaces GET failed (${res.status})`);

    const arrayBuf = await res.arrayBuffer();
    return Buffer.from(arrayBuf);
  }

  async exists(key: string): Promise<boolean> {
    const url = `https://${this.bucket}.${this.endpoint}/${key}`;
    const headers = this.signRequest("HEAD", key, Buffer.alloc(0), "", new Date());

    const res = await fetch(url, { method: "HEAD", headers });
    return res.ok;
  }

  async delete(key: string): Promise<boolean> {
    const url = `https://${this.bucket}.${this.endpoint}/${key}`;
    const headers = this.signRequest("DELETE", key, Buffer.alloc(0), "", new Date());

    const res = await fetch(url, { method: "DELETE", headers });
    return res.ok || res.status === 404;
  }

  async listPrefix(prefix: string, limit = 100): Promise<string[]> {
    const url = `https://${this.bucket}.${this.endpoint}/?prefix=${encodeURIComponent(prefix)}&max-keys=${limit}`;
    const headers = this.signRequest("GET", "", Buffer.alloc(0), "", new Date(), `?prefix=${encodeURIComponent(prefix)}&max-keys=${limit}`);

    const res = await fetch(url, { method: "GET", headers });
    if (!res.ok) return [];

    const xml = await res.text();
    const keys: string[] = [];
    const regex = /<Key>([^<]+)<\/Key>/g;
    let match;
    while ((match = regex.exec(xml)) !== null) {
      keys.push(match[1]);
    }
    return keys;
  }

  /**
   * AWS Signature V4 signing for S3-compatible APIs.
   */
  private signRequest(
    method: string,
    key: string,
    body: Buffer,
    contentType: string,
    date: Date,
    queryString = "",
  ): Record<string, string> {
    const dateStamp = date.toISOString().replace(/[-:]/g, "").split(".")[0] + "Z";
    const shortDate = dateStamp.substring(0, 8);
    const payloadHash = crypto.createHash("sha256").update(body).digest("hex");

    const host = `${this.bucket}.${this.endpoint}`;
    const canonicalUri = `/${key}`;
    const canonicalQueryString = queryString.startsWith("?") ? queryString.substring(1) : queryString;

    const signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date";
    const canonicalHeaders = [
      `content-type:${contentType || "application/octet-stream"}`,
      `host:${host}`,
      `x-amz-content-sha256:${payloadHash}`,
      `x-amz-date:${dateStamp}`,
    ].join("\n") + "\n";

    const canonicalRequest = [
      method,
      canonicalUri,
      canonicalQueryString,
      canonicalHeaders,
      signedHeaders,
      payloadHash,
    ].join("\n");

    const credentialScope = `${shortDate}/${this.region}/s3/aws4_request`;
    const stringToSign = [
      "AWS4-HMAC-SHA256",
      dateStamp,
      credentialScope,
      crypto.createHash("sha256").update(canonicalRequest).digest("hex"),
    ].join("\n");

    const signingKey = this.getSignatureKey(shortDate);
    const signature = crypto.createHmac("sha256", signingKey).update(stringToSign).digest("hex");

    const authorization = `AWS4-HMAC-SHA256 Credential=${this.accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    return {
      Authorization: authorization,
      "x-amz-date": dateStamp,
      "x-amz-content-sha256": payloadHash,
      "Content-Type": contentType || "application/octet-stream",
      Host: host,
    };
  }

  private getSignatureKey(dateStamp: string): Buffer {
    const kDate = crypto.createHmac("sha256", `AWS4${this.secretKey}`).update(dateStamp).digest();
    const kRegion = crypto.createHmac("sha256", kDate).update(this.region).digest();
    const kService = crypto.createHmac("sha256", kRegion).update("s3").digest();
    return crypto.createHmac("sha256", kService).update("aws4_request").digest();
  }
}

// ─── AWS S3 Client ──────────────────────────────────────────────────────────

/**
 * AWS S3 storage client.
 * Uses the same AWS Signature V4 approach as DO Spaces (they're S3-compatible).
 */
export class AWSS3Client implements StorageClient {
  provider: StorageProvider = "aws_s3";
  private bucket: string;
  private region: string;
  private accessKeyId: string;
  private secretAccessKey: string;

  constructor(config: NonNullable<StorageProviderConfig["awsS3"]>) {
    this.bucket = config.bucket;
    this.region = config.region;
    this.accessKeyId = config.accessKeyId;
    this.secretAccessKey = config.secretAccessKey;
  }

  async put(key: string, data: Buffer | string, contentType = "application/json"): Promise<StorageResult> {
    const body = typeof data === "string" ? Buffer.from(data, "utf-8") : data;
    const contentHash = crypto.createHash("sha256").update(body).digest("hex");
    const now = new Date();

    const host = `${this.bucket}.s3.${this.region}.amazonaws.com`;
    const url = `https://${host}/${key}`;
    const headers = this.signRequest("PUT", key, body, contentType, now, host);

    const res = await fetch(url, {
      method: "PUT",
      headers: { ...headers, "Content-Type": contentType },
      body,
    });

    if (!res.ok) {
      const errBody = await res.text();
      throw new Error(`AWS S3 PUT failed (${res.status}): ${errBody.substring(0, 200)}`);
    }

    return {
      key,
      url: `https://${host}/${key}`,
      provider: "aws_s3",
      sizeBytes: body.length,
      contentHash,
    };
  }

  async get(key: string): Promise<Buffer | null> {
    const host = `${this.bucket}.s3.${this.region}.amazonaws.com`;
    const url = `https://${host}/${key}`;
    const headers = this.signRequest("GET", key, Buffer.alloc(0), "", new Date(), host);

    const res = await fetch(url, { method: "GET", headers });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`AWS S3 GET failed (${res.status})`);

    const arrayBuf = await res.arrayBuffer();
    return Buffer.from(arrayBuf);
  }

  async exists(key: string): Promise<boolean> {
    const host = `${this.bucket}.s3.${this.region}.amazonaws.com`;
    const url = `https://${host}/${key}`;
    const headers = this.signRequest("HEAD", key, Buffer.alloc(0), "", new Date(), host);

    const res = await fetch(url, { method: "HEAD", headers });
    return res.ok;
  }

  async delete(key: string): Promise<boolean> {
    const host = `${this.bucket}.s3.${this.region}.amazonaws.com`;
    const url = `https://${host}/${key}`;
    const headers = this.signRequest("DELETE", key, Buffer.alloc(0), "", new Date(), host);

    const res = await fetch(url, { method: "DELETE", headers });
    return res.ok || res.status === 404;
  }

  async listPrefix(prefix: string, limit = 100): Promise<string[]> {
    const host = `${this.bucket}.s3.${this.region}.amazonaws.com`;
    const url = `https://${host}/?prefix=${encodeURIComponent(prefix)}&max-keys=${limit}`;
    const headers = this.signRequest("GET", "", Buffer.alloc(0), "", new Date(), host, `prefix=${encodeURIComponent(prefix)}&max-keys=${limit}`);

    const res = await fetch(url, { method: "GET", headers });
    if (!res.ok) return [];

    const xml = await res.text();
    const keys: string[] = [];
    const regex = /<Key>([^<]+)<\/Key>/g;
    let match;
    while ((match = regex.exec(xml)) !== null) {
      keys.push(match[1]);
    }
    return keys;
  }

  private signRequest(
    method: string,
    key: string,
    body: Buffer,
    contentType: string,
    date: Date,
    host: string,
    queryString = "",
  ): Record<string, string> {
    const dateStamp = date.toISOString().replace(/[-:]/g, "").split(".")[0] + "Z";
    const shortDate = dateStamp.substring(0, 8);
    const payloadHash = crypto.createHash("sha256").update(body).digest("hex");

    const canonicalUri = `/${key}`;
    const signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date";
    const canonicalHeaders = [
      `content-type:${contentType || "application/octet-stream"}`,
      `host:${host}`,
      `x-amz-content-sha256:${payloadHash}`,
      `x-amz-date:${dateStamp}`,
    ].join("\n") + "\n";

    const canonicalRequest = [
      method,
      canonicalUri,
      queryString,
      canonicalHeaders,
      signedHeaders,
      payloadHash,
    ].join("\n");

    const credentialScope = `${shortDate}/${this.region}/s3/aws4_request`;
    const stringToSign = [
      "AWS4-HMAC-SHA256",
      dateStamp,
      credentialScope,
      crypto.createHash("sha256").update(canonicalRequest).digest("hex"),
    ].join("\n");

    const kDate = crypto.createHmac("sha256", `AWS4${this.secretAccessKey}`).update(shortDate).digest();
    const kRegion = crypto.createHmac("sha256", kDate).update(this.region).digest();
    const kService = crypto.createHmac("sha256", kRegion).update("s3").digest();
    const signingKey = crypto.createHmac("sha256", kService).update("aws4_request").digest();
    const signature = crypto.createHmac("sha256", signingKey).update(stringToSign).digest("hex");

    const authorization = `AWS4-HMAC-SHA256 Credential=${this.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    return {
      Authorization: authorization,
      "x-amz-date": dateStamp,
      "x-amz-content-sha256": payloadHash,
      "Content-Type": contentType || "application/octet-stream",
      Host: host,
    };
  }
}

// ─── Local Filesystem Client ────────────────────────────────────────────────

/**
 * Local filesystem storage client for dev/test environments.
 */
export class LocalStorageClient implements StorageClient {
  provider: StorageProvider = "local";
  private basePath: string;

  constructor(basePath?: string) {
    this.basePath = basePath || "/tmp/ac3-telemetry";
  }

  async put(key: string, data: Buffer | string, _contentType?: string): Promise<StorageResult> {
    const body = typeof data === "string" ? Buffer.from(data, "utf-8") : data;
    const contentHash = crypto.createHash("sha256").update(body).digest("hex");
    const filePath = path.join(this.basePath, key);

    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, body);

    return {
      key,
      url: `file://${filePath}`,
      provider: "local",
      sizeBytes: body.length,
      contentHash,
    };
  }

  async get(key: string): Promise<Buffer | null> {
    const filePath = path.join(this.basePath, key);
    try {
      return await fs.readFile(filePath);
    } catch {
      return null;
    }
  }

  async exists(key: string): Promise<boolean> {
    const filePath = path.join(this.basePath, key);
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }

  async delete(key: string): Promise<boolean> {
    const filePath = path.join(this.basePath, key);
    try {
      await fs.unlink(filePath);
      return true;
    } catch {
      return false;
    }
  }

  async listPrefix(prefix: string, limit = 100): Promise<string[]> {
    const dirPath = path.join(this.basePath, path.dirname(prefix));
    try {
      const files = await fs.readdir(dirPath, { recursive: true });
      return files
        .map((f) => path.join(path.dirname(prefix), f as string))
        .filter((f) => f.startsWith(prefix))
        .slice(0, limit);
    } catch {
      return [];
    }
  }
}

// ─── Factory ────────────────────────────────────────────────────────────────

/**
 * Create a storage client from the provider config.
 */
export function createStorageClient(config: StorageProviderConfig): StorageClient | null {
  switch (config.provider) {
    case "do_spaces":
      if (!config.doSpaces) return null;
      return new DOSpacesClient(config.doSpaces);
    case "aws_s3":
      if (!config.awsS3) return null;
      return new AWSS3Client(config.awsS3);
    case "local":
      return new LocalStorageClient(config.localPath);
    case "none":
      return null;
  }
}

/**
 * Create a storage client from environment variables.
 * Auto-detects which provider is configured.
 */
export function createStorageClientFromEnv(): { client: StorageClient | null; config: StorageProviderConfig } {
  // Check DO Spaces first
  const doEndpoint = process.env.DO_SPACES_ENDPOINT;
  const doBucket = process.env.DO_SPACES_BUCKET;
  const doRegion = process.env.DO_SPACES_REGION;
  const doKey = process.env.DO_SPACES_KEY;
  const doSecret = process.env.DO_SPACES_SECRET;

  if (doEndpoint && doBucket && doKey && doSecret) {
    const config: StorageProviderConfig = {
      provider: "do_spaces",
      doSpaces: {
        endpoint: doEndpoint,
        bucket: doBucket,
        region: doRegion || "nyc3",
        accessKey: doKey,
        secretKey: doSecret,
      },
    };
    return { client: new DOSpacesClient(config.doSpaces!), config };
  }

  // Check AWS S3
  const awsBucket = process.env.AWS_S3_TELEMETRY_BUCKET || process.env.AWS_S3_BUCKET;
  const awsRegion = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION;
  const awsKey = process.env.AWS_ACCESS_KEY_ID;
  const awsSecret = process.env.AWS_SECRET_ACCESS_KEY;

  if (awsBucket && awsRegion && awsKey && awsSecret) {
    const config: StorageProviderConfig = {
      provider: "aws_s3",
      awsS3: {
        bucket: awsBucket,
        region: awsRegion,
        accessKeyId: awsKey,
        secretAccessKey: awsSecret,
      },
    };
    return { client: new AWSS3Client(config.awsS3!), config };
  }

  // Fallback to local
  const localPath = process.env.TELEMETRY_LOCAL_PATH || "/tmp/ac3-telemetry";
  const config: StorageProviderConfig = { provider: "local", localPath };
  return { client: new LocalStorageClient(localPath), config };
}

// ─── Payload Archival ───────────────────────────────────────────────────────

const PAYLOAD_SIZE_THRESHOLD = 2048; // 2KB — payloads larger than this get archived

/**
 * Archive a full payload to cloud storage if it exceeds the threshold.
 * Returns the storage key (or null if below threshold).
 */
export async function archivePayload(
  ctx: TelemetryContext,
  payload: string | Buffer,
  opts: {
    category: "request" | "response" | "evidence" | "diagnostic";
    step: string;
    engagementId: number;
  },
): Promise<string | null> {
  const data = typeof payload === "string" ? Buffer.from(payload, "utf-8") : payload;
  if (data.length < PAYLOAD_SIZE_THRESHOLD) return null;

  const client = createStorageClient(ctx.storageConfig);
  if (!client) return null;

  const timestamp = new Date().toISOString().replace(/[-:]/g, "").split(".")[0];
  const hash = crypto.createHash("sha256").update(data).digest("hex").substring(0, 8);
  const key = `telemetry/${opts.engagementId}/${opts.category}/${opts.step}_${timestamp}_${hash}.json`;

  try {
    const result = await client.put(key, data, "application/json");
    return result.key;
  } catch (err: any) {
    console.error(`[Telemetry Storage] Failed to archive payload: ${err.message}`);
    return null;
  }
}

/**
 * Retrieve an archived payload by key.
 */
export async function retrievePayload(ctx: TelemetryContext, key: string): Promise<string | null> {
  const client = createStorageClient(ctx.storageConfig);
  if (!client) return null;

  try {
    const data = await client.get(key);
    return data ? data.toString("utf-8") : null;
  } catch {
    return null;
  }
}

/**
 * Get the configured storage provider info for display.
 */
export function getStorageProviderInfo(config: StorageProviderConfig): {
  provider: StorageProvider;
  endpoint: string;
  bucket: string;
  region: string;
} {
  switch (config.provider) {
    case "do_spaces":
      return {
        provider: "do_spaces",
        endpoint: config.doSpaces?.endpoint || "",
        bucket: config.doSpaces?.bucket || "",
        region: config.doSpaces?.region || "",
      };
    case "aws_s3":
      return {
        provider: "aws_s3",
        endpoint: `s3.${config.awsS3?.region}.amazonaws.com`,
        bucket: config.awsS3?.bucket || "",
        region: config.awsS3?.region || "",
      };
    case "local":
      return {
        provider: "local",
        endpoint: "filesystem",
        bucket: config.localPath || "/tmp/ac3-telemetry",
        region: "local",
      };
    default:
      return { provider: "none", endpoint: "", bucket: "", region: "" };
  }
}
