/**
 * DigitalOcean Spaces Storage Helper
 *
 * Drop-in replacement for the built-in storagePut/storageGet that writes to
 * the aceofcloud-reports DO Space instead of the Manus-managed S3 proxy.
 *
 * All generated reports, PDFs, DOCX exports, ROE documents, evidence artifacts,
 * and file transfers are stored here for full ownership and persistence.
 */

import { S3Client, PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import { ENV } from "./_core/env";

// ─── Client Singleton ───────────────────────────────────────────────────────

let _client: S3Client | null = null;

function getClient(): S3Client {
  if (_client) return _client;

  const endpoint = ENV.DO_SPACES_ENDPOINT;
  const region = ENV.DO_SPACES_REGION;
  const accessKeyId = ENV.DO_SPACES_KEY;
  const secretAccessKey = ENV.DO_SPACES_SECRET;

  if (!accessKeyId || !secretAccessKey) {
    throw new Error(
      "DO Spaces credentials missing: set DO_SPACES_KEY and DO_SPACES_SECRET"
    );
  }

  _client = new S3Client({
    endpoint,
    region,
    credentials: { accessKeyId, secretAccessKey },
    forcePathStyle: false, // DO Spaces uses virtual-hosted style
  });

  return _client;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function normalizeKey(relKey: string): string {
  return relKey.replace(/^\/+/, "");
}

function buildPublicUrl(key: string): string {
  const bucket = ENV.DO_SPACES_BUCKET;
  const region = ENV.DO_SPACES_REGION;
  return `https://${bucket}.${region}.digitaloceanspaces.com/${key}`;
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Upload a file to DigitalOcean Spaces.
 * Returns the normalized key and a public URL.
 *
 * Files are uploaded with public-read ACL so the returned URL works without
 * additional signing — matching the behaviour of the old S3 proxy.
 */
export async function doStoragePut(
  relKey: string,
  data: Buffer | Uint8Array | string,
  contentType = "application/octet-stream"
): Promise<{ key: string; url: string }> {
  const client = getClient();
  const key = normalizeKey(relKey);
  const bucket = ENV.DO_SPACES_BUCKET;

  const body =
    typeof data === "string" ? Buffer.from(data, "utf-8") : data;

  await client.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: body,
      ContentType: contentType,
      ACL: "public-read",
    })
  );

  const url = buildPublicUrl(key);
  return { key, url };
}

/**
 * Get the public URL for an existing key in DO Spaces.
 * (No presigning needed — bucket objects are public-read.)
 */
export async function doStorageGet(
  relKey: string
): Promise<{ key: string; url: string }> {
  const key = normalizeKey(relKey);
  return { key, url: buildPublicUrl(key) };
}
