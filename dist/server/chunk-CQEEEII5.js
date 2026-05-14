import {
  ENV,
  init_env
} from "./chunk-GN2OC6SU.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/do-storage.ts
import { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { randomBytes, createCipheriv, createDecipheriv, createHash } from "crypto";
function resolveConfig() {
  const s3Endpoint = process.env.S3_ENDPOINT;
  const s3Region = process.env.S3_REGION;
  const s3AccessKey = process.env.S3_ACCESS_KEY;
  const s3SecretKey = process.env.S3_SECRET_KEY;
  const s3Bucket = process.env.S3_BUCKET;
  if (s3AccessKey && s3SecretKey && s3Endpoint) {
    const forcePathStyle = process.env.S3_FORCE_PATH_STYLE === "true";
    const publicUrlBase = process.env.S3_PUBLIC_URL_BASE || null;
    const provider = detectProvider(s3Endpoint);
    const sseAlgorithm = process.env.S3_SSE_ALGORITHM || "none";
    const sseKmsKeyId = process.env.S3_SSE_KMS_KEY_ID || null;
    const bucketKeyEnabled = process.env.S3_BUCKET_KEY_ENABLED === "true";
    const privateMode = process.env.S3_PRIVATE_MODE === "true" || sseAlgorithm !== "none";
    const region = s3Region || "us-east-1";
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
      fipsEndpoint
    };
  }
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
    sseAlgorithm: "none",
    sseKmsKeyId: null,
    bucketKeyEnabled: false,
    privateMode: false,
    useFips: false,
    fipsEndpoint: null
  };
}
function detectProvider(endpoint) {
  if (endpoint.includes("digitaloceanspaces.com")) return "do_spaces";
  if (endpoint.includes("amazonaws.com")) return "aws_s3";
  if (endpoint.includes("minio") || endpoint.includes("localhost") || endpoint.includes("127.0.0.1")) return "minio";
  return "custom";
}
function resolveFipsMode(envValue, region) {
  if (envValue === "true") return true;
  if (envValue === "false") return false;
  if (region.startsWith("us-gov-")) return true;
  if (region === "us-iso-east-1" || region === "us-isob-east-1") return true;
  return false;
}
function resolveFipsEndpoint(endpoint, region) {
  if (endpoint.includes("-fips") || endpoint.includes("fips.")) {
    return endpoint;
  }
  if (!endpoint.includes("amazonaws.com")) {
    return null;
  }
  return `https://s3-fips.${region}.amazonaws.com`;
}
function getEffectiveEndpoint(config) {
  if (config.useFips && config.fipsEndpoint) {
    return config.fipsEndpoint;
  }
  return config.endpoint;
}
function getConfig() {
  if (_config) return _config;
  _config = resolveConfig();
  return _config;
}
function getClient() {
  if (_client) return _client;
  const config = getConfig();
  if (!config.accessKeyId || !config.secretAccessKey) {
    throw new Error(
      "S3 storage credentials missing. Set S3_ACCESS_KEY/S3_SECRET_KEY (preferred) or DO_SPACES_KEY/DO_SPACES_SECRET (legacy). See server/do-storage.ts header for full configuration guide."
    );
  }
  const effectiveEndpoint = getEffectiveEndpoint(config);
  _client = new S3Client({
    endpoint: effectiveEndpoint,
    region: config.region,
    credentials: {
      accessKeyId: config.accessKeyId,
      secretAccessKey: config.secretAccessKey
    },
    forcePathStyle: config.forcePathStyle,
    // AWS SDK v3: useFipsEndpoint ensures all derived service endpoints use FIPS
    ...config.useFips ? { useFipsEndpoint: true } : {}
  });
  return _client;
}
function resetStorageClient() {
  _client = null;
  _config = null;
}
function buildPublicUrl(key) {
  const config = getConfig();
  if (config.publicUrlBase) {
    const base = config.publicUrlBase.replace(/\/+$/, "");
    return `${base}/${key}`;
  }
  switch (config.provider) {
    case "do_spaces":
      return `https://${config.bucket}.${config.region}.digitaloceanspaces.com/${key}`;
    case "aws_s3":
      return `https://${config.bucket}.s3.${config.region}.amazonaws.com/${key}`;
    case "minio":
      const endpoint = config.endpoint.replace(/\/+$/, "");
      return `${endpoint}/${config.bucket}/${key}`;
    case "custom":
    default:
      if (config.forcePathStyle) {
        const ep = config.endpoint.replace(/\/+$/, "");
        return `${ep}/${config.bucket}/${key}`;
      }
      const url = new URL(config.endpoint);
      return `${url.protocol}//${config.bucket}.${url.host}/${key}`;
  }
}
function normalizeKey(relKey) {
  return relKey.replace(/^\/+/, "");
}
async function doStoragePut(relKey, data, contentType = "application/octet-stream") {
  const client = getClient();
  const config = getConfig();
  const key = normalizeKey(relKey);
  const body = typeof data === "string" ? Buffer.from(data, "utf-8") : data;
  const putParams = {
    Bucket: config.bucket,
    Key: key,
    Body: body,
    ContentType: contentType
  };
  if (!config.privateMode) {
    putParams.ACL = "public-read";
  }
  if (config.sseAlgorithm !== "none") {
    putParams.ServerSideEncryption = config.sseAlgorithm;
    if ((config.sseAlgorithm === "aws:kms" || config.sseAlgorithm === "aws:kms:dsse") && config.sseKmsKeyId) {
      putParams.SSEKMSKeyId = config.sseKmsKeyId;
    }
    if (config.bucketKeyEnabled) {
      putParams.BucketKeyEnabled = true;
    }
  }
  await client.send(new PutObjectCommand(putParams));
  if (config.privateMode) {
    const getCmd = new GetObjectCommand({ Bucket: config.bucket, Key: key });
    const url2 = await getSignedUrl(client, getCmd, { expiresIn: 3600 });
    return { key, url: url2 };
  }
  const url = buildPublicUrl(key);
  return { key, url };
}
async function doStorageGet(relKey) {
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
async function doStorageGetSigned(relKey, expiresIn = 3600) {
  const client = getClient();
  const config = getConfig();
  const key = normalizeKey(relKey);
  const command = new GetObjectCommand({
    Bucket: config.bucket,
    Key: key
  });
  const url = await getSignedUrl(client, command, { expiresIn });
  return { key, url };
}
async function doStorageExists(relKey) {
  const client = getClient();
  const config = getConfig();
  const key = normalizeKey(relKey);
  try {
    await client.send(
      new HeadObjectCommand({
        Bucket: config.bucket,
        Key: key
      })
    );
    return true;
  } catch {
    return false;
  }
}
async function doStorageGetContent(relKey) {
  const client = getClient();
  const config = getConfig();
  const key = normalizeKey(relKey);
  try {
    const response = await client.send(
      new GetObjectCommand({ Bucket: config.bucket, Key: key })
    );
    const data = await streamToBuffer(response.Body);
    return { key, data, contentType: response.ContentType || "application/octet-stream" };
  } catch (err) {
    if (err.name === "NoSuchKey" || err.$metadata?.httpStatusCode === 404) {
      return null;
    }
    throw err;
  }
}
async function doStorageDelete(relKey) {
  const client = getClient();
  const config = getConfig();
  const key = normalizeKey(relKey);
  await client.send(
    new DeleteObjectCommand({
      Bucket: config.bucket,
      Key: key
    })
  );
}
function getStorageInfo() {
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
      bucketKeyEnabled: config.bucketKeyEnabled
    },
    privateMode: config.privateMode,
    fips: {
      enabled: config.useFips,
      endpoint: config.fipsEndpoint,
      autoDetected: config.useFips && !process.env.S3_USE_FIPS
    }
  };
}
function resolveCSEConfig() {
  const enabled = process.env.S3_CSE_ENABLED === "true";
  const keyArn = process.env.S3_CSE_KEY_ARN || "";
  if (!enabled || !keyArn) {
    return { enabled: false, keyArn: "", localKey: null };
  }
  if (keyArn.startsWith("arn:aws:kms:") || keyArn.startsWith("arn:aws-us-gov:kms:")) {
    return { enabled: true, keyArn, localKey: null };
  }
  const localKey = createHash("sha256").update(keyArn).digest();
  return { enabled: true, keyArn: `local:${createHash("md5").update(keyArn).digest("hex").slice(0, 8)}`, localKey };
}
function getCSEConfig() {
  if (_cseConfig) return _cseConfig;
  _cseConfig = resolveCSEConfig();
  return _cseConfig;
}
function resetCSEConfig() {
  _cseConfig = null;
}
function wrapDataKey(dek, config) {
  if (config.localKey) {
    const wrapIv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", config.localKey, wrapIv);
    const encrypted = Buffer.concat([cipher.update(dek), cipher.final()]);
    const tag = cipher.getAuthTag();
    const packed = Buffer.concat([wrapIv, tag, encrypted]);
    return { encryptedDEK: packed, keyId: config.keyArn };
  }
  throw new Error(
    "KMS-based CSE requires @aws-sdk/client-kms. Set S3_CSE_KEY_ARN to a local passphrase for development, or install @aws-sdk/client-kms for production KMS integration."
  );
}
function unwrapDataKey(encryptedDEK, keyId, config) {
  if (config.localKey) {
    const wrapIv = encryptedDEK.subarray(0, 12);
    const tag = encryptedDEK.subarray(12, 28);
    const ciphertext = encryptedDEK.subarray(28);
    const decipher = createDecipheriv("aes-256-gcm", config.localKey, wrapIv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }
  throw new Error(
    `KMS unwrap not implemented. Key ID: ${keyId}. Install @aws-sdk/client-kms for production KMS integration.`
  );
}
async function doStoragePutEncrypted(relKey, data, contentType = "application/octet-stream") {
  const cseConfig = getCSEConfig();
  if (!cseConfig.enabled) {
    throw new Error(
      "Client-Side Encryption is not enabled. Set S3_CSE_ENABLED=true and S3_CSE_KEY_ARN to enable."
    );
  }
  const plaintext = typeof data === "string" ? Buffer.from(data, "utf-8") : Buffer.from(data);
  const dek = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", dek, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const { encryptedDEK, keyId } = wrapDataKey(dek, cseConfig);
  const metadata = {
    algorithm: "aes-256-gcm",
    iv: iv.toString("base64"),
    encryptedDEK: encryptedDEK.toString("base64"),
    authTag: authTag.toString("base64"),
    keyId,
    version: "1"
  };
  const { key, url } = await doStoragePut(relKey, ciphertext, "application/octet-stream");
  const metaKey = `${key}.cse-meta.json`;
  const metaPayload = JSON.stringify({
    ...metadata,
    originalContentType: contentType,
    encryptedAt: (/* @__PURE__ */ new Date()).toISOString()
  });
  await doStoragePut(metaKey, metaPayload, "application/json");
  dek.fill(0);
  return { key, url, metadata };
}
async function doStorageGetDecrypted(relKey) {
  const cseConfig = getCSEConfig();
  if (!cseConfig.enabled) {
    throw new Error(
      "Client-Side Encryption is not enabled. Set S3_CSE_ENABLED=true and S3_CSE_KEY_ARN to enable."
    );
  }
  const key = normalizeKey(relKey);
  const client = getClient();
  const config = getConfig();
  const metaKey = `${key}.cse-meta.json`;
  const metaResponse = await client.send(
    new GetObjectCommand({ Bucket: config.bucket, Key: metaKey })
  );
  const metaBody = await streamToBuffer(metaResponse.Body);
  const metaJson = JSON.parse(metaBody.toString("utf-8"));
  const metadata = {
    algorithm: metaJson.algorithm,
    iv: metaJson.iv,
    encryptedDEK: metaJson.encryptedDEK,
    authTag: metaJson.authTag,
    keyId: metaJson.keyId,
    version: metaJson.version
  };
  const originalContentType = metaJson.originalContentType || "application/octet-stream";
  const dataResponse = await client.send(
    new GetObjectCommand({ Bucket: config.bucket, Key: key })
  );
  const ciphertext = await streamToBuffer(dataResponse.Body);
  const encryptedDEK = Buffer.from(metadata.encryptedDEK, "base64");
  const dek = unwrapDataKey(encryptedDEK, metadata.keyId, cseConfig);
  const iv = Buffer.from(metadata.iv, "base64");
  const authTag = Buffer.from(metadata.authTag, "base64");
  const decipher = createDecipheriv("aes-256-gcm", dek, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  dek.fill(0);
  return { key, data: plaintext, metadata, originalContentType };
}
function getCSEInfo() {
  const config = getCSEConfig();
  if (!config.enabled) {
    return { enabled: false, keyId: "", mode: "disabled" };
  }
  const mode = config.localKey ? "local" : "kms";
  return { enabled: true, keyId: config.keyArn, mode };
}
async function streamToBuffer(body) {
  if (Buffer.isBuffer(body)) return body;
  if (body instanceof Uint8Array) return Buffer.from(body);
  const chunks = [];
  for await (const chunk of body) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}
var _client, _config, _cseConfig;
var init_do_storage = __esm({
  "server/do-storage.ts"() {
    init_env();
    _client = null;
    _config = null;
    _cseConfig = null;
  }
});

export {
  resetStorageClient,
  doStoragePut,
  doStorageGet,
  doStorageGetSigned,
  doStorageExists,
  doStorageGetContent,
  doStorageDelete,
  getStorageInfo,
  resetCSEConfig,
  doStoragePutEncrypted,
  doStorageGetDecrypted,
  getCSEInfo,
  init_do_storage
};
