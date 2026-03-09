/**
 * Cloud Asset Discovery Connector — S3 / Azure / GCP Bucket Enumeration
 *
 * Probes common cloud storage naming patterns to identify publicly
 * accessible or misconfigured cloud assets. Covers Red Team Top-10 #8.
 *
 * Method: HTTP HEAD requests to cloud storage endpoints (passive probing)
 * Data Source: AWS S3, Azure Blob Storage, Google Cloud Storage public endpoints
 * Free: Yes, no API key required
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

function generateCandidates(domain: string): string[] {
  const parts = domain.split(".");
  const orgName = parts[0];
  const orgNameClean = orgName.replace(/[^a-z0-9]/gi, "");
  const suffixes = ["", "-backup", "-backups", "-dev", "-staging", "-prod", "-production", "-assets", "-static", "-media", "-uploads", "-data", "-logs", "-public", "-private", "-internal", "-docs", "-files", "-cdn", "-images", "-web", "-api", "-config"];
  const candidates: string[] = [];
  for (const suffix of suffixes) {
    candidates.push(`${orgNameClean}${suffix}`);
    if (orgName !== orgNameClean) candidates.push(`${orgName}${suffix}`);
  }
  const domainClean = domain.replace(/\./g, "-");
  candidates.push(domainClean, `${domainClean}-backup`, `${domainClean}-assets`);
  return Array.from(new Set(candidates.map(c => c.toLowerCase())));
}

interface BucketProbeResult {
  provider: "aws" | "azure" | "gcp";
  bucketName: string;
  url: string;
  status: "public" | "exists_private" | "not_found" | "error";
  statusCode?: number;
}

async function probeBucket(candidate: string, provider: "aws" | "azure" | "gcp", timeout: number, externalSignal?: AbortSignal): Promise<BucketProbeResult> {
  const url = provider === "aws" ? `https://${candidate}.s3.amazonaws.com/`
    : provider === "azure" ? `https://${candidate}.blob.core.windows.net/`
    : `https://storage.googleapis.com/${candidate}/`;
  const controller = new AbortController();
  // Link external abort signal to this controller
  if (externalSignal?.aborted) return { provider, bucketName: candidate, url, status: "error" };
  const onAbort = () => controller.abort();
  externalSignal?.addEventListener('abort', onAbort, { once: true });
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, { method: "HEAD", signal: controller.signal, redirect: "follow" });
    clearTimeout(timer);
    externalSignal?.removeEventListener('abort', onAbort);
    if (res.status === 200) return { provider, bucketName: candidate, url, status: "public", statusCode: 200 };
    if (res.status === 403) return { provider, bucketName: candidate, url, status: "exists_private", statusCode: 403 };
    return { provider, bucketName: candidate, url, status: res.status === 404 ? "not_found" : "error", statusCode: res.status };
  } catch {
    clearTimeout(timer);
    externalSignal?.removeEventListener('abort', onAbort);
    return { provider, bucketName: candidate, url, status: "error" };
  }
}

export const cloudAssetsConnector: PassiveConnector = {
  name: "cloud_assets",
  description: "Cloud storage enumeration — probes S3, Azure Blob, and GCP Storage for publicly accessible or misconfigured buckets",
  requiresApiKey: false,
  freeUrl: "https://buckets.grayhatwarfare.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 5000;
    const now = new Date();

    try {
      const candidates = generateCandidates(domain);
      const providers: Array<"aws" | "azure" | "gcp"> = ["aws", "azure", "gcp"];
      const allProbes: Array<{ candidate: string; provider: "aws" | "azure" | "gcp" }> = [];
      for (const candidate of candidates.slice(0, 20)) {
        for (const provider of providers) allProbes.push({ candidate, provider });
      }

      const results: BucketProbeResult[] = [];
      const externalSignal = config?.signal;
      for (let i = 0; i < allProbes.length; i += 10) {
        // Check if externally aborted before starting next batch
        if (externalSignal?.aborted) break;
        const batch = allProbes.slice(i, i + 10);
        const batchResults = await Promise.allSettled(batch.map(p => probeBucket(p.candidate, p.provider, timeout, externalSignal)));
        for (const r of batchResults) { if (r.status === "fulfilled") results.push(r.value); }
      }

      const found = results.filter(r => r.status === "public" || r.status === "exists_private");
      for (const bucket of found) {
        const isPublic = bucket.status === "public";
        const providerLabel = bucket.provider === "aws" ? "AWS S3" : bucket.provider === "azure" ? "Azure Blob" : "Google Cloud Storage";
        observations.push({
          assetId: makeAssetId(domain, `cloud:${bucket.provider}:${bucket.bucketName}`, "cloud_assets"),
          domain, assetType: "url",
          name: `${providerLabel}: ${bucket.bucketName} (${isPublic ? "PUBLIC" : "private"})`,
          source: "cloud_assets", observedAt: now,
          tags: ["cloud_asset", `provider:${bucket.provider}`, isPublic ? "public_bucket" : "private_bucket", ...(isPublic ? ["critical_misconfiguration", "data_exposure_risk"] : [])],
          evidence: { bucketName: bucket.bucketName, provider: bucket.provider, url: bucket.url, status: bucket.status, statusCode: bucket.statusCode },
          attribution: { provider: `${providerLabel} Bucket Probe`, url: bucket.url, method: `Probed ${providerLabel} endpoint for bucket named '${bucket.bucketName}' derived from domain ${domain}`, verifyUrl: bucket.url },
        });
      }

      const publicCount = found.filter(r => r.status === "public").length;
      const privateCount = found.filter(r => r.status === "exists_private").length;
      observations.push({
        assetId: makeAssetId(domain, `cloud_summary:${domain}`, "cloud_assets"),
        domain, assetType: "url",
        name: `Cloud Storage: ${found.length} buckets found (${publicCount} public, ${privateCount} private) from ${results.length} probes`,
        source: "cloud_assets", observedAt: now,
        tags: ["cloud_asset", "cloud_summary", ...(publicCount > 0 ? ["public_buckets_found", "critical_misconfiguration"] : [])],
        evidence: { totalProbed: results.length, totalFound: found.length, publicCount, privateCount, candidatesChecked: candidates.slice(0, 20), providersChecked: providers },
        attribution: { provider: "Cloud Storage Enumeration", method: `Probed ${results.length} cloud storage endpoints (S3, Azure Blob, GCP) using ${candidates.slice(0, 20).length} naming patterns derived from ${domain}` },
      });
    } catch (err: any) {
      errors.push(`Cloud asset discovery error: ${err.message}`);
    }

    return { connector: "cloud_assets", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
  },
};
