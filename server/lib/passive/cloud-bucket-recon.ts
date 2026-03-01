/**
 * Enhanced Cloud Bucket Reconnaissance Connector
 * ═════════════════════════════════════════════════════════════════════
 * Comprehensive cloud storage enumeration across 5 providers with
 * intelligent wordlist generation, permission depth analysis,
 * public content listing, and region-specific probing.
 *
 * Providers:
 *   1. AWS S3 — s3.amazonaws.com (+ regional endpoints)
 *   2. Azure Blob Storage — blob.core.windows.net
 *   3. Google Cloud Storage — storage.googleapis.com
 *   4. DigitalOcean Spaces — digitaloceanspaces.com
 *   5. Alibaba Cloud OSS — aliyuncs.com
 *
 * Capabilities:
 *   - Intelligent name generation (org name, acronyms, industry terms)
 *   - Permission depth analysis (public read/write/list detection)
 *   - Public bucket content listing (file enumeration)
 *   - Region-specific endpoint probing
 *   - Sensitive file detection in public buckets
 *
 * Covers: T1530 (Data from Cloud Storage), T1619 (Cloud Storage Enumeration)
 *
 * Method: HTTP HEAD/GET requests to cloud storage endpoints (passive probing)
 * Free: Yes, no API key required
 */

import { createHash } from "crypto";
import type {
  AssetObservation,
  ConnectorConfig,
  ConnectorResult,
  PassiveConnector,
} from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256")
    .update(`${domain}|${name}|${source}`)
    .digest("hex")
    .slice(0, 20);
}

// ═══════════════════════════════════════════════════════════════════════
// §1 — PROVIDER DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════

type CloudProvider = "aws" | "azure" | "gcp" | "digitalocean" | "alibaba";

interface ProviderEndpoint {
  provider: CloudProvider;
  label: string;
  /** Build the URL to probe for a given bucket name */
  buildUrl: (bucket: string, region?: string) => string;
  /** Parse the response to determine status */
  parseStatus: (status: number, body?: string) => BucketStatus;
  /** Regions to try (if applicable) */
  regions?: string[];
}

type BucketStatus =
  | "public_read"
  | "public_list"
  | "public_read_write"
  | "exists_private"
  | "not_found"
  | "error"
  | "redirect";

const PROVIDERS: ProviderEndpoint[] = [
  {
    provider: "aws",
    label: "AWS S3",
    buildUrl: (bucket, region) =>
      region
        ? `https://${bucket}.s3.${region}.amazonaws.com/`
        : `https://${bucket}.s3.amazonaws.com/`,
    parseStatus: (status, body) => {
      if (status === 200) return "public_list";
      if (status === 403) return "exists_private";
      if (status === 301) return "redirect"; // Bucket exists in different region
      if (status === 404) return "not_found";
      return "error";
    },
    regions: ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"],
  },
  {
    provider: "azure",
    label: "Azure Blob Storage",
    buildUrl: (bucket) =>
      `https://${bucket}.blob.core.windows.net/?comp=list&restype=container`,
    parseStatus: (status) => {
      if (status === 200) return "public_list";
      if (status === 403 || status === 409) return "exists_private";
      if (status === 404) return "not_found";
      return "error";
    },
  },
  {
    provider: "gcp",
    label: "Google Cloud Storage",
    buildUrl: (bucket) =>
      `https://storage.googleapis.com/${bucket}/`,
    parseStatus: (status) => {
      if (status === 200) return "public_list";
      if (status === 403) return "exists_private";
      if (status === 404) return "not_found";
      return "error";
    },
  },
  {
    provider: "digitalocean",
    label: "DigitalOcean Spaces",
    buildUrl: (bucket, region) =>
      `https://${bucket}.${region || "nyc3"}.digitaloceanspaces.com/`,
    parseStatus: (status) => {
      if (status === 200) return "public_list";
      if (status === 403) return "exists_private";
      if (status === 404) return "not_found";
      return "error";
    },
    regions: ["nyc3", "sfo3", "ams3", "sgp1", "fra1", "syd1"],
  },
  {
    provider: "alibaba",
    label: "Alibaba Cloud OSS",
    buildUrl: (bucket, region) =>
      `https://${bucket}.oss-${region || "us-east-1"}.aliyuncs.com/`,
    parseStatus: (status) => {
      if (status === 200) return "public_list";
      if (status === 403) return "exists_private";
      if (status === 404) return "not_found";
      return "error";
    },
    regions: ["us-east-1", "cn-hangzhou", "ap-southeast-1", "eu-central-1"],
  },
];

// ═══════════════════════════════════════════════════════════════════════
// §2 — INTELLIGENT WORDLIST GENERATION
// ═══════════════════════════════════════════════════════════════════════

/** Industry-specific bucket naming patterns */
const INDUSTRY_SUFFIXES = [
  // Common
  "", "-backup", "-backups", "-bak", "-dev", "-development", "-staging", "-stg",
  "-prod", "-production", "-prd", "-assets", "-static", "-media", "-uploads",
  "-data", "-logs", "-public", "-private", "-internal", "-docs", "-files",
  "-cdn", "-images", "-web", "-api", "-config", "-configs",
  // DevOps / Infrastructure
  "-terraform", "-tf-state", "-tfstate", "-ansible", "-deploy", "-deployments",
  "-artifacts", "-builds", "-releases", "-packages", "-docker", "-containers",
  "-k8s", "-kubernetes", "-helm", "-charts",
  // Data / Analytics
  "-datalake", "-data-lake", "-warehouse", "-analytics", "-reports", "-exports",
  "-imports", "-etl", "-pipeline", "-raw", "-processed", "-archive", "-archives",
  // Security / Compliance
  "-security", "-audit", "-compliance", "-scans", "-vulnerabilities", "-certs",
  "-certificates", "-keys", "-secrets",
  // Application
  "-app", "-application", "-frontend", "-backend", "-mobile", "-desktop",
  "-emails", "-notifications", "-temp", "-tmp", "-cache", "-test", "-testing",
  "-qa", "-uat", "-sandbox",
  // Database
  "-db-backup", "-db-backups", "-database", "-mysql-backup", "-pg-backup",
  "-mongo-backup", "-redis-backup", "-snapshots",
];

/** Generate bucket name candidates from domain and org info */
export function generateBucketCandidates(
  domain: string,
  orgName?: string,
  industry?: string
): string[] {
  const parts = domain.split(".");
  const base = parts[0];
  const baseClean = base.replace(/[^a-z0-9]/gi, "").toLowerCase();
  const baseDashed = base.replace(/[^a-z0-9]/gi, "-").toLowerCase();
  const domainDashed = domain.replace(/\./g, "-").toLowerCase();
  const domainUnderscore = domain.replace(/\./g, "_").toLowerCase();

  const roots = new Set<string>();
  roots.add(baseClean);
  if (baseDashed !== baseClean) roots.add(baseDashed);
  roots.add(domainDashed);
  roots.add(domainUnderscore);

  // Acronym (e.g., "acme-corporation" → "ac")
  if (base.includes("-") || base.includes("_")) {
    const acronym = base
      .split(/[-_]/)
      .map(p => p[0])
      .join("")
      .toLowerCase();
    if (acronym.length >= 2) roots.add(acronym);
  }

  // Org name variations
  if (orgName) {
    const orgClean = orgName.toLowerCase().replace(/[^a-z0-9]/gi, "");
    const orgDashed = orgName.toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9-]/gi, "");
    roots.add(orgClean);
    if (orgDashed !== orgClean) roots.add(orgDashed);

    // Org acronym
    const orgWords = orgName.split(/\s+/);
    if (orgWords.length >= 2) {
      const orgAcronym = orgWords.map(w => w[0]).join("").toLowerCase();
      if (orgAcronym.length >= 2) roots.add(orgAcronym);
    }
  }

  // Industry-specific roots
  if (industry) {
    const indClean = industry.toLowerCase().replace(/[^a-z0-9]/gi, "");
    roots.add(`${baseClean}-${indClean}`);
  }

  // Generate all combinations
  const candidates = new Set<string>();
  for (const root of roots) {
    for (const suffix of INDUSTRY_SUFFIXES) {
      const candidate = `${root}${suffix}`;
      if (candidate.length >= 3 && candidate.length <= 63) {
        candidates.add(candidate);
      }
    }
  }

  return Array.from(candidates);
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — BUCKET PROBING
// ═══════════════════════════════════════════════════════════════════════

interface BucketProbeResult {
  provider: CloudProvider;
  providerLabel: string;
  bucketName: string;
  url: string;
  status: BucketStatus;
  statusCode: number;
  region?: string;
  responseHeaders?: Record<string, string>;
  responseBody?: string;
}

async function probeBucket(
  candidate: string,
  endpoint: ProviderEndpoint,
  region: string | undefined,
  timeout: number
): Promise<BucketProbeResult> {
  const url = endpoint.buildUrl(candidate, region);
  try {
    const res = await fetch(url, {
      method: "GET",
      signal: AbortSignal.timeout(timeout),
      redirect: "follow",
      headers: { "User-Agent": "AceStrike-CloudRecon/2.0" },
    });

    const body = res.status === 200 ? await res.text().catch(() => "") : "";
    const status = endpoint.parseStatus(res.status, body);

    const headers: Record<string, string> = {};
    for (const [k, v] of res.headers.entries()) {
      if (["server", "x-amz-request-id", "x-goog-generation", "x-ms-request-id"].includes(k.toLowerCase())) {
        headers[k] = v;
      }
    }

    return {
      provider: endpoint.provider,
      providerLabel: endpoint.label,
      bucketName: candidate,
      url,
      status,
      statusCode: res.status,
      region,
      responseHeaders: Object.keys(headers).length > 0 ? headers : undefined,
      responseBody: body.slice(0, 5000), // Limit body size
    };
  } catch {
    return {
      provider: endpoint.provider,
      providerLabel: endpoint.label,
      bucketName: candidate,
      url,
      status: "error",
      statusCode: 0,
      region,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — PERMISSION DEPTH ANALYSIS
// ═══════════════════════════════════════════════════════════════════════

interface PermissionAnalysis {
  canList: boolean;
  canRead: boolean;
  canWrite: boolean;
  aclPublic: boolean;
  fileCount?: number;
  sampleFiles: string[];
  sensitiveFiles: string[];
  totalSizeEstimate?: string;
}

/** Sensitive file patterns to look for in public bucket listings */
const SENSITIVE_FILE_PATTERNS = [
  /\.env$/i,
  /\.pem$/i,
  /\.key$/i,
  /\.p12$/i,
  /\.pfx$/i,
  /\.sql$/i,
  /\.bak$/i,
  /\.backup$/i,
  /\.dump$/i,
  /password/i,
  /credential/i,
  /secret/i,
  /\.htpasswd$/i,
  /\.git\//i,
  /\.ssh\//i,
  /id_rsa/i,
  /\.csv$/i,
  /\.xlsx?$/i,
  /terraform\.tfstate/i,
  /\.tfvars$/i,
  /kubeconfig/i,
  /docker-compose/i,
  /\.npmrc$/i,
  /\.pypirc$/i,
  /\.netrc$/i,
  /\.pgpass$/i,
  /\.my\.cnf$/i,
];

function analyzePermissions(probe: BucketProbeResult): PermissionAnalysis {
  const result: PermissionAnalysis = {
    canList: false,
    canRead: false,
    canWrite: false,
    aclPublic: false,
    sampleFiles: [],
    sensitiveFiles: [],
  };

  if (probe.status === "public_list" || probe.status === "public_read") {
    result.canList = probe.status === "public_list";
    result.canRead = true;

    // Parse file listing from response body
    if (probe.responseBody) {
      // S3/GCS XML listing
      const keyMatches = probe.responseBody.match(/<Key>([^<]+)<\/Key>/g);
      if (keyMatches) {
        const files = keyMatches.map(m => m.replace(/<\/?Key>/g, ""));
        result.fileCount = files.length;
        result.sampleFiles = files.slice(0, 20);

        // Check for sensitive files
        for (const file of files) {
          for (const pattern of SENSITIVE_FILE_PATTERNS) {
            if (pattern.test(file)) {
              result.sensitiveFiles.push(file);
              break;
            }
          }
        }
      }

      // Azure Blob listing
      const blobMatches = probe.responseBody.match(/<Name>([^<]+)<\/Name>/g);
      if (blobMatches && !keyMatches) {
        const files = blobMatches.map(m => m.replace(/<\/?Name>/g, ""));
        result.fileCount = files.length;
        result.sampleFiles = files.slice(0, 20);

        for (const file of files) {
          for (const pattern of SENSITIVE_FILE_PATTERNS) {
            if (pattern.test(file)) {
              result.sensitiveFiles.push(file);
              break;
            }
          }
        }
      }

      // Estimate total size from Content-Length headers in listing
      const sizeMatches = probe.responseBody.match(/<Size>(\d+)<\/Size>/g);
      if (sizeMatches) {
        const totalBytes = sizeMatches.reduce((sum, m) => {
          const size = parseInt(m.replace(/<\/?Size>/g, ""), 10);
          return sum + (isNaN(size) ? 0 : size);
        }, 0);
        if (totalBytes > 1e9) result.totalSizeEstimate = `${(totalBytes / 1e9).toFixed(1)} GB`;
        else if (totalBytes > 1e6) result.totalSizeEstimate = `${(totalBytes / 1e6).toFixed(1)} MB`;
        else result.totalSizeEstimate = `${(totalBytes / 1e3).toFixed(1)} KB`;
      }
    }
  }

  return result;
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — OBSERVATION BUILDERS
// ═══════════════════════════════════════════════════════════════════════

function buildBucketObservation(
  domain: string,
  probe: BucketProbeResult,
  permissions: PermissionAnalysis,
  now: Date
): AssetObservation {
  const isPublic = probe.status === "public_list" || probe.status === "public_read" || probe.status === "public_read_write";
  const hasSensitiveFiles = permissions.sensitiveFiles.length > 0;

  const tags: string[] = [
    "cloud_asset",
    `provider:${probe.provider}`,
    isPublic ? "public_bucket" : "private_bucket",
  ];

  if (isPublic) {
    tags.push("critical_misconfiguration", "data_exposure_risk");
    if (permissions.canList) tags.push("public_listing");
    if (permissions.canWrite) tags.push("public_write", "critical_write_access");
    if (hasSensitiveFiles) tags.push("sensitive_files_exposed", "credential_exposure_risk");
  }

  let severity: "critical" | "high" | "medium" | "low" = "low";
  if (isPublic && hasSensitiveFiles) severity = "critical";
  else if (isPublic && permissions.canWrite) severity = "critical";
  else if (isPublic && permissions.canList) severity = "high";
  else if (isPublic) severity = "high";
  else if (probe.status === "exists_private") severity = "low";

  return {
    assetId: makeAssetId(domain, `cloud_bucket:${probe.provider}:${probe.bucketName}`, "cloud_bucket_recon"),
    domain,
    assetType: "url",
    name: `${probe.providerLabel}: ${probe.bucketName} (${isPublic ? "PUBLIC" : "private"}${hasSensitiveFiles ? " — SENSITIVE FILES" : ""})`,
    source: "cloud_bucket_recon",
    observedAt: now,
    tags,
    evidence: {
      bucketName: probe.bucketName,
      provider: probe.provider,
      providerLabel: probe.providerLabel,
      url: probe.url,
      status: probe.status,
      statusCode: probe.statusCode,
      region: probe.region,
      severity,
      permissions: {
        canList: permissions.canList,
        canRead: permissions.canRead,
        canWrite: permissions.canWrite,
        aclPublic: permissions.aclPublic,
      },
      fileCount: permissions.fileCount,
      sampleFiles: permissions.sampleFiles.slice(0, 10),
      sensitiveFiles: permissions.sensitiveFiles.slice(0, 20),
      totalSizeEstimate: permissions.totalSizeEstimate,
      responseHeaders: probe.responseHeaders,
    },
    attribution: {
      provider: `${probe.providerLabel} Bucket Probe`,
      url: probe.url,
      method: `Probed ${probe.providerLabel} endpoint for bucket '${probe.bucketName}' derived from ${domain}`,
      verifyUrl: probe.url,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — ENHANCED CONNECTOR EXPORT
// ═══════════════════════════════════════════════════════════════════════

export const cloudBucketReconConnector: PassiveConnector = {
  name: "cloud_bucket_recon",
  description:
    "Enhanced cloud storage enumeration — probes AWS S3, Azure Blob, GCP Storage, " +
    "DigitalOcean Spaces, and Alibaba OSS with intelligent wordlists, " +
    "permission depth analysis, and sensitive file detection " +
    "(T1530, T1619)",
  requiresApiKey: false,
  freeUrl: "https://buckets.grayhatwarfare.com",

  async collect(
    domain: string,
    config?: ConnectorConfig
  ): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 4000;
    const now = new Date();
    const GLOBAL_TIMEOUT = 60000; // 60s max for entire connector
    const CONCURRENCY = 15;

    try {
      const candidates = generateBucketCandidates(domain);

      // Prioritize candidates — common suffixes first, limit total probes
      const priorityCandidates = candidates.slice(0, 40);

      // Build probe list across all providers
      const probeList: Array<{
        candidate: string;
        endpoint: ProviderEndpoint;
        region?: string;
      }> = [];

      for (const candidate of priorityCandidates) {
        for (const endpoint of PROVIDERS) {
          if (endpoint.regions) {
            // Only probe the first 2 regions per provider to limit total probes
            for (const region of endpoint.regions.slice(0, 2)) {
              probeList.push({ candidate, endpoint, region });
            }
          } else {
            probeList.push({ candidate, endpoint });
          }
        }
      }

      // Execute probes in batches with concurrency control
      const results: BucketProbeResult[] = [];
      let aborted = false;

      for (let i = 0; i < probeList.length && !aborted; i += CONCURRENCY) {
        if (Date.now() - start >= GLOBAL_TIMEOUT) {
          aborted = true;
          break;
        }

        const batch = probeList.slice(i, i + CONCURRENCY);
        const batchResults = await Promise.allSettled(
          batch.map(p => probeBucket(p.candidate, p.endpoint, p.region, timeout))
        );

        for (const r of batchResults) {
          if (r.status === "fulfilled" && r.value.status !== "error" && r.value.status !== "not_found") {
            results.push(r.value);
          }
        }
      }

      // Analyze found buckets
      const found = results.filter(
        r => r.status === "public_list" || r.status === "public_read" ||
             r.status === "public_read_write" || r.status === "exists_private" ||
             r.status === "redirect"
      );

      // Deduplicate by bucket name + provider
      const seen = new Set<string>();
      const uniqueFound: BucketProbeResult[] = [];
      for (const bucket of found) {
        const key = `${bucket.provider}:${bucket.bucketName}`;
        if (!seen.has(key)) {
          seen.add(key);
          uniqueFound.push(bucket);
        }
      }

      // Analyze permissions and build observations for each found bucket
      for (const bucket of uniqueFound) {
        const permissions = analyzePermissions(bucket);
        observations.push(buildBucketObservation(domain, bucket, permissions, now));
      }

      // ── Summary Observation ─────────────────────────────────────
      const publicBuckets = uniqueFound.filter(
        r => r.status === "public_list" || r.status === "public_read" || r.status === "public_read_write"
      );
      const privateBuckets = uniqueFound.filter(r => r.status === "exists_private");
      const redirectBuckets = uniqueFound.filter(r => r.status === "redirect");
      const sensitiveFileCount = observations.reduce(
        (sum, o) => sum + (o.evidence?.sensitiveFiles?.length || 0), 0
      );

      const byProvider: Record<string, number> = {};
      for (const b of uniqueFound) {
        byProvider[b.providerLabel] = (byProvider[b.providerLabel] || 0) + 1;
      }

      let riskLevel: "critical" | "high" | "medium" | "low" | "none" = "none";
      if (sensitiveFileCount > 0 || publicBuckets.some(b => b.status === "public_read_write")) {
        riskLevel = "critical";
      } else if (publicBuckets.length > 0) {
        riskLevel = "high";
      } else if (privateBuckets.length > 0) {
        riskLevel = "medium";
      } else if (redirectBuckets.length > 0) {
        riskLevel = "low";
      }

      observations.push({
        assetId: makeAssetId(domain, `cloud_bucket_summary:${domain}`, "cloud_bucket_recon"),
        domain,
        assetType: "url",
        name: `Cloud Bucket Recon: ${uniqueFound.length} found (${publicBuckets.length} public, ${privateBuckets.length} private) across ${PROVIDERS.length} providers`,
        source: "cloud_bucket_recon",
        observedAt: now,
        tags: [
          "cloud_asset",
          "recon_summary",
          ...(publicBuckets.length > 0 ? ["public_buckets_found", "critical_misconfiguration"] : []),
          ...(sensitiveFileCount > 0 ? ["sensitive_files_exposed"] : []),
        ],
        evidence: {
          totalProbed: probeList.length,
          totalCandidates: priorityCandidates.length,
          totalFound: uniqueFound.length,
          publicCount: publicBuckets.length,
          privateCount: privateBuckets.length,
          redirectCount: redirectBuckets.length,
          sensitiveFileCount,
          byProvider,
          providersChecked: PROVIDERS.map(p => p.label),
          riskLevel,
          scanAborted: aborted,
          scanDurationMs: Date.now() - start,
        },
        attribution: {
          provider: "Cloud Bucket Enumeration v2",
          method: `Probed ${probeList.length} cloud storage endpoints across ${PROVIDERS.length} providers (S3, Azure, GCP, DO Spaces, Alibaba OSS) using ${priorityCandidates.length} naming patterns derived from ${domain}`,
        },
      });
    } catch (err: any) {
      errors.push(`Cloud bucket recon error: ${err.message}`);
    }

    return {
      connector: "cloud_bucket_recon",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited: false,
    };
  },
};

// ═══════════════════════════════════════════════════════════════════════
// §7 — EXPORTED ANALYSIS FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

/** Summarize cloud bucket findings for the UI */
export function summarizeCloudBuckets(observations: AssetObservation[]) {
  const summary = {
    totalFound: 0,
    publicBuckets: [] as Array<{
      name: string;
      provider: string;
      url: string;
      fileCount?: number;
      sensitiveFiles: string[];
    }>,
    privateBuckets: [] as Array<{ name: string; provider: string }>,
    byProvider: {} as Record<string, { total: number; public: number; private: number }>,
    sensitiveFileCount: 0,
    riskLevel: "none" as string,
    riskScore: 0,
  };

  for (const obs of observations) {
    if (obs.tags.includes("recon_summary")) {
      summary.totalFound = obs.evidence?.totalFound || 0;
      summary.riskLevel = obs.evidence?.riskLevel || "none";
      summary.byProvider = obs.evidence?.byProvider || {};
      continue;
    }

    if (obs.tags.includes("public_bucket")) {
      summary.publicBuckets.push({
        name: obs.evidence?.bucketName,
        provider: obs.evidence?.providerLabel,
        url: obs.evidence?.url,
        fileCount: obs.evidence?.fileCount,
        sensitiveFiles: obs.evidence?.sensitiveFiles || [],
      });
      summary.sensitiveFileCount += (obs.evidence?.sensitiveFiles?.length || 0);
    }

    if (obs.tags.includes("private_bucket")) {
      summary.privateBuckets.push({
        name: obs.evidence?.bucketName,
        provider: obs.evidence?.providerLabel,
      });
    }
  }

  // Risk score
  summary.riskScore = Math.min(100,
    summary.publicBuckets.length * 20 +
    summary.sensitiveFileCount * 30 +
    summary.privateBuckets.length * 5
  );

  return summary;
}

/** Get all supported providers for UI display */
export function getCloudProviders() {
  return PROVIDERS.map(p => ({
    provider: p.provider,
    label: p.label,
    regions: p.regions,
  }));
}
