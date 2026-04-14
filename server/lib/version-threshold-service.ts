/**
 * Version Threshold Auto-Refresh Service
 *
 * Keeps KNOWN_MIN_SAFE_VERSIONS current by:
 *   1. Querying the NVD CVE API for each technology's CPE to find the latest
 *      version ranges affected by critical/high CVEs
 *   2. Learning from DI scan detectedTechnologies — when a newer version is
 *      discovered in the wild, the threshold is bumped
 *   3. Persisting dynamic thresholds in the database (tech_version_thresholds)
 *   4. Merging DB thresholds with the static fallback (DB takes priority)
 *
 * The service runs on a configurable interval (default: every 24 hours) and
 * exposes stats + manual trigger via tRPC.
 *
 * @module version-threshold-service
 * @author Harrison Cook — AceofCloud
 */

import { getDb } from "../db";
import { sql } from "drizzle-orm";

// ─── Types ──────────────────────────────────────────────────────────

export interface VersionThreshold {
  technology: string;
  minSafeVersion: string;
  source: "static" | "nvd_cve" | "di_scan" | "manual";
  lastUpdated: number;
  /** CPE vendor:product used for NVD lookups */
  cpeVendor?: string;
  cpeProduct?: string;
  /** Most recent CVE that informed this threshold */
  latestCveId?: string;
  /** CVSS score of the CVE that set this threshold */
  latestCveCvss?: number;
  /** Highest version known to be affected */
  highestAffectedVersion?: string;
  /** Notes / audit trail */
  notes?: string;
}

export interface ThresholdRefreshResult {
  updated: number;
  added: number;
  unchanged: number;
  errors: string[];
  duration: number;
  sources: { nvd: number; diScan: number; manual: number };
}

export interface ThresholdStats {
  totalThresholds: number;
  bySource: { static: number; nvd_cve: number; di_scan: number; manual: number };
  lastRefreshTime: number;
  lastRefreshDuration: number;
  nextScheduledRefresh: number;
  refreshHistory: Array<{
    time: number;
    updated: number;
    added: number;
    duration: number;
  }>;
  staleThresholds: number; // thresholds not updated in > 30 days
}

// ─── NVD CVE API for Version Ranges ────────────────────────────────

const NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_RATE_LIMIT_NO_KEY_MS = 6500; // 6.5s between requests (no API key)
const NVD_RATE_LIMIT_WITH_KEY_MS = 600; // 0.6s between requests (with API key: 50 req/30s)
let lastNvdRequest = 0;

/** Get the NVD API key from environment, if configured */
function getNvdApiKey(): string | null {
  return process.env.NVD_API_KEY || null;
}

/** Check if NVD API key is configured */
export function hasNvdApiKey(): boolean {
  return !!getNvdApiKey();
}

/** Get NVD API key status info for the admin UI */
export function getNvdApiKeyStatus(): {
  configured: boolean;
  rateLimitMs: number;
  requestsPerMinute: number;
} {
  const hasKey = hasNvdApiKey();
  const rateLimitMs = hasKey ? NVD_RATE_LIMIT_WITH_KEY_MS : NVD_RATE_LIMIT_NO_KEY_MS;
  return {
    configured: hasKey,
    rateLimitMs,
    requestsPerMinute: Math.floor(60000 / rateLimitMs),
  };
}

async function nvdRateLimit(): Promise<void> {
  const rateLimitMs = hasNvdApiKey() ? NVD_RATE_LIMIT_WITH_KEY_MS : NVD_RATE_LIMIT_NO_KEY_MS;
  const now = Date.now();
  const elapsed = now - lastNvdRequest;
  if (elapsed < rateLimitMs) {
    await new Promise(resolve => setTimeout(resolve, rateLimitMs - elapsed));
  }
  lastNvdRequest = Date.now();
}

/**
 * Query NVD for recent critical/high CVEs affecting a specific CPE product.
 * Returns the highest affected version found across recent CVEs.
 */
async function queryNvdForLatestAffectedVersion(
  cpeVendor: string,
  cpeProduct: string,
  maxResults: number = 20,
): Promise<{
  highestAffectedVersion: string | null;
  latestCveId: string | null;
  latestCveCvss: number | null;
  minSafeVersion: string | null;
} | null> {
  await nvdRateLimit();

  try {
    // Search for recent high/critical CVEs for this product
    const cpeName = `cpe:2.3:a:${cpeVendor}:${cpeProduct}`;
    const url = `${NVD_CVE_API}?cpeName=${encodeURIComponent(cpeName)}:*&resultsPerPage=${maxResults}&cvssV3Severity=HIGH`;
    const headers: Record<string, string> = { "User-Agent": "AC3-VersionThresholdService/1.0" };
    const apiKey = getNvdApiKey();
    if (apiKey) headers["apiKey"] = apiKey;

    const res = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(15000),
    });

    if (!res.ok) {
      if (res.status === 403 || res.status === 429) {
        console.warn(`[VersionThreshold] NVD rate limited (${res.status}) for ${cpeVendor}:${cpeProduct}`);
        return null;
      }
      throw new Error(`HTTP ${res.status}`);
    }

    const data = (await res.json()) as any;
    const vulnerabilities = data.vulnerabilities || [];

    if (vulnerabilities.length === 0) return null;

    let highestAffectedVersion: string | null = null;
    let latestCveId: string | null = null;
    let latestCveCvss: number | null = null;

    for (const vuln of vulnerabilities) {
      const cve = vuln.cve;
      if (!cve) continue;

      // Extract CVSS score
      const cvssV31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
      const cvssV30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
      const cvss = cvssV31 || cvssV30;
      const score = cvss?.baseScore || 0;

      // Only consider high/critical CVEs (7.0+)
      if (score < 7.0) continue;

      // Extract version ranges from configurations
      const configs = cve.configurations || [];
      for (const config of configs) {
        const nodes = config.nodes || [];
        for (const node of nodes) {
          const cpeMatches = node.cpeMatch || [];
          for (const match of cpeMatches) {
            if (!match.vulnerable) continue;
            const criteria = (match.criteria || "").toLowerCase();
            if (!criteria.includes(cpeVendor) || !criteria.includes(cpeProduct)) continue;

            // Extract versionEndIncluding or versionEndExcluding
            const endIncluding = match.versionEndIncluding;
            const endExcluding = match.versionEndExcluding;
            const affectedEnd = endIncluding || endExcluding;

            if (affectedEnd && isValidVersion(affectedEnd)) {
              if (!highestAffectedVersion || compareSemver(affectedEnd, highestAffectedVersion) > 0) {
                highestAffectedVersion = affectedEnd;
                latestCveId = cve.id;
                latestCveCvss = score;
              }
            }
          }
        }
      }
    }

    if (!highestAffectedVersion) return null;

    // The minimum safe version is one patch above the highest affected version
    const minSafe = bumpPatchVersion(highestAffectedVersion);

    return {
      highestAffectedVersion,
      latestCveId,
      latestCveCvss,
      minSafeVersion: minSafe,
    };
  } catch (err: any) {
    console.error(`[VersionThreshold] NVD query failed for ${cpeVendor}:${cpeProduct}: ${err.message}`);
    return null;
  }
}

// ─── Version Helpers ───────────────────────────────────────────────

function isValidVersion(v: string): boolean {
  return /^\d+(\.\d+)*$/.test(v.replace(/^v/i, ""));
}

function compareSemver(a: string, b: string): number {
  const pa = a.replace(/^v/i, "").split(".").map(Number);
  const pb = b.replace(/^v/i, "").split(".").map(Number);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const va = pa[i] || 0;
    const vb = pb[i] || 0;
    if (va < vb) return -1;
    if (va > vb) return 1;
  }
  return 0;
}

/**
 * Bump the patch version by 1.
 * "2.4.58" → "2.4.59", "8.0.35" → "8.0.36", "1.25" → "1.26"
 */
function bumpPatchVersion(version: string): string {
  const parts = version.split(".").map(Number);
  if (parts.length === 0) return version;
  parts[parts.length - 1] += 1;
  return parts.join(".");
}

// ─── CPE Mapping (reuse from CPE dictionary updater) ───────────────

/**
 * Known technology → CPE vendor:product mappings.
 * This is a subset of the CPE dictionary updater's STATIC_SEED.
 */
const TECH_TO_CPE: Record<string, { vendor: string; product: string }> = {
  nginx: { vendor: "nginx", product: "nginx" },
  apache: { vendor: "apache", product: "http_server" },
  "apache http server": { vendor: "apache", product: "http_server" },
  "apache httpd": { vendor: "apache", product: "http_server" },
  "apache tomcat": { vendor: "apache", product: "tomcat" },
  iis: { vendor: "microsoft", product: "internet_information_services" },
  lighttpd: { vendor: "lighttpd", product: "lighttpd" },
  caddy: { vendor: "caddyserver", product: "caddy" },
  php: { vendor: "php", product: "php" },
  "node.js": { vendor: "nodejs", product: "node.js" },
  nodejs: { vendor: "nodejs", product: "node.js" },
  python: { vendor: "python", product: "python" },
  java: { vendor: "oracle", product: "jdk" },
  ruby: { vendor: "ruby-lang", product: "ruby" },
  mysql: { vendor: "oracle", product: "mysql" },
  mariadb: { vendor: "mariadb", product: "mariadb" },
  postgresql: { vendor: "postgresql", product: "postgresql" },
  mongodb: { vendor: "mongodb", product: "mongodb" },
  redis: { vendor: "redis", product: "redis" },
  wordpress: { vendor: "wordpress", product: "wordpress" },
  drupal: { vendor: "drupal", product: "drupal" },
  joomla: { vendor: "joomla", product: "joomla\\!" },
  jquery: { vendor: "jquery", product: "jquery" },
  react: { vendor: "facebook", product: "react" },
  angular: { vendor: "google", product: "angular" },
  vue: { vendor: "vuejs", product: "vue.js" },
  django: { vendor: "djangoproject", product: "django" },
  laravel: { vendor: "laravel", product: "laravel" },
  spring: { vendor: "vmware", product: "spring_framework" },
  "spring boot": { vendor: "vmware", product: "spring_boot" },
  express: { vendor: "expressjs", product: "express" },
  openssl: { vendor: "openssl", product: "openssl" },
  exchange: { vendor: "microsoft", product: "exchange_server" },
  postfix: { vendor: "postfix", product: "postfix" },
  docker: { vendor: "docker", product: "docker" },
  kubernetes: { vendor: "kubernetes", product: "kubernetes" },
  openssh: { vendor: "openbsd", product: "openssh" },
  jenkins: { vendor: "jenkins", product: "jenkins" },
  gitlab: { vendor: "gitlab", product: "gitlab" },
  confluence: { vendor: "atlassian", product: "confluence_server" },
  jira: { vendor: "atlassian", product: "jira" },
  grafana: { vendor: "grafana", product: "grafana" },
  elasticsearch: { vendor: "elastic", product: "elasticsearch" },
  kibana: { vendor: "elastic", product: "kibana" },
  "log4j": { vendor: "apache", product: "log4j" },
  "apache struts": { vendor: "apache", product: "struts" },
  "apache kafka": { vendor: "apache", product: "kafka" },
  "apache solr": { vendor: "apache", product: "solr" },
  rabbitmq: { vendor: "vmware", product: "rabbitmq" },
  memcached: { vendor: "memcached", product: "memcached" },
  bind: { vendor: "isc", product: "bind" },
  samba: { vendor: "samba", product: "samba" },
  squid: { vendor: "squid-cache", product: "squid" },
  haproxy: { vendor: "haproxy", product: "haproxy" },
  envoy: { vendor: "envoyproxy", product: "envoy" },
  traefik: { vendor: "traefik", product: "traefik" },
  vault: { vendor: "hashicorp", product: "vault" },
  consul: { vendor: "hashicorp", product: "consul" },
  terraform: { vendor: "hashicorp", product: "terraform" },
  nagios: { vendor: "nagios", product: "nagios" },
  zabbix: { vendor: "zabbix", product: "zabbix" },
  splunk: { vendor: "splunk", product: "splunk" },
  nextcloud: { vendor: "nextcloud", product: "nextcloud_server" },
  keycloak: { vendor: "redhat", product: "keycloak" },
  sonarqube: { vendor: "sonarsource", product: "sonarqube" },
  fortios: { vendor: "fortinet", product: "fortios" },
  "pan-os": { vendor: "paloaltonetworks", product: "pan-os" },
  junos: { vendor: "juniper", product: "junos" },
  "cisco ios": { vendor: "cisco", product: "ios" },
  "cisco asa": { vendor: "cisco", product: "adaptive_security_appliance_software" },
};

// ─── In-Memory State ───────────────────────────────────────────────

/** Dynamic thresholds loaded from DB, merged with static fallback */
const dynamicThresholds = new Map<string, VersionThreshold>();

let lastRefreshTime = 0;
let lastRefreshDuration = 0;
let refreshInterval: ReturnType<typeof setInterval> | null = null;
let nextScheduledRefresh = 0;

const refreshHistory: Array<{
  time: number;
  updated: number;
  added: number;
  duration: number;
}> = [];

// ─── Static Fallback (from battlespace-types.ts) ───────────────────

const STATIC_MIN_SAFE: Record<string, string> = {
  nginx: "1.25.0",
  apache: "2.4.58",
  "apache http server": "2.4.58",
  iis: "10.0",
  lighttpd: "1.4.73",
  caddy: "2.7.0",
  php: "8.2.0",
  "node.js": "20.0.0",
  nodejs: "20.0.0",
  python: "3.11.0",
  java: "17.0.0",
  ruby: "3.2.0",
  mysql: "8.0.35",
  mariadb: "10.11.0",
  postgresql: "16.0",
  mongodb: "7.0.0",
  redis: "7.2.0",
  wordpress: "6.4.0",
  drupal: "10.2.0",
  joomla: "5.0.0",
  jquery: "3.7.0",
  react: "18.0.0",
  angular: "17.0.0",
  vue: "3.4.0",
  django: "5.0",
  laravel: "11.0",
  spring: "6.1.0",
  express: "4.18.0",
  openssl: "3.1.0",
  exchange: "2019.0",
  postfix: "3.8.0",
  docker: "24.0.0",
  kubernetes: "1.28.0",
};

// ─── Core Functions ────────────────────────────────────────────────

/**
 * Get the current minimum safe version for a technology.
 * DB thresholds take priority over static fallback.
 */
export function getMinSafeVersion(tech: string): string | null {
  const key = tech.toLowerCase();
  const dynamic = dynamicThresholds.get(key);
  if (dynamic) return dynamic.minSafeVersion;
  return STATIC_MIN_SAFE[key] || null;
}

/**
 * Get all current thresholds (merged: dynamic + static fallback).
 */
export function getAllThresholds(): VersionThreshold[] {
  const result = new Map<string, VersionThreshold>();

  // Start with static fallback
  for (const [tech, version] of Object.entries(STATIC_MIN_SAFE)) {
    result.set(tech, {
      technology: tech,
      minSafeVersion: version,
      source: "static",
      lastUpdated: 0,
    });
  }

  // Override with dynamic thresholds
  for (const [tech, threshold] of dynamicThresholds) {
    result.set(tech, threshold);
  }

  return Array.from(result.values()).sort((a, b) =>
    a.technology.localeCompare(b.technology)
  );
}

/**
 * Refresh thresholds from NVD CVE data for all known technologies.
 * This is the main refresh loop — queries NVD for each tech with a CPE mapping.
 */
export async function refreshFromNvd(
  techKeys?: string[],
): Promise<ThresholdRefreshResult> {
  const startTime = Date.now();
  const result: ThresholdRefreshResult = {
    updated: 0,
    added: 0,
    unchanged: 0,
    errors: [],
    duration: 0,
    sources: { nvd: 0, diScan: 0, manual: 0 },
  };

  const keysToRefresh = techKeys || Object.keys(TECH_TO_CPE);
  console.log(`[VersionThreshold] Starting NVD refresh for ${keysToRefresh.length} technologies...`);

  for (const tech of keysToRefresh) {
    const cpe = TECH_TO_CPE[tech.toLowerCase()];
    if (!cpe) {
      result.unchanged++;
      continue;
    }

    try {
      const nvdResult = await queryNvdForLatestAffectedVersion(cpe.vendor, cpe.product);
      if (!nvdResult || !nvdResult.minSafeVersion) {
        result.unchanged++;
        continue;
      }

      const key = tech.toLowerCase();
      const existing = dynamicThresholds.get(key);
      const currentMinSafe = existing?.minSafeVersion || STATIC_MIN_SAFE[key];

      // Only update if NVD suggests a higher minimum safe version
      if (currentMinSafe && compareSemver(nvdResult.minSafeVersion, currentMinSafe) <= 0) {
        result.unchanged++;
        continue;
      }

      const threshold: VersionThreshold = {
        technology: key,
        minSafeVersion: nvdResult.minSafeVersion,
        source: "nvd_cve",
        lastUpdated: Date.now(),
        cpeVendor: cpe.vendor,
        cpeProduct: cpe.product,
        latestCveId: nvdResult.latestCveId || undefined,
        latestCveCvss: nvdResult.latestCveCvss || undefined,
        highestAffectedVersion: nvdResult.highestAffectedVersion || undefined,
        notes: `Auto-updated from NVD CVE ${nvdResult.latestCveId} (CVSS ${nvdResult.latestCveCvss})`,
      };

      dynamicThresholds.set(key, threshold);
      result.sources.nvd++;

      if (existing) {
        result.updated++;
        console.log(`[VersionThreshold] Updated ${key}: ${existing.minSafeVersion} → ${nvdResult.minSafeVersion} (${nvdResult.latestCveId})`);
      } else {
        result.added++;
        console.log(`[VersionThreshold] Added ${key}: ${nvdResult.minSafeVersion} (${nvdResult.latestCveId})`);
      }
    } catch (err: any) {
      result.errors.push(`${tech}: ${err.message}`);
    }
  }

  result.duration = Date.now() - startTime;
  lastRefreshTime = Date.now();
  lastRefreshDuration = result.duration;

  refreshHistory.push({
    time: lastRefreshTime,
    updated: result.updated,
    added: result.added,
    duration: result.duration,
  });
  if (refreshHistory.length > 50) refreshHistory.shift();

  // Persist to database
  await persistThresholds();

  console.log(
    `[VersionThreshold] NVD refresh complete in ${Math.round(result.duration / 1000)}s: ` +
    `${result.added} added, ${result.updated} updated, ${result.unchanged} unchanged, ${result.errors.length} errors`
  );

  return result;
}

/**
 * Learn from DI scan detectedTechnologies.
 * If a scan discovers a version higher than our current threshold,
 * we bump the threshold (since the version exists in the wild, it's likely current).
 */
export function learnFromDiScan(
  detectedTechnologies: Array<{ name: string; version?: string; category?: string }>,
): { updated: string[]; skipped: string[] } {
  const updated: string[] = [];
  const skipped: string[] = [];

  for (const tech of detectedTechnologies) {
    if (!tech.version || !isValidVersion(tech.version)) {
      skipped.push(tech.name);
      continue;
    }

    const key = tech.name.toLowerCase();
    const currentMinSafe = getMinSafeVersion(key);

    if (!currentMinSafe) {
      skipped.push(tech.name);
      continue;
    }

    const cleanVer = tech.version.replace(/^v/i, "");

    // If the detected version is BELOW our threshold, it's outdated — don't update
    if (compareSemver(cleanVer, currentMinSafe) < 0) {
      skipped.push(tech.name);
      continue;
    }

    // If the detected version is significantly ABOVE our threshold (2+ minor versions),
    // bump the threshold to be closer to current
    const currentParts = currentMinSafe.split(".").map(Number);
    const detectedParts = cleanVer.split(".").map(Number);

    // Only bump if detected is at least 2 minor versions ahead
    const majorDiff = (detectedParts[0] || 0) - (currentParts[0] || 0);
    const minorDiff = (detectedParts[1] || 0) - (currentParts[1] || 0);

    if (majorDiff > 0 || (majorDiff === 0 && minorDiff >= 2)) {
      // Set new threshold to one minor version below detected
      // (conservative: we know the detected version exists, but older minors may still be safe)
      const newMinSafe = `${detectedParts[0]}.${Math.max(0, (detectedParts[1] || 0) - 1)}.0`;

      if (compareSemver(newMinSafe, currentMinSafe) > 0) {
        const threshold: VersionThreshold = {
          technology: key,
          minSafeVersion: newMinSafe,
          source: "di_scan",
          lastUpdated: Date.now(),
          notes: `Auto-bumped from DI scan: detected v${cleanVer} in the wild`,
        };
        dynamicThresholds.set(key, threshold);
        updated.push(`${tech.name}: ${currentMinSafe} → ${newMinSafe} (detected v${cleanVer})`);
      } else {
        skipped.push(tech.name);
      }
    } else {
      skipped.push(tech.name);
    }
  }

  if (updated.length > 0) {
    console.log(`[VersionThreshold] DI scan learning: ${updated.length} thresholds bumped`);
    // Persist asynchronously
    persistThresholds().catch(err =>
      console.error(`[VersionThreshold] Failed to persist after DI scan learning: ${err.message}`)
    );
  }

  return { updated, skipped };
}

/**
 * Manually set a version threshold.
 */
export function setManualThreshold(
  technology: string,
  minSafeVersion: string,
  notes?: string,
): VersionThreshold {
  const key = technology.toLowerCase();
  const threshold: VersionThreshold = {
    technology: key,
    minSafeVersion,
    source: "manual",
    lastUpdated: Date.now(),
    notes: notes || "Manually set by admin",
  };
  dynamicThresholds.set(key, threshold);

  // Persist asynchronously
  persistThresholds().catch(err =>
    console.error(`[VersionThreshold] Failed to persist manual threshold: ${err.message}`)
  );

  return threshold;
}

/**
 * Delete a dynamic threshold (reverts to static fallback).
 */
export function deleteThreshold(technology: string): boolean {
  const key = technology.toLowerCase();
  const deleted = dynamicThresholds.delete(key);
  if (deleted) {
    persistThresholds().catch(err =>
      console.error(`[VersionThreshold] Failed to persist after delete: ${err.message}`)
    );
  }
  return deleted;
}

/**
 * Get stats about the threshold system.
 */
export function getThresholdStats(): ThresholdStats {
  const all = getAllThresholds();
  const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;

  const bySource = { static: 0, nvd_cve: 0, di_scan: 0, manual: 0 };
  let staleCount = 0;

  for (const t of all) {
    bySource[t.source]++;
    if (t.source !== "static" && t.lastUpdated < thirtyDaysAgo) {
      staleCount++;
    }
  }

  return {
    totalThresholds: all.length,
    bySource,
    lastRefreshTime,
    lastRefreshDuration,
    nextScheduledRefresh,
    refreshHistory: [...refreshHistory],
    staleThresholds: staleCount,
  };
}

// ─── Persistence ───────────────────────────────────────────────────

async function persistThresholds(): Promise<void> {
  try {
    const db = getDb();
    const entries = Array.from(dynamicThresholds.values());
    const payload = JSON.stringify(entries);

    await db.execute(sql`
      INSERT INTO system_settings (setting_key, setting_value, updated_at)
      VALUES ('version_thresholds', ${payload}, NOW())
      ON DUPLICATE KEY UPDATE setting_value = ${payload}, updated_at = NOW()
    `);
    console.log(`[VersionThreshold] Persisted ${entries.length} dynamic thresholds to database`);
  } catch (err: any) {
    // Table might not exist yet — create it
    try {
      const db = getDb();
      await db.execute(sql`
        CREATE TABLE IF NOT EXISTS system_settings (
          setting_key VARCHAR(255) PRIMARY KEY,
          setting_value LONGTEXT,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      const entries = Array.from(dynamicThresholds.values());
      const payload = JSON.stringify(entries);
      await db.execute(sql`
        INSERT INTO system_settings (setting_key, setting_value, updated_at)
        VALUES ('version_thresholds', ${payload}, NOW())
        ON DUPLICATE KEY UPDATE setting_value = ${payload}, updated_at = NOW()
      `);
      console.log(`[VersionThreshold] Created system_settings table and persisted ${entries.length} entries`);
    } catch (innerErr: any) {
      console.error(`[VersionThreshold] Failed to persist thresholds: ${innerErr.message}`);
    }
  }
}

async function loadPersistedThresholds(): Promise<number> {
  try {
    const db = getDb();
    const rows = await db.execute(sql`
      SELECT setting_value FROM system_settings WHERE setting_key = 'version_thresholds'
    `);
    const row = (rows as any)?.[0]?.[0] || (rows as any)?.[0];
    if (!row?.setting_value) return 0;

    const entries: VersionThreshold[] = JSON.parse(row.setting_value);
    let loaded = 0;
    for (const entry of entries) {
      if (entry.technology && entry.minSafeVersion) {
        dynamicThresholds.set(entry.technology.toLowerCase(), entry);
        loaded++;
      }
    }
    console.log(`[VersionThreshold] Loaded ${loaded} persisted thresholds from database`);
    return loaded;
  } catch (err: any) {
    console.warn(`[VersionThreshold] Failed to load persisted thresholds: ${err.message}`);
    return 0;
  }
}

// ─── Scheduler ─────────────────────────────────────────────────────

/**
 * Start the auto-refresh scheduler.
 * @param intervalMs Refresh interval in milliseconds (default: 24 hours)
 */
export async function startAutoRefresh(intervalMs: number = 24 * 60 * 60 * 1000): Promise<void> {
  // Load persisted thresholds first
  await loadPersistedThresholds();

  // Schedule periodic refresh
  if (refreshInterval) clearInterval(refreshInterval);

  nextScheduledRefresh = Date.now() + intervalMs;
  refreshInterval = setInterval(async () => {
    try {
      nextScheduledRefresh = Date.now() + intervalMs;
      await refreshFromNvd();
    } catch (err: any) {
      console.error(`[VersionThreshold] Scheduled refresh failed: ${err.message}`);
    }
  }, intervalMs);

  console.log(
    `[VersionThreshold] Auto-refresh started. Interval: ${Math.round(intervalMs / 3600000)}h. ` +
    `Dynamic thresholds: ${dynamicThresholds.size}, Static fallback: ${Object.keys(STATIC_MIN_SAFE).length}`
  );

  // Run initial refresh in background (don't block startup)
  // Only refresh if we haven't refreshed in the last 12 hours
  if (Date.now() - lastRefreshTime > 12 * 60 * 60 * 1000) {
    refreshFromNvd().catch(err =>
      console.error(`[VersionThreshold] Initial refresh failed: ${err.message}`)
    );
  }
}

/**
 * Stop the auto-refresh scheduler.
 */
export function stopAutoRefresh(): void {
  if (refreshInterval) {
    clearInterval(refreshInterval);
    refreshInterval = null;
    nextScheduledRefresh = 0;
    console.log("[VersionThreshold] Auto-refresh stopped");
  }
}

// ─── Exports for Testing ───────────────────────────────────────────

export const _testing = {
  compareSemver,
  bumpPatchVersion,
  isValidVersion,
  queryNvdForLatestAffectedVersion,
  TECH_TO_CPE,
  STATIC_MIN_SAFE,
  dynamicThresholds,
  loadPersistedThresholds,
  persistThresholds,
};
