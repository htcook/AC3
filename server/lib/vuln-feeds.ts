/**
 * Unified Vulnerability Feed Service
 * 
 * Aggregates multiple reputable vulnerability and 0-day feeds:
 * 1. CISA KEV (via kev-service.ts) — Known exploited vulnerabilities
 * 2. Google Project Zero — 0-day in-the-wild tracking
 * 3. NVD/NIST CVE API 2.0 — CVSS scoring and CVE enrichment
 * 4. CIRCL CVE API — Fast recent CVE lookup
 * 5. Exploit-DB — Public exploit availability (weaponization indicator)
 * 
 * All feeds are cached in-memory with configurable TTL.
 * Results are unified into a common VulnEntry format for consumption
 * by domain analysis, chain builder, and APT ability mapping.
 */

import {
  fetchKevCatalog,
  matchTechnologiesAgainstKev,
  getKevChainSteps,
  calculateKevRiskBoost,
  type KevMatch,
  type KevCatalog,
} from "./kev-service";

// ─── Common Types ───────────────────────────────────────────────────────────

export interface VulnEntry {
  cveId: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "unknown";
  cvssScore: number | null;
  vendor: string;
  product: string;
  datePublished: string;
  dateAdded?: string;
  sources: VulnSource[];
  exploitAvailable: boolean;
  inTheWild: boolean;          // Confirmed 0-day exploitation
  kevListed: boolean;          // On CISA KEV
  ransomwareLinked: boolean;
  suggestedTechniques: string[];
  exploitDbId?: string;
  patchAvailable?: boolean;
  attackVector?: string;
  attackComplexity?: string;
}

export type VulnSource = "cisa_kev" | "project_zero" | "nvd" | "circl" | "exploit_db";

export interface VulnFeedStats {
  totalEntries: number;
  bySource: Record<VulnSource, number>;
  bySeverity: Record<string, number>;
  exploitAvailableCount: number;
  inTheWildCount: number;
  kevListedCount: number;
  ransomwareLinkedCount: number;
  lastUpdated: string;
  feedHealth: Record<VulnSource, "ok" | "stale" | "error">;
}

export interface TechVulnMatch {
  technology: string;
  vulns: VulnEntry[];
  maxSeverity: "critical" | "high" | "medium" | "low" | "unknown";
  exploitCount: number;
  kevCount: number;
  riskScore: number; // 0-100
}

// ─── In-Memory Cache ────────────────────────────────────────────────────────

interface CacheEntry<T> {
  data: T;
  timestamp: number;
}

const cache = {
  projectZero: null as CacheEntry<ProjectZeroEntry[]> | null,
  nvdRecent: null as CacheEntry<NvdCveItem[]> | null,
  circlRecent: null as CacheEntry<CirclCve[]> | null,
  exploitDb: null as CacheEntry<ExploitDbEntry[]> | null,
  unified: null as CacheEntry<Map<string, VulnEntry>> | null,
};

const CACHE_TTL = {
  projectZero: 12 * 60 * 60 * 1000,  // 12 hours (CSV, infrequent updates)
  nvd: 2 * 60 * 60 * 1000,           // 2 hours (API, rate limited)
  circl: 1 * 60 * 60 * 1000,         // 1 hour (API, fast)
  exploitDb: 24 * 60 * 60 * 1000,    // 24 hours (CSV, large file)
  unified: 30 * 60 * 1000,           // 30 minutes
};

function isCacheValid<T>(entry: CacheEntry<T> | null, ttl: number): entry is CacheEntry<T> {
  return entry !== null && (Date.now() - entry.timestamp) < ttl;
}

// ─── Google Project Zero 0-Day In-The-Wild ──────────────────────────────────

interface ProjectZeroEntry {
  cveId: string;
  vendor: string;
  product: string;
  type: string;
  description: string;
  dateDiscovered: string;
  attribution: string;
}

const PROJECT_ZERO_CSV_URL =
  "https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/export?format=csv&gid=0";

async function fetchProjectZero(): Promise<ProjectZeroEntry[]> {
  if (isCacheValid(cache.projectZero, CACHE_TTL.projectZero)) {
    return cache.projectZero.data;
  }

  try {
    const res = await fetch(PROJECT_ZERO_CSV_URL, {
      headers: { "User-Agent": "AceC3-VulnFeed/1.0" },
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();

    const entries: ProjectZeroEntry[] = [];
    const lines = text.split("\n").slice(1); // skip header

    for (const line of lines) {
      if (!line.trim()) continue;
      // CSV parsing: handle quoted fields
      const fields = parseCSVLine(line);
      if (fields.length < 5) continue;

      const cveId = (fields[0] || "").trim();
      if (!cveId.startsWith("CVE-")) continue;

      entries.push({
        cveId,
        vendor: (fields[1] || "").trim(),
        product: (fields[2] || "").trim(),
        type: (fields[3] || "").trim(),
        description: (fields[4] || "").trim(),
        dateDiscovered: (fields[5] || "").trim(),
        attribution: (fields[6] || "").trim(),
      });
    }

    cache.projectZero = { data: entries, timestamp: Date.now() };
    console.log(`[VulnFeeds] Project Zero: ${entries.length} 0-day entries loaded`);
    return entries;
  } catch (err: any) {
    console.error(`[VulnFeeds] Project Zero fetch error: ${err.message}`);
    return cache.projectZero?.data || [];
  }
}

// ─── NVD/NIST CVE API 2.0 ──────────────────────────────────────────────────

interface NvdCveItem {
  cveId: string;
  description: string;
  published: string;
  lastModified: string;
  cvssV3Score: number | null;
  cvssV3Severity: string | null;
  attackVector: string | null;
  attackComplexity: string | null;
  vendor: string;
  product: string;
  cweId: string | null;
}

const NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";

async function fetchNvdRecent(days: number = 30): Promise<NvdCveItem[]> {
  if (isCacheValid(cache.nvdRecent, CACHE_TTL.nvd)) {
    return cache.nvdRecent.data;
  }

  try {
    const endDate = new Date();
    const startDate = new Date(endDate.getTime() - days * 24 * 60 * 60 * 1000);
    const fmt = (d: Date) => d.toISOString().replace(/\.\d+Z$/, ".000");

    const url = `${NVD_API_BASE}?pubStartDate=${fmt(startDate)}&pubEndDate=${fmt(endDate)}&resultsPerPage=200`;
    const res = await fetch(url, {
      headers: { "User-Agent": "AceC3-VulnFeed/1.0" },
      signal: AbortSignal.timeout(20000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json() as any;

    const items: NvdCveItem[] = [];
    for (const vuln of (data.vulnerabilities || [])) {
      const cve = vuln.cve;
      if (!cve) continue;

      const enDesc = cve.descriptions?.find((d: any) => d.lang === "en")?.value || "";
      const cvssV3 = cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
                     cve.metrics?.cvssMetricV30?.[0]?.cvssData;

      // Extract vendor/product from CPE
      let vendor = "", product = "";
      const cpeMatch = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0];
      if (cpeMatch?.criteria) {
        const parts = cpeMatch.criteria.split(":");
        vendor = parts[3] || "";
        product = parts[4] || "";
      }

      items.push({
        cveId: cve.id,
        description: enDesc,
        published: cve.published || "",
        lastModified: cve.lastModified || "",
        cvssV3Score: cvssV3?.baseScore ?? null,
        cvssV3Severity: cvssV3?.baseSeverity ?? null,
        attackVector: cvssV3?.attackVector ?? null,
        attackComplexity: cvssV3?.attackComplexity ?? null,
        vendor,
        product,
        cweId: cve.weaknesses?.[0]?.description?.[0]?.value || null,
      });
    }

    cache.nvdRecent = { data: items, timestamp: Date.now() };
    console.log(`[VulnFeeds] NVD: ${items.length} recent CVEs loaded (last ${days} days)`);
    return items;
  } catch (err: any) {
    console.error(`[VulnFeeds] NVD fetch error: ${err.message}`);
    return cache.nvdRecent?.data || [];
  }
}

/**
 * Enrich a specific CVE with NVD data (CVSS score, severity, etc.)
 */
async function enrichCveFromNvd(cveId: string): Promise<NvdCveItem | null> {
  try {
    const url = `${NVD_API_BASE}?cveId=${cveId}`;
    const res = await fetch(url, {
      headers: { "User-Agent": "AceC3-VulnFeed/1.0" },
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return null;
    const data = await res.json() as any;
    const cve = data.vulnerabilities?.[0]?.cve;
    if (!cve) return null;

    const enDesc = cve.descriptions?.find((d: any) => d.lang === "en")?.value || "";
    const cvssV3 = cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
                   cve.metrics?.cvssMetricV30?.[0]?.cvssData;

    let vendor = "", product = "";
    const cpeMatch = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0];
    if (cpeMatch?.criteria) {
      const parts = cpeMatch.criteria.split(":");
      vendor = parts[3] || "";
      product = parts[4] || "";
    }

    return {
      cveId: cve.id,
      description: enDesc,
      published: cve.published || "",
      lastModified: cve.lastModified || "",
      cvssV3Score: cvssV3?.baseScore ?? null,
      cvssV3Severity: cvssV3?.baseSeverity ?? null,
      attackVector: cvssV3?.attackVector ?? null,
      attackComplexity: cvssV3?.attackComplexity ?? null,
      vendor,
      product,
      cweId: cve.weaknesses?.[0]?.description?.[0]?.value || null,
    };
  } catch {
    return null;
  }
}

// ─── CIRCL CVE API ──────────────────────────────────────────────────────────

interface CirclCve {
  id: string;
  summary: string;
  Published: string;
  Modified: string;
  cvss: number | null;
  cvss3: number | null;
  references: string[];
}

const CIRCL_API_BASE = "https://cve.circl.lu/api";

async function fetchCirclRecent(): Promise<CirclCve[]> {
  if (isCacheValid(cache.circlRecent, CACHE_TTL.circl)) {
    return cache.circlRecent.data;
  }

  try {
    const res = await fetch(`${CIRCL_API_BASE}/last/50`, {
      headers: { "User-Agent": "AceC3-VulnFeed/1.0" },
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json() as CirclCve[];

    cache.circlRecent = { data: data || [], timestamp: Date.now() };
    console.log(`[VulnFeeds] CIRCL: ${data?.length || 0} recent CVEs loaded`);
    return data || [];
  } catch (err: any) {
    console.error(`[VulnFeeds] CIRCL fetch error: ${err.message}`);
    return cache.circlRecent?.data || [];
  }
}

/**
 * Look up a specific CVE via CIRCL
 */
async function lookupCveCircl(cveId: string): Promise<CirclCve | null> {
  try {
    const res = await fetch(`${CIRCL_API_BASE}/cve/${cveId}`, {
      headers: { "User-Agent": "AceC3-VulnFeed/1.0" },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    return await res.json() as CirclCve;
  } catch {
    return null;
  }
}

/**
 * Search CIRCL for CVEs by vendor/product
 */
async function searchCirclByVendor(vendor: string): Promise<string[]> {
  try {
    const res = await fetch(`${CIRCL_API_BASE}/browse/${encodeURIComponent(vendor)}`, {
      headers: { "User-Agent": "AceC3-VulnFeed/1.0" },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const data = await res.json() as any;
    return (data?.product || []).map((p: any) => typeof p === "string" ? p : p?.product || "");
  } catch {
    return [];
  }
}

// ─── Exploit-DB ─────────────────────────────────────────────────────────────

interface ExploitDbEntry {
  exploitId: string;
  description: string;
  datePublished: string;
  author: string;
  platform: string;
  type: string;
  cveIds: string[];
}

const EXPLOITDB_CSV_URL =
  "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv";

async function fetchExploitDb(): Promise<ExploitDbEntry[]> {
  if (isCacheValid(cache.exploitDb, CACHE_TTL.exploitDb)) {
    return cache.exploitDb.data;
  }

  try {
    const res = await fetch(EXPLOITDB_CSV_URL, {
      headers: { "User-Agent": "AceC3-VulnFeed/1.0" },
      signal: AbortSignal.timeout(30000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();

    const entries: ExploitDbEntry[] = [];
    const lines = text.split("\n").slice(1); // skip header

    // CSV columns: id,file,description,date_published,author,platform,type,port,codes
    for (const line of lines) {
      if (!line.trim()) continue;
      const fields = parseCSVLine(line);
      if (fields.length < 9) continue;

      const codes = (fields[8] || "").trim();
      const cveIds = codes.split(";")
        .map(c => c.trim())
        .filter(c => c.startsWith("CVE-"));

      if (cveIds.length === 0) continue; // Only keep entries with CVE mappings

      entries.push({
        exploitId: (fields[0] || "").trim(),
        description: (fields[2] || "").trim(),
        datePublished: (fields[3] || "").trim(),
        author: (fields[4] || "").trim(),
        platform: (fields[5] || "").trim(),
        type: (fields[6] || "").trim(),
        cveIds,
      });
    }

    cache.exploitDb = { data: entries, timestamp: Date.now() };
    console.log(`[VulnFeeds] Exploit-DB: ${entries.length} exploit entries with CVE mappings loaded`);
    return entries;
  } catch (err: any) {
    console.error(`[VulnFeeds] Exploit-DB fetch error: ${err.message}`);
    return cache.exploitDb?.data || [];
  }
}

/**
 * Check if a CVE has a public exploit in Exploit-DB
 */
function hasPublicExploit(cveId: string, exploitDb: ExploitDbEntry[]): ExploitDbEntry | null {
  return exploitDb.find(e => e.cveIds.includes(cveId)) || null;
}

// ─── CSV Parser ─────────────────────────────────────────────────────────────

function parseCSVLine(line: string): string[] {
  const fields: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === "," && !inQuotes) {
      fields.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  fields.push(current);
  return fields;
}

// ─── Unified Feed Aggregation ───────────────────────────────────────────────

function severityFromCvss(score: number | null): VulnEntry["severity"] {
  if (score === null) return "unknown";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

/**
 * Build the unified vulnerability map from all sources
 */
async function buildUnifiedMap(): Promise<Map<string, VulnEntry>> {
  if (isCacheValid(cache.unified, CACHE_TTL.unified)) {
    return cache.unified.data;
  }

  const map = new Map<string, VulnEntry>();

  // 1. CISA KEV (primary source of truth for actively exploited)
  const kev = await fetchKevCatalog();
  for (const v of kev.vulnerabilities || []) {
    map.set(v.cveID, {
      cveId: v.cveID,
      title: v.vulnerabilityName,
      description: v.shortDescription,
      severity: "critical", // All KEV entries are critical by definition
      cvssScore: null,
      vendor: v.vendorProject,
      product: v.product,
      datePublished: v.dateAdded,
      dateAdded: v.dateAdded,
      sources: ["cisa_kev"],
      exploitAvailable: true,
      inTheWild: true,
      kevListed: true,
      ransomwareLinked: v.knownRansomwareCampaignUse === "Known",
      suggestedTechniques: [],
      patchAvailable: true, // KEV entries require remediation
    });
  }

  // 2. Google Project Zero 0-days
  const pzEntries = await fetchProjectZero();
  for (const pz of pzEntries) {
    const existing = map.get(pz.cveId);
    if (existing) {
      if (!existing.sources.includes("project_zero")) {
        existing.sources.push("project_zero");
      }
      existing.inTheWild = true;
    } else {
      map.set(pz.cveId, {
        cveId: pz.cveId,
        title: `${pz.vendor} ${pz.product} ${pz.type}`,
        description: pz.description || `0-day in ${pz.vendor} ${pz.product}`,
        severity: "critical", // 0-days are critical
        cvssScore: null,
        vendor: pz.vendor,
        product: pz.product,
        datePublished: pz.dateDiscovered,
        sources: ["project_zero"],
        exploitAvailable: true,
        inTheWild: true,
        kevListed: false,
        ransomwareLinked: false,
        suggestedTechniques: [],
      });
    }
  }

  // 3. NVD recent CVEs (enrichment)
  const nvdItems = await fetchNvdRecent(30);
  for (const nvd of nvdItems) {
    const existing = map.get(nvd.cveId);
    if (existing) {
      if (!existing.sources.includes("nvd")) {
        existing.sources.push("nvd");
      }
      existing.cvssScore = nvd.cvssV3Score;
      existing.severity = severityFromCvss(nvd.cvssV3Score);
      existing.attackVector = nvd.attackVector || undefined;
      existing.attackComplexity = nvd.attackComplexity || undefined;
      if (!existing.description && nvd.description) {
        existing.description = nvd.description;
      }
    } else {
      map.set(nvd.cveId, {
        cveId: nvd.cveId,
        title: nvd.cveId,
        description: nvd.description,
        severity: severityFromCvss(nvd.cvssV3Score),
        cvssScore: nvd.cvssV3Score,
        vendor: nvd.vendor,
        product: nvd.product,
        datePublished: nvd.published,
        sources: ["nvd"],
        exploitAvailable: false,
        inTheWild: false,
        kevListed: false,
        ransomwareLinked: false,
        suggestedTechniques: [],
        attackVector: nvd.attackVector || undefined,
        attackComplexity: nvd.attackComplexity || undefined,
      });
    }
  }

  // 4. CIRCL recent CVEs
  const circlItems = await fetchCirclRecent();
  for (const c of circlItems) {
    const existing = map.get(c.id);
    if (existing) {
      if (!existing.sources.includes("circl")) {
        existing.sources.push("circl");
      }
      if (existing.cvssScore === null && c.cvss3) {
        existing.cvssScore = c.cvss3;
        existing.severity = severityFromCvss(c.cvss3);
      }
    } else {
      map.set(c.id, {
        cveId: c.id,
        title: c.id,
        description: c.summary || "",
        severity: severityFromCvss(c.cvss3 || c.cvss),
        cvssScore: c.cvss3 || c.cvss,
        vendor: "",
        product: "",
        datePublished: c.Published || "",
        sources: ["circl"],
        exploitAvailable: false,
        inTheWild: false,
        kevListed: false,
        ransomwareLinked: false,
        suggestedTechniques: [],
      });
    }
  }

  // 5. Exploit-DB (weaponization overlay)
  const exploitDb = await fetchExploitDb();
  for (const exp of exploitDb) {
    for (const cveId of exp.cveIds) {
      const existing = map.get(cveId);
      if (existing) {
        existing.exploitAvailable = true;
        existing.exploitDbId = exp.exploitId;
        if (!existing.sources.includes("exploit_db")) {
          existing.sources.push("exploit_db");
        }
      }
    }
  }

  cache.unified = { data: map, timestamp: Date.now() };
  console.log(`[VulnFeeds] Unified map: ${map.size} total CVEs from all sources`);
  return map;
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Get all vulnerability feed statistics
 */
export async function getVulnFeedStats(): Promise<VulnFeedStats> {
  const map = await buildUnifiedMap();
  const entries = Array.from(map.values());

  const bySource: Record<VulnSource, number> = {
    cisa_kev: 0, project_zero: 0, nvd: 0, circl: 0, exploit_db: 0,
  };
  const bySeverity: Record<string, number> = {
    critical: 0, high: 0, medium: 0, low: 0, unknown: 0,
  };

  let exploitAvailableCount = 0;
  let inTheWildCount = 0;
  let kevListedCount = 0;
  let ransomwareLinkedCount = 0;

  for (const e of entries) {
    for (const s of e.sources) bySource[s]++;
    bySeverity[e.severity]++;
    if (e.exploitAvailable) exploitAvailableCount++;
    if (e.inTheWild) inTheWildCount++;
    if (e.kevListed) kevListedCount++;
    if (e.ransomwareLinked) ransomwareLinkedCount++;
  }

  return {
    totalEntries: entries.length,
    bySource,
    bySeverity,
    exploitAvailableCount,
    inTheWildCount,
    kevListedCount,
    ransomwareLinkedCount,
    lastUpdated: new Date().toISOString(),
    feedHealth: {
      cisa_kev: cache.unified ? "ok" : "error",
      project_zero: cache.projectZero ? "ok" : "stale",
      nvd: cache.nvdRecent ? "ok" : "stale",
      circl: cache.circlRecent ? "ok" : "stale",
      exploit_db: cache.exploitDb ? "ok" : "stale",
    },
  };
}

/**
 * Get recent 0-day entries (confirmed in-the-wild exploitation)
 */
export async function getRecentZeroDays(limit: number = 50): Promise<VulnEntry[]> {
  const map = await buildUnifiedMap();
  return Array.from(map.values())
    .filter(e => e.inTheWild)
    .sort((a, b) => new Date(b.datePublished).getTime() - new Date(a.datePublished).getTime())
    .slice(0, limit);
}

/**
 * Get recent CVEs with public exploits (weaponized)
 */
export async function getWeaponizedCves(limit: number = 50): Promise<VulnEntry[]> {
  const map = await buildUnifiedMap();
  return Array.from(map.values())
    .filter(e => e.exploitAvailable && !e.kevListed) // Exclude KEV (shown separately)
    .sort((a, b) => new Date(b.datePublished).getTime() - new Date(a.datePublished).getTime())
    .slice(0, limit);
}

/**
 * Match discovered technologies against ALL vulnerability feeds
 * Returns matches grouped by technology with unified risk scoring
 */
export async function matchTechnologiesAgainstAllFeeds(
  technologies: string[]
): Promise<{
  matches: TechVulnMatch[];
  totalVulns: number;
  totalExploits: number;
  totalKev: number;
  totalZeroDay: number;
  overallRiskBoost: number;
}> {
  const map = await buildUnifiedMap();
  const kevCatalog = await fetchKevCatalog();

  // Get KEV matches (existing logic)
  const kevMatches = matchTechnologiesAgainstKev(technologies, kevCatalog);
  const kevRisk = calculateKevRiskBoost(kevMatches);

  // Match technologies against unified feed
  const techMatches: TechVulnMatch[] = [];
  let totalVulns = 0;
  let totalExploits = 0;
  let totalKev = 0;
  let totalZeroDay = 0;

  for (const tech of technologies) {
    const techLower = tech.toLowerCase().trim();
    if (techLower.length < 3) continue;

    const matchedVulns: VulnEntry[] = [];

    for (const entry of Array.from(map.values())) {
      const vendorLower = (entry.vendor || "").toLowerCase();
      const productLower = (entry.product || "").toLowerCase();
      const titleLower = (entry.title || "").toLowerCase();

      // Match against vendor, product, or title
      if (
        (techLower.length >= 4 && (
          vendorLower.includes(techLower) ||
          productLower.includes(techLower) ||
          titleLower.includes(techLower) ||
          techLower.includes(vendorLower) ||
          techLower.includes(productLower)
        ))
      ) {
        matchedVulns.push(entry);
      }
    }

    if (matchedVulns.length > 0) {
      const exploitCount = matchedVulns.filter(v => v.exploitAvailable).length;
      const kevCount = matchedVulns.filter(v => v.kevListed).length;
      const zeroDayCount = matchedVulns.filter(v => v.inTheWild).length;

      // Calculate risk score for this technology
      const maxCvss = Math.max(...matchedVulns.map(v => v.cvssScore || 0));
      const riskScore = Math.min(100, Math.round(
        (maxCvss / 10) * 40 +
        (exploitCount > 0 ? 25 : 0) +
        (kevCount > 0 ? 20 : 0) +
        (zeroDayCount > 0 ? 15 : 0)
      ));

      const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
      const maxSeverity = matchedVulns.reduce((max, v) =>
        (severityOrder[v.severity] > severityOrder[max]) ? v.severity : max,
        "unknown" as VulnEntry["severity"]
      );

      techMatches.push({
        technology: tech,
        vulns: matchedVulns.sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0)).slice(0, 25),
        maxSeverity,
        exploitCount,
        kevCount,
        riskScore,
      });

      totalVulns += matchedVulns.length;
      totalExploits += exploitCount;
      totalKev += kevCount;
      totalZeroDay += zeroDayCount;
    }
  }

  return {
    matches: techMatches.sort((a, b) => b.riskScore - a.riskScore),
    totalVulns,
    totalExploits,
    totalKev,
    totalZeroDay,
    overallRiskBoost: kevRisk.riskBoost,
  };
}

/**
 * Enrich a specific CVE with data from all feeds
 */
export async function enrichCve(cveId: string): Promise<VulnEntry | null> {
  const map = await buildUnifiedMap();
  const existing = map.get(cveId);
  if (existing) return existing;

  // Try NVD lookup
  const nvd = await enrichCveFromNvd(cveId);
  if (nvd) {
    return {
      cveId: nvd.cveId,
      title: nvd.cveId,
      description: nvd.description,
      severity: severityFromCvss(nvd.cvssV3Score),
      cvssScore: nvd.cvssV3Score,
      vendor: nvd.vendor,
      product: nvd.product,
      datePublished: nvd.published,
      sources: ["nvd"],
      exploitAvailable: false,
      inTheWild: false,
      kevListed: false,
      ransomwareLinked: false,
      suggestedTechniques: [],
      attackVector: nvd.attackVector || undefined,
      attackComplexity: nvd.attackComplexity || undefined,
    };
  }

  // Try CIRCL lookup
  const circl = await lookupCveCircl(cveId);
  if (circl) {
    return {
      cveId: circl.id,
      title: circl.id,
      description: circl.summary || "",
      severity: severityFromCvss(circl.cvss3 || circl.cvss),
      cvssScore: circl.cvss3 || circl.cvss,
      vendor: "",
      product: "",
      datePublished: circl.Published || "",
      sources: ["circl"],
      exploitAvailable: false,
      inTheWild: false,
      kevListed: false,
      ransomwareLinked: false,
      suggestedTechniques: [],
    };
  }

  return null;
}

/**
 * Get KEV chain steps for the attack chain builder (re-export from kev-service)
 */
export { getKevChainSteps, fetchKevCatalog, matchTechnologiesAgainstKev, calculateKevRiskBoost };

/**
 * Search vulnerabilities across all feeds
 */
export async function searchVulnerabilities(
  query: string,
  filters?: {
    severity?: string;
    source?: VulnSource;
    exploitOnly?: boolean;
    kevOnly?: boolean;
    zeroDayOnly?: boolean;
  },
  limit: number = 100
): Promise<VulnEntry[]> {
  const map = await buildUnifiedMap();
  const queryLower = query.toLowerCase();

  let results = Array.from(map.values());

  // Text search
  if (query) {
    results = results.filter(e =>
      e.cveId.toLowerCase().includes(queryLower) ||
      e.title.toLowerCase().includes(queryLower) ||
      e.description.toLowerCase().includes(queryLower) ||
      e.vendor.toLowerCase().includes(queryLower) ||
      e.product.toLowerCase().includes(queryLower)
    );
  }

  // Apply filters
  if (filters?.severity) {
    results = results.filter(e => e.severity === filters.severity);
  }
  if (filters?.source) {
    results = results.filter(e => e.sources.includes(filters.source!));
  }
  if (filters?.exploitOnly) {
    results = results.filter(e => e.exploitAvailable);
  }
  if (filters?.kevOnly) {
    results = results.filter(e => e.kevListed);
  }
  if (filters?.zeroDayOnly) {
    results = results.filter(e => e.inTheWild);
  }

  return results
    .sort((a, b) => {
      // Sort by: KEV first, then 0-day, then exploit available, then CVSS
      if (a.kevListed !== b.kevListed) return a.kevListed ? -1 : 1;
      if (a.inTheWild !== b.inTheWild) return a.inTheWild ? -1 : 1;
      if (a.exploitAvailable !== b.exploitAvailable) return a.exploitAvailable ? -1 : 1;
      return (b.cvssScore || 0) - (a.cvssScore || 0);
    })
    .slice(0, limit);
}

// Export internal functions for testing
export {
  parseCSVLine,
  severityFromCvss,
  fetchProjectZero,
  fetchNvdRecent,
  fetchCirclRecent,
  fetchExploitDb,
  searchCirclByVendor,
  enrichCveFromNvd,
  lookupCveCircl,
  hasPublicExploit,
  buildUnifiedMap,
};

/**
 * Generate chain steps from vuln feed matches.
 * Only includes confirmed/probable findings to prevent false-positive noise in adversary emulation.
 * @param matches - Technology vulnerability matches from all feeds
 * @param detectedVersions - Optional map of technology -> detected version for corroboration
 */
export function getVulnFeedChainSteps(
  matches: TechVulnMatch[],
  detectedVersions?: Record<string, string>
): Array<{ techniqueId: string; priority: number; source: "vuln_feed"; context: string; corroborationTier: string }> {
  const steps: Array<{ techniqueId: string; priority: number; source: "vuln_feed"; context: string; corroborationTier: string }> = [];
  const seenTechniques = new Set<string>();

  for (const match of matches) {
    // Determine corroboration tier for this technology match
    const hasVersion = detectedVersions && Object.keys(detectedVersions).some(
      tech => tech.toLowerCase().includes(match.technology.toLowerCase()) || match.technology.toLowerCase().includes(tech.toLowerCase())
    );
    const tier = hasVersion ? "confirmed" : "probable";

    for (const vuln of match.vulns) {
      // Only include vulns with confirmed exploits, 0-day status, or KEV listing
      if (!vuln.exploitAvailable && !vuln.inTheWild && !vuln.kevListed) continue;

      for (const tid of vuln.suggestedTechniques) {
        if (seenTechniques.has(tid)) continue;
        seenTechniques.add(tid);

        // Priority: confirmed + 0-day/KEV = 1, confirmed + exploit = 2, probable + KEV = 2, probable + exploit = 3
        let priority: number;
        if (tier === "confirmed") {
          priority = (vuln.inTheWild || vuln.kevListed) ? 1 : 2;
        } else {
          priority = (vuln.inTheWild || vuln.kevListed) ? 2 : 3;
        }

        const versionNote = hasVersion ? " [VERSION CONFIRMED]" : " [VERSION UNCONFIRMED]";
        steps.push({
          techniqueId: tid,
          priority,
          source: "vuln_feed",
          context: `${vuln.cveId} (${vuln.severity.toUpperCase()}, CVSS ${vuln.cvssScore || "N/A"}) affecting ${match.technology}${vuln.inTheWild ? " [0-DAY]" : ""}${vuln.kevListed ? " [KEV]" : ""}${vuln.exploitAvailable ? " [EXPLOIT]" : ""}${versionNote}`,
          corroborationTier: tier,
        });
      }
    }
  }

  return steps;
}
