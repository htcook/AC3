/**
 * Dynamic CPE Matcher
 * 
 * Replaces hardcoded technology-to-vulnerability mappings with live
 * queries against the NVD CVE API 2.0 and CPE Match Feed. When a
 * technology+version is discovered, dynamically queries NVD for all
 * CVEs affecting that CPE, with 24-hour TTL caching.
 * 
 * This eliminates the staleness problem — new CVEs are picked up
 * within a day of NVD publication.
 * 
 * @module dynamic-cpe-matcher
 */

// ─── Types ─────────────────────────────────────────────────────────

export interface CpeMatchResult {
  technology: string;
  version: string;
  cpeUri: string;
  cves: CpeMatchedCve[];
  matchConfidence: "exact" | "partial" | "fuzzy";
  cachedAt: number;
}

export interface CpeMatchedCve {
  cveId: string;
  description: string;
  cvssV3Score: number | null;
  severity: "critical" | "high" | "medium" | "low" | "unknown";
  attackVector: string | null;
  attackComplexity: string | null;
  published: string;
  exploitabilityScore: number | null;
  impactScore: number | null;
  affectedVersionRange: string | null;
}

export interface CpeMatchStats {
  totalQueries: number;
  cacheHits: number;
  cacheMisses: number;
  totalCvesFound: number;
  averageCvesPerTech: number;
  lastQueryTime: number;
}

// ─── CPE URI Construction ──────────────────────────────────────────

/**
 * Well-known technology-to-CPE vendor:product mappings.
 * Used to construct CPE URIs from discovered technology names.
 * This is NOT a vulnerability mapping — it only maps names to CPE identifiers.
 */
const TECH_TO_CPE: Record<string, { vendor: string; product: string }> = {
  "apache": { vendor: "apache", product: "http_server" },
  "apache httpd": { vendor: "apache", product: "http_server" },
  "apache tomcat": { vendor: "apache", product: "tomcat" },
  "nginx": { vendor: "nginx", product: "nginx" },
  "iis": { vendor: "microsoft", product: "internet_information_services" },
  "wordpress": { vendor: "wordpress", product: "wordpress" },
  "drupal": { vendor: "drupal", product: "drupal" },
  "joomla": { vendor: "joomla\\!", product: "joomla\\!" },
  "exchange": { vendor: "microsoft", product: "exchange_server" },
  "sharepoint": { vendor: "microsoft", product: "sharepoint_server" },
  "windows": { vendor: "microsoft", product: "windows" },
  "windows server": { vendor: "microsoft", product: "windows_server" },
  "openssh": { vendor: "openbsd", product: "openssh" },
  "openssl": { vendor: "openssl", product: "openssl" },
  "php": { vendor: "php", product: "php" },
  "mysql": { vendor: "oracle", product: "mysql" },
  "postgresql": { vendor: "postgresql", product: "postgresql" },
  "oracle database": { vendor: "oracle", product: "database_server" },
  "mssql": { vendor: "microsoft", product: "sql_server" },
  "sql server": { vendor: "microsoft", product: "sql_server" },
  "log4j": { vendor: "apache", product: "log4j" },
  "spring framework": { vendor: "vmware", product: "spring_framework" },
  "spring boot": { vendor: "vmware", product: "spring_boot" },
  "jenkins": { vendor: "jenkins", product: "jenkins" },
  "gitlab": { vendor: "gitlab", product: "gitlab" },
  "confluence": { vendor: "atlassian", product: "confluence_server" },
  "jira": { vendor: "atlassian", product: "jira" },
  "cisco ios": { vendor: "cisco", product: "ios" },
  "cisco asa": { vendor: "cisco", product: "adaptive_security_appliance_software" },
  "fortios": { vendor: "fortinet", product: "fortios" },
  "fortigate": { vendor: "fortinet", product: "fortios" },
  "palo alto pan-os": { vendor: "paloaltonetworks", product: "pan-os" },
  "pan-os": { vendor: "paloaltonetworks", product: "pan-os" },
  "junos": { vendor: "juniper", product: "junos" },
  "sonicwall": { vendor: "sonicwall", product: "sma" },
  "pulse secure": { vendor: "ivanti", product: "connect_secure" },
  "citrix adc": { vendor: "citrix", product: "application_delivery_controller_firmware" },
  "citrix netscaler": { vendor: "citrix", product: "netscaler_application_delivery_controller" },
  "vmware vcenter": { vendor: "vmware", product: "vcenter_server" },
  "vmware esxi": { vendor: "vmware", product: "esxi" },
  "veeam": { vendor: "veeam", product: "backup_\\&_replication" },
  "zimbra": { vendor: "zimbra", product: "collaboration" },
  "solarwinds orion": { vendor: "solarwinds", product: "orion_platform" },
  "moveit": { vendor: "progress", product: "moveit_transfer" },
  "barracuda esg": { vendor: "barracuda", product: "email_security_gateway" },
  "crowdstrike falcon": { vendor: "crowdstrike", product: "falcon" },
  "chrome": { vendor: "google", product: "chrome" },
  "firefox": { vendor: "mozilla", product: "firefox" },
  "edge": { vendor: "microsoft", product: "edge" },
  "java": { vendor: "oracle", product: "jdk" },
  "node.js": { vendor: "nodejs", product: "node.js" },
  "redis": { vendor: "redis", product: "redis" },
  "mongodb": { vendor: "mongodb", product: "mongodb" },
  "elasticsearch": { vendor: "elastic", product: "elasticsearch" },
  "docker": { vendor: "docker", product: "docker" },
  "kubernetes": { vendor: "kubernetes", product: "kubernetes" },
  "grafana": { vendor: "grafana", product: "grafana" },
  "prometheus": { vendor: "prometheus", product: "prometheus" },
};

/**
 * Construct a CPE 2.3 URI from technology name and version.
 * Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
 */
export function buildCpeUri(technology: string, version?: string): string | null {
  const techLower = technology.toLowerCase().trim();
  
  // Try exact match first
  let mapping = TECH_TO_CPE[techLower];
  
  // Try partial match
  if (!mapping) {
    for (const [key, value] of Object.entries(TECH_TO_CPE)) {
      if (techLower.includes(key) || key.includes(techLower)) {
        mapping = value;
        break;
      }
    }
  }
  
  if (!mapping) return null;
  
  const ver = version ? version.replace(/[^0-9.]/g, "") : "*";
  return `cpe:2.3:a:${mapping.vendor}:${mapping.product}:${ver}:*:*:*:*:*:*:*`;
}

/**
 * Extract vendor and product from a CPE URI
 */
export function parseCpeUri(cpeUri: string): { vendor: string; product: string; version: string } | null {
  const parts = cpeUri.split(":");
  if (parts.length < 6) return null;
  return {
    vendor: parts[3] || "",
    product: parts[4] || "",
    version: parts[5] || "*",
  };
}

// ─── NVD API Client ────────────────────────────────────────────────

const NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_CPE_API_BASE = "https://services.nvd.nist.gov/rest/json/cpes/2.0";

// Rate limiting: NVD allows 5 requests per 30 seconds without API key
let lastNvdRequest = 0;
const NVD_MIN_INTERVAL = 6500; // 6.5 seconds between requests

async function nvdRateLimit(): Promise<void> {
  const now = Date.now();
  const elapsed = now - lastNvdRequest;
  if (elapsed < NVD_MIN_INTERVAL) {
    await new Promise(resolve => setTimeout(resolve, NVD_MIN_INTERVAL - elapsed));
  }
  lastNvdRequest = Date.now();
}

/**
 * Query NVD for CVEs affecting a specific CPE
 */
async function queryNvdByCpe(
  cpeUri: string,
  maxResults: number = 50
): Promise<CpeMatchedCve[]> {
  await nvdRateLimit();
  
  try {
    // Use cpeName parameter for exact CPE matching
    const url = `${NVD_API_BASE}?cpeName=${encodeURIComponent(cpeUri)}&resultsPerPage=${maxResults}`;
    const res = await fetch(url, {
      headers: { "User-Agent": "AceC3-DynamicCPE/1.0" },
      signal: AbortSignal.timeout(15000),
    });
    
    if (!res.ok) {
      if (res.status === 403 || res.status === 429) {
        console.warn(`[DynamicCPE] NVD rate limited (${res.status}), will retry later`);
        return [];
      }
      throw new Error(`HTTP ${res.status}`);
    }
    
    const data = await res.json() as any;
    const results: CpeMatchedCve[] = [];
    
    for (const vuln of (data.vulnerabilities || [])) {
      const cve = vuln.cve;
      if (!cve) continue;
      
      const enDesc = cve.descriptions?.find((d: any) => d.lang === "en")?.value || "";
      const cvssV3 = cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
                     cve.metrics?.cvssMetricV30?.[0]?.cvssData;
      const cvssV3Meta = cve.metrics?.cvssMetricV31?.[0] ||
                         cve.metrics?.cvssMetricV30?.[0];
      
      // Extract affected version range from CPE match
      let affectedVersionRange: string | null = null;
      const cpeMatch = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0];
      if (cpeMatch) {
        const parts: string[] = [];
        if (cpeMatch.versionStartIncluding) parts.push(`>= ${cpeMatch.versionStartIncluding}`);
        if (cpeMatch.versionStartExcluding) parts.push(`> ${cpeMatch.versionStartExcluding}`);
        if (cpeMatch.versionEndIncluding) parts.push(`<= ${cpeMatch.versionEndIncluding}`);
        if (cpeMatch.versionEndExcluding) parts.push(`< ${cpeMatch.versionEndExcluding}`);
        if (parts.length > 0) affectedVersionRange = parts.join(", ");
      }
      
      const score = cvssV3?.baseScore ?? null;
      let severity: CpeMatchedCve["severity"] = "unknown";
      if (score !== null) {
        if (score >= 9.0) severity = "critical";
        else if (score >= 7.0) severity = "high";
        else if (score >= 4.0) severity = "medium";
        else severity = "low";
      }
      
      results.push({
        cveId: cve.id,
        description: enDesc.slice(0, 500),
        cvssV3Score: score,
        severity,
        attackVector: cvssV3?.attackVector ?? null,
        attackComplexity: cvssV3?.attackComplexity ?? null,
        published: cve.published || "",
        exploitabilityScore: cvssV3Meta?.exploitabilityScore ?? null,
        impactScore: cvssV3Meta?.impactScore ?? null,
        affectedVersionRange,
      });
    }
    
    return results.sort((a, b) => (b.cvssV3Score || 0) - (a.cvssV3Score || 0));
  } catch (err: any) {
    console.error(`[DynamicCPE] NVD query failed for ${cpeUri}: ${err.message}`);
    return [];
  }
}

/**
 * Query NVD for CVEs by keyword (fallback when CPE URI is not available)
 */
async function queryNvdByKeyword(
  keyword: string,
  maxResults: number = 25
): Promise<CpeMatchedCve[]> {
  await nvdRateLimit();
  
  try {
    const url = `${NVD_API_BASE}?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=${maxResults}`;
    const res = await fetch(url, {
      headers: { "User-Agent": "AceC3-DynamicCPE/1.0" },
      signal: AbortSignal.timeout(15000),
    });
    
    if (!res.ok) return [];
    const data = await res.json() as any;
    const results: CpeMatchedCve[] = [];
    
    for (const vuln of (data.vulnerabilities || [])) {
      const cve = vuln.cve;
      if (!cve) continue;
      
      const enDesc = cve.descriptions?.find((d: any) => d.lang === "en")?.value || "";
      const cvssV3 = cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
                     cve.metrics?.cvssMetricV30?.[0]?.cvssData;
      
      const score = cvssV3?.baseScore ?? null;
      let severity: CpeMatchedCve["severity"] = "unknown";
      if (score !== null) {
        if (score >= 9.0) severity = "critical";
        else if (score >= 7.0) severity = "high";
        else if (score >= 4.0) severity = "medium";
        else severity = "low";
      }
      
      results.push({
        cveId: cve.id,
        description: enDesc.slice(0, 500),
        cvssV3Score: score,
        severity,
        attackVector: cvssV3?.attackVector ?? null,
        attackComplexity: cvssV3?.attackComplexity ?? null,
        published: cve.published || "",
        exploitabilityScore: null,
        impactScore: null,
        affectedVersionRange: null,
      });
    }
    
    return results.sort((a, b) => (b.cvssV3Score || 0) - (a.cvssV3Score || 0));
  } catch (err: any) {
    console.error(`[DynamicCPE] NVD keyword query failed for ${keyword}: ${err.message}`);
    return [];
  }
}

// ─── Cache Layer ───────────────────────────────────────────────────

const cpeCache = new Map<string, CpeMatchResult>();
const CPE_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

let stats: CpeMatchStats = {
  totalQueries: 0,
  cacheHits: 0,
  cacheMisses: 0,
  totalCvesFound: 0,
  averageCvesPerTech: 0,
  lastQueryTime: 0,
};

function getCacheKey(technology: string, version?: string): string {
  return `${technology.toLowerCase().trim()}:${(version || "*").toLowerCase().trim()}`;
}

// ─── Public API ────────────────────────────────────────────────────

/**
 * Match a technology+version against NVD to find all applicable CVEs.
 * Uses CPE URI matching when possible, falls back to keyword search.
 * Results are cached for 24 hours.
 */
export async function matchTechnologyCves(
  technology: string,
  version?: string
): Promise<CpeMatchResult> {
  const cacheKey = getCacheKey(technology, version);
  stats.totalQueries++;
  
  // Check cache
  const cached = cpeCache.get(cacheKey);
  if (cached && (Date.now() - cached.cachedAt) < CPE_CACHE_TTL) {
    stats.cacheHits++;
    return cached;
  }
  stats.cacheMisses++;
  
  // Try CPE URI match first
  const cpeUri = buildCpeUri(technology, version);
  let cves: CpeMatchedCve[] = [];
  let matchConfidence: CpeMatchResult["matchConfidence"] = "fuzzy";
  
  if (cpeUri) {
    cves = await queryNvdByCpe(cpeUri);
    matchConfidence = version ? "exact" : "partial";
  }
  
  // Fallback to keyword search if CPE match yields no results
  if (cves.length === 0) {
    const keyword = version ? `${technology} ${version}` : technology;
    cves = await queryNvdByKeyword(keyword);
    matchConfidence = "fuzzy";
  }
  
  // VERSION-AWARE FILTERING: If a version was provided, filter out CVEs
  // whose affectedVersionRange explicitly excludes the detected version.
  // CVEs with no version range data are kept (can't confirm or deny).
  if (version && cves.length > 0) {
    const beforeCount = cves.length;
    cves = filterCvesByVersion(cves, version);
    if (cves.length < beforeCount) {
      console.log(`[DynamicCPE] Version filter for ${technology} v${version}: ${beforeCount} \u2192 ${cves.length} CVEs (removed ${beforeCount - cves.length} non-matching)`);
    }
  }
  
  const result: CpeMatchResult = {
    technology,
    version: version || "*",
    cpeUri: cpeUri || `keyword:${technology}`,
    cves,
    matchConfidence,
    cachedAt: Date.now(),
  };
  
  // Update cache and stats
  cpeCache.set(cacheKey, result);
  stats.totalCvesFound += cves.length;
  stats.averageCvesPerTech = stats.totalQueries > 0
    ? Math.round((stats.totalCvesFound / stats.totalQueries) * 10) / 10
    : 0;
  stats.lastQueryTime = Date.now();
  
  console.log(`[DynamicCPE] ${technology} ${version || "*"}: ${cves.length} CVEs found (${matchConfidence} match via ${cpeUri ? "CPE" : "keyword"})`);
  return result;
}

/**
 * Batch match multiple technologies against NVD.
 * Respects rate limits by processing sequentially.
 */
export async function matchMultipleTechnologies(
  technologies: Array<{ name: string; version?: string }>
): Promise<CpeMatchResult[]> {
  const results: CpeMatchResult[] = [];
  
  for (const tech of technologies) {
    const result = await matchTechnologyCves(tech.name, tech.version);
    results.push(result);
  }
  
  return results;
}

/**
 * Check if a specific version is within an affected version range.
 * Compares semantic version strings.
 */
export function isVersionAffected(
  detectedVersion: string,
  affectedRange: string | null
): boolean {
  if (!affectedRange) return true; // No range info = assume affected
  
  const detected = parseVersion(detectedVersion);
  if (!detected) return true; // Can't parse = assume affected
  
  const conditions = affectedRange.split(",").map(c => c.trim());
  
  for (const condition of conditions) {
    const match = condition.match(/^([<>=!]+)\s*(.+)$/);
    if (!match) continue;
    
    const [, op, verStr] = match;
    const ver = parseVersion(verStr);
    if (!ver) continue;
    
    const cmp = compareVersions(detected, ver);
    
    switch (op) {
      case ">=": if (cmp < 0) return false; break;
      case ">":  if (cmp <= 0) return false; break;
      case "<=": if (cmp > 0) return false; break;
      case "<":  if (cmp >= 0) return false; break;
      case "=":  if (cmp !== 0) return false; break;
    }
  }
  
  return true;
}

/**
 * Filter CVEs to only those affecting the detected version.
 */
export function filterCvesByVersion(
  cves: CpeMatchedCve[],
  detectedVersion: string
): CpeMatchedCve[] {
  return cves.filter(cve => isVersionAffected(detectedVersion, cve.affectedVersionRange));
}

/**
 * Get current CPE matcher statistics
 */
export function getCpeMatchStats(): CpeMatchStats {
  return { ...stats };
}

/**
 * Clear the CPE cache (for testing or manual refresh)
 */
export function clearCpeCache(): void {
  cpeCache.clear();
  stats = {
    totalQueries: 0,
    cacheHits: 0,
    cacheMisses: 0,
    totalCvesFound: 0,
    averageCvesPerTech: 0,
    lastQueryTime: 0,
  };
}

// ─── Version Comparison Utilities ──────────────────────────────────

interface ParsedVersion {
  major: number;
  minor: number;
  patch: number;
  rest: string;
}

function parseVersion(version: string): ParsedVersion | null {
  const cleaned = version.replace(/^v/i, "").trim();
  const match = cleaned.match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(.*)$/);
  if (!match) return null;
  
  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2] || "0", 10),
    patch: parseInt(match[3] || "0", 10),
    rest: match[4] || "",
  };
}

function compareVersions(a: ParsedVersion, b: ParsedVersion): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;
  return 0;
}
