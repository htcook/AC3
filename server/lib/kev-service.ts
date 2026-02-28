/**
 * CISA Known Exploited Vulnerabilities (KEV) Service
 * 
 * Provides:
 * 1. Fetch & cache KEV catalog from CISA
 * 2. Match KEV entries against discovered technologies/products
 * 3. Match KEV entries against threat actor TTPs and CVEs
 * 4. Enrich domain analysis with KEV severity boosts
 * 5. Feed KEV-exploited techniques into attack chain builder
 */

const CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

async function fetchWithRetry(url: string, opts: RequestInit = {}, retries = 2, delay = 3000): Promise<Response> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fetch(url, opts);
    } catch (err: any) {
      if (attempt === retries) throw err;
      console.warn(`[KEV Service] Fetch attempt ${attempt + 1} failed, retrying in ${delay}ms...`);
      await new Promise(r => setTimeout(r, delay));
    }
  }
  throw new Error("fetchWithRetry exhausted");
}

export interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  shortDescription: string;
  dateAdded: string;
  dueDate: string;
  requiredAction: string;
  knownRansomwareCampaignUse: "Known" | "Unknown";
  notes: string;
}

export interface KevCatalog {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KevEntry[];
}

export interface KevMatch {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  shortDescription: string;
  dateAdded: string;
  dueDate: string;
  requiredAction: string;
  knownRansomware: boolean;
  matchType: "technology" | "product" | "cve" | "vendor";
  matchedOn: string;
  severityBoost: number; // 0-30 additional risk points
  suggestedTechniques: string[]; // MITRE ATT&CK technique IDs
  /** Quality of the match: exact_product > product_family > vendor_only */
  matchQuality?: "exact_product" | "product_family" | "vendor_only" | "fuzzy";
}

export interface KevStats {
  totalEntries: number;
  ransomwareLinked: number;
  recentlyAdded: number; // last 90 days
  topVendors: { vendor: string; count: number }[];
  topProducts: { product: string; count: number }[];
}

// In-memory cache
let cachedCatalog: KevCatalog | null = null;
let cacheTimestamp = 0;
const CACHE_TTL = 6 * 60 * 60 * 1000; // 6 hours

/**
 * Fetch the CISA KEV catalog (with in-memory caching)
 */
export async function fetchKevCatalog(): Promise<KevCatalog> {
  const now = Date.now();
  if (cachedCatalog && (now - cacheTimestamp) < CACHE_TTL) {
    return cachedCatalog;
  }

  try {
    const response = await fetchWithRetry(CISA_KEV_URL, {
      signal: AbortSignal.timeout(30000),
    });
    if (!response.ok) {
      throw new Error(`CISA KEV fetch failed: HTTP ${response.status}`);
    }
    const data = await response.json() as KevCatalog;
    cachedCatalog = data;
    cacheTimestamp = now;
    console.log(`[KEV Service] Fetched ${data.vulnerabilities?.length || 0} KEV entries (catalog v${data.catalogVersion})`);
    return data;
  } catch (err: any) {
    console.error(`[KEV Service] Fetch error: ${err.message}`);
    // Return cached data if available, even if stale
    if (cachedCatalog) {
      console.log("[KEV Service] Using stale cache");
      return cachedCatalog;
    }
    // Return empty catalog as fallback
    return { title: "CISA KEV", catalogVersion: "0", dateReleased: "", count: 0, vulnerabilities: [] };
  }
}

/**
 * Get KEV statistics
 */
export function getKevStats(catalog: KevCatalog): KevStats {
  const vulns = catalog.vulnerabilities || [];
  const now = new Date();
  const ninetyDaysAgo = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);

  const vendorCounts = new Map<string, number>();
  const productCounts = new Map<string, number>();
  let ransomwareLinked = 0;
  let recentlyAdded = 0;

  vulns.forEach(v => {
    if (v.knownRansomwareCampaignUse === "Known") ransomwareLinked++;
    if (new Date(v.dateAdded) >= ninetyDaysAgo) recentlyAdded++;

    const vendor = v.vendorProject?.toLowerCase() || "unknown";
    vendorCounts.set(vendor, (vendorCounts.get(vendor) || 0) + 1);

    const product = v.product?.toLowerCase() || "unknown";
    productCounts.set(product, (productCounts.get(product) || 0) + 1);
  });

  const topVendors = Array.from(vendorCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15)
    .map(([vendor, count]) => ({ vendor, count }));

  const topProducts = Array.from(productCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15)
    .map(([product, count]) => ({ product, count }));

  return {
    totalEntries: vulns.length,
    ransomwareLinked,
    recentlyAdded,
    topVendors,
    topProducts,
  };
}

/**
 * Technology-to-product mapping for matching discovered technologies against KEV
 * Maps common technology names (from OSINT/domain intel) to KEV vendor/product patterns
 */
const TECH_TO_KEV_PATTERNS: Record<string, { vendors: string[]; products: string[] }> = {
  // Web servers
  "apache": { vendors: ["apache"], products: ["http server", "httpd", "tomcat", "struts", "log4j"] },
  "nginx": { vendors: ["nginx"], products: ["nginx"] },
  "f5 big-ip": { vendors: ["f5"], products: ["big-ip", "big ip", "tmui", "traffic management"] },
  "big-ip": { vendors: ["f5"], products: ["big-ip", "big ip", "tmui", "traffic management"] },
  "iis": { vendors: ["microsoft"], products: ["internet information services", "iis"] },
  // CMS
  "wordpress": { vendors: ["wordpress"], products: ["wordpress"] },
  "drupal": { vendors: ["drupal"], products: ["drupal"] },
  "joomla": { vendors: ["joomla"], products: ["joomla"] },
  // Microsoft
  "exchange": { vendors: ["microsoft"], products: ["exchange server", "exchange"] },
  "sharepoint": { vendors: ["microsoft"], products: ["sharepoint"] },
  "outlook": { vendors: ["microsoft"], products: ["outlook", "office"] },
  "office 365": { vendors: ["microsoft"], products: ["office", "365"] },
  "windows": { vendors: ["microsoft"], products: ["windows"] },
  "active directory": { vendors: ["microsoft"], products: ["active directory", "windows server"] },
  "azure": { vendors: ["microsoft"], products: ["azure"] },
  ".net": { vendors: ["microsoft"], products: [".net", "asp.net"] },
  // Networking
  "cisco": { vendors: ["cisco"], products: ["ios", "asa", "anyconnect", "webex"] },
  "fortinet": { vendors: ["fortinet"], products: ["fortigate", "fortios", "forticlient"] },
  "palo alto": { vendors: ["palo alto", "paloalto"], products: ["pan-os", "globalprotect", "cortex"] },
  "juniper": { vendors: ["juniper"], products: ["junos", "srx"] },
  "sonicwall": { vendors: ["sonicwall"], products: ["sma", "sra", "sonicos"] },
  // VPN / Remote Access
  "pulse secure": { vendors: ["pulse secure", "ivanti"], products: ["pulse connect secure", "pulse secure"] },
  "citrix": { vendors: ["citrix"], products: ["adc", "gateway", "netscaler", "xenapp", "xendesktop"] },
  "vmware": { vendors: ["vmware"], products: ["vcenter", "esxi", "horizon", "workspace one"] },
  // Cloud
  "aws": { vendors: ["amazon"], products: ["aws", "ec2", "s3"] },
  "google cloud": { vendors: ["google"], products: ["chrome", "cloud"] },
  // Identity
  "okta": { vendors: ["okta"], products: ["okta"] },
  "sso": { vendors: ["okta", "microsoft", "ping"], products: ["sso", "active directory"] },
  // Databases
  "mysql": { vendors: ["oracle", "mysql"], products: ["mysql"] },
  "postgresql": { vendors: ["postgresql"], products: ["postgresql"] },
  "oracle": { vendors: ["oracle"], products: ["database", "weblogic", "java"] },
  "mssql": { vendors: ["microsoft"], products: ["sql server"] },
  // Java / Frameworks
  "java": { vendors: ["oracle", "apache"], products: ["java", "log4j", "struts", "tomcat"] },
  "log4j": { vendors: ["apache"], products: ["log4j"] },
  "spring": { vendors: ["vmware", "spring"], products: ["spring framework", "spring cloud"] },
  // Security
  "crowdstrike": { vendors: ["crowdstrike"], products: ["falcon"] },
  "sentinelone": { vendors: ["sentinelone"], products: ["sentinelone"] },
  "sophos": { vendors: ["sophos"], products: ["firewall", "xg"] },
  // Backup / RMM
  "veeam": { vendors: ["veeam"], products: ["backup"] },
  "connectwise": { vendors: ["connectwise"], products: ["screenconnect", "automate", "manage"] },
  "kaseya": { vendors: ["kaseya"], products: ["vsa", "unitrends"] },
  "datto": { vendors: ["datto"], products: ["rmm", "siris"] },
  // Mail
  "zimbra": { vendors: ["zimbra", "synacor"], products: ["zimbra"] },
  "roundcube": { vendors: ["roundcube"], products: ["roundcube"] },
  // Other
  "php": { vendors: ["php"], products: ["php"] },
  "openssh": { vendors: ["openbsd"], products: ["openssh"] },
  "openssl": { vendors: ["openssl"], products: ["openssl"] },
  "gitlab": { vendors: ["gitlab"], products: ["gitlab"] },
  "jenkins": { vendors: ["jenkins"], products: ["jenkins"] },
  "confluence": { vendors: ["atlassian"], products: ["confluence"] },
  "jira": { vendors: ["atlassian"], products: ["jira"] },
  "solarwinds": { vendors: ["solarwinds"], products: ["orion", "serv-u"] },
  "barracuda": { vendors: ["barracuda"], products: ["email security gateway"] },
  "progress": { vendors: ["progress"], products: ["moveit", "telerik"] },
  "moveit": { vendors: ["progress"], products: ["moveit"] },
};

/**
 * Map a KEV entry to MITRE ATT&CK techniques based on its description and product
 */
function mapKevToTechniques(kev: KevEntry): string[] {
  const techniques: string[] = [];
  const desc = (kev.shortDescription + " " + kev.vulnerabilityName).toLowerCase();

  // Exploitation techniques
  if (desc.includes("remote code execution") || desc.includes("rce")) {
    techniques.push("T1190", "T1059");
  }
  if (desc.includes("privilege escalation") || desc.includes("privilege elevation")) {
    techniques.push("T1068");
  }
  if (desc.includes("authentication bypass") || desc.includes("auth bypass")) {
    techniques.push("T1078", "T1190");
  }
  if (desc.includes("sql injection")) {
    techniques.push("T1190");
  }
  if (desc.includes("directory traversal") || desc.includes("path traversal")) {
    techniques.push("T1083", "T1190");
  }
  if (desc.includes("command injection") || desc.includes("os command")) {
    techniques.push("T1059", "T1190");
  }
  if (desc.includes("deserialization")) {
    techniques.push("T1190", "T1059");
  }
  if (desc.includes("buffer overflow") || desc.includes("heap overflow") || desc.includes("stack overflow")) {
    techniques.push("T1190", "T1203");
  }
  if (desc.includes("arbitrary file") || desc.includes("file upload")) {
    techniques.push("T1190", "T1105");
  }
  if (desc.includes("credential") || desc.includes("password")) {
    techniques.push("T1078", "T1110");
  }
  if (desc.includes("information disclosure") || desc.includes("sensitive data")) {
    techniques.push("T1005", "T1083");
  }
  if (desc.includes("denial of service") || desc.includes("dos")) {
    techniques.push("T1499");
  }
  if (desc.includes("cross-site scripting") || desc.includes("xss")) {
    techniques.push("T1189");
  }
  if (desc.includes("server-side request forgery") || desc.includes("ssrf")) {
    techniques.push("T1190");
  }
  if (desc.includes("use-after-free")) {
    techniques.push("T1203");
  }

  // Product-specific techniques
  const product = (kev.product + " " + kev.vendorProject).toLowerCase();
  if (product.includes("vpn") || product.includes("pulse") || product.includes("fortinet") || product.includes("anyconnect")) {
    techniques.push("T1133"); // External Remote Services
  }
  if (product.includes("exchange") || product.includes("email") || product.includes("zimbra")) {
    techniques.push("T1114"); // Email Collection
  }
  if (product.includes("active directory") || product.includes("ldap")) {
    techniques.push("T1558", "T1003"); // Kerberoasting, OS Credential Dumping
  }
  if (product.includes("browser") || product.includes("chrome") || product.includes("firefox") || product.includes("edge")) {
    techniques.push("T1189"); // Drive-by Compromise
  }

  // Default: all KEV entries involve exploitation of public-facing apps
  if (techniques.length === 0) {
    techniques.push("T1190");
  }

  return Array.from(new Set(techniques));
}

/**
 * Match discovered technologies against the KEV catalog
 */
export function matchTechnologiesAgainstKev(
  technologies: string[],
  catalog: KevCatalog
): KevMatch[] {
  const matches: KevMatch[] = [];
  const seen = new Set<string>();

  technologies.forEach(tech => {
    const techLower = tech.toLowerCase().trim();

    // Check direct technology mapping — REQUIRE product match (vendor-only is too broad)
    for (const [pattern, mapping] of Object.entries(TECH_TO_KEV_PATTERNS)) {
      if (techLower.includes(pattern) || pattern.includes(techLower)) {
        catalog.vulnerabilities.forEach(kev => {
          if (seen.has(kev.cveID)) return;

          const kevVendor = (kev.vendorProject || "").toLowerCase();
          const kevProduct = (kev.product || "").toLowerCase();

          const vendorMatch = mapping.vendors.some(v => kevVendor.includes(v));
          const productMatch = mapping.products.some(p => kevProduct.includes(p));

          // FIX: Require BOTH vendor AND product match to prevent cross-product contamination.
          // Previously vendorMatch || productMatch caused "IIS" to match ALL Microsoft KEV entries
          // (SharePoint, Windows CLFS, Office, etc.) because IIS maps to vendors:["microsoft"].
          if (vendorMatch && productMatch) {
            seen.add(kev.cveID);
            matches.push({
              cveID: kev.cveID,
              vendorProject: kev.vendorProject,
              product: kev.product,
              vulnerabilityName: kev.vulnerabilityName,
              shortDescription: kev.shortDescription,
              dateAdded: kev.dateAdded,
              dueDate: kev.dueDate,
              requiredAction: kev.requiredAction,
              knownRansomware: kev.knownRansomwareCampaignUse === "Known",
              matchType: "product",
              matchedOn: tech,
              severityBoost: kev.knownRansomwareCampaignUse === "Known" ? 12 : 8,
              suggestedTechniques: mapKevToTechniques(kev),
              matchQuality: "exact_product",
            });
          }
        });
      }
    }

    // Fuzzy matching: only match when the technology name closely matches the KEV PRODUCT
    // (not just the vendor). This prevents "nginx" from matching all F5 entries, etc.
    catalog.vulnerabilities.forEach(kev => {
      if (seen.has(kev.cveID)) return;
      const kevProduct = (kev.product || "").toLowerCase();

      // Only match if the tech name is a close match to the KEV product name
      // (not the vendor — vendor-only matching is too broad for passive scans)
      if (
        techLower.length >= 4 &&
        (kevProduct.includes(techLower) || techLower.includes(kevProduct)) &&
        kevProduct.length >= 3 // Avoid matching empty or very short product names
      ) {
        seen.add(kev.cveID);
        matches.push({
          cveID: kev.cveID,
          vendorProject: kev.vendorProject,
          product: kev.product,
          vulnerabilityName: kev.vulnerabilityName,
          shortDescription: kev.shortDescription,
          dateAdded: kev.dateAdded,
          dueDate: kev.dueDate,
          requiredAction: kev.requiredAction,
          knownRansomware: kev.knownRansomwareCampaignUse === "Known",
          matchType: "technology",
          matchedOn: tech,
          severityBoost: kev.knownRansomwareCampaignUse === "Known" ? 10 : 6,
          suggestedTechniques: mapKevToTechniques(kev),
          matchQuality: "fuzzy",
        });
      }
    });
  });

  // Sort by severity boost (ransomware first), then by date added (newest first)
  return matches.sort((a, b) => {
    if (a.knownRansomware !== b.knownRansomware) return a.knownRansomware ? -1 : 1;
    return new Date(b.dateAdded).getTime() - new Date(a.dateAdded).getTime();
  });
}

/**
 * Match specific CVE IDs against the KEV catalog
 */
export function matchCvesAgainstKev(
  cveIds: string[],
  catalog: KevCatalog
): KevMatch[] {
  const kevMap = new Map<string, KevEntry>();
  catalog.vulnerabilities.forEach(v => kevMap.set(v.cveID, v));

  return cveIds
    .filter(cve => kevMap.has(cve))
    .map(cve => {
      const kev = kevMap.get(cve)!;
      return {
        cveID: kev.cveID,
        vendorProject: kev.vendorProject,
        product: kev.product,
        vulnerabilityName: kev.vulnerabilityName,
        shortDescription: kev.shortDescription,
        dateAdded: kev.dateAdded,
        dueDate: kev.dueDate,
        requiredAction: kev.requiredAction,
        knownRansomware: kev.knownRansomwareCampaignUse === "Known",
        matchType: "cve" as const,
        matchedOn: cve,
        severityBoost: kev.knownRansomwareCampaignUse === "Known" ? 15 : 10,
        suggestedTechniques: mapKevToTechniques(kev),
      };
    });
}

/**
 * Match threat actor CVEs against KEV to identify which actor TTPs exploit known vulnerabilities
 */
export function matchActorTtpsAgainstKev(
  actorTechniques: Array<{ id: string; name: string; tactic?: string; cves?: string[] }>,
  catalog: KevCatalog
): {
  kevExploitedTechniques: Array<{ techniqueId: string; techniqueName: string; kevEntries: KevMatch[] }>;
  totalKevMatches: number;
  ransomwareLinkedCount: number;
} {
  const kevMap = new Map<string, KevEntry>();
  catalog.vulnerabilities.forEach(v => kevMap.set(v.cveID, v));

  const results: Array<{ techniqueId: string; techniqueName: string; kevEntries: KevMatch[] }> = [];
  let totalKevMatches = 0;
  let ransomwareLinkedCount = 0;

  actorTechniques.forEach(tech => {
    if (!tech.cves || tech.cves.length === 0) return;

    const kevMatches = tech.cves
      .filter(cve => kevMap.has(cve))
      .map(cve => {
        const kev = kevMap.get(cve)!;
        return {
          cveID: kev.cveID,
          vendorProject: kev.vendorProject,
          product: kev.product,
          vulnerabilityName: kev.vulnerabilityName,
          shortDescription: kev.shortDescription,
          dateAdded: kev.dateAdded,
          dueDate: kev.dueDate,
          requiredAction: kev.requiredAction,
          knownRansomware: kev.knownRansomwareCampaignUse === "Known",
          matchType: "cve" as const,
          matchedOn: cve,
          severityBoost: kev.knownRansomwareCampaignUse === "Known" ? 15 : 10,
          suggestedTechniques: mapKevToTechniques(kev),
        };
      });

    if (kevMatches.length > 0) {
      results.push({
        techniqueId: tech.id,
        techniqueName: tech.name,
        kevEntries: kevMatches,
      });
      totalKevMatches += kevMatches.length;
      ransomwareLinkedCount += kevMatches.filter(m => m.knownRansomware).length;
    }
  });

  return { kevExploitedTechniques: results, totalKevMatches, ransomwareLinkedCount };
}

/**
 * Generate KEV-informed attack chain steps
 * Returns technique IDs and context for the chain builder to use
 */
export function getKevChainSteps(
  kevMatches: KevMatch[]
): Array<{ techniqueId: string; priority: number; source: "kev"; context: string }> {
  const steps: Array<{ techniqueId: string; priority: number; source: "kev"; context: string }> = [];
  const seenTechniques = new Set<string>();

  kevMatches.forEach(match => {
    match.suggestedTechniques.forEach(tid => {
      if (seenTechniques.has(tid)) return;
      seenTechniques.add(tid);

      steps.push({
        techniqueId: tid,
        priority: match.knownRansomware ? 100 : 80, // KEV entries get high priority
        source: "kev",
        context: `KEV: ${match.cveID} - ${match.vulnerabilityName} (${match.vendorProject} ${match.product})${match.knownRansomware ? " [RANSOMWARE]" : ""}`,
      });
    });
  });

  return steps.sort((a, b) => b.priority - a.priority);
}

/**
 * Enrich domain analysis risk score with KEV findings
 */
export function calculateKevRiskBoost(kevMatches: KevMatch[]): {
  riskBoost: number;
  ransomwareExposure: boolean;
  criticalKevCount: number;
  summary: string;
} {
  if (kevMatches.length === 0) {
    return { riskBoost: 0, ransomwareExposure: false, criticalKevCount: 0, summary: "No CISA KEV matches found." };
  }

  const ransomwareMatches = kevMatches.filter(m => m.knownRansomware);
  const maxBoost = Math.min(
    kevMatches.reduce((sum, m) => sum + Math.min(m.severityBoost, 8), 0),
    20 // Cap at 20 points (was 40) — KEV boost is informational, not a score multiplier
  );

  return {
    riskBoost: maxBoost,
    ransomwareExposure: ransomwareMatches.length > 0,
    criticalKevCount: kevMatches.length,
    summary: `${kevMatches.length} CISA KEV match${kevMatches.length > 1 ? "es" : ""} found across discovered technologies. ${ransomwareMatches.length > 0 ? `${ransomwareMatches.length} linked to known ransomware campaigns. ` : ""}Risk score boosted by ${maxBoost} points.`,
  };
}

// Export for testing
export { mapKevToTechniques, TECH_TO_KEV_PATTERNS };
