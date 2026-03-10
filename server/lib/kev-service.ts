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
 * Extract version from a technology string like "Apache/2.4.49", "nginx 1.21.3", "PHP/8.1.2"
 */
function extractVersion(tech: string): { name: string; version: string | null; major: number | null; minor: number | null; patch: number | null } {
  // Common patterns: "Apache/2.4.49", "nginx/1.21.3", "PHP/8.1.2", "OpenSSH_8.9p1"
  const patterns = [
    /^([\w.\-\s]+?)[\/\s_]v?(\d+(?:\.\d+)*(?:[\-_]?[a-z]\d*)?)/i,
    /^([\w.\-\s]+?)\s+version\s+(\d+(?:\.\d+)*)/i,
  ];
  for (const pat of patterns) {
    const m = tech.match(pat);
    if (m) {
      const name = m[1].trim().toLowerCase();
      const ver = m[2];
      const parts = ver.split(".").map(p => parseInt(p, 10));
      return { name, version: ver, major: parts[0] ?? null, minor: parts[1] ?? null, patch: parts[2] ?? null };
    }
  }
  return { name: tech.toLowerCase().trim(), version: null, major: null, minor: null, patch: null };
}

/**
 * Check if a KEV vulnerability name/description mentions a version range that matches the detected version.
 * Returns: "confirmed" if version matches, "potential" if no version info to compare, "excluded" if version clearly doesn't match.
 */
function checkVersionRelevance(
  detectedVersion: { version: string | null; major: number | null; minor: number | null },
  kevVulnName: string,
  kevDescription: string
): "confirmed" | "potential" | "excluded" {
  if (!detectedVersion.version || detectedVersion.major === null) return "potential";

  const combined = (kevVulnName + " " + kevDescription).toLowerCase();

  // Extract version references from KEV text
  const versionRefs = combined.match(/(\d+\.\d+(?:\.\d+)*)/g);
  if (!versionRefs || versionRefs.length === 0) return "potential"; // No version in KEV = can't confirm or exclude

  // Check if any referenced version shares the same major.minor
  for (const ref of versionRefs) {
    const refParts = ref.split(".").map(p => parseInt(p, 10));
    const refMajor = refParts[0];
    const refMinor = refParts[1] ?? null;

    if (refMajor === detectedVersion.major) {
      // Same major version — if minor also matches or minor isn't specified, it's relevant
      if (refMinor === null || detectedVersion.minor === null || refMinor === detectedVersion.minor) {
        return "confirmed";
      }
      // Same major, different minor — still potentially relevant (e.g., "before 2.4.50" affects 2.4.49)
      if (combined.includes("before") || combined.includes("prior to") || combined.includes("through")) {
        return "confirmed";
      }
    }
  }

  // Has version refs but none match our major version — likely not relevant
  return "excluded";
}

/**
 * Technology-to-product mapping for matching discovered technologies against KEV
 * Maps common technology names (from OSINT/domain intel) to KEV vendor/product patterns
 * IMPORTANT: Each tech maps to SPECIFIC products only — no cross-product contamination
 */
const TECH_TO_KEV_PATTERNS: Record<string, { vendors: string[]; products: string[] }> = {
  // Web servers — each maps to its OWN product only
  "apache httpd": { vendors: ["apache"], products: ["http server", "httpd"] },
  "apache http server": { vendors: ["apache"], products: ["http server", "httpd"] },
  "apache": { vendors: ["apache"], products: ["http server", "httpd"] }, // Default apache = httpd, NOT struts/log4j/tomcat
  "tomcat": { vendors: ["apache"], products: ["tomcat"] },
  "struts": { vendors: ["apache"], products: ["struts"] },
  "log4j": { vendors: ["apache"], products: ["log4j"] },
  "nginx": { vendors: ["nginx", "f5"], products: ["nginx"] },
  "f5 big-ip": { vendors: ["f5"], products: ["big-ip", "big ip", "tmui", "traffic management"] },
  "big-ip": { vendors: ["f5"], products: ["big-ip", "big ip", "tmui", "traffic management"] },
  "iis": { vendors: ["microsoft"], products: ["internet information services", "iis"] },
  // CMS
  "wordpress": { vendors: ["wordpress"], products: ["wordpress"] },
  "drupal": { vendors: ["drupal"], products: ["drupal"] },
  "joomla": { vendors: ["joomla"], products: ["joomla"] },
  // Microsoft — specific products only
  "exchange": { vendors: ["microsoft"], products: ["exchange server", "exchange"] },
  "sharepoint": { vendors: ["microsoft"], products: ["sharepoint"] },
  "outlook": { vendors: ["microsoft"], products: ["outlook"] },
  "office 365": { vendors: ["microsoft"], products: ["office 365", "365"] },
  "windows server": { vendors: ["microsoft"], products: ["windows server"] },
  "active directory": { vendors: ["microsoft"], products: ["active directory"] },
  "azure": { vendors: ["microsoft"], products: ["azure"] },
  ".net": { vendors: ["microsoft"], products: [".net", "asp.net"] },
  // Networking — specific product lines
  "cisco asa": { vendors: ["cisco"], products: ["asa", "adaptive security"] },
  "cisco ios": { vendors: ["cisco"], products: ["ios"] },
  "anyconnect": { vendors: ["cisco"], products: ["anyconnect"] },
  "fortios": { vendors: ["fortinet"], products: ["fortios"] },
  "fortigate": { vendors: ["fortinet"], products: ["fortigate", "fortios"] },
  "forticlient": { vendors: ["fortinet"], products: ["forticlient"] },
  "palo alto": { vendors: ["palo alto", "paloalto"], products: ["pan-os", "globalprotect", "cortex"] },
  "juniper": { vendors: ["juniper"], products: ["junos", "srx"] },
  "sonicwall": { vendors: ["sonicwall"], products: ["sma", "sra", "sonicos"] },
  // VPN / Remote Access
  "pulse secure": { vendors: ["pulse secure", "ivanti"], products: ["pulse connect secure", "pulse secure"] },
  "citrix": { vendors: ["citrix"], products: ["adc", "gateway", "netscaler"] },
  "vmware vcenter": { vendors: ["vmware"], products: ["vcenter"] },
  "vmware esxi": { vendors: ["vmware"], products: ["esxi"] },
  "vmware horizon": { vendors: ["vmware"], products: ["horizon"] },
  // Identity
  "okta": { vendors: ["okta"], products: ["okta"] },
  // Databases — specific products only
  "mysql": { vendors: ["oracle", "mysql"], products: ["mysql"] },
  "postgresql": { vendors: ["postgresql"], products: ["postgresql"] },
  "oracle database": { vendors: ["oracle"], products: ["database"] },
  "oracle weblogic": { vendors: ["oracle"], products: ["weblogic"] },
  "mssql": { vendors: ["microsoft"], products: ["sql server"] },
  "sql server": { vendors: ["microsoft"], products: ["sql server"] },
  // Java — ONLY matches Java SE, NOT log4j/struts/tomcat
  "java": { vendors: ["oracle"], products: ["java se", "jre", "jdk"] },
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
  "progress moveit": { vendors: ["progress"], products: ["moveit"] },
  "moveit": { vendors: ["progress"], products: ["moveit"] },
  "telerik": { vendors: ["progress"], products: ["telerik"] },
  // Cloud & Container
  "kubernetes": { vendors: ["kubernetes"], products: ["kubernetes"] },
  "k8s": { vendors: ["kubernetes"], products: ["kubernetes"] },
  "docker": { vendors: ["docker"], products: ["docker", "docker desktop"] },
  "containerd": { vendors: ["containerd"], products: ["containerd"] },
  "aws": { vendors: ["amazon"], products: ["aws", "ec2", "s3", "lambda", "cloudfront"] },
  "amazon ec2": { vendors: ["amazon"], products: ["ec2"] },
  "amazon s3": { vendors: ["amazon"], products: ["s3"] },
  "google cloud": { vendors: ["google"], products: ["cloud platform", "gcp"] },
  "terraform": { vendors: ["hashicorp"], products: ["terraform"] },
  "vault": { vendors: ["hashicorp"], products: ["vault"] },
  "consul": { vendors: ["hashicorp"], products: ["consul"] },
  // CI/CD & DevOps
  "github": { vendors: ["github"], products: ["enterprise server", "actions"] },
  "bitbucket": { vendors: ["atlassian"], products: ["bitbucket"] },
  "bamboo": { vendors: ["atlassian"], products: ["bamboo"] },
  "teamcity": { vendors: ["jetbrains"], products: ["teamcity"] },
  "argo cd": { vendors: ["argoproj"], products: ["argo cd"] },
  "harbor": { vendors: ["harbor"], products: ["harbor"] },
  "nexus": { vendors: ["sonatype"], products: ["nexus"] },
  "artifactory": { vendors: ["jfrog"], products: ["artifactory"] },
  // Modern Web Frameworks
  "node.js": { vendors: ["nodejs"], products: ["node.js"] },
  "nodejs": { vendors: ["nodejs"], products: ["node.js"] },
  "express": { vendors: ["expressjs"], products: ["express"] },
  "django": { vendors: ["django"], products: ["django"] },
  "flask": { vendors: ["palletsprojects"], products: ["flask"] },
  "ruby on rails": { vendors: ["rubyonrails"], products: ["rails"] },
  "rails": { vendors: ["rubyonrails"], products: ["rails"] },
  "laravel": { vendors: ["laravel"], products: ["laravel"] },
  // API Gateways & Proxies
  "kong": { vendors: ["kong"], products: ["kong gateway"] },
  "envoy": { vendors: ["envoyproxy"], products: ["envoy"] },
  "traefik": { vendors: ["traefik"], products: ["traefik"] },
  "haproxy": { vendors: ["haproxy"], products: ["haproxy"] },
  "caddy": { vendors: ["caddyserver"], products: ["caddy"] },
  // Message Queues & Data
  "redis": { vendors: ["redis"], products: ["redis"] },
  "rabbitmq": { vendors: ["vmware", "pivotal"], products: ["rabbitmq"] },
  "kafka": { vendors: ["apache"], products: ["kafka"] },
  "elasticsearch": { vendors: ["elastic"], products: ["elasticsearch", "kibana"] },
  "kibana": { vendors: ["elastic"], products: ["kibana"] },
  "grafana": { vendors: ["grafana"], products: ["grafana"] },
  "prometheus": { vendors: ["prometheus"], products: ["prometheus"] },
  "mongodb": { vendors: ["mongodb"], products: ["mongodb"] },
  "couchdb": { vendors: ["apache"], products: ["couchdb"] },
  // Network Appliances (expanded)
  "ivanti": { vendors: ["ivanti"], products: ["connect secure", "policy secure", "epmm", "avalanche"] },
  "zyxel": { vendors: ["zyxel"], products: ["firewall", "vpn", "nas"] },
  "netgear": { vendors: ["netgear"], products: ["prosafe", "readynas"] },
  "qnap": { vendors: ["qnap"], products: ["qts", "photo station"] },
  "synology": { vendors: ["synology"], products: ["diskstation", "dsm"] },
  // Identity & Access (expanded)
  "keycloak": { vendors: ["redhat"], products: ["keycloak"] },
  "auth0": { vendors: ["auth0"], products: ["auth0"] },
  "pingfederate": { vendors: ["ping identity"], products: ["pingfederate"] },
  "adfs": { vendors: ["microsoft"], products: ["active directory federation services"] },
  // Monitoring & Management
  "nagios": { vendors: ["nagios"], products: ["nagios", "nagios xi"] },
  "zabbix": { vendors: ["zabbix"], products: ["zabbix"] },
  "splunk": { vendors: ["splunk"], products: ["splunk"] },
  "manageengine": { vendors: ["zoho", "manageengine"], products: ["servicedesk", "adselfservice"] },
  // File Transfer
  "goanywhere": { vendors: ["fortra"], products: ["goanywhere"] },
  "aspera": { vendors: ["ibm"], products: ["aspera"] },
  "accellion": { vendors: ["accellion"], products: ["fta"] },
  "globalscape": { vendors: ["globalscape"], products: ["eft"] },
  // Collaboration
  "mattermost": { vendors: ["mattermost"], products: ["mattermost"] },
  "rocket.chat": { vendors: ["rocket.chat"], products: ["rocket.chat"] },
  "nextcloud": { vendors: ["nextcloud"], products: ["nextcloud"] },
  "owncloud": { vendors: ["owncloud"], products: ["owncloud"] },
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

  // Cloud & Container-specific techniques
  if (product.includes("kubernetes") || product.includes("k8s")) {
    techniques.push("T1610", "T1609"); // Deploy Container, Container Administration Command
  }
  if (product.includes("docker") || product.includes("containerd")) {
    techniques.push("T1610", "T1611"); // Deploy Container, Escape to Host
  }
  if (product.includes("aws") || product.includes("ec2") || product.includes("s3") || product.includes("lambda")) {
    techniques.push("T1078.004"); // Valid Accounts: Cloud Accounts
  }
  if (product.includes("terraform") || product.includes("vault") || product.includes("consul")) {
    techniques.push("T1552", "T1078"); // Unsecured Credentials, Valid Accounts
  }
  // CI/CD pipeline compromise
  if (product.includes("jenkins") || product.includes("teamcity") || product.includes("bamboo") || product.includes("github") || product.includes("gitlab")) {
    techniques.push("T1195.002"); // Supply Chain: Compromise Software Supply Chain
  }
  // File transfer exploitation (common in ransomware)
  if (product.includes("moveit") || product.includes("goanywhere") || product.includes("accellion") || product.includes("aspera")) {
    techniques.push("T1190", "T1567"); // Exploit Public-Facing, Exfiltration Over Web Service
  }
  // Identity provider compromise
  if (product.includes("okta") || product.includes("keycloak") || product.includes("adfs") || product.includes("pingfederate")) {
    techniques.push("T1556", "T1550"); // Modify Authentication Process, Use Alternate Auth Material
  }
  // Monitoring tool compromise (used for lateral movement)
  if (product.includes("solarwinds") || product.includes("nagios") || product.includes("zabbix") || product.includes("manageengine")) {
    techniques.push("T1195.002", "T1072"); // Supply Chain, Software Deployment Tools
  }

  // Default: all KEV entries involve exploitation of public-facing apps
  if (techniques.length === 0) {
    techniques.push("T1190");
  }

  return Array.from(new Set(techniques));
}

/**
 * Match discovered technologies against the KEV catalog
 * Version-aware matching with three confidence tiers:
 *   - version_confirmed: product matches AND detected version falls in the KEV's affected range
 *   - exact_product: product matches but no version info to confirm/exclude
 *   - product_family: vendor+product family match (lower confidence)
 *   - fuzzy: name-only match (lowest confidence, reduced severity boost)
 */
export function matchTechnologiesAgainstKev(
  technologies: string[],
  catalog: KevCatalog
): KevMatch[] {
  const matches: KevMatch[] = [];
  const seen = new Set<string>();

  // Blocklist: generic terms that should NEVER trigger fuzzy matching
  const FUZZY_BLOCKLIST = new Set([
    "http", "https", "html", "css", "json", "xml", "api", "web", "app",
    "mail", "smtp", "imap", "pop3", "ftp", "ssh", "dns", "tcp", "udp",
    "ssl", "tls", "cdn", "waf", "load", "proxy", "cache", "server",
    "linux", "unix", "cloud", "saas", "platform",
  ]);

  technologies.forEach(tech => {
    const parsed = extractVersion(tech);
    const techLower = parsed.name;

    // Phase 1: Mapped product matching with version awareness
    // IMPORTANT: Only match if the detected tech name contains the pattern key.
    // The reverse check (pattern.includes(techLower)) was removed because short
    // tech names like "api", "cdn", or "app" would match inside longer pattern
    // keys (e.g. "api" inside "apache"), pulling in completely unrelated KEV entries.
    for (const [pattern, mapping] of Object.entries(TECH_TO_KEV_PATTERNS)) {
      // Require minimum 3-char tech name to avoid generic protocol/term matches
      if (techLower.length < 3) continue;
      // Only forward match: detected tech must contain the pattern key
      // e.g. "nginx" includes "nginx" ✓, but "api" does NOT include "apache" ✓
      if (techLower.includes(pattern) || techLower === pattern) {
        catalog.vulnerabilities.forEach(kev => {
          if (seen.has(kev.cveID)) return;

          const kevVendor = (kev.vendorProject || "").toLowerCase();
          const kevProduct = (kev.product || "").toLowerCase();

          const vendorMatch = mapping.vendors.some(v => kevVendor.includes(v));
          const productMatch = mapping.products.some(p => kevProduct.includes(p));

          if (vendorMatch && productMatch) {
            // Version-aware confirmation
            const versionCheck = checkVersionRelevance(
              parsed,
              kev.vulnerabilityName,
              kev.shortDescription
            );

            if (versionCheck === "excluded") return; // Version clearly doesn't match — skip

            const isVersionConfirmed = versionCheck === "confirmed";
            const quality: KevMatch["matchQuality"] = isVersionConfirmed ? "exact_product" : "product_family";

            // Severity boost scales with confidence
            let boost: number;
            if (isVersionConfirmed) {
              boost = kev.knownRansomwareCampaignUse === "Known" ? 15 : 10;
            } else {
              // Unversioned match — lower boost since we can't confirm the version is affected
              boost = kev.knownRansomwareCampaignUse === "Known" ? 8 : 4;
            }

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
              severityBoost: boost,
              suggestedTechniques: mapKevToTechniques(kev),
              matchQuality: quality,
            });
          }
        });
      }
    }

    // Phase 2: Tightened fuzzy matching — only for specific, non-generic tech names
    // Requires: min 6 chars, not in blocklist, exact word boundary match (not substring)
    if (techLower.length >= 6 && !FUZZY_BLOCKLIST.has(techLower)) {
      catalog.vulnerabilities.forEach(kev => {
        if (seen.has(kev.cveID)) return;
        const kevProduct = (kev.product || "").toLowerCase();
        if (kevProduct.length < 4) return;

        // Require exact word match, not just substring containment
        // e.g., "gitlab" should match "GitLab" but NOT "digital"
        const techWords = techLower.split(/[\s\/\-_]+/);
        const productWords = kevProduct.split(/[\s\/\-_]+/);
        const hasExactWordMatch = techWords.some(tw =>
          tw.length >= 5 && productWords.some(pw => pw === tw || (pw.length >= 5 && pw.startsWith(tw)))
        );

        if (!hasExactWordMatch) return;

        // Version check for fuzzy matches too
        const versionCheck = checkVersionRelevance(parsed, kev.vulnerabilityName, kev.shortDescription);
        if (versionCheck === "excluded") return;

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
          // Fuzzy matches get minimal severity boost — they're informational, not confirmed
          severityBoost: versionCheck === "confirmed" ? 6 : 2,
          suggestedTechniques: mapKevToTechniques(kev),
          matchQuality: "fuzzy",
        });
      });
    }
  });

  // Sort: version-confirmed first, then ransomware, then by date
  return matches.sort((a, b) => {
    // Quality priority: exact_product > product_family > fuzzy
    const qualityOrder: Record<string, number> = { exact_product: 0, product_family: 1, vendor_only: 2, fuzzy: 3 };
    const qa = qualityOrder[a.matchQuality || "fuzzy"] ?? 3;
    const qb = qualityOrder[b.matchQuality || "fuzzy"] ?? 3;
    if (qa !== qb) return qa - qb;
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
 * Only version-confirmed and exact_product matches contribute full boost.
 * Fuzzy/unversioned matches contribute reduced boost.
 */
export function calculateKevRiskBoost(kevMatches: KevMatch[]): {
  riskBoost: number;
  ransomwareExposure: boolean;
  criticalKevCount: number;
  confirmedCount: number;
  potentialCount: number;
  summary: string;
} {
  if (kevMatches.length === 0) {
    return { riskBoost: 0, ransomwareExposure: false, criticalKevCount: 0, confirmedCount: 0, potentialCount: 0, summary: "No CISA KEV matches found." };
  }

  const confirmed = kevMatches.filter(m => m.matchQuality === "exact_product");
  const potential = kevMatches.filter(m => m.matchQuality !== "exact_product");
  const ransomwareMatches = kevMatches.filter(m => m.knownRansomware && m.matchQuality !== "fuzzy");

  // Only confirmed matches get full boost; fuzzy matches get minimal boost
  const confirmedBoost = confirmed.reduce((sum, m) => sum + Math.min(m.severityBoost, 10), 0);
  const potentialBoost = potential.reduce((sum, m) => sum + Math.min(m.severityBoost, 3), 0);
  const maxBoost = Math.min(confirmedBoost + potentialBoost, 20);

  const parts: string[] = [];
  if (confirmed.length > 0) {
    parts.push(`${confirmed.length} confirmed KEV match${confirmed.length > 1 ? "es" : ""} (version-verified)`);
  }
  if (potential.length > 0) {
    parts.push(`${potential.length} potential match${potential.length > 1 ? "es" : ""} (version unconfirmed)`);
  }
  if (ransomwareMatches.length > 0) {
    parts.push(`${ransomwareMatches.length} linked to known ransomware campaigns`);
  }

  return {
    riskBoost: maxBoost,
    ransomwareExposure: ransomwareMatches.length > 0,
    criticalKevCount: confirmed.length,
    confirmedCount: confirmed.length,
    potentialCount: potential.length,
    summary: parts.join(". ") + `. Risk score boosted by ${maxBoost} points.`,
  };
}

/**
 * Classify KEV entries by OWASP Top 10:2025 category based on vulnerability description
 */
export function classifyKevByOwasp(kev: KevEntry): string[] {
  const desc = (kev.shortDescription + " " + kev.vulnerabilityName).toLowerCase();
  const categories: string[] = [];

  // A01: Broken Access Control
  if (desc.includes("authentication bypass") || desc.includes("authorization") ||
      desc.includes("privilege escalation") || desc.includes("access control") ||
      desc.includes("directory traversal") || desc.includes("path traversal") ||
      desc.includes("idor") || desc.includes("insecure direct object")) {
    categories.push("A01:2025-Broken_Access_Control");
  }
  // A02: Cryptographic Failures
  if (desc.includes("cryptograph") || desc.includes("encryption") ||
      desc.includes("certificate") || desc.includes("tls") || desc.includes("ssl") ||
      desc.includes("key disclosure") || desc.includes("weak cipher")) {
    categories.push("A02:2025-Cryptographic_Failures");
  }
  // A03: Injection
  if (desc.includes("injection") || desc.includes("sql injection") ||
      desc.includes("command injection") || desc.includes("code injection") ||
      desc.includes("ldap injection") || desc.includes("xpath") ||
      desc.includes("template injection") || desc.includes("expression language")) {
    categories.push("A03:2025-Injection");
  }
  // A04: Insecure Design
  if (desc.includes("insecure design") || desc.includes("logic flaw") ||
      desc.includes("business logic") || desc.includes("race condition")) {
    categories.push("A04:2025-Insecure_Design");
  }
  // A05: Security Misconfiguration
  if (desc.includes("misconfigur") || desc.includes("default credential") ||
      desc.includes("default password") || desc.includes("information disclosure") ||
      desc.includes("debug") || desc.includes("stack trace") ||
      desc.includes("unnecessary feature")) {
    categories.push("A05:2025-Security_Misconfiguration");
  }
  // A06: Vulnerable and Outdated Components
  if (desc.includes("outdated") || desc.includes("end-of-life") ||
      desc.includes("unsupported") || desc.includes("known vulnerable")) {
    categories.push("A06:2025-Vulnerable_Outdated_Components");
  }
  // A07: Identification and Authentication Failures
  if (desc.includes("credential") || desc.includes("password") ||
      desc.includes("brute force") || desc.includes("session") ||
      desc.includes("token") || desc.includes("authentication failure")) {
    categories.push("A07:2025-Auth_Failures");
  }
  // A08: Software and Data Integrity Failures
  if (desc.includes("deserialization") || desc.includes("integrity") ||
      desc.includes("supply chain") || desc.includes("ci/cd") ||
      desc.includes("auto-update")) {
    categories.push("A08:2025-Integrity_Failures");
  }
  // A09: Security Logging and Monitoring Failures
  if (desc.includes("logging") || desc.includes("monitoring") ||
      desc.includes("audit") || desc.includes("log injection")) {
    categories.push("A09:2025-Logging_Monitoring_Failures");
  }
  // A10: Server-Side Request Forgery
  if (desc.includes("ssrf") || desc.includes("server-side request forgery") ||
      desc.includes("server side request")) {
    categories.push("A10:2025-SSRF");
  }

  // All KEV entries are at least A06 (known vulnerable component)
  if (!categories.includes("A06:2025-Vulnerable_Outdated_Components")) {
    categories.push("A06:2025-Vulnerable_Outdated_Components");
  }
  return categories;
}

/**
 * Filter KEV catalog for web-focused engagements — returns entries most relevant
 * to web application testing, excluding OS-only and hardware-only entries
 */
export function filterKevForWebEngagement(catalog: KevCatalog): KevEntry[] {
  const webRelevantVendors = new Set([
    "apache", "nginx", "f5", "microsoft", "wordpress", "drupal", "joomla",
    "atlassian", "gitlab", "jenkins", "php", "oracle", "vmware", "spring",
    "nodejs", "django", "laravel", "progress", "citrix", "pulse secure",
    "ivanti", "fortinet", "palo alto", "sonicwall", "barracuda", "zimbra",
    "roundcube", "grafana", "elastic", "redis", "mongodb", "hashicorp",
    "docker", "kubernetes", "harbor", "sonatype", "jfrog", "jetbrains",
    "kong", "envoyproxy", "traefik", "haproxy", "keycloak", "auth0",
    "fortra", "accellion", "mattermost", "nextcloud", "owncloud",
    "solarwinds", "zoho", "manageengine", "connectwise", "kaseya",
  ]);
  const webRelevantKeywords = [
    "web", "http", "api", "rest", "graphql", "sql", "xss", "csrf",
    "ssrf", "injection", "deserialization", "upload", "traversal",
    "authentication", "session", "cookie", "jwt", "oauth", "saml",
    "remote code execution", "rce", "command injection",
  ];
  return (catalog.vulnerabilities || []).filter(v => {
    const vendor = v.vendorProject?.toLowerCase() || "";
    if (webRelevantVendors.has(vendor)) return true;
    const desc = (v.shortDescription + " " + v.vulnerabilityName + " " + v.product).toLowerCase();
    return webRelevantKeywords.some(kw => desc.includes(kw));
  });
}

/**
 * Get KEV context enriched with OWASP classification for LLM prompts
 */
export function getKevOwaspContext(kevMatches: KevMatch[], catalog: KevCatalog): string {
  if (kevMatches.length === 0) return '';
  const owaspCounts = new Map<string, number>();
  kevMatches.forEach(m => {
    const entry = (catalog.vulnerabilities || []).find(v => v.cveID === m.cveID);
    if (entry) {
      const cats = classifyKevByOwasp(entry);
      cats.forEach(c => owaspCounts.set(c, (owaspCounts.get(c) || 0) + 1));
    }
  });
  const sorted = Array.from(owaspCounts.entries()).sort((a, b) => b[1] - a[1]);
  return `KEV-OWASP CROSS-REFERENCE:\n${sorted.map(([cat, count]) => `- ${cat}: ${count} KEV entries`).join('\n')}\nPrioritize testing for OWASP categories with the most KEV entries — these represent the most actively exploited vulnerability classes.`;
}

// Export for testing
export { mapKevToTechniques, TECH_TO_KEV_PATTERNS, extractVersion, checkVersionRelevance };
