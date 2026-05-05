import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/dynamic-cpe-matcher.ts
function buildCpeUri(technology, version) {
  const techLower = technology.toLowerCase().trim();
  let mapping = TECH_TO_CPE[techLower];
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
function parseCpeUri(cpeUri) {
  const parts = cpeUri.split(":");
  if (parts.length < 6) return null;
  return {
    vendor: parts[3] || "",
    product: parts[4] || "",
    version: parts[5] || "*"
  };
}
async function nvdRateLimit() {
  const now = Date.now();
  const elapsed = now - lastNvdRequest;
  if (elapsed < NVD_MIN_INTERVAL) {
    await new Promise((resolve) => setTimeout(resolve, NVD_MIN_INTERVAL - elapsed));
  }
  lastNvdRequest = Date.now();
}
async function queryNvdByCpe(cpeUri, maxResults = 50) {
  await nvdRateLimit();
  try {
    const url = `${NVD_API_BASE}?cpeName=${encodeURIComponent(cpeUri)}&resultsPerPage=${maxResults}`;
    const res = await fetch(url, {
      headers: { "User-Agent": "AC3-DynamicCPE/1.0" },
      signal: AbortSignal.timeout(15e3)
    });
    if (!res.ok) {
      if (res.status === 403 || res.status === 429) {
        console.warn(`[DynamicCPE] NVD rate limited (${res.status}), will retry later`);
        return [];
      }
      throw new Error(`HTTP ${res.status}`);
    }
    const data = await res.json();
    const results = [];
    for (const vuln of data.vulnerabilities || []) {
      const cve = vuln.cve;
      if (!cve) continue;
      const enDesc = cve.descriptions?.find((d) => d.lang === "en")?.value || "";
      const cvssV3 = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
      const cvssV3Meta = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0];
      let affectedVersionRange = null;
      const allNodes = (cve.configurations || []).flatMap((c) => c.nodes || []);
      for (const node of allNodes) {
        for (const cpeMatch of node.cpeMatch || []) {
          const parts = [];
          if (cpeMatch.versionStartIncluding) parts.push(`>= ${cpeMatch.versionStartIncluding}`);
          if (cpeMatch.versionStartExcluding) parts.push(`> ${cpeMatch.versionStartExcluding}`);
          if (cpeMatch.versionEndIncluding) parts.push(`<= ${cpeMatch.versionEndIncluding}`);
          if (cpeMatch.versionEndExcluding) parts.push(`< ${cpeMatch.versionEndExcluding}`);
          if (parts.length > 0) {
            if (!affectedVersionRange || parts.length > affectedVersionRange.split(",").length) {
              affectedVersionRange = parts.join(", ");
            }
          }
        }
      }
      const score = cvssV3?.baseScore ?? null;
      let severity = "unknown";
      if (score !== null) {
        if (score >= 9) severity = "critical";
        else if (score >= 7) severity = "high";
        else if (score >= 4) severity = "medium";
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
        affectedVersionRange
      });
    }
    return results.sort((a, b) => (b.cvssV3Score || 0) - (a.cvssV3Score || 0));
  } catch (err) {
    console.error(`[DynamicCPE] NVD query failed for ${cpeUri}: ${err.message}`);
    return [];
  }
}
async function queryNvdByKeyword(keyword, maxResults = 25) {
  await nvdRateLimit();
  try {
    const url = `${NVD_API_BASE}?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=${maxResults}`;
    const res = await fetch(url, {
      headers: { "User-Agent": "AC3-DynamicCPE/1.0" },
      signal: AbortSignal.timeout(15e3)
    });
    if (!res.ok) return [];
    const data = await res.json();
    const results = [];
    for (const vuln of data.vulnerabilities || []) {
      const cve = vuln.cve;
      if (!cve) continue;
      const enDesc = cve.descriptions?.find((d) => d.lang === "en")?.value || "";
      const cvssV3 = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
      const score = cvssV3?.baseScore ?? null;
      let severity = "unknown";
      if (score !== null) {
        if (score >= 9) severity = "critical";
        else if (score >= 7) severity = "high";
        else if (score >= 4) severity = "medium";
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
        affectedVersionRange: null
      });
    }
    return results.sort((a, b) => (b.cvssV3Score || 0) - (a.cvssV3Score || 0));
  } catch (err) {
    console.error(`[DynamicCPE] NVD keyword query failed for ${keyword}: ${err.message}`);
    return [];
  }
}
function getCacheKey(technology, version) {
  return `${technology.toLowerCase().trim()}:${(version || "*").toLowerCase().trim()}`;
}
async function matchTechnologyCves(technology, version) {
  const cacheKey = getCacheKey(technology, version);
  stats.totalQueries++;
  const cached = cpeCache.get(cacheKey);
  if (cached && Date.now() - cached.cachedAt < CPE_CACHE_TTL) {
    stats.cacheHits++;
    return cached;
  }
  stats.cacheMisses++;
  const cpeUri = buildCpeUri(technology, version);
  let cves = [];
  let matchConfidence = "fuzzy";
  if (cpeUri) {
    cves = await queryNvdByCpe(cpeUri);
    matchConfidence = version ? "exact" : "partial";
  }
  if (cves.length === 0) {
    const keyword = version ? `${technology} ${version}` : technology;
    cves = await queryNvdByKeyword(keyword);
    matchConfidence = "fuzzy";
  }
  if (version && cves.length > 0) {
    const beforeCount = cves.length;
    cves = filterCvesByVersion(cves, version);
    if (cves.length < beforeCount) {
      console.log(`[DynamicCPE] Version filter for ${technology} v${version}: ${beforeCount} \u2192 ${cves.length} CVEs (removed ${beforeCount - cves.length} non-matching)`);
    }
  }
  const result = {
    technology,
    version: version || "*",
    cpeUri: cpeUri || `keyword:${technology}`,
    cves,
    matchConfidence,
    cachedAt: Date.now()
  };
  cpeCache.set(cacheKey, result);
  stats.totalCvesFound += cves.length;
  stats.averageCvesPerTech = stats.totalQueries > 0 ? Math.round(stats.totalCvesFound / stats.totalQueries * 10) / 10 : 0;
  stats.lastQueryTime = Date.now();
  console.log(`[DynamicCPE] ${technology} ${version || "*"}: ${cves.length} CVEs found (${matchConfidence} match via ${cpeUri ? "CPE" : "keyword"})`);
  return result;
}
async function matchMultipleTechnologies(technologies) {
  const results = [];
  for (const tech of technologies) {
    const result = await matchTechnologyCves(tech.name, tech.version);
    results.push(result);
  }
  return results;
}
function isVersionAffected(detectedVersion, affectedRange) {
  if (!affectedRange) return true;
  const detected = parseVersion(detectedVersion);
  if (!detected) return true;
  const conditions = affectedRange.split(",").map((c) => c.trim());
  for (const condition of conditions) {
    const match = condition.match(/^([<>=!]+)\s*(.+)$/);
    if (!match) continue;
    const [, op, verStr] = match;
    const ver = parseVersion(verStr);
    if (!ver) continue;
    const cmp = compareVersions(detected, ver);
    switch (op) {
      case ">=":
        if (cmp < 0) return false;
        break;
      case ">":
        if (cmp <= 0) return false;
        break;
      case "<=":
        if (cmp > 0) return false;
        break;
      case "<":
        if (cmp >= 0) return false;
        break;
      case "=":
        if (cmp !== 0) return false;
        break;
    }
  }
  return true;
}
function filterCvesByVersion(cves, detectedVersion) {
  return cves.filter((cve) => isVersionAffected(detectedVersion, cve.affectedVersionRange));
}
function getCpeMatchStats() {
  return { ...stats };
}
function clearCpeCache() {
  cpeCache.clear();
  stats = {
    totalQueries: 0,
    cacheHits: 0,
    cacheMisses: 0,
    totalCvesFound: 0,
    averageCvesPerTech: 0,
    lastQueryTime: 0
  };
}
function parseVersion(version) {
  const cleaned = version.replace(/^v/i, "").trim();
  const match = cleaned.match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:p(\d+))?(.*)$/);
  if (!match) return null;
  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2] || "0", 10),
    patch: parseInt(match[3] || "0", 10),
    patchLevel: parseInt(match[4] || "0", 10),
    // OpenSSH p-suffix
    rest: match[5] || ""
  };
}
function compareVersions(a, b) {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;
  if (a.patchLevel !== b.patchLevel) return a.patchLevel - b.patchLevel;
  return 0;
}
var TECH_TO_CPE, NVD_API_BASE, lastNvdRequest, NVD_MIN_INTERVAL, cpeCache, CPE_CACHE_TTL, stats;
var init_dynamic_cpe_matcher = __esm({
  "server/lib/dynamic-cpe-matcher.ts"() {
    TECH_TO_CPE = {
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
      "prometheus": { vendor: "prometheus", product: "prometheus" }
    };
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    lastNvdRequest = 0;
    NVD_MIN_INTERVAL = 6500;
    cpeCache = /* @__PURE__ */ new Map();
    CPE_CACHE_TTL = 24 * 60 * 60 * 1e3;
    stats = {
      totalQueries: 0,
      cacheHits: 0,
      cacheMisses: 0,
      totalCvesFound: 0,
      averageCvesPerTech: 0,
      lastQueryTime: 0
    };
  }
});

export {
  buildCpeUri,
  parseCpeUri,
  matchTechnologyCves,
  matchMultipleTechnologies,
  isVersionAffected,
  filterCvesByVersion,
  getCpeMatchStats,
  clearCpeCache,
  init_dynamic_cpe_matcher
};
