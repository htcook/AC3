/**
 * Vulnerability Scanner Import Parsers
 * Parses scan exports from: Nessus (.nessus XML), Qualys (CSV), Rapid7/Nexpose (CSV),
 * Burp Suite (XML), OWASP ZAP (XML/JSON), and OpenVAS (XML).
 *
 * Each parser normalizes findings into a common ParsedVulnFinding interface so the
 * platform can ingest data from any commercial scanner uniformly.
 */

export type ScannerType = "nessus" | "qualys" | "rapid7" | "burp" | "zap" | "openvas" | "custom";

export interface ParsedVulnFinding {
  cveId: string | null;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cvssScore: number | null;
  hostIp: string | null;
  hostName: string | null;
  port: number | null;
  protocol: string | null;
  description: string | null;
  solution: string | null;
  pluginId: string | null;
  exploitAvailable: boolean;
  /** URL path for web-app scanners (Burp/ZAP) */
  url?: string | null;
  /** CWE ID when available */
  cweId?: string | null;
  /** Raw evidence / request-response for web scanners */
  evidence?: string | null;
}

export interface ParsedScanResult {
  scannerType: ScannerType;
  findings: ParsedVulnFinding[];
  totalHosts: number;
  totalVulns: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

// ═══════════════════════════════════════════════════════════════════════
//  Auto-detect scanner format from file content
// ═══════════════════════════════════════════════════════════════════════

export function detectScannerType(content: string, fileName?: string): ScannerType {
  const trimmed = content.trim();
  const lower = trimmed.toLowerCase();
  const ext = (fileName || "").toLowerCase();

  // XML-based detection
  if (lower.startsWith("<?xml") || lower.startsWith("<")) {
    if (lower.includes("<nessusclientdata") || lower.includes("<reporthost") || ext.endsWith(".nessus")) return "nessus";
    if (lower.includes("<issues") && lower.includes("<issue>") && (lower.includes("<type>") || lower.includes("<serialnumber>"))) return "burp";
    if (lower.includes("owasp zap") || lower.includes("<alertitem>") || lower.includes("<ozaspreport") || lower.includes("<site ")) return "zap";
    if (lower.includes("<report ") && (lower.includes("openvas") || lower.includes("<results") || lower.includes("<result "))) return "openvas";
    if (lower.includes("qualys")) return "qualys";
  }

  // JSON-based detection (ZAP JSON export)
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed.site || parsed["@programName"]?.includes("ZAP") || parsed.alerts) return "zap";
    } catch {
      // Not valid JSON, fall through
    }
  }

  // CSV-based detection
  if (lower.includes("qid") || lower.includes("qualys")) return "qualys";
  if (lower.includes("vulnerability severity level") || lower.includes("asset ip address") || lower.includes("nexpose") || lower.includes("insightvm")) return "rapid7";

  // Filename-based fallback
  if (ext.endsWith(".nessus")) return "nessus";
  if (ext.includes("burp")) return "burp";
  if (ext.includes("zap")) return "zap";
  if (ext.includes("openvas") || ext.includes("gvm")) return "openvas";
  if (ext.includes("qualys")) return "qualys";
  if (ext.includes("rapid7") || ext.includes("nexpose") || ext.includes("insightvm")) return "rapid7";

  return "custom";
}

// ═══════════════════════════════════════════════════════════════════════
//  Nessus XML Parser
// ═══════════════════════════════════════════════════════════════════════

function mapNessusSeverity(severity: string): ParsedVulnFinding["severity"] {
  switch (severity) {
    case "4": return "critical";
    case "3": return "high";
    case "2": return "medium";
    case "1": return "low";
    default: return "info";
  }
}

export function parseNessusXML(xmlContent: string): ParsedScanResult {
  const findings: ParsedVulnFinding[] = [];
  const hosts = new Set<string>();

  const reportHostRegex = /<ReportHost\s+name="([^"]*)"[^>]*>([\s\S]*?)<\/ReportHost>/g;
  const reportItemRegex = /<ReportItem\s+([\s\S]*?)<\/ReportItem>/g;
  const attrRegex = /(\w+)="([^"]*)"/g;
  const tagContentRegex = (tag: string) => new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, "i");

  let hostMatch;
  while ((hostMatch = reportHostRegex.exec(xmlContent)) !== null) {
    const hostName = hostMatch[1];
    const hostContent = hostMatch[2];
    hosts.add(hostName);

    let itemMatch;
    const itemRegex = new RegExp(reportItemRegex.source, reportItemRegex.flags);
    while ((itemMatch = itemRegex.exec(hostContent)) !== null) {
      const itemContent = itemMatch[0];
      const attrs: Record<string, string> = {};
      let attrMatch;
      const attrRe = new RegExp(attrRegex.source, attrRegex.flags);
      while ((attrMatch = attrRe.exec(itemContent.split(">")[0])) !== null) {
        attrs[attrMatch[1]] = attrMatch[2];
      }

      const getTag = (tag: string): string | null => {
        const m = tagContentRegex(tag).exec(itemContent);
        return m ? m[1].trim() : null;
      };

      const cveMatch = getTag("cve");
      const cvssMatch = getTag("cvss3_base_score") || getTag("cvss_base_score");
      const exploitMatch = getTag("exploit_available");

      findings.push({
        cveId: cveMatch || null,
        title: attrs.pluginName || "Unknown",
        severity: mapNessusSeverity(attrs.severity || "0"),
        cvssScore: cvssMatch ? parseFloat(cvssMatch) : null,
        hostIp: hostName,
        hostName: hostName,
        port: attrs.port ? parseInt(attrs.port) : null,
        protocol: attrs.protocol || null,
        description: getTag("description"),
        solution: getTag("solution"),
        pluginId: attrs.pluginID || null,
        exploitAvailable: exploitMatch === "true",
      });
    }
  }

  const counts = countSeverities(findings);
  return {
    scannerType: "nessus",
    findings,
    totalHosts: hosts.size,
    totalVulns: findings.length,
    ...counts,
  };
}

// ═══════════════════════════════════════════════════════════════════════
//  Qualys CSV Parser
// ═══════════════════════════════════════════════════════════════════════

export function parseQualysCSV(csvContent: string): ParsedScanResult {
  const findings: ParsedVulnFinding[] = [];
  const hosts = new Set<string>();

  const lines = csvContent.split("\n");
  let headerIdx = lines.findIndex((l) => l.toLowerCase().includes("qid") || l.toLowerCase().includes("ip"));
  if (headerIdx === -1) headerIdx = 0;

  const headers = parseCSVLine(lines[headerIdx]);
  const headerMap: Record<string, number> = {};
  headers.forEach((h, i) => { headerMap[h.toLowerCase().trim()] = i; });

  for (let i = headerIdx + 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const cols = parseCSVLine(line);

    const ip = cols[headerMap["ip"] ?? headerMap["ip address"] ?? -1] || null;
    const dns = cols[headerMap["dns"] ?? headerMap["dns name"] ?? headerMap["hostname"] ?? -1] || null;
    if (ip) hosts.add(ip);

    const severityRaw = cols[headerMap["severity"] ?? -1] || "1";
    const cvss = cols[headerMap["cvss base"] ?? headerMap["cvss score"] ?? headerMap["cvss3 score"] ?? headerMap["cvss_score"] ?? headerMap["cvss base score"] ?? -1];

    findings.push({
      cveId: cols[headerMap["cve id"] ?? headerMap["cve"] ?? -1] || null,
      title: cols[headerMap["title"] ?? headerMap["vulnerability"] ?? headerMap["qid"] ?? 0] || "Unknown",
      severity: mapQualysSeverity(severityRaw),
      cvssScore: cvss ? parseFloat(cvss) : null,
      hostIp: ip,
      hostName: dns,
      port: cols[headerMap["port"] ?? -1] ? parseInt(cols[headerMap["port"]]) : null,
      protocol: cols[headerMap["protocol"] ?? -1] || null,
      description: cols[headerMap["threat"] ?? headerMap["description"] ?? -1] || null,
      solution: cols[headerMap["solution"] ?? headerMap["impact"] ?? -1] || null,
      pluginId: cols[headerMap["qid"] ?? -1] || null,
      exploitAvailable: (cols[headerMap["exploitability"] ?? -1] || "").toLowerCase().includes("yes"),
    });
  }

  const counts = countSeverities(findings);
  return { scannerType: "qualys", findings, totalHosts: hosts.size, totalVulns: findings.length, ...counts };
}

function mapQualysSeverity(sev: string): ParsedVulnFinding["severity"] {
  const n = parseInt(sev);
  if (n >= 5) return "critical";
  if (n >= 4) return "high";
  if (n >= 3) return "medium";
  if (n >= 2) return "low";
  return "info";
}

// ═══════════════════════════════════════════════════════════════════════
//  Rapid7 / Nexpose / InsightVM CSV Parser
// ═══════════════════════════════════════════════════════════════════════

export function parseRapid7CSV(csvContent: string): ParsedScanResult {
  const findings: ParsedVulnFinding[] = [];
  const hosts = new Set<string>();

  const lines = csvContent.split("\n");
  const headers = parseCSVLine(lines[0]);
  const headerMap: Record<string, number> = {};
  headers.forEach((h, i) => { headerMap[h.toLowerCase().trim()] = i; });

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const cols = parseCSVLine(line);

    const ip = cols[headerMap["asset_ip"] ?? headerMap["asset ip address"] ?? headerMap["ip"] ?? headerMap["host"] ?? -1] || null;
    const hostName = cols[headerMap["asset_hostname"] ?? headerMap["asset names"] ?? headerMap["hostname"] ?? -1] || null;
    if (ip) hosts.add(ip);

    const severityRaw = (cols[headerMap["vulnerability severity level"] ?? headerMap["severity"] ?? -1] || "").toLowerCase();
    const cvss = cols[headerMap["cvss_score"] ?? headerMap["vulnerability cvss score"] ?? headerMap["cvss score"] ?? -1];

    findings.push({
      cveId: cols[headerMap["cve"] ?? headerMap["vulnerability cve ids"] ?? -1]?.split(",")[0]?.trim() || null,
      title: cols[headerMap["vulnerability_title"] ?? headerMap["vulnerability title"] ?? headerMap["title"] ?? 0] || "Unknown",
      severity: mapRapid7Severity(severityRaw),
      cvssScore: cvss ? parseFloat(cvss) : null,
      hostIp: ip,
      hostName: hostName,
      port: cols[headerMap["port"] ?? headerMap["service port"] ?? -1] ? parseInt(cols[headerMap["port"] ?? headerMap["service port"]]) : null,
      protocol: cols[headerMap["protocol"] ?? headerMap["service protocol"] ?? -1] || null,
      description: cols[headerMap["description"] ?? headerMap["vulnerability description"] ?? -1] || null,
      solution: cols[headerMap["solution"] ?? headerMap["vulnerability solution"] ?? -1] || null,
      pluginId: cols[headerMap["vulnerability id"] ?? -1] || null,
      exploitAvailable: (cols[headerMap["exploit_available"] ?? headerMap["vulnerability exploits"] ?? -1] || "").toLowerCase().includes("true") || (cols[headerMap["exploit_available"] ?? headerMap["vulnerability exploits"] ?? -1] || "").length > 0 && !(cols[headerMap["exploit_available"] ?? headerMap["vulnerability exploits"] ?? -1] || "").toLowerCase().includes("false"),
    });
  }

  const counts = countSeverities(findings);
  return { scannerType: "rapid7", findings, totalHosts: hosts.size, totalVulns: findings.length, ...counts };
}

function mapRapid7Severity(sev: string): ParsedVulnFinding["severity"] {
  if (sev.includes("critical")) return "critical";
  if (sev.includes("severe") || sev.includes("high")) return "high";
  if (sev.includes("moderate") || sev.includes("medium")) return "medium";
  if (sev.includes("low")) return "low";
  return "info";
}

// ═══════════════════════════════════════════════════════════════════════
//  Burp Suite XML Parser
// ═══════════════════════════════════════════════════════════════════════

function mapBurpSeverity(sev: string): ParsedVulnFinding["severity"] {
  const lower = sev.toLowerCase();
  if (lower === "high") return "high";
  if (lower === "medium") return "medium";
  if (lower === "low") return "low";
  if (lower === "information" || lower === "info") return "info";
  // Burp doesn't natively use "critical" but some extensions do
  if (lower === "critical") return "critical";
  return "info";
}

function extractHostFromUrl(url: string): { host: string | null; port: number | null; protocol: string | null } {
  try {
    const u = new URL(url);
    return {
      host: u.hostname,
      port: u.port ? parseInt(u.port) : (u.protocol === "https:" ? 443 : 80),
      protocol: u.protocol.replace(":", ""),
    };
  } catch {
    return { host: null, port: null, protocol: null };
  }
}

export function parseBurpXML(xmlContent: string): ParsedScanResult {
  const findings: ParsedVulnFinding[] = [];
  const hosts = new Set<string>();

  const tagContentRegex = (tag: string) => new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, "i");
  // Match each <issue> block
  const issueRegex = /<issue>([\s\S]*?)<\/issue>/gi;

  let issueMatch;
  while ((issueMatch = issueRegex.exec(xmlContent)) !== null) {
    const block = issueMatch[1];

    const getTag = (tag: string): string | null => {
      const m = tagContentRegex(tag).exec(block);
      return m ? m[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").trim() : null;
    };

    const name = getTag("name") || "Unknown";
    const severityRaw = getTag("severity") || "info";
    const hostContent = getTag("host") || "";
    const path = getTag("path") || "";
    const urlForParsing = hostContent || "";
    const { host, port, protocol } = extractHostFromUrl(urlForParsing);

    // Extract IP from <host ip="..."> attribute
    const hostIpAttrMatch = block.match(/<host\s+ip="([^"]+)"/i);
    const hostIp = hostIpAttrMatch ? hostIpAttrMatch[1] : host;
    if (hostIp) hosts.add(hostIp);

    // Build full URL from host + path
    const fullUrl = hostContent && path ? `${hostContent.replace(/\/$/, '')}${path}` : (hostContent || path || "");

    // Extract CVE from references if present
    const references = getTag("references") || getTag("issueBackground") || "";
    const cveMatch = references.match(/CVE-\d{4}-\d{4,}/i);

    // Extract CWE from vulnerability-classifications or vulnerability classifications
    const classificationsBlock = block.match(/<vulnerability-classifications>([\s\S]*?)<\/vulnerability-classifications>/i);
    const classifications = classificationsBlock ? classificationsBlock[1] : "";
    const cweMatch = classifications.match(/CWE-(\d+)/i);

    // Burp confidence → exploitAvailable heuristic
    const confidence = (getTag("confidence") || "").toLowerCase();

    // Build evidence from request/response snippets
    const requestSnippet = getTag("requestresponse");
    const issueDetail = getTag("issueDetail") || "";

    findings.push({
      cveId: cveMatch ? cveMatch[0].toUpperCase() : null,
      title: name,
      severity: mapBurpSeverity(severityRaw),
      cvssScore: null, // Burp doesn't export CVSS natively
      hostIp: hostIp,
      hostName: host || hostIp,
      port,
      protocol,
      description: getTag("issueBackground") || issueDetail || null,
      solution: getTag("remediationBackground") || getTag("remediationDetail") || null,
      pluginId: getTag("type") || null,
      exploitAvailable: confidence === "certain" || confidence === "firm",
      url: fullUrl,
      cweId: cweMatch ? `CWE-${cweMatch[1]}` : null,
      evidence: issueDetail || null,
    });
  }

  const counts = countSeverities(findings);
  return { scannerType: "burp", findings, totalHosts: hosts.size, totalVulns: findings.length, ...counts };
}

// ═══════════════════════════════════════════════════════════════════════
//  OWASP ZAP XML / JSON Parser
// ═══════════════════════════════════════════════════════════════════════

function mapZapRiskCode(riskCode: string): ParsedVulnFinding["severity"] {
  switch (riskCode) {
    case "3": return "high";
    case "2": return "medium";
    case "1": return "low";
    case "0": return "info";
    default: return "info";
  }
}

function mapZapSeverityString(sev: string): ParsedVulnFinding["severity"] {
  const lower = sev.toLowerCase();
  if (lower === "high") return "high";
  if (lower === "medium") return "medium";
  if (lower === "low") return "low";
  return "info";
}

export function parseZapXML(xmlContent: string): ParsedScanResult {
  const findings: ParsedVulnFinding[] = [];
  const hosts = new Set<string>();

  const tagContentRegex = (tag: string, content: string) => {
    const m = new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, "i").exec(content);
    return m ? m[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").trim() : null;
  };

  // ZAP XML has <site> blocks with <alerts><alertitem> children
  const siteRegex = /<site\s+([^>]*)>([\s\S]*?)<\/site>/gi;
  const alertRegex = /<alertitem>([\s\S]*?)<\/alertitem>/gi;

  let siteMatch;
  while ((siteMatch = siteRegex.exec(xmlContent)) !== null) {
    const siteAttrs = siteMatch[1];
    const siteContent = siteMatch[2];

    // Extract host/port from site attributes
    const hostAttr = siteAttrs.match(/host="([^"]*)"/);
    const portAttr = siteAttrs.match(/port="([^"]*)"/);
    const sslAttr = siteAttrs.match(/ssl="([^"]*)"/);
    const siteHost = hostAttr ? hostAttr[1] : null;
    const sitePort = portAttr ? parseInt(portAttr[1]) : null;
    if (siteHost) hosts.add(siteHost);

    let alertMatch;
    const alertRe = new RegExp(alertRegex.source, alertRegex.flags);
    while ((alertMatch = alertRe.exec(siteContent)) !== null) {
      const block = alertMatch[1];

      const name = tagContentRegex("alert", block) || tagContentRegex("name", block) || "Unknown";
      const riskCode = tagContentRegex("riskcode", block);
      const severity = riskCode ? mapZapRiskCode(riskCode) : mapZapSeverityString(tagContentRegex("riskdesc", block) || "info");
      const cweRaw = tagContentRegex("cweid", block);
      const url = tagContentRegex("uri", block) || tagContentRegex("url", block);

      // Extract CVE from references or other-info
      const refs = tagContentRegex("reference", block) || "";
      const otherInfo = tagContentRegex("otherinfo", block) || "";
      const cveMatch = (refs + " " + otherInfo).match(/CVE-\d{4}-\d{4,}/i);

      findings.push({
        cveId: cveMatch ? cveMatch[0].toUpperCase() : null,
        title: name,
        severity,
        cvssScore: null,
        hostIp: siteHost,
        hostName: siteHost,
        port: sitePort,
        protocol: sslAttr && sslAttr[1] === "true" ? "https" : "http",
        description: tagContentRegex("desc", block) || tagContentRegex("description", block) || null,
        solution: tagContentRegex("solution", block) || null,
        pluginId: tagContentRegex("pluginid", block) || tagContentRegex("alertRef", block) || null,
        exploitAvailable: false,
        url,
        cweId: cweRaw ? (cweRaw.startsWith("CWE-") ? cweRaw : `CWE-${cweRaw}`) : null,
        evidence: tagContentRegex("evidence", block) || tagContentRegex("attack", block) || null,
      });
    }
  }

  // Fallback: if no <site> blocks found, try flat <alertitem> parsing
  if (findings.length === 0) {
    let alertMatch;
    const alertRe = new RegExp(alertRegex.source, alertRegex.flags);
    while ((alertMatch = alertRe.exec(xmlContent)) !== null) {
      const block = alertMatch[1];
      const name = tagContentRegex("alert", block) || tagContentRegex("name", block) || "Unknown";
      const riskCode = tagContentRegex("riskcode", block);
      const severity = riskCode ? mapZapRiskCode(riskCode) : "info";
      const url = tagContentRegex("uri", block) || tagContentRegex("url", block) || "";
      const { host, port, protocol } = extractHostFromUrl(url);
      if (host) hosts.add(host);

      const refs = tagContentRegex("reference", block) || "";
      const cveMatch = refs.match(/CVE-\d{4}-\d{4,}/i);

      findings.push({
        cveId: cveMatch ? cveMatch[0].toUpperCase() : null,
        title: name,
        severity,
        cvssScore: null,
        hostIp: host,
        hostName: host,
        port,
        protocol,
        description: tagContentRegex("desc", block) || null,
        solution: tagContentRegex("solution", block) || null,
        pluginId: tagContentRegex("pluginid", block) || null,
        exploitAvailable: false,
        url,
        cweId: (() => { const c = tagContentRegex("cweid", block); return c ? (c.startsWith("CWE-") ? c : `CWE-${c}`) : null; })(),
        evidence: tagContentRegex("evidence", block) || null,
      });
    }
  }

  const counts = countSeverities(findings);
  return { scannerType: "zap", findings, totalHosts: hosts.size, totalVulns: findings.length, ...counts };
}

export function parseZapJSON(jsonContent: string): ParsedScanResult {
  const findings: ParsedVulnFinding[] = [];
  const hosts = new Set<string>();

  try {
    const data = JSON.parse(jsonContent);

    // ZAP JSON can be { site: [...] } or { alerts: [...] } or an array of sites
    const sites = Array.isArray(data.site) ? data.site : data.site ? [data.site] : [];
    const topAlerts = data.alerts || [];

    for (const site of sites) {
      const siteHost = site["@host"] || site.host || null;
      const sitePort = site["@port"] ? parseInt(site["@port"]) : site.port ? parseInt(site.port) : null;
      if (siteHost) hosts.add(siteHost);

      const alerts = site.alerts || site.alert || [];
      const alertList = Array.isArray(alerts) ? alerts : [alerts];

      for (const alert of alertList) {
        processZapAlert(alert, siteHost, sitePort, findings, hosts);
      }
    }

    // Process top-level alerts
    const alertList = Array.isArray(topAlerts) ? topAlerts : [topAlerts];
    for (const alert of alertList) {
      processZapAlert(alert, null, null, findings, hosts);
    }
  } catch {
    // Invalid JSON — return empty
  }

  const counts = countSeverities(findings);
  return { scannerType: "zap", findings, totalHosts: hosts.size, totalVulns: findings.length, ...counts };
}

function processZapAlert(
  alert: any,
  defaultHost: string | null,
  defaultPort: number | null,
  findings: ParsedVulnFinding[],
  hosts: Set<string>,
) {
  if (!alert) return;
  const name = alert.alert || alert.name || "Unknown";
  const riskCode = String(alert.riskcode ?? alert.risk ?? "0");
  const severity = mapZapRiskCode(riskCode);
  const url = alert.url || alert.uri || "";
  const { host: urlHost, port: urlPort, protocol } = url ? extractHostFromUrl(url) : { host: null, port: null, protocol: null };
  const host = urlHost || defaultHost;
  const port = urlPort || defaultPort;
  if (host) hosts.add(host);

  const refs = alert.reference || "";
  const cveMatch = refs.match(/CVE-\d{4}-\d{4,}/i);

  // Process instances if present
  const instances = alert.instances || [];
  const instanceList = Array.isArray(instances) ? instances : [instances];

  findings.push({
    cveId: cveMatch ? cveMatch[0].toUpperCase() : null,
    title: name,
    severity,
    cvssScore: null,
    hostIp: host,
    hostName: host,
    port,
    protocol,
    description: alert.desc || alert.description || null,
    solution: alert.solution || null,
    pluginId: alert.pluginid || alert.pluginId || alert.alertRef || null,
    exploitAvailable: false,
    url,
    cweId: alert.cweid ? (String(alert.cweid).startsWith("CWE-") ? String(alert.cweid) : `CWE-${alert.cweid}`) : null,
    evidence: instanceList.length > 0 ? instanceList.map((i: any) => `${i.method || ""} ${i.uri || ""}: ${i.evidence || ""}`).join("; ") : alert.evidence || null,
  });
}

// ═══════════════════════════════════════════════════════════════════════
//  OpenVAS / GVM XML Parser
// ═══════════════════════════════════════════════════════════════════════

function mapOpenVASThreat(threat: string): ParsedVulnFinding["severity"] {
  const lower = threat.toLowerCase();
  if (lower === "high") return "high";
  if (lower === "medium") return "medium";
  if (lower === "low") return "low";
  if (lower === "log" || lower === "debug" || lower === "info") return "info";
  // OpenVAS uses "Alarm" for critical in some versions
  if (lower === "alarm" || lower === "critical") return "critical";
  return "info";
}

export function parseOpenVASXML(xmlContent: string): ParsedScanResult {
  const findings: ParsedVulnFinding[] = [];
  const hosts = new Set<string>();

  const tagContentRegex = (tag: string, content: string) => {
    const m = new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, "i").exec(content);
    return m ? m[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").trim() : null;
  };

  // OpenVAS XML: <report><results><result> blocks
  const resultRegex = /<result[^>]*>([\s\S]*?)<\/result>/gi;

  let resultMatch;
  while ((resultMatch = resultRegex.exec(xmlContent)) !== null) {
    const block = resultMatch[1];

    const name = tagContentRegex("name", block) || "Unknown";
    const threat = tagContentRegex("threat", block) || "info";
    const hostTag = tagContentRegex("host", block) || "";
    // Host can contain sub-elements; extract the text content
    const hostIp = hostTag.replace(/<[^>]*>/g, "").trim().split("\n")[0].trim() || null;
    if (hostIp) hosts.add(hostIp);

    const portRaw = tagContentRegex("port", block) || "";
    // Port format: "443/tcp" or "general/tcp"
    const portParts = portRaw.split("/");
    const portNum = parseInt(portParts[0]);
    const protocol = portParts[1] || null;

    // Extract CVE from <nvt><cve> or from description
    const nvtBlock = block.match(/<nvt[^>]*>([\s\S]*?)<\/nvt>/i);
    const nvtContent = nvtBlock ? nvtBlock[1] : block;
    const cveTag = tagContentRegex("cve", nvtContent);
    const cveId = cveTag && cveTag !== "NOCVE" ? cveTag : null;

    // CVSS score from <nvt><cvss_base> or <severity>
    const cvssBase = tagContentRegex("cvss_base", nvtContent) || tagContentRegex("severity", block);
    const cvssScore = cvssBase ? parseFloat(cvssBase) : null;

    // OID as plugin ID
    const oidMatch = (nvtBlock ? nvtBlock[0] : "").match(/oid="([^"]*)"/);
    const pluginId = oidMatch ? oidMatch[1] : tagContentRegex("oid", nvtContent);

    const description = tagContentRegex("description", block) || tagContentRegex("summary", nvtContent);
    const solution = tagContentRegex("solution", nvtContent);

    // Exploit availability from tags or solution type
    const tags = tagContentRegex("tags", nvtContent) || "";
    const exploitAvailable = tags.toLowerCase().includes("exploit_available=true") ||
      tags.toLowerCase().includes("exploit_available=1");

    // CWE from tags
    const cweMatch = tags.match(/cwe[=:](\d+)/i);

    findings.push({
      cveId: cveId ? cveId.toUpperCase() : null,
      title: name,
      severity: mapOpenVASThreat(threat),
      cvssScore: cvssScore && !isNaN(cvssScore) ? cvssScore : null,
      hostIp,
      hostName: hostIp,
      port: !isNaN(portNum) ? portNum : null,
      protocol,
      description,
      solution,
      pluginId,
      exploitAvailable,
      cweId: cweMatch ? `CWE-${cweMatch[1]}` : null,
    });
  }

  const counts = countSeverities(findings);
  return { scannerType: "openvas", findings, totalHosts: hosts.size, totalVulns: findings.length, ...counts };
}

// ═══════════════════════════════════════════════════════════════════════
//  Utilities
// ═══════════════════════════════════════════════════════════════════════

export function parseCSVLine(line: string): string[] {
  const result: string[] = [];
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
      result.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  result.push(current);
  return result;
}

function countSeverities(findings: ParsedVulnFinding[]) {
  let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
  for (const f of findings) {
    switch (f.severity) {
      case "critical": criticalCount++; break;
      case "high": highCount++; break;
      case "medium": mediumCount++; break;
      case "low": lowCount++; break;
    }
  }
  return { criticalCount, highCount, mediumCount, lowCount };
}

/**
 * Parse a vulnerability scan report. Auto-detects format if scannerType is "custom" or not provided.
 */
export function parseVulnScan(scannerType: string, content: string, fileName?: string): ParsedScanResult {
  // Auto-detect if needed
  const resolved = scannerType === "custom" || !scannerType
    ? detectScannerType(content, fileName)
    : scannerType as ScannerType;

  switch (resolved) {
    case "nessus": return parseNessusXML(content);
    case "qualys": return parseQualysCSV(content);
    case "rapid7": return parseRapid7CSV(content);
    case "burp": return parseBurpXML(content);
    case "zap": {
      const trimmed = content.trim();
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        return parseZapJSON(content);
      }
      return parseZapXML(content);
    }
    case "openvas": return parseOpenVASXML(content);
    default: return parseQualysCSV(content); // fallback to CSV
  }
}

/** Scanner display names for UI */
export const SCANNER_LABELS: Record<ScannerType, string> = {
  nessus: "Tenable Nessus",
  qualys: "Qualys",
  rapid7: "Rapid7 Nexpose / InsightVM",
  burp: "Burp Suite",
  zap: "OWASP ZAP",
  openvas: "OpenVAS / Greenbone",
  custom: "Custom / Other",
};
