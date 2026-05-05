import {
  __esm,
  __export
} from "./chunk-KFQGP6VL.js";

// server/lib/vuln-scanner-parser.ts
var vuln_scanner_parser_exports = {};
__export(vuln_scanner_parser_exports, {
  SCANNER_LABELS: () => SCANNER_LABELS,
  detectScannerType: () => detectScannerType,
  parseBurpXML: () => parseBurpXML,
  parseCSVLine: () => parseCSVLine,
  parseNessusXML: () => parseNessusXML,
  parseOpenVASXML: () => parseOpenVASXML,
  parseQualysCSV: () => parseQualysCSV,
  parseRapid7CSV: () => parseRapid7CSV,
  parseVulnScan: () => parseVulnScan,
  parseZapJSON: () => parseZapJSON,
  parseZapXML: () => parseZapXML
});
function detectScannerType(content, fileName) {
  const trimmed = content.trim();
  const lower = trimmed.toLowerCase();
  const ext = (fileName || "").toLowerCase();
  if (lower.startsWith("<?xml") || lower.startsWith("<")) {
    if (lower.includes("<nessusclientdata") || lower.includes("<reporthost") || ext.endsWith(".nessus")) return "nessus";
    if (lower.includes("<issues") && lower.includes("<issue>") && (lower.includes("<type>") || lower.includes("<serialnumber>"))) return "burp";
    if (lower.includes("owasp zap") || lower.includes("<alertitem>") || lower.includes("<ozaspreport") || lower.includes("<site ")) return "zap";
    if (lower.includes("<report ") && (lower.includes("openvas") || lower.includes("<results") || lower.includes("<result "))) return "openvas";
    if (lower.includes("qualys")) return "qualys";
  }
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed.site || parsed["@programName"]?.includes("ZAP") || parsed.alerts) return "zap";
    } catch {
    }
  }
  if (lower.includes("qid") || lower.includes("qualys")) return "qualys";
  if (lower.includes("vulnerability severity level") || lower.includes("asset ip address") || lower.includes("nexpose") || lower.includes("insightvm")) return "rapid7";
  if (ext.endsWith(".nessus")) return "nessus";
  if (ext.includes("burp")) return "burp";
  if (ext.includes("zap")) return "zap";
  if (ext.includes("openvas") || ext.includes("gvm")) return "openvas";
  if (ext.includes("qualys")) return "qualys";
  if (ext.includes("rapid7") || ext.includes("nexpose") || ext.includes("insightvm")) return "rapid7";
  return "custom";
}
function mapNessusSeverity(severity) {
  switch (severity) {
    case "4":
      return "critical";
    case "3":
      return "high";
    case "2":
      return "medium";
    case "1":
      return "low";
    default:
      return "info";
  }
}
function parseNessusXML(xmlContent) {
  const findings = [];
  const hosts = /* @__PURE__ */ new Set();
  const reportHostRegex = /<ReportHost\s+name="([^"]*)"[^>]*>([\s\S]*?)<\/ReportHost>/g;
  const reportItemRegex = /<ReportItem\s+([\s\S]*?)<\/ReportItem>/g;
  const attrRegex = /(\w+)="([^"]*)"/g;
  const tagContentRegex = (tag) => new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, "i");
  let hostMatch;
  while ((hostMatch = reportHostRegex.exec(xmlContent)) !== null) {
    const hostName = hostMatch[1];
    const hostContent = hostMatch[2];
    hosts.add(hostName);
    let itemMatch;
    const itemRegex = new RegExp(reportItemRegex.source, reportItemRegex.flags);
    while ((itemMatch = itemRegex.exec(hostContent)) !== null) {
      const itemContent = itemMatch[0];
      const attrs = {};
      let attrMatch;
      const attrRe = new RegExp(attrRegex.source, attrRegex.flags);
      while ((attrMatch = attrRe.exec(itemContent.split(">")[0])) !== null) {
        attrs[attrMatch[1]] = attrMatch[2];
      }
      const getTag = (tag) => {
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
        hostName,
        port: attrs.port ? parseInt(attrs.port) : null,
        protocol: attrs.protocol || null,
        description: getTag("description"),
        solution: getTag("solution"),
        pluginId: attrs.pluginID || null,
        exploitAvailable: exploitMatch === "true"
      });
    }
  }
  const counts = countSeverities(findings);
  return {
    scannerType: "nessus",
    findings,
    totalHosts: hosts.size,
    totalVulns: findings.length,
    ...counts
  };
}
function parseQualysCSV(csvContent) {
  const findings = [];
  const hosts = /* @__PURE__ */ new Set();
  const lines = csvContent.split("\n");
  let headerIdx = lines.findIndex((l) => l.toLowerCase().includes("qid") || l.toLowerCase().includes("ip"));
  if (headerIdx === -1) headerIdx = 0;
  const headers = parseCSVLine(lines[headerIdx]);
  const headerMap = {};
  headers.forEach((h, i) => {
    headerMap[h.toLowerCase().trim()] = i;
  });
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
      exploitAvailable: (cols[headerMap["exploitability"] ?? -1] || "").toLowerCase().includes("yes")
    });
  }
  const counts = countSeverities(findings);
  return { scannerType: "qualys", findings, totalHosts: hosts.size, totalVulns: findings.length, ...counts };
}
function mapQualysSeverity(sev) {
  const n = parseInt(sev);
  if (n >= 5) return "critical";
  if (n >= 4) return "high";
  if (n >= 3) return "medium";
  if (n >= 2) return "low";
  return "info";
}
function parseRapid7CSV(csvContent) {
  const findings = [];
  const hosts = /* @__PURE__ */ new Set();
  const lines = csvContent.split("\n");
  const headers = parseCSVLine(lines[0]);
  const headerMap = {};
  headers.forEach((h, i) => {
    headerMap[h.toLowerCase().trim()] = i;
  });
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
      hostName,
      port: cols[headerMap["port"] ?? headerMap["service port"] ?? -1] ? parseInt(cols[headerMap["port"] ?? headerMap["service port"]]) : null,
      protocol: cols[headerMap["protocol"] ?? headerMap["service protocol"] ?? -1] || null,
      description: cols[headerMap["description"] ?? headerMap["vulnerability description"] ?? -1] || null,
      solution: cols[headerMap["solution"] ?? headerMap["vulnerability solution"] ?? -1] || null,
      pluginId: cols[headerMap["vulnerability id"] ?? -1] || null,
      exploitAvailable: (cols[headerMap["exploit_available"] ?? headerMap["vulnerability exploits"] ?? -1] || "").toLowerCase().includes("true") || (cols[headerMap["exploit_available"] ?? headerMap["vulnerability exploits"] ?? -1] || "").length > 0 && !(cols[headerMap["exploit_available"] ?? headerMap["vulnerability exploits"] ?? -1] || "").toLowerCase().includes("false")
    });
  }
  const counts = countSeverities(findings);
  return { scannerType: "rapid7", findings, totalHosts: hosts.size, totalVulns: findings.length, ...counts };
}
function mapRapid7Severity(sev) {
  if (sev.includes("critical")) return "critical";
  if (sev.includes("severe") || sev.includes("high")) return "high";
  if (sev.includes("moderate") || sev.includes("medium")) return "medium";
  if (sev.includes("low")) return "low";
  return "info";
}
function mapBurpSeverity(sev) {
  const lower = sev.toLowerCase();
  if (lower === "high") return "high";
  if (lower === "medium") return "medium";
  if (lower === "low") return "low";
  if (lower === "information" || lower === "info") return "info";
  if (lower === "critical") return "critical";
  return "info";
}
function extractHostFromUrl(url) {
  try {
    const u = new URL(url);
    return {
      host: u.hostname,
      port: u.port ? parseInt(u.port) : u.protocol === "https:" ? 443 : 80,
      protocol: u.protocol.replace(":", "")
    };
  } catch {
    return { host: null, port: null, protocol: null };
  }
}
function parseBurpXML(xmlContent) {
  const findings = [];
  const hosts = /* @__PURE__ */ new Set();
  const tagContentRegex = (tag) => new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, "i");
  const issueRegex = /<issue>([\s\S]*?)<\/issue>/gi;
  let issueMatch;
  while ((issueMatch = issueRegex.exec(xmlContent)) !== null) {
    const block = issueMatch[1];
    const getTag = (tag) => {
      const m = tagContentRegex(tag).exec(block);
      return m ? m[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").trim() : null;
    };
    const name = getTag("name") || "Unknown";
    const severityRaw = getTag("severity") || "info";
    const hostContent = getTag("host") || "";
    const path = getTag("path") || "";
    const urlForParsing = hostContent || "";
    const { host, port, protocol } = extractHostFromUrl(urlForParsing);
    const hostIpAttrMatch = block.match(/<host\s+ip="([^"]+)"/i);
    const hostIp = hostIpAttrMatch ? hostIpAttrMatch[1] : host;
    if (hostIp) hosts.add(hostIp);
    const fullUrl = hostContent && path ? `${hostContent.replace(/\/$/, "")}${path}` : hostContent || path || "";
    const references = getTag("references") || getTag("issueBackground") || "";
    const cveMatch = references.match(/CVE-\d{4}-\d{4,}/i);
    const classificationsBlock = block.match(/<vulnerability-classifications>([\s\S]*?)<\/vulnerability-classifications>/i);
    const classifications = classificationsBlock ? classificationsBlock[1] : "";
    const cweMatch = classifications.match(/CWE-(\d+)/i);
    const confidence = (getTag("confidence") || "").toLowerCase();
    const requestSnippet = getTag("requestresponse");
    const issueDetail = getTag("issueDetail") || "";
    findings.push({
      cveId: cveMatch ? cveMatch[0].toUpperCase() : null,
      title: name,
      severity: mapBurpSeverity(severityRaw),
      cvssScore: null,
      // Burp doesn't export CVSS natively
      hostIp,
      hostName: host || hostIp,
      port,
      protocol,
      description: getTag("issueBackground") || issueDetail || null,
      solution: getTag("remediationBackground") || getTag("remediationDetail") || null,
      pluginId: getTag("type") || null,
      exploitAvailable: confidence === "certain" || confidence === "firm",
      url: fullUrl,
      cweId: cweMatch ? `CWE-${cweMatch[1]}` : null,
      evidence: issueDetail || null
    });
  }
  const counts = countSeverities(findings);
  return { scannerType: "burp", findings, totalHosts: hosts.size, totalVulns: findings.length, ...counts };
}
function mapZapRiskCode(riskCode) {
  switch (riskCode) {
    case "3":
      return "high";
    case "2":
      return "medium";
    case "1":
      return "low";
    case "0":
      return "info";
    default:
      return "info";
  }
}
function mapZapSeverityString(sev) {
  const lower = sev.toLowerCase();
  if (lower === "high") return "high";
  if (lower === "medium") return "medium";
  if (lower === "low") return "low";
  return "info";
}
function parseZapXML(xmlContent) {
  const findings = [];
  const hosts = /* @__PURE__ */ new Set();
  const tagContentRegex = (tag, content) => {
    const m = new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, "i").exec(content);
    return m ? m[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").trim() : null;
  };
  const siteRegex = /<site\s+([^>]*)>([\s\S]*?)<\/site>/gi;
  const alertRegex = /<alertitem>([\s\S]*?)<\/alertitem>/gi;
  let siteMatch;
  while ((siteMatch = siteRegex.exec(xmlContent)) !== null) {
    const siteAttrs = siteMatch[1];
    const siteContent = siteMatch[2];
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
        cweId: cweRaw ? cweRaw.startsWith("CWE-") ? cweRaw : `CWE-${cweRaw}` : null,
        evidence: tagContentRegex("evidence", block) || tagContentRegex("attack", block) || null
      });
    }
  }
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
        cweId: (() => {
          const c = tagContentRegex("cweid", block);
          return c ? c.startsWith("CWE-") ? c : `CWE-${c}` : null;
        })(),
        evidence: tagContentRegex("evidence", block) || null
      });
    }
  }
  const counts = countSeverities(findings);
  return { scannerType: "zap", findings, totalHosts: hosts.size, totalVulns: findings.length, ...counts };
}
function parseZapJSON(jsonContent) {
  const findings = [];
  const hosts = /* @__PURE__ */ new Set();
  try {
    const data = JSON.parse(jsonContent);
    const sites = Array.isArray(data.site) ? data.site : data.site ? [data.site] : [];
    const topAlerts = data.alerts || [];
    for (const site of sites) {
      const siteHost = site["@host"] || site.host || null;
      const sitePort = site["@port"] ? parseInt(site["@port"]) : site.port ? parseInt(site.port) : null;
      if (siteHost) hosts.add(siteHost);
      const alerts = site.alerts || site.alert || [];
      const alertList2 = Array.isArray(alerts) ? alerts : [alerts];
      for (const alert of alertList2) {
        processZapAlert(alert, siteHost, sitePort, findings, hosts);
      }
    }
    const alertList = Array.isArray(topAlerts) ? topAlerts : [topAlerts];
    for (const alert of alertList) {
      processZapAlert(alert, null, null, findings, hosts);
    }
  } catch {
  }
  const counts = countSeverities(findings);
  return { scannerType: "zap", findings, totalHosts: hosts.size, totalVulns: findings.length, ...counts };
}
function processZapAlert(alert, defaultHost, defaultPort, findings, hosts) {
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
    cweId: alert.cweid ? String(alert.cweid).startsWith("CWE-") ? String(alert.cweid) : `CWE-${alert.cweid}` : null,
    evidence: instanceList.length > 0 ? instanceList.map((i) => `${i.method || ""} ${i.uri || ""}: ${i.evidence || ""}`).join("; ") : alert.evidence || null
  });
}
function mapOpenVASThreat(threat) {
  const lower = threat.toLowerCase();
  if (lower === "high") return "high";
  if (lower === "medium") return "medium";
  if (lower === "low") return "low";
  if (lower === "log" || lower === "debug" || lower === "info") return "info";
  if (lower === "alarm" || lower === "critical") return "critical";
  return "info";
}
function parseOpenVASXML(xmlContent) {
  const findings = [];
  const hosts = /* @__PURE__ */ new Set();
  const tagContentRegex = (tag, content) => {
    const m = new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, "i").exec(content);
    return m ? m[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").trim() : null;
  };
  const resultRegex = /<result[^>]*>([\s\S]*?)<\/result>/gi;
  let resultMatch;
  while ((resultMatch = resultRegex.exec(xmlContent)) !== null) {
    const block = resultMatch[1];
    const name = tagContentRegex("name", block) || "Unknown";
    const threat = tagContentRegex("threat", block) || "info";
    const hostTag = tagContentRegex("host", block) || "";
    const hostIp = hostTag.replace(/<[^>]*>/g, "").trim().split("\n")[0].trim() || null;
    if (hostIp) hosts.add(hostIp);
    const portRaw = tagContentRegex("port", block) || "";
    const portParts = portRaw.split("/");
    const portNum = parseInt(portParts[0]);
    const protocol = portParts[1] || null;
    const nvtBlock = block.match(/<nvt[^>]*>([\s\S]*?)<\/nvt>/i);
    const nvtContent = nvtBlock ? nvtBlock[1] : block;
    const cveTag = tagContentRegex("cve", nvtContent);
    const cveId = cveTag && cveTag !== "NOCVE" ? cveTag : null;
    const cvssBase = tagContentRegex("cvss_base", nvtContent) || tagContentRegex("severity", block);
    const cvssScore = cvssBase ? parseFloat(cvssBase) : null;
    const oidMatch = (nvtBlock ? nvtBlock[0] : "").match(/oid="([^"]*)"/);
    const pluginId = oidMatch ? oidMatch[1] : tagContentRegex("oid", nvtContent);
    const description = tagContentRegex("description", block) || tagContentRegex("summary", nvtContent);
    const solution = tagContentRegex("solution", nvtContent);
    const tags = tagContentRegex("tags", nvtContent) || "";
    const exploitAvailable = tags.toLowerCase().includes("exploit_available=true") || tags.toLowerCase().includes("exploit_available=1");
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
      cweId: cweMatch ? `CWE-${cweMatch[1]}` : null
    });
  }
  const counts = countSeverities(findings);
  return { scannerType: "openvas", findings, totalHosts: hosts.size, totalVulns: findings.length, ...counts };
}
function parseCSVLine(line) {
  const result = [];
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
function countSeverities(findings) {
  let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
  for (const f of findings) {
    switch (f.severity) {
      case "critical":
        criticalCount++;
        break;
      case "high":
        highCount++;
        break;
      case "medium":
        mediumCount++;
        break;
      case "low":
        lowCount++;
        break;
    }
  }
  return { criticalCount, highCount, mediumCount, lowCount };
}
function parseVulnScan(scannerType, content, fileName) {
  const resolved = scannerType === "custom" || !scannerType ? detectScannerType(content, fileName) : scannerType;
  switch (resolved) {
    case "nessus":
      return parseNessusXML(content);
    case "qualys":
      return parseQualysCSV(content);
    case "rapid7":
      return parseRapid7CSV(content);
    case "burp":
      return parseBurpXML(content);
    case "zap": {
      const trimmed = content.trim();
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        return parseZapJSON(content);
      }
      return parseZapXML(content);
    }
    case "openvas":
      return parseOpenVASXML(content);
    default:
      return parseQualysCSV(content);
  }
}
var SCANNER_LABELS;
var init_vuln_scanner_parser = __esm({
  "server/lib/vuln-scanner-parser.ts"() {
    SCANNER_LABELS = {
      nessus: "Tenable Nessus",
      qualys: "Qualys",
      rapid7: "Rapid7 Nexpose / InsightVM",
      burp: "Burp Suite",
      zap: "OWASP ZAP",
      openvas: "OpenVAS / Greenbone",
      custom: "Custom / Other"
    };
  }
});

export {
  detectScannerType,
  parseNessusXML,
  parseQualysCSV,
  parseRapid7CSV,
  parseBurpXML,
  parseZapXML,
  parseZapJSON,
  parseOpenVASXML,
  parseCSVLine,
  parseVulnScan,
  SCANNER_LABELS,
  vuln_scanner_parser_exports,
  init_vuln_scanner_parser
};
