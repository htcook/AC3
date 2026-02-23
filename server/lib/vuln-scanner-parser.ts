/**
 * Vulnerability Scanner Import Parsers
 * Parses Nessus (.nessus XML), Qualys (CSV/XML), and Rapid7 (CSV) scan exports.
 */

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
}

export interface ParsedScanResult {
  scannerType: "nessus" | "qualys" | "rapid7" | "openvas" | "custom";
  findings: ParsedVulnFinding[];
  totalHosts: number;
  totalVulns: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

// ---- Nessus XML Parser ----

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

  // Simple XML tag extraction (no external parser dependency)
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

// ---- Qualys CSV Parser ----

export function parseQualysCSV(csvContent: string): ParsedScanResult {
  const findings: ParsedVulnFinding[] = [];
  const hosts = new Set<string>();

  const lines = csvContent.split("\n");
  // Skip header lines (Qualys CSV often has metadata rows before the actual header)
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
    const cvss = cols[headerMap["cvss score"] ?? headerMap["cvss3 score"] ?? headerMap["cvss_score"] ?? -1];

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

// ---- Rapid7 CSV Parser ----

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

    const ip = cols[headerMap["asset ip address"] ?? headerMap["ip"] ?? headerMap["host"] ?? -1] || null;
    const hostName = cols[headerMap["asset names"] ?? headerMap["hostname"] ?? -1] || null;
    if (ip) hosts.add(ip);

    const severityRaw = (cols[headerMap["vulnerability severity level"] ?? headerMap["severity"] ?? -1] || "").toLowerCase();
    const cvss = cols[headerMap["vulnerability cvss score"] ?? headerMap["cvss score"] ?? headerMap["cvss_score"] ?? -1];

    findings.push({
      cveId: cols[headerMap["vulnerability cve ids"] ?? headerMap["cve"] ?? -1]?.split(",")[0]?.trim() || null,
      title: cols[headerMap["vulnerability title"] ?? headerMap["title"] ?? 0] || "Unknown",
      severity: mapRapid7Severity(severityRaw),
      cvssScore: cvss ? parseFloat(cvss) : null,
      hostIp: ip,
      hostName: hostName,
      port: cols[headerMap["service port"] ?? headerMap["port"] ?? -1] ? parseInt(cols[headerMap["service port"] ?? headerMap["port"]]) : null,
      protocol: cols[headerMap["service protocol"] ?? headerMap["protocol"] ?? -1] || null,
      description: cols[headerMap["vulnerability description"] ?? headerMap["description"] ?? -1] || null,
      solution: cols[headerMap["vulnerability solution"] ?? headerMap["solution"] ?? -1] || null,
      pluginId: cols[headerMap["vulnerability id"] ?? -1] || null,
      exploitAvailable: (cols[headerMap["vulnerability exploits"] ?? -1] || "").length > 0,
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

// ---- Utilities ----

function parseCSVLine(line: string): string[] {
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

export function parseVulnScan(content: string, scannerType: string): ParsedScanResult {
  switch (scannerType) {
    case "nessus": return parseNessusXML(content);
    case "qualys": return parseQualysCSV(content);
    case "rapid7": return parseRapid7CSV(content);
    default: return parseQualysCSV(content); // fallback to CSV
  }
}
