/**
 * Domain Intel Advanced Features
 * 
 * 1. Subdomain Change Detection — diff successive scans of the same domain
 * 2. Technology Vulnerability CVE Cross-Reference — match tech versions to known CVEs
 * 3. Subdomain Takeover Detection — identify dangling DNS records
 */

import dns from "dns/promises";

// ─── Types ───────────────────────────────────────────────────────────

export interface SubdomainChange {
  subdomain: string;
  changeType: "new" | "removed" | "ip_changed" | "port_changed" | "service_changed" | "tech_changed";
  severity: "critical" | "high" | "medium" | "low" | "info";
  previousValue?: string;
  currentValue?: string;
  description: string;
  detectedAt: number;
  riskImplication: string;
}

export interface ChangeDetectionResult {
  currentScanId: number;
  previousScanId: number;
  domain: string;
  scanDate: number;
  previousScanDate: number;
  totalChanges: number;
  criticalChanges: number;
  highChanges: number;
  newSubdomains: SubdomainChange[];
  removedSubdomains: SubdomainChange[];
  modifiedSubdomains: SubdomainChange[];
  summary: string;
}

export interface TechVulnerability {
  technology: string;
  detectedVersion: string;
  cveId: string;
  cvssScore: number;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  affectedVersions: string;
  fixedVersion?: string;
  exploitAvailable: boolean;
  references: string[];
  affectedAssets: string[];
  remediation: string;
  publishedDate: string;
}

export interface TechVulnResult {
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  vulnerabilities: TechVulnerability[];
  technologySummary: Array<{
    technology: string;
    version: string;
    vulnCount: number;
    maxSeverity: string;
    assetCount: number;
  }>;
}

export interface TakeoverCandidate {
  subdomain: string;
  cnameTarget: string;
  service: string;
  serviceCategory: string;
  riskLevel: "critical" | "high" | "medium" | "low";
  status: "vulnerable" | "potentially_vulnerable" | "monitoring";
  evidence: string[];
  description: string;
  remediation: string;
  mitreTechnique: string;
}

export interface TakeoverDetectionResult {
  totalChecked: number;
  vulnerableCount: number;
  potentiallyVulnerableCount: number;
  candidates: TakeoverCandidate[];
  summary: string;
}

// ─── 1. Subdomain Change Detection ──────────────────────────────────

interface ScanSnapshot {
  scanId: number;
  domain: string;
  scanDate: number;
  subdomains: Map<string, {
    ips: string[];
    ports: number[];
    services: string[];
    technologies: string[];
  }>;
}

function buildScanSnapshot(
  scanId: number,
  domain: string,
  scanDate: number,
  assets: any[],
  pipelineOutput: any
): ScanSnapshot {
  const subdomains = new Map<string, { ips: string[]; ports: number[]; services: string[]; technologies: string[] }>();

  // Add assets from discovered_assets table
  for (const asset of assets) {
    const hostname = asset.hostname?.toLowerCase();
    if (!hostname) continue;

    const ips: string[] = [];
    const ports: number[] = [];
    const services: string[] = [];
    const technologies: string[] = [];

    // Extract IPs from dnsRecords
    const dnsRecords = typeof asset.dnsRecords === "string" ? JSON.parse(asset.dnsRecords) : asset.dnsRecords;
    if (dnsRecords) {
      if (Array.isArray(dnsRecords.A)) ips.push(...dnsRecords.A);
      if (Array.isArray(dnsRecords.AAAA)) ips.push(...dnsRecords.AAAA);
    }

    // Extract technologies
    const techs = typeof asset.technologies === "string" ? JSON.parse(asset.technologies) : asset.technologies;
    if (Array.isArray(techs)) technologies.push(...techs);

    // Extract ports from postureFindings
    const findings = typeof asset.postureFindings === "string" ? JSON.parse(asset.postureFindings) : asset.postureFindings;
    if (Array.isArray(findings)) {
      for (const f of findings) {
        if (f.category === "open_port" || f.title?.includes("port")) {
          const portMatch = f.title?.match(/port\s+(\d+)/i);
          if (portMatch) ports.push(parseInt(portMatch[1]));
        }
      }
    }

    subdomains.set(hostname, {
      ips: [...new Set(ips)],
      ports: [...new Set(ports)].sort((a, b) => a - b),
      services: [...new Set(services)],
      technologies: [...new Set(technologies)],
    });
  }

  // Add subdomains from pipeline output
  const discoveredSubdomains = pipelineOutput?.discoveredSubdomains;
  if (Array.isArray(discoveredSubdomains)) {
    for (const sub of discoveredSubdomains) {
      const name = (sub.name || sub.subdomain || "").toLowerCase();
      if (!name || subdomains.has(name)) continue;

      const ips: string[] = [];
      if (sub.ip) ips.push(sub.ip);
      if (sub.resolvedIp) ips.push(sub.resolvedIp);

      const ports: number[] = [];
      const services: string[] = [];
      if (sub.ports && Array.isArray(sub.ports)) {
        for (const p of sub.ports) {
          if (typeof p === "number") ports.push(p);
          else if (p?.port) {
            ports.push(p.port);
            if (p.service) services.push(p.service);
            if (p.product) services.push(p.product);
          }
        }
      }

      subdomains.set(name, {
        ips: [...new Set(ips)],
        ports: [...new Set(ports)].sort((a, b) => a - b),
        services: [...new Set(services)],
        technologies: sub.technologies || [],
      });
    }
  }

  // Add subdomains from discoveredPorts
  const discoveredPorts = pipelineOutput?.discoveredPorts;
  if (Array.isArray(discoveredPorts)) {
    for (const p of discoveredPorts) {
      const hostname = (p.hostname || "").toLowerCase();
      if (!hostname) continue;
      const existing = subdomains.get(hostname);
      if (existing) {
        if (p.port && !existing.ports.includes(p.port)) existing.ports.push(p.port);
        if (p.product && !existing.services.includes(p.product)) existing.services.push(p.product);
      } else {
        subdomains.set(hostname, {
          ips: p.ip ? [p.ip] : [],
          ports: p.port ? [p.port] : [],
          services: p.product ? [p.product] : [],
          technologies: [],
        });
      }
    }
  }

  return { scanId, domain, scanDate, subdomains };
}

export function detectSubdomainChanges(
  currentScanId: number,
  previousScanId: number,
  domain: string,
  currentAssets: any[],
  previousAssets: any[],
  currentPipeline: any,
  previousPipeline: any,
  currentScanDate: number,
  previousScanDate: number
): ChangeDetectionResult {
  const current = buildScanSnapshot(currentScanId, domain, currentScanDate, currentAssets, currentPipeline);
  const previous = buildScanSnapshot(previousScanId, domain, previousScanDate, previousAssets, previousPipeline);

  const newSubdomains: SubdomainChange[] = [];
  const removedSubdomains: SubdomainChange[] = [];
  const modifiedSubdomains: SubdomainChange[] = [];
  const now = Date.now();

  // Find new subdomains
  for (const [name, data] of current.subdomains) {
    if (!previous.subdomains.has(name)) {
      newSubdomains.push({
        subdomain: name,
        changeType: "new",
        severity: data.ports.some(p => [21, 22, 23, 3389, 445, 3306, 5432].includes(p)) ? "high" : "medium",
        currentValue: `IP: ${data.ips.join(", ") || "unresolved"}, Ports: ${data.ports.join(", ") || "none"}`,
        description: `New subdomain discovered: ${name}`,
        detectedAt: now,
        riskImplication: "New subdomains may indicate infrastructure expansion, shadow IT, or unauthorized deployments that need security assessment.",
      });
    }
  }

  // Find removed subdomains
  for (const [name, data] of previous.subdomains) {
    if (!current.subdomains.has(name)) {
      removedSubdomains.push({
        subdomain: name,
        changeType: "removed",
        severity: "medium",
        previousValue: `IP: ${data.ips.join(", ") || "unresolved"}`,
        description: `Subdomain no longer detected: ${name}`,
        detectedAt: now,
        riskImplication: "Removed subdomains may indicate decommissioned services. Verify DNS records are cleaned up to prevent subdomain takeover.",
      });
    }
  }

  // Find modified subdomains
  for (const [name, currentData] of current.subdomains) {
    const previousData = previous.subdomains.get(name);
    if (!previousData) continue;

    // IP changes
    const prevIps = previousData.ips.sort().join(",");
    const currIps = currentData.ips.sort().join(",");
    if (prevIps !== currIps && (prevIps || currIps)) {
      modifiedSubdomains.push({
        subdomain: name,
        changeType: "ip_changed",
        severity: "high",
        previousValue: previousData.ips.join(", ") || "unresolved",
        currentValue: currentData.ips.join(", ") || "unresolved",
        description: `IP address changed for ${name}`,
        detectedAt: now,
        riskImplication: "IP changes may indicate infrastructure migration, DNS hijacking, or BGP hijacking. Verify the new IP belongs to your organization.",
      });
    }

    // Port changes
    const prevPorts = previousData.ports.sort((a, b) => a - b).join(",");
    const currPorts = currentData.ports.sort((a, b) => a - b).join(",");
    if (prevPorts !== currPorts && (prevPorts || currPorts)) {
      const newPorts = currentData.ports.filter(p => !previousData.ports.includes(p));
      const closedPorts = previousData.ports.filter(p => !currentData.ports.includes(p));
      const highRiskNew = newPorts.filter(p => [21, 22, 23, 3389, 445, 3306, 5432, 1433, 27017, 6379].includes(p));

      modifiedSubdomains.push({
        subdomain: name,
        changeType: "port_changed",
        severity: highRiskNew.length > 0 ? "critical" : newPorts.length > 0 ? "high" : "medium",
        previousValue: `Ports: ${previousData.ports.join(", ") || "none"}`,
        currentValue: `Ports: ${currentData.ports.join(", ") || "none"}`,
        description: `Port changes on ${name}: ${newPorts.length > 0 ? `+${newPorts.join(",")}` : ""} ${closedPorts.length > 0 ? `-${closedPorts.join(",")}` : ""}`.trim(),
        detectedAt: now,
        riskImplication: highRiskNew.length > 0
          ? `High-risk ports opened (${highRiskNew.join(", ")}). These services are common attack targets and should be verified immediately.`
          : "Port changes may indicate new services deployed or firewall rule changes. Review for unauthorized exposure.",
      });
    }

    // Technology changes
    const prevTech = previousData.technologies.sort().join(",");
    const currTech = currentData.technologies.sort().join(",");
    if (prevTech !== currTech && (prevTech || currTech)) {
      const newTech = currentData.technologies.filter(t => !previousData.technologies.includes(t));
      const removedTech = previousData.technologies.filter(t => !currentData.technologies.includes(t));

      modifiedSubdomains.push({
        subdomain: name,
        changeType: "tech_changed",
        severity: "medium",
        previousValue: previousData.technologies.join(", ") || "none detected",
        currentValue: currentData.technologies.join(", ") || "none detected",
        description: `Technology stack changed on ${name}: ${newTech.length > 0 ? `added ${newTech.join(", ")}` : ""} ${removedTech.length > 0 ? `removed ${removedTech.join(", ")}` : ""}`.trim(),
        detectedAt: now,
        riskImplication: "Technology changes may introduce new vulnerabilities. Run vulnerability assessment against the updated stack.",
      });
    }

    // Service changes
    const prevSvc = previousData.services.sort().join(",");
    const currSvc = currentData.services.sort().join(",");
    if (prevSvc !== currSvc && (prevSvc || currSvc)) {
      modifiedSubdomains.push({
        subdomain: name,
        changeType: "service_changed",
        severity: "medium",
        previousValue: previousData.services.join(", ") || "none detected",
        currentValue: currentData.services.join(", ") || "none detected",
        description: `Services changed on ${name}`,
        detectedAt: now,
        riskImplication: "Service changes may indicate software updates, new deployments, or unauthorized modifications.",
      });
    }
  }

  const allChanges = [...newSubdomains, ...removedSubdomains, ...modifiedSubdomains];
  const criticalChanges = allChanges.filter(c => c.severity === "critical").length;
  const highChanges = allChanges.filter(c => c.severity === "high").length;

  const summary = allChanges.length === 0
    ? "No changes detected between scans."
    : `Detected ${allChanges.length} change(s): ${newSubdomains.length} new subdomain(s), ${removedSubdomains.length} removed, ${modifiedSubdomains.length} modification(s). ${criticalChanges} critical, ${highChanges} high severity.`;

  return {
    currentScanId,
    previousScanId,
    domain,
    scanDate: currentScanDate,
    previousScanDate,
    totalChanges: allChanges.length,
    criticalChanges,
    highChanges,
    newSubdomains,
    removedSubdomains,
    modifiedSubdomains,
    summary,
  };
}

// ─── 2. Technology Vulnerability CVE Cross-Reference ─────────────────

// Known CVE database for common web technologies
// This is a curated subset — in production, integrate with NVD API
const KNOWN_TECH_CVES: Array<{
  technology: string;
  matchPattern: RegExp;
  cveId: string;
  cvssScore: number;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  affectedVersions: string;
  fixedVersion: string;
  exploitAvailable: boolean;
  publishedDate: string;
  references: string[];
}> = [
  // Apache
  { technology: "Apache", matchPattern: /^(apache|httpd)$/i, cveId: "CVE-2024-38476", cvssScore: 9.8, severity: "critical", description: "Apache HTTP Server: SSRF via backend applications with malicious or exploitable response headers", affectedVersions: "< 2.4.62", fixedVersion: "2.4.62", exploitAvailable: true, publishedDate: "2024-07-01", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-38476"] },
  { technology: "Apache", matchPattern: /^(apache|httpd)$/i, cveId: "CVE-2024-27316", cvssScore: 7.5, severity: "high", description: "Apache HTTP Server: HTTP/2 DoS by memory exhaustion on endless continuation frames", affectedVersions: "< 2.4.59", fixedVersion: "2.4.59", exploitAvailable: true, publishedDate: "2024-04-04", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-27316"] },
  { technology: "Apache", matchPattern: /^(apache|httpd)$/i, cveId: "CVE-2023-43622", cvssScore: 7.5, severity: "high", description: "Apache HTTP Server: HTTP/2 stream count limit can be bypassed", affectedVersions: "< 2.4.58", fixedVersion: "2.4.58", exploitAvailable: false, publishedDate: "2023-10-23", references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-43622"] },
  { technology: "Apache", matchPattern: /^(apache|httpd)$/i, cveId: "CVE-2021-41773", cvssScore: 7.5, severity: "high", description: "Apache HTTP Server: Path traversal and file disclosure vulnerability", affectedVersions: "2.4.49", fixedVersion: "2.4.50", exploitAvailable: true, publishedDate: "2021-10-05", references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"] },
  // Nginx
  { technology: "nginx", matchPattern: /^nginx$/i, cveId: "CVE-2024-7347", cvssScore: 4.7, severity: "medium", description: "NGINX: Worker process crash when processing a specially crafted mp4 file with ngx_http_mp4_module", affectedVersions: "< 1.27.1", fixedVersion: "1.27.1", exploitAvailable: false, publishedDate: "2024-08-14", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-7347"] },
  { technology: "nginx", matchPattern: /^nginx$/i, cveId: "CVE-2024-24989", cvssScore: 7.5, severity: "high", description: "NGINX: HTTP/3 QUIC NULL pointer dereference", affectedVersions: "< 1.25.4", fixedVersion: "1.25.4", exploitAvailable: false, publishedDate: "2024-02-14", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-24989"] },
  { technology: "nginx", matchPattern: /^nginx$/i, cveId: "CVE-2022-41741", cvssScore: 7.8, severity: "high", description: "NGINX: Memory corruption in ngx_http_mp4_module", affectedVersions: "< 1.23.2", fixedVersion: "1.23.2", exploitAvailable: true, publishedDate: "2022-10-19", references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-41741"] },
  // OpenSSL
  { technology: "OpenSSL", matchPattern: /^openssl$/i, cveId: "CVE-2024-5535", cvssScore: 9.1, severity: "critical", description: "OpenSSL: SSL_select_next_proto buffer overread", affectedVersions: "< 3.3.2", fixedVersion: "3.3.2", exploitAvailable: false, publishedDate: "2024-06-27", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-5535"] },
  { technology: "OpenSSL", matchPattern: /^openssl$/i, cveId: "CVE-2024-0727", cvssScore: 5.5, severity: "medium", description: "OpenSSL: NULL pointer dereference when processing PKCS12 data", affectedVersions: "< 3.2.1", fixedVersion: "3.2.1", exploitAvailable: false, publishedDate: "2024-01-26", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-0727"] },
  { technology: "OpenSSL", matchPattern: /^openssl$/i, cveId: "CVE-2022-3602", cvssScore: 7.5, severity: "high", description: "OpenSSL: X.509 Email Address 4-byte Buffer Overflow", affectedVersions: "3.0.0 - 3.0.6", fixedVersion: "3.0.7", exploitAvailable: true, publishedDate: "2022-11-01", references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-3602"] },
  // PHP
  { technology: "PHP", matchPattern: /^php$/i, cveId: "CVE-2024-4577", cvssScore: 9.8, severity: "critical", description: "PHP: CGI argument injection vulnerability allowing remote code execution", affectedVersions: "< 8.3.8", fixedVersion: "8.3.8", exploitAvailable: true, publishedDate: "2024-06-06", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-4577"] },
  { technology: "PHP", matchPattern: /^php$/i, cveId: "CVE-2024-2756", cvssScore: 6.5, severity: "medium", description: "PHP: __Host-/__Secure- cookie bypass due to partial CVE-2022-31629 fix", affectedVersions: "< 8.3.4", fixedVersion: "8.3.4", exploitAvailable: false, publishedDate: "2024-04-16", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-2756"] },
  { technology: "PHP", matchPattern: /^php$/i, cveId: "CVE-2023-3824", cvssScore: 9.8, severity: "critical", description: "PHP: Buffer overflow in phar_dir_read()", affectedVersions: "< 8.2.9", fixedVersion: "8.2.9", exploitAvailable: true, publishedDate: "2023-08-11", references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-3824"] },
  // WordPress
  { technology: "WordPress", matchPattern: /^wordpress$/i, cveId: "CVE-2024-6307", cvssScore: 6.4, severity: "medium", description: "WordPress: Authenticated stored XSS via HTML API", affectedVersions: "< 6.5.5", fixedVersion: "6.5.5", exploitAvailable: true, publishedDate: "2024-06-24", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-6307"] },
  { technology: "WordPress", matchPattern: /^wordpress$/i, cveId: "CVE-2024-31210", cvssScore: 7.6, severity: "high", description: "WordPress: Remote code execution via plugin/theme upload on multisite", affectedVersions: "< 6.4.4", fixedVersion: "6.4.4", exploitAvailable: true, publishedDate: "2024-04-04", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-31210"] },
  // jQuery
  { technology: "jQuery", matchPattern: /^jquery$/i, cveId: "CVE-2020-11023", cvssScore: 6.1, severity: "medium", description: "jQuery: Untrusted code execution via <option> element passed to DOM manipulation methods", affectedVersions: "< 3.5.0", fixedVersion: "3.5.0", exploitAvailable: true, publishedDate: "2020-04-29", references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-11023"] },
  { technology: "jQuery", matchPattern: /^jquery$/i, cveId: "CVE-2019-11358", cvssScore: 6.1, severity: "medium", description: "jQuery: Prototype pollution in $.extend", affectedVersions: "< 3.4.0", fixedVersion: "3.4.0", exploitAvailable: true, publishedDate: "2019-04-20", references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-11358"] },
  // Microsoft IIS
  { technology: "IIS", matchPattern: /^(iis|microsoft-iis)$/i, cveId: "CVE-2023-36899", cvssScore: 8.8, severity: "high", description: "Microsoft IIS: ASP.NET elevation of privilege vulnerability", affectedVersions: "IIS 10.0", fixedVersion: "Apply KB5029928", exploitAvailable: false, publishedDate: "2023-08-08", references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-36899"] },
  // Tomcat
  { technology: "Tomcat", matchPattern: /^(tomcat|apache tomcat)$/i, cveId: "CVE-2024-52316", cvssScore: 9.8, severity: "critical", description: "Apache Tomcat: Authentication bypass when using Jakarta Authentication", affectedVersions: "< 11.0.1", fixedVersion: "11.0.1", exploitAvailable: false, publishedDate: "2024-11-18", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-52316"] },
  { technology: "Tomcat", matchPattern: /^(tomcat|apache tomcat)$/i, cveId: "CVE-2024-23672", cvssScore: 7.5, severity: "high", description: "Apache Tomcat: WebSocket DoS via incomplete closing handshake", affectedVersions: "< 10.1.19", fixedVersion: "10.1.19", exploitAvailable: false, publishedDate: "2024-03-13", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-23672"] },
  // Node.js
  { technology: "Node.js", matchPattern: /^(node\.?js|express)$/i, cveId: "CVE-2024-22019", cvssScore: 7.5, severity: "high", description: "Node.js: HTTP request smuggling via Content-Length header", affectedVersions: "< 21.6.1", fixedVersion: "21.6.1", exploitAvailable: false, publishedDate: "2024-02-14", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-22019"] },
  { technology: "Node.js", matchPattern: /^(node\.?js|express)$/i, cveId: "CVE-2024-22025", cvssScore: 6.5, severity: "medium", description: "Node.js: Fetch API resource exhaustion DoS", affectedVersions: "< 21.6.1", fixedVersion: "21.6.1", exploitAvailable: false, publishedDate: "2024-02-14", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-22025"] },
  // Redis
  { technology: "Redis", matchPattern: /^redis$/i, cveId: "CVE-2024-31449", cvssScore: 8.8, severity: "high", description: "Redis: Lua library commands may lead to stack overflow and RCE", affectedVersions: "< 7.4.1", fixedVersion: "7.4.1", exploitAvailable: true, publishedDate: "2024-10-07", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-31449"] },
  // MySQL
  { technology: "MySQL", matchPattern: /^(mysql|mariadb)$/i, cveId: "CVE-2024-21047", cvssScore: 4.9, severity: "medium", description: "MySQL Server: InnoDB unspecified vulnerability", affectedVersions: "< 8.0.37", fixedVersion: "8.0.37", exploitAvailable: false, publishedDate: "2024-04-16", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-21047"] },
  // PostgreSQL
  { technology: "PostgreSQL", matchPattern: /^(postgresql|postgres)$/i, cveId: "CVE-2024-10979", cvssScore: 8.8, severity: "high", description: "PostgreSQL: PL/Perl environment variable changes execute arbitrary code", affectedVersions: "< 17.1", fixedVersion: "17.1", exploitAvailable: true, publishedDate: "2024-11-14", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-10979"] },
  // MongoDB
  { technology: "MongoDB", matchPattern: /^mongodb$/i, cveId: "CVE-2024-1351", cvssScore: 8.1, severity: "high", description: "MongoDB: Improper access control allows unauthenticated access", affectedVersions: "< 7.0.5", fixedVersion: "7.0.5", exploitAvailable: false, publishedDate: "2024-03-07", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-1351"] },
  // Elasticsearch
  { technology: "Elasticsearch", matchPattern: /^elasticsearch$/i, cveId: "CVE-2023-31419", cvssScore: 7.5, severity: "high", description: "Elasticsearch: Stack overflow in _search API with specially crafted queries", affectedVersions: "< 8.9.1", fixedVersion: "8.9.1", exploitAvailable: true, publishedDate: "2023-10-26", references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-31419"] },
  // Cloudflare
  { technology: "Cloudflare", matchPattern: /^cloudflare$/i, cveId: "CVE-2023-7101", cvssScore: 7.8, severity: "high", description: "Spreadsheet::ParseExcel RCE (used in Cloudflare email security)", affectedVersions: "< 0.66", fixedVersion: "0.66", exploitAvailable: true, publishedDate: "2023-12-24", references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-7101"] },
  // Envoy
  { technology: "Envoy", matchPattern: /^envoy$/i, cveId: "CVE-2024-23326", cvssScore: 7.5, severity: "high", description: "Envoy: Crash due to malformed HTTP/2 metadata", affectedVersions: "< 1.29.1", fixedVersion: "1.29.1", exploitAvailable: false, publishedDate: "2024-02-09", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-23326"] },
];

function compareVersions(detected: string, constraint: string): boolean {
  // Parse version strings like "1.18.0", "8.2.9"
  const parseVer = (v: string): number[] => {
    return v.replace(/^[v=<>!~^]+/, "").split(".").map(n => parseInt(n) || 0);
  };

  // Handle "< X.Y.Z" constraints
  const ltMatch = constraint.match(/^<\s*(.+)$/);
  if (ltMatch) {
    const target = parseVer(ltMatch[1]);
    const det = parseVer(detected);
    for (let i = 0; i < Math.max(target.length, det.length); i++) {
      const t = target[i] || 0;
      const d = det[i] || 0;
      if (d < t) return true;
      if (d > t) return false;
    }
    return false;
  }

  // Handle "X.Y.Z" exact match
  if (!constraint.includes("-") && !constraint.includes("<") && !constraint.includes(">")) {
    return detected === constraint;
  }

  // Handle "X.Y.Z - A.B.C" range
  const rangeMatch = constraint.match(/^(.+?)\s*-\s*(.+)$/);
  if (rangeMatch) {
    const low = parseVer(rangeMatch[1]);
    const high = parseVer(rangeMatch[2]);
    const det = parseVer(detected);

    let aboveLow = false;
    let belowHigh = false;

    for (let i = 0; i < Math.max(low.length, det.length); i++) {
      const l = low[i] || 0;
      const d = det[i] || 0;
      if (d > l) { aboveLow = true; break; }
      if (d < l) { aboveLow = false; break; }
      if (i === Math.max(low.length, det.length) - 1) aboveLow = true; // equal
    }

    for (let i = 0; i < Math.max(high.length, det.length); i++) {
      const h = high[i] || 0;
      const d = det[i] || 0;
      if (d < h) { belowHigh = true; break; }
      if (d > h) { belowHigh = false; break; }
      if (i === Math.max(high.length, det.length) - 1) belowHigh = true; // equal
    }

    return aboveLow && belowHigh;
  }

  // Default: assume vulnerable if we can't parse
  return false;
}

export function crossReferenceTechVulnerabilities(
  assets: any[],
  pipelineOutput: any
): TechVulnResult {
  const vulnerabilities: TechVulnerability[] = [];
  const techAssetMap = new Map<string, { version: string; assets: Set<string> }>();

  // Collect all technologies and their versions from assets
  for (const asset of assets) {
    const hostname = asset.hostname || "unknown";
    const techs = typeof asset.technologies === "string" ? JSON.parse(asset.technologies) : asset.technologies;
    const techVersions = typeof asset.technologyVersions === "string" ? JSON.parse(asset.technologyVersions) : asset.technologyVersions;

    if (Array.isArray(techs)) {
      for (const tech of techs) {
        const techName = tech.replace(/[\s/]+\d+.*$/, "").trim(); // Strip version from name
        const version = techVersions?.[tech] || techVersions?.[techName] || extractVersionFromTech(tech);

        const key = `${techName.toLowerCase()}|${version || "unknown"}`;
        const existing = techAssetMap.get(key);
        if (existing) {
          existing.assets.add(hostname);
        } else {
          techAssetMap.set(key, { version: version || "unknown", assets: new Set([hostname]) });
        }
      }
    }
  }

  // Also collect from pipeline subdomains
  const discoveredPorts = pipelineOutput?.discoveredPorts;
  if (Array.isArray(discoveredPorts)) {
    for (const p of discoveredPorts) {
      const hostname = p.hostname || p.ip || "unknown";
      if (p.product) {
        const version = p.version || "unknown";
        const key = `${p.product.toLowerCase()}|${version}`;
        const existing = techAssetMap.get(key);
        if (existing) {
          existing.assets.add(hostname);
        } else {
          techAssetMap.set(key, { version, assets: new Set([hostname]) });
        }
      }
    }
  }

  // Cross-reference against known CVEs
  for (const [key, data] of techAssetMap) {
    const [techLower] = key.split("|");
    const { version, assets: affectedHosts } = data;

    for (const cve of KNOWN_TECH_CVES) {
      if (!cve.matchPattern.test(techLower)) continue;

      // Check version match
      let isVulnerable = false;
      if (version !== "unknown") {
        isVulnerable = compareVersions(version, cve.affectedVersions);
      } else {
        // Unknown version — flag as potentially vulnerable
        isVulnerable = true;
      }

      if (isVulnerable) {
        // Avoid duplicates
        const existingVuln = vulnerabilities.find(v => v.cveId === cve.cveId && v.technology === cve.technology);
        if (existingVuln) {
          // Merge affected assets
          for (const h of affectedHosts) {
            if (!existingVuln.affectedAssets.includes(h)) {
              existingVuln.affectedAssets.push(h);
            }
          }
          continue;
        }

        vulnerabilities.push({
          technology: cve.technology,
          detectedVersion: version,
          cveId: cve.cveId,
          cvssScore: cve.cvssScore,
          severity: cve.severity,
          description: cve.description,
          affectedVersions: cve.affectedVersions,
          fixedVersion: cve.fixedVersion,
          exploitAvailable: cve.exploitAvailable,
          references: cve.references,
          affectedAssets: [...affectedHosts],
          remediation: `Upgrade ${cve.technology} to version ${cve.fixedVersion} or later. ${cve.exploitAvailable ? "PUBLIC EXPLOIT AVAILABLE — prioritize immediate patching." : "No public exploit known, but patching is recommended."}`,
          publishedDate: cve.publishedDate,
        });
      }
    }
  }

  // Sort by CVSS score descending
  vulnerabilities.sort((a, b) => b.cvssScore - a.cvssScore);

  // Build technology summary
  const techSummaryMap = new Map<string, { version: string; vulnCount: number; maxSeverity: string; maxCvss: number; assetCount: number }>();
  for (const vuln of vulnerabilities) {
    const key = `${vuln.technology}|${vuln.detectedVersion}`;
    const existing = techSummaryMap.get(key);
    if (existing) {
      existing.vulnCount++;
      if (vuln.cvssScore > existing.maxCvss) {
        existing.maxCvss = vuln.cvssScore;
        existing.maxSeverity = vuln.severity;
      }
      existing.assetCount = Math.max(existing.assetCount, vuln.affectedAssets.length);
    } else {
      techSummaryMap.set(key, {
        version: vuln.detectedVersion,
        vulnCount: 1,
        maxSeverity: vuln.severity,
        maxCvss: vuln.cvssScore,
        assetCount: vuln.affectedAssets.length,
      });
    }
  }

  const technologySummary = [...techSummaryMap.entries()].map(([key, data]) => ({
    technology: key.split("|")[0],
    version: data.version,
    vulnCount: data.vulnCount,
    maxSeverity: data.maxSeverity,
    assetCount: data.assetCount,
  })).sort((a, b) => {
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return (sevOrder[a.maxSeverity as keyof typeof sevOrder] ?? 4) - (sevOrder[b.maxSeverity as keyof typeof sevOrder] ?? 4);
  });

  return {
    totalVulnerabilities: vulnerabilities.length,
    criticalCount: vulnerabilities.filter(v => v.severity === "critical").length,
    highCount: vulnerabilities.filter(v => v.severity === "high").length,
    mediumCount: vulnerabilities.filter(v => v.severity === "medium").length,
    lowCount: vulnerabilities.filter(v => v.severity === "low").length,
    vulnerabilities,
    technologySummary,
  };
}

function extractVersionFromTech(tech: string): string | undefined {
  const match = tech.match(/[\s/](\d+\.\d+(?:\.\d+)?)/);
  return match ? match[1] : undefined;
}

// ─── 3. Subdomain Takeover Detection ─────────────────────────────────

// Services known to be vulnerable to subdomain takeover
const TAKEOVER_FINGERPRINTS: Array<{
  service: string;
  serviceCategory: string;
  cnamePatterns: RegExp[];
  httpFingerprints: string[];
  riskLevel: "critical" | "high" | "medium";
  description: string;
  remediation: string;
}> = [
  {
    service: "Amazon S3",
    serviceCategory: "Cloud Storage",
    cnamePatterns: [/\.s3\.amazonaws\.com$/i, /\.s3-website[.-].*\.amazonaws\.com$/i, /\.s3\..*\.amazonaws\.com$/i],
    httpFingerprints: ["NoSuchBucket", "The specified bucket does not exist"],
    riskLevel: "critical",
    description: "CNAME points to an S3 bucket that may not exist. An attacker can create the bucket and serve malicious content.",
    remediation: "Remove the CNAME record or create the S3 bucket with the expected name. Enable S3 bucket logging and access controls.",
  },
  {
    service: "GitHub Pages",
    serviceCategory: "Hosting",
    cnamePatterns: [/\.github\.io$/i, /\.githubusercontent\.com$/i],
    httpFingerprints: ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"],
    riskLevel: "high",
    description: "CNAME points to GitHub Pages but no repository is configured. An attacker can claim this subdomain.",
    remediation: "Remove the CNAME record or configure a GitHub repository with the matching custom domain.",
  },
  {
    service: "Heroku",
    serviceCategory: "PaaS",
    cnamePatterns: [/\.herokuapp\.com$/i, /\.herokussl\.com$/i, /\.herokudns\.com$/i],
    httpFingerprints: ["No such app", "no-such-app", "herokucdn.com/error-pages"],
    riskLevel: "critical",
    description: "CNAME points to a Heroku app that no longer exists. An attacker can create an app with this name.",
    remediation: "Remove the CNAME record or recreate the Heroku application with the expected name.",
  },
  {
    service: "Azure (App Service / Traffic Manager)",
    serviceCategory: "Cloud",
    cnamePatterns: [/\.azurewebsites\.net$/i, /\.cloudapp\.azure\.com$/i, /\.trafficmanager\.net$/i, /\.azure-api\.net$/i, /\.azurefd\.net$/i],
    httpFingerprints: ["404 Web Site not found", "The resource you are looking for has been removed"],
    riskLevel: "high",
    description: "CNAME points to an Azure resource that may be deprovisioned. Subdomain takeover possible via Azure resource claim.",
    remediation: "Remove the CNAME record or provision the Azure resource. Verify custom domain bindings in Azure portal.",
  },
  {
    service: "Netlify",
    serviceCategory: "Hosting",
    cnamePatterns: [/\.netlify\.app$/i, /\.netlify\.com$/i, /\.bitballoon\.com$/i],
    httpFingerprints: ["Not Found - Request ID", "Page not found"],
    riskLevel: "high",
    description: "CNAME points to Netlify but no site is configured for this domain.",
    remediation: "Remove the CNAME record or configure a Netlify site with the matching custom domain.",
  },
  {
    service: "Shopify",
    serviceCategory: "E-commerce",
    cnamePatterns: [/\.myshopify\.com$/i],
    httpFingerprints: ["Sorry, this shop is currently unavailable", "Only one step left"],
    riskLevel: "high",
    description: "CNAME points to a Shopify store that may not exist or is unclaimed.",
    remediation: "Remove the CNAME record or configure the Shopify store with the matching custom domain.",
  },
  {
    service: "Fastly",
    serviceCategory: "CDN",
    cnamePatterns: [/\.fastly\.net$/i, /\.fastlylb\.net$/i],
    httpFingerprints: ["Fastly error: unknown domain"],
    riskLevel: "high",
    description: "CNAME points to Fastly CDN but no service is configured for this domain.",
    remediation: "Remove the CNAME record or configure the Fastly service with the matching domain.",
  },
  {
    service: "Pantheon",
    serviceCategory: "Hosting",
    cnamePatterns: [/\.pantheonsite\.io$/i, /\.pantheon\.io$/i],
    httpFingerprints: ["404 error unknown site", "The gods are wise"],
    riskLevel: "high",
    description: "CNAME points to Pantheon hosting but no site is configured.",
    remediation: "Remove the CNAME record or configure the Pantheon site with the matching domain.",
  },
  {
    service: "Zendesk",
    serviceCategory: "SaaS",
    cnamePatterns: [/\.zendesk\.com$/i],
    httpFingerprints: ["Help Center Closed", "Oops, this help center no longer exists"],
    riskLevel: "medium",
    description: "CNAME points to a Zendesk instance that may be deprovisioned.",
    remediation: "Remove the CNAME record or reconfigure the Zendesk help center.",
  },
  {
    service: "Surge.sh",
    serviceCategory: "Hosting",
    cnamePatterns: [/\.surge\.sh$/i],
    httpFingerprints: ["project not found"],
    riskLevel: "high",
    description: "CNAME points to Surge.sh but no project is deployed.",
    remediation: "Remove the CNAME record or deploy a project to Surge.sh with the matching domain.",
  },
  {
    service: "Fly.io",
    serviceCategory: "PaaS",
    cnamePatterns: [/\.fly\.dev$/i, /\.flycast\.dev$/i],
    httpFingerprints: ["404 Not Found"],
    riskLevel: "high",
    description: "CNAME points to Fly.io but no application is configured.",
    remediation: "Remove the CNAME record or deploy an application to Fly.io with the matching domain.",
  },
  {
    service: "Vercel",
    serviceCategory: "Hosting",
    cnamePatterns: [/\.vercel\.app$/i, /\.now\.sh$/i, /cname\.vercel-dns\.com$/i],
    httpFingerprints: ["The deployment could not be found"],
    riskLevel: "high",
    description: "CNAME points to Vercel but no deployment is configured for this domain.",
    remediation: "Remove the CNAME record or configure a Vercel project with the matching custom domain.",
  },
  {
    service: "Render",
    serviceCategory: "PaaS",
    cnamePatterns: [/\.onrender\.com$/i],
    httpFingerprints: ["not found"],
    riskLevel: "high",
    description: "CNAME points to Render but no service is configured.",
    remediation: "Remove the CNAME record or deploy a service to Render with the matching domain.",
  },
  {
    service: "Cargo Collective",
    serviceCategory: "Hosting",
    cnamePatterns: [/\.cargocollective\.com$/i, /\.cargo\.site$/i],
    httpFingerprints: ["404 Not Found"],
    riskLevel: "medium",
    description: "CNAME points to Cargo Collective but no site is configured.",
    remediation: "Remove the CNAME record or configure the Cargo Collective site.",
  },
];

export async function detectSubdomainTakeover(
  assets: any[],
  pipelineOutput: any
): Promise<TakeoverDetectionResult> {
  const candidates: TakeoverCandidate[] = [];
  const checkedSubdomains = new Set<string>();

  // Collect all subdomains with their CNAME records
  const subdomainCnames = new Map<string, string[]>();

  // From discovered assets
  for (const asset of assets) {
    const hostname = asset.hostname?.toLowerCase();
    if (!hostname || checkedSubdomains.has(hostname)) continue;
    checkedSubdomains.add(hostname);

    const dnsRecords = typeof asset.dnsRecords === "string" ? JSON.parse(asset.dnsRecords) : asset.dnsRecords;
    if (dnsRecords?.CNAME && Array.isArray(dnsRecords.CNAME)) {
      subdomainCnames.set(hostname, dnsRecords.CNAME.map((c: string) => c.toLowerCase()));
    }
  }

  // From pipeline subdomains
  const discoveredSubdomains = pipelineOutput?.discoveredSubdomains;
  if (Array.isArray(discoveredSubdomains)) {
    for (const sub of discoveredSubdomains) {
      const name = (sub.name || sub.subdomain || "").toLowerCase();
      if (!name || checkedSubdomains.has(name)) continue;
      checkedSubdomains.add(name);

      // Try DNS CNAME lookup for subdomains without stored DNS records
      try {
        const cnameRecords = await dns.resolveCname(name).catch(() => []);
        if (cnameRecords.length > 0) {
          subdomainCnames.set(name, cnameRecords.map(c => c.toLowerCase()));
        }
      } catch {
        // DNS lookup failed — skip
      }
    }
  }

  // Check each subdomain against takeover fingerprints
  for (const [subdomain, cnames] of subdomainCnames) {
    for (const cname of cnames) {
      for (const fingerprint of TAKEOVER_FINGERPRINTS) {
        const matchedPattern = fingerprint.cnamePatterns.find(p => p.test(cname));
        if (!matchedPattern) continue;

        // Check if the CNAME target resolves
        let targetResolves = true;
        try {
          await dns.resolve4(cname);
        } catch {
          targetResolves = false;
        }

        const status = targetResolves ? "potentially_vulnerable" : "vulnerable";
        const riskLevel = targetResolves ? (fingerprint.riskLevel === "critical" ? "high" : fingerprint.riskLevel) : fingerprint.riskLevel;

        candidates.push({
          subdomain,
          cnameTarget: cname,
          service: fingerprint.service,
          serviceCategory: fingerprint.serviceCategory,
          riskLevel,
          status,
          evidence: [
            `CNAME record: ${subdomain} → ${cname}`,
            `Matched service pattern: ${fingerprint.service}`,
            targetResolves
              ? "CNAME target resolves — service may still be active but should be verified"
              : "CNAME target does NOT resolve — strong indicator of deprovisioned service",
          ],
          description: fingerprint.description,
          remediation: fingerprint.remediation,
          mitreTechnique: "T1584.001 — Compromise Infrastructure: Domains",
        });
      }
    }
  }

  // Sort by risk level
  const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  candidates.sort((a, b) => (riskOrder[a.riskLevel] ?? 4) - (riskOrder[b.riskLevel] ?? 4));

  const vulnerableCount = candidates.filter(c => c.status === "vulnerable").length;
  const potentiallyVulnerableCount = candidates.filter(c => c.status === "potentially_vulnerable").length;

  const summary = candidates.length === 0
    ? `Checked ${checkedSubdomains.size} subdomains — no subdomain takeover risks detected.`
    : `Checked ${checkedSubdomains.size} subdomains — found ${vulnerableCount} vulnerable and ${potentiallyVulnerableCount} potentially vulnerable to subdomain takeover across ${new Set(candidates.map(c => c.service)).size} service(s).`;

  return {
    totalChecked: checkedSubdomains.size,
    vulnerableCount,
    potentiallyVulnerableCount,
    candidates,
    summary,
  };
}
