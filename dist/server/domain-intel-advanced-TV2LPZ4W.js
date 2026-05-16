import "./chunk-KFQGP6VL.js";

// server/lib/domain-intel-advanced.ts
import dns from "dns/promises";
import https from "https";
import http from "http";
function buildScanSnapshot(scanId, domain, scanDate, assets, pipelineOutput) {
  const subdomains = /* @__PURE__ */ new Map();
  for (const asset of assets) {
    const hostname = asset.hostname?.toLowerCase();
    if (!hostname) continue;
    const ips = [];
    const ports = [];
    const services = [];
    const technologies = [];
    const dnsRecords = typeof asset.dnsRecords === "string" ? JSON.parse(asset.dnsRecords) : asset.dnsRecords;
    if (dnsRecords) {
      if (Array.isArray(dnsRecords.A)) ips.push(...dnsRecords.A);
      if (Array.isArray(dnsRecords.AAAA)) ips.push(...dnsRecords.AAAA);
    }
    const techs = typeof asset.technologies === "string" ? JSON.parse(asset.technologies) : asset.technologies;
    if (Array.isArray(techs)) technologies.push(...techs);
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
      technologies: [...new Set(technologies)]
    });
  }
  const discoveredSubdomains = pipelineOutput?.discoveredSubdomains;
  if (Array.isArray(discoveredSubdomains)) {
    for (const sub of discoveredSubdomains) {
      const name = (sub.name || sub.subdomain || "").toLowerCase();
      if (!name || subdomains.has(name)) continue;
      const ips = [];
      if (sub.ip) ips.push(sub.ip);
      if (sub.resolvedIp) ips.push(sub.resolvedIp);
      const ports = [];
      const services = [];
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
        technologies: sub.technologies || []
      });
    }
  }
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
          technologies: []
        });
      }
    }
  }
  return { scanId, domain, scanDate, subdomains };
}
function detectSubdomainChanges(currentScanId, previousScanId, domain, currentAssets, previousAssets, currentPipeline, previousPipeline, currentScanDate, previousScanDate) {
  const current = buildScanSnapshot(currentScanId, domain, currentScanDate, currentAssets, currentPipeline);
  const previous = buildScanSnapshot(previousScanId, domain, previousScanDate, previousAssets, previousPipeline);
  const newSubdomains = [];
  const removedSubdomains = [];
  const modifiedSubdomains = [];
  const now = Date.now();
  for (const [name, data] of current.subdomains) {
    if (!previous.subdomains.has(name)) {
      newSubdomains.push({
        subdomain: name,
        changeType: "new",
        severity: data.ports.some((p) => [21, 22, 23, 3389, 445, 3306, 5432].includes(p)) ? "high" : "medium",
        currentValue: `IP: ${data.ips.join(", ") || "unresolved"}, Ports: ${data.ports.join(", ") || "none"}`,
        description: `New subdomain discovered: ${name}`,
        detectedAt: now,
        riskImplication: "New subdomains may indicate infrastructure expansion, shadow IT, or unauthorized deployments that need security assessment."
      });
    }
  }
  for (const [name, data] of previous.subdomains) {
    if (!current.subdomains.has(name)) {
      removedSubdomains.push({
        subdomain: name,
        changeType: "removed",
        severity: "medium",
        previousValue: `IP: ${data.ips.join(", ") || "unresolved"}`,
        description: `Subdomain no longer detected: ${name}`,
        detectedAt: now,
        riskImplication: "Removed subdomains may indicate decommissioned services. Verify DNS records are cleaned up to prevent subdomain takeover."
      });
    }
  }
  for (const [name, currentData] of current.subdomains) {
    const previousData = previous.subdomains.get(name);
    if (!previousData) continue;
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
        riskImplication: "IP changes may indicate infrastructure migration, DNS hijacking, or BGP hijacking. Verify the new IP belongs to your organization."
      });
    }
    const prevPorts = previousData.ports.sort((a, b) => a - b).join(",");
    const currPorts = currentData.ports.sort((a, b) => a - b).join(",");
    if (prevPorts !== currPorts && (prevPorts || currPorts)) {
      const newPorts = currentData.ports.filter((p) => !previousData.ports.includes(p));
      const closedPorts = previousData.ports.filter((p) => !currentData.ports.includes(p));
      const highRiskNew = newPorts.filter((p) => [21, 22, 23, 3389, 445, 3306, 5432, 1433, 27017, 6379].includes(p));
      modifiedSubdomains.push({
        subdomain: name,
        changeType: "port_changed",
        severity: highRiskNew.length > 0 ? "critical" : newPorts.length > 0 ? "high" : "medium",
        previousValue: `Ports: ${previousData.ports.join(", ") || "none"}`,
        currentValue: `Ports: ${currentData.ports.join(", ") || "none"}`,
        description: `Port changes on ${name}: ${newPorts.length > 0 ? `+${newPorts.join(",")}` : ""} ${closedPorts.length > 0 ? `-${closedPorts.join(",")}` : ""}`.trim(),
        detectedAt: now,
        riskImplication: highRiskNew.length > 0 ? `High-risk ports opened (${highRiskNew.join(", ")}). These services are common attack targets and should be verified immediately.` : "Port changes may indicate new services deployed or firewall rule changes. Review for unauthorized exposure."
      });
    }
    const prevTech = previousData.technologies.sort().join(",");
    const currTech = currentData.technologies.sort().join(",");
    if (prevTech !== currTech && (prevTech || currTech)) {
      const newTech = currentData.technologies.filter((t) => !previousData.technologies.includes(t));
      const removedTech = previousData.technologies.filter((t) => !currentData.technologies.includes(t));
      modifiedSubdomains.push({
        subdomain: name,
        changeType: "tech_changed",
        severity: "medium",
        previousValue: previousData.technologies.join(", ") || "none detected",
        currentValue: currentData.technologies.join(", ") || "none detected",
        description: `Technology stack changed on ${name}: ${newTech.length > 0 ? `added ${newTech.join(", ")}` : ""} ${removedTech.length > 0 ? `removed ${removedTech.join(", ")}` : ""}`.trim(),
        detectedAt: now,
        riskImplication: "Technology changes may introduce new vulnerabilities. Run vulnerability assessment against the updated stack."
      });
    }
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
        riskImplication: "Service changes may indicate software updates, new deployments, or unauthorized modifications."
      });
    }
  }
  const allChanges = [...newSubdomains, ...removedSubdomains, ...modifiedSubdomains];
  const criticalChanges = allChanges.filter((c) => c.severity === "critical").length;
  const highChanges = allChanges.filter((c) => c.severity === "high").length;
  const summary = allChanges.length === 0 ? "No changes detected between scans." : `Detected ${allChanges.length} change(s): ${newSubdomains.length} new subdomain(s), ${removedSubdomains.length} removed, ${modifiedSubdomains.length} modification(s). ${criticalChanges} critical, ${highChanges} high severity.`;
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
    summary
  };
}
var KNOWN_TECH_CVES = [
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
  { technology: "Envoy", matchPattern: /^envoy$/i, cveId: "CVE-2024-23326", cvssScore: 7.5, severity: "high", description: "Envoy: Crash due to malformed HTTP/2 metadata", affectedVersions: "< 1.29.1", fixedVersion: "1.29.1", exploitAvailable: false, publishedDate: "2024-02-09", references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-23326"] }
];
function compareVersions(detected, constraint) {
  const parseVer = (v) => {
    return v.replace(/^[v=<>!~^]+/, "").split(".").map((n) => parseInt(n) || 0);
  };
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
  if (!constraint.includes("-") && !constraint.includes("<") && !constraint.includes(">")) {
    return detected === constraint;
  }
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
      if (d > l) {
        aboveLow = true;
        break;
      }
      if (d < l) {
        aboveLow = false;
        break;
      }
      if (i === Math.max(low.length, det.length) - 1) aboveLow = true;
    }
    for (let i = 0; i < Math.max(high.length, det.length); i++) {
      const h = high[i] || 0;
      const d = det[i] || 0;
      if (d < h) {
        belowHigh = true;
        break;
      }
      if (d > h) {
        belowHigh = false;
        break;
      }
      if (i === Math.max(high.length, det.length) - 1) belowHigh = true;
    }
    return aboveLow && belowHigh;
  }
  return false;
}
function crossReferenceTechVulnerabilities(assets, pipelineOutput) {
  const vulnerabilities = [];
  const techAssetMap = /* @__PURE__ */ new Map();
  for (const asset of assets) {
    const hostname = asset.hostname || "unknown";
    const techs = typeof asset.technologies === "string" ? JSON.parse(asset.technologies) : asset.technologies;
    const techVersions = typeof asset.technologyVersions === "string" ? JSON.parse(asset.technologyVersions) : asset.technologyVersions;
    if (Array.isArray(techs)) {
      for (const tech of techs) {
        const techName = tech.replace(/[\s/]+\d+.*$/, "").trim();
        const version = techVersions?.[tech] || techVersions?.[techName] || extractVersionFromTech(tech);
        const key = `${techName.toLowerCase()}|${version || "unknown"}`;
        const existing = techAssetMap.get(key);
        if (existing) {
          existing.assets.add(hostname);
        } else {
          techAssetMap.set(key, { version: version || "unknown", assets: /* @__PURE__ */ new Set([hostname]) });
        }
      }
    }
  }
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
          techAssetMap.set(key, { version, assets: /* @__PURE__ */ new Set([hostname]) });
        }
      }
    }
  }
  for (const [key, data] of techAssetMap) {
    const [techLower] = key.split("|");
    const { version, assets: affectedHosts } = data;
    for (const cve of KNOWN_TECH_CVES) {
      if (!cve.matchPattern.test(techLower)) continue;
      let isVulnerable = false;
      let versionConfidence = "potential";
      if (version !== "unknown") {
        isVulnerable = compareVersions(version, cve.affectedVersions);
        if (isVulnerable) versionConfidence = "confirmed";
      } else {
        isVulnerable = true;
        versionConfidence = "potential";
      }
      if (isVulnerable) {
        const existingVuln = vulnerabilities.find((v) => v.cveId === cve.cveId && v.technology === cve.technology);
        if (existingVuln) {
          for (const h of affectedHosts) {
            if (!existingVuln.affectedAssets.includes(h)) {
              existingVuln.affectedAssets.push(h);
            }
          }
          if (versionConfidence === "confirmed" && existingVuln.versionConfidence !== "confirmed") {
            existingVuln.versionConfidence = "confirmed";
          }
          continue;
        }
        vulnerabilities.push({
          technology: cve.technology,
          detectedVersion: version,
          cveId: cve.cveId,
          cvssScore: versionConfidence === "potential" ? Math.max(cve.cvssScore - 2, 1) : cve.cvssScore,
          // Reduce score for unconfirmed versions
          severity: versionConfidence === "potential" && cve.severity === "critical" ? "high" : cve.severity,
          // Downgrade critical to high for unconfirmed
          description: cve.description + (versionConfidence === "potential" ? " [Version not confirmed \u2014 potential match only]" : ""),
          affectedVersions: cve.affectedVersions,
          fixedVersion: cve.fixedVersion,
          exploitAvailable: cve.exploitAvailable,
          references: cve.references,
          affectedAssets: [...affectedHosts],
          remediation: `Upgrade ${cve.technology} to version ${cve.fixedVersion} or later. ${cve.exploitAvailable ? "PUBLIC EXPLOIT AVAILABLE \u2014 prioritize immediate patching." : "No public exploit known, but patching is recommended."}`,
          publishedDate: cve.publishedDate,
          versionConfidence
          // Track whether this is a confirmed or potential match
        });
      }
    }
  }
  vulnerabilities.sort((a, b) => b.cvssScore - a.cvssScore);
  const techSummaryMap = /* @__PURE__ */ new Map();
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
        assetCount: vuln.affectedAssets.length
      });
    }
  }
  const technologySummary = [...techSummaryMap.entries()].map(([key, data]) => ({
    technology: key.split("|")[0],
    version: data.version,
    vulnCount: data.vulnCount,
    maxSeverity: data.maxSeverity,
    assetCount: data.assetCount
  })).sort((a, b) => {
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return (sevOrder[a.maxSeverity] ?? 4) - (sevOrder[b.maxSeverity] ?? 4);
  });
  return {
    totalVulnerabilities: vulnerabilities.length,
    criticalCount: vulnerabilities.filter((v) => v.severity === "critical").length,
    highCount: vulnerabilities.filter((v) => v.severity === "high").length,
    mediumCount: vulnerabilities.filter((v) => v.severity === "medium").length,
    lowCount: vulnerabilities.filter((v) => v.severity === "low").length,
    vulnerabilities,
    technologySummary
  };
}
function extractVersionFromTech(tech) {
  const match = tech.match(/[\s/](\d+\.\d+(?:\.\d+)?)/);
  return match ? match[1] : void 0;
}
var TAKEOVER_FINGERPRINTS = [
  {
    service: "Amazon S3",
    serviceCategory: "Cloud Storage",
    cnamePatterns: [/\.s3\.amazonaws\.com$/i, /\.s3-website[.-].*\.amazonaws\.com$/i, /\.s3\..*\.amazonaws\.com$/i],
    httpFingerprints: ["NoSuchBucket", "The specified bucket does not exist"],
    riskLevel: "critical",
    description: "CNAME points to an S3 bucket that may not exist. An attacker can create the bucket and serve malicious content.",
    remediation: "Remove the CNAME record or create the S3 bucket with the expected name. Enable S3 bucket logging and access controls."
  },
  {
    service: "GitHub Pages",
    serviceCategory: "Hosting",
    cnamePatterns: [/\.github\.io$/i, /\.githubusercontent\.com$/i],
    httpFingerprints: ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"],
    riskLevel: "high",
    description: "CNAME points to GitHub Pages but no repository is configured. An attacker can claim this subdomain.",
    remediation: "Remove the CNAME record or configure a GitHub repository with the matching custom domain."
  },
  {
    service: "Heroku",
    serviceCategory: "PaaS",
    cnamePatterns: [/\.herokuapp\.com$/i, /\.herokussl\.com$/i, /\.herokudns\.com$/i],
    httpFingerprints: ["No such app", "no-such-app", "herokucdn.com/error-pages"],
    riskLevel: "critical",
    description: "CNAME points to a Heroku app that no longer exists. An attacker can create an app with this name.",
    remediation: "Remove the CNAME record or recreate the Heroku application with the expected name."
  },
  {
    service: "Azure (App Service / Traffic Manager)",
    serviceCategory: "Cloud",
    cnamePatterns: [/\.azurewebsites\.net$/i, /\.cloudapp\.azure\.com$/i, /\.trafficmanager\.net$/i, /\.azure-api\.net$/i, /\.azurefd\.net$/i],
    httpFingerprints: ["404 Web Site not found", "The resource you are looking for has been removed"],
    riskLevel: "high",
    description: "CNAME points to an Azure resource that may be deprovisioned. Subdomain takeover possible via Azure resource claim.",
    remediation: "Remove the CNAME record or provision the Azure resource. Verify custom domain bindings in Azure portal."
  },
  {
    service: "Netlify",
    serviceCategory: "Hosting",
    cnamePatterns: [/\.netlify\.app$/i, /\.netlify\.com$/i, /\.bitballoon\.com$/i],
    httpFingerprints: ["Not Found - Request ID", "Page not found"],
    riskLevel: "high",
    description: "CNAME points to Netlify but no site is configured for this domain.",
    remediation: "Remove the CNAME record or configure a Netlify site with the matching custom domain."
  },
  {
    service: "Shopify",
    serviceCategory: "E-commerce",
    cnamePatterns: [/\.myshopify\.com$/i],
    httpFingerprints: ["Sorry, this shop is currently unavailable", "Only one step left"],
    riskLevel: "high",
    description: "CNAME points to a Shopify store that may not exist or is unclaimed.",
    remediation: "Remove the CNAME record or configure the Shopify store with the matching custom domain."
  },
  {
    service: "Fastly",
    serviceCategory: "CDN",
    cnamePatterns: [/\.fastly\.net$/i, /\.fastlylb\.net$/i],
    httpFingerprints: ["Fastly error: unknown domain"],
    riskLevel: "high",
    description: "CNAME points to Fastly CDN but no service is configured for this domain.",
    remediation: "Remove the CNAME record or configure the Fastly service with the matching domain."
  },
  {
    service: "Pantheon",
    serviceCategory: "Hosting",
    cnamePatterns: [/\.pantheonsite\.io$/i, /\.pantheon\.io$/i],
    httpFingerprints: ["404 error unknown site", "The gods are wise"],
    riskLevel: "high",
    description: "CNAME points to Pantheon hosting but no site is configured.",
    remediation: "Remove the CNAME record or configure the Pantheon site with the matching domain."
  },
  {
    service: "Zendesk",
    serviceCategory: "SaaS",
    cnamePatterns: [/\.zendesk\.com$/i],
    httpFingerprints: ["Help Center Closed", "Oops, this help center no longer exists"],
    riskLevel: "medium",
    description: "CNAME points to a Zendesk instance that may be deprovisioned.",
    remediation: "Remove the CNAME record or reconfigure the Zendesk help center."
  },
  {
    service: "Surge.sh",
    serviceCategory: "Hosting",
    cnamePatterns: [/\.surge\.sh$/i],
    httpFingerprints: ["project not found"],
    riskLevel: "high",
    description: "CNAME points to Surge.sh but no project is deployed.",
    remediation: "Remove the CNAME record or deploy a project to Surge.sh with the matching domain."
  },
  {
    service: "Fly.io",
    serviceCategory: "PaaS",
    cnamePatterns: [/\.fly\.dev$/i, /\.flycast\.dev$/i],
    httpFingerprints: ["404 Not Found"],
    riskLevel: "high",
    description: "CNAME points to Fly.io but no application is configured.",
    remediation: "Remove the CNAME record or deploy an application to Fly.io with the matching domain."
  },
  {
    service: "Vercel",
    serviceCategory: "Hosting",
    cnamePatterns: [/\.vercel\.app$/i, /\.now\.sh$/i, /cname\.vercel-dns\.com$/i],
    httpFingerprints: ["The deployment could not be found"],
    riskLevel: "high",
    description: "CNAME points to Vercel but no deployment is configured for this domain.",
    remediation: "Remove the CNAME record or configure a Vercel project with the matching custom domain."
  },
  {
    service: "Render",
    serviceCategory: "PaaS",
    cnamePatterns: [/\.onrender\.com$/i],
    httpFingerprints: ["not found"],
    riskLevel: "high",
    description: "CNAME points to Render but no service is configured.",
    remediation: "Remove the CNAME record or deploy a service to Render with the matching domain."
  },
  {
    service: "Cargo Collective",
    serviceCategory: "Hosting",
    cnamePatterns: [/\.cargocollective\.com$/i, /\.cargo\.site$/i],
    httpFingerprints: ["404 Not Found"],
    riskLevel: "medium",
    description: "CNAME points to Cargo Collective but no site is configured.",
    remediation: "Remove the CNAME record or configure the Cargo Collective site."
  }
];
async function detectSubdomainTakeover(assets, pipelineOutput) {
  const candidates = [];
  const checkedSubdomains = /* @__PURE__ */ new Set();
  const subdomainCnames = /* @__PURE__ */ new Map();
  for (const asset of assets) {
    const hostname = asset.hostname?.toLowerCase();
    if (!hostname || checkedSubdomains.has(hostname)) continue;
    checkedSubdomains.add(hostname);
    const dnsRecords = typeof asset.dnsRecords === "string" ? JSON.parse(asset.dnsRecords) : asset.dnsRecords;
    if (dnsRecords?.CNAME && Array.isArray(dnsRecords.CNAME)) {
      subdomainCnames.set(hostname, dnsRecords.CNAME.map((c) => c.toLowerCase()));
    }
  }
  const discoveredSubdomains = pipelineOutput?.discoveredSubdomains;
  if (Array.isArray(discoveredSubdomains)) {
    for (const sub of discoveredSubdomains) {
      const name = (sub.name || sub.subdomain || "").toLowerCase();
      if (!name || checkedSubdomains.has(name)) continue;
      checkedSubdomains.add(name);
      try {
        const cnameRecords = await dns.resolveCname(name).catch(() => []);
        if (cnameRecords.length > 0) {
          subdomainCnames.set(name, cnameRecords.map((c) => c.toLowerCase()));
        }
      } catch {
      }
    }
  }
  for (const [subdomain, cnames] of subdomainCnames) {
    for (const cname of cnames) {
      for (const fingerprint of TAKEOVER_FINGERPRINTS) {
        const matchedPattern = fingerprint.cnamePatterns.find((p) => p.test(cname));
        if (!matchedPattern) continue;
        let targetResolves = true;
        try {
          await dns.resolve4(cname);
        } catch {
          targetResolves = false;
        }
        const status = targetResolves ? "potentially_vulnerable" : "vulnerable";
        const riskLevel = targetResolves ? fingerprint.riskLevel === "critical" ? "high" : fingerprint.riskLevel : fingerprint.riskLevel;
        candidates.push({
          subdomain,
          cnameTarget: cname,
          service: fingerprint.service,
          serviceCategory: fingerprint.serviceCategory,
          riskLevel,
          status,
          evidence: [
            `CNAME record: ${subdomain} \u2192 ${cname}`,
            `Matched service pattern: ${fingerprint.service}`,
            targetResolves ? "CNAME target resolves \u2014 service may still be active but should be verified" : "CNAME target does NOT resolve \u2014 strong indicator of deprovisioned service"
          ],
          description: fingerprint.description,
          remediation: fingerprint.remediation,
          mitreTechnique: "T1584.001 \u2014 Compromise Infrastructure: Domains"
        });
      }
    }
  }
  const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  candidates.sort((a, b) => (riskOrder[a.riskLevel] ?? 4) - (riskOrder[b.riskLevel] ?? 4));
  const vulnerableCount = candidates.filter((c) => c.status === "vulnerable").length;
  const potentiallyVulnerableCount = candidates.filter((c) => c.status === "potentially_vulnerable").length;
  const summary = candidates.length === 0 ? `Checked ${checkedSubdomains.size} subdomains \u2014 no subdomain takeover risks detected.` : `Checked ${checkedSubdomains.size} subdomains \u2014 found ${vulnerableCount} vulnerable and ${potentiallyVulnerableCount} potentially vulnerable to subdomain takeover across ${new Set(candidates.map((c) => c.service)).size} service(s).`;
  return {
    totalChecked: checkedSubdomains.size,
    vulnerableCount,
    potentiallyVulnerableCount,
    candidates,
    summary
  };
}
var CVE_ACTOR_MAP = [
  // Apache CVEs
  { cveId: "CVE-2024-38476", actors: [
    { name: "APT41 (Winnti)", type: "apt", origin: "China", sophistication: "nation-state", campaign: "Web infrastructure exploitation", exploitContext: "SSRF for lateral movement into cloud infrastructure", lastExploited: "2024-Q3" }
  ], attackPhase: "initial_access", mitreTechnique: "T1190 \u2014 Exploit Public-Facing Application" },
  { cveId: "CVE-2021-41773", actors: [
    { name: "APT29 (Cozy Bear)", type: "apt", origin: "Russia", sophistication: "nation-state", campaign: "SolarWinds follow-on operations", exploitContext: "Path traversal for initial foothold on web servers", lastExploited: "2023-Q4" },
    { name: "Lazarus Group", type: "apt", origin: "North Korea", sophistication: "nation-state", campaign: "Cryptocurrency exchange targeting", exploitContext: "Web server exploitation for credential harvesting", lastExploited: "2023-Q2" },
    { name: "LockBit", type: "ransomware", origin: "Russia", sophistication: "advanced", campaign: "Mass exploitation for ransomware deployment", exploitContext: "Automated scanning and exploitation for initial access", lastExploited: "2024-Q1" }
  ], attackPhase: "initial_access", mitreTechnique: "T1190 \u2014 Exploit Public-Facing Application" },
  // OpenSSL CVEs
  { cveId: "CVE-2024-5535", actors: [
    { name: "APT28 (Fancy Bear)", type: "apt", origin: "Russia", sophistication: "nation-state", campaign: "Government infrastructure targeting", exploitContext: "TLS exploitation for man-in-the-middle attacks", lastExploited: "2024-Q3" }
  ], attackPhase: "credential_access", mitreTechnique: "T1557 \u2014 Adversary-in-the-Middle" },
  { cveId: "CVE-2022-3602", actors: [
    { name: "APT28 (Fancy Bear)", type: "apt", origin: "Russia", sophistication: "nation-state", campaign: "European government targeting", exploitContext: "Buffer overflow for remote code execution on TLS servers", lastExploited: "2023-Q1" },
    { name: "Turla", type: "apt", origin: "Russia", sophistication: "nation-state", campaign: "Diplomatic espionage", exploitContext: "Exploiting vulnerable OpenSSL for initial compromise", lastExploited: "2023-Q2" }
  ], attackPhase: "initial_access", mitreTechnique: "T1190 \u2014 Exploit Public-Facing Application" },
  // PHP CVEs
  { cveId: "CVE-2024-4577", actors: [
    { name: "APT41 (Winnti)", type: "apt", origin: "China", sophistication: "nation-state", campaign: "Mass web server exploitation", exploitContext: "CGI argument injection for remote code execution", lastExploited: "2024-Q3" },
    { name: "Cl0p", type: "ransomware", origin: "Russia", sophistication: "advanced", campaign: "Mass exploitation campaigns", exploitContext: "Automated exploitation for ransomware deployment", lastExploited: "2024-Q2" },
    { name: "FIN11", type: "cybercrime", origin: "Russia", sophistication: "advanced", campaign: "Financial data theft", exploitContext: "PHP RCE for web shell deployment and data exfiltration", lastExploited: "2024-Q3" }
  ], attackPhase: "initial_access", mitreTechnique: "T1190 \u2014 Exploit Public-Facing Application" },
  // WordPress CVEs
  { cveId: "CVE-2024-2879", actors: [
    { name: "Magecart", type: "cybercrime", origin: "Various", sophistication: "intermediate", campaign: "E-commerce skimming", exploitContext: "SQL injection for payment data theft", lastExploited: "2024-Q2" }
  ], attackPhase: "collection", mitreTechnique: "T1213 \u2014 Data from Information Repositories" },
  { cveId: "CVE-2023-2982", actors: [
    { name: "FIN7", type: "cybercrime", origin: "Russia", sophistication: "advanced", campaign: "Web application compromise", exploitContext: "Authentication bypass for admin access and web shell deployment", lastExploited: "2024-Q1" }
  ], attackPhase: "initial_access", mitreTechnique: "T1078 \u2014 Valid Accounts" },
  // jQuery CVEs
  { cveId: "CVE-2020-11022", actors: [
    { name: "Magecart", type: "cybercrime", origin: "Various", sophistication: "intermediate", campaign: "Web skimming campaigns", exploitContext: "XSS via jQuery for injecting payment skimmers", lastExploited: "2023-Q4" }
  ], attackPhase: "execution", mitreTechnique: "T1059.007 \u2014 JavaScript" },
  // Log4j
  { cveId: "CVE-2021-44228", actors: [
    { name: "APT41 (Winnti)", type: "apt", origin: "China", sophistication: "nation-state", campaign: "Mass exploitation within hours of disclosure", exploitContext: "Log4Shell for initial access and lateral movement", lastExploited: "2024-Q2" },
    { name: "APT29 (Cozy Bear)", type: "apt", origin: "Russia", sophistication: "nation-state", campaign: "Government and enterprise targeting", exploitContext: "Log4Shell exploitation for persistent access", lastExploited: "2024-Q1" },
    { name: "Lazarus Group", type: "apt", origin: "North Korea", sophistication: "nation-state", campaign: "Cryptocurrency and financial targeting", exploitContext: "Log4Shell for deploying crypto miners and backdoors", lastExploited: "2024-Q1" },
    { name: "Conti", type: "ransomware", origin: "Russia", sophistication: "advanced", campaign: "Ransomware deployment via Log4Shell", exploitContext: "Automated mass exploitation for ransomware delivery", lastExploited: "2023-Q1" },
    { name: "LockBit", type: "ransomware", origin: "Russia", sophistication: "advanced", campaign: "Enterprise ransomware campaigns", exploitContext: "Log4Shell as initial access vector for ransomware", lastExploited: "2024-Q1" }
  ], attackPhase: "initial_access", mitreTechnique: "T1190 \u2014 Exploit Public-Facing Application" },
  // Nginx CVEs
  { cveId: "CVE-2022-41741", actors: [
    { name: "APT28 (Fancy Bear)", type: "apt", origin: "Russia", sophistication: "nation-state", campaign: "Web infrastructure exploitation", exploitContext: "Memory corruption for code execution on web servers", lastExploited: "2023-Q2" }
  ], attackPhase: "initial_access", mitreTechnique: "T1190 \u2014 Exploit Public-Facing Application" },
  // Microsoft Exchange
  { cveId: "CVE-2023-36745", actors: [
    { name: "Hafnium", type: "apt", origin: "China", sophistication: "nation-state", campaign: "Exchange server exploitation", exploitContext: "RCE on Exchange for email access and lateral movement", lastExploited: "2024-Q1" },
    { name: "APT29 (Cozy Bear)", type: "apt", origin: "Russia", sophistication: "nation-state", campaign: "Government email compromise", exploitContext: "Exchange exploitation for intelligence collection", lastExploited: "2024-Q1" }
  ], attackPhase: "initial_access", mitreTechnique: "T1190 \u2014 Exploit Public-Facing Application" },
  // Spring Framework
  { cveId: "CVE-2022-22965", actors: [
    { name: "APT41 (Winnti)", type: "apt", origin: "China", sophistication: "nation-state", campaign: "Spring4Shell exploitation", exploitContext: "RCE via Spring parameter binding for web shell deployment", lastExploited: "2023-Q4" },
    { name: "Mirai Botnet Operators", type: "cybercrime", origin: "Various", sophistication: "intermediate", campaign: "IoT/server botnet recruitment", exploitContext: "Automated exploitation for botnet enrollment", lastExploited: "2023-Q3" }
  ], attackPhase: "initial_access", mitreTechnique: "T1190 \u2014 Exploit Public-Facing Application" }
];
var CISA_KEV_CVES = /* @__PURE__ */ new Set([
  "CVE-2021-44228",
  // Log4Shell
  "CVE-2021-41773",
  // Apache path traversal
  "CVE-2024-4577",
  // PHP CGI argument injection
  "CVE-2022-22965",
  // Spring4Shell
  "CVE-2022-3602",
  // OpenSSL buffer overflow
  "CVE-2024-38476",
  // Apache SSRF
  "CVE-2023-36745",
  // Exchange RCE
  "CVE-2022-41741",
  // Nginx memory corruption
  "CVE-2024-5535",
  // OpenSSL buffer overread
  "CVE-2023-3824",
  // PHP buffer overflow
  "CVE-2024-31210",
  // WordPress RCE
  "CVE-2020-11022",
  // jQuery XSS
  "CVE-2020-11023",
  // jQuery XSS
  "CVE-2019-11358",
  // jQuery prototype pollution
  "CVE-2023-36899",
  // IIS elevation of privilege
  "CVE-2024-2879",
  // WordPress SQL injection
  "CVE-2023-2982"
  // WordPress auth bypass
]);
function calculatePriorityScore(opts) {
  const cvssComponent = Math.min(opts.cvssScore / 10 * 30, 30);
  let actorComponent = Math.min(opts.actorCount * 4, 15);
  if (opts.hasNationState) actorComponent += 6;
  if (opts.hasRansomware) actorComponent += 4;
  actorComponent = Math.min(actorComponent, 25);
  const activeComponent = opts.activelyExploited ? 20 : 0;
  const kevComponent = opts.cisaKev ? 15 : 0;
  const exploitComponent = opts.exploitAvailable ? 10 : 0;
  return Math.min(Math.round(cvssComponent + actorComponent + activeComponent + kevComponent + exploitComponent), 100);
}
function getRemediationUrgency(priorityScore) {
  if (priorityScore >= 80) return "immediate";
  if (priorityScore >= 60) return "urgent";
  if (priorityScore >= 40) return "scheduled";
  return "routine";
}
async function enrichCvesWithThreatActors(techVulnResult) {
  const enrichedCves = [];
  const allActorNames = /* @__PURE__ */ new Set();
  const actorTypeCount = /* @__PURE__ */ new Map();
  let dbActors = [];
  try {
    const dbModule = await import("./db-GNA5CL3K.js");
    const dbResult = await dbModule.listThreatActors({ limit: 500 });
    dbActors = dbResult?.actors || [];
  } catch {
  }
  for (const vuln of techVulnResult.vulnerabilities) {
    const staticMapping = CVE_ACTOR_MAP.find((m) => m.cveId === vuln.cveId);
    const dbMatchedActors = [];
    for (const actor of dbActors) {
      const techniques = parseTechniquesJson(actor.techniques);
      const relevantTechniques = techniques.filter((t) => {
        const tid = (t.id || "").toLowerCase();
        return tid === "t1190" || tid === "t1210" || tid === "t1133" || tid === "t1078" || tid === "t1059" || tid === "t1203";
      });
      if (relevantTechniques.length > 0 && actor.threatLevel === "critical") {
        const alreadyInStatic = staticMapping?.actors.some(
          (a) => a.name.toLowerCase().includes(actor.name.toLowerCase()) || actor.name.toLowerCase().includes(a.name.split(" ")[0].toLowerCase())
        );
        if (!alreadyInStatic) {
          dbMatchedActors.push({
            name: actor.name,
            type: actor.type || "unknown",
            origin: actor.origin || "Unknown",
            sophistication: actor.sophistication || "intermediate",
            campaign: `Known to use ${relevantTechniques.map((t) => t.id).join(", ")} techniques`,
            exploitContext: `Threat actor with ${relevantTechniques.length} relevant exploitation techniques in their arsenal`,
            lastExploited: actor.lastActive || "Unknown"
          });
        }
      }
    }
    const allActors = [
      ...staticMapping?.actors || [],
      ...dbMatchedActors
    ];
    if (allActors.length > 0) {
      const hasNationState = allActors.some((a) => a.sophistication === "nation-state");
      const hasRansomware = allActors.some((a) => a.type === "ransomware");
      const hasAdvanced = allActors.some((a) => a.sophistication === "advanced");
      const threatLevel = hasNationState ? "critical" : hasRansomware ? "critical" : hasAdvanced ? "high" : "medium";
      const activelyExploited = allActors.some((a) => {
        const lastQ = a.lastExploited;
        return lastQ.includes("2024") || lastQ.includes("2025") || lastQ.includes("2026");
      });
      const cisaKev = CISA_KEV_CVES.has(vuln.cveId);
      const exploitAvailable = vuln.exploitAvailable;
      const priorityScore = calculatePriorityScore({
        cvssScore: vuln.cvssScore,
        actorCount: allActors.length,
        hasNationState,
        hasRansomware,
        activelyExploited,
        cisaKev,
        exploitAvailable
      });
      enrichedCves.push({
        cveId: vuln.cveId,
        technology: vuln.technology,
        cvssScore: vuln.cvssScore,
        severity: vuln.severity,
        actors: allActors,
        attackPhase: staticMapping?.attackPhase || "initial_access",
        mitreTechnique: staticMapping?.mitreTechnique || "T1190 \u2014 Exploit Public-Facing Application",
        threatLevel,
        activelyExploited,
        priorityScore,
        exploitAvailable,
        cisaKev,
        description: vuln.description,
        affectedAssets: vuln.affectedAssets || [],
        remediationUrgency: getRemediationUrgency(priorityScore)
      });
      for (const actor of allActors) {
        allActorNames.add(actor.name);
        actorTypeCount.set(actor.type, (actorTypeCount.get(actor.type) || 0) + 1);
      }
    }
  }
  enrichedCves.sort((a, b) => b.priorityScore - a.priorityScore);
  const actorTypeSummary = [...actorTypeCount.entries()].map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count);
  const severitySummary = {
    critical: enrichedCves.filter((e) => e.severity === "critical").length,
    high: enrichedCves.filter((e) => e.severity === "high").length,
    medium: enrichedCves.filter((e) => e.severity === "medium").length,
    low: enrichedCves.filter((e) => e.severity === "low").length
  };
  const activelyExploitedCount = enrichedCves.filter((e) => e.activelyExploited).length;
  const cisaKevCount = enrichedCves.filter((e) => e.cisaKev).length;
  const exploitAvailableCount = enrichedCves.filter((e) => e.exploitAvailable).length;
  const averagePriorityScore = enrichedCves.length > 0 ? Math.round(enrichedCves.reduce((sum, e) => sum + e.priorityScore, 0) / enrichedCves.length) : 0;
  const nationStateCount = enrichedCves.filter((e) => e.actors.some((a) => a.sophistication === "nation-state")).length;
  const ransomwareCount = enrichedCves.filter((e) => e.actors.some((a) => a.type === "ransomware")).length;
  let riskElevation = "No threat actor correlations found \u2014 CVEs are known but not linked to active campaigns.";
  if (enrichedCves.length > 0) {
    const parts = [];
    if (nationStateCount > 0) parts.push(`${nationStateCount} CVE(s) exploited by nation-state actors`);
    if (ransomwareCount > 0) parts.push(`${ransomwareCount} CVE(s) used in ransomware campaigns`);
    if (activelyExploitedCount > 0) parts.push(`${activelyExploitedCount} CVE(s) actively exploited in 2024-2026`);
    if (cisaKevCount > 0) parts.push(`${cisaKevCount} CVE(s) in CISA KEV catalog`);
    riskElevation = `ELEVATED RISK: ${parts.join("; ")}. ${allActorNames.size} unique threat actor(s) linked. Average priority score: ${averagePriorityScore}/100.`;
  }
  const topPriorityCves = enrichedCves.slice(0, 5);
  return {
    totalCvesEnriched: enrichedCves.length,
    totalActorsLinked: allActorNames.size,
    uniqueActors: [...allActorNames].sort(),
    actorTypeSummary,
    enrichedCves,
    riskElevation,
    severitySummary,
    activelyExploitedCount,
    cisaKevCount,
    exploitAvailableCount,
    averagePriorityScore,
    topPriorityCves
  };
}
function parseTechniquesJson(raw) {
  if (!raw) return [];
  let arr;
  if (typeof raw === "string") {
    try {
      arr = JSON.parse(raw);
    } catch {
      return [];
    }
  } else if (Array.isArray(raw)) {
    arr = raw;
  } else {
    return [];
  }
  return arr.filter((t) => t && typeof t === "object" && t.id);
}
async function validateTakeoverCandidates(candidates) {
  const results = [];
  for (const candidate of candidates) {
    const result = await validateSingleCandidate(candidate);
    results.push(result);
  }
  results.sort((a, b) => b.confidence - a.confidence);
  const confirmedCount = results.filter((r) => r.validationStatus === "confirmed").length;
  const likelyCount = results.filter((r) => r.validationStatus === "likely").length;
  const possibleCount = results.filter((r) => r.validationStatus === "possible").length;
  const unlikelyCount = results.filter((r) => r.validationStatus === "unlikely").length;
  const errorCount = results.filter((r) => r.validationStatus === "error").length;
  const summary = results.length === 0 ? "No takeover candidates to validate." : `Validated ${results.length} candidate(s): ${confirmedCount} confirmed, ${likelyCount} likely, ${possibleCount} possible, ${unlikelyCount} unlikely${errorCount > 0 ? `, ${errorCount} error(s)` : ""}.`;
  return {
    totalValidated: results.length,
    confirmedCount,
    likelyCount,
    possibleCount,
    unlikelyCount,
    errorCount,
    results,
    summary
  };
}
async function validateSingleCandidate(candidate) {
  const result = {
    subdomain: candidate.subdomain,
    cnameTarget: candidate.cnameTarget,
    service: candidate.service,
    validationStatus: "possible",
    httpStatusCode: null,
    responseContainsFingerprint: false,
    fingerprintMatched: null,
    dnsResolves: false,
    responseSnippet: null,
    confidence: 0,
    validatedAt: Date.now(),
    validationMethod: "http_probe",
    exploitabilityNote: ""
  };
  try {
    await dns.resolve4(candidate.subdomain);
    result.dnsResolves = true;
  } catch {
    result.dnsResolves = false;
  }
  let cnameResolves = false;
  try {
    await dns.resolve4(candidate.cnameTarget);
    cnameResolves = true;
  } catch {
    cnameResolves = false;
  }
  const fingerprint = TAKEOVER_FINGERPRINTS.find((f) => f.service === candidate.service);
  const httpFingerprints = fingerprint?.httpFingerprints || [];
  try {
    const httpResult = await probeHttp(candidate.subdomain);
    result.httpStatusCode = httpResult.statusCode;
    result.responseSnippet = httpResult.body?.substring(0, 500) || null;
    if (httpResult.body) {
      for (const fp of httpFingerprints) {
        if (httpResult.body.includes(fp)) {
          result.responseContainsFingerprint = true;
          result.fingerprintMatched = fp;
          break;
        }
      }
    }
  } catch (err) {
    result.responseSnippet = `HTTP probe failed: ${err.message}`;
  }
  if (result.responseContainsFingerprint && !cnameResolves) {
    result.validationStatus = "confirmed";
    result.confidence = 95;
    result.exploitabilityNote = `CONFIRMED: CNAME target does not resolve and HTTP response contains "${result.fingerprintMatched}" \u2014 this subdomain can be claimed by registering the ${candidate.service} resource.`;
  } else if (result.responseContainsFingerprint && cnameResolves) {
    result.validationStatus = "likely";
    result.confidence = 80;
    result.exploitabilityNote = `LIKELY: HTTP response contains "${result.fingerprintMatched}" indicating the ${candidate.service} resource is unclaimed, though CNAME still resolves (may be cached).`;
  } else if (!cnameResolves && !result.dnsResolves) {
    result.validationStatus = "likely";
    result.confidence = 75;
    result.exploitabilityNote = `LIKELY: Both subdomain and CNAME target fail DNS resolution \u2014 the ${candidate.service} resource appears fully deprovisioned and claimable.`;
  } else if (!cnameResolves && result.dnsResolves) {
    result.validationStatus = "possible";
    result.confidence = 50;
    result.exploitabilityNote = `POSSIBLE: CNAME target does not resolve but subdomain has other DNS records. The ${candidate.service} resource may be claimable but additional records complicate exploitation.`;
  } else if (result.httpStatusCode && result.httpStatusCode >= 400 && result.httpStatusCode < 500) {
    result.validationStatus = "possible";
    result.confidence = 40;
    result.exploitabilityNote = `POSSIBLE: HTTP ${result.httpStatusCode} response without provider-specific error page. The ${candidate.service} resource may be misconfigured but not necessarily claimable.`;
  } else if (result.httpStatusCode && result.httpStatusCode >= 200 && result.httpStatusCode < 300) {
    result.validationStatus = "unlikely";
    result.confidence = 15;
    result.exploitabilityNote = `UNLIKELY: HTTP ${result.httpStatusCode} response indicates the ${candidate.service} resource is active and serving content.`;
  } else {
    result.validationStatus = "possible";
    result.confidence = 30;
    result.exploitabilityNote = `POSSIBLE: Unable to definitively determine exploitability. Manual verification recommended for ${candidate.service}.`;
  }
  return result;
}
function probeHttp(hostname) {
  return new Promise((resolve, reject) => {
    const timeout = 8e3;
    const httpsReq = https.get(`https://${hostname}`, {
      timeout,
      rejectUnauthorized: false,
      // Accept self-signed certs
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; AC3-TakeoverValidator/1.0)",
        "Accept": "text/html,application/xhtml+xml,*/*"
      }
    }, (res) => {
      let body = "";
      res.on("data", (chunk) => {
        body += chunk;
        if (body.length > 2e3) res.destroy();
      });
      res.on("end", () => resolve({ statusCode: res.statusCode || 0, body }));
      res.on("error", () => resolve({ statusCode: res.statusCode || 0, body }));
    });
    httpsReq.on("error", () => {
      const httpReq = http.get(`http://${hostname}`, {
        timeout,
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; AC3-TakeoverValidator/1.0)",
          "Accept": "text/html,application/xhtml+xml,*/*"
        }
      }, (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk;
          if (body.length > 2e3) res.destroy();
        });
        res.on("end", () => resolve({ statusCode: res.statusCode || 0, body }));
        res.on("error", () => resolve({ statusCode: res.statusCode || 0, body }));
      });
      httpReq.on("error", (err) => reject(err));
      httpReq.on("timeout", () => {
        httpReq.destroy();
        reject(new Error("HTTP request timeout"));
      });
    });
    httpsReq.on("timeout", () => {
      httpsReq.destroy();
      const httpReq = http.get(`http://${hostname}`, {
        timeout,
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; AC3-TakeoverValidator/1.0)",
          "Accept": "text/html,application/xhtml+xml,*/*"
        }
      }, (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk;
          if (body.length > 2e3) res.destroy();
        });
        res.on("end", () => resolve({ statusCode: res.statusCode || 0, body }));
        res.on("error", () => resolve({ statusCode: res.statusCode || 0, body }));
      });
      httpReq.on("error", (err) => reject(err));
      httpReq.on("timeout", () => {
        httpReq.destroy();
        reject(new Error("HTTP request timeout"));
      });
    });
  });
}
export {
  calculatePriorityScore,
  crossReferenceTechVulnerabilities,
  detectSubdomainChanges,
  detectSubdomainTakeover,
  enrichCvesWithThreatActors,
  validateTakeoverCandidates
};
