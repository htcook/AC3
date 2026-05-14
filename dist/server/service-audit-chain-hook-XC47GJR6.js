import "./chunk-KFQGP6VL.js";

// server/lib/service-audit-chain-hook.ts
function extractServicesFromScanForge(discoveryOutput) {
  if (!discoveryOutput) return [];
  const services = [];
  const PORT_SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    161: "snmp",
    162: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtp",
    587: "smtp",
    993: "imap",
    995: "pop3",
    1433: "mssql",
    1521: "oracle",
    2222: "ssh",
    2525: "smtp",
    3e3: "http",
    3306: "mysql",
    3388: "rdp",
    3389: "rdp",
    5e3: "http",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8e3: "http",
    8080: "http",
    8443: "https",
    8888: "http",
    9090: "http",
    27017: "mongodb"
  };
  function processHost(host) {
    const ip = host.ip || host.host || host.hostname;
    if (!ip) return;
    const ports = host.ports || [];
    for (const p of ports) {
      if (!p.port) continue;
      if (p.state && p.state !== "open") continue;
      const serviceName = p.service || PORT_SERVICE_MAP[p.port] || "unknown";
      const banner = [p.product, p.version, p.extraInfo].filter(Boolean).join(" ") || void 0;
      services.push({
        host: ip,
        port: p.port,
        service: serviceName,
        banner,
        protocol: p.protocol || "tcp"
      });
    }
  }
  if (Array.isArray(discoveryOutput)) {
    for (const host of discoveryOutput) {
      processHost(host);
    }
  }
  if (discoveryOutput.hosts && Array.isArray(discoveryOutput.hosts)) {
    for (const host of discoveryOutput.hosts) {
      processHost(host);
    }
  }
  return services;
}
function convertServiceAuditFindings(results, phase = "vulnerability_assessment") {
  const findings = [];
  const scannerTypes = ["ssh", "ftp", "smtp", "snmp", "rdp", "nikto", "wapiti", "arachni"];
  for (const scannerType of scannerTypes) {
    const scannerResults = results[scannerType];
    if (!Array.isArray(scannerResults)) continue;
    for (const result of scannerResults) {
      if (!result.findings || !Array.isArray(result.findings)) continue;
      for (const finding of result.findings) {
        findings.push({
          id: `service-audit-${scannerType}-${findings.length}`,
          type: finding.cve ? "vulnerability" : "misconfiguration",
          severity: finding.severity || "info",
          title: finding.title || `${scannerType.toUpperCase()} Finding`,
          description: finding.description || "",
          tool: `service_audit_${scannerType}`,
          phase,
          timestamp: Date.now(),
          cveId: finding.cve || void 0,
          evidence: {
            scanner: scannerType,
            category: finding.category,
            recommendation: finding.recommendation,
            cwe: finding.cwe,
            rawEvidence: finding.evidence,
            host: result.host,
            port: result.port
          }
        });
      }
    }
  }
  return findings;
}
export {
  convertServiceAuditFindings,
  extractServicesFromScanForge
};
