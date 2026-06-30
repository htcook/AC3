/**
 * Service Audit Chain Hook
 *
 * Extracts discovered services from ScanForge discovery stage output and converts them
 * into the format expected by the service audit pipeline.
 * Used as Stage 5 in the discovery chain.
 */

import type { DiscoveredService } from "./scanners/service-audit-pipeline";

/**
 * Extract discovered services from ScanForge discovery raw output for the service audit pipeline.
 * Maps open ports to service names using ScanForge service detection + port heuristics.
 */
export function extractServicesFromScanForge(
  discoveryOutput: any
): DiscoveredService[] {
  if (!discoveryOutput) return [];

  const services: DiscoveredService[] = [];

  const PORT_SERVICE_MAP: Record<number, string> = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 143: "imap",
    161: "snmp", 162: "snmp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtp", 587: "smtp", 993: "imap",
    995: "pop3", 1433: "mssql", 1521: "oracle", 2222: "ssh",
    2525: "smtp", 3000: "http", 3306: "mysql", 3388: "rdp",
    3389: "rdp", 5000: "http", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8000: "http", 8080: "http", 8443: "https",
    8888: "http", 9090: "http", 27017: "mongodb",
  };

  function processHost(host: any) {
    const ip = host.ip || host.host || host.hostname;
    if (!ip) return;

    const ports = host.ports || [];
    for (const p of ports) {
      if (!p.port) continue;
      // Only process open ports
      if (p.state && p.state !== "open") continue;

      const serviceName = p.service || PORT_SERVICE_MAP[p.port] || "unknown";
      const banner = [p.product, p.version, p.extraInfo].filter(Boolean).join(" ") || undefined;

      services.push({
        host: ip,
        port: p.port,
        service: serviceName,
        banner,
        protocol: p.protocol || "tcp",
      });
    }
  }

  // Handle array format (toScanForgeRawResults)
  if (Array.isArray(discoveryOutput)) {
    for (const host of discoveryOutput) {
      processHost(host);
    }
  }

  // Handle ScanForgeScanResult format
  if (discoveryOutput.hosts && Array.isArray(discoveryOutput.hosts)) {
    for (const host of discoveryOutput.hosts) {
      processHost(host);
    }
  }

  return services;
}

/**
 * Convert service audit findings to PipelineFinding format
 * for integration with the discovery chain's allFindings aggregation.
 */
export function convertServiceAuditFindings(
  results: any,
  phase: string = "vulnerability_assessment"
): Array<{
  id: string;
  type: string;
  severity: string;
  title: string;
  description: string;
  tool: string;
  phase: string;
  timestamp: number;
  cveId?: string;
  evidence?: Record<string, any>;
}> {
  const findings: any[] = [];
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
          tool: `service_audit_${scannerType}` as any,
          phase,
          timestamp: Date.now(),
          cveId: finding.cve || undefined,
          evidence: {
            scanner: scannerType,
            category: finding.category,
            recommendation: finding.recommendation,
            cwe: finding.cwe,
            rawEvidence: finding.evidence,
            host: result.host,
            port: result.port,
          },
        });
      }
    }
  }

  return findings;
}
