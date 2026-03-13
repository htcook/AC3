/**
 * Service Audit Pipeline
 *
 * Automated service-specific vulnerability follow-up after port discovery.
 * When naabu/nmap discovers open ports, this pipeline automatically triggers
 * the appropriate audit module:
 *
 *   Port 21 (FTP)  → FTP Audit (anonymous login, bounce, CVEs, creds)
 *   Port 22 (SSH)  → SSH Audit (weak algos, CVEs, auth methods)
 *   Port 80/443    → Nikto + Wapiti + Arachni (web server + injection testing)
 *   Port 8080/8443 → Nikto (web server checks)
 *
 * Architecture:
 *   Port Discovery (naabu/nmap) → this pipeline → scanner modules → scan_results
 *
 * The pipeline:
 *   1. Receives discovered services (host, port, service name)
 *   2. Maps services to appropriate audit modules
 *   3. Executes audits in parallel (respecting concurrency limits)
 *   4. Aggregates results and stores in scan_results
 *   5. Emits WebSocket events for real-time dashboard updates
 */

import { startSSHAudit, type SSHAuditResult } from "./ssh-audit-scanner";
import { startFTPAudit, type FTPAuditResult } from "./ftp-audit-scanner";
import { startNiktoScan, type NiktoScanResult } from "./nikto-scanner";
import { startWapitiScan, type WapitiScanResult } from "./wapiti-scanner";
import { startArachniScan, type ArachniScanResult } from "./arachni-scanner";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface DiscoveredService {
  host: string;
  port: number;
  service: string;
  banner?: string;
  protocol?: string;
}

export interface ServiceAuditConfig {
  /** Engagement ID for audit trail */
  engagementId: number;
  /** Operator ID */
  operatorId?: number;
  /** Max concurrent audits */
  concurrency?: number;
  /** Global timeout per audit in seconds */
  timeoutPerAudit?: number;
  /** Which scanner types to enable */
  enabledScanners?: {
    ssh?: boolean;
    ftp?: boolean;
    nikto?: boolean;
    wapiti?: boolean;
    arachni?: boolean;
  };
  /** Scan profile (affects depth/speed) */
  profile?: "quick" | "standard" | "deep";
  /** WebSocket event emitter for real-time updates */
  onEvent?: (event: ServiceAuditEvent) => void;
}

export interface ServiceAuditEvent {
  type: "audit_started" | "audit_completed" | "audit_error" | "pipeline_completed";
  service: DiscoveredService;
  scanner: string;
  result?: any;
  error?: string;
  timestamp: number;
}

export interface ServiceAuditPipelineResult {
  totalServices: number;
  auditsTriggered: number;
  auditsCompleted: number;
  auditsFailed: number;
  results: {
    ssh: SSHAuditResult[];
    ftp: FTPAuditResult[];
    nikto: NiktoScanResult[];
    wapiti: WapitiScanResult[];
    arachni: ArachniScanResult[];
  };
  totalFindings: number;
  severitySummary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  durationSeconds: number;
}

// ─── Service → Scanner Mapping ──────────────────────────────────────────────

interface ScannerMapping {
  scanners: string[];
  description: string;
}

const SERVICE_SCANNER_MAP: Record<string, ScannerMapping> = {
  ssh: { scanners: ["ssh-audit"], description: "SSH security audit" },
  ftp: { scanners: ["ftp-audit"], description: "FTP security audit" },
  http: { scanners: ["nikto", "wapiti"], description: "Web server + injection testing" },
  https: { scanners: ["nikto", "wapiti"], description: "Web server + injection testing (TLS)" },
  "http-proxy": { scanners: ["nikto"], description: "HTTP proxy audit" },
  "http-alt": { scanners: ["nikto"], description: "Alternate HTTP audit" },
};

const PORT_SCANNER_MAP: Record<number, ScannerMapping> = {
  21: { scanners: ["ftp-audit"], description: "FTP audit" },
  22: { scanners: ["ssh-audit"], description: "SSH audit" },
  2222: { scanners: ["ssh-audit"], description: "SSH audit (alt port)" },
  80: { scanners: ["nikto", "wapiti"], description: "HTTP web audit" },
  443: { scanners: ["nikto", "wapiti"], description: "HTTPS web audit" },
  8080: { scanners: ["nikto"], description: "HTTP alt web audit" },
  8443: { scanners: ["nikto"], description: "HTTPS alt web audit" },
  3000: { scanners: ["nikto"], description: "Dev server audit" },
  5000: { scanners: ["nikto"], description: "Dev server audit" },
  8000: { scanners: ["nikto"], description: "Dev server audit" },
  8888: { scanners: ["nikto"], description: "Dev server audit" },
  9090: { scanners: ["nikto"], description: "Admin panel audit" },
};

/**
 * Determine which scanners to run for a discovered service.
 */
function getScannersForService(service: DiscoveredService, enabled: ServiceAuditConfig["enabledScanners"]): string[] {
  const scanners = new Set<string>();

  // Match by service name
  const serviceLower = service.service?.toLowerCase() || "";
  for (const [svcName, mapping] of Object.entries(SERVICE_SCANNER_MAP)) {
    if (serviceLower.includes(svcName)) {
      for (const s of mapping.scanners) scanners.add(s);
    }
  }

  // Match by port number
  const portMapping = PORT_SCANNER_MAP[service.port];
  if (portMapping) {
    for (const s of portMapping.scanners) scanners.add(s);
  }

  // Filter by enabled scanners
  const enabledMap: Record<string, boolean> = {
    "ssh-audit": enabled?.ssh !== false,
    "ftp-audit": enabled?.ftp !== false,
    nikto: enabled?.nikto !== false,
    wapiti: enabled?.wapiti !== false,
    arachni: enabled?.arachni !== false,
  };

  return Array.from(scanners).filter(s => enabledMap[s] !== false);
}

// ─── Pipeline Execution ─────────────────────────────────────────────────────

/**
 * Run a single scanner against a service.
 */
async function runScanner(
  scanner: string,
  service: DiscoveredService,
  config: ServiceAuditConfig,
): Promise<{ scanner: string; result: any; error?: string }> {
  const timeout = config.timeoutPerAudit || 300;
  const isHttps = service.service?.toLowerCase().includes("https") || service.port === 443 || service.port === 8443;
  const protocol = isHttps ? "https" : "http";
  const targetUrl = `${protocol}://${service.host}:${service.port}`;

  try {
    switch (scanner) {
      case "ssh-audit": {
        const result = await startSSHAudit({
          host: service.host,
          port: service.port,
          engagementId: config.engagementId,
          operatorId: config.operatorId,
          timeoutSeconds: timeout,
        });
        return { scanner, result };
      }

      case "ftp-audit": {
        const result = await startFTPAudit({
          host: service.host,
          port: service.port,
          engagementId: config.engagementId,
          operatorId: config.operatorId,
          timeoutSeconds: timeout,
        });
        return { scanner, result };
      }

      case "nikto": {
        const result = await startNiktoScan({
          targetUrl,
          engagementId: config.engagementId,
          operatorId: config.operatorId,
          timeoutSeconds: timeout,
          ssl: isHttps,
          port: service.port,
          tuning: config.profile === "quick" ? "1234" : config.profile === "deep" ? "123456789" : "12345",
        });
        return { scanner, result };
      }

      case "wapiti": {
        const result = await startWapitiScan({
          targetUrl,
          engagementId: config.engagementId,
          operatorId: config.operatorId,
          timeoutSeconds: timeout,
          scope: config.profile === "quick" ? "page" : config.profile === "deep" ? "domain" : "folder",
          maxDepth: config.profile === "quick" ? 2 : config.profile === "deep" ? 10 : 5,
          modules: config.profile === "quick" ? "sql,xss,exec" : undefined,
        });
        return { scanner, result };
      }

      case "arachni": {
        const result = await startArachniScan({
          targetUrl,
          engagementId: config.engagementId,
          operatorId: config.operatorId,
          timeoutSeconds: timeout,
          maxPages: config.profile === "quick" ? 20 : config.profile === "deep" ? 500 : 100,
          maxDepth: config.profile === "quick" ? 2 : config.profile === "deep" ? 10 : 5,
        });
        return { scanner, result };
      }

      default:
        return { scanner, result: null, error: `Unknown scanner: ${scanner}` };
    }
  } catch (err: any) {
    return { scanner, result: null, error: err.message };
  }
}

/**
 * Execute the full service audit pipeline.
 *
 * Takes a list of discovered services and runs appropriate scanners against each.
 * Respects concurrency limits and emits real-time events.
 */
export async function runServiceAuditPipeline(
  services: DiscoveredService[],
  config: ServiceAuditConfig,
): Promise<ServiceAuditPipelineResult> {
  const startTime = Date.now();
  const concurrency = config.concurrency || 3;
  const emit = config.onEvent || (() => {});

  const results: ServiceAuditPipelineResult["results"] = {
    ssh: [],
    ftp: [],
    nikto: [],
    wapiti: [],
    arachni: [],
  };

  let auditsTriggered = 0;
  let auditsCompleted = 0;
  let auditsFailed = 0;

  // Build audit task queue
  const tasks: Array<{
    service: DiscoveredService;
    scanner: string;
  }> = [];

  for (const service of services) {
    const scanners = getScannersForService(service, config.enabledScanners);
    for (const scanner of scanners) {
      tasks.push({ service, scanner });
    }
  }

  auditsTriggered = tasks.length;
  console.log(`[ServiceAuditPipeline] ${tasks.length} audits queued for ${services.length} services`);

  // Execute with concurrency control
  const executing = new Set<Promise<void>>();

  for (const task of tasks) {
    const promise = (async () => {
      emit({
        type: "audit_started",
        service: task.service,
        scanner: task.scanner,
        timestamp: Date.now(),
      });

      const { scanner, result, error } = await runScanner(task.scanner, task.service, config);

      if (error || !result) {
        auditsFailed++;
        emit({
          type: "audit_error",
          service: task.service,
          scanner,
          error: error || "No result returned",
          timestamp: Date.now(),
        });
      } else {
        auditsCompleted++;

        // Store result in appropriate bucket
        switch (scanner) {
          case "ssh-audit": results.ssh.push(result); break;
          case "ftp-audit": results.ftp.push(result); break;
          case "nikto": results.nikto.push(result); break;
          case "wapiti": results.wapiti.push(result); break;
          case "arachni": results.arachni.push(result); break;
        }

        emit({
          type: "audit_completed",
          service: task.service,
          scanner,
          result: {
            findingCount: result.findings?.length || 0,
            status: result.status,
          },
          timestamp: Date.now(),
        });
      }
    })();

    executing.add(promise);
    promise.finally(() => executing.delete(promise));

    // Concurrency gate
    if (executing.size >= concurrency) {
      await Promise.race(executing);
    }
  }

  // Wait for remaining tasks
  await Promise.allSettled(executing);

  // Aggregate severity summary
  const severitySummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let totalFindings = 0;

  const allResults = [
    ...results.ssh.flatMap(r => r.findings),
    ...results.ftp.flatMap(r => r.findings),
    ...results.nikto.flatMap(r => r.findings),
    ...results.wapiti.flatMap(r => r.findings),
    ...results.arachni.flatMap(r => r.findings),
  ];

  for (const finding of allResults) {
    totalFindings++;
    const sev = (finding as any).severity as keyof typeof severitySummary;
    if (sev in severitySummary) severitySummary[sev]++;
  }

  const durationSeconds = (Date.now() - startTime) / 1000;

  emit({
    type: "pipeline_completed",
    service: services[0] || { host: "unknown", port: 0, service: "unknown" },
    scanner: "pipeline",
    result: { totalFindings, auditsCompleted, auditsFailed },
    timestamp: Date.now(),
  });

  console.log(`[ServiceAuditPipeline] Complete: ${auditsCompleted}/${auditsTriggered} audits, ${totalFindings} findings in ${durationSeconds.toFixed(1)}s`);

  return {
    totalServices: services.length,
    auditsTriggered,
    auditsCompleted,
    auditsFailed,
    results,
    totalFindings,
    severitySummary,
    durationSeconds,
  };
}

/**
 * Convenience function: auto-audit SSH ports from naabu/nmap discovery.
 */
export async function autoAuditSSHPorts(
  hosts: Array<{ host: string; port: number }>,
  engagementId: number,
  operatorId?: number,
): Promise<SSHAuditResult[]> {
  const sshHosts = hosts.filter(h => h.port === 22 || h.port === 2222);
  if (sshHosts.length === 0) return [];

  console.log(`[ServiceAuditPipeline] Auto-auditing ${sshHosts.length} SSH service(s)`);

  const results: SSHAuditResult[] = [];
  for (const { host, port } of sshHosts) {
    try {
      const result = await startSSHAudit({ host, port, engagementId, operatorId });
      results.push(result);
    } catch (err: any) {
      console.error(`[ServiceAuditPipeline] SSH audit failed for ${host}:${port}: ${err.message}`);
    }
  }
  return results;
}

/**
 * Convenience function: auto-audit FTP ports from naabu/nmap discovery.
 */
export async function autoAuditFTPPorts(
  hosts: Array<{ host: string; port: number }>,
  engagementId: number,
  operatorId?: number,
): Promise<FTPAuditResult[]> {
  const ftpHosts = hosts.filter(h => h.port === 21 || h.port === 990);
  if (ftpHosts.length === 0) return [];

  console.log(`[ServiceAuditPipeline] Auto-auditing ${ftpHosts.length} FTP service(s)`);

  const results: FTPAuditResult[] = [];
  for (const { host, port } of ftpHosts) {
    try {
      const result = await startFTPAudit({ host, port, engagementId, operatorId });
      results.push(result);
    } catch (err: any) {
      console.error(`[ServiceAuditPipeline] FTP audit failed for ${host}:${port}: ${err.message}`);
    }
  }
  return results;
}
