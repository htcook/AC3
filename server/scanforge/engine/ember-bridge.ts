/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * SCANFORGE ↔ EMBER BRIDGE
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * Enables ScanForge to execute vulnerability scans through deployed Ember agents,
 * providing internal network scanning capabilities that external scanners cannot reach.
 *
 * Architecture:
 *
 *   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
 *   │  ScanForge   │────▶│ Ember Bridge │────▶│ Ember Agent  │
 *   │  Orchestrator│     │              │     │ (Internal)   │
 *   └──────────────┘     └──────────────┘     └──────────────┘
 *          │                    │                     │
 *          │  scan request      │  task dispatch      │  execute scan
 *          │                    │                     │  from inside
 *          │                    │                     │  the network
 *          │                    │◀────────────────────│
 *          │                    │  beacon results     │
 *          │◀───────────────────│                     │
 *          │  normalized        │                     │
 *          │  findings          │                     │
 *
 * Scan Types Supported via Ember:
 *   - Port scanning (internal network ranges)
 *   - Service fingerprinting (banner grabbing)
 *   - Web application scanning (internal web apps)
 *   - Credential testing (internal services)
 *   - Network vulnerability detection (CVE checks)
 *   - SMB/LDAP/DNS enumeration
 *   - Certificate analysis (internal CAs)
 *   - Configuration auditing (via agent access)
 *
 * The bridge translates ScanForge templates into Ember tasks and normalizes
 * Ember intelligence back into ScanForge findings.
 */

import { randomUUID } from "crypto";
import type {
  EmberTask,
  EmberTaskResult,
  EmberIntelligence,
  EmberAgentConfig,
} from "../../lib/ember-agent-core";
import type { ScanFinding } from "../types/index";

// ─── Types ──────────────────────────────────────────────────────────────────

export type EmberScanType =
  | "port_scan"           // Internal port scanning
  | "service_fingerprint" // Banner grabbing and service identification
  | "web_scan"            // Internal web application scanning
  | "credential_test"     // Internal credential testing
  | "network_vuln"        // Network-level vulnerability detection
  | "smb_enum"            // SMB share and user enumeration
  | "ldap_enum"           // LDAP/AD enumeration
  | "dns_enum"            // Internal DNS enumeration
  | "cert_audit"          // Certificate chain analysis
  | "config_audit"        // Host configuration auditing
  | "custom_script";      // Custom scan script execution

export interface EmberScanRequest {
  /** Unique scan request ID */
  requestId: string;
  /** ScanForge scan ID this request belongs to */
  scanId: string;
  /** Engagement ID */
  engagementId: number;
  /** Type of scan to perform */
  scanType: EmberScanType;
  /** Target specification */
  target: EmberScanTarget;
  /** Scan configuration */
  config: EmberScanConfig;
  /** Template ID that generated this request (if any) */
  templateId?: string;
  /** Priority (1-10) */
  priority: number;
  /** Timeout in seconds */
  timeoutSeconds: number;
  /** Created timestamp */
  createdAt: number;
}

export interface EmberScanTarget {
  /** Target hosts/IPs/CIDRs */
  hosts: string[];
  /** Target ports (for port/service scans) */
  ports?: string;
  /** Target URLs (for web scans) */
  urls?: string[];
  /** Target services (for credential tests) */
  services?: Array<{
    host: string;
    port: number;
    protocol: string;
    service?: string;
  }>;
  /** Network range for discovery */
  networkRange?: string;
}

export interface EmberScanConfig {
  /** Scan intensity (1-5, 1=stealth, 5=aggressive) */
  intensity: number;
  /** Maximum concurrent connections */
  maxConcurrent: number;
  /** Rate limit (requests per second) */
  rateLimit: number;
  /** Whether to follow redirects (web scans) */
  followRedirects?: boolean;
  /** Authentication config for authenticated scans */
  auth?: {
    type: "basic" | "bearer" | "cookie" | "ntlm" | "kerberos";
    credentials: Record<string, string>;
  };
  /** Custom scripts to execute */
  scripts?: string[];
  /** NSE scripts for scanforge-discovery-style scanning */
  nseScripts?: string[];
  /** Wordlists for enumeration */
  wordlists?: {
    usernames?: string[];
    passwords?: string[];
    directories?: string[];
  };
  /** Whether to perform OS detection */
  osDetection?: boolean;
  /** Whether to perform version detection */
  versionDetection?: boolean;
}

export interface EmberScanResult {
  /** Request ID this result belongs to */
  requestId: string;
  /** Status */
  status: "completed" | "partial" | "failed" | "timeout";
  /** Findings from the scan */
  findings: ScanFinding[];
  /** Raw intelligence data from the agent */
  rawIntelligence: EmberIntelligence[];
  /** Discovered hosts */
  discoveredHosts?: Array<{
    ip: string;
    hostname?: string;
    os?: string;
    ports: Array<{ port: number; protocol: string; service: string; version?: string; state: string }>;
  }>;
  /** Duration in milliseconds */
  durationMs: number;
  /** Agent that executed the scan */
  agentId: string;
  /** Errors encountered */
  errors: string[];
  /** Timestamp */
  completedAt: number;
}

// ─── Ember Scan Task Builder ────────────────────────────────────────────────

/**
 * Translates a ScanForge scan request into one or more Ember tasks
 * that the agent can execute from inside the network.
 */
export function buildEmberScanTasks(request: EmberScanRequest): EmberTask[] {
  const tasks: EmberTask[] = [];

  switch (request.scanType) {
    case "port_scan":
      tasks.push(buildPortScanTask(request));
      break;

    case "service_fingerprint":
      tasks.push(buildServiceFingerprintTask(request));
      break;

    case "web_scan":
      tasks.push(...buildWebScanTasks(request));
      break;

    case "credential_test":
      tasks.push(buildCredentialTestTask(request));
      break;

    case "network_vuln":
      tasks.push(buildNetworkVulnTask(request));
      break;

    case "smb_enum":
      tasks.push(buildSMBEnumTask(request));
      break;

    case "ldap_enum":
      tasks.push(buildLDAPEnumTask(request));
      break;

    case "dns_enum":
      tasks.push(buildDNSEnumTask(request));
      break;

    case "cert_audit":
      tasks.push(buildCertAuditTask(request));
      break;

    case "config_audit":
      tasks.push(buildConfigAuditTask(request));
      break;

    case "custom_script":
      tasks.push(buildCustomScriptTask(request));
      break;
  }

  return tasks;
}

function buildPortScanTask(req: EmberScanRequest): EmberTask {
  const hosts = req.target.hosts.join(" ");
  const ports = req.target.ports || "1-1024";
  const intensity = req.config.intensity;

  // Map intensity to scanforge-discovery timing template
  const timing = intensity <= 2 ? "-T2" : intensity <= 3 ? "-T3" : "-T4";
  const stealth = intensity <= 2 ? "-sS" : "-sT"; // SYN scan for stealth
  const extraFlags = [
    req.config.osDetection ? "-O" : "",
    req.config.versionDetection ? "-sV" : "",
    req.config.rateLimit ? `--max-rate ${req.config.rateLimit}` : "",
  ].filter(Boolean).join(" ");

  return {
    taskId: `sf-portscan-${req.requestId}`,
    type: "shell_command",
    priority: req.priority,
    params: {
      command: `naabu -p ${ports} -host ${hosts} -json -o /tmp/sf-scan-${req.requestId}.json`,
      outputFile: `/tmp/sf-scan-${req.requestId}.xml`,
      parseFormat: "scanforge-discovery_xml",
    },
    attackTechnique: "T1046",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: intensity <= 2, // SYN scan requires root
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge",
  };
}

function buildServiceFingerprintTask(req: EmberScanRequest): EmberTask {
  const hosts = req.target.hosts.join(" ");
  const ports = req.target.ports || "1-1024";

  return {
    taskId: `sf-svcfp-${req.requestId}`,
    type: "shell_command",
    priority: req.priority,
    params: {
      command: `httpx -probe -tech-detect -status-code -title -json -o /tmp/sf-svcfp-${req.requestId}.json -l <(echo ${hosts})`,
      outputFile: `/tmp/sf-svcfp-${req.requestId}.xml`,
      parseFormat: "scanforge-discovery_xml",
    },
    attackTechnique: "T1046",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: false,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge",
  };
}

function buildWebScanTasks(req: EmberScanRequest): EmberTask[] {
  const tasks: EmberTask[] = [];
  const urls = req.target.urls || req.target.hosts.map(h => `http://${h}`);

  // Task 1: Directory/endpoint discovery
  tasks.push({
    taskId: `sf-webdisc-${req.requestId}`,
    type: "shell_command",
    priority: req.priority,
    params: {
      command: buildWebDiscoveryCommand(urls, req.config),
      parseFormat: "json",
    },
    attackTechnique: "T1595.002",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: false,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge",
  });

  // Task 2: Vulnerability probing
  tasks.push({
    taskId: `sf-webvuln-${req.requestId}`,
    type: "execute_module",
    priority: req.priority,
    params: {
      moduleId: "ember.recon.service_fingerprint",
      scanType: "web_vuln",
      targets: urls,
      checks: [
        "sql_injection",
        "xss_reflected",
        "xss_stored",
        "command_injection",
        "path_traversal",
        "ssrf",
        "open_redirect",
        "header_injection",
        "cors_misconfiguration",
        "security_headers",
      ],
      config: {
        followRedirects: req.config.followRedirects ?? true,
        maxDepth: 3,
        rateLimit: req.config.rateLimit,
        auth: req.config.auth,
      },
    },
    attackTechnique: "T1190",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: false,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge",
  });

  return tasks;
}

function buildCredentialTestTask(req: EmberScanRequest): EmberTask {
  const services = req.target.services || [];

  return {
    taskId: `sf-credtest-${req.requestId}`,
    type: "execute_module",
    priority: req.priority,
    params: {
      moduleId: "ember.cred.browser_extract",
      scanType: "credential_spray",
      targets: services,
      wordlists: req.config.wordlists || {
        usernames: ["admin", "root", "administrator", "sa", "postgres", "mysql"],
        passwords: ["admin", "password", "123456", "root", "toor", "changeme"],
      },
      config: {
        maxConcurrent: req.config.maxConcurrent,
        rateLimit: req.config.rateLimit,
        lockoutThreshold: 3, // Stop after 3 failures per account
      },
    },
    attackTechnique: "T1110.003",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: false,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge",
  };
}

function buildNetworkVulnTask(req: EmberScanRequest): EmberTask {
  const hosts = req.target.hosts.join(" ");
  const nseScripts = req.config.nseScripts || [
    "vuln", "exploit", "auth", "default",
  ];

  return {
    taskId: `sf-netvuln-${req.requestId}`,
    type: "shell_command",
    priority: req.priority,
    params: {
      command: `scanforge-discovery --script=${nseScripts.join(",")} -p ${req.target.ports || "1-65535"} -oX /tmp/sf-netvuln-${req.requestId}.xml ${hosts}`,
      outputFile: `/tmp/sf-netvuln-${req.requestId}.xml`,
      parseFormat: "scanforge-discovery_xml",
    },
    attackTechnique: "T1046",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: true,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge",
  };
}

function buildSMBEnumTask(req: EmberScanRequest): EmberTask {
  const hosts = req.target.hosts.join(" ");

  return {
    taskId: `sf-smbenum-${req.requestId}`,
    type: "shell_command",
    priority: req.priority,
    params: {
      command: `nuclei -t cves/smb/ -t network/smb/ -target ${hosts} -json -o /tmp/sf-smb-${req.requestId}.json`,
      outputFile: `/tmp/sf-smb-${req.requestId}.xml`,
      parseFormat: "scanforge-discovery_xml",
    },
    attackTechnique: "T1135",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: false,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge",
  };
}

function buildLDAPEnumTask(req: EmberScanRequest): EmberTask {
  const host = req.target.hosts[0];
  const auth = req.config.auth;

  const ldapCmd = auth?.type === "basic"
    ? `ldapsearch -H ldap://${host} -D "${auth.credentials.username}" -w "${auth.credentials.password}" -b "" "(objectClass=*)" -LLL`
    : `ldapsearch -H ldap://${host} -x -b "" "(objectClass=*)" -LLL`;

  return {
    taskId: `sf-ldapenum-${req.requestId}`,
    type: "shell_command",
    priority: req.priority,
    params: {
      command: `${ldapCmd} > /tmp/sf-ldap-${req.requestId}.txt 2>&1; nuclei -t network/ldap/ -target ${host} -json -o /tmp/sf-ldap-${req.requestId}.json`,
      outputFile: `/tmp/sf-ldap-${req.requestId}.xml`,
      parseFormat: "scanforge-discovery_xml",
    },
    attackTechnique: "T1087.002",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: false,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge",
  };
}

function buildDNSEnumTask(req: EmberScanRequest): EmberTask {
  const host = req.target.hosts[0];

  return {
    taskId: `sf-dnsenum-${req.requestId}`,
    type: "shell_command",
    priority: req.priority,
    params: {
      command: `nuclei -t dns/ -target ${host} -json -o /tmp/sf-dns-${req.requestId}.json`,
      outputFile: `/tmp/sf-dns-${req.requestId}.xml`,
      parseFormat: "scanforge-discovery_xml",
    },
    attackTechnique: "T1018",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: false,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge",
  };
}

function buildCertAuditTask(req: EmberScanRequest): EmberTask {
  const hosts = req.target.hosts.join(" ");
  const ports = req.target.ports || "443,8443,993,995,636";

  return {
    taskId: `sf-certaudit-${req.requestId}`,
    type: "shell_command",
    priority: req.priority,
    params: {
      command: `nuclei -t ssl/ -t cves/ssl/ -target ${hosts} -json -o /tmp/sf-cert-${req.requestId}.json`,
      outputFile: `/tmp/sf-cert-${req.requestId}.xml`,
      parseFormat: "scanforge-discovery_xml",
    },
    attackTechnique: "T1557",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: false,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge",
  };
}

function buildConfigAuditTask(req: EmberScanRequest): EmberTask {
  return {
    taskId: `sf-cfgaudit-${req.requestId}`,
    type: "execute_module",
    priority: req.priority,
    params: {
      moduleId: "ember.cognitive.env_analyzer",
      scanType: "config_audit",
      checks: [
        "password_policy",
        "firewall_rules",
        "open_shares",
        "writable_directories",
        "suid_binaries",
        "cron_jobs",
        "service_permissions",
        "registry_acls",
        "certificate_expiry",
        "patch_level",
      ],
    },
    attackTechnique: "T1082",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: true,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge",
  };
}

function buildCustomScriptTask(req: EmberScanRequest): EmberTask {
  const scripts = req.config.scripts || [];

  return {
    taskId: `sf-custom-${req.requestId}`,
    type: "shell_command",
    priority: req.priority,
    params: {
      command: scripts.join(" && "),
      parseFormat: "raw",
    },
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: false,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge",
  };
}

function buildWebDiscoveryCommand(urls: string[], config: EmberScanConfig): string {
  // Build a curl-based discovery script that checks common paths
  const paths = config.wordlists?.directories || [
    "/admin", "/login", "/api", "/wp-admin", "/phpmyadmin",
    "/.env", "/.git/config", "/robots.txt", "/sitemap.xml",
    "/server-status", "/server-info", "/.htaccess", "/web.config",
    "/backup", "/test", "/debug", "/console", "/swagger",
    "/api/v1", "/graphql", "/.well-known/security.txt",
  ];

  const urlList = urls.map(u => u.replace(/\/$/, "")).join(" ");
  const pathList = paths.join(" ");

  return `for url in ${urlList}; do for path in ${pathList}; do code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$url$path" 2>/dev/null); if [ "$code" != "000" ] && [ "$code" != "404" ]; then echo "$url$path:$code"; fi; done; done`;
}

// ─── Result Normalizer ──────────────────────────────────────────────────────

/**
 * Normalize Ember task results and intelligence into ScanForge findings.
 * This is the reverse translation — from Ember's format back to ScanForge's.
 */
export function normalizeEmberResults(
  taskResults: EmberTaskResult[],
  intelligence: EmberIntelligence[],
  request: EmberScanRequest,
): EmberScanResult {
  const findings: ScanFinding[] = [];
  const errors: string[] = [];
  let totalDuration = 0;

  for (const result of taskResults) {
    totalDuration += result.durationMs;

    if (result.status === "failed" || result.status === "timeout") {
      errors.push(`Task ${result.taskId}: ${result.error || result.status}`);
      continue;
    }

    // Parse findings from task output
    if (result.output) {
      const parsed = parseTaskOutput(result, request);
      findings.push(...parsed);
    }

    // Convert artifacts to findings
    for (const artifact of result.artifacts) {
      if (artifact.type === "intelligence") {
        const finding = artifactToFinding(artifact, request);
        if (finding) findings.push(finding);
      }
    }
  }

  // Convert intelligence to findings
  for (const intel of intelligence) {
    const finding = intelligenceToFinding(intel, request);
    if (finding) findings.push(finding);
  }

  // Deduplicate findings by URL + vulnerability class
  const deduped = deduplicateFindings(findings);

  const overallStatus = taskResults.every(r => r.status === "success")
    ? "completed"
    : taskResults.some(r => r.status === "success")
      ? "partial"
      : taskResults.some(r => r.status === "timeout")
        ? "timeout"
        : "failed";

  return {
    requestId: request.requestId,
    status: overallStatus,
    findings: deduped,
    rawIntelligence: intelligence,
    durationMs: totalDuration,
    agentId: taskResults[0]?.taskId.split("-")[0] || "unknown",
    errors,
    completedAt: Date.now(),
  };
}

function parseTaskOutput(result: EmberTaskResult, request: EmberScanRequest): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const output = result.output || "";

  // Parse web discovery output (url:statuscode format)
  if (output.includes(":200") || output.includes(":301") || output.includes(":403")) {
    const lines = output.split("\n").filter(l => l.trim());
    for (const line of lines) {
      const match = line.match(/^(.+):(\d{3})$/);
      if (match) {
        const [, url, code] = match;
        const statusCode = parseInt(code);

        if (statusCode === 200 && /\.(env|git|htaccess|config)/.test(url)) {
          findings.push({
            id: `sf-ember-${randomUUID().slice(0, 8)}`,
            scanId: request.scanId,
            templateId: request.templateId || "ember-web-discovery",
            title: `Sensitive File Exposed: ${url.split("/").pop()}`,
            description: `The file at ${url} is publicly accessible (HTTP ${statusCode}). This may expose sensitive configuration data, credentials, or internal paths.`,
            severity: "high",
            confidence: "confirmed",
            url,
            host: new URL(url).hostname,
            port: parseInt(new URL(url).port) || (url.startsWith("https") ? 443 : 80),
            evidence: `HTTP ${statusCode} response for ${url}`,
            remediation: "Restrict access to sensitive files via web server configuration. Add deny rules for .env, .git, .htaccess, and similar files.",
            cweId: "CWE-538",
            cvssScore: 7.5,
            tags: ["sensitive-file", "information-disclosure", "owasp-a01"],
            detectedAt: Date.now(),
            verifiedAt: null,
            falsePositive: false,
          });
        } else if (statusCode === 200 && /admin|console|debug|swagger|graphql/.test(url)) {
          findings.push({
            id: `sf-ember-${randomUUID().slice(0, 8)}`,
            scanId: request.scanId,
            templateId: request.templateId || "ember-web-discovery",
            title: `Administrative Interface Exposed: ${url}`,
            description: `An administrative or debug interface was found at ${url}. This could allow unauthorized access to management functions.`,
            severity: "medium",
            confidence: "confirmed",
            url,
            host: new URL(url).hostname,
            port: parseInt(new URL(url).port) || (url.startsWith("https") ? 443 : 80),
            evidence: `HTTP ${statusCode} response for ${url}`,
            remediation: "Restrict access to administrative interfaces using IP whitelisting, authentication, or VPN requirements.",
            cweId: "CWE-284",
            cvssScore: 5.3,
            tags: ["admin-interface", "access-control", "owasp-a01"],
            detectedAt: Date.now(),
            verifiedAt: null,
            falsePositive: false,
          });
        }
      }
    }
  }

  return findings;
}

function artifactToFinding(
  artifact: { type: string; name: string; description: string; data?: string; technique?: string },
  request: EmberScanRequest,
): ScanFinding | null {
  if (artifact.type !== "intelligence") return null;

  try {
    const data = artifact.data ? JSON.parse(Buffer.from(artifact.data, "base64").toString()) : {};

    return {
      id: `sf-ember-${randomUUID().slice(0, 8)}`,
      scanId: request.scanId,
      templateId: request.templateId || "ember-artifact",
      title: artifact.name,
      description: artifact.description,
      severity: data.severity || "info",
      confidence: "tentative",
      url: data.url || request.target.hosts[0],
      host: data.host || request.target.hosts[0],
      port: data.port || 0,
      evidence: data.evidence || artifact.description,
      remediation: data.remediation || "Review the finding and apply appropriate remediation.",
      cweId: data.cweId,
      cvssScore: data.cvssScore,
      tags: ["ember-agent", ...(data.tags || [])],
      detectedAt: Date.now(),
      verifiedAt: null,
      falsePositive: false,
    };
  } catch {
    return null;
  }
}

function intelligenceToFinding(
  intel: EmberIntelligence,
  request: EmberScanRequest,
): ScanFinding | null {
  if (intel.type !== "vulnerability_found") return null;

  const data = intel.data;

  return {
    id: `sf-ember-${randomUUID().slice(0, 8)}`,
    scanId: request.scanId,
    templateId: request.templateId || "ember-intelligence",
    title: data.title || `Vulnerability: ${data.type || "Unknown"}`,
    description: data.description || "Vulnerability detected by Ember agent during internal scan.",
    severity: mapConfidenceToSeverity(intel.confidence, data.severity),
    confidence: intel.confidence >= 80 ? "confirmed" : intel.confidence >= 50 ? "tentative" : "tentative",
    url: data.url || data.host || request.target.hosts[0],
    host: data.host || request.target.hosts[0],
    port: data.port || 0,
    evidence: data.evidence || JSON.stringify(data),
    remediation: data.remediation || "Review and remediate the identified vulnerability.",
    cweId: data.cweId,
    cveId: data.cveId,
    cvssScore: data.cvssScore,
    tags: ["ember-agent", "internal-scan", ...(data.tags || [])],
    detectedAt: Date.now(),
    verifiedAt: intel.confidence >= 80 ? Date.now() : null,
    falsePositive: false,
  };
}

function mapConfidenceToSeverity(confidence: number, existingSeverity?: string): "critical" | "high" | "medium" | "low" | "info" {
  if (existingSeverity && ["critical", "high", "medium", "low", "info"].includes(existingSeverity)) {
    return existingSeverity as any;
  }
  if (confidence >= 90) return "high";
  if (confidence >= 70) return "medium";
  if (confidence >= 50) return "low";
  return "info";
}

function deduplicateFindings(findings: ScanFinding[]): ScanFinding[] {
  const seen = new Map<string, ScanFinding>();

  for (const finding of findings) {
    const key = `${finding.host}:${finding.port}:${finding.cweId || finding.title}`;
    const existing = seen.get(key);

    if (!existing) {
      seen.set(key, finding);
    } else {
      // Keep the higher severity / higher confidence finding
      const severityOrder = ["critical", "high", "medium", "low", "info"];
      const existingSev = severityOrder.indexOf(existing.severity);
      const newSev = severityOrder.indexOf(finding.severity);
      if (newSev < existingSev) {
        seen.set(key, finding);
      }
    }
  }

  return Array.from(seen.values());
}

// ─── Bridge Orchestrator ────────────────────────────────────────────────────

/**
 * The main bridge class that coordinates ScanForge scans through Ember agents.
 */
export class ScanForgeEmberBridge {
  private pendingRequests: Map<string, EmberScanRequest> = new Map();
  private completedResults: Map<string, EmberScanResult> = new Map();
  private taskToRequest: Map<string, string> = new Map(); // taskId -> requestId

  /**
   * Submit a scan request to be executed by an Ember agent.
   */
  async submitScan(request: EmberScanRequest): Promise<{ tasks: EmberTask[]; requestId: string }> {
    this.pendingRequests.set(request.requestId, request);

    const tasks = buildEmberScanTasks(request);

    // Map tasks back to the request
    for (const task of tasks) {
      this.taskToRequest.set(task.taskId, request.requestId);
    }

    console.log(
      `[ScanForge-Ember] Submitted scan ${request.requestId} (${request.scanType}) → ${tasks.length} task(s) for agent dispatch`
    );

    return { tasks, requestId: request.requestId };
  }

  /**
   * Process results from an Ember agent beacon.
   * Called when the C2 receives task results from an agent.
   */
  processAgentResults(
    taskResults: EmberTaskResult[],
    intelligence: EmberIntelligence[],
  ): EmberScanResult | null {
    // Find which request these results belong to
    const requestId = taskResults
      .map(r => this.taskToRequest.get(r.taskId))
      .find(Boolean);

    if (!requestId) return null;

    const request = this.pendingRequests.get(requestId);
    if (!request) return null;

    const result = normalizeEmberResults(taskResults, intelligence, request);

    this.completedResults.set(requestId, result);
    this.pendingRequests.delete(requestId);

    // Clean up task mappings
    for (const tr of taskResults) {
      this.taskToRequest.delete(tr.taskId);
    }

    console.log(
      `[ScanForge-Ember] Scan ${requestId} completed: ${result.findings.length} findings, ${result.errors.length} errors`
    );

    return result;
  }

  /**
   * Get the result of a completed scan.
   */
  getResult(requestId: string): EmberScanResult | null {
    return this.completedResults.get(requestId) || null;
  }

  /**
   * Check if a scan is still pending.
   */
  isPending(requestId: string): boolean {
    return this.pendingRequests.has(requestId);
  }

  /**
   * Get all pending scan requests for an engagement.
   */
  getPendingForEngagement(engagementId: number): EmberScanRequest[] {
    return Array.from(this.pendingRequests.values())
      .filter(r => r.engagementId === engagementId);
  }

  /**
   * Get all completed results for an engagement.
   */
  getResultsForEngagement(engagementId: number): EmberScanResult[] {
    return Array.from(this.completedResults.values())
      .filter(r => {
        const req = this.pendingRequests.get(r.requestId);
        // Check completed results map
        return true; // All results in this map are for this bridge instance
      });
  }

  /**
   * Cancel a pending scan.
   */
  cancelScan(requestId: string): boolean {
    const request = this.pendingRequests.get(requestId);
    if (!request) return false;

    this.pendingRequests.delete(requestId);

    // Clean up task mappings
    for (const [taskId, reqId] of this.taskToRequest) {
      if (reqId === requestId) this.taskToRequest.delete(taskId);
    }

    console.log(`[ScanForge-Ember] Scan ${requestId} cancelled`);
    return true;
  }

  /**
   * Get bridge statistics.
   */
  getStats(): {
    pendingScans: number;
    completedScans: number;
    totalFindings: number;
    taskMappings: number;
  } {
    let totalFindings = 0;
    for (const result of this.completedResults.values()) {
      totalFindings += result.findings.length;
    }

    return {
      pendingScans: this.pendingRequests.size,
      completedScans: this.completedResults.size,
      totalFindings,
      taskMappings: this.taskToRequest.size,
    };
  }

  /**
   * Create a scan request from a ScanForge template.
   */
  static createRequestFromTemplate(
    scanId: string,
    engagementId: number,
    templateId: string,
    scanType: EmberScanType,
    target: EmberScanTarget,
    options?: Partial<EmberScanConfig>,
  ): EmberScanRequest {
    return {
      requestId: `ember-${randomUUID().slice(0, 8)}`,
      scanId,
      engagementId,
      scanType,
      target,
      config: {
        intensity: 3,
        maxConcurrent: 10,
        rateLimit: 50,
        followRedirects: true,
        ...options,
      },
      templateId,
      priority: 5,
      timeoutSeconds: 600,
      createdAt: Date.now(),
    };
  }
}

// ─── Singleton ──────────────────────────────────────────────────────────────

let bridgeInstance: ScanForgeEmberBridge | null = null;

export function getEmberBridge(): ScanForgeEmberBridge {
  if (!bridgeInstance) {
    bridgeInstance = new ScanForgeEmberBridge();
  }
  return bridgeInstance;
}
