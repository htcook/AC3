/**
 * Discovery Chain Orchestrator
 * 
 * Automatically sequences the full active discovery pipeline:
 * 
 *   Stage 1: AMASS — Subdomain enumeration (passive + active)
 *     ↓ discovered subdomains & IPs
 *   Stage 2: NMAP — Port scanning & service detection
 *     ↓ open ports & service banners
 *   Stage 3: SERVICE FINGERPRINTER — Protocol-specific probing
 *     ↓ detailed service metadata, security flags, risk indicators
 *   Stage 4: NUCLEI — Template-based vulnerability scanning
 *     ↓ CVEs, misconfigurations, exposures
 * 
 * Each stage's output automatically feeds the next stage's input.
 * Scope enforcement is applied at every stage boundary.
 * 
 * @module discovery-chain-orchestrator
 */

import type { PipelineFinding, PipelinePhase, ToolModule } from "./unified-pipeline";

// ─── Types ───────────────────────────────────────────────────────────

export type ChainStageId = "amass" | "nmap" | "service_fingerprinter" | "nuclei";

export type ChainStageStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "skipped"
  | "cancelled";

export type ChainRunStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "cancelled"
  | "paused";

export interface ChainStageDefinition {
  id: ChainStageId;
  name: string;
  description: string;
  tool: ToolModule;
  /** Which prior stages feed into this one */
  dependsOn: ChainStageId[];
  /** Estimated duration in seconds */
  estimatedDurationSec: number;
  /** Whether this stage can be skipped */
  optional: boolean;
}

export interface ChainStageResult {
  stageId: ChainStageId;
  status: ChainStageStatus;
  startedAt: number;
  completedAt?: number;
  durationMs?: number;
  /** Number of targets fed into this stage */
  inputTargetCount: number;
  /** Number of results produced */
  outputCount: number;
  /** Errors encountered */
  errors: string[];
  /** Findings produced by this stage */
  findings: PipelineFinding[];
  /** Raw output data for downstream consumption */
  rawOutput: any;
}

export interface ChainRunConfig {
  /** Target domain(s) to begin discovery from */
  domains: string[];
  /** Optional seed IPs to include in Nmap scanning */
  seedIps?: string[];
  /** Optional seed URLs to include in Nuclei scanning */
  seedUrls?: string[];
  /** Engagement ID for scope enforcement */
  engagementId?: number;
  /** Operator ID for audit trail */
  operatorId?: string;
  /** Stages to skip */
  skipStages?: ChainStageId[];
  /** Stage-specific configuration overrides */
  stageConfig?: {
    amass?: {
      mode?: "passive" | "active";
      timeout?: number;
      maxSubdomains?: number;
    };
    nmap?: {
      profile?: "quick" | "standard" | "deep" | "stealth" | "service" | "vuln";
      topPorts?: number;
      timeout?: number;
    };
    service_fingerprinter?: {
      timeout?: number;
      concurrency?: number;
      tryDefaultCreds?: boolean;
    };
    nuclei?: {
      severity?: string[];
      templateCategories?: string[];
      rateLimit?: number;
      timeout?: number;
    };
  };
  /** Maximum total chain duration in seconds (default: 3600 = 1 hour) */
  maxDurationSec?: number;
  /** Whether to continue to next stage on partial failure */
  continueOnPartialFailure?: boolean;
}

export interface ChainRun {
  id: string;
  config: ChainRunConfig;
  status: ChainRunStatus;
  stages: ChainStageResult[];
  /** Aggregated findings across all stages */
  allFindings: PipelineFinding[];
  /** Summary statistics */
  summary: ChainRunSummary;
  startedAt: number;
  completedAt?: number;
  durationMs?: number;
  /** Progress percentage (0-100) */
  progress: number;
  /** Current stage being executed */
  currentStage?: ChainStageId;
  /** Cancellation flag */
  cancelled: boolean;
}

export interface ChainRunSummary {
  totalSubdomains: number;
  totalHosts: number;
  totalOpenPorts: number;
  totalServices: number;
  totalVulnerabilities: number;
  totalFindings: number;
  findingsBySeverity: Record<string, number>;
  findingsByStage: Record<ChainStageId, number>;
  stagesCompleted: number;
  stagesTotal: number;
  stagesFailed: number;
  stagesSkipped: number;
  /** Unique CVEs discovered across all stages */
  uniqueCves: string[];
  /** Unique ATT&CK techniques mapped */
  attackTechniques: string[];
}

// ─── Stage Definitions ──────────────────────────────────────────────

export const CHAIN_STAGES: ChainStageDefinition[] = [
  {
    id: "amass",
    name: "Subdomain Enumeration",
    description:
      "Discover subdomains via passive OSINT (cert transparency, DNS records, web archives) and optionally active DNS brute-force. Output: subdomain list with resolved IPs.",
    tool: "amass",
    dependsOn: [],
    estimatedDurationSec: 120,
    optional: false,
  },
  {
    id: "nmap",
    name: "Port Scanning & Service Detection",
    description:
      "Scan discovered hosts for open ports, detect running services and versions, perform OS fingerprinting. Output: host/port/service inventory.",
    tool: "nmap",
    dependsOn: ["amass"],
    estimatedDurationSec: 300,
    optional: false,
  },
  {
    id: "service_fingerprinter",
    name: "Protocol-Specific Fingerprinting",
    description:
      "Deep-probe discovered services with protocol-specific handlers (SSH, SMTP, FTP, SNMP, RDP, SMB, LDAP, databases). Extract banners, versions, security flags, and risk indicators.",
    tool: "service_fingerprinter",
    dependsOn: ["nmap"],
    estimatedDurationSec: 180,
    optional: true,
  },
  {
    id: "nuclei",
    name: "Vulnerability Scanning",
    description:
      "Run template-based vulnerability scanning against discovered services. Match CVEs, detect misconfigurations, identify exposures using 8,000+ templates.",
    tool: "nuclei_vuln",
    dependsOn: ["nmap", "service_fingerprinter"],
    estimatedDurationSec: 600,
    optional: true,
  },
];

// ─── Data Flow Extractors ───────────────────────────────────────────

/**
 * Extract Nmap targets from Amass results.
 * Produces a deduplicated list of IPs and subdomains to scan.
 */
export function extractNmapTargetsFromAmass(amassOutput: any): string[] {
  if (!amassOutput) return [];

  const targets = new Set<string>();

  // Handle array of subdomain results from toUnifiedDiscoveryFormat
  if (Array.isArray(amassOutput)) {
    for (const sub of amassOutput) {
      if (sub.name) targets.add(sub.name);
      if (sub.ips && Array.isArray(sub.ips)) {
        for (const ip of sub.ips) {
          if (ip && typeof ip === "string") targets.add(ip);
        }
      }
    }
  }

  // Handle raw AmassResult object
  if (amassOutput.subdomains && Array.isArray(amassOutput.subdomains)) {
    for (const sub of amassOutput.subdomains) {
      if (sub.name) targets.add(sub.name);
      if (sub.addresses && Array.isArray(sub.addresses)) {
        for (const addr of sub.addresses) {
          if (addr.ip) targets.add(addr.ip);
        }
      }
    }
  }

  return Array.from(targets);
}

/**
 * Extract Service Fingerprinter targets from Nmap results.
 * Maps open ports to protocol-specific fingerprinting targets.
 */
export function extractFingerprintTargetsFromNmap(
  nmapOutput: any
): Array<{ host: string; port: number; protocol?: string }> {
  if (!nmapOutput) return [];

  const targets: Array<{ host: string; port: number; protocol?: string }> = [];

  // Port-to-protocol mapping for service fingerprinter
  const PORT_PROTOCOL_MAP: Record<number, string> = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 110: "pop3", 143: "imap", 161: "snmp",
    389: "ldap", 445: "smb", 465: "smtp", 587: "smtp",
    993: "imap", 995: "pop3", 1433: "mssql", 1521: "mssql",
    3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 27017: "mongodb",
    636: "ldap", 5060: "sip", 123: "ntp",
  };

  // Handle toNmapRawResults format (array of host objects)
  if (Array.isArray(nmapOutput)) {
    for (const host of nmapOutput) {
      if (host.ports && Array.isArray(host.ports)) {
        for (const port of host.ports) {
          const protocol = PORT_PROTOCOL_MAP[port.port];
          if (protocol) {
            targets.push({
              host: host.host || host.ip,
              port: port.port,
              protocol,
            });
          }
        }
      }
    }
  }

  // Handle NmapScanResult format
  if (nmapOutput.hosts && Array.isArray(nmapOutput.hosts)) {
    for (const host of nmapOutput.hosts) {
      if (host.ports && Array.isArray(host.ports)) {
        for (const port of host.ports) {
          const protocol = PORT_PROTOCOL_MAP[port.port];
          if (protocol) {
            targets.push({
              host: host.ip || host.hostname,
              port: port.port,
              protocol,
            });
          }
        }
      }
    }
  }

  return targets;
}

/**
 * Extract Nuclei targets from Nmap and Service Fingerprinter results.
 * Produces URLs and host:port pairs for template scanning.
 */
export function extractNucleiTargetsFromResults(
  nmapOutput: any,
  fingerprintOutput: any
): string[] {
  const targets = new Set<string>();

  // From Nmap: generate URLs for HTTP/HTTPS services
  const httpPorts = new Set([80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090, 9443]);

  if (Array.isArray(nmapOutput)) {
    for (const host of nmapOutput) {
      if (host.ports && Array.isArray(host.ports)) {
        for (const port of host.ports) {
          const hostAddr = host.host || host.ip;
          if (httpPorts.has(port.port) || port.service === "http" || port.service === "https") {
            const scheme = port.port === 443 || port.port === 8443 || port.port === 9443 || port.service === "https" ? "https" : "http";
            targets.add(`${scheme}://${hostAddr}:${port.port}`);
          } else {
            targets.add(`${hostAddr}:${port.port}`);
          }
        }
      }
    }
  }

  if (nmapOutput?.hosts && Array.isArray(nmapOutput.hosts)) {
    for (const host of nmapOutput.hosts) {
      if (host.ports && Array.isArray(host.ports)) {
        for (const port of host.ports) {
          const hostAddr = host.ip || host.hostname;
          if (httpPorts.has(port.port) || port.service === "http" || port.service === "https") {
            const scheme = port.port === 443 || port.port === 8443 || port.port === 9443 || port.service === "https" ? "https" : "http";
            targets.add(`${scheme}://${hostAddr}:${port.port}`);
          } else {
            targets.add(`${hostAddr}:${port.port}`);
          }
        }
      }
    }
  }

  // From fingerprinter: add services with known vulnerabilities
  if (Array.isArray(fingerprintOutput)) {
    for (const result of fingerprintOutput) {
      if (!result.error && result.host && result.port) {
        targets.add(`${result.host}:${result.port}`);
      }
    }
  }

  return Array.from(targets);
}

/**
 * Determine which Nuclei template categories to use based on discovered services.
 */
export function selectNucleiTemplates(
  nmapOutput: any,
  fingerprintOutput: any
): { categories: string[]; tags: string[] } {
  const categories = new Set<string>(["cves", "vulnerabilities", "misconfiguration"]);
  const tags = new Set<string>();

  // Analyze Nmap services
  const services = new Set<string>();
  if (Array.isArray(nmapOutput)) {
    for (const host of nmapOutput) {
      for (const port of host.ports || []) {
        if (port.service) services.add(port.service.toLowerCase());
      }
    }
  }

  // Add relevant template categories based on services
  if (services.has("http") || services.has("https")) {
    categories.add("exposures");
    categories.add("technologies");
    categories.add("default-logins");
    tags.add("apache"); tags.add("nginx"); tags.add("iis");
  }
  if (services.has("ssh")) {
    tags.add("ssh");
    categories.add("default-logins");
  }
  if (services.has("ftp")) {
    tags.add("ftp");
    categories.add("default-logins");
  }
  if (services.has("smtp") || services.has("pop3") || services.has("imap")) {
    tags.add("mail");
  }
  if (services.has("mysql") || services.has("postgresql") || services.has("mssql") || services.has("mongodb") || services.has("redis")) {
    tags.add("database");
    categories.add("default-logins");
  }
  if (services.has("dns")) {
    categories.add("dns");
  }
  if (services.has("ssl") || services.has("https")) {
    categories.add("ssl");
  }

  // Analyze fingerprinter results for additional context
  if (Array.isArray(fingerprintOutput)) {
    for (const result of fingerprintOutput) {
      if (result.riskIndicators?.length > 0) {
        categories.add("vulnerabilities");
      }
      if (result.potentialCves?.length > 0) {
        categories.add("cves");
      }
    }
  }

  return {
    categories: Array.from(categories),
    tags: Array.from(tags),
  };
}

// ─── Chain Execution Engine ─────────────────────────────────────────

/** In-memory store for chain runs */
const chainRuns = new Map<string, ChainRun>();
const MAX_CHAIN_RUNS = 100;

/**
 * Create a new chain run with initial state.
 */
export function createChainRun(config: ChainRunConfig): ChainRun {
  const id = `chain-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;

  const stages: ChainStageResult[] = CHAIN_STAGES.map(stage => ({
    stageId: stage.id,
    status: config.skipStages?.includes(stage.id) ? "skipped" : "pending",
    startedAt: 0,
    inputTargetCount: 0,
    outputCount: 0,
    errors: [],
    findings: [],
    rawOutput: null,
  }));

  const run: ChainRun = {
    id,
    config,
    status: "pending",
    stages,
    allFindings: [],
    summary: createEmptySummary(),
    startedAt: Date.now(),
    progress: 0,
    cancelled: false,
  };

  // Enforce max runs
  if (chainRuns.size >= MAX_CHAIN_RUNS) {
    const oldest = Array.from(chainRuns.entries())
      .sort((a, b) => a[1].startedAt - b[1].startedAt)[0];
    if (oldest) chainRuns.delete(oldest[0]);
  }

  chainRuns.set(id, run);
  return run;
}

/**
 * Get a chain run by ID.
 */
export function getChainRun(id: string): ChainRun | undefined {
  return chainRuns.get(id);
}

/**
 * Get all chain runs with optional filtering.
 */
export function getChainRuns(filter?: {
  status?: ChainRunStatus;
  engagementId?: number;
  limit?: number;
  offset?: number;
}): { total: number; runs: ChainRun[] } {
  let runs = Array.from(chainRuns.values()).sort((a, b) => b.startedAt - a.startedAt);

  if (filter?.status) {
    runs = runs.filter(r => r.status === filter.status);
  }
  if (filter?.engagementId) {
    runs = runs.filter(r => r.config.engagementId === filter.engagementId);
  }

  const total = runs.length;
  const offset = filter?.offset || 0;
  const limit = filter?.limit || 25;

  return {
    total,
    runs: runs.slice(offset, offset + limit),
  };
}

/**
 * Cancel a running chain.
 */
export function cancelChainRun(id: string): boolean {
  const run = chainRuns.get(id);
  if (!run || run.status !== "running") return false;

  run.cancelled = true;
  run.status = "cancelled";
  run.completedAt = Date.now();
  run.durationMs = run.completedAt - run.startedAt;

  // Mark any running stages as cancelled
  for (const stage of run.stages) {
    if (stage.status === "running") {
      stage.status = "cancelled";
      stage.completedAt = Date.now();
      stage.durationMs = stage.completedAt - stage.startedAt;
    }
  }

  return true;
}

/**
 * Update a stage's result in a chain run.
 */
export function updateStageResult(
  runId: string,
  stageId: ChainStageId,
  update: Partial<ChainStageResult>
): void {
  const run = chainRuns.get(runId);
  if (!run) return;

  const stage = run.stages.find(s => s.stageId === stageId);
  if (!stage) return;

  Object.assign(stage, update);

  // Recalculate progress
  const completedStages = run.stages.filter(
    s => s.status === "completed" || s.status === "skipped" || s.status === "failed"
  ).length;
  run.progress = Math.round((completedStages / run.stages.length) * 100);

  // Update current stage
  const runningStage = run.stages.find(s => s.status === "running");
  run.currentStage = runningStage?.stageId;

  // Aggregate findings
  run.allFindings = run.stages.flatMap(s => s.findings);
  run.summary = computeChainSummary(run);
}

/**
 * Mark a chain run as completed.
 */
export function completeChainRun(runId: string, status: "completed" | "failed"): void {
  const run = chainRuns.get(runId);
  if (!run) return;

  run.status = status;
  run.completedAt = Date.now();
  run.durationMs = run.completedAt - run.startedAt;
  run.progress = 100;
  run.allFindings = run.stages.flatMap(s => s.findings);
  run.summary = computeChainSummary(run);
}

// ─── Summary Computation ────────────────────────────────────────────

function createEmptySummary(): ChainRunSummary {
  return {
    totalSubdomains: 0,
    totalHosts: 0,
    totalOpenPorts: 0,
    totalServices: 0,
    totalVulnerabilities: 0,
    totalFindings: 0,
    findingsBySeverity: {},
    findingsByStage: { amass: 0, nmap: 0, service_fingerprinter: 0, nuclei: 0 },
    stagesCompleted: 0,
    stagesTotal: 4,
    stagesFailed: 0,
    stagesSkipped: 0,
    uniqueCves: [],
    attackTechniques: [],
  };
}

export function computeChainSummary(run: ChainRun): ChainRunSummary {
  const allFindings = run.stages.flatMap(s => s.findings);
  const findingsBySeverity: Record<string, number> = {};
  const findingsByStage: Record<ChainStageId, number> = {
    amass: 0, nmap: 0, service_fingerprinter: 0, nuclei: 0,
  };
  const cves = new Set<string>();
  const techniques = new Set<string>();

  let totalSubdomains = 0;
  let totalHosts = 0;
  let totalOpenPorts = 0;
  let totalServices = 0;
  let totalVulnerabilities = 0;

  for (const f of allFindings) {
    findingsBySeverity[f.severity] = (findingsBySeverity[f.severity] || 0) + 1;

    // Map tool back to stage
    const stageId = toolToStage(f.tool);
    if (stageId) findingsByStage[stageId] = (findingsByStage[stageId] || 0) + 1;

    if (f.cveId) cves.add(f.cveId);
    if (f.attackTechnique) techniques.add(f.attackTechnique);

    // Count by type
    if (f.evidence?.assetType === "subdomain") totalSubdomains++;
    if (f.evidence?.assetType === "ip" || f.evidence?.assetType === "port") totalHosts++;
    if (f.evidence?.ports) totalOpenPorts += f.evidence.ports.length;
    if (f.evidence?.assetType === "service" || f.evidence?.protocol) totalServices++;
    if (f.type === "vulnerability") totalVulnerabilities++;
  }

  return {
    totalSubdomains,
    totalHosts,
    totalOpenPorts,
    totalServices,
    totalVulnerabilities,
    totalFindings: allFindings.length,
    findingsBySeverity,
    findingsByStage,
    stagesCompleted: run.stages.filter(s => s.status === "completed").length,
    stagesTotal: run.stages.length,
    stagesFailed: run.stages.filter(s => s.status === "failed").length,
    stagesSkipped: run.stages.filter(s => s.status === "skipped").length,
    uniqueCves: Array.from(cves),
    attackTechniques: Array.from(techniques),
  };
}

function toolToStage(tool: ToolModule): ChainStageId | null {
  switch (tool) {
    case "amass": return "amass";
    case "nmap": return "nmap";
    case "service_fingerprinter": return "service_fingerprinter";
    case "nuclei_info":
    case "nuclei_vuln":
    case "nuclei_critical":
      return "nuclei";
    default:
      return null;
  }
}

// ─── Chain Execution Orchestration ──────────────────────────────────

/**
 * Execute the full discovery chain.
 * This is the main entry point that sequences all stages.
 * 
 * The actual tool execution is delegated to the caller via callbacks,
 * since the orchestrator doesn't directly import tool-specific modules
 * to maintain loose coupling.
 */
export interface ChainExecutionCallbacks {
  /** Execute Amass subdomain enumeration */
  executeAmass: (config: {
    domains: string[];
    mode: "passive" | "active";
    timeout?: number;
    maxSubdomains?: number;
    engagementId?: number;
    operatorId?: string;
  }) => Promise<{ subdomains: any[]; rawResult: any }>;

  /** Execute Nmap port scanning */
  executeNmap: (config: {
    targets: string[];
    profile: string;
    topPorts?: number;
    timeout?: number;
    engagementId?: number;
    operatorId?: string;
  }) => Promise<{ hosts: any[]; rawResult: any }>;

  /** Execute Service Fingerprinter */
  executeFingerprint: (config: {
    targets: Array<{ host: string; port: number; protocol?: string }>;
    timeout?: number;
    concurrency?: number;
    tryDefaultCreds?: boolean;
    engagementId?: number;
    operatorId?: string;
  }) => Promise<{ results: any[]; rawResult: any }>;

  /** Execute Nuclei vulnerability scanning */
  executeNuclei: (config: {
    targets: string[];
    categories?: string[];
    tags?: string[];
    severity?: string[];
    rateLimit?: number;
    timeout?: number;
    engagementId?: number;
    operatorId?: string;
  }) => Promise<{ findings: any[]; rawResult: any }>;

  /** Scope enforcement check */
  enforceScope: (config: {
    targets: string[];
    tool: string;
    engagementId: number;
    operatorId: string;
  }) => Promise<{ inScope: string[]; outOfScope: string[] }>;

  /** Progress callback */
  onProgress?: (run: ChainRun) => void;

  /** Stage completion callback */
  onStageComplete?: (run: ChainRun, stageId: ChainStageId) => void;
}

/**
 * Execute the discovery chain with the provided callbacks.
 * Returns the completed chain run.
 */
export async function executeChain(
  config: ChainRunConfig,
  callbacks: ChainExecutionCallbacks
): Promise<ChainRun> {
  const run = createChainRun(config);
  run.status = "running";

  const maxDuration = (config.maxDurationSec || 3600) * 1000;
  const deadline = run.startedAt + maxDuration;

  try {
    // ─── Stage 1: Amass ───────────────────────────────────────────
    const amassStage = run.stages.find(s => s.stageId === "amass")!;
    if (amassStage.status !== "skipped") {
      if (run.cancelled || Date.now() > deadline) {
        throw new ChainTimeoutError("Chain cancelled or timed out before Amass stage");
      }

      amassStage.status = "running";
      amassStage.startedAt = Date.now();
      amassStage.inputTargetCount = config.domains.length;
      run.currentStage = "amass";
      callbacks.onProgress?.(run);

      try {
        const amassConfig = config.stageConfig?.amass;
        const amassResult = await callbacks.executeAmass({
          domains: config.domains,
          mode: amassConfig?.mode || "passive",
          timeout: amassConfig?.timeout,
          maxSubdomains: amassConfig?.maxSubdomains,
          engagementId: config.engagementId,
          operatorId: config.operatorId,
        });

        amassStage.rawOutput = amassResult.rawResult;
        amassStage.outputCount = amassResult.subdomains.length;
        amassStage.status = "completed";
        amassStage.completedAt = Date.now();
        amassStage.durationMs = amassStage.completedAt - amassStage.startedAt;

        // Convert to pipeline findings
        const { convertAmassFindings } = await import("./unified-pipeline");
        amassStage.findings = convertAmassFindings(amassResult.subdomains, "enumeration");

        callbacks.onStageComplete?.(run, "amass");
      } catch (err: any) {
        amassStage.status = "failed";
        amassStage.completedAt = Date.now();
        amassStage.durationMs = amassStage.completedAt - amassStage.startedAt;
        amassStage.errors.push(err.message || "Amass execution failed");

        if (!config.continueOnPartialFailure) {
          throw err;
        }
      }

      updateStageResult(run.id, "amass", amassStage);
      callbacks.onProgress?.(run);
    }

    // ─── Stage 2: Nmap ────────────────────────────────────────────
    const nmapStage = run.stages.find(s => s.stageId === "nmap")!;
    if (nmapStage.status !== "skipped") {
      if (run.cancelled || Date.now() > deadline) {
        throw new ChainTimeoutError("Chain cancelled or timed out before Nmap stage");
      }

      // Extract targets from Amass output + seed IPs + original domains
      let nmapTargets: string[] = [...config.domains];
      if (config.seedIps) nmapTargets.push(...config.seedIps);

      if (amassStage.rawOutput) {
        const amassTargets = extractNmapTargetsFromAmass(amassStage.rawOutput);
        nmapTargets.push(...amassTargets);
      }
      nmapTargets = Array.from(new Set(nmapTargets));

      // Scope enforcement
      if (config.engagementId && callbacks.enforceScope) {
        try {
          const scopeResult = await callbacks.enforceScope({
            targets: nmapTargets,
            tool: "nmap_chain",
            engagementId: config.engagementId,
            operatorId: config.operatorId || "system",
          });
          nmapTargets = scopeResult.inScope;
        } catch {
          // Continue with original targets if scope check fails
        }
      }

      nmapStage.status = "running";
      nmapStage.startedAt = Date.now();
      nmapStage.inputTargetCount = nmapTargets.length;
      run.currentStage = "nmap";
      callbacks.onProgress?.(run);

      try {
        const nmapConfig = config.stageConfig?.nmap;
        const nmapResult = await callbacks.executeNmap({
          targets: nmapTargets,
          profile: nmapConfig?.profile || "standard",
          topPorts: nmapConfig?.topPorts,
          timeout: nmapConfig?.timeout,
          engagementId: config.engagementId,
          operatorId: config.operatorId,
        });

        nmapStage.rawOutput = nmapResult.rawResult;
        nmapStage.outputCount = nmapResult.hosts.length;
        nmapStage.status = "completed";
        nmapStage.completedAt = Date.now();
        nmapStage.durationMs = nmapStage.completedAt - nmapStage.startedAt;

        // Convert to pipeline findings
        const { convertNmapFindings } = await import("./unified-pipeline");
        nmapStage.findings = convertNmapFindings(nmapResult.hosts, "enumeration");

        callbacks.onStageComplete?.(run, "nmap");
      } catch (err: any) {
        nmapStage.status = "failed";
        nmapStage.completedAt = Date.now();
        nmapStage.durationMs = nmapStage.completedAt - nmapStage.startedAt;
        nmapStage.errors.push(err.message || "Nmap execution failed");

        if (!config.continueOnPartialFailure) {
          throw err;
        }
      }

      updateStageResult(run.id, "nmap", nmapStage);
      callbacks.onProgress?.(run);
    }

    // ─── Stage 3: Service Fingerprinter ───────────────────────────
    const fpStage = run.stages.find(s => s.stageId === "service_fingerprinter")!;
    if (fpStage.status !== "skipped") {
      if (run.cancelled || Date.now() > deadline) {
        throw new ChainTimeoutError("Chain cancelled or timed out before Service Fingerprinter stage");
      }

      // Extract targets from Nmap output
      let fpTargets: Array<{ host: string; port: number; protocol?: string }> = [];
      if (nmapStage.rawOutput) {
        fpTargets = extractFingerprintTargetsFromNmap(nmapStage.rawOutput);
      }

      if (fpTargets.length === 0) {
        fpStage.status = "skipped";
        fpStage.errors.push("No fingerprintable services found in Nmap results");
        updateStageResult(run.id, "service_fingerprinter", fpStage);
      } else {
        fpStage.status = "running";
        fpStage.startedAt = Date.now();
        fpStage.inputTargetCount = fpTargets.length;
        run.currentStage = "service_fingerprinter";
        callbacks.onProgress?.(run);

        try {
          const fpConfig = config.stageConfig?.service_fingerprinter;
          const fpResult = await callbacks.executeFingerprint({
            targets: fpTargets,
            timeout: fpConfig?.timeout,
            concurrency: fpConfig?.concurrency,
            tryDefaultCreds: fpConfig?.tryDefaultCreds,
            engagementId: config.engagementId,
            operatorId: config.operatorId,
          });

          fpStage.rawOutput = fpResult.rawResult;
          fpStage.outputCount = fpResult.results.filter((r: any) => !r.error).length;
          fpStage.status = "completed";
          fpStage.completedAt = Date.now();
          fpStage.durationMs = fpStage.completedAt - fpStage.startedAt;

          // Convert to pipeline findings
          const { convertFingerprintFindings } = await import("./unified-pipeline");
          fpStage.findings = convertFingerprintFindings(fpResult.results, "enumeration");

          // ─── Auto-test OEM credentials against fingerprinted services ───
          try {
            const { enrichFingerprintsWithCredentialTests } = await import("./credential-tester");
            const fpResultsForCredTest = (fpResult.results || []).filter((r: any) => r.host && r.port && r.protocol);
            if (fpResultsForCredTest.length > 0) {
              console.log(`[DiscoveryChain] Running OEM credential tests against ${fpResultsForCredTest.length} fingerprinted services`);
              const credTestResult = await enrichFingerprintsWithCredentialTests(
                fpResultsForCredTest,
                [], // technologies extracted from fingerprints themselves
                { engagementId: config.engagementId, operatorId: config.operatorId },
              );
              const successCount = credTestResult.credentialResults.successfulLogins;
              if (successCount > 0) {
                console.log(`[DiscoveryChain] ✓ ${successCount} default credential(s) confirmed across fingerprinted services`);
              } else {
                console.log(`[DiscoveryChain] No default credentials confirmed (${credTestResult.credentialResults.totalCredentialsTested} tested)`);
              }
              // Store credential test summary in fingerprinter stage metadata
              fpStage.rawOutput = {
                ...((typeof fpStage.rawOutput === 'object' && fpStage.rawOutput) || { results: fpResult.results }),
                credentialTestSummary: {
                  totalTested: credTestResult.credentialResults.totalCredentialsTested,
                  successfulLogins: successCount,
                  failedAttempts: credTestResult.credentialResults.failedAttempts,
                  timeouts: credTestResult.credentialResults.timeouts,
                  errors: credTestResult.credentialResults.errors,
                },
              };
            }
          } catch (credErr: any) {
            console.warn(`[DiscoveryChain] Credential testing failed (non-fatal): ${credErr.message}`);
          }

          callbacks.onStageComplete?.(run, "service_fingerprinter");
        } catch (err: any) {
          fpStage.status = "failed";
          fpStage.completedAt = Date.now();
          fpStage.durationMs = fpStage.completedAt - fpStage.startedAt;
          fpStage.errors.push(err.message || "Service fingerprinting failed");

          if (!config.continueOnPartialFailure) {
            throw err;
          }
        }

        updateStageResult(run.id, "service_fingerprinter", fpStage);
        callbacks.onProgress?.(run);
      }
    }

    // ─── Stage 4: Nuclei ──────────────────────────────────────────
    const nucleiStage = run.stages.find(s => s.stageId === "nuclei")!;
    if (nucleiStage.status !== "skipped") {
      if (run.cancelled || Date.now() > deadline) {
        throw new ChainTimeoutError("Chain cancelled or timed out before Nuclei stage");
      }

      // Extract targets from Nmap + Fingerprinter
      let nucleiTargets = extractNucleiTargetsFromResults(
        nmapStage.rawOutput,
        fpStage.rawOutput
      );

      // Add seed URLs
      if (config.seedUrls) {
        nucleiTargets = Array.from(new Set([...nucleiTargets, ...config.seedUrls]));
      }

      if (nucleiTargets.length === 0) {
        nucleiStage.status = "skipped";
        nucleiStage.errors.push("No scannable targets found from prior stages");
        updateStageResult(run.id, "nuclei", nucleiStage);
      } else {
        // Select templates based on discovered services
        const templateSelection = selectNucleiTemplates(nmapStage.rawOutput, fpStage.rawOutput);

        nucleiStage.status = "running";
        nucleiStage.startedAt = Date.now();
        nucleiStage.inputTargetCount = nucleiTargets.length;
        run.currentStage = "nuclei";
        callbacks.onProgress?.(run);

        try {
          const nucleiConfig = config.stageConfig?.nuclei;
          const nucleiResult = await callbacks.executeNuclei({
            targets: nucleiTargets,
            categories: nucleiConfig?.templateCategories || templateSelection.categories,
            tags: templateSelection.tags,
            severity: nucleiConfig?.severity,
            rateLimit: nucleiConfig?.rateLimit,
            timeout: nucleiConfig?.timeout,
            engagementId: config.engagementId,
            operatorId: config.operatorId,
          });

          nucleiStage.rawOutput = nucleiResult.rawResult;
          nucleiStage.outputCount = nucleiResult.findings.length;
          nucleiStage.status = "completed";
          nucleiStage.completedAt = Date.now();
          nucleiStage.durationMs = nucleiStage.completedAt - nucleiStage.startedAt;

          // Convert to pipeline findings
          const { convertNucleiFindings } = await import("./unified-pipeline");
          nucleiStage.findings = convertNucleiFindings(nucleiResult.findings, "vulnerability_assessment");

          callbacks.onStageComplete?.(run, "nuclei");
        } catch (err: any) {
          nucleiStage.status = "failed";
          nucleiStage.completedAt = Date.now();
          nucleiStage.durationMs = nucleiStage.completedAt - nucleiStage.startedAt;
          nucleiStage.errors.push(err.message || "Nuclei scanning failed");

          if (!config.continueOnPartialFailure) {
            throw err;
          }
        }

        updateStageResult(run.id, "nuclei", nucleiStage);
        callbacks.onProgress?.(run);
      }
    }

    // ─── Complete ─────────────────────────────────────────────────
    const anyFailed = run.stages.some(s => s.status === "failed");
    completeChainRun(run.id, anyFailed && !config.continueOnPartialFailure ? "failed" : "completed");

  } catch (err: any) {
    // Mark remaining pending stages as cancelled
    for (const stage of run.stages) {
      if (stage.status === "pending" || stage.status === "running") {
        stage.status = "cancelled";
        stage.completedAt = Date.now();
        if (stage.startedAt) stage.durationMs = stage.completedAt - stage.startedAt;
        stage.errors.push(err.message || "Chain execution aborted");
      }
    }
    completeChainRun(run.id, "failed");
  }

  return chainRuns.get(run.id)!;
}

// ─── Error Types ────────────────────────────────────────────────────

export class ChainTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ChainTimeoutError";
  }
}

export class ChainScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ChainScopeError";
  }
}

// ─── Utility ────────────────────────────────────────────────────────

/**
 * Get the chain stage definitions (for UI display).
 */
export function getChainStageDefinitions(): ChainStageDefinition[] {
  return [...CHAIN_STAGES];
}

/**
 * Estimate total chain duration based on target count and configuration.
 */
export function estimateChainDuration(config: ChainRunConfig): {
  totalSeconds: number;
  byStage: Record<ChainStageId, number>;
} {
  const domainCount = config.domains.length;
  const skipStages = new Set(config.skipStages || []);

  const byStage: Record<ChainStageId, number> = {
    amass: skipStages.has("amass") ? 0 : 120 * domainCount,
    nmap: skipStages.has("nmap") ? 0 : 300 * domainCount,
    service_fingerprinter: skipStages.has("service_fingerprinter") ? 0 : 180,
    nuclei: skipStages.has("nuclei") ? 0 : 600,
  };

  // Adjust based on profile
  if (config.stageConfig?.nmap?.profile === "quick") {
    byStage.nmap = Math.round(byStage.nmap * 0.3);
  } else if (config.stageConfig?.nmap?.profile === "deep") {
    byStage.nmap = Math.round(byStage.nmap * 2);
  }

  return {
    totalSeconds: Object.values(byStage).reduce((a, b) => a + b, 0),
    byStage,
  };
}
