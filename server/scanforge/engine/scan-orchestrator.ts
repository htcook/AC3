/**
 * ScanForge Scan Orchestrator
 *
 * Coordinates the full scan lifecycle across multiple phases:
 *   1. Recon — Port scanning, service detection, technology fingerprinting
 *   2. Enumeration — Directory brute-force, subdomain enumeration
 *   3. Detection — Template execution, protocol scanning, vulnerability checks
 *   4. Verification — Re-test findings for false positive reduction
 *   5. Reporting — Aggregate results, compute risk scores, generate summary
 *
 * The orchestrator manages scanner concurrency within a single scan job,
 * routes targets to appropriate protocol scanners, and applies TI enrichment
 * at each phase to prioritize the most impactful checks.
 */

import { randomUUID } from "crypto";
import type {
  ScanJob,
  ScanTarget,
  ScanFinding,
  ScannerResult,
  ScanConfig,
  ScanPhase,
  FindingSeverity,
  RiskScore,
} from "../types";
import { ScanQueue } from "../queue/scan-queue";
import { getTemplateEngine, TemplateEngine } from "./template-engine";
import { getProtocolRegistry, ProtocolRegistry } from "../protocols/registry";
import { getIntelligenceEngine, IntelligenceEngine } from "../intelligence/ti-engine";

// ─── Phase Configuration ───────────────────────────────────────────────────

interface PhaseConfig {
  /** Max time for this phase in ms */
  timeoutMs: number;
  /** Max concurrent operations within this phase */
  concurrency: number;
}

const PHASE_DEFAULTS: Record<ScanPhase, PhaseConfig> = {
  recon: { timeoutMs: 120_000, concurrency: 5 },
  enumeration: { timeoutMs: 180_000, concurrency: 3 },
  detection: { timeoutMs: 600_000, concurrency: 5 },
  verification: { timeoutMs: 120_000, concurrency: 3 },
  reporting: { timeoutMs: 30_000, concurrency: 1 },
};

// ─── Orchestrator ──────────────────────────────────────────────────────────

export class ScanOrchestrator {
  private queue: ScanQueue;
  private templates: TemplateEngine;
  private protocols: ProtocolRegistry;
  private intelligence: IntelligenceEngine;

  constructor(queue: ScanQueue) {
    this.queue = queue;
    this.templates = getTemplateEngine();
    this.protocols = getProtocolRegistry();
    this.intelligence = getIntelligenceEngine();

    // Register as the queue processor
    this.queue.setProcessor(this.processJob.bind(this));
  }

  /**
   * Initialize the orchestrator — load templates and TI feeds.
   */
  async initialize(): Promise<void> {
    await this.templates.loadTemplates();
    await this.intelligence.initialize();
    console.log(`[ScanOrchestrator] Initialized: ${this.templates.count} templates, ${this.protocols.count} protocol scanners`);
  }

  /**
   * Process a scan job through all phases.
   */
  private async processJob(job: ScanJob): Promise<void> {
    const scanId = job.request.id;
    const config = job.request.config || {};

    console.log(`[ScanOrchestrator] Processing scan ${scanId}: type=${job.request.type}, targets=${job.request.targets.length}`);

    try {
      // Phase 1: Recon
      await this.runPhase(job, "recon", async () => {
        await this.phaseRecon(job);
      });

      // Phase 2: Enumeration (skip for quick scans)
      if (job.request.type !== "quick" && job.request.type !== "recon") {
        await this.runPhase(job, "enumeration", async () => {
          await this.phaseEnumeration(job);
        });
      }

      // Phase 3: Detection
      if (job.request.type !== "recon") {
        await this.runPhase(job, "detection", async () => {
          await this.phaseDetection(job);
        });
      }

      // Phase 4: Verification (skip for quick scans)
      if (job.request.type !== "quick" && job.request.type !== "recon") {
        await this.runPhase(job, "verification", async () => {
          await this.phaseVerification(job);
        });
      }

      // Phase 5: Reporting
      await this.runPhase(job, "reporting", async () => {
        await this.phaseReporting(job);
      });

    } catch (err: any) {
      console.error(`[ScanOrchestrator] Scan ${scanId} error: ${err.message}`);
      throw err;
    }
  }

  // ─── Phase Implementations ─────────────────────────────────────────────

  /**
   * Phase 1: Reconnaissance
   * - Port scanning via nmap/naabu
   * - Service detection
   * - Technology fingerprinting
   */
  private async phaseRecon(job: ScanJob): Promise<void> {
    const scanId = job.request.id;

    for (const target of job.request.targets) {
      const startTime = Date.now();

      try {
        // Use existing scan-server-executor for nmap
        const { executeTool } = await import("../../lib/scan-server-executor");

        // Quick port scan
        const nmapResult = await executeTool({
          tool: "nmap",
          args: `-sV -sC --top-ports 1000 -T4 --open ${target.value}`,
          target: target.value,
          timeoutSeconds: 90,
          engagementId: job.request.engagementId,
        });

        // Parse nmap output to discover ports and services
        const discovered = this.parseNmapOutput(nmapResult.stdout);
        target.ports = discovered.ports;
        target.services = discovered.services;

        this.queue.addScannerResult(scanId, {
          scanner: "nmap-recon",
          status: nmapResult.exitCode === 0 ? "completed" : "failed",
          durationMs: Date.now() - startTime,
          findingCount: 0,
          error: nmapResult.exitCode !== 0 ? nmapResult.stderr : undefined,
        });

        // Technology fingerprinting via httpx (for web targets)
        if (target.type === "domain" || target.type === "url") {
          const httpxResult = await executeTool({
            tool: "httpx",
            args: `-u ${target.value} -tech-detect -status-code -title -json`,
            target: target.value,
            timeoutSeconds: 30,
            engagementId: job.request.engagementId,
          });

          if (httpxResult.exitCode === 0 && httpxResult.stdout) {
            // Parse httpx JSON output for technologies
            try {
              const lines = httpxResult.stdout.trim().split("\n");
              for (const line of lines) {
                const data = JSON.parse(line);
                if (data.tech) {
                  target.services = target.services || {};
                  target.services[443] = `https (${data.tech.join(", ")})`;
                }
              }
            } catch { /* non-JSON output, skip */ }
          }
        }

        console.log(`[ScanOrchestrator] Recon for ${target.value}: ${target.ports?.length || 0} ports, ${Object.keys(target.services || {}).length} services`);

      } catch (err: any) {
        console.warn(`[ScanOrchestrator] Recon failed for ${target.value}: ${err.message}`);
        this.queue.addScannerResult(scanId, {
          scanner: "nmap-recon",
          status: "failed",
          durationMs: Date.now() - startTime,
          findingCount: 0,
          error: err.message,
        });
      }
    }
  }

  /**
   * Phase 2: Enumeration
   * - Directory brute-force
   * - Subdomain enumeration
   * - DNS records
   */
  private async phaseEnumeration(job: ScanJob): Promise<void> {
    const scanId = job.request.id;

    for (const target of job.request.targets) {
      if (target.type !== "domain" && target.type !== "url") continue;

      const startTime = Date.now();

      try {
        const { executeTool } = await import("../../lib/scan-server-executor");

        // Directory brute-force with gobuster
        const gobusterResult = await executeTool({
          tool: "gobuster",
          args: `dir -u https://${target.value} -w /usr/share/wordlists/dirb/common.txt -t 20 -q --no-error`,
          target: target.value,
          timeoutSeconds: 120,
          engagementId: job.request.engagementId,
        });

        const dirFindings = this.parseGobusterOutput(gobusterResult.stdout, target);
        for (const f of dirFindings) {
          this.queue.addFinding(scanId, f);
        }

        this.queue.addScannerResult(scanId, {
          scanner: "gobuster-enum",
          status: gobusterResult.exitCode === 0 ? "completed" : "failed",
          durationMs: Date.now() - startTime,
          findingCount: dirFindings.length,
        });

      } catch (err: any) {
        this.queue.addScannerResult(scanId, {
          scanner: "gobuster-enum",
          status: "failed",
          durationMs: Date.now() - startTime,
          findingCount: 0,
          error: err.message,
        });
      }
    }
  }

  /**
   * Phase 3: Detection
   * - Execute relevant templates based on discovered services
   * - Run protocol-specific scanners
   * - Apply TI-informed template selection
   */
  private async phaseDetection(job: ScanJob): Promise<void> {
    const scanId = job.request.id;
    const config = job.request.config || {};

    for (const target of job.request.targets) {
      // Step 1: Select templates based on target, services, and TI enrichment
      let selectedTemplates = this.selectTemplates(job, target);

      // Step 2: TI-informed prioritization
      if (job.request.intelligence) {
        selectedTemplates = await this.intelligence.prioritizeTemplates(
          selectedTemplates,
          target,
          job.request.intelligence
        );
      }

      console.log(`[ScanOrchestrator] Detection for ${target.value}: ${selectedTemplates.length} templates selected`);

      // Step 3: Execute templates with concurrency control
      const concurrency = config.maxConcurrency || PHASE_DEFAULTS.detection.concurrency;
      const batches = this.chunk(selectedTemplates, concurrency);
      let completed = 0;

      for (const batch of batches) {
        const results = await Promise.allSettled(
          batch.map(async (template) => {
            const startTime = Date.now();
            try {
              const findings = await this.templates.execute(template, target, config);
              for (const f of findings) {
                this.queue.addFinding(scanId, f);
              }
              return { scanner: template.id, findings: findings.length, durationMs: Date.now() - startTime };
            } catch (err: any) {
              return { scanner: template.id, findings: 0, durationMs: Date.now() - startTime, error: err.message };
            }
          })
        );

        for (const r of results) {
          if (r.status === "fulfilled") {
            completed++;
            this.queue.addScannerResult(scanId, {
              scanner: r.value.scanner,
              status: r.value.error ? "failed" : "completed",
              durationMs: r.value.durationMs,
              findingCount: r.value.findings,
              error: r.value.error,
            });
          }
        }

        // Update progress
        const progress = Math.round((completed / selectedTemplates.length) * 60) + 20; // 20-80%
        this.queue.updateProgress(scanId, progress, `templates (${completed}/${selectedTemplates.length})`);
      }

      // Step 4: Run protocol-specific scanners for discovered services
      await this.runProtocolScanners(job, target);
    }
  }

  /**
   * Phase 4: Verification
   * - Re-test high/critical findings to reduce false positives
   * - Cross-reference with TI data
   */
  private async phaseVerification(job: ScanJob): Promise<void> {
    const scanId = job.request.id;
    const highFindings = job.findings.filter(
      f => f.severity === "critical" || f.severity === "high"
    );

    console.log(`[ScanOrchestrator] Verifying ${highFindings.length} high/critical findings`);

    for (const finding of highFindings) {
      // Enrich with TI data
      const enriched = await this.intelligence.enrichFinding(finding);
      if (enriched.riskScore) {
        finding.riskScore = enriched.riskScore;
      }
    }

    // Also compute risk scores for medium/low findings
    for (const finding of job.findings) {
      if (!finding.riskScore) {
        finding.riskScore = this.computeBaseRiskScore(finding);
      }
    }
  }

  /**
   * Phase 5: Reporting
   * - Sort findings by risk score
   * - Generate summary statistics
   */
  private async phaseReporting(job: ScanJob): Promise<void> {
    // Sort findings by composite risk score (highest first)
    job.findings.sort((a, b) => {
      const scoreA = a.riskScore?.composite || this.severityToScore(a.severity);
      const scoreB = b.riskScore?.composite || this.severityToScore(b.severity);
      return scoreB - scoreA;
    });

    // Deduplicate findings with same title+target
    const seen = new Set<string>();
    job.findings = job.findings.filter(f => {
      const key = `${f.title}:${f.target}:${f.port || ""}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    console.log(`[ScanOrchestrator] Reporting: ${job.findings.length} unique findings after dedup`);
  }

  // ─── Helpers ───────────────────────────────────────────────────────────

  private async runPhase(
    job: ScanJob,
    phase: ScanPhase,
    fn: () => Promise<void>
  ): Promise<void> {
    // Check if job was cancelled
    if (job.status === "cancelled") return;

    this.queue.setPhase(job.request.id, phase);
    const phaseConfig = PHASE_DEFAULTS[phase];

    const timeout = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(`Phase ${phase} timed out`)), phaseConfig.timeoutMs);
    });

    try {
      await Promise.race([fn(), timeout]);
    } catch (err: any) {
      console.warn(`[ScanOrchestrator] Phase ${phase} error: ${err.message}`);
      // Non-fatal — continue to next phase
    }
  }

  private selectTemplates(job: ScanJob, target: ScanTarget): any[] {
    const scanType = job.request.type;

    // If specific template IDs requested, use those
    if (job.request.templateIds?.length) {
      return job.request.templateIds
        .map(id => this.templates.get(id))
        .filter(Boolean) as any[];
    }

    // Select based on scan type and discovered services
    const protocols: string[] = [];

    if (scanType === "web" || scanType === "full" || scanType === "quick") {
      protocols.push("http", "https");
    }

    if (scanType === "network" || scanType === "full") {
      // Add protocols based on discovered services
      if (target.services) {
        for (const [port, service] of Object.entries(target.services)) {
          const proto = this.serviceToProtocol(service);
          if (proto && !protocols.includes(proto)) {
            protocols.push(proto);
          }
        }
      }
    }

    // Query templates for matching protocols
    let templates = protocols.flatMap(p => this.templates.query({ protocol: p }));

    // For quick scans, limit to critical/high severity templates
    if (scanType === "quick") {
      templates = templates.filter(t => t.severity === "critical" || t.severity === "high");
    }

    return templates;
  }

  private async runProtocolScanners(job: ScanJob, target: ScanTarget): Promise<void> {
    const scanId = job.request.id;
    if (!target.services || !target.ports?.length) return;

    for (const [portStr, service] of Object.entries(target.services)) {
      const port = parseInt(portStr, 10);
      const protocol = this.serviceToProtocol(service);
      if (!protocol) continue;

      const scanner = this.protocols.get(protocol);
      if (!scanner) continue;

      const startTime = Date.now();
      try {
        const findings = await scanner.scan(target, job.request.config);
        for (const f of findings) {
          f.port = port;
          this.queue.addFinding(scanId, f);
        }

        this.queue.addScannerResult(scanId, {
          scanner: `protocol:${protocol}`,
          status: "completed",
          durationMs: Date.now() - startTime,
          findingCount: findings.length,
        });
      } catch (err: any) {
        this.queue.addScannerResult(scanId, {
          scanner: `protocol:${protocol}`,
          status: "failed",
          durationMs: Date.now() - startTime,
          findingCount: 0,
          error: err.message,
        });
      }
    }
  }

  private parseNmapOutput(stdout: string): { ports: number[]; services: Record<number, string> } {
    const ports: number[] = [];
    const services: Record<number, string> = {};

    const lines = stdout.split("\n");
    for (const line of lines) {
      // Match: 22/tcp   open  ssh     OpenSSH 8.9p1
      const match = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)/);
      if (match) {
        const port = parseInt(match[1], 10);
        const service = `${match[3]} ${match[4] || ""}`.trim();
        ports.push(port);
        services[port] = service;
      }
    }

    return { ports, services };
  }

  private parseGobusterOutput(stdout: string, target: ScanTarget): ScanFinding[] {
    const findings: ScanFinding[] = [];
    const lines = stdout.split("\n");

    const sensitivePatterns = [
      /\/(admin|login|dashboard|config|backup|\.env|\.git|phpinfo|server-status)/i,
      /\/(wp-admin|wp-login|xmlrpc\.php|wp-config)/i,
      /\/(api|graphql|swagger|docs|debug)/i,
    ];

    for (const line of lines) {
      const match = line.match(/^(\/\S+)\s+\(Status:\s*(\d+)\)/);
      if (!match) continue;

      const path = match[1];
      const status = parseInt(match[2], 10);

      // Only report sensitive/interesting paths
      if (sensitivePatterns.some(p => p.test(path))) {
        findings.push({
          id: randomUUID(),
          source: "gobuster-enum",
          title: `Sensitive Path Discovered: ${path}`,
          description: `The path ${path} was discovered on ${target.value} with HTTP status ${status}. This may expose sensitive functionality or information.`,
          severity: path.match(/\.(env|git|config|backup)/i) ? "high" : "medium",
          confidence: 90,
          target: target.value,
          port: 443,
          protocol: "https",
          cwes: ["CWE-538"],
          evidence: {
            matchedPattern: path,
            data: { statusCode: status },
          },
          remediation: "Restrict access to sensitive paths using authentication or IP whitelisting. Remove unnecessary files and directories from the web root.",
          foundAt: Date.now(),
        });
      }
    }

    return findings;
  }

  private serviceToProtocol(service: string): string | null {
    const s = service.toLowerCase();
    if (s.includes("ssh")) return "ssh";
    if (s.includes("ftp")) return "ftp";
    if (s.includes("smtp") || s.includes("mail")) return "smtp";
    if (s.includes("dns") || s.includes("domain")) return "dns";
    if (s.includes("http") || s.includes("nginx") || s.includes("apache")) return "http";
    if (s.includes("mysql") || s.includes("mariadb")) return "mysql";
    if (s.includes("postgres")) return "postgresql";
    if (s.includes("redis")) return "redis";
    if (s.includes("mongo")) return "mongodb";
    if (s.includes("smb") || s.includes("microsoft-ds") || s.includes("netbios")) return "smb";
    if (s.includes("ldap")) return "ldap";
    if (s.includes("snmp")) return "snmp";
    if (s.includes("rdp") || s.includes("ms-wbt")) return "rdp";
    if (s.includes("vnc")) return "vnc";
    if (s.includes("telnet")) return "telnet";
    if (s.includes("rabbitmq") || s.includes("amqp")) return "amqp";
    if (s.includes("kafka")) return "kafka";
    return null;
  }

  private computeBaseRiskScore(finding: ScanFinding): RiskScore {
    const severityScore = this.severityToScore(finding.severity);
    return {
      composite: Math.round(severityScore * (finding.confidence / 100)),
      cvss: finding.severity === "critical" ? 9.0 : finding.severity === "high" ? 7.5 : finding.severity === "medium" ? 5.0 : 3.0,
    };
  }

  private severityToScore(severity: FindingSeverity): number {
    switch (severity) {
      case "critical": return 95;
      case "high": return 75;
      case "medium": return 50;
      case "low": return 25;
      case "info": return 10;
    }
  }

  private chunk<T>(arr: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < arr.length; i += size) {
      chunks.push(arr.slice(i, i + size));
    }
    return chunks;
  }
}
