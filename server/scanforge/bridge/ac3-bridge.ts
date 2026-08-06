/**
 * AC3 Bridge — ScanForge ↔ Engagement Orchestrator Integration
 *
 * This module bridges the existing AC3 engagement orchestrator with the
 * ScanForge engine. It provides:
 *
 *   1. A drop-in replacement for scan-server-executor.ts that routes scans
 *      through the ScanForge API instead of SSH commands.
 *   2. Result translation from ScanForge findings to the AC3 engagement
 *      data format (passiveRecon, activeRecon, vulnFindings, etc.).
 *   3. WebSocket event forwarding to the engagement ops WebSocket.
 *
 * Migration path:
 *   - Phase 1: ScanForge runs alongside existing scanners (dual-write)
 *   - Phase 2: ScanForge becomes primary, SSH fallback for unsupported tools
 *   - Phase 3: Full ScanForge, SSH executor deprecated
 */

import type {
  ScanRequest,
  ScanTarget,
  ScanFinding,
  ScanJob,
  FindingSeverity,
} from "../types";
import { getScanQueue } from "../queue/scan-queue";
import { randomUUID } from "crypto";

// ─── AC3 Engagement Data Types ─────────────────────────────────────────────

interface AC3Finding {
  id: string;
  title: string;
  description: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Informational";
  cvss?: number;
  cves?: string[];
  cwes?: string[];
  evidence?: string;
  remediation?: string;
  source: string;
  port?: number;
  protocol?: string;
  status: "open" | "confirmed" | "false_positive" | "remediated";
  foundAt: number;
  riskScore?: number;
  attackTechniques?: string[];
}

interface AC3ScanResult {
  scanner: string;
  status: "success" | "error" | "timeout";
  duration: number;
  findingCount: number;
  error?: string;
  rawOutput?: string;
}

// ─── Severity Mapping ──────────────────────────────────────────────────────

const SEVERITY_MAP: Record<FindingSeverity, AC3Finding["severity"]> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Informational",
};

// ─── Bridge Class ──────────────────────────────────────────────────────────

export class AC3ScanForgeBridge {
  private activeScanIds: Map<number, string> = new Map(); // engagementId -> scanId

  /**
   * Execute a scan via ScanForge for an AC3 engagement.
   * This is the primary entry point that replaces SSH-based scan execution.
   */
  async executeScan(params: {
    engagementId: number;
    target: string;
    targetType?: "domain" | "ip" | "cidr" | "url";
    scanType?: "quick" | "web" | "network" | "full" | "recon";
    ports?: number[];
    services?: Record<number, string>;
    industry?: string;
    priority?: "critical" | "high" | "medium" | "low";
    callbackUrl?: string;
  }): Promise<{ scanId: string; status: string }> {
    const scanTarget: ScanTarget = {
      type: params.targetType || "domain",
      value: params.target,
      ports: params.ports,
      services: params.services,
    };

    const request: ScanRequest = {
      id: randomUUID(),
      engagementId: params.engagementId,
      type: params.scanType || "full",
      priority: params.priority || "medium",
      targets: [scanTarget],
      config: {
        maxConcurrency: 3,
        timeoutSeconds: 1800,
        scannerTimeoutSeconds: 300,
        mode: "active",
      },
      intelligence: {
        useKEV: true,
        useEPSS: true,
        useThreatActors: true,
        useDFIR: true,
        targetIndustry: params.industry,
      },
      callbackUrl: params.callbackUrl,
      createdAt: Date.now(),
    };

    const queue = getScanQueue();
    const job = queue.enqueue(request);

    this.activeScanIds.set(params.engagementId, request.id);

    return {
      scanId: request.id,
      status: job.status,
    };
  }

  /**
   * Get scan progress for an engagement.
   */
  getScanProgress(engagementId: number): {
    scanId: string | null;
    status: string;
    progress: number;
    currentScanner: string | null;
    findingCount: number;
  } {
    const scanId = this.activeScanIds.get(engagementId);
    if (!scanId) {
      return {
        scanId: null,
        status: "not_found",
        progress: 0,
        currentScanner: null,
        findingCount: 0,
      };
    }

    const queue = getScanQueue();
    const job = queue.getJob(scanId);
    if (!job) {
      return {
        scanId,
        status: "not_found",
        progress: 0,
        currentScanner: null,
        findingCount: 0,
      };
    }

    return {
      scanId,
      status: job.status,
      progress: job.progress,
      currentScanner: job.currentScanner || null,
      findingCount: job.findings.length,
    };
  }

  /**
   * Convert ScanForge findings to AC3 engagement findings format.
   */
  translateFindings(findings: ScanFinding[]): AC3Finding[] {
    return findings.map(f => ({
      id: f.id,
      title: f.title,
      description: f.description,
      severity: SEVERITY_MAP[f.severity] || "Informational",
      cvss: f.riskScore?.cvss,
      cves: f.cves,
      cwes: f.cwes,
      evidence: f.evidence?.request
        ? `Request:\n${f.evidence.request}\n\nResponse:\n${f.evidence.response || "N/A"}`
        : f.evidence?.matchedPattern || undefined,
      remediation: f.remediation,
      source: `ScanForge:${f.source}`,
      port: f.port,
      protocol: f.protocol,
      status: "open" as const,
      foundAt: f.foundAt,
      riskScore: f.riskScore?.composite,
      attackTechniques: f.techniqueIds,
    }));
  }

  /**
   * Convert ScanForge scanner results to AC3 scan result format.
   */
  translateScannerResults(job: ScanJob): AC3ScanResult[] {
    return job.scannerResults.map(r => ({
      scanner: r.scanner,
      status: r.status === "completed" ? "success"
        : r.status === "timeout" ? "timeout"
        : "error",
      duration: r.durationMs,
      findingCount: r.findingCount,
      error: r.error,
    }));
  }

  /**
   * Cancel an active scan for an engagement.
   */
  cancelScan(engagementId: number): boolean {
    const scanId = this.activeScanIds.get(engagementId);
    if (!scanId) return false;

    const queue = getScanQueue();
    const success = queue.cancel(scanId);

    if (success) {
      this.activeScanIds.delete(engagementId);
    }

    return success;
  }

  /**
   * Get the full scan job for an engagement.
   */
  getFullScanJob(engagementId: number): ScanJob | null {
    const scanId = this.activeScanIds.get(engagementId);
    if (!scanId) return null;

    const queue = getScanQueue();
    return queue.getJob(scanId) || null;
  }
}

// ─── Singleton ─────────────────────────────────────────────────────────────

let _bridge: AC3ScanForgeBridge | null = null;

export function getAC3Bridge(): AC3ScanForgeBridge {
  if (!_bridge) {
    _bridge = new AC3ScanForgeBridge();
  }
  return _bridge;
}
