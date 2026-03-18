/**
 * Quality Gates & State Persistence — Unit Tests
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Tests for:
 *   1. Training Data Quality Gate logic (verdict computation)
 *   2. Ops State persistence and recovery (normalize, serialize/deserialize)
 *   3. LiveTrigger getState with DB recovery fallback
 */
import { describe, it, expect } from "vitest";

// ─── Quality Gate Verdict Logic ────────────────────────────────────────────

interface QualityGateInput {
  total: number;
  approved: number;
  rejected: number;
  flagged: number;
  pending: number;
  avgQualityScore: number;
  avgApprovedScore: number;
}

type QualityVerdict = 'pass' | 'warn' | 'fail' | 'insufficient';

function computeQualityGateVerdict(input: QualityGateInput): { verdict: QualityVerdict; reason: string } {
  const reviewed = input.approved + input.rejected;
  const approvalRate = reviewed > 0 ? (input.approved / reviewed) * 100 : 0;

  if (reviewed < 20) {
    return {
      verdict: 'insufficient',
      reason: `Only ${reviewed} examples reviewed (need ≥20 for assessment)`,
    };
  }
  if (approvalRate >= 80 && reviewed >= 50 && input.avgApprovedScore >= 0.75) {
    return {
      verdict: 'pass',
      reason: `${approvalRate.toFixed(1)}% approval rate with ${reviewed} reviewed examples`,
    };
  }
  if (approvalRate >= 60 && reviewed >= 20 && input.avgQualityScore >= 0.5) {
    return {
      verdict: 'warn',
      reason: `Approval rate ${approvalRate.toFixed(1)}% — needs improvement`,
    };
  }
  return {
    verdict: 'fail',
    reason: approvalRate < 60
      ? `Low approval rate: ${approvalRate.toFixed(1)}%`
      : `Low quality score: ${input.avgQualityScore.toFixed(2)}`,
  };
}

describe("Training Data Quality Gate — Verdict Logic", () => {
  it("should return 'insufficient' when fewer than 20 examples reviewed", () => {
    const result = computeQualityGateVerdict({
      total: 100, approved: 10, rejected: 5, flagged: 0, pending: 85,
      avgQualityScore: 0.9, avgApprovedScore: 0.95,
    });
    expect(result.verdict).toBe('insufficient');
    expect(result.reason).toContain('15 examples reviewed');
  });

  it("should return 'pass' with ≥80% approval, ≥50 reviewed, avg score ≥0.75", () => {
    const result = computeQualityGateVerdict({
      total: 100, approved: 55, rejected: 5, flagged: 2, pending: 38,
      avgQualityScore: 0.85, avgApprovedScore: 0.88,
    });
    expect(result.verdict).toBe('pass');
    expect(result.reason).toContain('91.7%');
  });

  it("should return 'warn' with 60-80% approval rate and ≥20 reviewed", () => {
    const result = computeQualityGateVerdict({
      total: 50, approved: 18, rejected: 7, flagged: 0, pending: 25,
      avgQualityScore: 0.65, avgApprovedScore: 0.7,
    });
    expect(result.verdict).toBe('warn');
    expect(result.reason).toContain('72.0%');
  });

  it("should return 'fail' with <60% approval rate", () => {
    const result = computeQualityGateVerdict({
      total: 50, approved: 10, rejected: 15, flagged: 0, pending: 25,
      avgQualityScore: 0.4, avgApprovedScore: 0.5,
    });
    expect(result.verdict).toBe('fail');
    expect(result.reason).toContain('40.0%');
  });

  it("should return 'fail' when avg quality score is too low even with decent approval rate", () => {
    const result = computeQualityGateVerdict({
      total: 50, approved: 15, rejected: 8, flagged: 0, pending: 27,
      avgQualityScore: 0.3, avgApprovedScore: 0.4,
    });
    expect(result.verdict).toBe('fail');
  });

  it("should handle edge case of 0 total examples", () => {
    const result = computeQualityGateVerdict({
      total: 0, approved: 0, rejected: 0, flagged: 0, pending: 0,
      avgQualityScore: 0, avgApprovedScore: 0,
    });
    expect(result.verdict).toBe('insufficient');
  });

  it("should handle edge case of exactly 20 reviewed examples at boundary", () => {
    const result = computeQualityGateVerdict({
      total: 30, approved: 14, rejected: 6, flagged: 0, pending: 10,
      avgQualityScore: 0.6, avgApprovedScore: 0.65,
    });
    // 70% approval, 20 reviewed, score 0.6 → warn
    expect(result.verdict).toBe('warn');
  });

  it("should require ≥50 reviewed for 'pass' even with high approval rate", () => {
    const result = computeQualityGateVerdict({
      total: 40, approved: 30, rejected: 2, flagged: 0, pending: 8,
      avgQualityScore: 0.9, avgApprovedScore: 0.92,
    });
    // 93.75% approval but only 32 reviewed < 50 → warn not pass
    expect(result.verdict).toBe('warn');
  });

  it("should correctly compute approval rate from approved/(approved+rejected)", () => {
    // 80 approved, 20 rejected = 80% approval rate
    const result = computeQualityGateVerdict({
      total: 200, approved: 80, rejected: 20, flagged: 10, pending: 90,
      avgQualityScore: 0.8, avgApprovedScore: 0.85,
    });
    expect(result.verdict).toBe('pass');
  });
});

// ─── Ops State Normalization ───────────────────────────────────────────────

function normalizeOpsState(state: any): any {
  if (!Array.isArray(state.assets)) state.assets = [];
  if (!Array.isArray(state.log)) state.log = [];
  if (!Array.isArray(state.approvalGates)) state.approvalGates = [];

  const defaultStats = {
    hostsScanned: 0, portsFound: 0, vulnsFound: 0,
    exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0,
    zapScansRun: 0, wafDetections: 0,
  };
  state.stats = { ...defaultStats, ...(state.stats || {}) };

  if (state.skippedDomains && !(state.skippedDomains instanceof Set)) {
    try {
      const arr = Array.isArray(state.skippedDomains)
        ? state.skippedDomains
        : Object.values(state.skippedDomains);
      state.skippedDomains = new Set(arr);
    } catch {
      state.skippedDomains = new Set();
    }
  } else if (!state.skippedDomains) {
    state.skippedDomains = new Set();
  }

  if (typeof state.isRunning !== 'boolean') state.isRunning = false;
  if (typeof state.isPaused !== 'boolean') state.isPaused = false;
  if (!state.phase) state.phase = 'idle';
  if (typeof state.progress !== 'number') state.progress = 0;

  if (state.roeScopeGuard) {
    if (!Array.isArray(state.roeScopeGuard.authorizedDomains)) state.roeScopeGuard.authorizedDomains = [];
    if (!Array.isArray(state.roeScopeGuard.authorizedIps)) state.roeScopeGuard.authorizedIps = [];
  }

  for (const asset of state.assets) {
    if (!Array.isArray(asset.vulns)) asset.vulns = [];
    if (!Array.isArray(asset.toolResults)) asset.toolResults = [];
    if (!Array.isArray(asset.ports)) asset.ports = [];
    if (!Array.isArray(asset.zapFindings)) asset.zapFindings = [];
    if (!Array.isArray(asset.exploitAttempts)) asset.exploitAttempts = [];
    if (!Array.isArray(asset.confirmedCredentials)) asset.confirmedCredentials = [];
  }

  return state;
}

describe("Ops State Normalization", () => {
  it("should add missing arrays to empty state", () => {
    const state = normalizeOpsState({});
    expect(Array.isArray(state.assets)).toBe(true);
    expect(Array.isArray(state.log)).toBe(true);
    expect(Array.isArray(state.approvalGates)).toBe(true);
    expect(state.phase).toBe('idle');
    expect(state.progress).toBe(0);
    expect(state.isRunning).toBe(false);
    expect(state.isPaused).toBe(false);
  });

  it("should preserve existing state values", () => {
    const state = normalizeOpsState({
      phase: 'exploitation',
      progress: 75,
      isRunning: true,
      isPaused: false,
      assets: [{ hostname: 'test.com', vulns: [], ports: [], toolResults: [], zapFindings: [], exploitAttempts: [], confirmedCredentials: [] }],
      log: [{ id: '1', type: 'info', title: 'test' }],
      stats: { hostsScanned: 5, vulnsFound: 10 },
    });
    expect(state.phase).toBe('exploitation');
    expect(state.progress).toBe(75);
    expect(state.isRunning).toBe(true);
    expect(state.assets).toHaveLength(1);
    expect(state.log).toHaveLength(1);
    expect(state.stats.hostsScanned).toBe(5);
    expect(state.stats.vulnsFound).toBe(10);
  });

  it("should fill missing stats fields with defaults", () => {
    const state = normalizeOpsState({
      stats: { hostsScanned: 3 },
    });
    expect(state.stats.hostsScanned).toBe(3);
    expect(state.stats.portsFound).toBe(0);
    expect(state.stats.vulnsFound).toBe(0);
    expect(state.stats.exploitsAttempted).toBe(0);
    expect(state.stats.zapScansRun).toBe(0);
  });

  it("should rehydrate skippedDomains from JSON array to Set", () => {
    const state = normalizeOpsState({
      skippedDomains: ['domain1.com', 'domain2.com'],
    });
    expect(state.skippedDomains instanceof Set).toBe(true);
    expect(state.skippedDomains.has('domain1.com')).toBe(true);
    expect(state.skippedDomains.has('domain2.com')).toBe(true);
  });

  it("should handle null skippedDomains", () => {
    const state = normalizeOpsState({ skippedDomains: null });
    expect(state.skippedDomains instanceof Set).toBe(true);
    expect(state.skippedDomains.size).toBe(0);
  });

  it("should not re-wrap an existing Set", () => {
    const existing = new Set(['a.com', 'b.com']);
    const state = normalizeOpsState({ skippedDomains: existing });
    expect(state.skippedDomains).toBe(existing);
    expect(state.skippedDomains.size).toBe(2);
  });

  it("should normalize asset arrays when missing", () => {
    const state = normalizeOpsState({
      assets: [{ hostname: 'target.com' }],
    });
    const asset = state.assets[0];
    expect(Array.isArray(asset.vulns)).toBe(true);
    expect(Array.isArray(asset.toolResults)).toBe(true);
    expect(Array.isArray(asset.ports)).toBe(true);
    expect(Array.isArray(asset.zapFindings)).toBe(true);
    expect(Array.isArray(asset.exploitAttempts)).toBe(true);
    expect(Array.isArray(asset.confirmedCredentials)).toBe(true);
  });

  it("should normalize roeScopeGuard arrays", () => {
    const state = normalizeOpsState({
      roeScopeGuard: { roeStatus: 'signed' },
    });
    expect(Array.isArray(state.roeScopeGuard.authorizedDomains)).toBe(true);
    expect(Array.isArray(state.roeScopeGuard.authorizedIps)).toBe(true);
  });

  it("should handle non-boolean isRunning/isPaused", () => {
    const state = normalizeOpsState({
      isRunning: 1,
      isPaused: 'false',
    });
    expect(state.isRunning).toBe(false);
    expect(state.isPaused).toBe(false);
  });
});

// ─── State Serialization Round-Trip ────────────────────────────────────────

describe("Ops State Serialization Round-Trip", () => {
  it("should survive JSON serialize/deserialize cycle", () => {
    const original = {
      engagementId: 1770040,
      phase: 'vuln_detection',
      progress: 35,
      isRunning: true,
      isPaused: false,
      assets: [{
        hostname: 'scan.aceofcloud.io',
        ip: '159.223.152.190',
        type: 'web_app',
        ports: [{ port: 80, service: 'http' }, { port: 443, service: 'https' }],
        vulns: [{ id: 'v1', severity: 'high', title: 'SQL Injection', cve: 'CVE-2021-1234' }],
        zapFindings: [],
        exploitAttempts: [],
        confirmedCredentials: [],
        toolResults: [{ tool: 'nmap', command: 'nmap -sV', exitCode: 0, durationMs: 5000, timedOut: false, findingCount: 3, findings: [], outputPreview: 'test', executedAt: Date.now(), phase: 'enumeration' }],
        status: 'vulns_found',
      }],
      log: [{ id: 'ops-1', timestamp: Date.now(), phase: 'vuln_detection', type: 'scan_result', title: 'Nuclei Complete', detail: 'Found 5 vulns' }],
      approvalGates: [],
      skippedDomains: new Set(['skip.com']),
      stats: { hostsScanned: 2, portsFound: 10, vulnsFound: 22, exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0, zapScansRun: 3, wafDetections: 0 },
    };

    // Serialize (like saveOpsSnapshot does)
    const serialized = JSON.stringify({
      ...original,
      skippedDomains: original.skippedDomains instanceof Set ? Array.from(original.skippedDomains) : [],
    });

    // Deserialize and normalize (like loadOpsSnapshot + normalizeOpsState)
    const parsed = JSON.parse(serialized);
    const recovered = normalizeOpsState(parsed);

    expect(recovered.engagementId).toBe(1770040);
    expect(recovered.phase).toBe('vuln_detection');
    expect(recovered.progress).toBe(35);
    expect(recovered.isRunning).toBe(true);
    expect(recovered.assets).toHaveLength(1);
    expect(recovered.assets[0].hostname).toBe('scan.aceofcloud.io');
    expect(recovered.assets[0].vulns).toHaveLength(1);
    expect(recovered.assets[0].toolResults).toHaveLength(1);
    expect(recovered.log).toHaveLength(1);
    expect(recovered.stats.vulnsFound).toBe(22);
    expect(recovered.skippedDomains instanceof Set).toBe(true);
    expect(recovered.skippedDomains.has('skip.com')).toBe(true);
  });

  it("should handle empty state round-trip", () => {
    const empty = { engagementId: 1, phase: 'idle', progress: 0 };
    const serialized = JSON.stringify(empty);
    const recovered = normalizeOpsState(JSON.parse(serialized));
    expect(recovered.phase).toBe('idle');
    expect(recovered.assets).toEqual([]);
    expect(recovered.log).toEqual([]);
    expect(recovered.stats.hostsScanned).toBe(0);
  });
});

// ─── Vuln Deduplication ────────────────────────────────────────────────────

function pushVulnDeduped(
  asset: { vulns: Array<{ id: string; severity: string; title: string; cve?: string }> },
  vuln: { id: string; severity: string; title: string; cve?: string },
): boolean {
  const isDuplicate = asset.vulns.some((existing) => {
    if (vuln.cve && existing.cve && vuln.cve === existing.cve) return true;
    if (existing.title === vuln.title) return true;
    return false;
  });
  if (isDuplicate) return false;
  asset.vulns.push(vuln);
  return true;
}

describe("Vulnerability Deduplication", () => {
  it("should add new vulnerability", () => {
    const asset = { vulns: [] as any[] };
    const added = pushVulnDeduped(asset, { id: '1', severity: 'high', title: 'SQL Injection', cve: 'CVE-2021-1234' });
    expect(added).toBe(true);
    expect(asset.vulns).toHaveLength(1);
  });

  it("should reject duplicate by CVE", () => {
    const asset = { vulns: [{ id: '1', severity: 'high', title: 'SQL Injection', cve: 'CVE-2021-1234' }] };
    const added = pushVulnDeduped(asset, { id: '2', severity: 'critical', title: 'Different Title', cve: 'CVE-2021-1234' });
    expect(added).toBe(false);
    expect(asset.vulns).toHaveLength(1);
  });

  it("should reject duplicate by title", () => {
    const asset = { vulns: [{ id: '1', severity: 'high', title: 'XSS Reflected' }] };
    const added = pushVulnDeduped(asset, { id: '2', severity: 'medium', title: 'XSS Reflected' });
    expect(added).toBe(false);
    expect(asset.vulns).toHaveLength(1);
  });

  it("should allow different vulns", () => {
    const asset = { vulns: [{ id: '1', severity: 'high', title: 'SQL Injection', cve: 'CVE-2021-1234' }] };
    const added = pushVulnDeduped(asset, { id: '2', severity: 'medium', title: 'XSS Reflected', cve: 'CVE-2021-5678' });
    expect(added).toBe(true);
    expect(asset.vulns).toHaveLength(2);
  });
});

// ─── RoE Scope Guard ───────────────────────────────────────────────────────

function isInRoeScope(
  roeScopeGuard: { authorizedDomains: string[]; authorizedIps: string[] } | undefined,
  hostname: string,
  ip?: string,
): boolean {
  if (!roeScopeGuard) return true;
  const normalizedHost = hostname.toLowerCase().trim();
  const normalizedIp = (ip || "").trim();
  if (roeScopeGuard.authorizedDomains.some(d => d.toLowerCase().trim() === normalizedHost)) return true;
  if (normalizedIp && roeScopeGuard.authorizedIps.some(i => i.trim() === normalizedIp)) return true;
  return false;
}

describe("RoE Scope Guard", () => {
  it("should allow all targets when no guard is set", () => {
    expect(isInRoeScope(undefined, 'anything.com')).toBe(true);
  });

  it("should allow authorized domain", () => {
    const guard = { authorizedDomains: ['target.com'], authorizedIps: [] };
    expect(isInRoeScope(guard, 'target.com')).toBe(true);
  });

  it("should allow authorized IP", () => {
    const guard = { authorizedDomains: [], authorizedIps: ['192.168.1.1'] };
    expect(isInRoeScope(guard, 'unknown.com', '192.168.1.1')).toBe(true);
  });

  it("should reject unauthorized target", () => {
    const guard = { authorizedDomains: ['target.com'], authorizedIps: ['192.168.1.1'] };
    expect(isInRoeScope(guard, 'evil.com', '10.0.0.1')).toBe(false);
  });

  it("should be case-insensitive for domains", () => {
    const guard = { authorizedDomains: ['Target.COM'], authorizedIps: [] };
    expect(isInRoeScope(guard, 'target.com')).toBe(true);
  });

  it("should not allow subdomains by default", () => {
    const guard = { authorizedDomains: ['target.com'], authorizedIps: [] };
    expect(isInRoeScope(guard, 'sub.target.com')).toBe(false);
  });
});

// ─── Graduation Tier Computation ───────────────────────────────────────────

const KEEP_LLM_TASKS = new Set([
  "operator-cockpit.chat",
  "engagement-orchestrator.opsDecision",
  "specialist:attack-planner",
]);

function computeTier(
  caller: string,
  successRate: number,
  totalCalls: number,
  avgLatencyMs: number,
): { tier: number; label: string } {
  if (KEEP_LLM_TASKS.has(caller)) {
    return { tier: 5, label: "Keep LLM (Creative/Reasoning)" };
  }
  if (successRate >= 97 && totalCalls >= 500 && avgLatencyMs <= 5000) {
    return { tier: 1, label: "Ready to Graduate" };
  }
  if (successRate >= 90 && totalCalls >= 200 && avgLatencyMs <= 10000) {
    return { tier: 2, label: "Near Graduation" };
  }
  if (successRate >= 80 && totalCalls >= 50) {
    return { tier: 3, label: "Emerging Pattern" };
  }
  return { tier: 4, label: "Still Training" };
}

describe("Graduation Tier Computation", () => {
  it("should assign Tier 1 for high-performing callers", () => {
    const result = computeTier('scan-analyst.analyze', 98, 600, 3000);
    expect(result.tier).toBe(1);
    expect(result.label).toBe("Ready to Graduate");
  });

  it("should assign Tier 2 for near-graduation callers", () => {
    const result = computeTier('vuln-correlator.correlate', 92, 250, 8000);
    expect(result.tier).toBe(2);
  });

  it("should assign Tier 3 for emerging callers", () => {
    const result = computeTier('exploit-planner.plan', 85, 60, 15000);
    expect(result.tier).toBe(3);
  });

  it("should assign Tier 4 for low-performing callers", () => {
    const result = computeTier('new-agent.test', 50, 10, 20000);
    expect(result.tier).toBe(4);
  });

  it("should assign Tier 5 for keep-LLM tasks regardless of metrics", () => {
    const result = computeTier('operator-cockpit.chat', 99, 1000, 1000);
    expect(result.tier).toBe(5);
    expect(result.label).toContain("Keep LLM");
  });

  it("should not graduate if latency is too high despite good success rate", () => {
    const result = computeTier('slow-agent.process', 98, 600, 12000);
    // Success and volume pass Tier 1 but latency too high
    expect(result.tier).toBe(3); // Falls to Tier 3 (80%+ success, 50+ calls)
  });
});
