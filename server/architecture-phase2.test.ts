/**
 * Architecture Remediation Phase 2 Tests
 * 
 * Tests for:
 * 1. Stage parallelization (3.5||3.6, 3.8+3.81||3.85)
 * 2. Phase 7 exploitation extraction
 * 3. Scope enforcement parity (Phase 5 vs Phase 7)
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

const DI_PATH = path.resolve(__dirname, "domainIntel.ts");
const ORCH_PATH = path.resolve(__dirname, "lib/engagement-orchestrator.ts");
const EXPLOIT_PATH = path.resolve(__dirname, "lib/engagement-phase-exploitation.ts");

describe("Stage Parallelization (domainIntel.ts)", () => {
  const diContent = fs.readFileSync(DI_PATH, "utf-8");

  it("should parallelize Stage 3.5 and 3.6 with parallelWithRetry", () => {
    expect(diContent).toContain("Parallel Execution: Stage 3.5 (KEV) || Stage 3.6 (Vuln Feeds)");
    expect(diContent).toContain("const [kevRetry, vulnFeedRetry] = await parallelWithRetry([");
  });

  it("should have kevEnrichment hoisted above the parallelWithRetry", () => {
    const kevDeclIndex = diContent.indexOf("let kevEnrichment: KevEnrichment | undefined;");
    const retryIndex = diContent.indexOf("const [kevRetry, vulnFeedRetry] = await parallelWithRetry([");
    expect(kevDeclIndex).toBeLessThan(retryIndex);
    expect(kevDeclIndex).toBeGreaterThan(0);
  });

  it("should log retry statistics for KEV/VulnFeed execution", () => {
    expect(diContent).toContain('for (const r of [kevRetry, vulnFeedRetry])');
    expect(diContent).toContain('r.stageName');
  });

  it("should parallelize Stage 3.8+3.81 and 3.85 with Promise.allSettled", () => {
    expect(diContent).toContain("Parallel Execution: Stage 3.8+3.81 (Exploit Matching) || Stage 3.85 (Port Scoring)");
    expect(diContent).toContain("// Branch A: Stage 3.8 (Exploit Matching) + Stage 3.81 (Cross-link)");
    expect(diContent).toContain("// Branch B: Stage 3.85 (Port-Based Risk Scoring)");
  });

  it("should hoist exploitMatchResult and portRiskStats above the parallel block", () => {
    const exploitDeclIndex = diContent.indexOf("let exploitMatchResult: PipelineResult['exploitMatches'] | undefined;");
    const portDeclIndex = diContent.indexOf("let portRiskStats = { totalAssetsWithPorts: 0");
    const parallelIndex = diContent.indexOf("// Branch A: Stage 3.8 (Exploit Matching)");
    expect(exploitDeclIndex).toBeLessThan(parallelIndex);
    expect(portDeclIndex).toBeLessThan(parallelIndex);
  });

  it("should maintain Stage 3.7 after the 3.5||3.6 parallel block", () => {
    const retryStatsIndex = diContent.indexOf('for (const r of [kevRetry, vulnFeedRetry])');
    const stage37Index = diContent.indexOf("// Stage 3.7: Shodan CVE Verification");
    expect(stage37Index).toBeGreaterThan(retryStatsIndex);
  });

  it("should maintain Stage 3.9 after the 3.8||3.85 parallel block", () => {
    const branchBIndex = diContent.indexOf("// Branch B: Stage 3.85 (Port-Based Risk Scoring)");
    const stage39Index = diContent.indexOf("// Stage 3.9: Email Security Analysis");
    expect(stage39Index).toBeGreaterThan(branchBIndex);
  });
});

describe("Phase 7 Exploitation Extraction", () => {
  const orchContent = fs.readFileSync(ORCH_PATH, "utf-8");
  const exploitContent = fs.readFileSync(EXPLOIT_PATH, "utf-8");

  it("should have a thin wrapper in the orchestrator that delegates to the extracted module", () => {
    expect(orchContent).toContain("const { executeExploitation: runExploitPhase } = await import('./engagement-phase-exploitation');");
    expect(orchContent).toContain("return runExploitPhase(state, engagement, operatorCtx);");
  });

  it("should export executeExploitation from the extracted module", () => {
    expect(exploitContent).toContain("export async function executeExploitation(state: EngagementOpsState");
  });

  it("should import EngagementOpsState from shared types", () => {
    expect(exploitContent).toContain('EngagementOpsState');
    expect(exploitContent).toContain('from "../../shared/orchestrator-types"');
  });

  it("should import addLog, broadcastOpsUpdate, requestApproval from orchestrator", () => {
    expect(exploitContent).toContain("addLog,");
    expect(exploitContent).toContain("broadcastOpsUpdate,");
    expect(exploitContent).toContain("requestApproval,");
  });

  it("should import evidence integrity functions", () => {
    expect(exploitContent).toContain("evidenceGate,");
    expect(exploitContent).toContain("createIntegrityEnvelope,");
    expect(exploitContent).toContain("buildProvenance,");
    expect(exploitContent).toContain("recordCustodyEvent,");
  });

  it("should import learning engine functions", () => {
    expect(exploitContent).toContain("accumulateOutcome as accumulateLearningOutcome");
    expect(exploitContent).toContain("hydrateFromDb as hydrateLearningEngine");
  });

  it("should have dynamic imports for heavy modules", () => {
    expect(exploitContent).toContain("await import('./scan-server-executor')");
    expect(exploitContent).toContain('await import("./exploitation-bridge-engine")');
    expect(exploitContent).toContain('await import("./enhanced-exploit-orchestration")');
  });

  it("should reduce the orchestrator below 13,200 lines", () => {
    const lineCount = orchContent.split("\n").length;
    expect(lineCount).toBeLessThan(13200);
  });

  it("should have the exploitation module at ~1400+ lines", () => {
    const lineCount = exploitContent.split("\n").length;
    expect(lineCount).toBeGreaterThan(1300);
    expect(lineCount).toBeLessThan(1600);
  });
});

describe("Scope Enforcement Parity (Phase 5 vs Phase 7)", () => {
  const orchContent = fs.readFileSync(ORCH_PATH, "utf-8");
  const exploitContent = fs.readFileSync(EXPLOIT_PATH, "utf-8");

  it("Phase 5 should have RoE scope guard filtering (now in extracted enumeration module)", () => {
    // Phase 5 is now extracted to engagement-phase-enumeration.ts
    const enumPath = path.resolve(__dirname, 'lib/engagement-phase-enumeration.ts');
    const enumContent = fs.readFileSync(enumPath, 'utf-8');
    expect(enumContent).toContain("RoE SCOPE GUARD");
    expect(enumContent).toContain("const scopedAssets = state.assets.filter(a => isInRoeScope(state, a.hostname, a.ip));");
  });

  it("Phase 7 should have matching RoE scope guard filtering", () => {
    expect(exploitContent).toContain("RoE SCOPE GUARD: Filter exploitation targets to only authorized assets");
    expect(exploitContent).toContain("const scopedAssets = state.assets.filter(a => isInRoeScope(state, a.hostname, a.ip));");
  });

  it("Phase 7 should log excluded assets", () => {
    expect(exploitContent).toContain("Scope Guard:");
    expect(exploitContent).toContain("assets excluded from exploitation");
  });

  it("Phase 7 should early-return if no assets are in scope", () => {
    expect(exploitContent).toContain("if (scopedAssets.length === 0)");
    expect(exploitContent).toContain("All assets are out of RoE scope. Skipping exploitation phase.");
  });

  it("Phase 7 should restore original assets after exploitation", () => {
    expect(exploitContent).toContain("Restore full asset list after scoped exploitation");
    expect(exploitContent).toContain("state.assets = originalAssets;");
  });

  it("Phase 7 should import isInRoeScope from shared types (breaks circular import)", () => {
    expect(exploitContent).toContain("isInRoeScope");
    expect(exploitContent).toContain('from "../../shared/orchestrator-types"');
  });

  it("Both phases should use the same isInRoeScope function signature", () => {
    // Phase 5 pattern
    const phase5Pattern = "isInRoeScope(state, a.hostname, a.ip)";
    expect(orchContent).toContain(phase5Pattern);
    // Phase 7 pattern (should match)
    expect(exploitContent).toContain(phase5Pattern);
  });
});

describe("Orchestrator Exports for Extracted Modules", () => {
  const orchContent = fs.readFileSync(ORCH_PATH, "utf-8");

  it("should export requestApproval", () => {
    expect(orchContent).toContain("export async function requestApproval(");
  });

  it("should export auditLog", () => {
    expect(orchContent).toContain("export async function auditLog(params:");
  });

  it("should export llmDecide", () => {
    expect(orchContent).toContain("export async function llmDecide(context:");
  });

  it("should export isInRoeScope", () => {
    expect(orchContent).toContain("export function isInRoeScope(");
  });
});
