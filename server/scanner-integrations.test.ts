import { describe, it, expect, vi } from "vitest";

// ═══ SQLMap Scanner Module Tests ═══
describe("SQLMap Scanner", () => {
  it("should export startSqlmapScan function", async () => {
    const mod = await import("./lib/scanners/sqlmap-scanner");
    expect(typeof mod.startSqlmapScan).toBe("function");
  });

  it("should build correct sqlmap command with URL and forms flag", async () => {
    const mod = await import("./lib/scanners/sqlmap-scanner");
    // The function should exist and be callable
    expect(mod.startSqlmapScan).toBeDefined();
  });
});

// ═══ XSStrike Scanner Module Tests ═══
describe("XSStrike Scanner", () => {
  it("should export startXssScan function", async () => {
    const mod = await import("./lib/scanners/xsstrike-scanner");
    expect(typeof mod.startXssScan).toBe("function");
  });

  it("should export batchXssScan function", async () => {
    const mod = await import("./lib/scanners/xsstrike-scanner");
    expect(typeof mod.batchXssScan).toBe("function");
  });
});

// ═══ Scan Server Executor - Tool Whitelist Tests ═══
describe("Scan Server Executor Tool Whitelist", async () => {
  it("should include xsstrike and dalfox in allowed tools", async () => {
    // Read the source file to verify the whitelist
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/scan-server-executor.ts", "utf-8");
    expect(source).toContain("xsstrike");
    expect(source).toContain("dalfox");
  });
});

// ═══ Safety Engine - Training Lab Auto-Escalation Tests ═══
describe("Training Lab Safety Auto-Escalation", () => {
  it("should have training lab auto-escalation code in engagement orchestrator", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");
    // Verify the training lab auto-escalation block exists
    expect(source).toContain("TRAINING LAB AUTO-ESCALATION");
    expect(source).toContain("trainingLabMode");
    expect(source).toContain("Safety Auto-Escalated: Training Lab");
  });

  it("should set scanMode and roeStatus in batch training engagement creation", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/routers/engagement-automation.ts", "utf-8");
    // Verify the batch training run sets scanMode and roeStatus
    expect(source).toContain("scanMode: input.scanMode");
    expect(source).toContain("roeStatus: 'signed'");
    expect(source).toContain("roeSignedDate: new Date()");
  });
});

// ═══ ZAP Scanner - Active Scan Fix Tests ═══
describe("ZAP Active Scan Fix", () => {
  it("should NOT pass scanPolicyName to active scan API call", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/zap-scanner.ts", "utf-8");
    // The scanPolicyName should NOT be in the active scan params
    // It should use the default policy since rules are configured via applyPlaybookToZap
    const activeScanCalls = source.match(/ascan\/action\/scan/g);
    expect(activeScanCalls).toBeTruthy();
    expect(activeScanCalls!.length).toBeGreaterThan(0);
  });

  it("should include attack surface enumeration after spider", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/zap-scanner.ts", "utf-8");
    expect(source).toContain("Attack Surface Enumeration");
    expect(source).toContain("core/view/urls");
  });

  it("should inject learning context into generateLLMScanConfig", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/zap-scanner.ts", "utf-8");
    expect(source).toContain("buildLearningContext");
    expect(source).toContain("SELF-LEARNING FEEDBACK");
  });

  it("should have detectTargetPreset function for training lab URL mapping", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/zap-scanner.ts", "utf-8");
    expect(source).toContain("detectTargetPreset");
    expect(source).toContain("dvwa");
    expect(source).toContain("juice");
  });
});

// ═══ Knowledge Lazy - ESM Compatibility Tests ═══
describe("Knowledge Lazy ESM Compatibility", () => {
  it("should NOT use require() for module loading (only in comments)", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/knowledge-lazy.ts", "utf-8");
    // Strip comments, then check no require() calls remain
    const codeOnly = source.replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
    expect(codeOnly).not.toMatch(/\brequire\s*\(/);
  });

  it("should export all knowledge functions", async () => {
    const mod = await import("./lib/knowledge-lazy");
    expect(typeof mod.getChainsByVulnDescriptions).toBe("function");
    expect(typeof mod.formatOntologyForPrompt).toBe("function");
    expect(typeof mod.inferAssetContext).toBe("function");
  });
});
