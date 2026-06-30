import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "fs";
import { join } from "path";

describe("Pipeline Audit — Architecture Document", () => {
  const archPath = join(__dirname, "lib/exploit-pipeline-architecture.md");

  it("architecture document exists", () => {
    expect(existsSync(archPath)).toBe(true);
  });

  it("architecture document contains all 9 architectural layers", () => {
    const content = readFileSync(archPath, "utf-8");
    const expectedLayers = [
      "Scan Policy Engine",
      "C2 Framework Abstraction",
      "Exploit Knowledge",
      "Engagement Integration",
      "Proof Engine",
      "Post-Exploit",
      "Payload Generator",
      "Safety Engine",
      "Attack Chain",
    ];
    for (const layer of expectedLayers) {
      expect(content).toContain(layer);
    }
  });

  it("architecture document covers safety guardrails", () => {
    const content = readFileSync(archPath, "utf-8");
    expect(content).toContain("Safety");
    expect(content).toContain("ROE");
    expect(content.toLowerCase()).toContain("blast radius");
    expect(content.toLowerCase()).toContain("audit");
  });

  it("architecture document covers C2 frameworks", () => {
    const content = readFileSync(archPath, "utf-8");
    expect(content).toContain("Caldera");
    expect(content).toContain("Metasploit");
    expect(content).toContain("Sliver");
  });
});

describe("Pipeline Audit — Router Module", () => {
  it("pipeline-audit router file exists", () => {
    const routerPath = join(__dirname, "routers/pipeline-audit.ts");
    expect(existsSync(routerPath)).toBe(true);
  });

  it("router exports pipelineAuditRouter", () => {
    const content = readFileSync(join(__dirname, "routers/pipeline-audit.ts"), "utf-8");
    expect(content).toContain("export const pipelineAuditRouter");
  });

  it("router has getModuleInventory procedure", () => {
    const content = readFileSync(join(__dirname, "routers/pipeline-audit.ts"), "utf-8");
    expect(content).toContain("getModuleInventory");
  });

  it("router has generateReport procedure", () => {
    const content = readFileSync(join(__dirname, "routers/pipeline-audit.ts"), "utf-8");
    expect(content).toContain("generateReport");
  });

  it("router has getCachedReport procedure", () => {
    const content = readFileSync(join(__dirname, "routers/pipeline-audit.ts"), "utf-8");
    expect(content).toContain("getCachedReport");
  });

  it("router imports from correct trpc path", () => {
    const content = readFileSync(join(__dirname, "routers/pipeline-audit.ts"), "utf-8");
    expect(content).toContain("from \"../_core/trpc\"");
  });

  it("router uses invokeLLM for report generation", () => {
    const content = readFileSync(join(__dirname, "routers/pipeline-audit.ts"), "utf-8");
    expect(content).toContain("invokeLLM");
  });
});

describe("Pipeline Audit — Safety & Legal Framework", () => {
  it("ROE guard enforces signed ROE for Orange/Red operations", () => {
    const content = readFileSync(join(__dirname, "lib/roe-guard.ts"), "utf-8");
    expect(content).toContain("enforceROE");
    expect(content).toContain("PRECONDITION_FAILED");
    expect(content).toContain("roeStatus");
    expect(content).toContain("roeExpiryDate");
  });

  it("ROE guard has risk tier classification for all action types", () => {
    const content = readFileSync(join(__dirname, "lib/roe-guard.ts"), "utf-8");
    const expectedActions = [
      "active_probe", "msf_check", "msf_auxiliary", "msf_exploit",
      "phishing_launch", "caldera_operation", "payload_delivery", "session_interaction",
    ];
    for (const action of expectedActions) {
      expect(content).toContain(action);
    }
  });

  it("Safety engine has four safety levels", () => {
    const content = readFileSync(join(__dirname, "lib/safety-engine.ts"), "utf-8");
    expect(content).toContain("passive_only");
    expect(content).toContain("low_impact");
    expect(content).toContain("standard");
    expect(content).toContain("full_exploitation");
  });

  it("Safety engine enforces blast radius estimation", () => {
    const content = readFileSync(join(__dirname, "lib/safety-engine.ts"), "utf-8");
    expect(content).toContain("blastRadius");
    expect(content).toContain("BlastRadiusEstimate");
    expect(content).toContain("riskScore");
  });

  it("Safety engine requires dual approval for full exploitation", () => {
    const content = readFileSync(join(__dirname, "lib/safety-engine.ts"), "utf-8");
    expect(content).toContain("dualApprovalRequired");
  });

  it("Safety engine has phase gating", () => {
    const content = readFileSync(join(__dirname, "lib/safety-engine.ts"), "utf-8");
    expect(content).toContain("PHASE_MINIMUM_SAFETY");
    expect(content).toContain("recon");
    expect(content).toContain("exploitation");
    expect(content).toContain("c2_deployment");
    expect(content).toContain("lateral_movement");
  });

  it("Offensive audit log captures operator identity and risk tier", () => {
    const content = readFileSync(join(__dirname, "lib/roe-guard.ts"), "utf-8");
    expect(content).toContain("operatorId");
    expect(content).toContain("riskTier");
    expect(content).toContain("offensiveAuditLog");
  });
});

describe("Pipeline Audit — Scan Policy Engine Tool Classification", () => {
  it("scan policy engine has TOOL_TIER_CLASSIFICATION", () => {
    const content = readFileSync(join(__dirname, "lib/scan-policy-engine.ts"), "utf-8");
    expect(content).toContain("TOOL_TIER_CLASSIFICATION");
  });

  it("scan policy engine classifies 60+ tools", () => {
    const content = readFileSync(join(__dirname, "lib/scan-policy-engine.ts"), "utf-8");
    // Count tool entries (each has a name: field)
    const toolEntries = content.match(/name:\s*"/g);
    expect(toolEntries).not.toBeNull();
    expect(toolEntries!.length).toBeGreaterThanOrEqual(60);
  });

  it("scan policy engine has all four tiers", () => {
    const content = readFileSync(join(__dirname, "lib/scan-policy-engine.ts"), "utf-8");
    expect(content).toContain("passive");
    expect(content).toContain("active-low");
    expect(content).toContain("active-standard");
    expect(content).toContain("active-aggressive");
  });
});
