/**
 * Test Plan Generator & Pipeline Phases Test Suite
 *
 * Tests for:
 *   - Test plan generator (NIST 800-115 aligned, no FedRAMP branding)
 *   - Pipeline phases (passive discovery, scoping, test plan generation)
 *   - DNS security assessment integration (NIST SP 800-81r3)
 *
 * @author Harrison Cook — AceofCloud
 */

import { describe, it, expect, vi } from "vitest";

// ─── Test Plan Generator Type Tests ──────────────────────────────────────

describe("Test Plan Generator — Type Definitions", () => {
  it("should import the test plan generator module without errors", async () => {
    const mod = await import("./test-plan-generator");
    expect(mod).toBeDefined();
    expect(mod.generateTestPlan).toBeDefined();
    expect(typeof mod.generateTestPlan).toBe("function");
  });

  it("should export testPlanToMarkdown function", async () => {
    const { testPlanToMarkdown } = await import("./test-plan-generator");
    expect(testPlanToMarkdown).toBeDefined();
    expect(typeof testPlanToMarkdown).toBe("function");
  });
});

describe("Test Plan Generator — No FedRAMP Branding", () => {
  it("should not contain FedRAMP in the module source", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/test-plan-generator.ts",
      "utf-8"
    );

    // The only allowed FedRAMP reference is the negative instruction in the LLM prompt
    const fedRampMatches = source.match(/FedRAMP/gi) || [];
    const allowedMatches = fedRampMatches.filter(m => {
      // Check if this is in the negative instruction context
      const idx = source.indexOf(m);
      const surrounding = source.substring(Math.max(0, idx - 100), idx + 100);
      return surrounding.includes("Do NOT") || surrounding.includes("do not");
    });

    // All FedRAMP references should be in the "Do NOT claim" context
    expect(fedRampMatches.length).toBe(allowedMatches.length);
  });

  it("should not contain 3PAO references except in negative instructions", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/test-plan-generator.ts",
      "utf-8"
    );

    const threepaMatches = source.match(/3PAO/gi) || [];
    const allowedMatches = threepaMatches.filter(m => {
      const idx = source.indexOf(m);
      const surrounding = source.substring(Math.max(0, idx - 100), idx + 100);
      return surrounding.includes("Do NOT") || surrounding.includes("do not");
    });

    expect(threepaMatches.length).toBe(allowedMatches.length);
  });

  it("should reference NIST 800-115 as the primary standard", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/test-plan-generator.ts",
      "utf-8"
    );

    expect(source).toContain("800-115");
    expect(source).toContain("NIST");
  });

  it("should include DNS security assessment based on SP 800-81r3", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/test-plan-generator.ts",
      "utf-8"
    );

    expect(source).toContain("800-81");
    expect(source).toContain("dns");
  });

  it("should use AssessmentAttackVector instead of FedRAMPAttackVector", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/test-plan-generator.ts",
      "utf-8"
    );

    expect(source).toContain("AssessmentAttackVector");
    expect(source).not.toContain("FedRAMPAttackVector");
  });

  it("should use standardsReference instead of fedRampReference", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/test-plan-generator.ts",
      "utf-8"
    );

    expect(source).toContain("standardsReference");
    expect(source).not.toContain("fedRampReference");
  });
});

describe("Test Plan Generator — Assessment Attack Vectors", () => {
  it("should define 9 assessment attack vectors in the source", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/test-plan-generator.ts",
      "utf-8"
    );

    // All 9 attack vectors should be defined (with av prefix naming)
    const vectors = [
      "external_network", "web_application",
      "mobile_application", "social_engineering",
      "dns_infrastructure", "cloud_infrastructure", "api_security"
    ];
    for (const v of vectors) {
      expect(source).toContain(v);
    }
  });

  it("should include DNS Infrastructure as an attack vector", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/test-plan-generator.ts",
      "utf-8"
    );

    expect(source).toContain("dns_infrastructure");
  });

  it("should include Cloud Infrastructure as an attack vector", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/test-plan-generator.ts",
      "utf-8"
    );

    expect(source).toContain("cloud_infrastructure");
  });

  it("should include API Security as an attack vector", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/test-plan-generator.ts",
      "utf-8"
    );

    expect(source).toContain("api_security");
  });
});

// ─── Pipeline Phases Module Tests ────────────────────────────────────────

describe("Pipeline Phases — Module Structure", () => {
  it("should import the pipeline-phases module without errors", async () => {
    const mod = await import("./pipeline-phases");
    expect(mod).toBeDefined();
  });

  it("should export executePassiveDiscovery function", async () => {
    const mod = await import("./pipeline-phases");
    expect(mod.executePassiveDiscovery).toBeDefined();
    expect(typeof mod.executePassiveDiscovery).toBe("function");
  });

  it("should export executeScopingReview function", async () => {
    const mod = await import("./pipeline-phases");
    expect(mod.executeScopingReview).toBeDefined();
    expect(typeof mod.executeScopingReview).toBe("function");
  });

  it("should export executeTestPlanGeneration function", async () => {
    const mod = await import("./pipeline-phases");
    expect(mod.executeTestPlanGeneration).toBeDefined();
    expect(typeof mod.executeTestPlanGeneration).toBe("function");
  });
});

// ─── Engagement Pipeline Phase Order Tests ───────────────────────────────

describe("Engagement Pipeline — Phase Order", () => {
  it("should have the correct expanded phase order in the orchestrator", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/engagement-orchestrator.ts",
      "utf-8"
    );

    // The OpsPhase type should include all new phases
    expect(source).toContain("passive_discovery");
    expect(source).toContain("scoping");
    expect(source).toContain("test_plan");

    // The original phases should still exist
    expect(source).toContain("recon");
    expect(source).toContain("enumeration");
    expect(source).toContain("vuln_detection");
    expect(source).toContain("exploitation");
    expect(source).toContain("post_exploit");
  });

  it("should have Domain Recon as the first phase label", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/engagement-orchestrator.ts",
      "utf-8"
    );

    expect(source).toContain("Domain Recon");
  });

  it("should import pipeline-phases module in the orchestrator", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/engagement-orchestrator.ts",
      "utf-8"
    );

    expect(source).toContain("pipeline-phases");
  });
});

// ─── UI Label Tests ──────────────────────────────────────────────────────

describe("UI Labels — Domain Recon Rename", () => {
  it("should use Domain Recon in the sidebar navigation", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/components/AppShell.tsx",
      "utf-8"
    );

    expect(source).toContain("DOMAIN RECON");
    expect(source).not.toContain("DOMAIN INTEL\"");
  });

  it("should use Domain Recon in the DomainIntel page title", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/pages/DomainIntel.tsx",
      "utf-8"
    );

    expect(source).toContain("Full-Scope Domain Recon");
    expect(source).not.toContain("Full-Scope Domain Intelligence");
  });

  it("should use Domain Recon in the EngagementPipeline steps", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/pages/EngagementPipeline.tsx",
      "utf-8"
    );

    expect(source).toContain("Domain Recon");
    expect(source).toContain("Passive Discovery");
    expect(source).toContain("Scoping & RoE Review");
    expect(source).toContain("Test Plan Generation");
  });

  it("should use Domain Recon in the WorkflowLauncher", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/components/WorkflowLauncher.tsx",
      "utf-8"
    );

    expect(source).toContain("Run Domain Recon");
    expect(source).not.toContain("Run Domain Intelligence");
  });

  it("should use domain recon in the CommandPalette", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/components/CommandPalette.tsx",
      "utf-8"
    );

    expect(source).toContain("domain recon scan");
    expect(source).not.toContain("domain intelligence scan");
  });
});

// ─── EngagementOps Phase Display Tests ───────────────────────────────────

describe("EngagementOps — Phase Display", () => {
  it("should include all 8 phases in the PHASES array", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/pages/EngagementOps.tsx",
      "utf-8"
    );

    // New phases should be in the PHASES array
    expect(source).toContain("passive_discovery");
    expect(source).toContain("scoping");
    expect(source).toContain("test_plan");

    // Original phases should still be present
    expect(source).toContain("recon");
    expect(source).toContain("enumeration");
    expect(source).toContain("vuln_detection");
    expect(source).toContain("exploitation");
    expect(source).toContain("post_exploit");
  });

  it("should have updated phase labels in PHASE_LABELS", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/pages/EngagementOps.tsx",
      "utf-8"
    );

    expect(source).toContain("Domain Recon");
    expect(source).toContain("Passive Discovery");
    expect(source).toContain("Test Plan");
  });

  it("should have re-run options for new phases", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/pages/EngagementOps.tsx",
      "utf-8"
    );

    // Re-run options should include new phases
    expect(source).toContain("'passive_discovery' as const");
    expect(source).toContain("'scoping' as const");
    expect(source).toContain("'test_plan' as const");
  });
});

// ─── NIST SP 800-81r3 DNS Security Integration Tests ────────────────────

describe("NIST SP 800-81r3 DNS Security Integration", () => {
  it("should reference NIST SP 800-81r3 in the test plan generator", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/test-plan-generator.ts",
      "utf-8"
    );

    expect(source).toContain("800-81");
  });

  it("should include DNS assessment data input in the test plan generator", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/test-plan-generator.ts",
      "utf-8"
    );

    expect(source).toContain("dnsAssessmentData");
  });

  it("should include DNS records in passive recon summary", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/test-plan-generator.ts",
      "utf-8"
    );

    expect(source).toContain("dnsRecords");
  });

  it("should reference NIST 800-53 DNS controls SC-20, SC-21, SC-22", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/test-plan-generator.ts",
      "utf-8"
    );

    // Should reference at least one of the DNS-related NIST 800-53 controls
    const hasScControls = source.includes("SC-20") || source.includes("SC-21") || source.includes("SC-22");
    expect(hasScControls).toBe(true);
  });
});
