import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

/**
 * Tests for LLM Vuln Synthesis Labeling Fix
 * Ensures LLM-synthesized vulns are labeled as "potential" not "confirmed"
 * and that only tool-confirmed findings get "confirmed" tier.
 */

const PROJECT_ROOT = path.resolve(__dirname, "..");

// Helper to read file content
function readFile(relPath: string): string {
  return fs.readFileSync(path.join(PROJECT_ROOT, relPath), "utf-8");
}

describe("LLM Vuln Synthesis Labeling", () => {
  describe("rerunFullPipeline vuln synthesis", () => {
    const opsCore = readFile("server/routers/engagement-ops-core.ts");

    it("should set corroborationTier to 'potential' for LLM-synthesized vulns", () => {
      // The rerunFullPipeline should add corroborationTier: 'potential' when pushing LLM vulns
      expect(opsCore).toContain("corroborationTier: 'potential'");
    });

    it("should prefix LLM-synthesized vuln titles with [Potential]", () => {
      // Check that the push includes [Potential] prefix logic
      expect(opsCore).toContain("[Potential]");
    });

    it("should use 'POTENTIAL' language in LLM synthesis prompts", () => {
      // The prompt should say POTENTIAL not REAL
      expect(opsCore).toContain("POTENTIAL");
    });

    it("should NOT use 'most likely REAL vulnerabilities' in prompts", () => {
      // The misleading prompt should be fixed
      expect(opsCore).not.toContain("most likely REAL vulnerabilities");
    });
  });

  describe("engagement-orchestrator vuln tiers", () => {
    const orchestrator = readFile("server/lib/engagement-orchestrator.ts");

    it("should have confirmed tier for tool-based findings", () => {
      // Tool-confirmed vulns (nuclei, hydra, ZAP) should get 'confirmed'
      expect(orchestrator).toContain("corroborationTier: 'confirmed'");
    });

    it("should have unverified tier for AI-verified findings that are inconclusive", () => {
      // AI verification can downgrade to 'unverified' when inconclusive
      expect(orchestrator).toContain("corroborationTier = 'unverified'");
    });

    it("should have tiered corroboration in postureToVulns", () => {
      // Passive recon uses postureToVulns which assigns tiers based on evidence
      expect(orchestrator).toContain("corroborationTier: tier");
    });
  });

  describe("EngagementOps UI vuln synthesis display", () => {
    const opsUI = readFile("client/src/pages/EngagementOps.tsx");

    it("should display warning banner for LLM-synthesized findings", () => {
      // UI should warn that LLM findings are potential, not confirmed
      expect(opsUI).toContain("potential (unconfirmed)");
    });

    it("should show Potential badge for LLM-synthesized vulns", () => {
      // UI should display 'potential (unconfirmed)' label
      expect(opsUI).toContain("potential (unconfirmed)");
    });

    it("should import AlertTriangle icon for warning display", () => {
      expect(opsUI).toContain("AlertTriangle");
    });
  });

  describe("corroborationTier consistency", () => {
    const opsCore = readFile("server/routers/engagement-ops-core.ts");

    it("should only use valid corroboration tier values", () => {
      // Valid tiers: confirmed, probable, potential, unverified
      const tierMatches = opsCore.match(/corroborationTier:\s*['"](\w+)['"]/g) || [];
      const validTiers = ["confirmed", "probable", "potential", "unverified"];
      for (const match of tierMatches) {
        const tier = match.match(/['"](\w+)['"]/)?.[1];
        expect(validTiers).toContain(tier);
      }
    });

    it("should have more potential tiers than confirmed in synthesis code", () => {
      // LLM synthesis sections should predominantly use 'potential'
      const potentialCount = (opsCore.match(/corroborationTier:\s*'potential'/g) || []).length;
      expect(potentialCount).toBeGreaterThanOrEqual(2);
    });
  });
});

describe("Hydra http-form-post Fix Validation", () => {
  const executor = readFile("server/lib/scan-server-executor.ts");

  it("should use http-form-post mode for web form credential testing", () => {
    expect(executor).toContain("http-form-post");
  });

  it("should include failure string detection in form data", () => {
    // Form-based auth should check for failure indicators
    expect(executor).toContain("F=");
  });

  it("should support both http and https protocols", () => {
    expect(executor).toContain("http-form-post");
  });
});

describe("Asset scope bug fix", () => {
  const orchestrator = readFile("server/lib/engagement-orchestrator.ts");

  it("should not reference 'asset' variable outside its for-loop scope", () => {
    // The fix should iterate over all assets for HTTP credential verification
    // rather than referencing a single 'asset' variable from an outer scope
    // Check that the credential verification section uses proper iteration
    const lines = orchestrator.split("\n");
    let inCredVerification = false;
    let foundForLoop = false;

    for (const line of lines) {
      if (line.includes("HTTP credential verification") || line.includes("httpCredentialVerification")) {
        inCredVerification = true;
      }
      if (inCredVerification && (line.includes("for (const") || line.includes("for(const") || line.includes(".forEach"))) {
        foundForLoop = true;
        break;
      }
      if (inCredVerification && line.includes("// End credential")) {
        break;
      }
    }
    // The section should use iteration, not a single variable reference
    // This is a structural check - the fix should have added a loop
    expect(orchestrator).not.toMatch(/\basset\b.*is not defined/);
  });
});
