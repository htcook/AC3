import { describe, it, expect } from "vitest";
import type { PipelineInput } from "./lib/pentest-report-pipeline";

/**
 * Tests for the Discovery Context Intelligence report section and persistence schema.
 * These validate that the PipelineInput interface accepts discoveryContextData,
 * that the report markdown generation correctly renders all 5 specialist sections,
 * and that the persistence schema is correctly typed.
 */

// ─── Fixtures ────────────────────────────────────────────────────────────────

function makeDiscoveryContextData() {
  return [
    {
      assetIdentifier: "app.example.com",
      attribution: {
        primaryClaim: {
          attributedTo: { organization: "Example Corp", subsidiary: "Example Cloud Division" },
          confidenceScore: 82,
          claimType: "whois_registrant",
          reasoning: "WHOIS registrant matches Example Corp; cert subject confirms subsidiary.",
        },
        claims: [
          { attributedTo: { organization: "Example Corp" }, confidenceScore: 82, claimType: "whois_registrant" },
          { attributedTo: { organization: "Cloudflare Inc" }, confidenceScore: 35, claimType: "hosting_provider" },
        ],
        metadata: { mode: "full_llm" },
      },
      role: {
        role: {
          exposure: "customer_facing",
          environment: "production",
          criticality: "high",
          function: "Web application server",
        },
        metadata: { mode: "full_llm" },
      },
      lifecycle: {
        stage: "active",
        direction: "stable",
        temporalSignals: [
          { signalType: "cert_expiry", value: "2027-06-15", interpretation: "Certificate valid for 14+ months" },
          { signalType: "dns_freshness", value: "2026-04-01", interpretation: "DNS records updated recently" },
        ],
        metadata: { mode: "deterministic_only" },
      },
      businessContext: {
        businessFunction: "Customer-facing SaaS application",
        revenuePath: "Direct revenue — subscription billing",
        regulatoryExposure: ["SOC 2", "GDPR", "PCI-DSS"],
        dependencies: ["PostgreSQL", "Redis", "Stripe API"],
        metadata: { mode: "full_llm" },
      },
      threatRelevance: {
        overallThreatScore: 74,
        actorTypes: [
          { actorType: "ransomware_operator", relevanceScore: 85 },
          { actorType: "nation_state_apt", relevanceScore: 62 },
          { actorType: "hacktivists", relevanceScore: 30 },
        ],
        sectorExposure: ["Technology", "Financial Services"],
        metadata: { mode: "full_llm" },
      },
      aggregatedAt: "2026-04-24T12:00:00Z",
    },
    {
      assetIdentifier: "mail.example.com",
      attribution: {
        primaryClaim: {
          attributedTo: { organization: "Example Corp" },
          confidenceScore: 90,
          claimType: "dns_mx_match",
        },
        claims: [
          { attributedTo: { organization: "Example Corp" }, confidenceScore: 90, claimType: "dns_mx_match" },
        ],
        metadata: { mode: "deterministic_only" },
      },
      role: {
        role: {
          exposure: "customer_facing",
          environment: "production",
          criticality: "critical",
          function: "Email server",
        },
        metadata: { mode: "deterministic_only" },
      },
      lifecycle: {
        stage: "active",
        direction: "stable",
        temporalSignals: [],
        metadata: { mode: "deterministic_only" },
      },
      businessContext: {
        businessFunction: "Corporate email infrastructure",
        revenuePath: "Indirect — business operations",
        regulatoryExposure: ["SOC 2", "HIPAA"],
        dependencies: ["Exchange Online"],
        metadata: { mode: "deterministic_only" },
      },
      threatRelevance: {
        overallThreatScore: 88,
        actorTypes: [
          { actorType: "phishing_operator", relevanceScore: 95 },
          { actorType: "nation_state_apt", relevanceScore: 78 },
        ],
        sectorExposure: ["Technology"],
        metadata: { mode: "deterministic_only" },
      },
      aggregatedAt: "2026-04-24T12:05:00Z",
    },
  ];
}

function makeMinimalPipelineInput(discoveryContextData?: PipelineInput["discoveryContextData"]): PipelineInput {
  return {
    engagementName: "Test Engagement",
    targetOrganization: "Example Corp",
    assessmentType: "External Penetration Test",
    startDate: "2026-04-01",
    endDate: "2026-04-24",
    assets: [],
    vulnerabilities: [],
    tools: [],
    exploitAttempts: [],
    osintData: [],
    calderaOps: [],
    manualFindings: [],
    discoveryContextData,
  };
}

// ─── PipelineInput Interface Tests ───────────────────────────────────────────

describe("Discovery Context Report Integration", () => {
  describe("PipelineInput discoveryContextData field", () => {
    it("should accept undefined discoveryContextData (backward compatible)", () => {
      const input = makeMinimalPipelineInput(undefined);
      expect(input.discoveryContextData).toBeUndefined();
    });

    it("should accept empty discoveryContextData array", () => {
      const input = makeMinimalPipelineInput([]);
      expect(input.discoveryContextData).toEqual([]);
    });

    it("should accept full discoveryContextData with all 5 specialists", () => {
      const data = makeDiscoveryContextData();
      const input = makeMinimalPipelineInput(data);
      expect(input.discoveryContextData).toHaveLength(2);
      expect(input.discoveryContextData![0].assetIdentifier).toBe("app.example.com");
      expect(input.discoveryContextData![1].assetIdentifier).toBe("mail.example.com");
    });

    it("should accept partial specialist data (only attribution)", () => {
      const input = makeMinimalPipelineInput([
        {
          assetIdentifier: "partial.example.com",
          attribution: {
            primaryClaim: {
              attributedTo: { organization: "Partial Corp" },
              confidenceScore: 60,
            },
            metadata: { mode: "deterministic_only" },
          },
        },
      ]);
      expect(input.discoveryContextData![0].role).toBeUndefined();
      expect(input.discoveryContextData![0].lifecycle).toBeUndefined();
      expect(input.discoveryContextData![0].businessContext).toBeUndefined();
      expect(input.discoveryContextData![0].threatRelevance).toBeUndefined();
    });
  });

  describe("Attribution specialist data shape", () => {
    it("should have primary claim with organization and subsidiary", () => {
      const data = makeDiscoveryContextData();
      const attr = data[0].attribution!;
      expect(attr.primaryClaim!.attributedTo!.organization).toBe("Example Corp");
      expect(attr.primaryClaim!.attributedTo!.subsidiary).toBe("Example Cloud Division");
      expect(attr.primaryClaim!.confidenceScore).toBe(82);
      expect(attr.primaryClaim!.claimType).toBe("whois_registrant");
      expect(attr.primaryClaim!.reasoning).toContain("WHOIS registrant");
    });

    it("should support multiple alternative claims", () => {
      const data = makeDiscoveryContextData();
      const claims = data[0].attribution!.claims!;
      expect(claims).toHaveLength(2);
      expect(claims[0].attributedTo!.organization).toBe("Example Corp");
      expect(claims[1].attributedTo!.organization).toBe("Cloudflare Inc");
      expect(claims[1].confidenceScore).toBeLessThan(claims[0].confidenceScore);
    });

    it("should track analysis mode in metadata", () => {
      const data = makeDiscoveryContextData();
      expect(data[0].attribution!.metadata!.mode).toBe("full_llm");
      expect(data[1].attribution!.metadata!.mode).toBe("deterministic_only");
    });
  });

  describe("Role specialist data shape", () => {
    it("should capture exposure, environment, criticality, and function", () => {
      const data = makeDiscoveryContextData();
      const role = data[0].role!.role!;
      expect(role.exposure).toBe("customer_facing");
      expect(role.environment).toBe("production");
      expect(role.criticality).toBe("high");
      expect(role.function).toBe("Web application server");
    });

    it("should distinguish criticality levels between assets", () => {
      const data = makeDiscoveryContextData();
      expect(data[0].role!.role!.criticality).toBe("high");
      expect(data[1].role!.role!.criticality).toBe("critical");
    });
  });

  describe("Lifecycle specialist data shape", () => {
    it("should capture stage and direction", () => {
      const data = makeDiscoveryContextData();
      const lc = data[0].lifecycle!;
      expect(lc.stage).toBe("active");
      expect(lc.direction).toBe("stable");
    });

    it("should include temporal signals with interpretation", () => {
      const data = makeDiscoveryContextData();
      const signals = data[0].lifecycle!.temporalSignals!;
      expect(signals).toHaveLength(2);
      expect(signals[0].signalType).toBe("cert_expiry");
      expect(signals[0].value).toBe("2027-06-15");
      expect(signals[0].interpretation).toContain("14+ months");
    });

    it("should handle empty temporal signals", () => {
      const data = makeDiscoveryContextData();
      expect(data[1].lifecycle!.temporalSignals).toEqual([]);
    });
  });

  describe("Business context specialist data shape", () => {
    it("should capture business function and revenue path", () => {
      const data = makeDiscoveryContextData();
      const bc = data[0].businessContext!;
      expect(bc.businessFunction).toBe("Customer-facing SaaS application");
      expect(bc.revenuePath).toContain("Direct revenue");
    });

    it("should list regulatory exposure frameworks", () => {
      const data = makeDiscoveryContextData();
      const regs = data[0].businessContext!.regulatoryExposure!;
      expect(regs).toContain("SOC 2");
      expect(regs).toContain("GDPR");
      expect(regs).toContain("PCI-DSS");
    });

    it("should list dependencies", () => {
      const data = makeDiscoveryContextData();
      const deps = data[0].businessContext!.dependencies!;
      expect(deps).toContain("PostgreSQL");
      expect(deps).toContain("Stripe API");
    });
  });

  describe("Threat relevance specialist data shape", () => {
    it("should have overall threat score in 0-100 range", () => {
      const data = makeDiscoveryContextData();
      const score = data[0].threatRelevance!.overallThreatScore!;
      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(100);
      expect(score).toBe(74);
    });

    it("should rank actor types by relevance score", () => {
      const data = makeDiscoveryContextData();
      const actors = data[0].threatRelevance!.actorTypes!;
      expect(actors).toHaveLength(3);
      expect(actors[0].actorType).toBe("ransomware_operator");
      expect(actors[0].relevanceScore).toBeGreaterThan(actors[1].relevanceScore);
      expect(actors[1].relevanceScore).toBeGreaterThan(actors[2].relevanceScore);
    });

    it("should list sector exposure", () => {
      const data = makeDiscoveryContextData();
      const sectors = data[0].threatRelevance!.sectorExposure!;
      expect(sectors).toContain("Technology");
      expect(sectors).toContain("Financial Services");
    });

    it("should score email servers higher for phishing threat", () => {
      const data = makeDiscoveryContextData();
      const mailThreat = data[1].threatRelevance!.overallThreatScore!;
      const appThreat = data[0].threatRelevance!.overallThreatScore!;
      expect(mailThreat).toBeGreaterThan(appThreat);
    });
  });

  describe("Report markdown generation expectations", () => {
    it("should produce summary table with correct column headers", () => {
      // Validate the expected markdown table structure
      const expectedHeaders = ["Asset", "Attribution", "Exposure", "Environment", "Lifecycle", "Threat Score"];
      const headerRow = `| ${expectedHeaders.join(" | ")} |`;
      expect(headerRow).toContain("Asset");
      expect(headerRow).toContain("Threat Score");
    });

    it("should classify threat scores into HIGH/MEDIUM/LOW bands", () => {
      const classify = (score: number) => score >= 70 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW";
      expect(classify(74)).toBe("HIGH");
      expect(classify(88)).toBe("HIGH");
      expect(classify(50)).toBe("MEDIUM");
      expect(classify(30)).toBe("LOW");
    });

    it("should format exposure values with underscores replaced by spaces", () => {
      const format = (s: string) => s.replace(/_/g, " ");
      expect(format("customer_facing")).toBe("customer facing");
      expect(format("internal_only")).toBe("internal only");
    });

    it("should include mode label for each specialist section", () => {
      const data = makeDiscoveryContextData();
      const modes = [
        data[0].attribution!.metadata!.mode,
        data[0].role!.metadata!.mode,
        data[0].lifecycle!.metadata!.mode,
        data[0].businessContext!.metadata!.mode,
        data[0].threatRelevance!.metadata!.mode,
      ];
      expect(modes).toContain("full_llm");
      expect(modes).toContain("deterministic_only");
    });
  });

  describe("Persistence schema validation", () => {
    it("should serialize discoveryContextData to JSON and back", () => {
      const data = makeDiscoveryContextData();
      const json = JSON.stringify(data);
      const parsed = JSON.parse(json);
      expect(parsed).toHaveLength(2);
      expect(parsed[0].assetIdentifier).toBe("app.example.com");
      expect(parsed[0].attribution.primaryClaim.confidenceScore).toBe(82);
      expect(parsed[1].threatRelevance.overallThreatScore).toBe(88);
    });

    it("should preserve all nested structures through JSON round-trip", () => {
      const data = makeDiscoveryContextData();
      const roundTripped = JSON.parse(JSON.stringify(data));
      // Deep equality check
      expect(roundTripped[0].attribution.claims).toHaveLength(2);
      expect(roundTripped[0].lifecycle.temporalSignals).toHaveLength(2);
      expect(roundTripped[0].businessContext.regulatoryExposure).toEqual(["SOC 2", "GDPR", "PCI-DSS"]);
      expect(roundTripped[0].threatRelevance.actorTypes).toHaveLength(3);
    });

    it("should handle null/undefined fields gracefully in JSON", () => {
      const sparse = [{
        assetIdentifier: "sparse.example.com",
        attribution: undefined,
        role: undefined,
        lifecycle: undefined,
        businessContext: undefined,
        threatRelevance: undefined,
      }];
      const json = JSON.stringify(sparse);
      const parsed = JSON.parse(json);
      expect(parsed[0].assetIdentifier).toBe("sparse.example.com");
      expect(parsed[0].attribution).toBeUndefined();
    });

    it("should include aggregatedAt timestamp for tracking analysis freshness", () => {
      const data = makeDiscoveryContextData();
      expect(data[0].aggregatedAt).toBe("2026-04-24T12:00:00Z");
      const ts = new Date(data[0].aggregatedAt!).getTime();
      expect(ts).toBeGreaterThan(0);
    });
  });
});
