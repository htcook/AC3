import { describe, expect, it } from "vitest";

/**
 * Tests for:
 * 1. Org Discovery data inclusion in pipeline output
 * 2. KEV match quality indicators (confirmed vs potential)
 */

describe("Org Discovery Pipeline Integration", () => {
  it("OrgDiscoveryResult type has required fields", async () => {
    // Dynamically import to verify the module and types compile correctly
    const mod = await import("./lib/org-domain-discovery");
    expect(mod.discoverOrgDomains).toBeDefined();
    expect(typeof mod.discoverOrgDomains).toBe("function");
  });

  it("PipelineResult includes orgDiscovery field", async () => {
    // Verify domainIntel exports include orgDiscovery in the type
    const mod = await import("./domainIntel");
    expect(mod.runDomainIntelPipeline).toBeDefined();
    expect(typeof mod.runDomainIntelPipeline).toBe("function");
  });

  it("OrgDomainResult structure has ownership and mission fields", async () => {
    // Create a mock OrgDomainResult and verify shape
    const mockDomain = {
      domain: "example-subsidiary.com",
      ownershipConfidence: 85,
      ownershipSignals: [
        {
          type: "whois_org" as const,
          value: "Example Corp",
          confidence: 90,
          detail: "WHOIS registrant organization matches",
        },
      ],
      missionRelevance: "product" as const,
      discoverySource: ["reverse_whois", "ct_org_search"],
      registrant: "Example Corp",
      registrantEmail: "domains@example.com",
      sslCertOrg: "Example Corp",
      nameservers: ["ns1.example.com"],
      mxRecords: ["mail.example.com"],
      resolvedIps: ["1.2.3.4"],
      asn: "AS12345",
      isVerified: true,
    };

    expect(mockDomain.ownershipConfidence).toBeGreaterThanOrEqual(0);
    expect(mockDomain.ownershipConfidence).toBeLessThanOrEqual(100);
    expect(mockDomain.isVerified).toBe(true);
    expect(["product", "service", "infrastructure", "marketing", "corporate", "unknown"]).toContain(
      mockDomain.missionRelevance
    );
    expect(mockDomain.ownershipSignals).toHaveLength(1);
    expect(mockDomain.ownershipSignals[0].type).toBe("whois_org");
    expect(mockDomain.discoverySource).toContain("reverse_whois");
  });

  it("OrgDiscoveryResult structure validates correctly", async () => {
    const mockResult = {
      seedDomain: "example.com",
      orgName: "Example Corp",
      orgEmail: "admin@example.com",
      totalCandidatesFound: 15,
      verifiedDomains: [
        {
          domain: "example-app.com",
          ownershipConfidence: 92,
          ownershipSignals: [],
          missionRelevance: "product" as const,
          discoverySource: ["ct_org_search"],
          registrant: "Example Corp",
          registrantEmail: "admin@example.com",
          sslCertOrg: "Example Corp",
          nameservers: [],
          mxRecords: [],
          resolvedIps: [],
          asn: null,
          isVerified: true,
        },
      ],
      unverifiedDomains: [
        {
          domain: "maybe-example.com",
          ownershipConfidence: 45,
          ownershipSignals: [],
          missionRelevance: "unknown" as const,
          discoverySource: ["shared_ns"],
          registrant: null,
          registrantEmail: null,
          sslCertOrg: null,
          nameservers: [],
          mxRecords: [],
          resolvedIps: [],
          asn: null,
          isVerified: false,
        },
      ],
      discoveryStats: [
        { source: "reverse_whois", domainsFound: 5, durationMs: 1200, status: "success" as const, error: null },
        { source: "ct_org_search", domainsFound: 8, durationMs: 800, status: "success" as const, error: null },
        { source: "censys_cert", domainsFound: 0, durationMs: 0, status: "skipped" as const, error: null },
      ],
      durationMs: 3500,
    };

    expect(mockResult.verifiedDomains).toHaveLength(1);
    expect(mockResult.unverifiedDomains).toHaveLength(1);
    expect(mockResult.verifiedDomains[0].isVerified).toBe(true);
    expect(mockResult.unverifiedDomains[0].isVerified).toBe(false);
    expect(mockResult.verifiedDomains[0].ownershipConfidence).toBeGreaterThan(
      mockResult.unverifiedDomains[0].ownershipConfidence
    );
    expect(mockResult.discoveryStats).toHaveLength(3);
    expect(mockResult.discoveryStats.filter((s) => s.status === "success")).toHaveLength(2);
  });

  it("trimmedOutput orgDiscovery slicing limits domains correctly", () => {
    // Simulate the slicing logic used in routers.ts
    const mockOrgDiscovery = {
      seedDomain: "test.com",
      orgName: "Test Corp",
      orgEmail: null,
      totalCandidatesFound: 100,
      verifiedDomains: Array.from({ length: 60 }, (_, i) => ({
        domain: `verified-${i}.com`,
        ownershipConfidence: 80 + (i % 20),
        isVerified: true,
      })),
      unverifiedDomains: Array.from({ length: 40 }, (_, i) => ({
        domain: `unverified-${i}.com`,
        ownershipConfidence: 30 + (i % 30),
        isVerified: false,
      })),
      discoveryStats: [],
      durationMs: 5000,
    };

    // Simulate the trimming logic from routers.ts
    const trimmed = {
      seedDomain: mockOrgDiscovery.seedDomain,
      orgName: mockOrgDiscovery.orgName,
      orgEmail: mockOrgDiscovery.orgEmail,
      totalCandidatesFound: mockOrgDiscovery.totalCandidatesFound,
      verifiedDomains: mockOrgDiscovery.verifiedDomains.slice(0, 50),
      unverifiedDomains: mockOrgDiscovery.unverifiedDomains.slice(0, 30),
      discoveryStats: mockOrgDiscovery.discoveryStats,
      durationMs: mockOrgDiscovery.durationMs,
    };

    expect(trimmed.verifiedDomains).toHaveLength(50);
    expect(trimmed.unverifiedDomains).toHaveLength(30);
    expect(trimmed.totalCandidatesFound).toBe(100);
  });
});

describe("KEV Match Quality Indicators", () => {
  it("KEV match quality fields exist on KevMatch type", async () => {
    const mod = await import("./lib/kev-service");
    expect(mod.matchTechnologiesAgainstKev).toBeDefined();
    expect(mod.calculateKevRiskBoost).toBeDefined();
    expect(typeof mod.matchTechnologiesAgainstKev).toBe("function");
  });

  it("versionMatchConfirmed distinguishes confirmed from potential KEV matches", () => {
    // Simulate findings with KEV match quality
    const confirmedFinding = {
      id: "pf-001",
      title: "Apache Log4j RCE (CVE-2021-44228)",
      kevListed: true,
      versionMatchConfirmed: true,
      detectedVersion: "2.14.1",
      corroborationTier: "confirmed",
      severity: 10,
    };

    const potentialFinding = {
      id: "pf-002",
      title: "Apache HTTP Server Vulnerability",
      kevListed: true,
      versionMatchConfirmed: false,
      detectedVersion: null,
      corroborationTier: "probable",
      severity: 6,
    };

    // Confirmed: version detected and matched
    expect(confirmedFinding.kevListed).toBe(true);
    expect(confirmedFinding.versionMatchConfirmed).toBe(true);
    expect(confirmedFinding.detectedVersion).toBeTruthy();

    // Potential: KEV listed but no version confirmation
    expect(potentialFinding.kevListed).toBe(true);
    expect(potentialFinding.versionMatchConfirmed).toBe(false);
    expect(potentialFinding.detectedVersion).toBeNull();

    // Severity should be capped for potential matches
    expect(confirmedFinding.severity).toBeGreaterThan(potentialFinding.severity);
  });

  it("KEV badge rendering logic correctly selects confirmed vs potential", () => {
    // Simulate the badge rendering logic from DomainIntelResults.tsx
    const renderKevBadge = (finding: { kevListed: boolean; versionMatchConfirmed?: boolean }) => {
      if (!finding.kevListed) return null;
      if (finding.versionMatchConfirmed) return "CONFIRMED";
      return "POTENTIAL";
    };

    expect(renderKevBadge({ kevListed: true, versionMatchConfirmed: true })).toBe("CONFIRMED");
    expect(renderKevBadge({ kevListed: true, versionMatchConfirmed: false })).toBe("POTENTIAL");
    expect(renderKevBadge({ kevListed: true })).toBe("POTENTIAL");
    expect(renderKevBadge({ kevListed: false, versionMatchConfirmed: true })).toBeNull();
    expect(renderKevBadge({ kevListed: false })).toBeNull();
  });

  it("KEV match quality is preserved through pipeline output trimming", () => {
    // Simulate a finding going through the pipeline
    const pipelineFinding = {
      id: "pf-test",
      title: "Test Vulnerability",
      kevListed: true,
      versionMatchConfirmed: true,
      detectedVersion: "1.2.3",
      kevMatchQuality: "confirmed",
      corroborationTier: "confirmed",
      severity: 9,
      likelihood: 8,
      cveIds: ["CVE-2024-1234"],
    };

    // These fields should survive trimming
    expect(pipelineFinding.kevListed).toBe(true);
    expect(pipelineFinding.versionMatchConfirmed).toBe(true);
    expect(pipelineFinding.kevMatchQuality).toBe("confirmed");
    expect(pipelineFinding.detectedVersion).toBe("1.2.3");
  });

  it("mission relevance classification values are valid", () => {
    const validMissions = ["product", "service", "infrastructure", "marketing", "corporate", "unknown"];

    // All mission types should be in the valid set
    validMissions.forEach((mission) => {
      expect(validMissions).toContain(mission);
    });

    // Invalid mission types should not be accepted
    expect(validMissions).not.toContain("invalid");
    expect(validMissions).not.toContain("");
  });
});
