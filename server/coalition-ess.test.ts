import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  computeRiskTier,
  generateRiskSummary,
  summarizeExploitIntelligence,
  clearCache,
  getCacheSize,
  type EssEnrichment,
  type CessScore,
  type CvssScore,
  type EpssScore,
  type ExploitAvailability,
  type SocialVisibility,
  type ThreatFlags,
} from "./lib/coalition-ess";

// ─── Helper: build a mock EssEnrichment ────────────────────────────────

function mockEnrichment(overrides: Partial<{
  cveId: string;
  cess: number;
  cvssBase: number;
  epss: number;
  metasploit: number;
  exploitdb: number;
  cisaKev: boolean;
  githubPocs: number;
}>): EssEnrichment {
  const cessScore = overrides.cess ?? 0.1;
  const cvssBase = overrides.cvssBase ?? 5.0;
  const epssScore = overrides.epss ?? 0.05;

  const base: Omit<EssEnrichment, "riskTier" | "riskSummary"> = {
    cveId: overrides.cveId || "CVE-2024-0001",
    description: "Test vulnerability",
    publishedDate: "2024-01-01",
    lastModifiedDate: "2024-06-01",
    cess: {
      probabilityExploitUsage: cessScore,
      probabilityExploitUsageVariation: 0.01,
    },
    cvss: {
      type: "Primary",
      version: "3.1",
      baseScore: cvssBase,
      impactScore: 5.0,
      exploitabilityScore: 3.0,
      vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    epss: {
      score: epssScore,
      variation: 0.001,
    },
    exploits: {
      exploitdb: { numExploits: overrides.exploitdb ?? 0, numVerifiedExploits: 0 },
      metasploit: { numExploits: overrides.metasploit ?? 0 },
    },
    social: {
      twitter: { numTweets: 0, numRetweets: 0 },
      github: {
        numRepos: 0,
        numReposWithPocKeyword: overrides.githubPocs ?? 0,
        numReposWithExploitKeyword: 0,
      },
    },
    visibility: {
      cisaKev: overrides.cisaKev ?? false,
      vulncheckKev: false,
      coalitionHoneypots: false,
      exploitdb: (overrides.exploitdb ?? 0) > 0,
      metasploit: (overrides.metasploit ?? 0) > 0,
      github: (overrides.githubPocs ?? 0) > 0,
      twitter: false,
    },
  };

  const riskTier = computeRiskTier(base);
  const enrichment: EssEnrichment = { ...base, riskTier, riskSummary: "" };
  enrichment.riskSummary = generateRiskSummary(enrichment);
  return enrichment;
}

// ─── computeRiskTier Tests ─────────────────────────────────────────────

describe("computeRiskTier", () => {
  it("returns critical for CISA KEV + high CESS", () => {
    const e = mockEnrichment({ cisaKev: true, cess: 0.75, cvssBase: 9.8 });
    expect(e.riskTier).toBe("critical");
  });

  it("returns critical for Metasploit + CVSS >= 9.0", () => {
    const e = mockEnrichment({ metasploit: 3, cvssBase: 9.5, cess: 0.4 });
    expect(e.riskTier).toBe("critical");
  });

  it("returns critical for high CESS + high EPSS", () => {
    const e = mockEnrichment({ cess: 0.85, epss: 0.55, cvssBase: 7.0 });
    expect(e.riskTier).toBe("critical");
  });

  it("returns high for CISA KEV alone (low CESS)", () => {
    const e = mockEnrichment({ cisaKev: true, cess: 0.3, cvssBase: 5.0 });
    expect(e.riskTier).toBe("high");
  });

  it("returns high for known exploits in ExploitDB", () => {
    const e = mockEnrichment({ exploitdb: 2, cess: 0.2, cvssBase: 6.0 });
    expect(e.riskTier).toBe("high");
  });

  it("returns high for known exploits in Metasploit (CVSS < 9)", () => {
    const e = mockEnrichment({ metasploit: 1, cess: 0.2, cvssBase: 7.5 });
    expect(e.riskTier).toBe("high");
  });

  it("returns high for high CESS alone (>= 0.6)", () => {
    const e = mockEnrichment({ cess: 0.65, cvssBase: 5.0 });
    expect(e.riskTier).toBe("high");
  });

  it("returns high for high EPSS alone (>= 0.3)", () => {
    const e = mockEnrichment({ epss: 0.35, cess: 0.1, cvssBase: 5.0 });
    expect(e.riskTier).toBe("high");
  });

  it("returns medium for CVSS >= 7.0 without exploit signals", () => {
    const e = mockEnrichment({ cvssBase: 7.5, cess: 0.1, epss: 0.05 });
    expect(e.riskTier).toBe("medium");
  });

  it("returns medium for moderate CESS (>= 0.3)", () => {
    const e = mockEnrichment({ cess: 0.35, cvssBase: 5.0, epss: 0.05 });
    expect(e.riskTier).toBe("medium");
  });

  it("returns medium for moderate EPSS (>= 0.1)", () => {
    const e = mockEnrichment({ epss: 0.15, cess: 0.1, cvssBase: 5.0 });
    expect(e.riskTier).toBe("medium");
  });

  it("returns low for CVSS >= 4.0 without other signals", () => {
    const e = mockEnrichment({ cvssBase: 5.0, cess: 0.05, epss: 0.02 });
    expect(e.riskTier).toBe("low");
  });

  it("returns informational for very low scores across the board", () => {
    const e = mockEnrichment({ cvssBase: 2.0, cess: 0.01, epss: 0.001 });
    expect(e.riskTier).toBe("informational");
  });
});

// ─── generateRiskSummary Tests ─────────────────────────────────────────

describe("generateRiskSummary", () => {
  it("includes CISA KEV when flagged", () => {
    const e = mockEnrichment({ cisaKev: true, cess: 0.8, cvssBase: 9.8 });
    expect(e.riskSummary).toContain("CISA KEV listed");
  });

  it("includes Metasploit module count", () => {
    const e = mockEnrichment({ metasploit: 3, cvssBase: 9.0 });
    expect(e.riskSummary).toContain("3 Metasploit module(s)");
  });

  it("includes ExploitDB entry count", () => {
    const e = mockEnrichment({ exploitdb: 5 });
    expect(e.riskSummary).toContain("5 ExploitDB entry(ies)");
  });

  it("includes CESS percentage for high probability", () => {
    const e = mockEnrichment({ cess: 0.72 });
    expect(e.riskSummary).toContain("CESS 72% exploit probability");
  });

  it("does not include CESS for low probability", () => {
    const e = mockEnrichment({ cess: 0.1 });
    expect(e.riskSummary).not.toContain("CESS");
  });

  it("includes EPSS for significant scores", () => {
    const e = mockEnrichment({ epss: 0.25 });
    expect(e.riskSummary).toContain("EPSS 25.0%");
  });

  it("always includes CVSS base score", () => {
    const e = mockEnrichment({ cvssBase: 7.5 });
    expect(e.riskSummary).toContain("CVSS 7.5/10");
  });

  it("includes GitHub PoC count", () => {
    const e = mockEnrichment({ githubPocs: 4 });
    expect(e.riskSummary).toContain("4 GitHub PoC(s)");
  });

  it("uses dot separator between parts", () => {
    const e = mockEnrichment({ cisaKev: true, metasploit: 1, cess: 0.8, cvssBase: 9.8 });
    const parts = e.riskSummary.split(" · ");
    expect(parts.length).toBeGreaterThanOrEqual(3);
  });
});

// ─── summarizeExploitIntelligence Tests ─────────────────────────────────

describe("summarizeExploitIntelligence", () => {
  it("counts CISA KEV entries correctly", () => {
    const enrichments = new Map<string, EssEnrichment>();
    enrichments.set("CVE-2024-0001", mockEnrichment({ cveId: "CVE-2024-0001", cisaKev: true, cess: 0.8, cvssBase: 9.8 }));
    enrichments.set("CVE-2024-0002", mockEnrichment({ cveId: "CVE-2024-0002", cisaKev: false }));
    enrichments.set("CVE-2024-0003", mockEnrichment({ cveId: "CVE-2024-0003", cisaKev: true, cess: 0.7, cvssBase: 8.0 }));

    const summary = summarizeExploitIntelligence(enrichments);
    expect(summary.cisaKevCount).toBe(2);
    expect(summary.totalCves).toBe(3);
  });

  it("counts Metasploit and ExploitDB entries", () => {
    const enrichments = new Map<string, EssEnrichment>();
    enrichments.set("CVE-2024-0001", mockEnrichment({ cveId: "CVE-2024-0001", metasploit: 2, exploitdb: 3 }));
    enrichments.set("CVE-2024-0002", mockEnrichment({ cveId: "CVE-2024-0002", metasploit: 1 }));

    const summary = summarizeExploitIntelligence(enrichments);
    expect(summary.metasploitCount).toBe(2);
    expect(summary.exploitdbCount).toBe(1);
  });

  it("counts high CESS entries (>= 0.5)", () => {
    const enrichments = new Map<string, EssEnrichment>();
    enrichments.set("CVE-2024-0001", mockEnrichment({ cveId: "CVE-2024-0001", cess: 0.8 }));
    enrichments.set("CVE-2024-0002", mockEnrichment({ cveId: "CVE-2024-0002", cess: 0.3 }));
    enrichments.set("CVE-2024-0003", mockEnrichment({ cveId: "CVE-2024-0003", cess: 0.55 }));

    const summary = summarizeExploitIntelligence(enrichments);
    expect(summary.highCessCount).toBe(2);
  });

  it("counts critical and high risk tiers", () => {
    const enrichments = new Map<string, EssEnrichment>();
    enrichments.set("CVE-2024-0001", mockEnrichment({ cveId: "CVE-2024-0001", cisaKev: true, cess: 0.9, cvssBase: 9.8 }));
    enrichments.set("CVE-2024-0002", mockEnrichment({ cveId: "CVE-2024-0002", exploitdb: 2, cess: 0.2 }));
    enrichments.set("CVE-2024-0003", mockEnrichment({ cveId: "CVE-2024-0003", cvssBase: 3.0, cess: 0.01 }));

    const summary = summarizeExploitIntelligence(enrichments);
    expect(summary.criticalRiskCount).toBe(1);
    expect(summary.highRiskCount).toBe(1);
  });

  it("returns topThreats sorted by CESS score descending", () => {
    const enrichments = new Map<string, EssEnrichment>();
    enrichments.set("CVE-2024-0001", mockEnrichment({ cveId: "CVE-2024-0001", cess: 0.3 }));
    enrichments.set("CVE-2024-0002", mockEnrichment({ cveId: "CVE-2024-0002", cess: 0.9 }));
    enrichments.set("CVE-2024-0003", mockEnrichment({ cveId: "CVE-2024-0003", cess: 0.6 }));

    const summary = summarizeExploitIntelligence(enrichments);
    expect(summary.topThreats[0].cveId).toBe("CVE-2024-0002");
    expect(summary.topThreats[1].cveId).toBe("CVE-2024-0003");
    expect(summary.topThreats[2].cveId).toBe("CVE-2024-0001");
  });

  it("limits topThreats to 10 entries", () => {
    const enrichments = new Map<string, EssEnrichment>();
    for (let i = 0; i < 15; i++) {
      enrichments.set(`CVE-2024-${String(i).padStart(4, "0")}`, mockEnrichment({
        cveId: `CVE-2024-${String(i).padStart(4, "0")}`,
        cess: Math.random(),
      }));
    }

    const summary = summarizeExploitIntelligence(enrichments);
    expect(summary.topThreats.length).toBe(10);
    expect(summary.totalCves).toBe(15);
  });

  it("handles empty enrichments map", () => {
    const summary = summarizeExploitIntelligence(new Map());
    expect(summary.totalCves).toBe(0);
    expect(summary.cisaKevCount).toBe(0);
    expect(summary.topThreats).toHaveLength(0);
  });
});

// ─── Cache Tests ───────────────────────────────────────────────────────

describe("cache management", () => {
  beforeEach(() => {
    clearCache();
  });

  it("clearCache resets cache size to 0", () => {
    clearCache();
    expect(getCacheSize()).toBe(0);
  });

  it("getCacheSize returns current cache count", () => {
    // After clear, should be 0
    expect(getCacheSize()).toBe(0);
  });
});

// ─── Risk Tier Edge Cases ──────────────────────────────────────────────

describe("computeRiskTier edge cases", () => {
  it("CISA KEV with CESS exactly 0.7 is critical", () => {
    const e = mockEnrichment({ cisaKev: true, cess: 0.7 });
    expect(e.riskTier).toBe("critical");
  });

  it("CISA KEV with CESS 0.69 is high (not critical)", () => {
    const e = mockEnrichment({ cisaKev: true, cess: 0.69, cvssBase: 5.0 });
    expect(e.riskTier).toBe("high");
  });

  it("CESS exactly 0.8 + EPSS exactly 0.5 is critical", () => {
    const e = mockEnrichment({ cess: 0.8, epss: 0.5, cvssBase: 5.0 });
    expect(e.riskTier).toBe("critical");
  });

  it("CESS exactly 0.6 is high", () => {
    const e = mockEnrichment({ cess: 0.6, cvssBase: 5.0, epss: 0.05 });
    expect(e.riskTier).toBe("high");
  });

  it("CVSS exactly 7.0 is medium", () => {
    const e = mockEnrichment({ cvssBase: 7.0, cess: 0.1, epss: 0.05 });
    expect(e.riskTier).toBe("medium");
  });

  it("CVSS exactly 4.0 is low", () => {
    const e = mockEnrichment({ cvssBase: 4.0, cess: 0.05, epss: 0.02 });
    expect(e.riskTier).toBe("low");
  });

  it("all zeros returns informational", () => {
    const e = mockEnrichment({ cvssBase: 0, cess: 0, epss: 0 });
    expect(e.riskTier).toBe("informational");
  });
});

// ─── Coalition Control Connector Tests ─────────────────────────────────

describe("Coalition Control connector (BinaryEdge replacement)", () => {
  it("connector module exports required interface", async () => {
    const mod = await import("./lib/passive/coalition-control");
    const connector = mod.coalitionControlConnector;
    expect(connector).toBeDefined();
    expect(connector.name).toBe("coalition_control");
    expect(connector.description).toBeDefined();
    expect(typeof connector.collect).toBe("function");
    expect(connector.requiresApiKey).toBe(true);
  });

  it("connector skips when no credentials are configured", async () => {
    const mod = await import("./lib/passive/coalition-control");
    const connector = mod.coalitionControlConnector;
    // With no env vars set, collect should return empty observations with an error
    const result = await connector.collect("example.com");
    expect(result.observations).toHaveLength(0);
    expect(result.connector).toBe("coalition_control");
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain("not configured");
  });
});
