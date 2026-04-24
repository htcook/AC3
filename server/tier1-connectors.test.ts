import { describe, it, expect } from "vitest";

// === Connector Module Imports ===
import { urlhausConnector } from "./lib/passive/urlhaus";
import { malwarebazaarConnector } from "./lib/passive/malwarebazaar";
import { secEdgarConnector } from "./lib/passive/sec-edgar";
import { osvDevConnector } from "./lib/passive/osv-dev";
import { teamCymruConnector } from "./lib/passive/team-cymru";
import { cisaAdvisoriesConnector } from "./lib/passive/cisa-advisories";

// === Architectural Module Imports ===
import {
  getEvidenceMultiplier,
  getEvidenceTier,
  isAuthoritativeFor,
  applyEvidenceMultiplier,
  getConfidenceLanguage,
  getEvidenceTierSummary,
  EVIDENCE_MULTIPLIER_MAP,
} from "./lib/passive/evidence-multiplier";

import {
  osintRateLimiter,
  CONNECTOR_RATE_LIMITS,
} from "./lib/passive/rate-limiter";

import {
  getTosEntry,
  requiresAttribution,
  getAttributionText,
  isCachingAllowed,
  isReportInclusionAllowed,
  getGdprRestrictedConnectors,
  getAttributionRequiredConnectors,
  generateComplianceSummary,
  TOS_REGISTRY,
} from "./lib/passive/tos-compliance";

// === Connector Registration ===
import { ALL_CONNECTORS } from "./lib/passive/index";

describe("Tier 1 Connector Registration", () => {
  it("all 6 new connectors are registered in ALL_CONNECTORS", () => {
    const names = ALL_CONNECTORS.map(c => c.name);
    expect(names).toContain("urlhaus");
    expect(names).toContain("malwarebazaar");
    expect(names).toContain("sec_edgar");
    expect(names).toContain("osv_dev");
    expect(names).toContain("team_cymru");
    expect(names).toContain("cisa_advisories");
  });
});

describe("URLhaus Connector", () => {
  it("has correct metadata", () => {
    expect(urlhausConnector.name).toBe("urlhaus");
    expect(urlhausConnector.requiresApiKey).toBe(false);
    expect(urlhausConnector.description).toContain("abuse.ch");
  });

  it("collect returns valid ConnectorResult shape", async () => {
    const result = await urlhausConnector.collect("test-nonexistent-domain.invalid");
    expect(result.connector).toBe("urlhaus");
    expect(result.domain).toBe("test-nonexistent-domain.invalid");
    expect(Array.isArray(result.observations)).toBe(true);
    expect(Array.isArray(result.errors)).toBe(true);
    expect(typeof result.durationMs).toBe("number");
  });
});

describe("MalwareBazaar Connector", () => {
  it("has correct metadata", () => {
    expect(malwarebazaarConnector.name).toBe("malwarebazaar");
    expect(malwarebazaarConnector.requiresApiKey).toBe(false);
    expect(malwarebazaarConnector.description).toContain("abuse.ch");
  });

  it("collect returns valid ConnectorResult shape", async () => {
    const result = await malwarebazaarConnector.collect("test-nonexistent-domain.invalid");
    expect(result.connector).toBe("malwarebazaar");
    expect(result.domain).toBe("test-nonexistent-domain.invalid");
    expect(Array.isArray(result.observations)).toBe(true);
    expect(Array.isArray(result.errors)).toBe(true);
  });
});

describe("SEC EDGAR Connector", () => {
  it("has correct metadata", () => {
    expect(secEdgarConnector.name).toBe("sec_edgar");
    expect(secEdgarConnector.requiresApiKey).toBe(false);
    expect(secEdgarConnector.description).toContain("SEC EDGAR");
  });

  it("collect returns valid ConnectorResult shape", async () => {
    const result = await secEdgarConnector.collect("test-nonexistent-domain.invalid");
    expect(result.connector).toBe("sec_edgar");
    expect(result.domain).toBe("test-nonexistent-domain.invalid");
    expect(Array.isArray(result.observations)).toBe(true);
  });
});

describe("OSV.dev Connector", () => {
  it("has correct metadata", () => {
    expect(osvDevConnector.name).toBe("osv_dev");
    expect(osvDevConnector.requiresApiKey).toBe(false);
    expect(osvDevConnector.description).toContain("OSV.dev");
  });

  it("collect returns valid ConnectorResult shape with no tech stack", async () => {
    const result = await osvDevConnector.collect("test-nonexistent-domain.invalid");
    expect(result.connector).toBe("osv_dev");
    expect(Array.isArray(result.observations)).toBe(true);
    // With no prior observations, should return a no-tech-stack info observation
    if (result.observations.length > 0) {
      expect(result.observations[0].tags).toContain("osv_dev");
    }
  });
});

describe("Team Cymru Connector", () => {
  it("has correct metadata", () => {
    expect(teamCymruConnector.name).toBe("team_cymru");
    expect(teamCymruConnector.requiresApiKey).toBe(false);
    expect(teamCymruConnector.description).toContain("Team Cymru");
  });

  it("collect returns valid ConnectorResult shape", async () => {
    const result = await teamCymruConnector.collect("test-nonexistent-domain.invalid");
    expect(result.connector).toBe("team_cymru");
    expect(Array.isArray(result.observations)).toBe(true);
  });
});

describe("CISA Advisories Connector", () => {
  it("has correct metadata", () => {
    expect(cisaAdvisoriesConnector.name).toBe("cisa_advisories");
    expect(cisaAdvisoriesConnector.requiresApiKey).toBe(false);
    expect(cisaAdvisoriesConnector.description).toContain("CISA");
  });

  it("collect returns valid ConnectorResult shape", async () => {
    const result = await cisaAdvisoriesConnector.collect("test-nonexistent-domain.invalid");
    expect(result.connector).toBe("cisa_advisories");
    expect(Array.isArray(result.observations)).toBe(true);
  });
});

// === Evidence Multiplier Tests ===
describe("Evidence Multiplier Mapping", () => {
  it("confirmed tier connectors have 1.0 multiplier", () => {
    expect(getEvidenceMultiplier("shodan")).toBe(1.0);
    expect(getEvidenceMultiplier("cisa_advisories")).toBe(1.0);
    expect(getEvidenceMultiplier("team_cymru")).toBe(1.0);
    expect(getEvidenceMultiplier("sec_edgar")).toBe(1.0);
    expect(getEvidenceMultiplier("dehashed")).toBe(1.0);
    expect(getEvidenceMultiplier("hibp")).toBe(1.0);
  });

  it("corroborated tier connectors have 0.8 multiplier", () => {
    expect(getEvidenceMultiplier("virustotal")).toBe(0.8);
    expect(getEvidenceMultiplier("urlhaus")).toBe(0.8);
    expect(getEvidenceMultiplier("malwarebazaar")).toBe(0.8);
    expect(getEvidenceMultiplier("osv_dev")).toBe(0.8);
  });

  it("unverified tier connectors have 0.5 multiplier", () => {
    expect(getEvidenceMultiplier("wayback")).toBe(0.5);
    expect(getEvidenceMultiplier("github_leaks")).toBe(0.5);
    expect(getEvidenceMultiplier("builtwith")).toBe(0.5);
  });

  it("unknown connectors default to 0.5", () => {
    expect(getEvidenceMultiplier("nonexistent_connector")).toBe(0.5);
  });

  it("getEvidenceTier returns correct tiers", () => {
    expect(getEvidenceTier("shodan")).toBe("confirmed");
    expect(getEvidenceTier("virustotal")).toBe("corroborated");
    expect(getEvidenceTier("wayback")).toBe("unverified");
  });

  it("isAuthoritativeFor checks data types correctly", () => {
    expect(isAuthoritativeFor("shodan", "ports")).toBe(true);
    expect(isAuthoritativeFor("shodan", "breach_credentials")).toBe(false);
    expect(isAuthoritativeFor("cisa_advisories", "kev")).toBe(true);
    expect(isAuthoritativeFor("wayback", "ports")).toBe(false);
  });

  it("applyEvidenceMultiplier adjusts severity correctly", () => {
    expect(applyEvidenceMultiplier("shodan", 10)).toBe(10);     // 10 * 1.0
    expect(applyEvidenceMultiplier("virustotal", 10)).toBe(8);  // 10 * 0.8
    expect(applyEvidenceMultiplier("wayback", 10)).toBe(5);     // 10 * 0.5
  });

  it("getConfidenceLanguage returns appropriate language", () => {
    expect(getConfidenceLanguage("shodan").prefix).toBe("Confirmed");
    expect(getConfidenceLanguage("virustotal").prefix).toBe("Likely");
    expect(getConfidenceLanguage("wayback").prefix).toBe("Possible");
  });

  it("getEvidenceTierSummary returns all three tiers", () => {
    const summary = getEvidenceTierSummary();
    expect(summary.confirmed.length).toBeGreaterThan(0);
    expect(summary.corroborated.length).toBeGreaterThan(0);
    expect(summary.unverified.length).toBeGreaterThan(0);
    expect(summary.confirmed).toContain("shodan");
    expect(summary.corroborated).toContain("urlhaus");
    expect(summary.unverified).toContain("wayback");
  });

  it("all new connectors have evidence multiplier entries", () => {
    expect(EVIDENCE_MULTIPLIER_MAP["urlhaus"]).toBeDefined();
    expect(EVIDENCE_MULTIPLIER_MAP["malwarebazaar"]).toBeDefined();
    expect(EVIDENCE_MULTIPLIER_MAP["sec_edgar"]).toBeDefined();
    expect(EVIDENCE_MULTIPLIER_MAP["osv_dev"]).toBeDefined();
    expect(EVIDENCE_MULTIPLIER_MAP["team_cymru"]).toBeDefined();
    expect(EVIDENCE_MULTIPLIER_MAP["cisa_advisories"]).toBeDefined();
  });
});

// === Rate Limiter Tests ===
describe("Unified OSINT Rate Limiter", () => {
  it("all new connectors have rate limit configs", () => {
    expect(CONNECTOR_RATE_LIMITS["urlhaus"]).toBeDefined();
    expect(CONNECTOR_RATE_LIMITS["malwarebazaar"]).toBeDefined();
    expect(CONNECTOR_RATE_LIMITS["sec_edgar"]).toBeDefined();
    expect(CONNECTOR_RATE_LIMITS["osv_dev"]).toBeDefined();
    expect(CONNECTOR_RATE_LIMITS["team_cymru"]).toBeDefined();
    expect(CONNECTOR_RATE_LIMITS["cisa_advisories"]).toBeDefined();
  });

  it("tryAcquire allows initial requests", () => {
    osintRateLimiter.reset();
    expect(osintRateLimiter.tryAcquire("urlhaus")).toBe(true);
    expect(osintRateLimiter.tryAcquire("malwarebazaar")).toBe(true);
  });

  it("getStatus returns stats for active connectors", () => {
    osintRateLimiter.reset();
    osintRateLimiter.tryAcquire("urlhaus");
    const status = osintRateLimiter.getStatus();
    expect(status["__global__"]).toBeDefined();
    expect(status["urlhaus"]).toBeDefined();
    expect(status["urlhaus"].totalRequests).toBe(1);
  });

  it("report429 activates backoff", () => {
    osintRateLimiter.reset();
    osintRateLimiter.tryAcquire("urlhaus");
    osintRateLimiter.report429("urlhaus");
    const status = osintRateLimiter.getConnectorStatus("urlhaus");
    expect(status!.total429s).toBe(1);
    expect(status!.backoffLevel).toBe(1);
  });

  it("rate limit configs have valid structure", () => {
    for (const [name, config] of Object.entries(CONNECTOR_RATE_LIMITS)) {
      expect(config.maxRequests).toBeGreaterThan(0);
      expect(config.windowMs).toBeGreaterThan(0);
    }
  });
});

// === ToS Compliance Registry Tests ===
describe("ToS Compliance Registry", () => {
  it("all new connectors have ToS entries", () => {
    expect(TOS_REGISTRY["urlhaus"]).toBeDefined();
    expect(TOS_REGISTRY["malwarebazaar"]).toBeDefined();
    expect(TOS_REGISTRY["sec_edgar"]).toBeDefined();
    expect(TOS_REGISTRY["osv_dev"]).toBeDefined();
    expect(TOS_REGISTRY["team_cymru"]).toBeDefined();
    expect(TOS_REGISTRY["cisa_advisories"]).toBeDefined();
  });

  it("getTosEntry returns correct entries", () => {
    const entry = getTosEntry("cisa_advisories");
    expect(entry).not.toBeNull();
    expect(entry!.sourceName).toContain("CISA");
    expect(entry!.dataClassification).toBe("government");
  });

  it("requiresAttribution identifies correct connectors", () => {
    expect(requiresAttribution("urlhaus")).toBe(true);
    expect(requiresAttribution("cisa_advisories")).toBe(true);
    expect(requiresAttribution("shodan")).toBe(false);
  });

  it("getAttributionText returns text for attributed connectors", () => {
    expect(getAttributionText("urlhaus")).toContain("URLhaus");
    expect(getAttributionText("cisa_advisories")).toContain("CISA");
  });

  it("isCachingAllowed correctly identifies breach data", () => {
    expect(isCachingAllowed("cisa_advisories")).toBe(true);
    expect(isCachingAllowed("dehashed")).toBe(false);
    expect(isCachingAllowed("hibp")).toBe(false);
  });

  it("isReportInclusionAllowed is true for all connectors", () => {
    for (const entry of Object.values(TOS_REGISTRY)) {
      expect(isReportInclusionAllowed(entry.connector)).toBe(true);
    }
  });

  it("getGdprRestrictedConnectors returns breach data sources", () => {
    const gdpr = getGdprRestrictedConnectors();
    const names = gdpr.map(g => g.connector);
    expect(names).toContain("dehashed");
    expect(names).toContain("hibp");
    expect(names).toContain("hudson_rock");
    expect(names).not.toContain("shodan");
  });

  it("getAttributionRequiredConnectors returns correct list", () => {
    const attrs = getAttributionRequiredConnectors();
    const names = attrs.map(a => a.connector);
    expect(names).toContain("urlhaus");
    expect(names).toContain("cisa_advisories");
    expect(names).toContain("osv_dev");
  });

  it("generateComplianceSummary produces correct output", () => {
    const summary = generateComplianceSummary(["urlhaus", "dehashed", "cisa_advisories", "shodan"]);
    expect(summary.attributions.length).toBeGreaterThan(0);
    expect(summary.gdprWarnings.length).toBeGreaterThan(0);
    expect(summary.restrictions.length).toBeGreaterThan(0);
    expect(summary.lastReviewDates.length).toBe(4);
  });

  it("all ToS entries have required fields", () => {
    for (const [name, entry] of Object.entries(TOS_REGISTRY)) {
      expect(entry.connector).toBe(name);
      expect(entry.sourceName).toBeTruthy();
      expect(entry.tosUrl).toBeTruthy();
      expect(entry.dataClassification).toBeTruthy();
      expect(Array.isArray(entry.restrictions)).toBe(true);
      expect(typeof entry.attributionRequired).toBe("boolean");
      expect(typeof entry.cachingAllowed).toBe("boolean");
      expect(typeof entry.reportInclusionAllowed).toBe("boolean");
      expect(typeof entry.thirdPartyShareAllowed).toBe("boolean");
      expect(entry.lastReviewDate).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
  });
});
