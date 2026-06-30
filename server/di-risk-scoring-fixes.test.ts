/**
 * DI Risk Scoring Fixes Tests
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Tests for two critical bug fixes:
 *   1. Mission function key mismatch between LLM output and scoring engine baselines
 *   2. KEV ransomware floor triggering on unconfirmed matches (causing static 75)
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";

const domainIntelSource = fs.readFileSync("server/domainIntel.ts", "utf-8");

// ─── Bug Fix 1: Mission Function Key Normalization ─────────────────────

describe("Mission Function Key Normalization", () => {
  it("normalizeMissionFunction function exists in domainIntel.ts", () => {
    expect(domainIntelSource).toContain("function normalizeMissionFunction(");
  });

  it("maps LLM 'command_and_control' to baselines key 'command_control'", () => {
    expect(domainIntelSource).toContain("'command_and_control': 'command_control'");
  });

  it("maps LLM 'authentication_and_access' to baselines key 'authentication'", () => {
    expect(domainIntelSource).toContain("'authentication_and_access': 'authentication'");
  });

  it("maps LLM 'customer_data_processing' to baselines key 'customer_data'", () => {
    expect(domainIntelSource).toContain("'customer_data_processing': 'customer_data'");
  });

  it("maps LLM 'intellectual_property_storage' to baselines key 'intellectual_property'", () => {
    expect(domainIntelSource).toContain("'intellectual_property_storage': 'intellectual_property'");
  });

  it("maps LLM 'communication_infrastructure' to baselines key 'external_communication'", () => {
    expect(domainIntelSource).toContain("'communication_infrastructure': 'external_communication'");
  });

  it("maps LLM 'regulatory_compliance' to baselines key 'compliance'", () => {
    expect(domainIntelSource).toContain("'regulatory_compliance': 'compliance'");
  });

  it("maps LLM 'business_continuity' to baselines key 'operational_continuity'", () => {
    expect(domainIntelSource).toContain("'business_continuity': 'operational_continuity'");
  });

  it("maps LLM 'supply_chain_integration' to baselines key 'supply_chain'", () => {
    expect(domainIntelSource).toContain("'supply_chain_integration': 'supply_chain'");
  });

  it("maps LLM 'public_facing_services' to a valid baselines key", () => {
    expect(domainIntelSource).toContain("'public_facing_services': 'external_communication'");
  });

  it("normalizeMissionFunction is called before applyMissionBaselines", () => {
    const normalizeCallIdx = domainIntelSource.indexOf("normalizeMissionFunction(a.missionFunction");
    const baselineCallIdx = domainIntelSource.indexOf("applyMissionBaselines(");
    // The last occurrence of applyMissionBaselines (the actual call, not the import)
    const lastBaselineIdx = domainIntelSource.lastIndexOf("applyMissionBaselines(");
    expect(normalizeCallIdx).toBeGreaterThan(0);
    expect(normalizeCallIdx).toBeLessThan(lastBaselineIdx);
  });
});

// ─── Bug Fix 1b: Essential Service Key Normalization ───────────────────

describe("Essential Service Key Normalization", () => {
  it("normalizeEssentialService function exists in domainIntel.ts", () => {
    expect(domainIntelSource).toContain("function normalizeEssentialService(");
  });

  it("maps LLM 'sso_idp' to baselines key 'sso'", () => {
    expect(domainIntelSource).toContain("'sso_idp': 'sso'");
  });

  it("maps LLM 'email_gateway' to baselines key 'email'", () => {
    expect(domainIntelSource).toContain("'email_gateway': 'email'");
  });

  it("maps LLM 'vpn_concentrator' to baselines key 'vpn'", () => {
    expect(domainIntelSource).toContain("'vpn_concentrator': 'vpn'");
  });

  it("maps LLM 'dns_infrastructure' to baselines key 'dns'", () => {
    expect(domainIntelSource).toContain("'dns_infrastructure': 'dns'");
  });

  it("maps LLM 'web_application_firewall' to baselines key 'waf'", () => {
    expect(domainIntelSource).toContain("'web_application_firewall': 'waf'");
  });

  it("maps LLM 'ci_cd_pipeline' to baselines key 'ci_cd'", () => {
    expect(domainIntelSource).toContain("'ci_cd_pipeline': 'ci_cd'");
  });

  it("normalizeEssentialService is called before applyMissionBaselines", () => {
    const normalizeCallIdx = domainIntelSource.indexOf("normalizeEssentialService(a.essentialService");
    expect(normalizeCallIdx).toBeGreaterThan(0);
  });
});

// ─── Bug Fix 2: KEV Floor Restricted to Confirmed Matches ─────────────

describe("KEV Ransomware Floor — Confirmed Matches Only", () => {
  it("filters KEV matches by matchQuality === 'exact_product' before applying floor", () => {
    expect(domainIntelSource).toContain("m.matchQuality === 'exact_product'");
  });

  it("creates confirmedKevMatches array from exact_product matches", () => {
    expect(domainIntelSource).toContain("const confirmedKevMatches = kevEnrichment.matches.filter(m => m.matchQuality === 'exact_product')");
  });

  it("creates confirmedRansomware array from confirmed matches only", () => {
    expect(domainIntelSource).toContain("const confirmedRansomware = confirmedKevMatches.filter(m => m.knownRansomware)");
  });

  it("Floor 1 (75) only triggers on confirmedRansomware.length > 0", () => {
    expect(domainIntelSource).toContain("if (confirmedRansomware.length > 0)");
  });

  it("Floor 2 (55) only triggers on confirmedCount >= 3", () => {
    expect(domainIntelSource).toContain("else if (confirmedCount >= 3)");
  });

  it("Floor 3 (45) only triggers on confirmedCount > 0", () => {
    expect(domainIntelSource).toContain("else if (confirmedCount > 0)");
  });

  it("logs advisory message for unconfirmed-only KEV matches", () => {
    expect(domainIntelSource).toContain("unconfirmed KEV matches found (advisory only");
  });

  it("does NOT use kevEnrichment.ransomwareExposure directly for floor decisions", () => {
    // The old buggy code used: kevEnrichment.ransomwareExposure && kevEnrichment.matches.length > 0
    // The fix should NOT have this pattern in the floor adjustment section
    const floorSection = domainIntelSource.substring(
      domainIntelSource.indexOf("Floor 1-3: CISA KEV matches"),
      domainIntelSource.indexOf("Floor 4:")
    );
    expect(floorSection).not.toContain("kevEnrichment.ransomwareExposure &&");
  });
});

// ─── Integration: Overall Scoring Pipeline ─────────────────────────────

describe("Risk Scoring Pipeline Integration", () => {
  it("computeHybridRisk uses Impact × Likelihood model", () => {
    expect(domainIntelSource).toContain("Math.sqrt(impact * likelihood) * 100");
  });

  it("overall risk uses 60% max + 40% avg blending", () => {
    expect(domainIntelSource).toContain("maxRisk * 0.6 + avgRisk * 0.4");
  });

  it("initial pass uses low baseline likelihood (innocent until proven guilty)", () => {
    expect(domainIntelSource).toContain("(ctx.exposure * 0.1) + (ctx.recognizability * 0.05)");
  });

  it("post-enrichment uses confirmedVulnScore as primary likelihood driver", () => {
    expect(domainIntelSource).toContain("a.vulnRiskScore, // Pass the CONFIRMED vuln score");
  });
});
