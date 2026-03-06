/**
 * KEV-Enhanced Scoring Integration Tests
 * Validates that CISA KEV matches properly boost risk scores
 * and differentiate between regular KEV and ransomware-linked KEV entries.
 */
import { describe, it, expect } from "vitest";
import { DISCOVERY_PHASE_TRIGGERS } from "./lib/scoring-engine";

describe("KEV-Enhanced Scoring Triggers", () => {
  it("kev_match trigger exists in DISCOVERY_PHASE_TRIGGERS", () => {
    expect(DISCOVERY_PHASE_TRIGGERS).toHaveProperty("kev_match");
  });

  it("kev_match trigger has correct description", () => {
    expect(DISCOVERY_PHASE_TRIGGERS.kev_match.description).toContain("CISA Known Exploited Vulnerabilities");
  });

  it("kev_match CARVER adjustments set vulnerability to max (10)", () => {
    const adjustments = DISCOVERY_PHASE_TRIGGERS.kev_match.carverAdjustments({});
    expect(adjustments.vulnerability).toBe(10);
    expect(adjustments.recognizability).toBe(8);
  });

  it("kev_match with ransomware flag boosts criticality and effect", () => {
    const adjustments = DISCOVERY_PHASE_TRIGGERS.kev_match.carverAdjustments({ ransomware: true });
    expect(adjustments.vulnerability).toBe(10);
    expect(adjustments.criticality).toBe(9);
    expect(adjustments.effect).toBe(9);
  });

  it("kev_match with overdue action flag boosts accessibility", () => {
    const adjustments = DISCOVERY_PHASE_TRIGGERS.kev_match.carverAdjustments({ overdueAction: true });
    expect(adjustments.accessibility).toBe(9);
  });

  it("kev_match ransomware shock adjustments are higher than non-ransomware", () => {
    const normalShock = DISCOVERY_PHASE_TRIGGERS.kev_match.shockAdjustments({});
    const ransomwareShock = DISCOVERY_PHASE_TRIGGERS.kev_match.shockAdjustments({ ransomware: true });
    expect(ransomwareShock.scope).toBeGreaterThan(normalShock.scope);
    expect(ransomwareShock.handling).toBeGreaterThan(normalShock.handling);
    expect(ransomwareShock.cascadingEffects).toBe(9);
    expect(ransomwareShock.operationalImpact).toBe(9);
  });

  it("kev_match ransomware likelihood boost (0.45) > non-ransomware (0.3)", () => {
    const normalBoost = DISCOVERY_PHASE_TRIGGERS.kev_match.likelihoodBoost({});
    const ransomwareBoost = DISCOVERY_PHASE_TRIGGERS.kev_match.likelihoodBoost({ ransomware: true });
    expect(normalBoost).toBe(0.3);
    expect(ransomwareBoost).toBe(0.45);
    expect(ransomwareBoost).toBeGreaterThan(normalBoost);
  });

  it("attack_chain_match trigger exists and scores by feasibility", () => {
    expect(DISCOVERY_PHASE_TRIGGERS).toHaveProperty("attack_chain_match");
    const highFeasibility = DISCOVERY_PHASE_TRIGGERS.attack_chain_match.carverAdjustments({ feasibility: "high" });
    const lowFeasibility = DISCOVERY_PHASE_TRIGGERS.attack_chain_match.carverAdjustments({ feasibility: "low" });
    expect(highFeasibility.vulnerability).toBeGreaterThan(lowFeasibility.vulnerability!);
  });

  it("bug_bounty_correlation trigger exists", () => {
    expect(DISCOVERY_PHASE_TRIGGERS).toHaveProperty("bug_bounty_correlation");
    const adjustments = DISCOVERY_PHASE_TRIGGERS.bug_bounty_correlation.carverAdjustments({ bountyTier: "critical" });
    expect(adjustments.vulnerability).toBeDefined();
  });
});
