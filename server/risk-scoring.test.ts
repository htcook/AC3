import { describe, it, expect } from "vitest";

/**
 * Tests for the Confirmed-Only Risk Scoring Model (Feb 2026):
 *
 * IMPACT: Derived from CARVER/SHOCK mission impact (how bad if compromised)
 * LIKELIHOOD: Driven ONLY by confirmed/probable vulnerabilities (version-matched CVEs, KEV, zero-days)
 *   - Unconfirmed/potential vulns are recorded as weaknesses but DO NOT affect risk score
 *   - If no confirmed vulns exist, Likelihood drops to baseline low (~5-15%)
 * RISK = sqrt(Impact × Likelihood) × 100
 *
 * Key principle: A critical asset with no confirmed vulnerabilities = high impact, LOW risk.
 */

// ─── Scoring Functions (mirroring domainIntel.ts) ───

function clamp(v: number, min: number, max: number) {
  return Math.max(min, Math.min(max, v));
}

function normalizeCarver(raw: any) {
  return {
    criticality: clamp(raw.criticality || 3, 0, 10),
    accessibility: clamp(raw.accessibility || 3, 0, 10),
    recuperability: clamp(raw.recuperability || 3, 0, 10),
    vulnerability: clamp(raw.vulnerability || 3, 0, 10),
    effect: clamp(raw.effect || 3, 0, 10),
    recognizability: clamp(raw.recognizability || 3, 0, 10),
  };
}

function normalizeShock(raw: any) {
  return {
    scope: clamp(raw.scope || 3, 0, 10),
    handling: clamp(raw.handling || 3, 0, 10),
    operationalImpact: clamp(raw.operationalImpact || 3, 0, 10),
    cascadingEffects: clamp(raw.cascadingEffects || 3, 0, 10),
    knowledge: clamp(raw.knowledge || 3, 0, 10),
  };
}

function computeMissionImpact(carver: any, shock: any) {
  const carverWeights: Record<string, number> = { criticality: 2, accessibility: 1.5, recuperability: 1, vulnerability: 1.5, effect: 1.5, recognizability: 0.5 };
  const shockWeights: Record<string, number> = { scope: 1.5, handling: 1, operationalImpact: 2, cascadingEffects: 1.5, knowledge: 1 };

  let carverSum = 0, carverWeightSum = 0;
  for (const [k, w] of Object.entries(carverWeights)) {
    carverSum += (carver[k] || 0) * w;
    carverWeightSum += w;
  }
  const carverScore = carverSum / carverWeightSum;

  let shockSum = 0, shockWeightSum = 0;
  for (const [k, w] of Object.entries(shockWeights)) {
    shockSum += (shock[k] || 0) * w;
    shockWeightSum += w;
  }
  const shockScore = shockSum / shockWeightSum;

  return (carverScore + shockScore) / 2;
}

// Confirmed-Only Impact × Likelihood model
function computeHybridRisk(
  cvss: number,
  missionImpact: number,
  ctx: { exposure: number; recognizability: number; confidence: number },
  confirmedVulnScore?: number
) {
  const impact = clamp(missionImpact / 10, 0, 1);
  let likelihoodBase: number;

  if (confirmedVulnScore !== undefined) {
    // POST-ENRICHMENT: Use confirmed vuln score for Likelihood
    const vulnNorm = clamp(confirmedVulnScore / 100, 0, 1);
    if (vulnNorm === 0) {
      // No confirmed vulns → baseline low Likelihood from exposure/recognizability only
      likelihoodBase = clamp((ctx.exposure * 0.1) + (ctx.recognizability * 0.05), 0, 0.15);
    } else {
      likelihoodBase = vulnNorm;
      likelihoodBase += (ctx.exposure - 0.5) * 0.2;
      likelihoodBase += (ctx.recognizability - 0.5) * 0.1;
    }
  } else {
    // INITIAL PASS (pre-enrichment): Use LLM CVSS estimate as placeholder
    const cvssNorm = clamp(cvss / 10, 0, 1);
    likelihoodBase = cvssNorm;
    likelihoodBase += (ctx.exposure - 0.5) * 0.2;
    likelihoodBase += (ctx.recognizability - 0.5) * 0.1;
  }

  likelihoodBase = clamp(likelihoodBase, 0, 1);
  const confidenceDampening = 0.55 + (ctx.confidence * 0.45);
  const likelihood = clamp(likelihoodBase * confidenceDampening, 0, 1);
  const score = clamp(Math.round(Math.sqrt(impact * likelihood) * 100), 0, 100);
  return { score, band: riskBand(score), impact: Math.round(impact * 100), likelihood: Math.round(likelihood * 100) };
}

function riskBand(score: number): string {
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function riskTier(score: number): string {
  if (score >= 90) return "tier0_critical";
  if (score >= 70) return "tier1_high";
  if (score >= 40) return "tier2_medium";
  return "tier3_low";
}

function computeAssetCriticality(missionImpact: number) {
  const score = clamp(Math.round(missionImpact * 10), 0, 100);
  return { score, band: riskBand(score) };
}

function computeVulnRisk(findings: Array<{ severity: number; corroborationTier: string }>) {
  const actionable = findings.filter(f => f.corroborationTier === "confirmed" || f.corroborationTier === "probable");
  if (actionable.length === 0) return { score: 0, band: "low" };

  let maxSeverity = 0;
  let weightedSum = 0;
  for (const f of actionable) {
    const weight = f.corroborationTier === "confirmed" ? 1.0 : 0.6;
    const findingScore = (f.severity / 10) * 100 * weight;
    weightedSum += findingScore;
    if (f.severity > maxSeverity) maxSeverity = f.severity;
  }

  const avgWeighted = weightedSum / actionable.length;
  const maxNorm = (maxSeverity / 10) * 100;
  const score = clamp(Math.round(maxNorm * 0.6 + avgWeighted * 0.4), 0, 100);
  return { score, band: riskBand(score) };
}

// ─── DEFAULTS ───

describe("Risk Scoring - Defaults", () => {
  it("should default CARVER scores to 3 for missing data", () => {
    const carver = normalizeCarver({});
    expect(carver.criticality).toBe(3);
    expect(carver.accessibility).toBe(3);
    expect(carver.vulnerability).toBe(3);
  });

  it("should default SHOCK scores to 3 for missing data", () => {
    const shock = normalizeShock({});
    expect(shock.scope).toBe(3);
    expect(shock.operationalImpact).toBe(3);
  });

  it("should preserve actual scores when provided", () => {
    const carver = normalizeCarver({ criticality: 8, accessibility: 7 });
    expect(carver.criticality).toBe(8);
    expect(carver.accessibility).toBe(7);
    expect(carver.recuperability).toBe(3); // default
  });

  it("should clamp scores to 0-10 range", () => {
    const carver = normalizeCarver({ criticality: 15, accessibility: -3 });
    expect(carver.criticality).toBe(10);
    expect(carver.accessibility).toBe(0);
  });
});

// ─── CONFIRMED-ONLY SCORING: CORE PRINCIPLE ───

describe("Confirmed-Only Scoring - Core Principle", () => {
  const ctx = { exposure: 0.6, recognizability: 0.5, confidence: 0.4 };

  it("critical asset with NO confirmed vulns should be LOW risk", () => {
    const result = computeHybridRisk(7, 8, ctx, 0);
    expect(result.impact).toBe(80);
    expect(result.likelihood).toBeLessThanOrEqual(10);
    expect(result.band).toBe("low");
    expect(result.score).toBeLessThan(30);
  });

  it("critical asset with LOW confirmed vulns should be MEDIUM risk", () => {
    const result = computeHybridRisk(7, 8, ctx, 30);
    expect(result.impact).toBe(80);
    expect(result.band).toBe("medium");
    expect(result.score).toBeGreaterThanOrEqual(40);
    expect(result.score).toBeLessThan(70);
  });

  it("critical asset with MEDIUM confirmed vulns should be MEDIUM risk", () => {
    const result = computeHybridRisk(7, 8, ctx, 60);
    expect(result.impact).toBe(80);
    expect(result.band).toBe("medium");
  });

  it("critical asset with HIGH confirmed vulns should be HIGH risk", () => {
    const result = computeHybridRisk(7, 8, ctx, 85);
    expect(result.impact).toBe(80);
    expect(result.band).toBe("high");
    expect(result.score).toBeGreaterThanOrEqual(70);
  });

  it("low asset with NO confirmed vulns should be LOW risk", () => {
    const result = computeHybridRisk(3, 3, ctx, 0);
    expect(result.impact).toBe(30);
    expect(result.band).toBe("low");
    expect(result.score).toBeLessThan(20);
  });

  it("low asset with HIGH confirmed vulns should be MEDIUM risk (not high)", () => {
    // Low importance caps the risk even with high vulns
    const result = computeHybridRisk(3, 3, ctx, 85);
    expect(result.impact).toBe(30);
    expect(result.band).toBe("medium");
    expect(result.score).toBeLessThan(70);
  });

  it("moderate asset with moderate confirmed vulns should be MEDIUM risk", () => {
    const result = computeHybridRisk(5, 5, ctx, 50);
    expect(result.band).toBe("medium");
  });
});

// ─── INITIAL PASS (PRE-ENRICHMENT) ───

describe("Initial Pass - Pre-Enrichment (LLM CVSS Placeholder)", () => {
  const ctx = { exposure: 0.6, recognizability: 0.5, confidence: 0.4 };

  it("initial pass uses LLM CVSS as placeholder (no confirmedVulnScore)", () => {
    const result = computeHybridRisk(7, 8, ctx);
    // Should produce a medium score as placeholder
    expect(result.band).toBe("medium");
    expect(result.score).toBeGreaterThan(30);
  });

  it("initial pass score is HIGHER than post-enrichment with zero confirmed vulns", () => {
    const initial = computeHybridRisk(7, 8, ctx);
    const postEnrichment = computeHybridRisk(7, 8, ctx, 0);
    expect(initial.score).toBeGreaterThan(postEnrichment.score);
  });

  it("initial pass score is overridden by post-enrichment recalculation", () => {
    // This is the key behavior: initial pass is just a placeholder
    const initial = computeHybridRisk(7, 8, ctx);
    const withConfirmed = computeHybridRisk(7, 8, ctx, 85);
    // With high confirmed vulns, post-enrichment should be higher than initial
    expect(withConfirmed.score).toBeGreaterThan(initial.score);
  });
});

// ─── CONFIDENCE DAMPENING ───

describe("Confirmed-Only - Confidence Dampening", () => {
  it("should not dampen at full confidence (1.0)", () => {
    const result = computeHybridRisk(7, 7, { exposure: 0.5, recognizability: 0.5, confidence: 1.0 }, 70);
    expect(result.likelihood).toBeGreaterThan(60);
  });

  it("should strongly dampen at low confidence (0.2)", () => {
    const highConf = computeHybridRisk(7, 7, { exposure: 0.5, recognizability: 0.5, confidence: 1.0 }, 70);
    const lowConf = computeHybridRisk(7, 7, { exposure: 0.5, recognizability: 0.5, confidence: 0.2 }, 70);
    expect(lowConf.score).toBeLessThan(highConf.score);
    expect(lowConf.likelihood).toBeLessThan(highConf.likelihood);
  });

  it("impact should NOT be affected by confidence (only likelihood is)", () => {
    const highConf = computeHybridRisk(7, 7, { exposure: 0.5, recognizability: 0.5, confidence: 1.0 }, 70);
    const lowConf = computeHybridRisk(7, 7, { exposure: 0.5, recognizability: 0.5, confidence: 0.2 }, 70);
    expect(highConf.impact).toBe(lowConf.impact);
  });
});

// ─── BAND THRESHOLDS ───

describe("Band Thresholds", () => {
  it("riskBand: >= 90 is critical", () => {
    expect(riskBand(90)).toBe("critical");
    expect(riskBand(89)).toBe("high");
  });

  it("riskBand: 70-89 is high", () => {
    expect(riskBand(70)).toBe("high");
    expect(riskBand(85)).toBe("high");
  });

  it("riskBand: 40-69 is medium", () => {
    expect(riskBand(40)).toBe("medium");
    expect(riskBand(69)).toBe("medium");
  });

  it("riskBand: < 40 is low", () => {
    expect(riskBand(39)).toBe("low");
    expect(riskBand(0)).toBe("low");
  });

  it("riskTier aligns with riskBand", () => {
    expect(riskTier(90)).toBe("tier0_critical");
    expect(riskTier(70)).toBe("tier1_high");
    expect(riskTier(40)).toBe("tier2_medium");
    expect(riskTier(39)).toBe("tier3_low");
  });
});

// ─── KEV BOOST CAPS ───

describe("KEV Boost Caps (Confirmed Version Only)", () => {
  it("per-asset KEV boost capped at 15 (individual match capped at 8)", () => {
    const matches = [{ severityBoost: 25 }, { severityBoost: 20 }, { severityBoost: 15 }];
    const assetBoost = Math.min(matches.reduce((s, m) => s + Math.min(m.severityBoost, 8), 0), 15);
    expect(assetBoost).toBe(15);
  });

  it("overall KEV boost capped at 20", () => {
    const matches = Array(10).fill({ severityBoost: 15 });
    const overallBoost = Math.min(
      matches.reduce((sum: number, m: any) => sum + Math.min(m.severityBoost, 8), 0),
      20
    );
    expect(overallBoost).toBe(20);
  });

  it("KEV boost should only apply to confirmed version matches (not probable)", () => {
    // Simulating the filter: only versionConfirmed matches get boost
    const kevMatches = [
      { versionConfirmed: true, severityBoost: 10 },
      { versionConfirmed: false, severityBoost: 15 }, // probable — should be excluded
      { versionConfirmed: true, severityBoost: 8 },
    ];
    const confirmedOnly = kevMatches.filter(m => m.versionConfirmed);
    const boost = Math.min(confirmedOnly.reduce((s, m) => s + Math.min(m.severityBoost, 8), 0), 15);
    expect(boost).toBeLessThanOrEqual(15);
    expect(confirmedOnly.length).toBe(2);
  });
});

// ─── SEPARATED SCORING ───

describe("Separated Scoring - Asset Criticality", () => {
  it("high-criticality asset (8.5) should be high band (not critical — threshold is 90)", () => {
    const crit = computeAssetCriticality(8.5);
    expect(crit.score).toBe(85);
    expect(crit.band).toBe("high");
  });

  it("very high criticality (9.5) should be critical", () => {
    const crit = computeAssetCriticality(9.5);
    expect(crit.score).toBe(95);
    expect(crit.band).toBe("critical");
  });

  it("low criticality with confirmed vulns: low criticality, high vuln risk", () => {
    const crit = computeAssetCriticality(2.5);
    const vuln = computeVulnRisk([
      { severity: 9, corroborationTier: "confirmed" },
      { severity: 7, corroborationTier: "confirmed" },
    ]);
    expect(crit.band).toBe("low");
    expect(vuln.score).toBeGreaterThanOrEqual(70);
  });

  it("medium criticality with only potential findings: zero vuln risk", () => {
    const crit = computeAssetCriticality(5.0);
    const vuln = computeVulnRisk([
      { severity: 8, corroborationTier: "potential" },
    ]);
    expect(crit.band).toBe("medium");
    expect(vuln.score).toBe(0);
    expect(vuln.band).toBe("low");
  });
});

describe("Separated Scoring - Vulnerability Risk", () => {
  it("probable findings contribute with reduced weight (0.6x)", () => {
    const confirmed = computeVulnRisk([{ severity: 6, corroborationTier: "confirmed" }]);
    const probable = computeVulnRisk([{ severity: 6, corroborationTier: "probable" }]);
    expect(probable.score).toBeLessThan(confirmed.score);
  });

  it("single confirmed critical finding = critical vuln risk", () => {
    const result = computeVulnRisk([{ severity: 10, corroborationTier: "confirmed" }]);
    expect(result.score).toBe(100);
    expect(result.band).toBe("critical");
  });

  it("no actionable findings = score 0, band low", () => {
    const result = computeVulnRisk([{ severity: 10, corroborationTier: "potential" }]);
    expect(result.score).toBe(0);
    expect(result.band).toBe("low");
  });
});

// ─── CORROBORATION TIERS ───

describe("Corroboration Tiers - Severity Caps", () => {
  it("confirmed: no cap", () => {
    const severity = 9, tier = "confirmed";
    const capped = tier === "probable" ? Math.min(severity, 6) : tier === "potential" ? Math.min(severity, 4) : severity;
    expect(capped).toBe(9);
  });

  it("probable: capped at 6", () => {
    const severity = 9, tier = "probable";
    const capped = tier === "probable" ? Math.min(severity, 6) : tier === "potential" ? Math.min(severity, 4) : severity;
    expect(capped).toBe(6);
  });

  it("potential: capped at 4", () => {
    const severity = 8, tier = "potential";
    const capped = tier === "probable" ? Math.min(severity, 6) : tier === "potential" ? Math.min(severity, 4) : severity;
    expect(capped).toBe(4);
  });
});

// ─── FALSE POSITIVE PREVENTION ───

describe("False Positive Prevention", () => {
  it("default/missing data should never produce high or critical", () => {
    const carver = normalizeCarver({});
    const shock = normalizeShock({});
    const mi = computeMissionImpact(carver, shock);
    const hybrid = computeHybridRisk(3, mi, { exposure: 0.3, recognizability: 0.3, confidence: 0.2 }, 0);
    expect(hybrid.band).not.toBe("critical");
    expect(hybrid.band).not.toBe("high");
    expect(hybrid.band).toBe("low");
  });

  it("high CARVER scores with zero confirmed vulns should be LOW (not medium/high)", () => {
    const carver = normalizeCarver({ criticality: 9, accessibility: 8, vulnerability: 8, effect: 9, recuperability: 7, recognizability: 8 });
    const shock = normalizeShock({ scope: 8, handling: 7, operationalImpact: 9, cascadingEffects: 8, knowledge: 7 });
    const mi = computeMissionImpact(carver, shock);
    const hybrid = computeHybridRisk(7, mi, { exposure: 0.7, recognizability: 0.7, confidence: 0.75 }, 0);
    expect(hybrid.impact).toBeGreaterThan(70); // High impact (CARVER says important)
    expect(hybrid.likelihood).toBeLessThan(15); // Low likelihood (no confirmed vulns)
    expect(hybrid.band).toBe("low"); // Low risk overall
  });

  it("moderate LLM scores with low confidence and no confirmed vulns should be low", () => {
    const carver = normalizeCarver({ criticality: 6, accessibility: 5, vulnerability: 5 });
    const shock = normalizeShock({ operationalImpact: 5, scope: 4 });
    const mi = computeMissionImpact(carver, shock);
    const hybrid = computeHybridRisk(5, mi, { exposure: 0.5, recognizability: 0.4, confidence: 0.3 }, 0);
    expect(hybrid.band).toBe("low");
  });

  it("only confirmed vulns on critical assets should reach critical risk", () => {
    const carver = normalizeCarver({ criticality: 10, accessibility: 9, recuperability: 9, vulnerability: 10, effect: 9, recognizability: 9 });
    const shock = normalizeShock({ scope: 9, handling: 9, operationalImpact: 10, cascadingEffects: 9, knowledge: 9 });
    const mi = computeMissionImpact(carver, shock);
    // With max confirmed vulns AND max impact
    const hybrid = computeHybridRisk(10, mi, { exposure: 1.0, recognizability: 1.0, confidence: 1.0 }, 100);
    expect(hybrid.band).toBe("critical");
    expect(hybrid.score).toBeGreaterThanOrEqual(90);
  });
});

// ─── RECALIBRATION SCENARIOS ───

describe("Recalibration Scenarios - Confirmed vs Unconfirmed", () => {
  it("typical LLM inflation (7/7 scores) with zero confirmed vulns = LOW", () => {
    const carver = normalizeCarver({ criticality: 7, accessibility: 7, vulnerability: 7, effect: 7, recuperability: 6, recognizability: 6 });
    const shock = normalizeShock({ scope: 7, handling: 6, operationalImpact: 7, cascadingEffects: 7, knowledge: 6 });
    const mi = computeMissionImpact(carver, shock);
    const hybrid = computeHybridRisk(7, mi, { exposure: 0.7, recognizability: 0.7, confidence: 0.75 }, 0);
    expect(hybrid.band).toBe("low");
    expect(hybrid.score).toBeLessThan(40);
  });

  it("typical LLM inflation with moderate confirmed vulns = MEDIUM", () => {
    const carver = normalizeCarver({ criticality: 7, accessibility: 7, vulnerability: 7, effect: 7, recuperability: 6, recognizability: 6 });
    const shock = normalizeShock({ scope: 7, handling: 6, operationalImpact: 7, cascadingEffects: 7, knowledge: 6 });
    const mi = computeMissionImpact(carver, shock);
    const hybrid = computeHybridRisk(7, mi, { exposure: 0.7, recognizability: 0.7, confidence: 0.75 }, 50);
    expect(hybrid.band).toBe("medium");
  });

  it("typical LLM inflation with high confirmed vulns = HIGH", () => {
    const carver = normalizeCarver({ criticality: 7, accessibility: 7, vulnerability: 7, effect: 7, recuperability: 6, recognizability: 6 });
    const shock = normalizeShock({ scope: 7, handling: 6, operationalImpact: 7, cascadingEffects: 7, knowledge: 6 });
    const mi = computeMissionImpact(carver, shock);
    const hybrid = computeHybridRisk(7, mi, { exposure: 0.7, recognizability: 0.7, confidence: 0.75 }, 85);
    expect(hybrid.band).toBe("high");
  });
});

// ─── F5 BIG-IP FALSE POSITIVE FIX ───

import { extractTechnologiesFromHeaders } from "./lib/dns-banner-verify";

describe("F5 BIG-IP Detection - False Positive Fix", () => {
  it("should NOT detect F5 from generic headers containing 'f5' substring", () => {
    const headers: Record<string, string> = {
      "server": "nginx/1.21.0",
      "x-request-id": "abc123f5def456",
    };
    const techs = extractTechnologiesFromHeaders(headers);
    expect(techs.find(t => t.name === "F5 BIG-IP")).toBeUndefined();
  });

  it("should detect F5 from BIG-IP in server header", () => {
    const headers: Record<string, string> = { "server": "BIG-IP" };
    const techs = extractTechnologiesFromHeaders(headers);
    expect(techs.find(t => t.name === "F5 BIG-IP")).toBeDefined();
  });

  it("should detect F5 from BIGipServer cookie", () => {
    const headers: Record<string, string> = {
      "server": "nginx",
      "set-cookie": "BIGipServerpool_web=123456.789.0000; path=/",
    };
    const techs = extractTechnologiesFromHeaders(headers);
    expect(techs.find(t => t.name === "F5 BIG-IP")).toBeDefined();
  });
});
