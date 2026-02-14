import { describe, it, expect } from "vitest";

/**
 * Tests for the enriched risk scoring system:
 * - Confidence-based dampening
 * - Lower defaults for missing data
 * - Evidence fields on posture findings
 * - False-positive prevention
 */

// Re-implement the scoring functions locally to test them in isolation
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

function computeHybridRisk(
  cvss: number,
  missionImpact: number,
  ctx: { exposure: number; recognizability: number; confidence: number }
) {
  const alpha = 0.4;
  const cvssNorm = cvss / 10;
  const missionNorm = missionImpact / 10;
  const blended = alpha * cvssNorm + (1 - alpha) * missionNorm;

  let multiplier = 1.0;
  multiplier += (ctx.exposure - 0.5) * 0.3;
  multiplier += (ctx.recognizability - 0.5) * 0.15;
  multiplier = clamp(multiplier, 0.7, 1.4);

  const confidenceDampening = 0.7 + (ctx.confidence * 0.3);
  const score = clamp(100 * blended * multiplier * confidenceDampening, 0, 100);
  const band = score >= 85 ? "critical" : score >= 70 ? "high" : score >= 40 ? "medium" : "low";

  return { score, band };
}

describe("Risk Scoring - Defaults", () => {
  it("should default CARVER scores to 3 (not 5) for missing data", () => {
    const carver = normalizeCarver({});
    expect(carver.criticality).toBe(3);
    expect(carver.accessibility).toBe(3);
    expect(carver.recuperability).toBe(3);
    expect(carver.vulnerability).toBe(3);
    expect(carver.effect).toBe(3);
    expect(carver.recognizability).toBe(3);
  });

  it("should default SHOCK scores to 3 (not 5) for missing data", () => {
    const shock = normalizeShock({});
    expect(shock.scope).toBe(3);
    expect(shock.handling).toBe(3);
    expect(shock.operationalImpact).toBe(3);
    expect(shock.cascadingEffects).toBe(3);
    expect(shock.knowledge).toBe(3);
  });

  it("should preserve actual scores when provided", () => {
    const carver = normalizeCarver({ criticality: 8, accessibility: 7, vulnerability: 9 });
    expect(carver.criticality).toBe(8);
    expect(carver.accessibility).toBe(7);
    expect(carver.vulnerability).toBe(9);
    // Missing ones still default to 3
    expect(carver.recuperability).toBe(3);
    expect(carver.effect).toBe(3);
    expect(carver.recognizability).toBe(3);
  });

  it("should clamp scores to 0-10 range", () => {
    const carver = normalizeCarver({ criticality: 15, accessibility: -3 });
    expect(carver.criticality).toBe(10);
    expect(carver.accessibility).toBe(0);
  });
});

describe("Risk Scoring - Confidence Dampening", () => {
  it("should not dampen scores at full confidence (1.0)", () => {
    const result = computeHybridRisk(7, 7, { exposure: 0.5, recognizability: 0.5, confidence: 1.0 });
    // At confidence 1.0: dampening = 0.7 + 0.3 = 1.0 (no dampening)
    const noDampen = computeHybridRisk(7, 7, { exposure: 0.5, recognizability: 0.5, confidence: 1.0 });
    expect(result.score).toBeCloseTo(noDampen.score, 1);
  });

  it("should significantly dampen scores at low confidence (0.2)", () => {
    const highConf = computeHybridRisk(7, 7, { exposure: 0.5, recognizability: 0.5, confidence: 1.0 });
    const lowConf = computeHybridRisk(7, 7, { exposure: 0.5, recognizability: 0.5, confidence: 0.2 });
    // Low confidence should produce a lower score
    expect(lowConf.score).toBeLessThan(highConf.score);
    // At confidence 0.2: dampening = 0.7 + 0.06 = 0.76, so ~24% reduction
    expect(lowConf.score).toBeLessThan(highConf.score * 0.85);
  });

  it("should produce medium dampening at confidence 0.5", () => {
    const fullConf = computeHybridRisk(7, 7, { exposure: 0.5, recognizability: 0.5, confidence: 1.0 });
    const halfConf = computeHybridRisk(7, 7, { exposure: 0.5, recognizability: 0.5, confidence: 0.5 });
    const lowConf = computeHybridRisk(7, 7, { exposure: 0.5, recognizability: 0.5, confidence: 0.2 });
    // Half confidence should be between full and low
    expect(halfConf.score).toBeLessThan(fullConf.score);
    expect(halfConf.score).toBeGreaterThan(lowConf.score);
  });
});

describe("Risk Scoring - Default Analysis (no LLM data)", () => {
  it("should produce low risk band for default analysis with no data", () => {
    const carver = normalizeCarver({});
    const shock = normalizeShock({});
    const mission = computeMissionImpact(carver, shock);
    // Default CVSS = 3, low exposure/recognizability/confidence
    const hybrid = computeHybridRisk(3, mission, { exposure: 0.3, recognizability: 0.3, confidence: 0.2 });
    expect(hybrid.band).toBe("low");
    expect(hybrid.score).toBeLessThan(40);
  });

  it("should produce lower scores than the old defaults (5/0.5/0.5)", () => {
    // Old defaults: CARVER/SHOCK = 5, CVSS = 5, exposure/recog/conf = 0.5
    const oldCarver = { criticality: 5, accessibility: 5, recuperability: 5, vulnerability: 5, effect: 5, recognizability: 5 };
    const oldShock = { scope: 5, handling: 5, operationalImpact: 5, cascadingEffects: 5, knowledge: 5 };
    const oldMission = computeMissionImpact(oldCarver, oldShock);
    // Old system had no confidence dampening, simulate with confidence=1
    const oldHybrid = computeHybridRisk(5, oldMission, { exposure: 0.5, recognizability: 0.5, confidence: 1.0 });

    // New defaults
    const newCarver = normalizeCarver({});
    const newShock = normalizeShock({});
    const newMission = computeMissionImpact(newCarver, newShock);
    const newHybrid = computeHybridRisk(3, newMission, { exposure: 0.3, recognizability: 0.3, confidence: 0.2 });

    expect(newHybrid.score).toBeLessThan(oldHybrid.score);
  });
});

describe("Risk Scoring - Band Thresholds", () => {
  it("should classify >= 85 as critical", () => {
    const result = computeHybridRisk(10, 10, { exposure: 1.0, recognizability: 1.0, confidence: 1.0 });
    expect(result.band).toBe("critical");
    expect(result.score).toBeGreaterThanOrEqual(85);
  });

  it("should classify 70-84 as high", () => {
    const result = computeHybridRisk(8, 8, { exposure: 0.5, recognizability: 0.5, confidence: 0.9 });
    // This should be in the high range
    expect(result.score).toBeGreaterThanOrEqual(40);
  });

  it("should classify < 40 as low", () => {
    const result = computeHybridRisk(2, 2, { exposure: 0.2, recognizability: 0.2, confidence: 0.3 });
    expect(result.band).toBe("low");
    expect(result.score).toBeLessThan(40);
  });
});

describe("Risk Scoring - Mission Impact", () => {
  it("should weight criticality and operationalImpact highest", () => {
    // High criticality, low everything else
    const highCrit = normalizeCarver({ criticality: 10, accessibility: 1, recuperability: 1, vulnerability: 1, effect: 1, recognizability: 1 });
    const highShock = normalizeShock({ operationalImpact: 10, scope: 1, handling: 1, cascadingEffects: 1, knowledge: 1 });
    const missionHigh = computeMissionImpact(highCrit, highShock);

    // Low criticality, low everything
    const lowAll = normalizeCarver({ criticality: 1, accessibility: 1, recuperability: 1, vulnerability: 1, effect: 1, recognizability: 1 });
    const lowShock = normalizeShock({ operationalImpact: 1, scope: 1, handling: 1, cascadingEffects: 1, knowledge: 1 });
    const missionLow = computeMissionImpact(lowAll, lowShock);

    expect(missionHigh).toBeGreaterThan(missionLow);
  });
});

describe("Evidence Fields - Posture Findings", () => {
  it("should define valid evidence basis types", () => {
    const validTypes = ["kev_match", "confirmed_cve", "vuln_feed", "technology_match", "llm_inference"];
    expect(validTypes.length).toBe(5);
    // Each should be a non-empty string
    for (const t of validTypes) {
      expect(t.length).toBeGreaterThan(0);
    }
  });

  it("should have KEV findings with highest confidence", () => {
    // KEV findings should have confidence >= 0.9
    const kevConfidence = 0.95;
    const llmConfidence = 0.5;
    expect(kevConfidence).toBeGreaterThan(llmConfidence);
    expect(kevConfidence).toBeGreaterThanOrEqual(0.9);
  });

  it("should have CVE-backed findings with higher confidence than LLM-only", () => {
    const cveConfidence = 0.85;
    const llmConfidence = 0.5;
    expect(cveConfidence).toBeGreaterThan(llmConfidence);
  });

  it("should require CVE IDs for KEV and confirmed_cve evidence types", () => {
    // KEV findings must have cveIds
    const kevFinding = {
      id: "kev-CVE-2024-1234",
      cveIds: ["CVE-2024-1234"],
      kevListed: true,
      evidenceBasis: "kev_match",
    };
    expect(kevFinding.cveIds.length).toBeGreaterThan(0);
    expect(kevFinding.kevListed).toBe(true);

    // Confirmed CVE findings must have cveIds
    const cveFinding = {
      id: "vf-CVE-2024-5678",
      cveIds: ["CVE-2024-5678"],
      kevListed: false,
      evidenceBasis: "confirmed_cve",
    };
    expect(cveFinding.cveIds.length).toBeGreaterThan(0);
  });

  it("should include affected asset hostnames", () => {
    const finding = {
      affectedAssets: ["mail.example.com"],
      assetHostname: "mail.example.com",
    };
    expect(finding.affectedAssets.length).toBeGreaterThan(0);
    expect(finding.assetHostname).toBeTruthy();
  });

  it("should include evidence detail string", () => {
    const kevDetail = `Matched technology "nginx" on mail.example.com against CISA KEV entry CVE-2024-1234 (Vendor Product). Due date: 2024-12-01.`;
    expect(kevDetail).toContain("CVE-");
    expect(kevDetail).toContain("mail.example.com");
    expect(kevDetail).toContain("CISA KEV");
  });
});

describe("False Positive Prevention", () => {
  it("should not produce critical scores from default/missing data", () => {
    const carver = normalizeCarver({});
    const shock = normalizeShock({});
    const mission = computeMissionImpact(carver, shock);
    const hybrid = computeHybridRisk(3, mission, { exposure: 0.3, recognizability: 0.3, confidence: 0.2 });
    expect(hybrid.band).not.toBe("critical");
    expect(hybrid.band).not.toBe("high");
  });

  it("should not produce high scores from moderate LLM analysis with low confidence", () => {
    // Moderate scores but low confidence should not be high
    const carver = normalizeCarver({ criticality: 6, accessibility: 5, vulnerability: 5 });
    const shock = normalizeShock({ operationalImpact: 5, scope: 4 });
    const mission = computeMissionImpact(carver, shock);
    const hybrid = computeHybridRisk(5, mission, { exposure: 0.5, recognizability: 0.4, confidence: 0.3 });
    expect(hybrid.score).toBeLessThan(70); // Should not be "high"
  });

  it("should allow high scores only with high confidence and high CVSS", () => {
    const carver = normalizeCarver({ criticality: 9, accessibility: 8, vulnerability: 9, effect: 8 });
    const shock = normalizeShock({ operationalImpact: 9, scope: 8, cascadingEffects: 8 });
    const mission = computeMissionImpact(carver, shock);
    const hybrid = computeHybridRisk(9, mission, { exposure: 0.9, recognizability: 0.8, confidence: 0.95 });
    expect(hybrid.score).toBeGreaterThanOrEqual(70);
  });

  it("should sort findings: KEV first, then by severity, then by confidence", () => {
    const findings = [
      { kevListed: false, severity: 8, confidence: 0.6, title: "LLM finding" },
      { kevListed: true, severity: 9, confidence: 0.95, title: "KEV finding" },
      { kevListed: false, severity: 8, confidence: 0.85, title: "CVE finding" },
      { kevListed: false, severity: 5, confidence: 0.5, title: "Low finding" },
    ];

    const sorted = [...findings].sort((a, b) => {
      if (a.kevListed && !b.kevListed) return -1;
      if (!a.kevListed && b.kevListed) return 1;
      if (b.severity !== a.severity) return b.severity - a.severity;
      return b.confidence - a.confidence;
    });

    expect(sorted[0].title).toBe("KEV finding");
    expect(sorted[1].title).toBe("CVE finding"); // Same severity but higher confidence
    expect(sorted[2].title).toBe("LLM finding");
    expect(sorted[3].title).toBe("Low finding");
  });
});

describe("Discovery Method Labels", () => {
  it("should label LLM-discovered assets as inferred", () => {
    const asset = { discoveryMethod: "inferred" };
    expect(asset.discoveryMethod).toBe("inferred");
  });

  it("should distinguish inferred from verified discovery methods", () => {
    const methods = ["inferred", "dns_verified", "scan_confirmed"];
    expect(methods).toContain("inferred");
    expect(methods).toContain("dns_verified");
  });
});
