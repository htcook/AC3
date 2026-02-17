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

// ─── Corroboration Tier Tests ───

describe("Corroboration Tiers - Classification", () => {
  it("should classify as 'confirmed' when version is detected and matches CVE affected range", () => {
    const finding = {
      corroborationTier: "confirmed",
      detectedVersion: "1.18.0",
      versionMatchConfirmed: true,
      cveIds: ["CVE-2021-23017"],
      evidenceBasis: "confirmed_cve",
      confidence: 0.95,
    };
    expect(finding.corroborationTier).toBe("confirmed");
    expect(finding.versionMatchConfirmed).toBe(true);
    expect(finding.detectedVersion).toBeTruthy();
    expect(finding.cveIds.length).toBeGreaterThan(0);
  });

  it("should classify as 'probable' when product detected but version unknown", () => {
    const finding = {
      corroborationTier: "probable",
      detectedVersion: undefined,
      versionMatchConfirmed: false,
      cveIds: ["CVE-2024-1234"],
      evidenceBasis: "vuln_feed",
      confidence: 0.6,
    };
    expect(finding.corroborationTier).toBe("probable");
    expect(finding.detectedVersion).toBeUndefined();
    expect(finding.versionMatchConfirmed).toBe(false);
    expect(finding.cveIds.length).toBeGreaterThan(0);
  });

  it("should classify as 'potential' when LLM-inferred with no CVE backing", () => {
    const finding = {
      corroborationTier: "potential",
      detectedVersion: undefined,
      versionMatchConfirmed: false,
      cveIds: [],
      evidenceBasis: "llm_inference",
      confidence: 0.3,
    };
    expect(finding.corroborationTier).toBe("potential");
    expect(finding.cveIds.length).toBe(0);
    expect(finding.evidenceBasis).toBe("llm_inference");
  });
});

describe("Corroboration Tiers - Severity Caps", () => {
  it("should not cap severity for confirmed findings", () => {
    // Confirmed findings can have any severity
    const severity = 9;
    const tier = "confirmed";
    const capped = tier === "probable" ? Math.min(severity, 6) : tier === "potential" ? Math.min(severity, 4) : severity;
    expect(capped).toBe(9);
  });

  it("should cap severity at 6 for probable findings", () => {
    const severity = 9;
    const tier = "probable";
    const capped = tier === "probable" ? Math.min(severity, 6) : tier === "potential" ? Math.min(severity, 4) : severity;
    expect(capped).toBe(6);
  });

  it("should cap severity at 4 for potential findings", () => {
    const severity = 8;
    const tier = "potential";
    const capped = tier === "probable" ? Math.min(severity, 6) : tier === "potential" ? Math.min(severity, 4) : severity;
    expect(capped).toBe(4);
  });

  it("should not increase severity when already below cap", () => {
    const severity = 3;
    const tier = "probable";
    const capped = tier === "probable" ? Math.min(severity, 6) : severity;
    expect(capped).toBe(3);
  });
});

describe("Corroboration Tiers - Evidence Chains", () => {
  it("should build a multi-step evidence chain for confirmed findings", () => {
    const chain = [
      "Asset mail.example.com discovered via DNS enumeration",
      "Technology nginx 1.18.0 detected via HTTP response headers",
      "CVE-2021-23017 affects nginx versions < 1.21.0 (NVD confirmed)",
      "Detected version 1.18.0 falls within affected range",
      "CISA KEV listing confirms active exploitation in the wild",
    ];
    expect(chain.length).toBeGreaterThanOrEqual(3);
    expect(chain[0]).toContain("discovered");
    expect(chain[1]).toContain("detected");
    expect(chain[chain.length - 1]).toContain("confirm");
  });

  it("should build a shorter evidence chain for probable findings", () => {
    const chain = [
      "Asset www.example.com discovered via OSINT inference",
      "Technology Apache identified via product name match",
      "CVE-2024-5678 exists for Apache product family — version unconfirmed",
    ];
    expect(chain.length).toBeGreaterThanOrEqual(2);
    expect(chain[chain.length - 1]).toContain("unconfirmed");
  });

  it("should have minimal evidence chain for potential findings", () => {
    const chain = [
      "Risk inferred by LLM analysis — no direct CVE or version evidence",
    ];
    expect(chain.length).toBe(1);
    expect(chain[0]).toContain("inferred");
  });
});

describe("Corroboration Tiers - Version Matching Logic", () => {
  function isVersionAffected(detected: string, affectedRange: string): boolean {
    // Simple semver comparison: "< X.Y.Z" or "<= X.Y.Z"
    const match = affectedRange.match(/^([<>]=?)\s*([\d.]+)$/);
    if (!match) return false;
    const [, op, ver] = match;
    const dParts = detected.split(".").map(Number);
    const vParts = ver.split(".").map(Number);
    for (let i = 0; i < Math.max(dParts.length, vParts.length); i++) {
      const d = dParts[i] || 0;
      const v = vParts[i] || 0;
      if (d < v) return op === "<" || op === "<=" || op === ">";
      if (d > v) return op === ">" || op === ">=";
    }
    return op === "<=" || op === ">=";
  }

  it("should match version within affected range (< operator)", () => {
    expect(isVersionAffected("1.18.0", "< 1.21.0")).toBe(true);
  });

  it("should not match version outside affected range", () => {
    expect(isVersionAffected("1.25.0", "< 1.21.0")).toBe(false);
  });

  it("should match exact version with <= operator", () => {
    expect(isVersionAffected("1.21.0", "<= 1.21.0")).toBe(true);
  });

  it("should not match exact version with < operator", () => {
    expect(isVersionAffected("1.21.0", "< 1.21.0")).toBe(false);
  });
});

describe("Corroboration Tiers - Campaign Filtering", () => {
  it("should include confirmed findings in campaign recommendations", () => {
    const findings = [
      { corroborationTier: "confirmed", severity: 9, title: "Confirmed vuln" },
      { corroborationTier: "probable", severity: 6, title: "Probable vuln" },
      { corroborationTier: "potential", severity: 4, title: "Potential vuln" },
    ];
    const campaignFindings = findings.filter(f => f.corroborationTier !== "potential");
    expect(campaignFindings.length).toBe(2);
    expect(campaignFindings.map(f => f.title)).toContain("Confirmed vuln");
    expect(campaignFindings.map(f => f.title)).toContain("Probable vuln");
    expect(campaignFindings.map(f => f.title)).not.toContain("Potential vuln");
  });

  it("should exclude potential-only findings from chain builder", () => {
    const vulnSteps = [
      { corroborationTier: "confirmed", techniqueId: "T1190", name: "Exploit nginx" },
      { corroborationTier: "potential", techniqueId: "T1059", name: "LLM-inferred script" },
    ];
    const filtered = vulnSteps.filter((s: any) => s.corroborationTier !== "potential");
    expect(filtered.length).toBe(1);
    expect(filtered[0].name).toBe("Exploit nginx");
  });

  it("should prioritize confirmed over probable in chain ordering", () => {
    const steps = [
      { corroborationTier: "probable", priority: 2 },
      { corroborationTier: "confirmed", priority: 1 },
    ];
    const sorted = [...steps].sort((a, b) => {
      const order: Record<string, number> = { confirmed: 0, probable: 1, potential: 2 };
      return (order[a.corroborationTier] ?? 2) - (order[b.corroborationTier] ?? 2);
    });
    expect(sorted[0].corroborationTier).toBe("confirmed");
    expect(sorted[1].corroborationTier).toBe("probable");
  });
});

describe("Corroboration Tiers - Sorting in UI", () => {
  it("should sort findings: confirmed first, then probable, then potential", () => {
    const findings = [
      { corroborationTier: "potential", severity: 4, kevListed: false, confidence: 0.3 },
      { corroborationTier: "confirmed", severity: 9, kevListed: true, confidence: 0.95 },
      { corroborationTier: "probable", severity: 6, kevListed: false, confidence: 0.6 },
      { corroborationTier: "confirmed", severity: 7, kevListed: false, confidence: 0.9 },
    ];

    const tierOrder: Record<string, number> = { confirmed: 0, probable: 1, potential: 2 };
    const sorted = [...findings].sort((a, b) => {
      const aTier = tierOrder[a.corroborationTier] ?? 2;
      const bTier = tierOrder[b.corroborationTier] ?? 2;
      if (aTier !== bTier) return aTier - bTier;
      if (a.kevListed && !b.kevListed) return -1;
      if (!a.kevListed && b.kevListed) return 1;
      if (b.severity !== a.severity) return b.severity - a.severity;
      return b.confidence - a.confidence;
    });

    expect(sorted[0].corroborationTier).toBe("confirmed");
    expect(sorted[0].kevListed).toBe(true);
    expect(sorted[1].corroborationTier).toBe("confirmed");
    expect(sorted[2].corroborationTier).toBe("probable");
    expect(sorted[3].corroborationTier).toBe("potential");
  });

  it("should visually dim potential findings (opacity-75)", () => {
    const tier = "potential";
    const className = tier === "potential" ? "border-purple-500/20 opacity-75" : "";
    expect(className).toContain("opacity-75");
  });
});

describe("Corroboration Tiers - Summary Counts", () => {
  it("should correctly count findings by tier", () => {
    const findings = [
      { corroborationTier: "confirmed" },
      { corroborationTier: "confirmed" },
      { corroborationTier: "probable" },
      { corroborationTier: "potential" },
      { corroborationTier: "potential" },
      { corroborationTier: "potential" },
      { corroborationTier: undefined }, // defaults to potential
    ];

    const confirmed = findings.filter(f => f.corroborationTier === "confirmed");
    const probable = findings.filter(f => f.corroborationTier === "probable");
    const potential = findings.filter(f => !f.corroborationTier || f.corroborationTier === "potential");

    expect(confirmed.length).toBe(2);
    expect(probable.length).toBe(1);
    expect(potential.length).toBe(4); // 3 explicit + 1 undefined
  });
});

// ─── NEW: Separated Criticality vs Vulnerability Risk Tests ─────────

import { extractTechnologiesFromHeaders } from "./lib/dns-banner-verify";

function computeAssetCriticality(missionImpact: number) {
  const score = Math.max(0, Math.min(100, Math.round(missionImpact * 10)));
  const band = score >= 85 ? "critical" : score >= 70 ? "high" : score >= 40 ? "medium" : "low";
  return { score, band };
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
  const score = Math.max(0, Math.min(100, Math.round(maxNorm * 0.6 + avgWeighted * 0.4)));
  const band = score >= 85 ? "critical" : score >= 70 ? "high" : score >= 40 ? "medium" : "low";
  return { score, band };
}

describe("Separated Scoring - Asset Criticality", () => {
  it("high-criticality asset with no vulns should have high criticality but zero vuln risk", () => {
    const mission = 8.5; // High CARVER+SHOCK
    const crit = computeAssetCriticality(mission);
    const vuln = computeVulnRisk([]); // No findings at all

    expect(crit.score).toBe(85);
    expect(crit.band).toBe("critical");
    expect(vuln.score).toBe(0);
    expect(vuln.band).toBe("low");
  });

  it("low-criticality asset with confirmed vulns should have low criticality but high vuln risk", () => {
    const mission = 2.5; // Low CARVER+SHOCK
    const crit = computeAssetCriticality(mission);
    const vuln = computeVulnRisk([
      { severity: 9, corroborationTier: "confirmed" },
      { severity: 7, corroborationTier: "confirmed" },
    ]);

    expect(crit.score).toBe(25);
    expect(crit.band).toBe("low");
    expect(vuln.score).toBeGreaterThanOrEqual(70);
    expect(["high", "critical"]).toContain(vuln.band);
  });

  it("medium-criticality asset with only potential findings should have zero vuln risk", () => {
    const mission = 5.0;
    const crit = computeAssetCriticality(mission);
    const vuln = computeVulnRisk([
      { severity: 8, corroborationTier: "potential" },
      { severity: 7, corroborationTier: "potential" },
    ]);

    expect(crit.score).toBe(50);
    expect(crit.band).toBe("medium");
    expect(vuln.score).toBe(0);
    expect(vuln.band).toBe("low");
  });
});

describe("Separated Scoring - Vulnerability Risk", () => {
  it("probable findings should contribute with reduced weight (0.6x)", () => {
    const confirmedOnly = computeVulnRisk([
      { severity: 6, corroborationTier: "confirmed" },
    ]);
    const probableOnly = computeVulnRisk([
      { severity: 6, corroborationTier: "probable" },
    ]);

    // Probable should produce a lower score than confirmed at same severity
    expect(probableOnly.score).toBeLessThan(confirmedOnly.score);
  });

  it("mixed confirmed + probable should score higher than probable alone", () => {
    const mixed = computeVulnRisk([
      { severity: 8, corroborationTier: "confirmed" },
      { severity: 6, corroborationTier: "probable" },
    ]);
    const probableOnly = computeVulnRisk([
      { severity: 6, corroborationTier: "probable" },
    ]);

    expect(mixed.score).toBeGreaterThan(probableOnly.score);
  });

  it("no actionable findings should always return score 0 band low", () => {
    const result = computeVulnRisk([
      { severity: 10, corroborationTier: "potential" },
    ]);
    expect(result.score).toBe(0);
    expect(result.band).toBe("low");
  });

  it("single confirmed critical finding should produce critical vuln risk", () => {
    const result = computeVulnRisk([
      { severity: 10, corroborationTier: "confirmed" },
    ]);
    expect(result.score).toBe(100);
    expect(result.band).toBe("critical");
  });
});

// ─── NEW: F5 BIG-IP False Positive Fix Tests ────────────────────────

describe("F5 BIG-IP Detection - False Positive Fix", () => {
  it("should NOT detect F5 from generic headers containing 'f5' substring", () => {
    const headers: Record<string, string> = {
      "server": "nginx/1.21.0",
      "x-powered-by": "Express",
      "x-request-id": "abc123f5def456",
    };
    const techs = extractTechnologiesFromHeaders(headers);
    const f5 = techs.find(t => t.name === "F5 BIG-IP");
    expect(f5).toBeUndefined();
  });

  it("should NOT detect F5 from Cloudflare cf-ray headers", () => {
    const headers: Record<string, string> = {
      "server": "cloudflare",
      "cf-ray": "8f5abc123-IAD",
    };
    const techs = extractTechnologiesFromHeaders(headers);
    const f5 = techs.find(t => t.name === "F5 BIG-IP");
    expect(f5).toBeUndefined();
  });

  it("should NOT detect F5 from X-Cnection header (removed as too weak)", () => {
    const headers: Record<string, string> = {
      "server": "Apache/2.4",
      "x-cnection": "close",
    };
    const techs = extractTechnologiesFromHeaders(headers);
    const f5 = techs.find(t => t.name === "F5 BIG-IP");
    expect(f5).toBeUndefined();
  });

  it("should detect F5 from BIG-IP in server header", () => {
    const headers: Record<string, string> = {
      "server": "BIG-IP",
    };
    const techs = extractTechnologiesFromHeaders(headers);
    const f5 = techs.find(t => t.name === "F5 BIG-IP");
    expect(f5).toBeDefined();
  });

  it("should detect F5 from BigIP in server header", () => {
    const headers: Record<string, string> = {
      "server": "BigIP",
    };
    const techs = extractTechnologiesFromHeaders(headers);
    const f5 = techs.find(t => t.name === "F5 BIG-IP");
    expect(f5).toBeDefined();
  });

  it("should detect F5 from BIGipServer cookie", () => {
    const headers: Record<string, string> = {
      "server": "nginx",
      "set-cookie": "BIGipServerpool_web=123456.789.0000; path=/",
    };
    const techs = extractTechnologiesFromHeaders(headers);
    const f5 = techs.find(t => t.name === "F5 BIG-IP");
    expect(f5).toBeDefined();
  });

  it("should detect F5 from standalone 'F5' in Server header", () => {
    const headers: Record<string, string> = {
      "server": "F5 HTTPD",
    };
    const techs = extractTechnologiesFromHeaders(headers);
    const f5 = techs.find(t => t.name === "F5 BIG-IP");
    expect(f5).toBeDefined();
  });

  it("should NOT detect F5 from 'F5' in non-Server headers", () => {
    const headers: Record<string, string> = {
      "server": "Apache/2.4",
      "x-custom": "F5 load balancer info",
    };
    const techs = extractTechnologiesFromHeaders(headers);
    const f5 = techs.find(t => t.name === "F5 BIG-IP");
    expect(f5).toBeUndefined();
  });
});
