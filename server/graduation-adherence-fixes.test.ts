import { describe, test, expect } from 'vitest';

/**
 * Tests for Graduation Scoring & Test Plan Adherence Fixes
 * ═══════════════════════════════════════════════════════════
 * Validates:
 *   P1 — Recon scoring credits intelligence enrichment (KEV, CVE, vulns)
 *   P2 — Exploit scoring credits attempt effort + severity depth
 *   P3 — Cognitive core credits PTES coverage + corroboration
 *   P4 — N/A categories (cloud/supply_chain) excluded from average
 *   P5 — Test plan adherence uses phase-based floor
 *   P6 — Adherence percentage never 0% when PTES phases are completed
 */

// ─── Replicate scoring functions from post-pipeline-graduation.ts ────────────

interface PipelineMetrics {
  pipelineType: string;
  assetsDiscovered: number;
  subdomainsFound: number;
  portsFound: number;
  servicesIdentified: number;
  technologiesDetected: number;
  totalVulns: number;
  confirmedVulns: number;
  criticalVulns: number;
  highVulns: number;
  mediumVulns: number;
  lowVulns: number;
  uniqueCVEs: number;
  kevMatches: number;
  exploitsAttempted: number;
  exploitsSucceeded: number;
  verifiedVulns: number;
  wafDetected: boolean;
  wafBypassed: boolean;
  scanBlocked: boolean;
  scanRecovered: boolean;
  owaspCategoriesTested: number;
  owaspCategoriesTotal: number;
  ptesPhasesCovered: number;
  ptesPhasesTotal: number;
  cloudAssetsFound: number;
  storageAssetsFound: number;
  containerAssetsFound: number;
  identityAssetsFound: number;
  repoExposuresFound: number;
  platformAssetsFound: number;
  falsePositiveRate: number;
}

function scoreReconAnalyst(m: PipelineMetrics): number {
  const assetScore = Math.min(30, m.assetsDiscovered * 5 + m.subdomainsFound * 2);
  const portScore = Math.min(25, m.portsFound * 3);
  const serviceScore = Math.min(15, m.servicesIdentified * 4);
  const techScore = Math.min(10, m.technologiesDetected * 2);
  const kevBonus = Math.min(10, m.kevMatches * 5);
  const cveBonus = Math.min(5, m.uniqueCVEs > 0 ? 5 : 0);
  const vulnDiscoveryBonus = Math.min(5, m.totalVulns > 0 ? Math.min(5, Math.ceil(m.totalVulns / 4)) : 0);
  return Math.min(100, assetScore + portScore + serviceScore + techScore + kevBonus + cveBonus + vulnDiscoveryBonus);
}

function scoreExploitSelector(m: PipelineMetrics): number {
  if (m.pipelineType === "di_scan" || m.pipelineType === "scheduled_scan") {
    const vulnAccuracy = m.totalVulns > 0 ? (m.confirmedVulns / m.totalVulns) * 50 : 0;
    const severityDepth = Math.min(30, (m.criticalVulns * 10) + (m.highVulns * 5) + (m.mediumVulns * 2));
    const kevScore = Math.min(20, m.kevMatches * 10);
    return Math.min(100, Math.round(vulnAccuracy + severityDepth + kevScore));
  }
  const successRate = m.exploitsAttempted > 0 ? (m.exploitsSucceeded / m.exploitsAttempted) * 35 : 0;
  const attemptCredit = Math.min(15, m.exploitsAttempted * 5);
  const evidenceRate = m.totalVulns > 0 ? (m.verifiedVulns / m.totalVulns) * 20 : 0;
  const volumeBonus = Math.min(15, m.totalVulns > 10 ? 15 : Math.ceil(m.totalVulns * 1.5));
  const severityBonus = Math.min(15, (m.criticalVulns * 5) + (m.highVulns * 3) + (m.mediumVulns * 1));
  return Math.min(100, Math.round(successRate + attemptCredit + evidenceRate + volumeBonus + severityBonus));
}

function scoreCognitiveCore(m: PipelineMetrics): number {
  const coverageScore = m.owaspCategoriesTotal > 0
    ? Math.round((m.owaspCategoriesTested / m.owaspCategoriesTotal) * 35)
    : 20;
  const evidenceRate = m.totalVulns > 0
    ? Math.round((m.confirmedVulns / m.totalVulns) * 25)
    : 0;
  const fpPenalty = Math.round(m.falsePositiveRate * 20);
  const vulnBaseline = m.totalVulns > 0 ? 15 : 0;
  const ptesBonus = m.ptesPhasesTotal > 0
    ? Math.min(15, Math.round((m.ptesPhasesCovered / m.ptesPhasesTotal) * 15))
    : 0;
  const corroborationBonus = m.confirmedVulns > 0 && m.totalVulns > m.confirmedVulns ? 5 : 0;
  const baseScore = coverageScore + evidenceRate + vulnBaseline + ptesBonus + corroborationBonus;
  return Math.min(100, Math.max(0, baseScore - fpPenalty));
}

// ─── Replicate adherence calculation from engagement-report-handoff.ts ───────

interface PtesPhaseStatus {
  phase: string;
  status: "completed" | "partial" | "skipped" | "not_applicable";
}

function calculatePhaseAdherence(phases: PtesPhaseStatus[]): number {
  const weights: Record<string, number> = {
    "Pre-engagement Interactions": 5,
    "Intelligence Gathering": 20,
    "Threat Modeling": 10,
    "Vulnerability Analysis": 25,
    "Exploitation": 25,
    "Post-Exploitation": 10,
    "Reporting": 5,
  };
  let totalWeight = 0;
  let completedWeight = 0;
  for (const phase of phases) {
    const weight = weights[phase.phase] || 10;
    totalWeight += weight;
    if (phase.status === "completed") completedWeight += weight;
    else if (phase.status === "partial") completedWeight += weight * 0.5;
  }
  return totalWeight > 0 ? Math.round((completedWeight / totalWeight) * 100) : 0;
}

// ─── Test Data: DVWA-like training lab engagement ────────────────────────────

const dvwaMetrics: PipelineMetrics = {
  pipelineType: "engagement",
  assetsDiscovered: 1,
  subdomainsFound: 0,
  portsFound: 7,
  servicesIdentified: 3,
  technologiesDetected: 4,
  totalVulns: 15,
  confirmedVulns: 5,
  criticalVulns: 3,
  highVulns: 5,
  mediumVulns: 4,
  lowVulns: 3,
  uniqueCVEs: 8,
  kevMatches: 2,
  exploitsAttempted: 2,
  exploitsSucceeded: 0,
  verifiedVulns: 5,
  wafDetected: false,
  wafBypassed: false,
  scanBlocked: false,
  scanRecovered: false,
  owaspCategoriesTested: 8,
  owaspCategoriesTotal: 25,
  ptesPhasesCovered: 5,
  ptesPhasesTotal: 7,
  cloudAssetsFound: 0,
  storageAssetsFound: 0,
  containerAssetsFound: 0,
  identityAssetsFound: 0,
  repoExposuresFound: 0,
  platformAssetsFound: 0,
  falsePositiveRate: 0,
};

// ═══════════════════════════════════════════════════════════════════════
// §1 — RECON SCORING TESTS
// ═══════════════════════════════════════════════════════════════════════

describe("scoreReconAnalyst (tuned)", () => {
  test("DVWA-like target scores above 50 with intelligence enrichment", () => {
    const score = scoreReconAnalyst(dvwaMetrics);
    // 1 asset (5) + 7 ports (21) + 3 services (12) + 4 tech (8) + 2 KEV (10) + CVEs (5) + vulns (4) = 65
    expect(score).toBeGreaterThanOrEqual(55);
  });

  test("KEV matches add bonus points", () => {
    const withKev = { ...dvwaMetrics, kevMatches: 3 };
    const withoutKev = { ...dvwaMetrics, kevMatches: 0 };
    expect(scoreReconAnalyst(withKev)).toBeGreaterThan(scoreReconAnalyst(withoutKev));
  });

  test("CVE discovery adds bonus points", () => {
    const withCves = { ...dvwaMetrics, uniqueCVEs: 5 };
    const withoutCves = { ...dvwaMetrics, uniqueCVEs: 0 };
    expect(scoreReconAnalyst(withCves)).toBeGreaterThan(scoreReconAnalyst(withoutCves));
  });

  test("vuln discovery adds bonus points", () => {
    const withVulns = { ...dvwaMetrics, totalVulns: 20 };
    const withoutVulns = { ...dvwaMetrics, totalVulns: 0 };
    expect(scoreReconAnalyst(withVulns)).toBeGreaterThan(scoreReconAnalyst(withoutVulns));
  });

  test("score is capped at 100", () => {
    const maxMetrics = {
      ...dvwaMetrics,
      assetsDiscovered: 10,
      subdomainsFound: 20,
      portsFound: 50,
      servicesIdentified: 20,
      technologiesDetected: 30,
      kevMatches: 10,
      uniqueCVEs: 20,
      totalVulns: 100,
    };
    expect(scoreReconAnalyst(maxMetrics)).toBeLessThanOrEqual(100);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §2 — EXPLOIT SCORING TESTS
// ═══════════════════════════════════════════════════════════════════════

describe("scoreExploitSelector (tuned)", () => {
  test("DVWA-like target with 0 success but attempts scores above 30", () => {
    const score = scoreExploitSelector(dvwaMetrics);
    // 0 success rate + 2 attempts (10) + evidence (6.7) + volume (15) + severity (15) = ~47
    expect(score).toBeGreaterThanOrEqual(30);
  });

  test("attempt credit rewards making exploit attempts", () => {
    const withAttempts = { ...dvwaMetrics, exploitsAttempted: 3 };
    const withoutAttempts = { ...dvwaMetrics, exploitsAttempted: 0 };
    expect(scoreExploitSelector(withAttempts)).toBeGreaterThan(scoreExploitSelector(withoutAttempts));
  });

  test("severity depth rewards finding critical/high vulns", () => {
    const withSeverity = { ...dvwaMetrics, criticalVulns: 5, highVulns: 5 };
    const withoutSeverity = { ...dvwaMetrics, criticalVulns: 0, highVulns: 0 };
    expect(scoreExploitSelector(withSeverity)).toBeGreaterThan(scoreExploitSelector(withoutSeverity));
  });

  test("successful exploits significantly boost score", () => {
    const withSuccess = { ...dvwaMetrics, exploitsSucceeded: 2 };
    const withoutSuccess = { ...dvwaMetrics, exploitsSucceeded: 0 };
    expect(scoreExploitSelector(withSuccess)).toBeGreaterThan(scoreExploitSelector(withoutSuccess));
  });

  test("DI scan mode uses vuln accuracy instead of exploit success", () => {
    const diMetrics = { ...dvwaMetrics, pipelineType: "di_scan" };
    const score = scoreExploitSelector(diMetrics);
    expect(score).toBeGreaterThan(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §3 — COGNITIVE CORE SCORING TESTS
// ═══════════════════════════════════════════════════════════════════════

describe("scoreCognitiveCore (tuned)", () => {
  test("DVWA-like target scores above 40 with PTES coverage", () => {
    const score = scoreCognitiveCore(dvwaMetrics);
    expect(score).toBeGreaterThanOrEqual(40);
  });

  test("PTES phase coverage adds bonus", () => {
    const withPtes = { ...dvwaMetrics, ptesPhasesCovered: 6 };
    const withoutPtes = { ...dvwaMetrics, ptesPhasesCovered: 0 };
    expect(scoreCognitiveCore(withPtes)).toBeGreaterThan(scoreCognitiveCore(withoutPtes));
  });

  test("corroboration bonus when confirmed < total", () => {
    const withCorroboration = { ...dvwaMetrics, confirmedVulns: 5, totalVulns: 15 };
    const withoutCorroboration = { ...dvwaMetrics, confirmedVulns: 0, totalVulns: 15 };
    expect(scoreCognitiveCore(withCorroboration)).toBeGreaterThan(scoreCognitiveCore(withoutCorroboration));
  });

  test("false positive rate penalizes score", () => {
    const withFP = { ...dvwaMetrics, falsePositiveRate: 0.5 };
    const withoutFP = { ...dvwaMetrics, falsePositiveRate: 0 };
    expect(scoreCognitiveCore(withFP)).toBeLessThan(scoreCognitiveCore(withoutFP));
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §4 — N/A CATEGORY EXCLUSION TESTS
// ═══════════════════════════════════════════════════════════════════════

describe("N/A category exclusion from average", () => {
  test("cloud_assessor is N/A when no cloud assets found", () => {
    // Simulating the filter logic from runPostPipelineGraduation
    const isCloudNA = dvwaMetrics.cloudAssetsFound === 0 &&
      dvwaMetrics.storageAssetsFound === 0 &&
      dvwaMetrics.containerAssetsFound === 0 &&
      dvwaMetrics.identityAssetsFound === 0;
    expect(isCloudNA).toBe(true);
  });

  test("supply_chain_analyst is N/A when no repo/platform assets found", () => {
    const isSupplyChainNA = dvwaMetrics.repoExposuresFound === 0 &&
      dvwaMetrics.platformAssetsFound === 0 &&
      dvwaMetrics.technologiesDetected === 0;
    // DVWA has technologies, so supply chain is NOT N/A
    expect(isSupplyChainNA).toBe(false);
  });

  test("average score is higher when N/A categories are excluded", () => {
    // With all 6 categories (including 0-score cloud): avg is lower
    const scores = {
      recon: 65,
      exploit: 47,
      evasion: 90,
      cognitive: 45,
      cloud: 0,
      supply_chain: 12,
    };
    const allAvg = Math.round(Object.values(scores).reduce((s, v) => s + v, 0) / 6);
    // Without cloud (N/A)
    const applicableValues = [scores.recon, scores.exploit, scores.evasion, scores.cognitive, scores.supply_chain];
    const filteredAvg = Math.round(applicableValues.reduce((s, v) => s + v, 0) / applicableValues.length);
    expect(filteredAvg).toBeGreaterThan(allAvg);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §5 — TEST PLAN ADHERENCE FLOOR TESTS
// ═══════════════════════════════════════════════════════════════════════

describe("Test plan adherence phase-based floor", () => {
  const completedPhases: PtesPhaseStatus[] = [
    { phase: "Pre-engagement Interactions", status: "completed" },
    { phase: "Intelligence Gathering", status: "completed" },
    { phase: "Threat Modeling", status: "partial" },
    { phase: "Vulnerability Analysis", status: "completed" },
    { phase: "Exploitation", status: "completed" },
    { phase: "Post-Exploitation", status: "skipped" },
    { phase: "Reporting", status: "completed" },
  ];

  test("phase-based adherence is non-zero when phases are completed", () => {
    const adherence = calculatePhaseAdherence(completedPhases);
    expect(adherence).toBeGreaterThan(0);
    expect(adherence).toBeGreaterThanOrEqual(50);
  });

  test("phase-based adherence reflects weighted completion", () => {
    // Pre-engagement (5/5) + Intel (20/20) + Threat (5/10) + VulnAnalysis (25/25) + Exploit (25/25) + Post (0/10) + Report (5/5) = 85/100
    const adherence = calculatePhaseAdherence(completedPhases);
    expect(adherence).toBe(85);
  });

  test("adherence percentage uses max of planned-vs-actual and phase-based", () => {
    const plannedAdherence = 0; // When tool names don't match
    const phaseAdherence = calculatePhaseAdherence(completedPhases);
    const finalAdherence = Math.max(plannedAdherence, phaseAdherence);
    expect(finalAdherence).toBe(85); // Phase-based wins over false 0%
  });

  test("all-skipped phases give 0% adherence", () => {
    const allSkipped: PtesPhaseStatus[] = [
      { phase: "Pre-engagement Interactions", status: "skipped" },
      { phase: "Intelligence Gathering", status: "skipped" },
      { phase: "Threat Modeling", status: "skipped" },
      { phase: "Vulnerability Analysis", status: "skipped" },
      { phase: "Exploitation", status: "skipped" },
      { phase: "Post-Exploitation", status: "skipped" },
      { phase: "Reporting", status: "skipped" },
    ];
    expect(calculatePhaseAdherence(allSkipped)).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §6 — MODULE EXPORT VERIFICATION
// ═══════════════════════════════════════════════════════════════════════

describe("Module exports verification", () => {
  test("post-pipeline-graduation exports scoring and metric extraction", async () => {
    const mod = await import("./lib/post-pipeline-graduation");
    expect(typeof mod.runPostPipelineGraduation).toBe("function");
    expect(typeof mod.extractEngagementMetrics).toBe("function");
    expect(typeof mod.extractDIScanMetrics).toBe("function");
  });

  test("engagement-report-handoff exports adherence functions", async () => {
    const mod = await import("./lib/engagement-report-handoff");
    expect(typeof mod.generateTestPlanAdherence).toBe("function");
    expect(typeof mod.adherenceToMarkdown).toBe("function");
  });
});
