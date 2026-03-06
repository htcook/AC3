/**
 * Hunt Engine & Enhanced Scoring Triggers — Test Suite
 * Tests the hunt workflow engine types, NICE KSA mapping,
 * and the new attack_chain_match / bug_bounty_correlation
 * scoring triggers added to the hybrid scoring engine.
 */
import { describe, it, expect } from "vitest";
import {
  NICE_KSAS,
  mapHuntToNiceKsas,
  type HuntContext,
  type HuntHypothesis,
  type HuntFinding,
  type HuntDeliverable,
} from "./lib/hunt-engine";
import {
  DISCOVERY_PHASE_TRIGGERS,
  applyDiscoveryTrigger,
  type CarverScores,
  type ShockScores,
} from "./lib/scoring-engine";

// ─── Hunt Engine Types ──────────────────────────────────────────────────────

describe("Hunt Engine — Types", () => {
  it("should define HuntContext with required fields", () => {
    const ctx: HuntContext = {
      sessionId: 1,
      orgName: "Vianova Corp",
      orgSector: "technology",
      siemPlatform: "splunk",
      dataSources: ["Windows Event Logs", "Sysmon", "DNS", "Proxy"],
    };
    expect(ctx.sessionId).toBe(1);
    expect(ctx.siemPlatform).toBe("splunk");
    expect(ctx.dataSources).toHaveLength(4);
  });

  it("should define HuntContext with optional threat actor", () => {
    const ctx: HuntContext = {
      sessionId: 2,
      orgName: "Test Org",
      orgSector: "finance",
      siemPlatform: "elastic",
      dataSources: ["EDR"],
      threatActor: {
        id: "APT29",
        name: "Cozy Bear",
        aliases: ["The Dukes"],
        ttps: ["T1566", "T1059"],
        targetSectors: ["government", "finance"],
        knownTools: ["Cobalt Strike", "Mimikatz"],
      },
    };
    expect(ctx.threatActor?.name).toBe("Cozy Bear");
    expect(ctx.threatActor?.ttps).toContain("T1566");
  });

  it("should define HuntHypothesis with all fields", () => {
    const hyp: HuntHypothesis = {
      statement: "Adversary is using PowerShell for lateral movement",
      mitreTechniqueId: "T1059.001",
      mitreTechniqueName: "PowerShell",
      mitreTactic: "execution",
      requiredDataSources: ["Windows Event Logs", "Sysmon"],
      sigmaRule: "title: PowerShell Execution\nlogsource:\n  product: windows",
      splQuery: 'index=windows sourcetype=WinEventLog EventCode=4104',
      kqlQuery: 'SecurityEvent | where EventID == 4104',
      confidence: "high",
      priority: 1,
      reasoning: "PowerShell is commonly used for post-exploitation",
      attackChainRef: "chain_001",
      bugBountyPatternRef: "rce_pattern_001",
    };
    expect(hyp.confidence).toBe("high");
    expect(hyp.mitreTechniqueId).toBe("T1059.001");
    expect(hyp.attackChainRef).toBe("chain_001");
  });

  it("should define HuntFinding with severity levels", () => {
    const finding: HuntFinding = {
      title: "Suspicious PowerShell Activity Detected",
      description: "Multiple encoded PowerShell commands executed from service account",
      severity: "high",
      mitreTechniqueId: "T1059.001",
      mitreTechniqueName: "PowerShell",
      mitreTactic: "execution",
      evidence: "Event ID 4104 with encoded commands from SYSTEM account",
      affectedAssets: ["DC01", "WEB01"],
      detectionRule: "sigma rule content here",
      remediation: "Restrict PowerShell execution policy, enable constrained language mode",
      confidence: "high",
    };
    expect(finding.severity).toBe("high");
    expect(finding.affectedAssets).toHaveLength(2);
  });

  it("should define HuntDeliverable with GSA HACS compliance", () => {
    const deliverable: HuntDeliverable = {
      executiveSummary: "Hunt operation identified 3 critical findings",
      hypothesesTested: 5,
      hypothesesConfirmed: 2,
      hypothesesRefuted: 2,
      hypothesesInconclusive: 1,
      findings: [],
      detectionRules: [
        {
          name: "PowerShell Encoded Command Detection",
          format: "sigma",
          content: "title: Encoded PowerShell",
          mitreTechniqueId: "T1059.001",
        },
      ],
      recommendations: ["Enable PowerShell logging", "Deploy Sysmon"],
      dataSourceGaps: ["No EDR telemetry available"],
      hacsComplianceNotes: ["Hunt aligned with GSA HACS SIN 54151HACS requirements"],
    };
    expect(deliverable.hypothesesTested).toBe(5);
    expect(deliverable.detectionRules).toHaveLength(1);
    expect(deliverable.hacsComplianceNotes.length).toBeGreaterThan(0);
  });
});

// ─── NICE Framework KSA Mapping ─────────────────────────────────────────────

describe("Hunt Engine — NICE KSA Mapping", () => {
  it("should have both work role definitions", () => {
    expect(NICE_KSAS.cyberDefenseAnalysis.workRoleId).toBe("PR-CDA-001");
    expect(NICE_KSAS.threatAnalysis.workRoleId).toBe("AN-TWA-001");
  });

  it("should have knowledge, skills, and abilities for each role", () => {
    expect(NICE_KSAS.cyberDefenseAnalysis.knowledge.length).toBeGreaterThan(10);
    expect(NICE_KSAS.cyberDefenseAnalysis.skills.length).toBeGreaterThan(5);
    expect(NICE_KSAS.cyberDefenseAnalysis.abilities.length).toBeGreaterThan(0);
    expect(NICE_KSAS.threatAnalysis.knowledge.length).toBeGreaterThan(5);
    expect(NICE_KSAS.threatAnalysis.skills.length).toBeGreaterThan(3);
    expect(NICE_KSAS.threatAnalysis.abilities.length).toBeGreaterThan(5);
  });

  it("should map hypothesis_generation to correct KSAs", () => {
    const result = mapHuntToNiceKsas(["hypothesis_generation"]);
    expect(result.exercisedKnowledge.length).toBeGreaterThan(0);
    // Should include K0005 (cyber threats) and K0161 (classes of attacks)
    expect(result.exercisedKnowledge.some(k => k.includes("K0005"))).toBe(true);
    expect(result.exercisedKnowledge.some(k => k.includes("K0161"))).toBe(true);
  });

  it("should map siem_query_creation to network analysis KSAs", () => {
    const result = mapHuntToNiceKsas(["siem_query_creation"]);
    expect(result.exercisedKnowledge.some(k => k.includes("K0058"))).toBe(true); // network traffic analysis
    expect(result.exercisedSkills.some(s => s.includes("S0020"))).toBe(true); // developing signatures
  });

  it("should map evidence_analysis to detection KSAs", () => {
    const result = mapHuntToNiceKsas(["evidence_analysis"]);
    expect(result.exercisedKnowledge.some(k => k.includes("K0046"))).toBe(true); // intrusion detection
    expect(result.exercisedSkills.some(s => s.includes("S0025"))).toBe(true); // detecting intrusions
  });

  it("should map report_generation to communication abilities", () => {
    const result = mapHuntToNiceKsas(["report_generation"]);
    expect(result.exercisedAbilities.some(a => a.includes("A0013"))).toBe(true); // communicate complex info
    expect(result.exercisedAbilities.some(a => a.includes("A0106"))).toBe(true); // think critically
  });

  it("should aggregate KSAs across multiple activities", () => {
    const result = mapHuntToNiceKsas([
      "hypothesis_generation",
      "siem_query_creation",
      "evidence_analysis",
      "detection_rule_creation",
      "report_generation",
    ]);
    // Should have KSAs from all activities
    expect(result.exercisedKnowledge.length).toBeGreaterThan(5);
    expect(result.exercisedSkills.length).toBeGreaterThan(3);
    expect(result.exercisedAbilities.length).toBeGreaterThan(2);
  });

  it("should handle unknown activities gracefully", () => {
    const result = mapHuntToNiceKsas(["unknown_activity"]);
    expect(result.exercisedKnowledge).toHaveLength(0);
    expect(result.exercisedSkills).toHaveLength(0);
    expect(result.exercisedAbilities).toHaveLength(0);
  });

  it("should not duplicate KSAs across overlapping activities", () => {
    const result = mapHuntToNiceKsas([
      "hypothesis_generation",
      "vulnerability_assessment", // both share K0005
    ]);
    const k0005Count = result.exercisedKnowledge.filter(k => k.includes("K0005")).length;
    expect(k0005Count).toBe(1); // deduplicated
  });
});

// ─── Enhanced Scoring Triggers ──────────────────────────────────────────────

describe("Scoring Engine — Enhanced Discovery Triggers", () => {
  const baseCarver: CarverScores = {
    criticality: 5,
    accessibility: 5,
    recuperability: 5,
    vulnerability: 5,
    effect: 5,
    recognizability: 5,
  };
  const baseShock: ShockScores = {
    scope: 5,
    handling: 5,
    operationalImpact: 5,
    cascadingEffects: 5,
    knowledge: 5,
  };

  it("should have attack_chain_match trigger defined", () => {
    expect(DISCOVERY_PHASE_TRIGGERS.attack_chain_match).toBeDefined();
    expect(DISCOVERY_PHASE_TRIGGERS.attack_chain_match.description).toContain("attack chain");
  });

  it("should have bug_bounty_correlation trigger defined", () => {
    expect(DISCOVERY_PHASE_TRIGGERS.bug_bounty_correlation).toBeDefined();
    expect(DISCOVERY_PHASE_TRIGGERS.bug_bounty_correlation.description).toContain("bug bounty");
  });

  it("should boost vulnerability score for high-feasibility attack chains", () => {
    const result = applyDiscoveryTrigger(
      "attack_chain_match",
      { chainLength: 4, feasibility: "high" },
      baseCarver,
      baseShock
    );
    expect(result.carver.vulnerability).toBe(9); // high feasibility → 9
    expect(result.carver.effect).toBe(8); // chainLength >= 3 → 8
    expect(result.likelihoodBoost).toBe(0.25);
  });

  it("should boost cascading effects for long attack chains", () => {
    const result = applyDiscoveryTrigger(
      "attack_chain_match",
      { chainLength: 5, feasibility: "medium" },
      baseCarver,
      baseShock
    );
    expect(result.shock.cascadingEffects).toBe(8); // chainLength >= 3
    expect(result.shock.scope).toBe(7); // chainLength >= 4
    expect(result.carver.vulnerability).toBe(7); // medium feasibility
  });

  it("should apply moderate boost for short chains", () => {
    const result = applyDiscoveryTrigger(
      "attack_chain_match",
      { chainLength: 2, feasibility: "low" },
      baseCarver,
      baseShock
    );
    expect(result.carver.vulnerability).toBe(5); // low feasibility → 5, same as base
    expect(result.carver.effect).toBe(6); // chainLength < 3 → 6
    expect(result.shock.cascadingEffects).toBe(5); // chainLength < 3 → 5
    expect(result.likelihoodBoost).toBe(0.05);
  });

  it("should boost scores for critical bug bounty correlations", () => {
    const result = applyDiscoveryTrigger(
      "bug_bounty_correlation",
      { bountyTier: "critical" },
      baseCarver,
      baseShock
    );
    expect(result.carver.vulnerability).toBe(9);
    expect(result.carver.accessibility).toBe(7);
    expect(result.shock.handling).toBe(8);
    expect(result.likelihoodBoost).toBe(0.3);
  });

  it("should boost scores for high bug bounty correlations", () => {
    const result = applyDiscoveryTrigger(
      "bug_bounty_correlation",
      { bountyTier: "high" },
      baseCarver,
      baseShock
    );
    expect(result.carver.vulnerability).toBe(7);
    expect(result.carver.accessibility).toBe(7);
    expect(result.likelihoodBoost).toBe(0.2);
  });

  it("should never lower existing scores (floor behavior)", () => {
    const highCarver: CarverScores = { ...baseCarver, vulnerability: 10, accessibility: 9 };
    const result = applyDiscoveryTrigger(
      "bug_bounty_correlation",
      { bountyTier: "high" },
      highCarver,
      baseShock
    );
    expect(result.carver.vulnerability).toBe(10); // was 10, trigger says 7 → stays 10
    expect(result.carver.accessibility).toBe(9); // was 9, trigger says 7 → stays 9
  });

  it("should handle existing triggers (kev_match, darkweb_exposure)", () => {
    const kevResult = applyDiscoveryTrigger("kev_match", {}, baseCarver, baseShock);
    expect(kevResult.carver.vulnerability).toBe(10);
    expect(kevResult.carver.recognizability).toBe(8);
    expect(kevResult.likelihoodBoost).toBe(0.3);

    const dwResult = applyDiscoveryTrigger("darkweb_exposure", { dataType: "credentials" }, baseCarver, baseShock);
    expect(dwResult.carver.accessibility).toBe(9);
    expect(dwResult.shock.scope).toBe(8);
  });

  it("should return unchanged scores for unknown triggers", () => {
    const result = applyDiscoveryTrigger("nonexistent_trigger", {}, baseCarver, baseShock);
    expect(result.carver).toEqual(baseCarver);
    expect(result.shock).toEqual(baseShock);
    expect(result.likelihoodBoost).toBe(0);
  });
});
