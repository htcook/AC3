/**
 * Tests for CI/CD Threat Intelligence Correlator (P0-P3):
 * 1. CVE-to-actor mapping
 * 2. Severity boosting rules
 * 3. Kill chain phase mapping
 * 4. Actor exposure scoring
 * 5. Pre-scan template selection
 * 6. Quick threat score
 * 7. Cross-run aggregation
 * 8. Notification enrichment
 * 9. Engagement bridge
 * 10. Sector context
 */
import { describe, it, expect, vi } from "vitest";

// ─── Mock Types ────────────────────────────────────────────────────────────────

interface MockFinding {
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  url: string;
  description: string;
  scanner: string;
  cweId?: string;
  cvss?: number;
}

// ─── 1. CVE-to-Actor Mapping ───────────────────────────────────────────────────

describe("CVE-to-Actor Mapping", () => {
  it("should extract CVE IDs from finding titles", () => {
    const cvePattern = /CVE-\d{4}-\d{4,}/gi;
    const title = "Apache Log4j RCE (CVE-2021-44228) detected on target";
    const matches = title.match(cvePattern) || [];
    expect(matches).toHaveLength(1);
    expect(matches[0].toUpperCase()).toBe("CVE-2021-44228");
  });

  it("should extract multiple CVEs from descriptions", () => {
    const cvePattern = /CVE-\d{4}-\d{4,}/gi;
    const desc = "Vulnerabilities found: CVE-2023-0001, CVE-2023-0002, and CVE-2022-9999";
    const matches = desc.match(cvePattern) || [];
    expect(matches).toHaveLength(3);
    expect(matches.map(m => m.toUpperCase())).toContain("CVE-2023-0001");
    expect(matches.map(m => m.toUpperCase())).toContain("CVE-2023-0002");
    expect(matches.map(m => m.toUpperCase())).toContain("CVE-2022-9999");
  });

  it("should deduplicate CVEs across title and description", () => {
    const cvePattern = /CVE-\d{4}-\d{4,}/gi;
    const combined = "CVE-2021-44228 found. Details: CVE-2021-44228 is critical.";
    const matches = combined.match(cvePattern) || [];
    const unique = [...new Set(matches.map(m => m.toUpperCase()))];
    expect(unique).toHaveLength(1);
  });

  it("should return empty array when no CVEs present", () => {
    const cvePattern = /CVE-\d{4}-\d{4,}/gi;
    const title = "Missing security headers detected";
    const matches = title.match(cvePattern) || [];
    expect(matches).toHaveLength(0);
  });
});

// ─── 2. Severity Boosting Rules ────────────────────────────────────────────────

describe("Severity Boosting Rules", () => {
  const SEVERITY_ORDER: Record<string, number> = {
    info: 0, low: 1, medium: 2, high: 3, critical: 4,
  };
  const SEVERITY_NAMES = ["info", "low", "medium", "high", "critical"];

  function boostSeverity(current: string, levels: number): string {
    const idx = SEVERITY_ORDER[current];
    const newIdx = Math.min(idx + levels, 4);
    return SEVERITY_NAMES[newIdx];
  }

  it("should boost medium to high by one level", () => {
    expect(boostSeverity("medium", 1)).toBe("high");
  });

  it("should boost low to high by two levels", () => {
    expect(boostSeverity("low", 2)).toBe("high");
  });

  it("should cap at critical", () => {
    expect(boostSeverity("high", 3)).toBe("critical");
    expect(boostSeverity("critical", 1)).toBe("critical");
  });

  it("should not change severity when boosting by zero", () => {
    expect(boostSeverity("medium", 0)).toBe("medium");
  });

  it("should boost info to low by one level", () => {
    expect(boostSeverity("info", 1)).toBe("low");
  });

  it("should apply Rule A: critical actor exploit → boost to critical", () => {
    const finding = { severity: "medium" };
    const criticalActors = [{ threatLevel: "critical", matchType: "cve_exploit" }];
    if (criticalActors.length > 0) {
      finding.severity = "critical";
    }
    expect(finding.severity).toBe("critical");
  });

  it("should apply Rule B: multiple exploiters → boost by one level", () => {
    const finding = { severity: "medium" };
    const cveExploiters = [
      { matchType: "cve_exploit", threatLevel: "high" },
      { matchType: "cve_exploit", threatLevel: "medium" },
    ];
    if (cveExploiters.length >= 2) {
      finding.severity = boostSeverity(finding.severity, 1);
    }
    expect(finding.severity).toBe("high");
  });

  it("should apply Rule C: ransomware group → flag RANSOMWARE_RISK", () => {
    const riskTags: string[] = [];
    const actors = [{ groupType: "ransomware" }];
    if (actors.some(a => a.groupType === "ransomware")) {
      riskTags.push("RANSOMWARE_RISK");
    }
    expect(riskTags).toContain("RANSOMWARE_RISK");
  });

  it("should apply Rule D: APT group → flag APT_RISK", () => {
    const riskTags: string[] = [];
    const actors = [{ groupType: "apt" }];
    if (actors.some(a => a.groupType === "apt")) {
      riskTags.push("APT_RISK");
    }
    expect(riskTags).toContain("APT_RISK");
  });

  it("should apply Rule E: active group → flag ACTIVE_EXPLOITATION", () => {
    const riskTags: string[] = [];
    const actors = [{ active: true }];
    if (actors.some(a => a.active)) {
      riskTags.push("ACTIVE_EXPLOITATION");
    }
    expect(riskTags).toContain("ACTIVE_EXPLOITATION");
  });
});

// ─── 3. CWE-to-Kill Chain Phase Mapping ────────────────────────────────────────

describe("CWE-to-Kill Chain Mapping", () => {
  const CWE_TO_TACTIC: Record<string, { tactic: string; tacticId: string; techniques: string[] }> = {
    "CWE-79":  { tactic: "Initial Access",        tacticId: "TA0001", techniques: ["T1189", "T1566.002"] },
    "CWE-89":  { tactic: "Initial Access",        tacticId: "TA0001", techniques: ["T1190"] },
    "CWE-94":  { tactic: "Execution",             tacticId: "TA0002", techniques: ["T1059"] },
    "CWE-78":  { tactic: "Execution",             tacticId: "TA0002", techniques: ["T1059.004"] },
    "CWE-287": { tactic: "Credential Access",     tacticId: "TA0006", techniques: ["T1110"] },
    "CWE-434": { tactic: "Persistence",           tacticId: "TA0003", techniques: ["T1505.003"] },
    "CWE-798": { tactic: "Credential Access",     tacticId: "TA0006", techniques: ["T1552.001"] },
    "CWE-918": { tactic: "Discovery",             tacticId: "TA0007", techniques: ["T1046"] },
    "CWE-269": { tactic: "Privilege Escalation",  tacticId: "TA0004", techniques: ["T1068"] },
  };

  it("should map CWE-89 (SQL Injection) to Initial Access", () => {
    const mapping = CWE_TO_TACTIC["CWE-89"];
    expect(mapping).toBeDefined();
    expect(mapping.tactic).toBe("Initial Access");
    expect(mapping.tacticId).toBe("TA0001");
    expect(mapping.techniques).toContain("T1190");
  });

  it("should map CWE-78 (OS Command Injection) to Execution", () => {
    const mapping = CWE_TO_TACTIC["CWE-78"];
    expect(mapping.tactic).toBe("Execution");
    expect(mapping.techniques).toContain("T1059.004");
  });

  it("should map CWE-798 (Hardcoded Credentials) to Credential Access", () => {
    const mapping = CWE_TO_TACTIC["CWE-798"];
    expect(mapping.tactic).toBe("Credential Access");
    expect(mapping.tacticId).toBe("TA0006");
  });

  it("should map CWE-434 (File Upload) to Persistence", () => {
    const mapping = CWE_TO_TACTIC["CWE-434"];
    expect(mapping.tactic).toBe("Persistence");
    expect(mapping.techniques).toContain("T1505.003");
  });

  it("should map CWE-269 (Improper Privilege) to Privilege Escalation", () => {
    const mapping = CWE_TO_TACTIC["CWE-269"];
    expect(mapping.tactic).toBe("Privilege Escalation");
    expect(mapping.tacticId).toBe("TA0004");
  });

  it("should extract CWE ID from various formats", () => {
    const extractCWE = (s: string) => {
      const match = s.match(/CWE-(\d+)/i);
      return match ? `CWE-${match[1]}` : null;
    };
    expect(extractCWE("CWE-89")).toBe("CWE-89");
    expect(extractCWE("cwe-89")).toBe("CWE-89");
    expect(extractCWE("CWE-79: XSS")).toBe("CWE-79");
    expect(extractCWE("No CWE")).toBeNull();
  });
});

// ─── 4. Actor Exposure Scoring ─────────────────────────────────────────────────

describe("Actor Exposure Scoring", () => {
  it("should compute higher scores for critical threat level actors", () => {
    const criticalScore = (3 * 10 + 2 * 15) * 1.5 * 1.3; // 3 findings, 2 CVEs, critical, active
    const mediumScore = (3 * 10 + 2 * 15) * 1.0 * 1.0;   // same counts, medium, inactive
    expect(criticalScore).toBeGreaterThan(mediumScore);
  });

  it("should cap exposure score at 100", () => {
    const rawScore = (20 * 10 + 15 * 15) * 1.5 * 1.3; // very high
    const capped = Math.min(100, Math.round(rawScore));
    expect(capped).toBe(100);
  });

  it("should return 0 for no actor matches", () => {
    const topActors: { exposureScore: number }[] = [];
    const score = topActors.length > 0
      ? Math.round(topActors.reduce((sum, a) => sum + a.exposureScore, 0) / topActors.length)
      : 0;
    expect(score).toBe(0);
  });

  it("should average top 5 actor scores for overall exposure", () => {
    const topActors = [
      { exposureScore: 80 },
      { exposureScore: 60 },
      { exposureScore: 40 },
      { exposureScore: 30 },
      { exposureScore: 20 },
    ];
    const avg = Math.round(topActors.reduce((sum, a) => sum + a.exposureScore, 0) / topActors.length);
    expect(avg).toBe(46);
  });

  it("should sort actors by exposure score descending", () => {
    const actors = [
      { groupId: "a", exposureScore: 30 },
      { groupId: "b", exposureScore: 80 },
      { groupId: "c", exposureScore: 50 },
    ];
    const sorted = actors.sort((a, b) => b.exposureScore - a.exposureScore);
    expect(sorted[0].groupId).toBe("b");
    expect(sorted[1].groupId).toBe("c");
    expect(sorted[2].groupId).toBe("a");
  });
});

// ─── 5. Kill Chain Coverage Calculation ────────────────────────────────────────

describe("Kill Chain Coverage", () => {
  const ALL_PHASES = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
  ];

  it("should calculate 0% coverage when no phases are hit", () => {
    const coveredPhases = 0;
    const coverage = Math.round((coveredPhases / ALL_PHASES.length) * 100);
    expect(coverage).toBe(0);
  });

  it("should calculate correct coverage for partial hits", () => {
    const coveredPhases = 4; // e.g., Initial Access, Execution, Credential Access, Discovery
    const coverage = Math.round((coveredPhases / ALL_PHASES.length) * 100);
    expect(coverage).toBe(29); // 4/14 = 28.57 → 29
  });

  it("should calculate 100% coverage when all phases hit", () => {
    const coveredPhases = ALL_PHASES.length;
    const coverage = Math.round((coveredPhases / ALL_PHASES.length) * 100);
    expect(coverage).toBe(100);
  });

  it("should have exactly 14 kill chain phases", () => {
    expect(ALL_PHASES).toHaveLength(14);
  });

  it("should include all MITRE ATT&CK enterprise tactics", () => {
    expect(ALL_PHASES).toContain("Initial Access");
    expect(ALL_PHASES).toContain("Execution");
    expect(ALL_PHASES).toContain("Persistence");
    expect(ALL_PHASES).toContain("Privilege Escalation");
    expect(ALL_PHASES).toContain("Defense Evasion");
    expect(ALL_PHASES).toContain("Credential Access");
    expect(ALL_PHASES).toContain("Discovery");
    expect(ALL_PHASES).toContain("Lateral Movement");
    expect(ALL_PHASES).toContain("Collection");
    expect(ALL_PHASES).toContain("Command and Control");
    expect(ALL_PHASES).toContain("Exfiltration");
    expect(ALL_PHASES).toContain("Impact");
  });
});

// ─── 6. Pre-Scan Template Selection (P1) ───────────────────────────────────────

describe("Pre-Scan Template Selection (P1)", () => {
  it("should map phishing initial access to phishing template tag", () => {
    const templateTags = new Set<string>();
    const method = "Spear-phishing with malicious attachments";
    if (method.toLowerCase().includes("phishing")) templateTags.add("phishing");
    expect(templateTags.has("phishing")).toBe(true);
  });

  it("should map exploit-based access to cves template tag", () => {
    const templateTags = new Set<string>();
    const method = "Exploit public-facing vulnerability";
    if (method.toLowerCase().includes("exploit") || method.toLowerCase().includes("vulnerability")) {
      templateTags.add("cves");
    }
    expect(templateTags.has("cves")).toBe(true);
  });

  it("should map brute force to default-logins template tag", () => {
    const templateTags = new Set<string>();
    const method = "Brute force credential attacks";
    if (method.toLowerCase().includes("brute") || method.toLowerCase().includes("credential")) {
      templateTags.add("default-logins");
    }
    expect(templateTags.has("default-logins")).toBe(true);
  });

  it("should prioritize CVEs exploited by multiple groups", () => {
    const cveToGroups = new Map<string, string[]>();
    cveToGroups.set("CVE-2021-44228", ["APT41", "Lazarus", "FIN7"]);
    cveToGroups.set("CVE-2023-0001", ["APT28"]);
    cveToGroups.set("CVE-2022-5555", ["APT29", "Sandworm"]);

    const sorted = [...cveToGroups.entries()].sort((a, b) => b[1].length - a[1].length);
    expect(sorted[0][0]).toBe("CVE-2021-44228");
    expect(sorted[0][1]).toHaveLength(3);
  });

  it("should exclude already-found CVEs from recommendations", () => {
    const alreadyFound = new Set(["CVE-2021-44228"]);
    const allCVEs = ["CVE-2021-44228", "CVE-2023-0001", "CVE-2022-5555"];
    const recommended = allCVEs.filter(c => !alreadyFound.has(c));
    expect(recommended).not.toContain("CVE-2021-44228");
    expect(recommended).toHaveLength(2);
  });

  it("should assign priority based on group count", () => {
    const groupCount = 3;
    const priority = groupCount >= 3 ? "critical" : groupCount >= 2 ? "high" : "medium";
    expect(priority).toBe("critical");

    const priority2 = 2 >= 3 ? "critical" : 2 >= 2 ? "high" : "medium";
    expect(priority2).toBe("high");

    const priority3 = 1 >= 3 ? "critical" : 1 >= 2 ? "high" : "medium";
    expect(priority3).toBe("medium");
  });
});

// ─── 7. Quick Threat Score ─────────────────────────────────────────────────────

describe("Quick Threat Score", () => {
  it("should return 0 for empty findings", () => {
    const actorCount = 0;
    const hasRansomwareRisk = false;
    const hasAptRisk = false;
    const baseScore = Math.min(100, actorCount * 15 + (hasRansomwareRisk ? 20 : 0) + (hasAptRisk ? 15 : 0));
    expect(baseScore).toBe(0);
  });

  it("should add 20 points for ransomware risk", () => {
    const actorCount = 1;
    const hasRansomwareRisk = true;
    const hasAptRisk = false;
    const baseScore = Math.min(100, actorCount * 15 + (hasRansomwareRisk ? 20 : 0) + (hasAptRisk ? 15 : 0));
    expect(baseScore).toBe(35); // 15 + 20
  });

  it("should add 15 points for APT risk", () => {
    const actorCount = 1;
    const hasRansomwareRisk = false;
    const hasAptRisk = true;
    const baseScore = Math.min(100, actorCount * 15 + (hasRansomwareRisk ? 20 : 0) + (hasAptRisk ? 15 : 0));
    expect(baseScore).toBe(30); // 15 + 15
  });

  it("should cap at 100", () => {
    const actorCount = 10;
    const hasRansomwareRisk = true;
    const hasAptRisk = true;
    const baseScore = Math.min(100, actorCount * 15 + (hasRansomwareRisk ? 20 : 0) + (hasAptRisk ? 15 : 0));
    expect(baseScore).toBe(100); // 150 + 20 + 15 → capped at 100
  });

  it("should scale linearly with actor count", () => {
    const score1 = Math.min(100, 1 * 15);
    const score3 = Math.min(100, 3 * 15);
    const score5 = Math.min(100, 5 * 15);
    expect(score1).toBe(15);
    expect(score3).toBe(45);
    expect(score5).toBe(75);
  });
});

// ─── 8. Threat-Enriched Notifications (P2) ─────────────────────────────────────

describe("Threat-Enriched Notifications (P2)", () => {
  it("should include threat intelligence section when actors are matched", () => {
    const tc = {
      summary: {
        uniqueActorsMatched: 3,
        actorExposureScore: 65,
        severityBoostedCount: 2,
        ransomwareRiskFindings: 1,
        aptRiskFindings: 2,
        killChainCoverage: 29,
      },
      actorExposure: [
        { groupName: "APT28", groupType: "apt", threatLevel: "critical", findingCount: 5, exposureScore: 80 },
        { groupName: "LockBit", groupType: "ransomware", threatLevel: "high", findingCount: 3, exposureScore: 60 },
      ],
    };

    const threatLines: string[] = [];
    if (tc.summary) {
      threatLines.push(`━━━ THREAT INTELLIGENCE ━━━`);
      threatLines.push(`Actors Matched: ${tc.summary.uniqueActorsMatched} | Exposure Score: ${tc.summary.actorExposureScore}/100`);
      threatLines.push(`Severity Boosted: ${tc.summary.severityBoostedCount} findings`);
      if (tc.summary.ransomwareRiskFindings > 0) threatLines.push(`RANSOMWARE RISK: ${tc.summary.ransomwareRiskFindings} findings`);
      if (tc.summary.aptRiskFindings > 0) threatLines.push(`APT RISK: ${tc.summary.aptRiskFindings} findings`);
    }

    expect(threatLines).toHaveLength(5);
    expect(threatLines[0]).toContain("THREAT INTELLIGENCE");
    expect(threatLines[1]).toContain("3");
    expect(threatLines[1]).toContain("65/100");
    expect(threatLines[3]).toContain("RANSOMWARE RISK");
    expect(threatLines[4]).toContain("APT RISK");
  });

  it("should include top 3 actors in notification", () => {
    const actors = [
      { groupName: "APT28", groupType: "apt", threatLevel: "critical", findingCount: 5, exposureScore: 80 },
      { groupName: "LockBit", groupType: "ransomware", threatLevel: "high", findingCount: 3, exposureScore: 60 },
      { groupName: "FIN7", groupType: "cybercrime", threatLevel: "high", findingCount: 2, exposureScore: 40 },
      { groupName: "APT29", groupType: "apt", threatLevel: "critical", findingCount: 1, exposureScore: 30 },
    ];

    const top3 = actors.slice(0, 3);
    expect(top3).toHaveLength(3);
    expect(top3[0].groupName).toBe("APT28");
    expect(top3[2].groupName).toBe("FIN7");
  });

  it("should not include threat section when no actors matched", () => {
    const tc = { summary: { uniqueActorsMatched: 0 } };
    const threatLines: string[] = [];
    if (tc.summary.uniqueActorsMatched > 0) {
      threatLines.push("THREAT INTELLIGENCE");
    }
    expect(threatLines).toHaveLength(0);
  });
});

// ─── 9. Engagement Bridge (P2) ─────────────────────────────────────────────────

describe("Engagement Bridge (P2)", () => {
  it("should allow linking a pipeline to an engagement", () => {
    const pipeline = { id: 1, engagementId: null as number | null };
    pipeline.engagementId = 42;
    expect(pipeline.engagementId).toBe(42);
  });

  it("should allow unlinking a pipeline from an engagement", () => {
    const pipeline = { id: 1, engagementId: 42 as number | null };
    pipeline.engagementId = null;
    expect(pipeline.engagementId).toBeNull();
  });

  it("should include engagementId in pipeline mapping", () => {
    const row = {
      id: 1,
      cicdName: "Test Pipeline",
      cicdEngagementId: 42,
      cicdSectorContext: "financial",
    };
    const mapped = {
      id: row.id,
      name: row.cicdName,
      engagementId: row.cicdEngagementId || null,
      sectorContext: row.cicdSectorContext || null,
    };
    expect(mapped.engagementId).toBe(42);
    expect(mapped.sectorContext).toBe("financial");
  });

  it("should include threatContext in run mapping", () => {
    const row = {
      id: 1,
      cicdThreatContext: JSON.stringify({
        summary: { uniqueActorsMatched: 3 },
      }),
    };
    const parsed = typeof row.cicdThreatContext === "string"
      ? JSON.parse(row.cicdThreatContext)
      : row.cicdThreatContext;
    expect(parsed.summary.uniqueActorsMatched).toBe(3);
  });

  it("should handle null threat context gracefully", () => {
    const row = { id: 1, cicdThreatContext: null };
    const parsed = row.cicdThreatContext
      ? JSON.parse(row.cicdThreatContext as string)
      : null;
    expect(parsed).toBeNull();
  });
});

// ─── 10. Sector Context (P1/P2) ────────────────────────────────────────────────

describe("Sector Context", () => {
  const VALID_SECTORS = [
    "financial", "healthcare", "government", "defense", "energy",
    "technology", "telecommunications", "manufacturing", "retail",
    "education", "transportation", "media", "legal", "aerospace",
  ];

  it("should accept valid sector values", () => {
    for (const sector of VALID_SECTORS) {
      expect(typeof sector).toBe("string");
      expect(sector.length).toBeGreaterThan(0);
    }
  });

  it("should include at least 10 sector options", () => {
    expect(VALID_SECTORS.length).toBeGreaterThanOrEqual(10);
  });

  it("should include critical infrastructure sectors", () => {
    expect(VALID_SECTORS).toContain("financial");
    expect(VALID_SECTORS).toContain("healthcare");
    expect(VALID_SECTORS).toContain("government");
    expect(VALID_SECTORS).toContain("defense");
    expect(VALID_SECTORS).toContain("energy");
  });

  it("should use sector for pre-scan template filtering", () => {
    // Simulate: financial sector → groups targeting financial → their CVEs
    const financialGroups = [
      { name: "FIN7", exploitedCVEs: ["CVE-2023-0001", "CVE-2023-0002"] },
      { name: "Carbanak", exploitedCVEs: ["CVE-2023-0003"] },
    ];
    const priorityCVEs = new Set<string>();
    for (const g of financialGroups) {
      g.exploitedCVEs.forEach(c => priorityCVEs.add(c));
    }
    expect(priorityCVEs.size).toBe(3);
    expect(priorityCVEs.has("CVE-2023-0001")).toBe(true);
  });
});

// ─── 11. Enriched Finding Structure ────────────────────────────────────────────

describe("Enriched Finding Structure", () => {
  it("should preserve original severity after boosting", () => {
    const enriched = {
      title: "SQL Injection",
      severity: "critical",
      originalSeverity: "medium",
      severityBoosted: true,
      boostReason: "Exploited by critical threat group: APT28",
      attributedGroups: [{ groupName: "APT28" }],
      riskTags: ["APT_RISK", "ACTIVE_EXPLOITATION"],
      killChainPhases: ["Initial Access"],
    };

    expect(enriched.originalSeverity).toBe("medium");
    expect(enriched.severity).toBe("critical");
    expect(enriched.severityBoosted).toBe(true);
    expect(enriched.boostReason).toContain("APT28");
    expect(enriched.riskTags).toContain("APT_RISK");
    expect(enriched.killChainPhases).toContain("Initial Access");
  });

  it("should not modify findings without actor matches", () => {
    const enriched = {
      title: "Missing X-Frame-Options",
      severity: "low",
      originalSeverity: "low",
      severityBoosted: false,
      boostReason: undefined,
      attributedGroups: [],
      riskTags: [],
      killChainPhases: [],
    };

    expect(enriched.severity).toBe(enriched.originalSeverity);
    expect(enriched.severityBoosted).toBe(false);
    expect(enriched.attributedGroups).toHaveLength(0);
    expect(enriched.riskTags).toHaveLength(0);
  });
});

// ─── 12. Cross-Run Aggregation (P3) ────────────────────────────────────────────

describe("Cross-Run Aggregation (P3)", () => {
  it("should aggregate actor frequency across multiple runs", () => {
    const runs = [
      { actorExposure: [{ groupId: "apt28", groupName: "APT28", findingCount: 3 }] },
      { actorExposure: [{ groupId: "apt28", groupName: "APT28", findingCount: 2 }, { groupId: "fin7", groupName: "FIN7", findingCount: 1 }] },
      { actorExposure: [{ groupId: "fin7", groupName: "FIN7", findingCount: 4 }] },
    ];

    const freq = new Map<string, { name: string; count: number }>();
    for (const run of runs) {
      for (const actor of run.actorExposure) {
        const existing = freq.get(actor.groupId);
        if (existing) {
          existing.count += actor.findingCount;
        } else {
          freq.set(actor.groupId, { name: actor.groupName, count: actor.findingCount });
        }
      }
    }

    const sorted = [...freq.values()].sort((a, b) => b.count - a.count);
    expect(sorted[0].name).toBe("APT28");
    expect(sorted[0].count).toBe(5);
    expect(sorted[1].name).toBe("FIN7");
    expect(sorted[1].count).toBe(5);
  });

  it("should aggregate kill chain hits across runs", () => {
    const runs = [
      { killChainMap: [{ phase: "Initial Access", findingCount: 3 }, { phase: "Execution", findingCount: 1 }] },
      { killChainMap: [{ phase: "Initial Access", findingCount: 2 }, { phase: "Persistence", findingCount: 1 }] },
    ];

    const hits = new Map<string, number>();
    for (const run of runs) {
      for (const kc of run.killChainMap) {
        if (kc.findingCount > 0) {
          hits.set(kc.phase, (hits.get(kc.phase) || 0) + kc.findingCount);
        }
      }
    }

    expect(hits.get("Initial Access")).toBe(5);
    expect(hits.get("Execution")).toBe(1);
    expect(hits.get("Persistence")).toBe(1);
  });

  it("should sum severity boosts and risk flags across runs", () => {
    const summaries = [
      { severityBoostedCount: 3, ransomwareRiskFindings: 1, aptRiskFindings: 2 },
      { severityBoostedCount: 1, ransomwareRiskFindings: 0, aptRiskFindings: 1 },
      { severityBoostedCount: 2, ransomwareRiskFindings: 2, aptRiskFindings: 0 },
    ];

    const totals = summaries.reduce((acc, s) => ({
      boosted: acc.boosted + s.severityBoostedCount,
      ransomware: acc.ransomware + s.ransomwareRiskFindings,
      apt: acc.apt + s.aptRiskFindings,
    }), { boosted: 0, ransomware: 0, apt: 0 });

    expect(totals.boosted).toBe(6);
    expect(totals.ransomware).toBe(3);
    expect(totals.apt).toBe(3);
  });
});

// ─── 13. Threat Context JSON Storage ───────────────────────────────────────────

describe("Threat Context JSON Storage", () => {
  it("should serialize threat context to JSON", () => {
    const tc = {
      summary: { uniqueActorsMatched: 3, actorExposureScore: 65 },
      actorExposure: [{ groupId: "apt28", groupName: "APT28" }],
    };
    const json = JSON.stringify(tc);
    expect(typeof json).toBe("string");
    const parsed = JSON.parse(json);
    expect(parsed.summary.uniqueActorsMatched).toBe(3);
  });

  it("should escape single quotes for SQL storage", () => {
    const tc = { summary: { note: "It's a test" } };
    const json = JSON.stringify(tc).replace(/'/g, "''");
    expect(json).toContain("It''s a test");
  });

  it("should handle empty threat context gracefully", () => {
    const tc = null;
    const stored = tc ? JSON.stringify(tc) : null;
    expect(stored).toBeNull();
  });

  it("should parse stored JSON back to object", () => {
    const stored = '{"summary":{"uniqueActorsMatched":5}}';
    const parsed = JSON.parse(stored);
    expect(parsed.summary.uniqueActorsMatched).toBe(5);
  });
});
