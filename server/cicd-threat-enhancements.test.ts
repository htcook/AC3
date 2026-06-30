/**
 * Tests for CI/CD Threat Intelligence Enhancements:
 * 1. Threat Trend Sparklines (time-series data generation)
 * 2. Auto-Gate Escalation (threat-based pass→fail override)
 * 3. Engagement Auto-Import (finding enrichment and transfer)
 */
import { describe, it, expect, vi } from "vitest";

// ─── Mock Types ────────────────────────────────────────────────────────────────

interface ThreatSummary {
  uniqueActorsMatched: number;
  severityBoostedCount: number;
  actorExposureScore: number;
  killChainCoverage: number;
  ransomwareRiskFindings: number;
  aptRiskFindings: number;
}

interface ThreatContext {
  summary: ThreatSummary;
  enrichedFindings: Array<{
    title: string;
    severity: string;
    originalSeverity: string;
    severityBoosted: boolean;
    boostReason?: string;
    attributedGroups: Array<{ groupName: string; groupType: string; threatLevel: string }>;
    riskTags: string[];
    killChainPhases: string[];
  }>;
  actorExposure: Array<{
    groupId: string;
    groupName: string;
    groupType: string;
    threatLevel: string;
    findingCount: number;
    exposureScore: number;
    active: boolean;
  }>;
}

interface GateEscalationConfig {
  escalateOnRansomware: boolean;
  escalateOnApt: boolean;
  escalateOnActorCount: number;
  escalateOnExposureScore: number;
}

interface TrendPoint {
  runId: number;
  date: string;
  status: string;
  actorExposureScore: number;
  killChainCoverage: number;
  uniqueActors: number;
  severityBoosted: number;
  ransomwareRisk: number;
  aptRisk: number;
}

// ─── Helper: Simulate gate escalation logic ───────────────────────────────────

function evaluateGateEscalation(
  scanStatus: string,
  threatSummary: ThreatSummary | null,
  config: GateEscalationConfig
): { finalStatus: string; escalationReason: string } {
  let finalStatus = scanStatus;
  let escalationReason = "";

  if (scanStatus === "passed" && threatSummary) {
    const reasons: string[] = [];

    if (config.escalateOnRansomware && threatSummary.ransomwareRiskFindings > 0) {
      reasons.push(`${threatSummary.ransomwareRiskFindings} finding(s) linked to ransomware groups`);
    }
    if (config.escalateOnApt && threatSummary.aptRiskFindings > 0) {
      reasons.push(`${threatSummary.aptRiskFindings} finding(s) linked to APT groups`);
    }
    if (config.escalateOnActorCount > 0 && threatSummary.uniqueActorsMatched >= config.escalateOnActorCount) {
      reasons.push(`${threatSummary.uniqueActorsMatched} threat actors matched (threshold: ${config.escalateOnActorCount})`);
    }
    if (config.escalateOnExposureScore > 0 && threatSummary.actorExposureScore >= config.escalateOnExposureScore) {
      reasons.push(`Actor exposure score ${threatSummary.actorExposureScore} (threshold: ${config.escalateOnExposureScore})`);
    }

    if (reasons.length > 0) {
      finalStatus = "failed";
      escalationReason = `Auto-gate escalation: ${reasons.join("; ")}`;
    }
  }

  return { finalStatus, escalationReason };
}

// ─── Helper: Build trend points from run data ─────────────────────────────────

function buildTrendPoints(
  runs: Array<{ id: number; createdAt: string; status: string; threatContext: ThreatContext | null }>
): TrendPoint[] {
  return runs.map((run) => {
    const tc = run.threatContext;
    return {
      runId: run.id,
      date: run.createdAt,
      status: run.status,
      actorExposureScore: tc?.summary?.actorExposureScore || 0,
      killChainCoverage: tc?.summary?.killChainCoverage || 0,
      uniqueActors: tc?.summary?.uniqueActorsMatched || 0,
      severityBoosted: tc?.summary?.severityBoostedCount || 0,
      ransomwareRisk: tc?.summary?.ransomwareRiskFindings || 0,
      aptRisk: tc?.summary?.aptRiskFindings || 0,
    };
  });
}

// ─── Helper: Simulate auto-import enrichment ──────────────────────────────────

function enrichFindingForImport(
  finding: { title: string; severity: string; description: string; url?: string; scanner?: string; cweId?: string },
  enrichedMap: Map<string, any>,
  runId: number
): {
  title: string;
  severity: string;
  description: string;
  source: string;
  cve: string | null;
  mitreTechnique: string | null;
} {
  const enriched = enrichedMap.get(finding.title);
  const severity = enriched?.severity || finding.severity || "medium";
  const descParts = [finding.description || ""];

  if (enriched?.attributedGroups?.length > 0) {
    descParts.push(`\n--- THREAT INTEL (auto-imported from CI/CD run #${runId}) ---`);
    descParts.push(`Groups: ${enriched.attributedGroups.map((g: any) => g.groupName).join(", ")}`);
    if (enriched.severityBoosted) {
      descParts.push(`Boosted: ${enriched.originalSeverity} → ${enriched.severity}`);
    }
    if (enriched.riskTags?.length) {
      descParts.push(`Risk: ${enriched.riskTags.join(", ")}`);
    }
  }

  const cveMatch = (finding.title + " " + (finding.description || "")).match(/CVE-\d{4}-\d{4,}/i);

  return {
    title: finding.title.substring(0, 512),
    severity,
    description: descParts.join("\n"),
    source: `cicd-auto-run-${runId}`,
    cve: cveMatch ? cveMatch[0].toUpperCase() : null,
    mitreTechnique: enriched?.killChainPhases?.[0] || null,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. THREAT TREND SPARKLINES
// ═══════════════════════════════════════════════════════════════════════════════

describe("Threat Trend Sparklines", () => {
  it("should build trend points from runs with threat context", () => {
    const runs = [
      {
        id: 1,
        createdAt: "2026-04-10T10:00:00Z",
        status: "passed",
        threatContext: {
          summary: {
            uniqueActorsMatched: 3,
            severityBoostedCount: 2,
            actorExposureScore: 45,
            killChainCoverage: 28,
            ransomwareRiskFindings: 1,
            aptRiskFindings: 0,
          },
          enrichedFindings: [],
          actorExposure: [],
        } as ThreatContext,
      },
      {
        id: 2,
        createdAt: "2026-04-12T14:00:00Z",
        status: "failed",
        threatContext: {
          summary: {
            uniqueActorsMatched: 7,
            severityBoostedCount: 5,
            actorExposureScore: 72,
            killChainCoverage: 42,
            ransomwareRiskFindings: 3,
            aptRiskFindings: 2,
          },
          enrichedFindings: [],
          actorExposure: [],
        } as ThreatContext,
      },
    ];

    const points = buildTrendPoints(runs);
    expect(points).toHaveLength(2);
    expect(points[0].actorExposureScore).toBe(45);
    expect(points[0].killChainCoverage).toBe(28);
    expect(points[0].uniqueActors).toBe(3);
    expect(points[1].actorExposureScore).toBe(72);
    expect(points[1].ransomwareRisk).toBe(3);
    expect(points[1].aptRisk).toBe(2);
  });

  it("should handle runs with null threat context", () => {
    const runs = [
      { id: 1, createdAt: "2026-04-10T10:00:00Z", status: "error", threatContext: null },
      { id: 2, createdAt: "2026-04-11T10:00:00Z", status: "passed", threatContext: null },
    ];

    const points = buildTrendPoints(runs);
    expect(points).toHaveLength(2);
    expect(points[0].actorExposureScore).toBe(0);
    expect(points[0].killChainCoverage).toBe(0);
    expect(points[0].uniqueActors).toBe(0);
    expect(points[1].ransomwareRisk).toBe(0);
  });

  it("should preserve run metadata in trend points", () => {
    const runs = [
      {
        id: 42,
        createdAt: "2026-04-15T08:30:00Z",
        status: "failed",
        threatContext: {
          summary: {
            uniqueActorsMatched: 5,
            severityBoostedCount: 3,
            actorExposureScore: 65,
            killChainCoverage: 35,
            ransomwareRiskFindings: 2,
            aptRiskFindings: 1,
          },
          enrichedFindings: [],
          actorExposure: [],
        } as ThreatContext,
      },
    ];

    const points = buildTrendPoints(runs);
    expect(points[0].runId).toBe(42);
    expect(points[0].date).toBe("2026-04-15T08:30:00Z");
    expect(points[0].status).toBe("failed");
  });

  it("should show increasing exposure score trend", () => {
    const runs = Array.from({ length: 5 }, (_, i) => ({
      id: i + 1,
      createdAt: `2026-04-${10 + i}T10:00:00Z`,
      status: "passed",
      threatContext: {
        summary: {
          uniqueActorsMatched: i + 1,
          severityBoostedCount: i,
          actorExposureScore: 20 + i * 15,
          killChainCoverage: 10 + i * 8,
          ransomwareRiskFindings: 0,
          aptRiskFindings: 0,
        },
        enrichedFindings: [],
        actorExposure: [],
      } as ThreatContext,
    }));

    const points = buildTrendPoints(runs);
    expect(points).toHaveLength(5);
    // Verify increasing trend
    for (let i = 1; i < points.length; i++) {
      expect(points[i].actorExposureScore).toBeGreaterThan(points[i - 1].actorExposureScore);
      expect(points[i].killChainCoverage).toBeGreaterThan(points[i - 1].killChainCoverage);
    }
  });

  it("should handle empty runs array", () => {
    const points = buildTrendPoints([]);
    expect(points).toHaveLength(0);
  });

  it("should handle partial threat summary data", () => {
    const runs = [
      {
        id: 1,
        createdAt: "2026-04-10T10:00:00Z",
        status: "passed",
        threatContext: {
          summary: {
            uniqueActorsMatched: 2,
            severityBoostedCount: 0,
            actorExposureScore: 0,
            killChainCoverage: 0,
            ransomwareRiskFindings: 0,
            aptRiskFindings: 0,
          },
          enrichedFindings: [],
          actorExposure: [],
        } as ThreatContext,
      },
    ];

    const points = buildTrendPoints(runs);
    expect(points[0].uniqueActors).toBe(2);
    expect(points[0].severityBoosted).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 2. AUTO-GATE ESCALATION
// ═══════════════════════════════════════════════════════════════════════════════

describe("Auto-Gate Escalation", () => {
  const defaultConfig: GateEscalationConfig = {
    escalateOnRansomware: true,
    escalateOnApt: true,
    escalateOnActorCount: 3,
    escalateOnExposureScore: 60,
  };

  it("should escalate passed scan with ransomware findings", () => {
    const summary: ThreatSummary = {
      uniqueActorsMatched: 1,
      severityBoostedCount: 1,
      actorExposureScore: 30,
      killChainCoverage: 14,
      ransomwareRiskFindings: 2,
      aptRiskFindings: 0,
    };

    const result = evaluateGateEscalation("passed", summary, defaultConfig);
    expect(result.finalStatus).toBe("failed");
    expect(result.escalationReason).toContain("ransomware groups");
    expect(result.escalationReason).toContain("2 finding(s)");
  });

  it("should escalate passed scan with APT findings", () => {
    const summary: ThreatSummary = {
      uniqueActorsMatched: 1,
      severityBoostedCount: 1,
      actorExposureScore: 25,
      killChainCoverage: 14,
      ransomwareRiskFindings: 0,
      aptRiskFindings: 3,
    };

    const result = evaluateGateEscalation("passed", summary, defaultConfig);
    expect(result.finalStatus).toBe("failed");
    expect(result.escalationReason).toContain("APT groups");
    expect(result.escalationReason).toContain("3 finding(s)");
  });

  it("should escalate when actor count exceeds threshold", () => {
    const summary: ThreatSummary = {
      uniqueActorsMatched: 5,
      severityBoostedCount: 3,
      actorExposureScore: 40,
      killChainCoverage: 28,
      ransomwareRiskFindings: 0,
      aptRiskFindings: 0,
    };

    const result = evaluateGateEscalation("passed", summary, defaultConfig);
    expect(result.finalStatus).toBe("failed");
    expect(result.escalationReason).toContain("5 threat actors matched");
    expect(result.escalationReason).toContain("threshold: 3");
  });

  it("should escalate when exposure score exceeds threshold", () => {
    const summary: ThreatSummary = {
      uniqueActorsMatched: 2,
      severityBoostedCount: 2,
      actorExposureScore: 75,
      killChainCoverage: 35,
      ransomwareRiskFindings: 0,
      aptRiskFindings: 0,
    };

    const result = evaluateGateEscalation("passed", summary, defaultConfig);
    expect(result.finalStatus).toBe("failed");
    expect(result.escalationReason).toContain("Actor exposure score 75");
    expect(result.escalationReason).toContain("threshold: 60");
  });

  it("should combine multiple escalation reasons", () => {
    const summary: ThreatSummary = {
      uniqueActorsMatched: 8,
      severityBoostedCount: 6,
      actorExposureScore: 85,
      killChainCoverage: 50,
      ransomwareRiskFindings: 4,
      aptRiskFindings: 3,
    };

    const result = evaluateGateEscalation("passed", summary, defaultConfig);
    expect(result.finalStatus).toBe("failed");
    expect(result.escalationReason).toContain("ransomware");
    expect(result.escalationReason).toContain("APT");
    expect(result.escalationReason).toContain("threat actors matched");
    expect(result.escalationReason).toContain("exposure score");
  });

  it("should NOT escalate when all values are below thresholds", () => {
    const summary: ThreatSummary = {
      uniqueActorsMatched: 1,
      severityBoostedCount: 0,
      actorExposureScore: 20,
      killChainCoverage: 7,
      ransomwareRiskFindings: 0,
      aptRiskFindings: 0,
    };

    const result = evaluateGateEscalation("passed", summary, defaultConfig);
    expect(result.finalStatus).toBe("passed");
    expect(result.escalationReason).toBe("");
  });

  it("should NOT escalate already-failed scans", () => {
    const summary: ThreatSummary = {
      uniqueActorsMatched: 10,
      severityBoostedCount: 8,
      actorExposureScore: 95,
      killChainCoverage: 60,
      ransomwareRiskFindings: 5,
      aptRiskFindings: 4,
    };

    const result = evaluateGateEscalation("failed", summary, defaultConfig);
    expect(result.finalStatus).toBe("failed");
    expect(result.escalationReason).toBe(""); // No escalation needed
  });

  it("should NOT escalate error scans", () => {
    const summary: ThreatSummary = {
      uniqueActorsMatched: 10,
      severityBoostedCount: 8,
      actorExposureScore: 95,
      killChainCoverage: 60,
      ransomwareRiskFindings: 5,
      aptRiskFindings: 4,
    };

    const result = evaluateGateEscalation("error", summary, defaultConfig);
    expect(result.finalStatus).toBe("error");
    expect(result.escalationReason).toBe("");
  });

  it("should respect disabled ransomware escalation", () => {
    const config: GateEscalationConfig = {
      ...defaultConfig,
      escalateOnRansomware: false,
    };

    const summary: ThreatSummary = {
      uniqueActorsMatched: 1,
      severityBoostedCount: 1,
      actorExposureScore: 20,
      killChainCoverage: 7,
      ransomwareRiskFindings: 5,
      aptRiskFindings: 0,
    };

    const result = evaluateGateEscalation("passed", summary, config);
    expect(result.finalStatus).toBe("passed");
    expect(result.escalationReason).toBe("");
  });

  it("should respect disabled APT escalation", () => {
    const config: GateEscalationConfig = {
      ...defaultConfig,
      escalateOnApt: false,
    };

    const summary: ThreatSummary = {
      uniqueActorsMatched: 1,
      severityBoostedCount: 1,
      actorExposureScore: 20,
      killChainCoverage: 7,
      ransomwareRiskFindings: 0,
      aptRiskFindings: 5,
    };

    const result = evaluateGateEscalation("passed", summary, config);
    expect(result.finalStatus).toBe("passed");
    expect(result.escalationReason).toBe("");
  });

  it("should handle zero thresholds as disabled", () => {
    const config: GateEscalationConfig = {
      escalateOnRansomware: false,
      escalateOnApt: false,
      escalateOnActorCount: 0,
      escalateOnExposureScore: 0,
    };

    const summary: ThreatSummary = {
      uniqueActorsMatched: 10,
      severityBoostedCount: 8,
      actorExposureScore: 95,
      killChainCoverage: 60,
      ransomwareRiskFindings: 5,
      aptRiskFindings: 4,
    };

    const result = evaluateGateEscalation("passed", summary, config);
    expect(result.finalStatus).toBe("passed");
    expect(result.escalationReason).toBe("");
  });

  it("should handle null threat summary gracefully", () => {
    const result = evaluateGateEscalation("passed", null, defaultConfig);
    expect(result.finalStatus).toBe("passed");
    expect(result.escalationReason).toBe("");
  });

  it("should escalate at exact threshold boundary", () => {
    const summary: ThreatSummary = {
      uniqueActorsMatched: 3,
      severityBoostedCount: 0,
      actorExposureScore: 60,
      killChainCoverage: 0,
      ransomwareRiskFindings: 0,
      aptRiskFindings: 0,
    };

    const result = evaluateGateEscalation("passed", summary, defaultConfig);
    expect(result.finalStatus).toBe("failed");
    // Both actor count and exposure score should trigger
    expect(result.escalationReason).toContain("threat actors matched");
    expect(result.escalationReason).toContain("exposure score");
  });

  it("should NOT escalate just below threshold boundary", () => {
    const summary: ThreatSummary = {
      uniqueActorsMatched: 2,
      severityBoostedCount: 0,
      actorExposureScore: 59,
      killChainCoverage: 0,
      ransomwareRiskFindings: 0,
      aptRiskFindings: 0,
    };

    const result = evaluateGateEscalation("passed", summary, defaultConfig);
    expect(result.finalStatus).toBe("passed");
    expect(result.escalationReason).toBe("");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 3. ENGAGEMENT AUTO-IMPORT
// ═══════════════════════════════════════════════════════════════════════════════

describe("Engagement Auto-Import", () => {
  it("should enrich finding with threat intel context", () => {
    const finding = {
      title: "Apache Log4j RCE (CVE-2021-44228) detected",
      severity: "high",
      description: "Remote code execution via JNDI injection",
      url: "https://target.com/api",
      scanner: "nuclei",
    };

    const enrichedMap = new Map<string, any>();
    enrichedMap.set(finding.title, {
      severity: "critical",
      originalSeverity: "high",
      severityBoosted: true,
      boostReason: "Exploited by 5+ threat groups",
      attributedGroups: [
        { groupName: "APT41", groupType: "apt", threatLevel: "critical" },
        { groupName: "Lazarus Group", groupType: "apt", threatLevel: "critical" },
      ],
      riskTags: ["ransomware_risk", "apt_risk"],
      killChainPhases: ["Initial Access", "Execution"],
    });

    const result = enrichFindingForImport(finding, enrichedMap, 42);

    expect(result.severity).toBe("critical");
    expect(result.source).toBe("cicd-auto-run-42");
    expect(result.cve).toBe("CVE-2021-44228");
    expect(result.mitreTechnique).toBe("Initial Access");
    expect(result.description).toContain("THREAT INTEL");
    expect(result.description).toContain("APT41");
    expect(result.description).toContain("Lazarus Group");
    expect(result.description).toContain("Boosted: high → critical");
    expect(result.description).toContain("ransomware_risk");
  });

  it("should handle finding without threat enrichment", () => {
    const finding = {
      title: "Missing X-Frame-Options header",
      severity: "low",
      description: "The X-Frame-Options header is not set",
      url: "https://target.com",
      scanner: "config-audit",
    };

    const enrichedMap = new Map<string, any>();
    const result = enrichFindingForImport(finding, enrichedMap, 10);

    expect(result.severity).toBe("low");
    expect(result.source).toBe("cicd-auto-run-10");
    expect(result.cve).toBeNull();
    expect(result.mitreTechnique).toBeNull();
    expect(result.description).not.toContain("THREAT INTEL");
  });

  it("should extract CVE from description when not in title", () => {
    const finding = {
      title: "Critical vulnerability detected",
      severity: "critical",
      description: "This server is affected by CVE-2024-1234 which allows remote code execution",
    };

    const enrichedMap = new Map<string, any>();
    const result = enrichFindingForImport(finding, enrichedMap, 5);

    expect(result.cve).toBe("CVE-2024-1234");
  });

  it("should truncate long titles to 512 characters", () => {
    const finding = {
      title: "A".repeat(600),
      severity: "medium",
      description: "Test",
    };

    const enrichedMap = new Map<string, any>();
    const result = enrichFindingForImport(finding, enrichedMap, 1);

    expect(result.title.length).toBe(512);
  });

  it("should use enriched severity over original", () => {
    const finding = {
      title: "SQL Injection",
      severity: "medium",
      description: "SQL injection found",
    };

    const enrichedMap = new Map<string, any>();
    enrichedMap.set("SQL Injection", {
      severity: "critical",
      originalSeverity: "medium",
      severityBoosted: true,
      boostReason: "Exploited by APT28",
      attributedGroups: [{ groupName: "APT28", groupType: "apt", threatLevel: "critical" }],
      riskTags: ["apt_risk"],
      killChainPhases: ["Initial Access"],
    });

    const result = enrichFindingForImport(finding, enrichedMap, 7);
    expect(result.severity).toBe("critical");
  });

  it("should include risk tags in description", () => {
    const finding = {
      title: "Exposed Admin Panel",
      severity: "high",
      description: "Admin panel accessible without authentication",
    };

    const enrichedMap = new Map<string, any>();
    enrichedMap.set("Exposed Admin Panel", {
      severity: "high",
      attributedGroups: [{ groupName: "FIN7", groupType: "cybercrime", threatLevel: "high" }],
      riskTags: ["ransomware_risk", "active_exploitation"],
      killChainPhases: ["Initial Access"],
    });

    const result = enrichFindingForImport(finding, enrichedMap, 15);
    expect(result.description).toContain("ransomware_risk");
    expect(result.description).toContain("active_exploitation");
    expect(result.description).toContain("FIN7");
  });

  it("should handle finding with empty description", () => {
    const finding = {
      title: "Test finding",
      severity: "info",
      description: "",
    };

    const enrichedMap = new Map<string, any>();
    const result = enrichFindingForImport(finding, enrichedMap, 1);
    expect(result.description).toBe("");
    expect(result.severity).toBe("info");
  });

  it("should handle multiple groups in enrichment", () => {
    const finding = {
      title: "ProxyShell RCE (CVE-2021-34473)",
      severity: "critical",
      description: "Microsoft Exchange ProxyShell vulnerability",
    };

    const enrichedMap = new Map<string, any>();
    enrichedMap.set(finding.title, {
      severity: "critical",
      attributedGroups: [
        { groupName: "APT33", groupType: "apt", threatLevel: "critical" },
        { groupName: "Conti", groupType: "ransomware", threatLevel: "critical" },
        { groupName: "LockBit", groupType: "ransomware", threatLevel: "critical" },
      ],
      riskTags: ["ransomware_risk", "apt_risk", "active_exploitation"],
      killChainPhases: ["Initial Access", "Privilege Escalation"],
    });

    const result = enrichFindingForImport(finding, enrichedMap, 20);
    expect(result.description).toContain("APT33");
    expect(result.description).toContain("Conti");
    expect(result.description).toContain("LockBit");
    expect(result.cve).toBe("CVE-2021-34473");
    expect(result.mitreTechnique).toBe("Initial Access");
  });

  it("should handle enrichment without severity boost", () => {
    const finding = {
      title: "Open redirect",
      severity: "medium",
      description: "Open redirect vulnerability found",
    };

    const enrichedMap = new Map<string, any>();
    enrichedMap.set("Open redirect", {
      severity: "medium",
      severityBoosted: false,
      attributedGroups: [{ groupName: "APT29", groupType: "apt", threatLevel: "high" }],
      riskTags: [],
      killChainPhases: ["Initial Access"],
    });

    const result = enrichFindingForImport(finding, enrichedMap, 3);
    expect(result.description).toContain("APT29");
    expect(result.description).not.toContain("Boosted:");
  });

  it("should correctly format source with run ID", () => {
    const finding = {
      title: "Test",
      severity: "low",
      description: "Test",
    };

    const enrichedMap = new Map<string, any>();
    const result = enrichFindingForImport(finding, enrichedMap, 999);
    expect(result.source).toBe("cicd-auto-run-999");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 4. GATE ESCALATION CONFIG VALIDATION
// ═══════════════════════════════════════════════════════════════════════════════

describe("Gate Escalation Config Validation", () => {
  it("should accept valid config with all fields", () => {
    const config: GateEscalationConfig = {
      escalateOnRansomware: true,
      escalateOnApt: true,
      escalateOnActorCount: 5,
      escalateOnExposureScore: 70,
    };

    expect(config.escalateOnRansomware).toBe(true);
    expect(config.escalateOnApt).toBe(true);
    expect(config.escalateOnActorCount).toBe(5);
    expect(config.escalateOnExposureScore).toBe(70);
  });

  it("should serialize config to JSON for storage", () => {
    const config: GateEscalationConfig = {
      escalateOnRansomware: true,
      escalateOnApt: false,
      escalateOnActorCount: 3,
      escalateOnExposureScore: 60,
    };

    const json = JSON.stringify(config);
    const parsed = JSON.parse(json);
    expect(parsed.escalateOnRansomware).toBe(true);
    expect(parsed.escalateOnApt).toBe(false);
    expect(parsed.escalateOnActorCount).toBe(3);
    expect(parsed.escalateOnExposureScore).toBe(60);
  });

  it("should provide sensible defaults when no config exists", () => {
    const defaults: GateEscalationConfig = {
      escalateOnRansomware: true,
      escalateOnApt: true,
      escalateOnActorCount: 3,
      escalateOnExposureScore: 60,
    };

    // Verify defaults are reasonable
    expect(defaults.escalateOnRansomware).toBe(true);
    expect(defaults.escalateOnApt).toBe(true);
    expect(defaults.escalateOnActorCount).toBeGreaterThan(0);
    expect(defaults.escalateOnActorCount).toBeLessThanOrEqual(10);
    expect(defaults.escalateOnExposureScore).toBeGreaterThan(0);
    expect(defaults.escalateOnExposureScore).toBeLessThanOrEqual(100);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 5. NOTIFICATION ENRICHMENT WITH ESCALATION
// ═══════════════════════════════════════════════════════════════════════════════

describe("Notification Enrichment with Escalation", () => {
  it("should include THREAT ESCALATED in notification title when escalated", () => {
    const gateEscalationReason = "Auto-gate escalation: 3 finding(s) linked to ransomware groups";
    const pipelineName = "staging-pipeline";
    const finalStatus = "failed";

    const title = `CI/CD Gate ${finalStatus === "error" ? "Error" : "Failed"}${gateEscalationReason ? " (THREAT ESCALATED)" : ""}: ${pipelineName}`;
    expect(title).toContain("THREAT ESCALATED");
    expect(title).toContain("staging-pipeline");
    expect(title).toContain("Failed");
  });

  it("should NOT include THREAT ESCALATED when not escalated", () => {
    const gateEscalationReason = "";
    const pipelineName = "prod-pipeline";
    const finalStatus = "failed";

    const title = `CI/CD Gate ${finalStatus === "error" ? "Error" : "Failed"}${gateEscalationReason ? " (THREAT ESCALATED)" : ""}: ${pipelineName}`;
    expect(title).not.toContain("THREAT ESCALATED");
    expect(title).toContain("prod-pipeline");
  });

  it("should include escalation reason in notification body", () => {
    const gateEscalationReason = "Auto-gate escalation: 5 threat actors matched (threshold: 3); Actor exposure score 85 (threshold: 60)";

    const bodyLines = [
      `Status: FAILED — THREAT-ESCALATED`,
      gateEscalationReason ? `\n${gateEscalationReason}` : null,
      `Target: https://staging.app.com`,
    ].filter(Boolean);

    const body = bodyLines.join("\n");
    expect(body).toContain("THREAT-ESCALATED");
    expect(body).toContain("5 threat actors matched");
    expect(body).toContain("exposure score 85");
  });
});
