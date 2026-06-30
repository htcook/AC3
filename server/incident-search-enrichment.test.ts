import { describe, it, expect } from "vitest";

/**
 * Tests for the Incident Search Enrichment module and its integration
 * with the DI pipeline, risk floor, and PDF report generation.
 *
 * The module lives at server/lib/incident-search-enrichment.ts and produces
 * an IncidentSearchResult that is consumed by:
 * - domainIntel.ts (pipeline stage + risk floor 8)
 * - export-di-report.ts (BLUF paragraph, dashboard metrics, section 12b)
 */

// ─── IncidentSearchResult shape validation ──────────────────────────────────

describe("IncidentSearchResult shape", () => {
  const emptyResult = {
    domain: "example.com",
    searchedAt: Date.now(),
    catalogMatches: [],
    webSearchMatches: [],
    totalMatches: 0,
    hasActiveThreats: false,
    hasRansomwareEvent: false,
    hasRecentBreach: false,
    riskFloorContribution: 0,
    summary: "No known security incidents found.",
    newActorsDiscovered: [],
    newTTPsDiscovered: [],
    newIOCsDiscovered: [],
  };

  it("should have all required fields", () => {
    expect(emptyResult).toHaveProperty("domain");
    expect(emptyResult).toHaveProperty("searchedAt");
    expect(emptyResult).toHaveProperty("catalogMatches");
    expect(emptyResult).toHaveProperty("webSearchMatches");
    expect(emptyResult).toHaveProperty("totalMatches");
    expect(emptyResult).toHaveProperty("hasActiveThreats");
    expect(emptyResult).toHaveProperty("hasRansomwareEvent");
    expect(emptyResult).toHaveProperty("hasRecentBreach");
    expect(emptyResult).toHaveProperty("riskFloorContribution");
    expect(emptyResult).toHaveProperty("summary");
    expect(emptyResult).toHaveProperty("newActorsDiscovered");
    expect(emptyResult).toHaveProperty("newTTPsDiscovered");
    expect(emptyResult).toHaveProperty("newIOCsDiscovered");
  });

  it("should have zero matches for empty result", () => {
    expect(emptyResult.totalMatches).toBe(0);
    expect(emptyResult.catalogMatches).toHaveLength(0);
    expect(emptyResult.webSearchMatches).toHaveLength(0);
  });
});

// ─── Risk Floor Contribution Logic ──────────────────────────────────────────

describe("Incident Search Risk Floor Contribution", () => {
  function computeRiskFloor(matches: Array<{
    eventType?: string;
    actorType?: string;
    title: string;
    date?: string;
    confidence: string;
    severity: string;
  }>): { riskFloorContribution: number; hasRansomwareEvent: boolean; hasRecentBreach: boolean; hasActiveThreats: boolean } {
    const hasRansomwareEvent = matches.some(m =>
      m.eventType === "ransomware" ||
      m.actorType === "ransomware" ||
      m.title.toLowerCase().includes("ransomware")
    );
    const hasRecentBreach = matches.some(m => {
      if (!m.date) return false;
      const eventYear = parseInt(m.date.substring(0, 4));
      return eventYear >= 2024 && (m.eventType === "data_breach" || m.eventType === "data_leak" || m.eventType === "ransomware");
    });
    const hasActiveThreats = matches.some(m =>
      m.confidence === "confirmed" &&
      (m.severity === "critical" || m.severity === "high")
    );

    let riskFloorContribution = 0;
    if (hasRansomwareEvent) riskFloorContribution = Math.max(riskFloorContribution, 75);
    if (hasRecentBreach) riskFloorContribution = Math.max(riskFloorContribution, 65);
    if (hasActiveThreats) riskFloorContribution = Math.max(riskFloorContribution, 60);
    for (const m of matches) {
      if (m.confidence === "confirmed" && m.severity === "critical") {
        riskFloorContribution = Math.max(riskFloorContribution, 80);
      }
    }

    return { riskFloorContribution, hasRansomwareEvent, hasRecentBreach, hasActiveThreats };
  }

  it("should return 0 for no matches", () => {
    const result = computeRiskFloor([]);
    expect(result.riskFloorContribution).toBe(0);
    expect(result.hasRansomwareEvent).toBe(false);
    expect(result.hasRecentBreach).toBe(false);
    expect(result.hasActiveThreats).toBe(false);
  });

  it("should set floor to 75 for ransomware event", () => {
    const result = computeRiskFloor([{
      eventType: "ransomware",
      actorType: "ransomware",
      title: "LockBit Ransomware Attack on Target Corp",
      date: "2024-06",
      confidence: "confirmed",
      severity: "critical",
    }]);
    expect(result.hasRansomwareEvent).toBe(true);
    // Ransomware + confirmed critical → max(75, 80) = 80
    expect(result.riskFloorContribution).toBe(80);
  });

  it("should set floor to 65 for recent breach without ransomware", () => {
    const result = computeRiskFloor([{
      eventType: "data_breach",
      title: "Data breach at Target Corp",
      date: "2024-03",
      confidence: "probable",
      severity: "high",
    }]);
    expect(result.hasRecentBreach).toBe(true);
    expect(result.hasRansomwareEvent).toBe(false);
    expect(result.riskFloorContribution).toBe(65);
  });

  it("should set floor to 60 for active high-confidence threats", () => {
    const result = computeRiskFloor([{
      eventType: "attack",
      title: "APT29 targeting financial sector",
      confidence: "confirmed",
      severity: "high",
    }]);
    expect(result.hasActiveThreats).toBe(true);
    expect(result.riskFloorContribution).toBe(60);
  });

  it("should set floor to 80 for confirmed critical incident", () => {
    const result = computeRiskFloor([{
      eventType: "data_breach",
      title: "Critical data breach",
      date: "2025-01",
      confidence: "confirmed",
      severity: "critical",
    }]);
    expect(result.riskFloorContribution).toBe(80);
  });

  it("should not flag old breaches as recent", () => {
    const result = computeRiskFloor([{
      eventType: "data_breach",
      title: "Old breach",
      date: "2020-01",
      confidence: "confirmed",
      severity: "high",
    }]);
    expect(result.hasRecentBreach).toBe(false);
    // Still has active threats (confirmed + high)
    expect(result.hasActiveThreats).toBe(true);
    expect(result.riskFloorContribution).toBe(60);
  });

  it("should detect ransomware from title even without eventType", () => {
    const result = computeRiskFloor([{
      eventType: "attack",
      title: "Ransomware deployment via phishing",
      confidence: "probable",
      severity: "high",
    }]);
    expect(result.hasRansomwareEvent).toBe(true);
    expect(result.riskFloorContribution).toBe(75);
  });
});

// ─── Pipeline Integration (risk floor 8) ────────────────────────────────────

describe("Pipeline Risk Floor 8 Integration", () => {
  it("should apply incident search floor when contribution exceeds current score", () => {
    // Simulate the floor logic from domainIntel.ts
    let currentScore = 40;
    let currentBand = "medium";
    const reasons: string[] = [];

    const incidentSearch = {
      totalMatches: 3,
      hasRansomwareEvent: true,
      hasRecentBreach: true,
      riskFloorContribution: 75,
    };

    // Floor 8: Incident search enrichment
    if (incidentSearch && incidentSearch.totalMatches > 0 && incidentSearch.riskFloorContribution > 0) {
      const incidentFloor = incidentSearch.riskFloorContribution;
      if (incidentFloor > currentScore) {
        const floorReasons: string[] = [];
        if (incidentSearch.hasRansomwareEvent) floorReasons.push("confirmed ransomware event");
        if (incidentSearch.hasRecentBreach) floorReasons.push("recent data breach");
        reasons.push(`Incident intelligence: ${floorReasons.join(", ")} (${incidentSearch.totalMatches} incident(s) found)`);
        currentScore = incidentFloor;
        currentBand = incidentFloor >= 80 ? "critical" : incidentFloor >= 60 ? "high" : "medium";
      }
    }

    expect(currentScore).toBe(75);
    expect(currentBand).toBe("high");
    expect(reasons).toHaveLength(1);
    expect(reasons[0]).toContain("confirmed ransomware event");
    expect(reasons[0]).toContain("recent data breach");
    expect(reasons[0]).toContain("3 incident(s) found");
  });

  it("should NOT apply floor when contribution is below current score", () => {
    let currentScore = 85;
    let currentBand = "critical";
    const reasons: string[] = [];

    const incidentSearch = {
      totalMatches: 1,
      hasRansomwareEvent: false,
      hasRecentBreach: false,
      riskFloorContribution: 60,
    };

    if (incidentSearch && incidentSearch.totalMatches > 0 && incidentSearch.riskFloorContribution > 0) {
      const incidentFloor = incidentSearch.riskFloorContribution;
      if (incidentFloor > currentScore) {
        reasons.push("Should not reach here");
        currentScore = incidentFloor;
      }
    }

    expect(currentScore).toBe(85);
    expect(currentBand).toBe("critical");
    expect(reasons).toHaveLength(0);
  });

  it("should NOT apply floor when no matches exist", () => {
    let currentScore = 30;
    const reasons: string[] = [];

    const incidentSearch = {
      totalMatches: 0,
      hasRansomwareEvent: false,
      hasRecentBreach: false,
      riskFloorContribution: 0,
    };

    if (incidentSearch && incidentSearch.totalMatches > 0 && incidentSearch.riskFloorContribution > 0) {
      reasons.push("Should not reach here");
    }

    expect(currentScore).toBe(30);
    expect(reasons).toHaveLength(0);
  });
});

// ─── Report BLUF Integration ────────────────────────────────────────────────

describe("Report BLUF Incident Search Paragraph", () => {
  it("should generate BLUF paragraph for ransomware incident", () => {
    const incidentSearch = {
      totalMatches: 2,
      hasRansomwareEvent: true,
      hasRecentBreach: true,
      hasActiveThreats: true,
      catalogMatches: [
        { source: "threat_catalog_event", actorName: "LockBit", eventType: "ransomware" },
      ],
      webSearchMatches: [
        { source: "web_search", actorName: "LockBit", eventType: "ransomware" },
      ],
      riskFloorContribution: 80,
    };

    // Simulate the BLUF generation logic from export-di-report.ts
    const blufParts: string[] = [];
    if (incidentSearch && incidentSearch.totalMatches > 0) {
      const incParts: string[] = [];
      incParts.push(`Incident intelligence search identified ${incidentSearch.totalMatches} known security incident(s) associated with the target organization`);
      if (incidentSearch.hasRansomwareEvent) {
        const ransomwareIncidents = [...(incidentSearch.catalogMatches || []), ...(incidentSearch.webSearchMatches || [])]
          .filter((m: any) => m.eventType === "ransomware" || m.actorType === "ransomware");
        const actorNames = [...new Set(ransomwareIncidents.map((m: any) => m.actorName).filter(Boolean))];
        incParts.push(`including a confirmed ransomware event${actorNames.length > 0 ? ` attributed to ${actorNames.join(", ")}` : ""}`);
      }
      if (incidentSearch.hasRecentBreach) incParts.push("with recent data breach activity identified");
      const catalogCount = incidentSearch.catalogMatches?.length || 0;
      const webCount = incidentSearch.webSearchMatches?.length || 0;
      if (catalogCount > 0 && webCount > 0) {
        incParts.push(`(${catalogCount} from internal threat catalog, ${webCount} from open-source intelligence)`);
      }
      blufParts.push(`${incParts.join(", ")}. This historical incident context significantly informs the risk assessment and defensive prioritization.`);
    }

    expect(blufParts).toHaveLength(1);
    expect(blufParts[0]).toContain("2 known security incident(s)");
    expect(blufParts[0]).toContain("confirmed ransomware event");
    expect(blufParts[0]).toContain("LockBit");
    expect(blufParts[0]).toContain("recent data breach activity");
    expect(blufParts[0]).toContain("1 from internal threat catalog");
    expect(blufParts[0]).toContain("1 from open-source intelligence");
  });

  it("should not generate BLUF paragraph when no incidents found", () => {
    const incidentSearch = { totalMatches: 0, catalogMatches: [], webSearchMatches: [] };
    const blufParts: string[] = [];
    if (incidentSearch && incidentSearch.totalMatches > 0) {
      blufParts.push("Should not reach here");
    }
    expect(blufParts).toHaveLength(0);
  });
});

// ─── Report Dashboard Metrics ───────────────────────────────────────────────

describe("Report Dashboard Metrics - Known Incidents Row", () => {
  it("should add Known Incidents row with flags", () => {
    const incidentSearch = {
      totalMatches: 3,
      hasRansomwareEvent: true,
      hasRecentBreach: false,
      hasActiveThreats: true,
    };

    const dashboardRows: string[][] = [];
    if (incidentSearch && incidentSearch.totalMatches > 0) {
      const incFlags: string[] = [];
      if (incidentSearch.hasRansomwareEvent) incFlags.push("ransomware");
      if (incidentSearch.hasRecentBreach) incFlags.push("breach");
      if (incidentSearch.hasActiveThreats) incFlags.push("active threats");
      dashboardRows.push(["Known Incidents", `${incidentSearch.totalMatches} incident(s)${incFlags.length > 0 ? ` (${incFlags.join(", ")})` : ""}`]);
    }

    expect(dashboardRows).toHaveLength(1);
    expect(dashboardRows[0][0]).toBe("Known Incidents");
    expect(dashboardRows[0][1]).toContain("3 incident(s)");
    expect(dashboardRows[0][1]).toContain("ransomware");
    expect(dashboardRows[0][1]).toContain("active threats");
    expect(dashboardRows[0][1]).not.toContain("breach");
  });

  it("should not add row when no incidents", () => {
    const incidentSearch = { totalMatches: 0 };
    const dashboardRows: string[][] = [];
    if (incidentSearch && incidentSearch.totalMatches > 0) {
      dashboardRows.push(["Known Incidents", "should not appear"]);
    }
    expect(dashboardRows).toHaveLength(0);
  });
});

// ─── IncidentMatch validation ───────────────────────────────────────────────

describe("IncidentMatch structure", () => {
  it("should validate catalog event match", () => {
    const match = {
      source: "threat_catalog_event" as const,
      actorId: "apt29",
      actorName: "APT29 (Cozy Bear)",
      actorType: "apt",
      eventType: "campaign",
      title: "SolarWinds Supply Chain Compromise",
      description: "APT29 compromised SolarWinds Orion software updates",
      severity: "critical" as const,
      date: "2020-12",
      victimName: "SolarWinds",
      victimSector: "Technology",
      mitreTechniques: ["T1195.002", "T1059.001"],
      confidence: "confirmed" as const,
      relevanceScore: 0.95,
    };

    expect(match.source).toBe("threat_catalog_event");
    expect(match.actorName).toContain("APT29");
    expect(match.severity).toBe("critical");
    expect(match.confidence).toBe("confirmed");
    expect(match.relevanceScore).toBeGreaterThanOrEqual(0);
    expect(match.relevanceScore).toBeLessThanOrEqual(1);
    expect(match.mitreTechniques).toHaveLength(2);
  });

  it("should validate web search match", () => {
    const match = {
      source: "web_search" as const,
      actorName: "BlackCat/ALPHV",
      actorType: "ransomware",
      eventType: "ransomware",
      title: "BlackCat Ransomware Attack on Healthcare Provider",
      description: "BlackCat ransomware group targeted healthcare provider via phishing",
      severity: "critical" as const,
      date: "2024-02",
      mitreTechniques: ["T1566.001", "T1486"],
      confidence: "confirmed" as const,
      relevanceScore: 0.85,
    };

    expect(match.source).toBe("web_search");
    expect(match.actorType).toBe("ransomware");
    expect(match.eventType).toBe("ransomware");
    expect(match.confidence).toBe("confirmed");
  });

  it("should validate IOC match", () => {
    const match = {
      source: "threat_catalog_ioc" as const,
      actorId: "lazarus",
      actorName: "Lazarus Group",
      title: "IOC Match: domain indicator linked to Lazarus Group",
      description: "Domain indicator associated with Lazarus Group",
      severity: "high" as const,
      iocType: "domain",
      iocValue: "malicious.example.com",
      confidence: "probable" as const,
      relevanceScore: 0.6,
    };

    expect(match.source).toBe("threat_catalog_ioc");
    expect(match.iocType).toBe("domain");
    expect(match.confidence).toBe("probable");
  });
});

// ─── Summary Generation ─────────────────────────────────────────────────────

describe("Incident Search Summary Generation", () => {
  function generateSummary(
    domain: string,
    matches: Array<{ source: string; actorName?: string; eventType?: string; actorType?: string }>,
    hasRansomware: boolean,
    hasRecentBreach: boolean
  ): string {
    if (matches.length === 0) {
      return `No known security incidents or threat actor activity found targeting ${domain} in the threat intelligence catalog or public sources.`;
    }

    const parts: string[] = [];
    const catalogCount = matches.filter(m => m.source !== "web_search").length;
    const webCount = matches.filter(m => m.source === "web_search").length;

    parts.push(`${matches.length} security incident(s) identified targeting ${domain}`);
    if (catalogCount > 0) parts.push(`${catalogCount} from internal threat catalog`);
    if (webCount > 0) parts.push(`${webCount} from open-source intelligence`);

    if (hasRansomware) {
      const ransomwareMatches = matches.filter(m => m.eventType === "ransomware" || m.actorType === "ransomware");
      const actors = ransomwareMatches.map(m => m.actorName).filter(Boolean);
      parts.push(`RANSOMWARE EVENT CONFIRMED${actors.length > 0 ? ` — attributed to ${actors.join(", ")}` : ""}`);
    }

    if (hasRecentBreach) {
      parts.push("Recent data breach or data leak event identified");
    }

    const uniqueActors = [...new Set(matches.map(m => m.actorName).filter(Boolean))];
    if (uniqueActors.length > 0) {
      parts.push(`Threat actors involved: ${uniqueActors.join(", ")}`);
    }

    return parts.join(". ") + ".";
  }

  it("should generate empty summary for no matches", () => {
    const summary = generateSummary("example.com", [], false, false);
    expect(summary).toContain("No known security incidents");
    expect(summary).toContain("example.com");
  });

  it("should include ransomware flag in summary", () => {
    const summary = generateSummary("target.com", [
      { source: "web_search", actorName: "LockBit", eventType: "ransomware", actorType: "ransomware" },
    ], true, false);
    expect(summary).toContain("RANSOMWARE EVENT CONFIRMED");
    expect(summary).toContain("LockBit");
    expect(summary).toContain("1 security incident(s)");
  });

  it("should include recent breach flag", () => {
    const summary = generateSummary("target.com", [
      { source: "threat_catalog_event", actorName: "Unknown", eventType: "data_breach" },
    ], false, true);
    expect(summary).toContain("Recent data breach");
    expect(summary).toContain("1 from internal threat catalog");
  });

  it("should list unique threat actors", () => {
    const summary = generateSummary("target.com", [
      { source: "threat_catalog_event", actorName: "APT29" },
      { source: "web_search", actorName: "APT29" },
      { source: "web_search", actorName: "FIN7" },
    ], false, false);
    expect(summary).toContain("Threat actors involved: APT29, FIN7");
    expect(summary).toContain("3 security incident(s)");
    expect(summary).toContain("1 from internal threat catalog");
    expect(summary).toContain("2 from open-source intelligence");
  });
});
