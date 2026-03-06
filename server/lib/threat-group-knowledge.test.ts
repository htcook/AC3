/**
 * Tests for Threat Group Knowledge Module + OWASP Coverage Tracker
 */
import { describe, it, expect } from "vitest";

// ─── Threat Group Knowledge Tests ───────────────────────────────────────

import {
  getAllGroups,
  getGroupById,
  getGroupByName,
  getGroupsByType,
  getGroupsBySector,
  getGroupsByTechnique,
  getGroupsByCVE,
  getSectorProfiles,
  getThreatGroupSummary,
  getThreatGroupHuntContext,
  getThreatGroupScanContext,
  getThreatGroupVulnContext,
  getSectorThreatContext,
  type ThreatGroupKnowledge,
  type ThreatGroupType,
} from "./threat-group-knowledge";

describe("Threat Group Knowledge — Data Integrity", () => {
  it("should have at least 15 threat groups total", () => {
    const groups = getAllGroups();
    expect(groups.length).toBeGreaterThanOrEqual(15);
  });

  it("should include APT, ransomware, and cybercrime group types", () => {
    const groups = getAllGroups();
    const types = new Set(groups.map(g => g.type));
    expect(types.has("apt")).toBe(true);
    expect(types.has("ransomware")).toBe(true);
    expect(types.has("cybercrime")).toBe(true);
  });

  it("should have at least 10 APT groups", () => {
    const aptGroups = getGroupsByType("apt");
    expect(aptGroups.length).toBeGreaterThanOrEqual(10);
  });

  it("should have at least 5 ransomware groups", () => {
    const ransomwareGroups = getGroupsByType("ransomware");
    expect(ransomwareGroups.length).toBeGreaterThanOrEqual(5);
  });

  it("every group should have required fields populated", () => {
    const groups = getAllGroups();
    for (const g of groups) {
      expect(g.id).toBeTruthy();
      expect(g.name).toBeTruthy();
      expect(g.type).toBeTruthy();
      expect(g.origin).toBeTruthy();
      expect(g.threatLevel).toBeTruthy();
      expect(g.description.length).toBeGreaterThan(20);
      expect(g.motivation).toBeTruthy();
      expect(g.targetSectors.length).toBeGreaterThan(0);
      expect(g.targetRegions.length).toBeGreaterThan(0);
      expect(g.ttps.length).toBeGreaterThan(0);
      expect(g.tools.length).toBeGreaterThan(0);
      expect(g.initialAccessMethods.length).toBeGreaterThan(0);
      expect(g.defenseRecommendations.length).toBeGreaterThan(0);
    }
  });

  it("every TTP should have a valid MITRE technique ID format", () => {
    const groups = getAllGroups();
    for (const g of groups) {
      for (const ttp of g.ttps) {
        expect(ttp.techniqueId).toMatch(/^T\d{4}(\.\d{3})?$/);
        expect(ttp.techniqueName).toBeTruthy();
        expect(ttp.tactic).toBeTruthy();
        expect(["primary", "secondary", "occasional"]).toContain(ttp.frequency);
      }
    }
  });

  it("every defense recommendation should have valid priority and category", () => {
    const groups = getAllGroups();
    for (const g of groups) {
      for (const rec of g.defenseRecommendations) {
        expect(["critical", "high", "medium"]).toContain(rec.priority);
        expect(["detection", "prevention", "monitoring", "hardening"]).toContain(rec.category);
        expect(rec.recommendation.length).toBeGreaterThan(10);
        expect(rec.mitreTechniques.length).toBeGreaterThan(0);
      }
    }
  });

  it("should have unique group IDs", () => {
    const groups = getAllGroups();
    const ids = groups.map(g => g.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("should have diverse threat group origins", () => {
    const groups = getAllGroups();
    const origins = new Set(groups.map(g => g.origin.split(" ")[0]));
    // Should have at least Russia, China, North Korea, Iran, USA/UK
    expect(origins.size).toBeGreaterThanOrEqual(4);
  });
});

describe("Threat Group Knowledge — Lookup Functions", () => {
  it("getGroupById should return the correct group", () => {
    const apt29 = getGroupById("apt29");
    expect(apt29).toBeDefined();
    expect(apt29!.name).toContain("APT29");
    expect(apt29!.type).toBe("apt");
  });

  it("getGroupById should return undefined for non-existent ID", () => {
    const result = getGroupById("nonexistent_group");
    expect(result).toBeUndefined();
  });

  it("getGroupByName should find by primary name", () => {
    const lockbit = getGroupByName("LockBit");
    expect(lockbit).toBeDefined();
    expect(lockbit!.type).toBe("ransomware");
  });

  it("getGroupByName should find by alias", () => {
    const cozyBear = getGroupByName("Cozy Bear");
    expect(cozyBear).toBeDefined();
    expect(cozyBear!.id).toBe("apt29");
  });

  it("getGroupByName should find by alias (Midnight Blizzard)", () => {
    const mb = getGroupByName("Midnight Blizzard");
    expect(mb).toBeDefined();
    expect(mb!.id).toBe("apt29");
  });

  it("getGroupsByType should filter correctly", () => {
    const ransomware = getGroupsByType("ransomware");
    expect(ransomware.every(g => g.type === "ransomware")).toBe(true);
    expect(ransomware.length).toBeGreaterThan(0);
  });

  it("getGroupsBySector should return groups for known sectors", () => {
    const healthcareGroups = getGroupsBySector("healthcare");
    expect(healthcareGroups.length).toBeGreaterThan(0);
    // LockBit and BlackCat target healthcare
    const names = healthcareGroups.map(g => g.id);
    expect(names).toContain("lockbit");
  });

  it("getGroupsBySector should return empty for unknown sectors", () => {
    const result = getGroupsBySector("underwater_basket_weaving");
    expect(result).toEqual([]);
  });

  it("getGroupsByTechnique should find groups using T1190", () => {
    const groups = getGroupsByTechnique("T1190");
    expect(groups.length).toBeGreaterThan(3); // Many groups exploit public-facing apps
  });

  it("getGroupsByCVE should find groups exploiting Log4j", () => {
    const groups = getGroupsByCVE("CVE-2021-44228");
    expect(groups.length).toBeGreaterThan(0);
  });
});

describe("Threat Group Knowledge — Summary", () => {
  it("should return accurate summary statistics", () => {
    const summary = getThreatGroupSummary();
    expect(summary.totalGroups).toBeGreaterThanOrEqual(15);
    expect(summary.byType.apt).toBeGreaterThanOrEqual(10);
    expect(summary.byType.ransomware).toBeGreaterThanOrEqual(5);
    expect(summary.totalTTPs).toBeGreaterThan(50);
    expect(summary.totalCVEs).toBeGreaterThan(20);
    expect(summary.totalTools).toBeGreaterThan(20);
    expect(summary.activeGroups).toBeGreaterThan(10);
  });
});

describe("Threat Group Knowledge — Sector Profiles", () => {
  it("should have at least 8 sector profiles", () => {
    const profiles = getSectorProfiles();
    expect(profiles.length).toBeGreaterThanOrEqual(8);
  });

  it("each sector profile should have valid structure", () => {
    const profiles = getSectorProfiles();
    for (const p of profiles) {
      expect(p.sector).toBeTruthy();
      expect(p.topGroups.length).toBeGreaterThan(0);
      expect(p.commonTTPs.length).toBeGreaterThan(0);
      expect(p.priorityDefenses.length).toBeGreaterThan(0);
    }
  });

  it("sector profile groups should reference valid group IDs", () => {
    const profiles = getSectorProfiles();
    const allIds = new Set(getAllGroups().map(g => g.id));
    for (const p of profiles) {
      for (const gId of p.topGroups) {
        expect(allIds.has(gId)).toBe(true);
      }
    }
  });
});

describe("Threat Group Knowledge — LLM Context Builders", () => {
  it("getThreatGroupHuntContext should return non-empty context for known sectors", () => {
    const ctx = getThreatGroupHuntContext({ sector: "government" });
    expect(ctx.length).toBeGreaterThan(100);
    expect(ctx).toContain("THREAT GROUP INTELLIGENCE");
    expect(ctx).toContain("APT29");
    expect(ctx).toContain("INSTRUCTIONS");
  });

  it("getThreatGroupHuntContext should return context for specific group IDs", () => {
    const ctx = getThreatGroupHuntContext({ groupIds: ["lockbit", "blackcat"] });
    expect(ctx).toContain("LockBit");
    expect(ctx).toContain("ALPHV");
  });

  it("getThreatGroupHuntContext should return critical groups by default", () => {
    const ctx = getThreatGroupHuntContext();
    expect(ctx.length).toBeGreaterThan(100);
    expect(ctx).toContain("CRITICAL");
  });

  it("getThreatGroupHuntContext should include SIEM queries", () => {
    const ctx = getThreatGroupHuntContext({ sector: "government" });
    expect(ctx).toContain("SIEM Query:");
  });

  it("getThreatGroupScanContext should return CVEs and initial access methods", () => {
    const ctx = getThreatGroupScanContext({ sector: "healthcare" });
    expect(ctx.length).toBeGreaterThan(100);
    expect(ctx).toContain("PRIORITY CVEs");
    expect(ctx).toContain("INITIAL ACCESS METHODS");
    expect(ctx).toContain("INSTRUCTIONS");
  });

  it("getThreatGroupScanContext should include tool signatures", () => {
    const ctx = getThreatGroupScanContext({ sector: "technology" });
    expect(ctx).toContain("TOOL SIGNATURES");
  });

  it("getThreatGroupVulnContext should return CVE-to-group mappings", () => {
    const ctx = getThreatGroupVulnContext();
    expect(ctx.length).toBeGreaterThan(100);
    expect(ctx).toContain("VULNERABILITY CORRELATION");
    expect(ctx).toContain("CVEs ACTIVELY EXPLOITED");
    expect(ctx).toContain("SEVERITY BOOST RULES");
  });

  it("getSectorThreatContext should return sector-specific intelligence", () => {
    const ctx = getSectorThreatContext("energy");
    expect(ctx.length).toBeGreaterThan(50);
    expect(ctx).toContain("ENERGY");
    expect(ctx).toContain("Sandworm");
  });

  it("getSectorThreatContext should return empty for unknown sectors", () => {
    const ctx = getSectorThreatContext("nonexistent_sector");
    expect(ctx).toBe("");
  });
});

// ─── OWASP Coverage Tracker Tests ───────────────────────────────────────

import {
  OwaspCoverageTracker,
  renderOwaspCoverageHTML,
  generateOwaspReportSection,
  getOwaspTracker,
  resetOwaspTracker,
} from "./owasp-coverage-tracker";

describe("OWASP Coverage Tracker — Core Functionality", () => {
  it("should create a new tracker instance", () => {
    const tracker = new OwaspCoverageTracker();
    expect(tracker).toBeDefined();
  });

  it("should register asset technologies", () => {
    const tracker = new OwaspCoverageTracker();
    tracker.registerAssetTech("example.com", ["apache", "php", "mysql"]);
    const coverage = tracker.getAssetCoverage("example.com");
    expect(coverage.detectedTech).toContain("apache");
    expect(coverage.detectedTech).toContain("php");
    expect(coverage.detectedTech).toContain("mysql");
  });

  it("should record findings and classify them", () => {
    const tracker = new OwaspCoverageTracker();
    tracker.registerAssetTech("example.com", ["apache"]);
    tracker.addFinding({
      title: "SQL Injection in login form",
      severity: "high",
      tool: "sqlmap",
      target: "example.com",
    });
    tracker.addToolRun({
      tool: "sqlmap",
      target: "example.com",
      command: "sqlmap -u http://example.com/login",
    });
    const coverage = tracker.getAssetCoverage("example.com");
    // sqlmap covers A05:2025 (Injection)
    const injectionCat = coverage.categories.find(c => c.categoryId === "A05:2025");
    expect(injectionCat).toBeDefined();
    expect(injectionCat!.toolsUsed.length).toBeGreaterThan(0);
  });

  it("should track tool runs for coverage determination", () => {
    const tracker = new OwaspCoverageTracker();
    tracker.registerAssetTech("example.com", ["nginx"]);
    tracker.addToolRun({ tool: "nmap", target: "example.com", command: "nmap -sV example.com" });
    tracker.addToolRun({ tool: "nuclei", target: "example.com", command: "nuclei -u example.com" });
    tracker.addToolRun({ tool: "testssl", target: "example.com", command: "testssl.sh example.com" });
    
    const coverage = tracker.getAssetCoverage("example.com");
    // nmap covers A03, A04; nuclei covers A02, A03, A05; testssl covers A04
    const testedCats = coverage.categories.filter(c => c.status === "tested");
    expect(testedCats.length).toBeGreaterThan(0);
  });

  it("should calculate coverage score correctly", () => {
    const tracker = new OwaspCoverageTracker();
    tracker.registerAssetTech("example.com", ["apache"]);
    // Run tools covering multiple categories
    tracker.addToolRun({ tool: "nmap", target: "example.com" });
    tracker.addToolRun({ tool: "nuclei", target: "example.com" });
    tracker.addToolRun({ tool: "zap", target: "example.com" });
    tracker.addToolRun({ tool: "sqlmap", target: "example.com" });
    tracker.addToolRun({ tool: "testssl", target: "example.com" });
    
    const coverage = tracker.getAssetCoverage("example.com");
    expect(coverage.coverageScore).toBeGreaterThanOrEqual(0);
    expect(coverage.coverageScore).toBeLessThanOrEqual(100);
    expect(coverage.testedCount + coverage.partialCount + coverage.gapCount + coverage.notApplicableCount).toBe(10);
  });

  it("should identify coverage gaps", () => {
    const tracker = new OwaspCoverageTracker();
    tracker.registerAssetTech("example.com", ["apache"]);
    // Only run nmap — many categories will be gaps
    tracker.addToolRun({ tool: "nmap", target: "example.com" });
    
    const coverage = tracker.getAssetCoverage("example.com");
    expect(coverage.gapCount).toBeGreaterThan(0);
    const gaps = coverage.categories.filter(c => c.status === "not_tested");
    expect(gaps.length).toBeGreaterThan(0);
    // Each gap should have a rationale with recommendations
    for (const gap of gaps) {
      expect(gap.rationale).toContain("Recommended");
    }
  });
});

describe("OWASP Coverage Tracker — Engagement Coverage", () => {
  it("should generate engagement-wide coverage report", () => {
    const tracker = new OwaspCoverageTracker();
    tracker.registerAssetTech("web1.example.com", ["apache", "php"]);
    tracker.registerAssetTech("web2.example.com", ["nginx", "nodejs"]);
    tracker.addToolRun({ tool: "nmap", target: "web1.example.com" });
    tracker.addToolRun({ tool: "nuclei", target: "web1.example.com" });
    tracker.addToolRun({ tool: "nmap", target: "web2.example.com" });
    
    const coverage = tracker.getEngagementCoverage("test-engagement-1");
    expect(coverage.assets.length).toBe(2);
    expect(coverage.overallScore).toBeGreaterThanOrEqual(0);
    expect(coverage.overallScore).toBeLessThanOrEqual(100);
    expect(coverage.summaryNarrative.length).toBeGreaterThan(50);
  });

  it("should identify critical gaps across all assets", () => {
    const tracker = new OwaspCoverageTracker();
    tracker.registerAssetTech("web1.example.com", ["apache"]);
    tracker.registerAssetTech("web2.example.com", ["nginx"]);
    // Only run nmap on both — many gaps
    tracker.addToolRun({ tool: "nmap", target: "web1.example.com" });
    tracker.addToolRun({ tool: "nmap", target: "web2.example.com" });
    
    const coverage = tracker.getEngagementCoverage("test-engagement-2");
    expect(coverage.criticalGaps.length).toBeGreaterThan(0);
    // Each gap should have priority and recommendation
    for (const gap of coverage.criticalGaps) {
      expect(["critical", "high", "medium", "low"]).toContain(gap.priority);
      expect(gap.recommendation.length).toBeGreaterThan(10);
      expect(gap.affectedAssets.length).toBeGreaterThan(0);
    }
  });

  it("should generate summary narrative with grade", () => {
    const tracker = new OwaspCoverageTracker();
    tracker.registerAssetTech("example.com", ["apache"]);
    tracker.addToolRun({ tool: "nmap", target: "example.com" });
    
    const coverage = tracker.getEngagementCoverage("test-engagement-3");
    expect(coverage.summaryNarrative).toContain("Grade");
    expect(coverage.summaryNarrative).toContain("%");
  });
});

describe("OWASP Coverage Tracker — Bulk Import", () => {
  it("should import from engagement ops data", () => {
    const tracker = new OwaspCoverageTracker();
    tracker.importFromEngagementOps({
      assets: [
        {
          hostname: "testphp.vulnweb.com",
          passiveRecon: { technologies: ["php", "nginx"] },
          toolResults: [
            { tool: "nmap", command: "nmap -sV testphp.vulnweb.com", exitCode: 0, findings: ["80/tcp open http nginx"] },
            { tool: "nuclei", command: "nuclei -u http://testphp.vulnweb.com", exitCode: 0, findings: ["SQL Injection detected", "XSS reflected"] },
          ],
        },
      ],
    });

    const coverage = tracker.getAssetCoverage("testphp.vulnweb.com");
    expect(coverage.detectedTech).toContain("php");
    expect(coverage.detectedTech).toContain("nginx");
    expect(coverage.testedCount).toBeGreaterThan(0);
  });
});

describe("OWASP Coverage Tracker — HTML Report Generation", () => {
  it("should render valid HTML for coverage report", () => {
    const tracker = new OwaspCoverageTracker();
    tracker.registerAssetTech("example.com", ["apache"]);
    tracker.addToolRun({ tool: "nmap", target: "example.com" });
    tracker.addToolRun({ tool: "nuclei", target: "example.com" });
    
    const coverage = tracker.getEngagementCoverage("test-engagement-html");
    const html = renderOwaspCoverageHTML(coverage);
    
    expect(html).toContain("OWASP Top 10:2025 Coverage Analysis");
    expect(html).toContain("Coverage");
    expect(html).toContain("<table");
    expect(html).toContain("example.com");
  });

  it("should include gap recommendations in HTML", () => {
    const tracker = new OwaspCoverageTracker();
    tracker.registerAssetTech("example.com", ["apache"]);
    tracker.addToolRun({ tool: "nmap", target: "example.com" });
    
    const coverage = tracker.getEngagementCoverage("test-engagement-gaps");
    const html = renderOwaspCoverageHTML(coverage);
    
    if (coverage.criticalGaps.length > 0) {
      expect(html).toContain("Coverage Gaps");
    }
  });

  it("should generate report section data", () => {
    const tracker = new OwaspCoverageTracker();
    tracker.registerAssetTech("example.com", ["apache"]);
    tracker.addToolRun({ tool: "nmap", target: "example.com" });
    
    const coverage = tracker.getEngagementCoverage("test-engagement-section");
    const section = generateOwaspReportSection(coverage);
    
    expect(section.title).toBe("OWASP Top 10:2025 Coverage Analysis");
    expect(section.content.length).toBeGreaterThan(50);
  });
});

describe("OWASP Coverage Tracker — Singleton", () => {
  it("getOwaspTracker should return the same instance", () => {
    const t1 = getOwaspTracker();
    const t2 = getOwaspTracker();
    expect(t1).toBe(t2);
  });

  it("resetOwaspTracker should create a new instance", () => {
    const t1 = getOwaspTracker();
    const t2 = resetOwaspTracker();
    expect(t1).not.toBe(t2);
  });
});
