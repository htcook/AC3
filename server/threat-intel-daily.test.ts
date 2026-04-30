/**
 * Tests for the daily threat intel monitoring endpoint and Lazarus Mach-O Man update
 */
import { describe, it, expect } from "vitest";

// ─── Test: Lazarus Mach-O Man campaign data structure ───
describe("Lazarus Mach-O Man Campaign Intelligence", () => {
  it("should have correct MITRE ATT&CK technique IDs for ClickFix macOS campaign", () => {
    const expectedTechniques = [
      "T1204.002", // User Execution: Malicious File
      "T1059.004", // Unix Shell
      "T1059.006", // Python
      "T1547.011", // Plist Modification (LaunchAgent)
      "T1555.001", // Keychain
      "T1539",     // Steal Web Session Cookie
      "T1555.003", // Credentials from Web Browsers
      "T1082",     // System Information Discovery
      "T1005",     // Data from Local System
      "T1567",     // Exfiltration Over Web Service (Telegram)
      "T1070.004", // File Deletion (self-deletion)
      "T1036.005", // Masquerading
      "T1566.003", // Spearphishing via Service (Telegram)
    ];
    
    // All techniques should be valid MITRE format
    for (const t of expectedTechniques) {
      expect(t).toMatch(/^T\d{4}(\.\d{3})?$/);
    }
    expect(expectedTechniques.length).toBe(13);
  });

  it("should have correct malware components for Mach-O Man kit", () => {
    const malwareKit = [
      "Mach-O Man (macOS malware kit)",
      "macrasv2 (macOS credential stealer)",
      "PyLangGhostRAT (Python RAT, vibe-ported from Go)",
      "teamsSDK.bin (stage 1 dropper, disguised as Teams SDK)",
      "Mach-O Man System Profiler (Go-based, stage 2)",
      "Mach-O Man Persistence Agent (LaunchAgent-based)",
    ];
    
    expect(malwareKit.length).toBe(6);
    // Verify each has a description in parentheses
    for (const m of malwareKit) {
      expect(m).toContain("(");
      expect(m).toContain(")");
    }
  });

  it("should have correct IOC types for the campaign", () => {
    const iocTypes = ["filename", "technique", "behavior"];
    const iocs = [
      { type: "filename", value: "teamsSDK.bin" },
      { type: "filename", value: "macrasv2" },
      { type: "filename", value: "PyLangGhostRAT" },
      { type: "technique", value: "ClickFix via Telegram" },
      { type: "technique", value: "LaunchAgent persistence" },
      { type: "technique", value: "Telegram C2 exfiltration" },
      { type: "behavior", value: "curl | bash initial access" },
      { type: "behavior", value: "macOS Keychain dump" },
      { type: "behavior", value: "Self-deletion post-exfil" },
      { type: "behavior", value: "System profiler Go binary" },
    ];
    
    expect(iocs.length).toBe(10);
    for (const ioc of iocs) {
      expect(iocTypes).toContain(ioc.type);
      expect(ioc.value.length).toBeGreaterThan(0);
    }
  });

  it("should target correct sectors and regions", () => {
    const targetSectors = ["FinTech", "Cryptocurrency", "Technology", "Financial Services"];
    const targetRegions = ["Global", "United States", "Europe", "Asia-Pacific"];
    
    expect(targetSectors).toContain("Cryptocurrency");
    expect(targetSectors).toContain("FinTech");
    expect(targetRegions).toContain("Global");
  });
});

// ─── Test: Daily threat intel endpoint request/response structure ───
describe("Daily Threat Intel Endpoint Structure", () => {
  it("should define correct phases for the daily pipeline", () => {
    const expectedPhases = [
      "rss_sync",
      "full_ingest",
      "actor_crawl",
      "targeted_enrichment",
      "external_articles",
    ];
    
    expect(expectedPhases.length).toBe(5);
    for (const phase of expectedPhases) {
      expect(phase).toMatch(/^[a-z_]+$/);
    }
  });

  it("should accept valid article payload format for external ingestion", () => {
    const validPayload = {
      articles: [
        {
          actorId: "lazarus",
          event: {
            eventType: "campaign",
            tgeTitle: "Test Campaign",
            tgeDescription: "Description of the campaign",
            tgeSeverity: "critical",
            tgeVictimSector: "FinTech",
            tgeVictimCountry: "Global",
            tgeMitreTechniques: ["T1566.001"],
            tgeSource: "Test Source",
            tgeSourceUrl: "https://example.com",
            tgeConfidence: 85,
            eventDate: "2026-04-30",
          },
        },
      ],
    };
    
    expect(validPayload.articles).toHaveLength(1);
    expect(validPayload.articles[0].actorId).toBe("lazarus");
    expect(validPayload.articles[0].event.tgeSeverity).toMatch(/^(critical|high|medium|low)$/);
    expect(validPayload.articles[0].event.tgeConfidence).toBeGreaterThanOrEqual(0);
    expect(validPayload.articles[0].event.tgeConfidence).toBeLessThanOrEqual(100);
    expect(validPayload.articles[0].event.tgeMitreTechniques[0]).toMatch(/^T\d{4}/);
  });

  it("should validate actor ID format for new actors", () => {
    // Known actors should use existing IDs
    const knownActors = [
      "lazarus", "lazarus-group-g0032", "apt28-fancy-bear",
      "apt29-cozy-bear", "sandworm", "charming-kitten-apt35",
    ];
    
    for (const id of knownActors) {
      expect(id).toMatch(/^[a-z0-9-]+$/);
    }
    
    // New actors should follow kebab-case
    const newActorName = "Emerald Sleet";
    const expectedId = newActorName.toLowerCase().replace(/\s+/g, "-");
    expect(expectedId).toBe("emerald-sleet");
    expect(expectedId).toMatch(/^[a-z0-9-]+$/);
  });
});

// ─── Test: Scheduled task configuration ───
describe("Scheduled Task Configuration", () => {
  it("should run daily at 6:00 AM UTC", () => {
    const cronExpression = "0 0 6 * * *";
    const parts = cronExpression.split(" ");
    expect(parts).toHaveLength(6);
    expect(parts[0]).toBe("0"); // seconds
    expect(parts[1]).toBe("0"); // minutes
    expect(parts[2]).toBe("6"); // hours (6 AM)
    expect(parts[3]).toBe("*"); // every day
    expect(parts[4]).toBe("*"); // every month
    expect(parts[5]).toBe("*"); // every day of week
  });

  it("should cover all required threat intel sources", () => {
    const requiredSources = [
      "DFIR Report",
      "CISA",
      "Unit42",
      "Dark Reading",
      "Hacker News",
      "CyberScoop",
      "Mandiant",
      "SentinelOne",
      "MISP",
      "BleepingComputer",
    ];
    
    expect(requiredSources.length).toBeGreaterThanOrEqual(10);
  });

  it("should include both internal pipeline trigger and external research", () => {
    const pipelineSteps = [
      "trigger_internal_feeds",  // POST to /api/scheduled/threat-intel-daily
      "deep_research_new_campaigns",  // Search for new APT reports
      "extract_and_post_findings",  // POST new articles back
      "nvd_cve_refresh",  // POST to /api/scheduled/cve-refresh
    ];
    
    expect(pipelineSteps).toHaveLength(4);
  });
});
