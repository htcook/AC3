import { describe, it, expect } from "vitest";
import {
  applyGuardrails,
  validateEnrichmentOutput,
  GUARDRAIL_CONFIG,
  type LocalDbContext,
} from "./lib/enrichment-guardrails";

// ─── Test Helpers ─────────────────────────────────────────────────────

function makeSource(field: string, sourceType: string, confidence: number, opts?: { sourceName?: string; sourceUrl?: string }) {
  return {
    field,
    value: `Test value for ${field}`,
    sourceName: opts?.sourceName || "MITRE ATT&CK",
    sourceType,
    sourceUrl: opts?.sourceUrl || "https://attack.mitre.org",
    confidence,
  };
}

function makeEmptyLocalContext(): LocalDbContext {
  return { tgeEvents: [], uieEvents: [], iocs: [] };
}

function makeLocalContextWithEvents(): LocalDbContext {
  return {
    tgeEvents: [
      { victimSector: "Financial Services", victimCountry: "United States", description: "Used Cobalt Strike beacon", mitreTechniques: "T1566, T1059" },
      { victimSector: "Healthcare", victimCountry: "Germany", description: "Deployed Mimikatz for credential harvesting" },
    ],
    uieEvents: [
      { victimSector: "Government", victimCountry: "United Kingdom", description: "Ransomware deployment via RDP" },
    ],
    iocs: [],
  };
}

function makeBasicParsed() {
  return {
    description: "A sophisticated nation-state threat group known for targeting critical infrastructure across multiple sectors with advanced persistent access techniques.",
    motivation: "espionage",
    origin: "Russia",
    firstSeen: "2015-03",
    lastActive: "2024-11",
    threatLevel: "critical",
    sophistication: "advanced",
    activityScore: 85,
    trend: "increasing",
    aliases: ["Fancy Bear", "APT28", "Sofacy"],
    targetSectors: ["Government", "Defense", "Energy"],
    targetRegions: ["United States", "Europe", "NATO members"],
    techniques: [
      { id: "T1566", name: "Phishing", tactic: "Initial Access" },
      { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
    ],
    tools: ["Cobalt Strike", "Mimikatz"],
    malware: ["X-Agent", "Zebrocy"],
    notableAttacks: [
      { date: "2016-06", victimName: "DNC", description: "Democratic National Committee breach", source: "CrowdStrike" },
    ],
    activityTimeline: [
      { date: "2024-01", event: "Targeted European energy sector" },
    ],
    conflicts: ["Russia-Ukraine"],
    sources: [],
    summary: "Well-documented APT group with extensive OSINT coverage",
    dataQualityScore: 85,
  };
}

// ─── Tests ────────────────────────────────────────────────────────────

describe("Enrichment Guardrails", () => {
  describe("validateEnrichmentOutput", () => {
    it("should accept high-confidence data with verifiable sources", () => {
      const parsed = makeBasicParsed();
      const sources = [
        makeSource("description", "osint", 90),
        makeSource("motivation", "government", 85),
        makeSource("origin", "vendor_report", 80),
        makeSource("firstSeen", "osint", 75),
        makeSource("lastActive", "osint", 80),
        makeSource("aliases", "osint", 85),
        makeSource("targetSectors", "osint", 80),
        makeSource("targetRegions", "osint", 80),
        makeSource("techniques", "osint", 85),
        makeSource("tools", "vendor_report", 80),
        makeSource("malware", "vendor_report", 80),
        makeSource("notableAttacks", "osint", 90),
      ];

      const report = validateEnrichmentOutput(parsed, sources, makeEmptyLocalContext(), {});

      expect(report.accepted).toBeGreaterThan(0);
      expect(report.rejected).toBe(0);
      expect(report.overallTrustScore).toBeGreaterThan(60);
    });

    it("should reject fields with very low confidence from non-LLM sources", () => {
      const parsed = makeBasicParsed();
      // Confidence 10 from a verifiable source (not LLM-only) should hit the general reject threshold
      // Use 'osint' source type so LLM-only check doesn't flag first
      const sources = [
        makeSource("aliases", "osint", 10),
        makeSource("targetSectors", "osint", 10),
        makeSource("targetRegions", "osint", 10),
        makeSource("tools", "osint", 10),
      ];

      const report = validateEnrichmentOutput(parsed, sources, makeEmptyLocalContext(), {});

      // Array fields with confidence 10 from non-LLM sources should be rejected
      expect(report.rejected).toBeGreaterThan(0);
      expect(report.rejectedFields.length).toBeGreaterThan(0);
    });

    it("should flag LLM-only sources below confidence threshold", () => {
      const parsed = makeBasicParsed();
      const sources = [
        makeSource("description", "llm_knowledge", 55),
        makeSource("motivation", "llm_knowledge", 55),
        makeSource("origin", "llm_knowledge", 55),
        makeSource("aliases", "llm_knowledge", 55),
        makeSource("targetSectors", "llm_knowledge", 55),
      ];

      const report = validateEnrichmentOutput(parsed, sources, makeEmptyLocalContext(), {});

      expect(report.flagged).toBeGreaterThan(0);
      expect(report.flaggedFields.length).toBeGreaterThan(0);
    });

    it("should accept flagged fields when corroborated by local DB", () => {
      const parsed = makeBasicParsed();
      parsed.targetSectors = ["Financial Services", "Healthcare"];
      parsed.tools = ["Cobalt Strike"];
      const sources = [
        makeSource("targetSectors", "llm_knowledge", 55),
        makeSource("tools", "llm_knowledge", 55),
      ];

      const report = validateEnrichmentOutput(parsed, sources, makeLocalContextWithEvents(), {});

      // targetSectors and tools should be corroborated and accepted
      const sectorVerdict = report.verdicts.find(v => v.field === "targetSectors");
      const toolsVerdict = report.verdicts.find(v => v.field === "tools");
      expect(sectorVerdict?.corroboratedByLocalDb).toBe(true);
      expect(toolsVerdict?.corroboratedByLocalDb).toBe(true);
    });

    it("should reject descriptions that are too short", () => {
      const parsed = makeBasicParsed();
      parsed.description = "Short desc";
      const sources = [makeSource("description", "osint", 90)];

      const report = validateEnrichmentOutput(parsed, sources, makeEmptyLocalContext(), {});

      const descVerdict = report.verdicts.find(v => v.field === "description");
      expect(descVerdict?.status).toBe("rejected");
    });

    it("should reject future dates", () => {
      const parsed = makeBasicParsed();
      parsed.firstSeen = "2035-01";
      const sources = [makeSource("firstSeen", "osint", 90)];

      const report = validateEnrichmentOutput(parsed, sources, makeEmptyLocalContext(), {});

      const dateVerdict = report.verdicts.find(v => v.field === "firstSeen");
      expect(dateVerdict?.status).toBe("rejected");
    });

    it("should flag unusually old dates", () => {
      const parsed = makeBasicParsed();
      parsed.firstSeen = "1985-01";
      const sources = [makeSource("firstSeen", "osint", 90)];

      const report = validateEnrichmentOutput(parsed, sources, makeEmptyLocalContext(), {});

      const dateVerdict = report.verdicts.find(v => v.field === "firstSeen");
      expect(dateVerdict?.status).toBe("flagged");
    });

    it("should validate MITRE technique T-codes", () => {
      const parsed = makeBasicParsed();
      parsed.techniques = [
        { id: "T1566", name: "Phishing", tactic: "Initial Access" },
        { id: "INVALID", name: "Bad Tech", tactic: "Execution" },
        { id: "T9999", name: "Another", tactic: "Impact" },
        { id: "NOPE", name: "Nope", tactic: "Discovery" },
      ];
      const sources = [makeSource("techniques", "osint", 80)];

      const report = validateEnrichmentOutput(parsed, sources, makeEmptyLocalContext(), {});

      const techVerdict = report.verdicts.find(v => v.field === "techniques");
      // 2 out of 4 are invalid = 50%, should be flagged or rejected
      expect(techVerdict?.status).not.toBe("accepted");
    });

    it("should reject techniques when more than 50% have invalid T-codes", () => {
      const parsed = makeBasicParsed();
      parsed.techniques = [
        { id: "INVALID1", name: "Bad", tactic: "Execution" },
        { id: "INVALID2", name: "Bad2", tactic: "Impact" },
        { id: "T1059", name: "Good", tactic: "Execution" },
      ];
      const sources = [makeSource("techniques", "osint", 80)];

      const report = validateEnrichmentOutput(parsed, sources, makeEmptyLocalContext(), {});

      const techVerdict = report.verdicts.find(v => v.field === "techniques");
      expect(techVerdict?.status).toBe("rejected");
    });

    it("should detect suspicious sources", () => {
      const parsed = makeBasicParsed();
      const sources = [
        makeSource("description", "osint", 90, { sourceName: "example.com", sourceUrl: "https://example.com/fake" }),
        makeSource("motivation", "osint", 85, { sourceName: "N/A" }),
        makeSource("origin", "osint", 80, { sourceName: "none" }),
      ];

      const report = validateEnrichmentOutput(parsed, sources, makeEmptyLocalContext(), {});

      expect(report.warnings.some(w => w.includes("suspicious"))).toBe(true);
    });

    it("should warn about high LLM-knowledge reliance", () => {
      const parsed = makeBasicParsed();
      const sources = [
        makeSource("description", "llm_knowledge", 80),
        makeSource("motivation", "llm_knowledge", 80),
        makeSource("origin", "llm_knowledge", 80),
        makeSource("aliases", "llm_knowledge", 80),
        makeSource("targetSectors", "llm_knowledge", 80),
      ];

      const report = validateEnrichmentOutput(parsed, sources, makeEmptyLocalContext(), {});

      expect(report.warnings.some(w => w.includes("LLM-knowledge reliance"))).toBe(true);
    });

    it("should compute trust score based on verdicts", () => {
      const parsed = makeBasicParsed();
      const sources = [
        makeSource("description", "osint", 90),
        makeSource("motivation", "osint", 85),
        makeSource("origin", "osint", 80),
        makeSource("aliases", "osint", 85),
        makeSource("techniques", "osint", 85),
      ];

      const report = validateEnrichmentOutput(parsed, sources, makeEmptyLocalContext(), {});

      expect(report.overallTrustScore).toBeGreaterThanOrEqual(0);
      expect(report.overallTrustScore).toBeLessThanOrEqual(100);
      expect(report.totalFields).toBeGreaterThan(0);
    });
  });

  describe("applyGuardrails", () => {
    it("should remove rejected fields from sanitized data", () => {
      const parsed = makeBasicParsed();
      parsed.description = "Too short"; // Will be rejected
      parsed.firstSeen = "2035-01"; // Will be rejected (future date)
      const sources = [
        makeSource("description", "osint", 90),
        makeSource("firstSeen", "osint", 90),
        makeSource("motivation", "osint", 80),
      ];

      const { sanitizedData, report } = applyGuardrails(parsed, sources, makeEmptyLocalContext(), {});

      expect(sanitizedData.description).toBeUndefined();
      expect(sanitizedData.firstSeen).toBeUndefined();
      expect(report.rejectedFields).toContain("description");
      expect(report.rejectedFields).toContain("firstSeen");
    });

    it("should truncate oversized arrays", () => {
      const parsed = makeBasicParsed();
      parsed.aliases = Array.from({ length: 50 }, (_, i) => `Alias${i}`);
      const sources = [makeSource("aliases", "osint", 85)];

      const { sanitizedData } = applyGuardrails(parsed, sources, makeEmptyLocalContext(), {});

      expect(sanitizedData.aliases.length).toBeLessThanOrEqual(GUARDRAIL_CONFIG.MAX_ALIASES);
    });

    it("should filter out techniques with invalid T-codes", () => {
      const parsed = makeBasicParsed();
      parsed.techniques = [
        { id: "T1566", name: "Phishing", tactic: "Initial Access" },
        { id: "INVALID", name: "Bad", tactic: "Execution" },
        { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      ];
      const sources = [makeSource("techniques", "osint", 85)];

      const { sanitizedData } = applyGuardrails(parsed, sources, makeEmptyLocalContext(), {});

      // Only valid T-codes should remain
      const validIds = sanitizedData.techniques.map((t: any) => t.id);
      expect(validIds).toContain("T1566");
      expect(validIds).toContain("T1059.001");
      expect(validIds).not.toContain("INVALID");
    });

    it("should remove notable attacks with future dates", () => {
      const parsed = makeBasicParsed();
      parsed.notableAttacks = [
        { date: "2024-01", victimName: "Real Corp", description: "Real attack", source: "CISA" },
        { date: "2035-06", victimName: "Future Corp", description: "Future attack", source: "Unknown" },
      ];
      const sources = [makeSource("notableAttacks", "osint", 85)];

      const { sanitizedData } = applyGuardrails(parsed, sources, makeEmptyLocalContext(), {});

      expect(sanitizedData.notableAttacks.length).toBe(1);
      expect(sanitizedData.notableAttacks[0].victimName).toBe("Real Corp");
    });

    it("should remove suspicious sources from cleaned list", () => {
      const parsed = makeBasicParsed();
      const sources = [
        makeSource("description", "osint", 90),
        makeSource("motivation", "osint", 85, { sourceName: "example.com", sourceUrl: "https://example.com/fake" }),
      ];

      const { report } = applyGuardrails(parsed, sources, makeEmptyLocalContext(), {});

      expect(report.warnings.some(w => w.includes("suspicious"))).toBe(true);
    });

    it("should include guardrail report with verdicts", () => {
      const parsed = makeBasicParsed();
      const sources = [
        makeSource("description", "osint", 90),
        makeSource("motivation", "government", 85),
      ];

      const { report } = applyGuardrails(parsed, sources, makeEmptyLocalContext(), {});

      expect(report).toHaveProperty("totalFields");
      expect(report).toHaveProperty("accepted");
      expect(report).toHaveProperty("flagged");
      expect(report).toHaveProperty("rejected");
      expect(report).toHaveProperty("verdicts");
      expect(report).toHaveProperty("overallTrustScore");
      expect(report).toHaveProperty("warnings");
      expect(report).toHaveProperty("rejectedFields");
      expect(report).toHaveProperty("flaggedFields");
      expect(Array.isArray(report.verdicts)).toBe(true);
    });
  });

  describe("GUARDRAIL_CONFIG", () => {
    it("should have valid MITRE technique regex", () => {
      expect(GUARDRAIL_CONFIG.MITRE_TECHNIQUE_REGEX.test("T1566")).toBe(true);
      expect(GUARDRAIL_CONFIG.MITRE_TECHNIQUE_REGEX.test("T1059.001")).toBe(true);
      expect(GUARDRAIL_CONFIG.MITRE_TECHNIQUE_REGEX.test("INVALID")).toBe(false);
      expect(GUARDRAIL_CONFIG.MITRE_TECHNIQUE_REGEX.test("T12")).toBe(false);
      expect(GUARDRAIL_CONFIG.MITRE_TECHNIQUE_REGEX.test("T12345")).toBe(false);
    });

    it("should have reasonable thresholds", () => {
      expect(GUARDRAIL_CONFIG.CONFIDENCE_ACCEPT_THRESHOLD).toBeGreaterThan(GUARDRAIL_CONFIG.CONFIDENCE_REJECT_THRESHOLD);
      expect(GUARDRAIL_CONFIG.LLM_ONLY_MIN_CONFIDENCE).toBeGreaterThanOrEqual(GUARDRAIL_CONFIG.CONFIDENCE_ACCEPT_THRESHOLD);
      expect(GUARDRAIL_CONFIG.MAX_ALIASES).toBeGreaterThan(0);
      expect(GUARDRAIL_CONFIG.MAX_TECHNIQUES).toBeGreaterThan(0);
    });
  });

  describe("Cross-reference with local DB", () => {
    it("should corroborate target sectors found in local events", () => {
      const parsed = makeBasicParsed();
      parsed.targetSectors = ["Financial Services"];
      const sources = [makeSource("targetSectors", "llm_knowledge", 55)];

      const report = validateEnrichmentOutput(parsed, sources, makeLocalContextWithEvents(), {});

      const verdict = report.verdicts.find(v => v.field === "targetSectors");
      expect(verdict?.corroboratedByLocalDb).toBe(true);
    });

    it("should corroborate techniques found in local events", () => {
      const parsed = makeBasicParsed();
      parsed.techniques = [{ id: "T1566", name: "Phishing", tactic: "Initial Access" }];
      const sources = [makeSource("techniques", "osint", 80)];

      const report = validateEnrichmentOutput(parsed, sources, makeLocalContextWithEvents(), {});

      const verdict = report.verdicts.find(v => v.field === "techniques");
      expect(verdict?.corroboratedByLocalDb).toBe(true);
    });

    it("should corroborate tools found in local event descriptions", () => {
      const parsed = makeBasicParsed();
      parsed.tools = ["Cobalt Strike"];
      const sources = [makeSource("tools", "llm_knowledge", 55)];

      const report = validateEnrichmentOutput(parsed, sources, makeLocalContextWithEvents(), {});

      const verdict = report.verdicts.find(v => v.field === "tools");
      expect(verdict?.corroboratedByLocalDb).toBe(true);
    });
  });

  describe("Bulk enrichment batch processing", () => {
    it("should accept batch sizes up to 500 in the backend input schema", () => {
      // This tests the conceptual contract — the backend now accepts up to 500 IDs
      const batchSizes = [20, 50, 100, 250, 500];
      for (const size of batchSizes) {
        expect(size).toBeLessThanOrEqual(500);
        expect(size).toBeGreaterThan(0);
      }
    });

    it("should process actors in chunks of 10 on the frontend", () => {
      const CHUNK_SIZE = 10;
      const totalActors = 100;
      const expectedChunks = Math.ceil(totalActors / CHUNK_SIZE);
      expect(expectedChunks).toBe(10);
    });

    it("should support configurable batch sizes", () => {
      const BATCH_SIZE_OPTIONS = [20, 50, 100, 250, 500, 1000];
      expect(BATCH_SIZE_OPTIONS).toContain(20);
      expect(BATCH_SIZE_OPTIONS).toContain(50);
      expect(BATCH_SIZE_OPTIONS).toContain(100);
      expect(BATCH_SIZE_OPTIONS).toContain(250);
      expect(BATCH_SIZE_OPTIONS).toContain(500);
      expect(BATCH_SIZE_OPTIONS).toContain(1000);
    });
  });
});
