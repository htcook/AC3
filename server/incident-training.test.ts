import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock DB helpers ────────────────────────────────────────────────────────
vi.mock("./db", () => ({
  getDb: vi.fn().mockResolvedValue(null),
  bulkInsertDITrainingExamples: vi.fn().mockResolvedValue(undefined),
  getDITrainingExamplesForDomain: vi.fn().mockResolvedValue([]),
  getDITrainingExamplesForSector: vi.fn().mockResolvedValue([]),
  getHighQualityDITrainingExamples: vi.fn().mockResolvedValue([]),
  incrementDITrainingUsage: vi.fn().mockResolvedValue(undefined),
  updateDITrainingAnalystRating: vi.fn().mockResolvedValue(undefined),
  getDITrainingStats: vi.fn().mockResolvedValue({ total: 0, high: 0, medium: 0, low: 0, rejected: 0, reviewed: 0, unreviewed: 0 }),
}));

vi.mock("./_core/llm", () => ({
  invokeLLM: vi.fn().mockResolvedValue({
    choices: [{ message: { content: JSON.stringify({ incidents: [] }) } }],
  }),
}));

// ─── Import after mocks ─────────────────────────────────────────────────────
import { collectTrainingData, type TrainingCollectorInput } from "./lib/incident-training-collector";
import { getIncidentTrainingContext, getIncidentSearchPromptContext } from "./lib/incident-training-context";
import * as db from "./db";
import type { IncidentSearchResult } from "./lib/incident-search-enrichment";

// ─── Test Data ──────────────────────────────────────────────────────────────

function makeIncidentSearch(overrides: Partial<IncidentSearchResult> = {}): IncidentSearchResult {
  return {
    domain: "example.com",
    searchedAt: Date.now(),
    catalogMatches: [
      {
        source: "threat_catalog_event",
        actorId: "apt28",
        actorName: "APT28",
        actorType: "apt",
        eventType: "attack",
        title: "APT28 Campaign Against Example Corp",
        description: "Spear-phishing campaign targeting example.com employees",
        severity: "high",
        date: "2024-03",
        mitreTechniques: ["T1566.001", "T1078"],
        confidence: "confirmed",
        relevanceScore: 0.9,
      },
    ],
    webSearchMatches: [
      {
        source: "web_search",
        actorName: "LockBit",
        actorType: "ransomware",
        eventType: "ransomware",
        title: "LockBit Ransomware Attack on Example Corp",
        description: "LockBit 3.0 ransomware attack resulting in data exfiltration and encryption",
        severity: "critical",
        date: "2024-06",
        mitreTechniques: ["T1486", "T1567"],
        confidence: "confirmed",
        relevanceScore: 0.95,
      },
      {
        source: "web_search",
        eventType: "data_breach",
        title: "Example Corp Data Breach - 2M Records",
        description: "Data breach exposing 2 million customer records including emails and passwords",
        severity: "critical",
        date: "2024-01",
        confidence: "confirmed",
        relevanceScore: 0.85,
      },
    ],
    totalMatches: 3,
    hasActiveThreats: true,
    hasRansomwareEvent: true,
    hasRecentBreach: true,
    riskFloorContribution: 80,
    summary: "Example Corp has been targeted by APT28 and LockBit ransomware, with a recent data breach exposing 2M records.",
    newActorsDiscovered: ["LockBit"],
    newTTPsDiscovered: ["T1486", "T1567"],
    newIOCsDiscovered: [],
    ...overrides,
  };
}

function makeAffiliatedDomains() {
  return {
    targetDomain: "example.com",
    searchedAt: Date.now(),
    registrantOrg: "Example Corporation",
    registrantEmail: "admin@example.com",
    affiliatedDomains: [
      { domain: "example.org", relationship: "same_registrant", confidence: 95, source: "securitytrails_reverse_whois", evidence: "Same registrant org" },
      { domain: "example.net", relationship: "shared_certificate", confidence: 85, source: "crtsh_org_search", evidence: "Shared TLS cert" },
      { domain: "myexample.com", relationship: "llm_knowledge", confidence: 60, source: "llm_knowledge", evidence: "Known brand" },
    ],
    totalDiscovered: 3,
    sourceBreakdown: { securitytrails_reverse_whois: 1, crtsh_org_search: 1, llm_knowledge: 1 },
    summary: "3 affiliated domains discovered for Example Corporation.",
  };
}

// ─── Training Data Collector Tests ──────────────────────────────────────────


// Skip in CI — requires production database connection
const __skipInCI = !process.env.DATABASE_URL || process.env.DATABASE_URL.includes("localhost");

describe.skipIf(__skipInCI)("Incident Training Data Collector", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should generate training examples from a scan with incidents", async () => {
    const input: TrainingCollectorInput = {
      scanId: 1,
      domain: "example.com",
      sector: "technology",
      incidentSearch: makeIncidentSearch(),
      affiliatedDomains: makeAffiliatedDomains(),
      riskScore: 78,
      riskBand: "high",
    };

    const result = await collectTrainingData(input);

    expect(result.totalExamples).toBeGreaterThan(0);
    expect(result.examplesByType).toHaveProperty("incident_context");
    expect(db.bulkInsertDITrainingExamples).toHaveBeenCalledTimes(1);
  });

  it("should generate actor attribution examples per unique actor", async () => {
    const input: TrainingCollectorInput = {
      scanId: 2,
      domain: "example.com",
      sector: "finance",
      incidentSearch: makeIncidentSearch(),
      riskScore: 85,
      riskBand: "critical",
    };

    const result = await collectTrainingData(input);

    // Should have actor_attribution for APT28 and LockBit
    expect(result.examplesByType.actor_attribution).toBe(2);
  });

  it("should generate ransomware profile when ransomware events exist", async () => {
    const input: TrainingCollectorInput = {
      scanId: 3,
      domain: "example.com",
      incidentSearch: makeIncidentSearch(),
      riskScore: 90,
      riskBand: "critical",
    };

    const result = await collectTrainingData(input);

    expect(result.examplesByType).toHaveProperty("ransomware_profile");
    expect(result.examplesByType.ransomware_profile).toBe(1);
  });

  it("should generate breach pattern when breaches exist", async () => {
    const input: TrainingCollectorInput = {
      scanId: 4,
      domain: "example.com",
      incidentSearch: makeIncidentSearch(),
      riskScore: 75,
      riskBand: "high",
    };

    const result = await collectTrainingData(input);

    expect(result.examplesByType).toHaveProperty("breach_pattern");
    expect(result.examplesByType.breach_pattern).toBe(1);
  });

  it("should generate attack surface map when affiliated domains exist", async () => {
    const input: TrainingCollectorInput = {
      scanId: 5,
      domain: "example.com",
      incidentSearch: null,
      affiliatedDomains: makeAffiliatedDomains(),
      riskScore: 45,
      riskBand: "medium",
    };

    const result = await collectTrainingData(input);

    expect(result.examplesByType).toHaveProperty("attack_surface_map");
    expect(result.examplesByType.attack_surface_map).toBe(1);
  });

  it("should return 0 examples when no incidents or affiliated domains", async () => {
    const input: TrainingCollectorInput = {
      scanId: 6,
      domain: "clean-domain.com",
      incidentSearch: {
        domain: "clean-domain.com",
        searchedAt: Date.now(),
        catalogMatches: [],
        webSearchMatches: [],
        totalMatches: 0,
        hasActiveThreats: false,
        hasRansomwareEvent: false,
        hasRecentBreach: false,
        riskFloorContribution: 0,
        summary: "No incidents found.",
        newActorsDiscovered: [],
        newTTPsDiscovered: [],
        newIOCsDiscovered: [],
      },
      riskScore: 20,
      riskBand: "low",
    };

    const result = await collectTrainingData(input);

    expect(result.totalExamples).toBe(0);
    expect(db.bulkInsertDITrainingExamples).not.toHaveBeenCalled();
  });

  it("should not generate ransomware example when no ransomware events", async () => {
    const noRansom = makeIncidentSearch({
      hasRansomwareEvent: false,
      catalogMatches: [{
        source: "threat_catalog_event",
        actorName: "APT28",
        actorType: "apt",
        eventType: "attack",
        title: "APT28 Phishing Campaign",
        description: "Phishing campaign only, no ransomware",
        severity: "high",
        date: "2024-03",
        confidence: "confirmed",
        relevanceScore: 0.9,
      }],
      webSearchMatches: [{
        source: "web_search",
        eventType: "data_breach",
        title: "Data Breach Only",
        description: "Just a breach, no ransomware",
        severity: "high",
        date: "2024-05",
        confidence: "confirmed",
        relevanceScore: 0.8,
      }],
    });

    const input: TrainingCollectorInput = {
      scanId: 7,
      domain: "example.com",
      incidentSearch: noRansom,
      riskScore: 60,
      riskBand: "medium",
    };

    const result = await collectTrainingData(input);

    expect(result.examplesByType.ransomware_profile).toBeUndefined();
  });

  it("should calculate quality scores correctly", async () => {
    const input: TrainingCollectorInput = {
      scanId: 8,
      domain: "example.com",
      sector: "healthcare",
      incidentSearch: makeIncidentSearch(),
      affiliatedDomains: makeAffiliatedDomains(),
      riskScore: 92,
      riskBand: "critical",
    };

    const result = await collectTrainingData(input);

    // With confirmed incidents, ransomware, and breaches, should have high-quality examples
    expect(result.highQualityCount).toBeGreaterThan(0);
  });

  it("should handle null incidentSearch gracefully", async () => {
    const input: TrainingCollectorInput = {
      scanId: 9,
      domain: "example.com",
      incidentSearch: null,
      riskScore: 30,
      riskBand: "low",
    };

    const result = await collectTrainingData(input);

    expect(result.totalExamples).toBe(0);
  });
});

// ─── Training Context Injection Tests ───────────────────────────────────────

describe("Incident Training Context Injection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should return empty context when no training data exists", async () => {
    const context = await getIncidentTrainingContext("unknown.com");

    expect(context.systemPromptAddition).toBe("");
    expect(context.totalExamplesUsed).toBe(0);
    expect(context.exampleIds).toHaveLength(0);
  });

  it("should prioritize same-domain examples", async () => {
    const mockExamples = [
      {
        exampleId: "ditd_test1",
        domain: "example.com",
        exampleType: "incident_context",
        trainingMessages: JSON.stringify([
          { role: "system", content: "You are a threat analyst." },
          { role: "user", content: "Analyze example.com" },
          { role: "assistant", content: "Example Corp has been targeted by APT28." },
        ]),
        qualityScore: 0.9,
        qualityBand: "high",
        analystRating: "accurate",
      },
    ];

    vi.mocked(db.getDITrainingExamplesForDomain).mockResolvedValueOnce(mockExamples as any);

    const context = await getIncidentTrainingContext("example.com", "technology");

    expect(context.totalExamplesUsed).toBe(1);
    expect(context.sources.sameDomain).toBe(1);
    expect(context.systemPromptAddition).toContain("Historical Incident Intelligence Context");
    expect(db.incrementDITrainingUsage).toHaveBeenCalledWith(["ditd_test1"]);
  });

  it("should fall back to sector examples when no domain match", async () => {
    vi.mocked(db.getDITrainingExamplesForDomain).mockResolvedValueOnce([]);
    vi.mocked(db.getDITrainingExamplesForSector).mockResolvedValueOnce([
      {
        exampleId: "ditd_sector1",
        domain: "other-tech.com",
        exampleType: "actor_attribution",
        trainingMessages: JSON.stringify([
          { role: "system", content: "You are a threat analyst." },
          { role: "user", content: "Analyze other-tech.com" },
          { role: "assistant", content: "Other Tech was targeted by APT29." },
        ]),
        qualityScore: 0.8,
        qualityBand: "high",
        analystRating: "accurate",
      },
    ] as any);

    const context = await getIncidentTrainingContext("new-domain.com", "technology");

    expect(context.totalExamplesUsed).toBe(1);
    expect(context.sources.sameSector).toBe(1);
  });

  it("should respect maxExamples limit", async () => {
    const manyExamples = Array.from({ length: 20 }, (_, i) => ({
      exampleId: `ditd_bulk${i}`,
      domain: "example.com",
      exampleType: "incident_context",
      trainingMessages: JSON.stringify([
        { role: "system", content: "Analyst" },
        { role: "user", content: "Analyze" },
        { role: "assistant", content: `Short result ${i}` },
      ]),
      qualityScore: 0.7,
      qualityBand: "medium",
      analystRating: "not_reviewed",
    }));

    vi.mocked(db.getDITrainingExamplesForDomain).mockResolvedValueOnce(manyExamples as any);

    const context = await getIncidentTrainingContext("example.com", undefined, { maxExamples: 3 });

    expect(context.totalExamplesUsed).toBeLessThanOrEqual(3);
  });

  it("should skip rejected quality examples", async () => {
    vi.mocked(db.getDITrainingExamplesForDomain).mockResolvedValueOnce([
      {
        exampleId: "ditd_rejected",
        domain: "example.com",
        exampleType: "incident_context",
        trainingMessages: JSON.stringify([
          { role: "system", content: "Analyst" },
          { role: "user", content: "Analyze" },
          { role: "assistant", content: "Bad data" },
        ]),
        qualityScore: 0.1,
        qualityBand: "rejected",
        analystRating: "inaccurate",
      },
    ] as any);

    const context = await getIncidentTrainingContext("example.com");

    expect(context.totalExamplesUsed).toBe(0);
  });

  it("should build compact prompt context for incident search", async () => {
    vi.mocked(db.getDITrainingExamplesForDomain).mockResolvedValueOnce([
      {
        exampleId: "ditd_compact1",
        domain: "example.com",
        exampleType: "ransomware_profile",
        trainingMessages: JSON.stringify([
          { role: "system", content: "Analyst" },
          { role: "user", content: "Analyze" },
          { role: "assistant", content: "LockBit targeted Example Corp in June 2024." },
        ]),
        qualityScore: 0.85,
        qualityBand: "high",
        analystRating: "accurate",
      },
    ] as any);

    const prompt = await getIncidentSearchPromptContext("example.com");

    expect(prompt).toContain("Historical Incident Intelligence Context");
    expect(prompt).toContain("LockBit");
  });

  it("should handle errors gracefully", async () => {
    vi.mocked(db.getDITrainingExamplesForDomain).mockRejectedValueOnce(new Error("DB connection failed"));

    const context = await getIncidentTrainingContext("example.com");

    expect(context.systemPromptAddition).toBe("");
    expect(context.totalExamplesUsed).toBe(0);
  });
});
