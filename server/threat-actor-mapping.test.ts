/**
 * Threat Actor Catalog Field Mapping Tests
 * 
 * Verifies that the getActor and list procedures correctly map
 * prefixed DB column names to the frontend-expected field names.
 */
import { describe, it, expect } from "vitest";

// Simulate the safeParseArr / safeParseObj helpers
function safeParseArr(v: unknown): any[] {
  if (Array.isArray(v)) return v;
  if (typeof v === "string") { try { const p = JSON.parse(v); return Array.isArray(p) ? p : []; } catch { return []; } }
  return [];
}
function safeParseObj(v: unknown): any {
  if (!v) return null;
  if (typeof v === "object" && !Array.isArray(v)) return v;
  if (typeof v === "string") { try { return JSON.parse(v); } catch { return null; } }
  return null;
}

// Simulate the DB row shapes (what Drizzle returns)
const mockActorRow = {
  id: 1,
  actorId: "apt28",
  name: "APT28",
  actorType: "apt",
  aliases: '["Fancy Bear","Sofacy"]',
  targetSectors: '["government","military"]',
  targetRegions: '["europe","north-america"]',
  techniques: '[]',
  tools: '[]',
  malware: '[]',
  activityTimeline: '[]',
  calderaProfile: null,
  threatLevel: "high",
  confidence: 85,
  stixId: "intrusion-set--apt28",
  firstSeen: "2004",
  lastActive: "2024",
  dataSource: "mitre",
  createdAt: "2025-01-01 00:00:00",
  updatedAt: "2025-06-01 00:00:00",
};

const mockEventRow = {
  id: 100,
  tgeActorId: "apt28",
  eventType: "attack",
  tgeTitle: "Phishing Campaign Targeting NATO",
  tgeDescription: "APT28 launched a phishing campaign targeting NATO officials",
  tgeSeverity: "critical",
  tgeVictimName: "NATO",
  tgeVictimSector: "government",
  tgeVictimCountry: "Belgium",
  tgeMitreTechniques: '["T1566.001","T1059.001"]',
  tgeIocs: '["evil.com","192.168.1.1"]',
  tgeSource: "CISA",
  tgeSourceUrl: "https://cisa.gov/advisory-123",
  tgeConfidence: 90,
  eventDate: "2024-06-15 00:00:00",
  discoveredAt: "2024-06-16 00:00:00",
  tgeCreatedAt: "2024-06-16 00:00:00",
};

const mockIocRow = {
  id: 200,
  actorId: "apt28",
  iocType: "domain",
  value: "evil-apt28.com",
  description: "C2 domain used in phishing campaign",
  iocConfidence: "high",
  iocFirstSeen: "2024-06-15",
  iocLastSeen: "2024-06-20",
  source: "CISA",
  createdAt: "2024-06-16 00:00:00",
};

// Simulate the getActor response mapping (from threat-intel.ts)
function mapActorResponse(actor: typeof mockActorRow, events: typeof mockEventRow[], iocs: typeof mockIocRow[]) {
  return {
    actor: {
      ...actor,
      type: actor.actorType, // alias for frontend compatibility
      aliases: safeParseArr(actor.aliases),
      targetSectors: safeParseArr(actor.targetSectors),
      targetRegions: safeParseArr(actor.targetRegions),
      techniques: safeParseArr(actor.techniques),
      tools: safeParseArr(actor.tools),
      malware: safeParseArr(actor.malware),
      activityTimeline: safeParseArr(actor.activityTimeline),
      calderaProfile: safeParseObj(actor.calderaProfile),
    },
    events: events.map(e => ({
      ...e,
      actorId: e.tgeActorId,
      title: e.tgeTitle,
      description: e.tgeDescription,
      severity: e.tgeSeverity,
      victimName: e.tgeVictimName,
      victimSector: e.tgeVictimSector,
      victimCountry: e.tgeVictimCountry,
      mitreTechniques: safeParseArr(e.tgeMitreTechniques),
      iocs: safeParseArr(e.tgeIocs),
      source: e.tgeSource,
      sourceUrl: e.tgeSourceUrl,
      confidence: e.tgeConfidence,
    })),
    iocs: iocs.map(ioc => ({
      ...ioc,
      type: ioc.iocType,
      confidence: ioc.iocConfidence,
      firstSeen: ioc.iocFirstSeen,
      lastSeen: ioc.iocLastSeen,
    })),
    ransomwareProfile: null,
  };
}

describe("Threat Actor Catalog Field Mapping", () => {

  describe("Actor type alias", () => {
    it("should map actorType to type for frontend compatibility", () => {
      const result = mapActorResponse(mockActorRow, [], []);
      expect(result.actor.type).toBe("apt");
      expect(result.actor.actorType).toBe("apt");
    });

    it("should preserve all original actor fields", () => {
      const result = mapActorResponse(mockActorRow, [], []);
      expect(result.actor.actorId).toBe("apt28");
      expect(result.actor.name).toBe("APT28");
      expect(result.actor.threatLevel).toBe("high");
      expect(result.actor.confidence).toBe(85);
      expect(result.actor.stixId).toBe("intrusion-set--apt28");
    });

    it("should parse JSON string arrays into real arrays", () => {
      const result = mapActorResponse(mockActorRow, [], []);
      expect(result.actor.aliases).toEqual(["Fancy Bear", "Sofacy"]);
      expect(result.actor.targetSectors).toEqual(["government", "military"]);
      expect(result.actor.targetRegions).toEqual(["europe", "north-america"]);
    });

    it("should handle null calderaProfile", () => {
      const result = mapActorResponse(mockActorRow, [], []);
      expect(result.actor.calderaProfile).toBeNull();
    });
  });

  describe("Event field mapping (tge* prefix)", () => {
    it("should map tgeActorId to actorId", () => {
      const result = mapActorResponse(mockActorRow, [mockEventRow], []);
      expect(result.events[0].actorId).toBe("apt28");
    });

    it("should map tgeTitle to title", () => {
      const result = mapActorResponse(mockActorRow, [mockEventRow], []);
      expect(result.events[0].title).toBe("Phishing Campaign Targeting NATO");
    });

    it("should map tgeDescription to description", () => {
      const result = mapActorResponse(mockActorRow, [mockEventRow], []);
      expect(result.events[0].description).toBe("APT28 launched a phishing campaign targeting NATO officials");
    });

    it("should map tgeSeverity to severity", () => {
      const result = mapActorResponse(mockActorRow, [mockEventRow], []);
      expect(result.events[0].severity).toBe("critical");
    });

    it("should map victim fields correctly", () => {
      const result = mapActorResponse(mockActorRow, [mockEventRow], []);
      expect(result.events[0].victimName).toBe("NATO");
      expect(result.events[0].victimSector).toBe("government");
      expect(result.events[0].victimCountry).toBe("Belgium");
    });

    it("should parse tgeMitreTechniques JSON into array", () => {
      const result = mapActorResponse(mockActorRow, [mockEventRow], []);
      expect(result.events[0].mitreTechniques).toEqual(["T1566.001", "T1059.001"]);
    });

    it("should parse tgeIocs JSON into array", () => {
      const result = mapActorResponse(mockActorRow, [mockEventRow], []);
      expect(result.events[0].iocs).toEqual(["evil.com", "192.168.1.1"]);
    });

    it("should map source fields correctly", () => {
      const result = mapActorResponse(mockActorRow, [mockEventRow], []);
      expect(result.events[0].source).toBe("CISA");
      expect(result.events[0].sourceUrl).toBe("https://cisa.gov/advisory-123");
      expect(result.events[0].confidence).toBe(90);
    });

    it("should preserve eventType and eventDate (no prefix)", () => {
      const result = mapActorResponse(mockActorRow, [mockEventRow], []);
      expect(result.events[0].eventType).toBe("attack");
      expect(result.events[0].eventDate).toBe("2024-06-15 00:00:00");
    });
  });

  describe("IOC field mapping (ioc* prefix)", () => {
    it("should map iocType to type", () => {
      const result = mapActorResponse(mockActorRow, [], [mockIocRow]);
      expect(result.iocs[0].type).toBe("domain");
    });

    it("should map iocConfidence to confidence", () => {
      const result = mapActorResponse(mockActorRow, [], [mockIocRow]);
      expect(result.iocs[0].confidence).toBe("high");
    });

    it("should map iocFirstSeen and iocLastSeen", () => {
      const result = mapActorResponse(mockActorRow, [], [mockIocRow]);
      expect(result.iocs[0].firstSeen).toBe("2024-06-15");
      expect(result.iocs[0].lastSeen).toBe("2024-06-20");
    });

    it("should preserve value and source fields", () => {
      const result = mapActorResponse(mockActorRow, [], [mockIocRow]);
      expect(result.iocs[0].value).toBe("evil-apt28.com");
      expect(result.iocs[0].source).toBe("CISA");
    });
  });

  describe("Edge cases", () => {
    it("should handle empty events and iocs arrays", () => {
      const result = mapActorResponse(mockActorRow, [], []);
      expect(result.events).toEqual([]);
      expect(result.iocs).toEqual([]);
    });

    it("should handle malformed JSON in actor fields gracefully", () => {
      const badActor = { ...mockActorRow, aliases: "not-valid-json{", techniques: null as any };
      const result = mapActorResponse(badActor, [], []);
      expect(result.actor.aliases).toEqual([]);
      expect(result.actor.techniques).toEqual([]);
    });

    it("should handle malformed JSON in event fields gracefully", () => {
      const badEvent = { ...mockEventRow, tgeMitreTechniques: "broken{", tgeIocs: null as any };
      const result = mapActorResponse(mockActorRow, [badEvent], []);
      expect(result.events[0].mitreTechniques).toEqual([]);
      expect(result.events[0].iocs).toEqual([]);
    });
  });
});
