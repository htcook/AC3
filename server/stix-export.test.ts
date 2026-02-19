import { describe, it, expect } from "vitest";
import {
  threatActorToStix,
  iocToStix,
  iocFeedToStix,
  engagementToStix,
  exploitToStix,
  createStixBundle,
  getBundleStats,
  TAXII_COLLECTIONS,
  createAceC3Identity,
  type ThreatActorInput,
  type IocInput,
  type IocFeedInput,
  type EngagementInput,
  type ExploitInput,
} from "./lib/stix-generator";

// ─── Test Data (matching actual interface shapes) ─────────────────────────────

const mockThreatActor: ThreatActorInput = {
  id: 1,
  actorId: "ta-001",
  name: "APT29",
  aliases: JSON.stringify(["Cozy Bear", "The Dukes", "NOBELIUM"]),
  type: "apt",
  origin: "Russia",
  description: "Russian state-sponsored threat group known for cyber espionage",
  motivation: "espionage",
  threatLevel: "critical",
  sophistication: "advanced",
  confidence: 95,
  firstSeen: "2008-01-01",
  lastActive: "2024-12-01",
  techniques: JSON.stringify([
    { id: "T1566", name: "Phishing", tactic: "initial-access" },
    { id: "T1059", name: "Command and Scripting Interpreter", tactic: "execution" },
    { id: "T1053", name: "Scheduled Task/Job", tactic: "persistence" },
  ]),
  targetSectors: JSON.stringify(["Government", "Defense", "Technology"]),
  tools: JSON.stringify(["Cobalt Strike", "Mimikatz", "SolarWinds"]),
  malware: JSON.stringify(["SUNBURST", "TEARDROP", "WellMess"]),
  createdAt: new Date("2024-01-01"),
};

const mockIoc: IocInput = {
  id: 1,
  type: "ip",
  value: "192.168.1.100",
  confidence: "high",
  firstSeen: "2024-06-01",
  lastSeen: "2024-12-01",
  source: "internal",
  description: "Command and control server",
  actorId: "ta-001",
};

const mockIocFeed: IocFeedInput = {
  id: 1,
  feedSource: "cisa_kev",
  feedType: "vulnerability",
  title: "CVE-2024-1234 Active Exploitation",
  iocType: "cve",
  iocValue: "CVE-2024-1234",
  cveId: "CVE-2024-1234",
  severity: "critical",
  tags: JSON.stringify(["kev", "critical"]),
  createdAt: new Date("2024-06-15"),
};

const mockEngagement: EngagementInput = {
  id: 1,
  name: "Operation Red Storm",
  customerName: "Acme Corp",
  engagementType: "red_team",
  status: "completed",
  description: "Test external perimeter defenses and internal lateral movement. Scope: External network, internal AD environment",
  createdAt: new Date("2024-01-10"),
};

const mockExploit: ExploitInput = {
  id: 1,
  catalogId: "exploit-001",
  name: "EternalBlue",
  description: "SMBv1 remote code execution vulnerability",
  source: "metasploit",
  category: "remote_code_execution",
  cveIds: JSON.stringify(["CVE-2017-0144"]),
  cvssScore: 9.8,
  severity: "critical",
  platform: "windows",
  mitreId: "T1210",
  mitreName: "Exploitation of Remote Services",
  mitreTactic: "lateral-movement",
};

// ─── STIX Bundle Structure Tests ──────────────────────────────────────────────

describe("STIX 2.1 Bundle Structure", () => {
  it("creates a valid STIX 2.1 bundle with correct type", () => {
    const bundle = createStixBundle([]);
    expect(bundle.type).toBe("bundle");
    expect(bundle.id).toMatch(/^bundle--[0-9a-f-]+$/);
    expect(bundle.objects).toBeInstanceOf(Array);
  });

  it("includes identity object as first element", () => {
    const bundle = createStixBundle([]);
    expect(bundle.objects.length).toBeGreaterThanOrEqual(1);
    const identity = bundle.objects[0];
    expect(identity.type).toBe("identity");
    expect(identity.name).toBe("Ace C3 - Cyber Campaign Command");
    expect(identity.identity_class).toBe("organization");
  });

  it("includes TLP:WHITE marking definition", () => {
    const bundle = createStixBundle([]);
    const marking = bundle.objects.find((o: any) => o.type === "marking-definition");
    expect(marking).toBeDefined();
    expect(marking.name).toBe("TLP:WHITE");
  });

  it("deduplicates objects by ID", () => {
    const stixObjects = threatActorToStix(mockThreatActor);
    // Add same objects twice
    const bundle = createStixBundle([...stixObjects, ...stixObjects]);
    const ids = bundle.objects.map((o: any) => o.id);
    const uniqueIds = new Set(ids);
    expect(ids.length).toBe(uniqueIds.size);
  });

  it("cleans undefined values from objects", () => {
    const bundle = createStixBundle([]);
    for (const obj of bundle.objects) {
      for (const val of Object.values(obj)) {
        expect(val).not.toBeUndefined();
        expect(val).not.toBeNull();
      }
    }
  });
});

// ─── Ace C3 Identity Tests ───────────────────────────────────────────────────

describe("Ace C3 Identity", () => {
  it("creates identity with correct fields", () => {
    const identity = createAceC3Identity();
    expect(identity.type).toBe("identity");
    expect(identity.spec_version).toBe("2.1");
    expect(identity.name).toBe("Ace C3 - Cyber Campaign Command");
    expect(identity.identity_class).toBe("organization");
    expect(identity.sectors).toContain("technology");
  });
});

// ─── Bundle Stats Tests ──────────────────────────────────────────────────────

describe("Bundle Stats", () => {
  it("returns correct stats for a bundle", () => {
    const stixObjects = threatActorToStix(mockThreatActor);
    const bundle = createStixBundle(stixObjects);
    const stats = getBundleStats(bundle);

    expect(stats.totalObjects).toBeGreaterThan(0);
    expect(stats.byType).toBeDefined();
    expect(stats.bundleSize).toBeGreaterThan(0);
    expect(stats.generatedAt).toBeDefined();
    expect(typeof stats.byType["intrusion-set"]).toBe("number");
  });

  it("counts object types correctly", () => {
    const actorStix = threatActorToStix(mockThreatActor);
    const bundle = createStixBundle(actorStix);
    const stats = getBundleStats(bundle);

    // Should have identity + marking-definition + intrusion-set + attack-patterns + malware + tools + relationships
    expect(Object.keys(stats.byType).length).toBeGreaterThanOrEqual(3);
  });
});

// ─── Threat Actor Conversion Tests ────────────────────────────────────────────

describe("Threat Actor to STIX", () => {
  it("converts a threat actor to intrusion-set STIX object", () => {
    const stixObjects = threatActorToStix(mockThreatActor);
    expect(stixObjects.length).toBeGreaterThan(0);

    const intrusionSet = stixObjects.find((o) => o.type === "intrusion-set");
    expect(intrusionSet).toBeDefined();
    expect(intrusionSet!.name).toBe("APT29");
    expect(intrusionSet!.id).toMatch(/^intrusion-set--/);
    expect(intrusionSet!.spec_version).toBe("2.1");
  });

  it("includes aliases from JSON array string", () => {
    const stixObjects = threatActorToStix(mockThreatActor);
    const intrusionSet = stixObjects.find((o) => o.type === "intrusion-set");
    expect(intrusionSet!.aliases).toContain("Cozy Bear");
    expect(intrusionSet!.aliases).toContain("The Dukes");
    expect(intrusionSet!.aliases).toContain("NOBELIUM");
  });

  it("maps actor type to STIX resource_level", () => {
    const stixObjects = threatActorToStix(mockThreatActor);
    const intrusionSet = stixObjects.find((o) => o.type === "intrusion-set");
    expect(intrusionSet!.resource_level).toBe("government");
  });

  it("maps motivation to STIX primary_motivation", () => {
    const stixObjects = threatActorToStix(mockThreatActor);
    const intrusionSet = stixObjects.find((o) => o.type === "intrusion-set");
    expect(intrusionSet!.primary_motivation).toBe("espionage");
  });

  it("generates attack-pattern objects for techniques", () => {
    const stixObjects = threatActorToStix(mockThreatActor);
    const attackPatterns = stixObjects.filter((o) => o.type === "attack-pattern");
    expect(attackPatterns.length).toBe(3); // T1566, T1059, T1053
    attackPatterns.forEach((ap) => {
      expect(ap.id).toMatch(/^attack-pattern--/);
      expect(ap.external_references).toBeDefined();
      expect(ap.external_references[0].source_name).toBe("mitre-attack");
    });
  });

  it("generates malware objects", () => {
    const stixObjects = threatActorToStix(mockThreatActor);
    const malware = stixObjects.filter((o) => o.type === "malware");
    expect(malware.length).toBe(3); // SUNBURST, TEARDROP, WellMess
    malware.forEach((m) => {
      expect(m.id).toMatch(/^malware--/);
      expect(m.is_family).toBe(true);
    });
  });

  it("generates tool objects", () => {
    const stixObjects = threatActorToStix(mockThreatActor);
    const tools = stixObjects.filter((o) => o.type === "tool");
    expect(tools.length).toBe(3); // Cobalt Strike, Mimikatz, SolarWinds
    tools.forEach((t) => {
      expect(t.id).toMatch(/^tool--/);
    });
  });

  it("generates relationship objects linking actor to TTPs/malware/tools", () => {
    const stixObjects = threatActorToStix(mockThreatActor);
    const relationships = stixObjects.filter((o) => o.type === "relationship");
    expect(relationships.length).toBe(9); // 3 attack-patterns + 3 malware + 3 tools
    relationships.forEach((r) => {
      expect(r.id).toMatch(/^relationship--/);
      expect(r.source_ref).toMatch(/^intrusion-set--/);
      expect(r.target_ref).toBeDefined();
      expect(r.relationship_type).toBe("uses");
    });
  });

  it("includes confidence score", () => {
    const stixObjects = threatActorToStix(mockThreatActor);
    const intrusionSet = stixObjects.find((o) => o.type === "intrusion-set");
    expect(intrusionSet!.confidence).toBe(95);
  });

  it("includes TLP:WHITE marking", () => {
    const stixObjects = threatActorToStix(mockThreatActor);
    const intrusionSet = stixObjects.find((o) => o.type === "intrusion-set");
    expect(intrusionSet!.object_marking_refs).toContain(
      "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    );
  });

  it("handles actor with no techniques, malware, or tools", () => {
    const minimalActor: ThreatActorInput = {
      ...mockThreatActor,
      techniques: null,
      malware: null,
      tools: null,
      aliases: null,
    };
    const stixObjects = threatActorToStix(minimalActor);
    const intrusionSet = stixObjects.find((o) => o.type === "intrusion-set");
    expect(intrusionSet).toBeDefined();
    expect(intrusionSet!.name).toBe("APT29");
    // Should only have the intrusion-set itself
    expect(stixObjects.filter((o) => o.type === "attack-pattern").length).toBe(0);
    expect(stixObjects.filter((o) => o.type === "malware").length).toBe(0);
    expect(stixObjects.filter((o) => o.type === "tool").length).toBe(0);
  });
});

// ─── IOC Conversion Tests ─────────────────────────────────────────────────────

describe("IOC to STIX", () => {
  it("converts an IPv4 IOC to STIX indicator", () => {
    const indicator = iocToStix(mockIoc);
    expect(indicator).toBeDefined();
    expect(indicator!.type).toBe("indicator");
    expect(indicator!.id).toMatch(/^indicator--/);
    expect(indicator!.pattern_type).toBe("stix");
    expect(indicator!.pattern).toContain("ipv4-addr:value");
    expect(indicator!.pattern).toContain("192.168.1.100");
  });

  it("converts domain IOC correctly", () => {
    const domainIoc: IocInput = { ...mockIoc, type: "domain", value: "evil.example.com" };
    const indicator = iocToStix(domainIoc);
    expect(indicator).toBeDefined();
    expect(indicator!.pattern).toContain("domain-name:value");
  });

  it("converts URL IOC correctly", () => {
    const urlIoc: IocInput = { ...mockIoc, type: "url", value: "https://evil.example.com/malware" };
    const indicator = iocToStix(urlIoc);
    expect(indicator).toBeDefined();
    expect(indicator!.pattern).toContain("url:value");
  });

  it("converts hash IOC correctly", () => {
    const hashIoc: IocInput = { ...mockIoc, type: "hash_sha256", value: "abc123def456" };
    const indicator = iocToStix(hashIoc);
    expect(indicator).toBeDefined();
    expect(indicator!.pattern).toContain("file:hashes");
  });

  it("converts email IOC correctly", () => {
    const emailIoc: IocInput = { ...mockIoc, type: "email", value: "attacker@evil.com" };
    const indicator = iocToStix(emailIoc);
    expect(indicator).toBeDefined();
    expect(indicator!.pattern).toContain("email-addr:value");
  });

  it("maps confidence string to numeric score", () => {
    const indicator = iocToStix(mockIoc);
    expect(indicator!.confidence).toBe(85); // "high" maps to 85
  });

  it("returns null for unknown IOC type", () => {
    const unknownIoc: IocInput = { ...mockIoc, type: "unknown_type", value: "something" };
    const indicator = iocToStix(unknownIoc);
    expect(indicator).toBeNull();
  });

  it("includes created_by_ref pointing to Ace C3 identity", () => {
    const indicator = iocToStix(mockIoc);
    expect(indicator!.created_by_ref).toBe("identity--ace-c3-00000000-0000-4000-a000-000000000001");
  });
});

// ─── IOC Feed Conversion Tests ────────────────────────────────────────────────

describe("IOC Feed to STIX", () => {
  it("creates vulnerability object for CVE entries", () => {
    const stixObjects = iocFeedToStix(mockIocFeed);
    const vuln = stixObjects.find((o) => o.type === "vulnerability");
    expect(vuln).toBeDefined();
    expect(vuln!.name).toBe("CVE-2024-1234");
    expect(vuln!.external_references).toBeDefined();
    const cveRef = vuln!.external_references.find((r: any) => r.source_name === "cve");
    expect(cveRef).toBeDefined();
    expect(cveRef.external_id).toBe("CVE-2024-1234");
  });

  it("creates indicator for non-CVE feed entries", () => {
    const urlFeed: IocFeedInput = {
      ...mockIocFeed,
      iocType: "url",
      iocValue: "https://malware.example.com/payload",
      feedSource: "abusech_urlhaus",
      feedType: "url",
      cveId: null,
    };
    const stixObjects = iocFeedToStix(urlFeed);
    const indicator = stixObjects.find((o) => o.type === "indicator");
    expect(indicator).toBeDefined();
    expect(indicator!.pattern).toContain("url:value");
  });

  it("handles feed entry with null cveId", () => {
    const feedNoCve: IocFeedInput = { ...mockIocFeed, cveId: null };
    const stixObjects = iocFeedToStix(feedNoCve);
    // Should not have vulnerability object
    const vulns = stixObjects.filter((o) => o.type === "vulnerability");
    expect(vulns.length).toBe(0);
  });

  it("sets confidence based on severity", () => {
    const critFeed: IocFeedInput = { ...mockIocFeed, severity: "critical", iocType: "ip", iocValue: "1.2.3.4" };
    const stixObjects = iocFeedToStix(critFeed);
    const indicator = stixObjects.find((o) => o.type === "indicator");
    if (indicator) {
      expect(indicator.confidence).toBe(90);
    }
  });
});

// ─── Engagement Conversion Tests ──────────────────────────────────────────────

describe("Engagement to STIX", () => {
  it("converts an engagement to STIX campaign object", () => {
    const campaign = engagementToStix(mockEngagement);
    expect(campaign.type).toBe("campaign");
    expect(campaign.id).toMatch(/^campaign--/);
    expect(campaign.name).toBe("Operation Red Storm");
    expect(campaign.spec_version).toBe("2.1");
  });

  it("includes engagement description", () => {
    const campaign = engagementToStix(mockEngagement);
    expect(campaign.description).toContain("Test external perimeter defenses");
  });

  it("includes engagement type in objective", () => {
    const campaign = engagementToStix(mockEngagement);
    expect(campaign.objective).toContain("red");
  });

  it("sets first_seen from createdAt", () => {
    const campaign = engagementToStix(mockEngagement);
    expect(campaign.first_seen).toBeDefined();
  });

  it("includes Ace C3 external reference", () => {
    const campaign = engagementToStix(mockEngagement);
    expect(campaign.external_references).toBeDefined();
    const aceRef = campaign.external_references.find((r: any) => r.source_name === "Ace C3");
    expect(aceRef).toBeDefined();
    expect(aceRef.external_id).toBe("engagement-1");
  });
});

// ─── Exploit Conversion Tests ─────────────────────────────────────────────────

describe("Exploit to STIX", () => {
  it("converts an exploit to STIX objects", () => {
    const stixObjects = exploitToStix(mockExploit);
    expect(stixObjects.length).toBeGreaterThan(0);
  });

  it("creates attack-pattern when mitreId is present", () => {
    const stixObjects = exploitToStix(mockExploit);
    const ap = stixObjects.find((o) => o.type === "attack-pattern");
    expect(ap).toBeDefined();
    expect(ap!.name).toBe("Exploitation of Remote Services");
    expect(ap!.external_references[0].source_name).toBe("mitre-attack");
    expect(ap!.external_references[0].external_id).toBe("T1210");
  });

  it("creates vulnerability object with CVE reference", () => {
    const stixObjects = exploitToStix(mockExploit);
    const vuln = stixObjects.find((o) => o.type === "vulnerability");
    expect(vuln).toBeDefined();
    expect(vuln!.name).toBe("CVE-2017-0144");
    const cveRef = vuln!.external_references.find((r: any) => r.source_name === "cve");
    expect(cveRef).toBeDefined();
    expect(cveRef.external_id).toBe("CVE-2017-0144");
  });

  it("handles exploit with no CVE (still creates attack-pattern)", () => {
    const noCveExploit: ExploitInput = { ...mockExploit, cveIds: null };
    const stixObjects = exploitToStix(noCveExploit);
    // Should still create attack-pattern from mitreId
    const ap = stixObjects.find((o) => o.type === "attack-pattern");
    expect(ap).toBeDefined();
    // But no vulnerability
    const vulns = stixObjects.filter((o) => o.type === "vulnerability");
    expect(vulns.length).toBe(0);
  });

  it("handles exploit with no mitreId (only creates vulnerabilities)", () => {
    const noMitreExploit: ExploitInput = { ...mockExploit, mitreId: null, mitreName: null, mitreTactic: null };
    const stixObjects = exploitToStix(noMitreExploit);
    const ap = stixObjects.find((o) => o.type === "attack-pattern");
    expect(ap).toBeUndefined();
    const vuln = stixObjects.find((o) => o.type === "vulnerability");
    expect(vuln).toBeDefined();
  });

  it("handles exploit with multiple CVEs", () => {
    const multiCveExploit: ExploitInput = {
      ...mockExploit,
      cveIds: JSON.stringify(["CVE-2017-0144", "CVE-2017-0145"]),
    };
    const stixObjects = exploitToStix(multiCveExploit);
    const vulns = stixObjects.filter((o) => o.type === "vulnerability");
    expect(vulns.length).toBe(2);
  });
});

// ─── TAXII Collections Tests ──────────────────────────────────────────────────

describe("TAXII Collections", () => {
  it("defines expected collections", () => {
    expect(TAXII_COLLECTIONS.length).toBe(5);
    const ids = TAXII_COLLECTIONS.map((c) => c.id);
    expect(ids).toContain("ace-c3-threat-actors");
    expect(ids).toContain("ace-c3-indicators");
    expect(ids).toContain("ace-c3-vulnerabilities");
    expect(ids).toContain("ace-c3-campaigns");
    expect(ids).toContain("ace-c3-all");
  });

  it("all collections have required TAXII fields", () => {
    TAXII_COLLECTIONS.forEach((col) => {
      expect(col.id).toBeDefined();
      expect(col.title).toBeDefined();
      expect(col.description).toBeDefined();
      expect(col.can_read).toBe(true);
      expect(col.can_write).toBe(false);
      expect(col.media_types).toContain("application/stix+json;version=2.1");
    });
  });
});

// ─── Deterministic ID Tests ──────────────────────────────────────────────────

describe("Deterministic STIX IDs", () => {
  it("generates same ID for same input", () => {
    const stix1 = threatActorToStix(mockThreatActor);
    const stix2 = threatActorToStix(mockThreatActor);
    const id1 = stix1.find((o) => o.type === "intrusion-set")!.id;
    const id2 = stix2.find((o) => o.type === "intrusion-set")!.id;
    expect(id1).toBe(id2);
  });

  it("generates different IDs for different inputs", () => {
    const actor2: ThreatActorInput = { ...mockThreatActor, id: 2, actorId: "ta-002", name: "APT28" };
    const stix1 = threatActorToStix(mockThreatActor);
    const stix2 = threatActorToStix(actor2);
    const id1 = stix1.find((o) => o.type === "intrusion-set")!.id;
    const id2 = stix2.find((o) => o.type === "intrusion-set")!.id;
    expect(id1).not.toBe(id2);
  });
});

// ─── Edge Cases ──────────────────────────────────────────────────────────────

describe("Edge Cases", () => {
  it("handles empty JSON array fields gracefully", () => {
    const emptyActor: ThreatActorInput = {
      ...mockThreatActor,
      aliases: "[]",
      techniques: "[]",
      tools: "[]",
      malware: "[]",
      targetSectors: "[]",
    };
    const stixObjects = threatActorToStix(emptyActor);
    const intrusionSet = stixObjects.find((o) => o.type === "intrusion-set");
    expect(intrusionSet).toBeDefined();
    // Only the intrusion-set, no attack-patterns/malware/tools
    expect(stixObjects.length).toBe(1);
  });

  it("creates valid bundle from mixed object types", () => {
    const allObjects = [
      ...threatActorToStix(mockThreatActor),
      ...(iocToStix(mockIoc) ? [iocToStix(mockIoc)!] : []),
      ...iocFeedToStix(mockIocFeed),
      engagementToStix(mockEngagement),
      ...exploitToStix(mockExploit),
    ];
    const bundle = createStixBundle(allObjects);
    expect(bundle.type).toBe("bundle");
    // identity + marking-definition + all the objects
    expect(bundle.objects.length).toBeGreaterThan(5);

    // All objects should have required STIX fields
    bundle.objects.forEach((obj: any) => {
      expect(obj.type).toBeDefined();
      expect(obj.id).toBeDefined();
      expect(obj.id).toMatch(new RegExp(`^${obj.type}--`));
    });
  });

  it("handles large number of objects without error", () => {
    const objects = [];
    for (let i = 0; i < 100; i++) {
      const actor: ThreatActorInput = {
        ...mockThreatActor,
        id: i,
        actorId: `ta-${i}`,
        name: `Actor ${i}`,
        techniques: null,
        malware: null,
        tools: null,
      };
      objects.push(...threatActorToStix(actor));
    }
    const bundle = createStixBundle(objects);
    // 100 intrusion-sets + identity + marking-definition
    expect(bundle.objects.length).toBe(102);
    const stats = getBundleStats(bundle);
    expect(stats.totalObjects).toBe(102);
  });

  it("empty bundle has identity and marking only", () => {
    const bundle = createStixBundle([]);
    expect(bundle.objects.length).toBe(2);
    expect(bundle.objects[0].type).toBe("identity");
    expect(bundle.objects[1].type).toBe("marking-definition");
  });
});
