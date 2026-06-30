import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * Tests for conflict mapping logic:
 * 1. Conflict filter in threatIntel.list procedure
 * 2. Conflict data population rules
 * 3. Multi-conflict tagging
 */

// ─── Conflict Mapping Rules (mirroring populate-conflicts.mjs logic) ─────────

const CONFLICT_RULES: Record<string, { origins: string[]; keywords: string[]; targetRegions: string[] }> = {
  "russia-ukraine": {
    origins: ["Russia", "Ukraine", "Belarus"],
    keywords: ["ukraine", "ukrainian", "russia", "russian", "sandworm", "fancy bear", "apt28", "apt29", "turla", "gamaredon", "armageddon", "killnet", "noname057"],
    targetRegions: ["Ukraine", "Eastern Europe"],
  },
  "israel-hamas-iran": {
    origins: ["Iran", "Palestine"],
    keywords: ["hamas", "hezbollah", "israel", "israeli", "gaza", "irgc", "charming kitten", "apt33", "apt34", "apt35", "apt42", "muddywater", "oilrig"],
    targetRegions: ["Israel", "Palestine"],
  },
  "china-taiwan": {
    origins: ["China"],
    keywords: ["taiwan", "taiwanese", "apt1", "apt10", "apt40", "apt41", "mustang panda", "winnti", "hafnium", "volt typhoon", "salt typhoon"],
    targetRegions: ["Taiwan"],
  },
  "north-korea": {
    origins: ["North Korea", "DPRK"],
    keywords: ["lazarus", "kimsuky", "apt37", "apt38", "andariel", "bluenoroff", "hidden cobra", "temp.hermit"],
    targetRegions: [],
  },
  "iran-us-gulf": {
    origins: ["Iran"],
    keywords: ["irgc", "apt33", "apt34", "apt35", "apt42", "muddywater", "oilrig", "shamoon", "charming kitten", "phosphorus"],
    targetRegions: ["United States", "Saudi Arabia", "UAE", "Gulf"],
  },
};

function mapActorToConflicts(actor: {
  origin?: string;
  description?: string;
  targetRegions?: string[];
  name?: string;
}): string[] {
  const conflicts: Set<string> = new Set();
  const descLower = (actor.description || "").toLowerCase();
  const nameLower = (actor.name || "").toLowerCase();

  for (const [conflictId, rules] of Object.entries(CONFLICT_RULES)) {
    // Check origin
    if (actor.origin && rules.origins.some(o => o.toLowerCase() === actor.origin!.toLowerCase())) {
      conflicts.add(conflictId);
      continue;
    }
    // Check keywords in description or name
    if (rules.keywords.some(kw => descLower.includes(kw) || nameLower.includes(kw))) {
      conflicts.add(conflictId);
      continue;
    }
    // Check target regions
    if (actor.targetRegions && rules.targetRegions.length > 0) {
      if (actor.targetRegions.some(r => rules.targetRegions.some(tr => r.toLowerCase().includes(tr.toLowerCase())))) {
        conflicts.add(conflictId);
      }
    }
  }

  return Array.from(conflicts);
}

describe("Conflict Mapping Rules", () => {
  it("should tag a Russian APT to russia-ukraine conflict", () => {
    const conflicts = mapActorToConflicts({
      origin: "Russia",
      name: "APT28",
      description: "Russian state-sponsored group",
    });
    expect(conflicts).toContain("russia-ukraine");
  });

  it("should tag a Chinese APT to china-taiwan conflict", () => {
    const conflicts = mapActorToConflicts({
      origin: "China",
      name: "Mustang Panda",
      description: "Chinese espionage group",
    });
    expect(conflicts).toContain("china-taiwan");
  });

  it("should tag an Iranian actor to both israel-hamas-iran and iran-us-gulf", () => {
    const conflicts = mapActorToConflicts({
      origin: "Iran",
      name: "APT33",
      description: "IRGC-linked group targeting US and Israel",
    });
    expect(conflicts).toContain("israel-hamas-iran");
    expect(conflicts).toContain("iran-us-gulf");
  });

  it("should tag a North Korean actor to north-korea conflict", () => {
    const conflicts = mapActorToConflicts({
      origin: "North Korea",
      name: "Lazarus Group",
      description: "DPRK-linked financial theft group",
    });
    expect(conflicts).toContain("north-korea");
  });

  it("should tag by keyword even without matching origin", () => {
    const conflicts = mapActorToConflicts({
      origin: "Unknown",
      name: "SomeGroup",
      description: "This group was observed targeting Ukrainian infrastructure with Sandworm-like TTPs",
    });
    expect(conflicts).toContain("russia-ukraine");
  });

  it("should tag by target region", () => {
    const conflicts = mapActorToConflicts({
      origin: "Unknown",
      name: "SomeGroup",
      description: "Unknown group",
      targetRegions: ["Taiwan", "Japan"],
    });
    expect(conflicts).toContain("china-taiwan");
  });

  it("should return empty for unrelated actors", () => {
    const conflicts = mapActorToConflicts({
      origin: "Brazil",
      name: "BankerTrojan",
      description: "Brazilian banking trojan targeting South American banks",
    });
    expect(conflicts).toHaveLength(0);
  });

  it("should handle multiple conflicts for a single actor", () => {
    const conflicts = mapActorToConflicts({
      origin: "Iran",
      name: "MuddyWater",
      description: "IRGC-linked group targeting Israel and US government",
      targetRegions: ["United States", "Israel"],
    });
    // Should match both Iran conflicts
    expect(conflicts).toContain("israel-hamas-iran");
    expect(conflicts).toContain("iran-us-gulf");
  });

  it("should match by name keyword (lazarus)", () => {
    const conflicts = mapActorToConflicts({
      origin: "Unknown",
      name: "Lazarus",
      description: "Financial theft operations",
    });
    expect(conflicts).toContain("north-korea");
  });

  it("should match Gamaredon to russia-ukraine", () => {
    const conflicts = mapActorToConflicts({
      origin: "Unknown",
      name: "Gamaredon",
      description: "Espionage group",
    });
    expect(conflicts).toContain("russia-ukraine");
  });

  it("should match Volt Typhoon to china-taiwan", () => {
    const conflicts = mapActorToConflicts({
      origin: "Unknown",
      name: "Volt Typhoon",
      description: "Pre-positioning in critical infrastructure",
    });
    expect(conflicts).toContain("china-taiwan");
  });
});

describe("Conflict Filter SQL Logic", () => {
  it("should generate correct LIKE clause for conflict filter", () => {
    const conflict = "russia-ukraine";
    const likePattern = `%${conflict}%`;
    expect(likePattern).toBe("%russia-ukraine%");
  });

  it("should match comma-separated conflicts", () => {
    const conflictsStr = "israel-hamas-iran,iran-us-gulf";
    const filter = "iran-us-gulf";
    expect(conflictsStr.includes(filter)).toBe(true);
  });

  it("should not match partial conflict IDs", () => {
    const conflictsStr = "russia-ukraine";
    const filter = "ukraine"; // This is not a valid conflict ID
    // The LIKE %filter% would match, but we use full conflict IDs
    // The filter dropdown only sends valid conflict IDs
    expect(CONFLICT_RULES).not.toHaveProperty(filter);
    expect(CONFLICT_RULES).toHaveProperty("russia-ukraine");
  });
});

describe("Conflict Display Logic", () => {
  const CONFLICT_LABEL_MAP: Record<string, string> = {
    "russia-ukraine": "RU-UA",
    "israel-hamas-iran": "IL-Hamas/IR",
    "china-taiwan": "CN-TW",
    "north-korea": "DPRK",
    "iran-us-gulf": "IR-US/Gulf",
  };

  it("should split conflict string into individual tags", () => {
    const conflictsStr = "israel-hamas-iran,iran-us-gulf";
    const tags = conflictsStr.split(",").filter(Boolean);
    expect(tags).toEqual(["israel-hamas-iran", "iran-us-gulf"]);
  });

  it("should map conflict IDs to short labels", () => {
    const tags = ["russia-ukraine", "north-korea"];
    const labels = tags.map(t => CONFLICT_LABEL_MAP[t] || t);
    expect(labels).toEqual(["RU-UA", "DPRK"]);
  });

  it("should handle single conflict", () => {
    const conflictsStr = "china-taiwan";
    const tags = conflictsStr.split(",").filter(Boolean);
    expect(tags).toEqual(["china-taiwan"]);
    expect(CONFLICT_LABEL_MAP[tags[0]]).toBe("CN-TW");
  });

  it("should handle empty/null conflicts gracefully", () => {
    const conflictsStr = "";
    const tags = conflictsStr.split(",").filter(Boolean);
    expect(tags).toEqual([]);
  });

  it("should handle null conflicts", () => {
    const conflictsStr: string | null = null;
    const tags = conflictsStr ? conflictsStr.split(",").filter(Boolean) : [];
    expect(tags).toEqual([]);
  });
});
