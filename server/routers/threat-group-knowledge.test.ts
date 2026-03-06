import { describe, it, expect } from "vitest";
import {
  getAllGroups,
  getGroupById,
  getGroupsByTechnique,
  getGroupsByCVE,
  getGroupsBySector,
  getSectorProfiles,
  getThreatGroupSummary,
  getThreatGroupHuntContext,
  getThreatGroupScanContext,
  getThreatGroupVulnContext,
  getSectorThreatContext,
  type ThreatGroupKnowledge,
} from "../lib/threat-group-knowledge";

// ─── Filter helper (mirrors router logic) ─────────────────────────────────

function filterGroups(
  groups: ThreatGroupKnowledge[],
  filters: {
    type?: string;
    sector?: string;
    search?: string;
    ttp?: string;
    tool?: string;
  }
): ThreatGroupKnowledge[] {
  let result = [...groups];
  if (filters.type && filters.type !== "all") {
    result = result.filter((g) => g.type === filters.type);
  }
  if (filters.sector) {
    const sectorLower = filters.sector.toLowerCase();
    result = result.filter(
      (g) =>
        g.targetSectors &&
        g.targetSectors.some((s) => s.toLowerCase().includes(sectorLower))
    );
  }
  if (filters.search) {
    const q = filters.search.toLowerCase();
    result = result.filter(
      (g) =>
        g.name.toLowerCase().includes(q) ||
        g.id.toLowerCase().includes(q) ||
        (g.aliases && g.aliases.some((a) => a.toLowerCase().includes(q))) ||
        (g.description && g.description.toLowerCase().includes(q))
    );
  }
  if (filters.ttp) {
    const ttpGroups = getGroupsByTechnique(filters.ttp);
    const ttpIds = new Set(ttpGroups.map((g) => g.id));
    result = result.filter((g) => ttpIds.has(g.id));
  }
  if (filters.tool) {
    const toolLower = filters.tool.toLowerCase();
    result = result.filter((g) =>
      g.tools.some((t) => t.name.toLowerCase().includes(toolLower))
    );
  }
  return result;
}

// ─── Tests ─────────────────────────────────────────────────────────────────

describe("Threat Group Knowledge Router Logic", () => {
  describe("list endpoint logic", () => {
    it("returns all groups when no filters", () => {
      const groups = getAllGroups();
      expect(groups.length).toBeGreaterThan(0);
    });

    it("filters by type=apt", () => {
      const groups = getAllGroups();
      const filtered = filterGroups(groups, { type: "apt" });
      expect(filtered.length).toBeGreaterThan(0);
      expect(filtered.every((g) => g.type === "apt")).toBe(true);
    });

    it("filters by type=ransomware", () => {
      const groups = getAllGroups();
      const filtered = filterGroups(groups, { type: "ransomware" });
      expect(filtered.length).toBeGreaterThan(0);
      expect(filtered.every((g) => g.type === "ransomware")).toBe(true);
    });

    it("filters by sector", () => {
      const groups = getAllGroups();
      const filtered = filterGroups(groups, { sector: "government" });
      expect(filtered.length).toBeGreaterThan(0);
      for (const g of filtered) {
        expect(
          g.targetSectors.some((s) =>
            s.toLowerCase().includes("government")
          )
        ).toBe(true);
      }
    });

    it("filters by search query", () => {
      const groups = getAllGroups();
      const filtered = filterGroups(groups, { search: "cozy bear" });
      expect(filtered.length).toBeGreaterThan(0);
      expect(
        filtered.some(
          (g) =>
            g.name.toLowerCase().includes("cozy bear") ||
            g.aliases.some((a) => a.toLowerCase().includes("cozy bear"))
        )
      ).toBe(true);
    });

    it("filters by TTP technique ID", () => {
      const groups = getAllGroups();
      const filtered = filterGroups(groups, { ttp: "T1190" });
      expect(filtered.length).toBeGreaterThan(0);
      for (const g of filtered) {
        expect(
          g.ttps.some((t) => t.techniqueId === "T1190")
        ).toBe(true);
      }
    });

    it("filters by tool name", () => {
      const groups = getAllGroups();
      const filtered = filterGroups(groups, { tool: "mimikatz" });
      expect(filtered.length).toBeGreaterThan(0);
      for (const g of filtered) {
        expect(
          g.tools.some((t) =>
            t.name.toLowerCase().includes("mimikatz")
          )
        ).toBe(true);
      }
    });

    it("returns empty when no match", () => {
      const groups = getAllGroups();
      const filtered = filterGroups(groups, {
        search: "nonexistent_group_xyz_12345",
      });
      expect(filtered.length).toBe(0);
    });

    it("combines type and sector filters", () => {
      const groups = getAllGroups();
      const filtered = filterGroups(groups, {
        type: "apt",
        sector: "technology",
      });
      for (const g of filtered) {
        expect(g.type).toBe("apt");
        expect(
          g.targetSectors.some((s) =>
            s.toLowerCase().includes("technology")
          )
        ).toBe(true);
      }
    });
  });

  describe("getById endpoint logic", () => {
    it("returns a group by ID", () => {
      const group = getGroupById("apt29");
      expect(group).toBeDefined();
      expect(group!.id).toBe("apt29");
      expect(group!.name).toContain("APT29");
    });

    it("returns undefined for unknown ID", () => {
      const group = getGroupById("nonexistent");
      expect(group).toBeUndefined();
    });
  });

  describe("summary endpoint logic", () => {
    it("returns valid summary stats", () => {
      const summary = getThreatGroupSummary();
      expect(summary.totalGroups).toBeGreaterThan(0);
      expect(summary.byType.apt).toBeGreaterThan(0);
      expect(summary.totalTTPs).toBeGreaterThan(0);
      expect(summary.totalTools).toBeGreaterThan(0);
    });
  });

  describe("filterOptions endpoint logic", () => {
    it("returns unique filter values", () => {
      const groups = getAllGroups();
      const sectors = new Set<string>();
      const ttps = new Set<string>();
      const tools = new Set<string>();
      const types = new Set<string>();

      for (const g of groups) {
        types.add(g.type);
        g.targetSectors.forEach((s) => sectors.add(s));
        for (const ttp of g.ttps) {
          ttps.add(ttp.techniqueId);
        }
        for (const t of g.tools) {
          tools.add(t.name);
        }
      }

      expect(types.size).toBeGreaterThan(0);
      expect(sectors.size).toBeGreaterThan(0);
      expect(ttps.size).toBeGreaterThan(0);
      expect(tools.size).toBeGreaterThan(0);
    });
  });

  describe("context builders", () => {
    it("huntContext returns non-empty string", () => {
      const ctx = getThreatGroupHuntContext();
      expect(ctx.length).toBeGreaterThan(100);
      expect(ctx).toContain("THREAT GROUP");
    });

    it("scanContext returns non-empty string", () => {
      const ctx = getThreatGroupScanContext();
      expect(ctx.length).toBeGreaterThan(100);
    });

    it("vulnContext returns non-empty string", () => {
      const ctx = getThreatGroupVulnContext();
      expect(ctx.length).toBeGreaterThan(100);
    });

    it("sectorContext returns non-empty string for known sector", () => {
      const ctx = getSectorThreatContext("government");
      expect(ctx.length).toBeGreaterThan(50);
    });
  });

  describe("sector profiles", () => {
    it("returns sector profiles", () => {
      const profiles = getSectorProfiles();
      expect(profiles.length).toBeGreaterThan(0);
      for (const p of profiles) {
        expect(p.sector).toBeTruthy();
        expect(p.topGroups.length).toBeGreaterThan(0);
      }
    });
  });
});
