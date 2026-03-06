import { publicProcedure, protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
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
  type SectorThreatProfile,
} from "../lib/threat-group-knowledge";

// ─── Helper: filter groups by criteria ────────────────────────────────────────
function filterGroups(
  groups: ThreatGroupKnowledge[],
  filters: {
    type?: string;
    sector?: string;
    search?: string;
    ttp?: string;
    cve?: string;
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

  if (filters.cve) {
    const cveGroups = getGroupsByCVE(filters.cve);
    const cveIds = new Set(cveGroups.map((g) => g.id));
    result = result.filter((g) => cveIds.has(g.id));
  }

  if (filters.tool) {
    const toolLower = filters.tool.toLowerCase();
    result = result.filter((g) =>
      g.tools.some((t) => t.name.toLowerCase().includes(toolLower))
    );
  }

  return result;
}

export const threatGroupKnowledgeRouter = router({
  /** List all threat groups with optional filtering */
  list: protectedProcedure
    .input(
      z
        .object({
          type: z.enum(["all", "apt", "ransomware", "cybercrime"]).optional(),
          sector: z.string().optional(),
          search: z.string().optional(),
          ttp: z.string().optional(),
          cve: z.string().optional(),
          tool: z.string().optional(),
        })
        .optional()
    )
    .query(({ input }) => {
      const groups = getAllGroups();
      if (!input) return { groups, total: groups.length };
      const filtered = filterGroups(groups, input);
      return { groups: filtered, total: filtered.length };
    }),

  /** Get a single threat group by ID */
  getById: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(({ input }) => {
      const group = getGroupById(input.id);
      if (!group) return null;
      return group;
    }),

  /** Get all sector profiles */
  sectorProfiles: protectedProcedure.query(() => {
    return getSectorProfiles();
  }),

  /** Get sector-specific threat context */
  sectorContext: protectedProcedure
    .input(z.object({ sector: z.string() }))
    .query(({ input }) => {
      return getSectorThreatContext(input.sector);
    }),

  /** Get threat group summary statistics */
  summary: protectedProcedure.query(() => {
    return getThreatGroupSummary();
  }),

  /** Get hunt context for LLM injection */
  huntContext: protectedProcedure
    .input(
      z.object({
        sector: z.string().optional(),
        groupIds: z.array(z.string()).optional(),
      })
    )
    .query(({ input }) => {
      return getThreatGroupHuntContext(input);
    }),

  /** Get scan context for LLM injection */
  scanContext: protectedProcedure
    .input(
      z.object({
        sector: z.string().optional(),
        groupIds: z.array(z.string()).optional(),
      })
    )
    .query(({ input }) => {
      return getThreatGroupScanContext(input);
    }),

  /** Get vulnerability correlation context */
  vulnContext: protectedProcedure
    .input(
      z.object({
        technologies: z.array(z.string()).optional(),
      })
    )
    .query(({ input }) => {
      return getThreatGroupVulnContext(input.technologies);
    }),

  /** Get unique values for filter dropdowns */
  filterOptions: protectedProcedure.query(() => {
    const groups = getAllGroups();
    const sectors = new Set<string>();
    const ttps = new Set<string>();
    const tools = new Set<string>();
    const types = new Set<string>();

    for (const g of groups) {
      types.add(g.type);
      if (g.targetSectors) g.targetSectors.forEach((s) => sectors.add(s));
      if (g.ttps) {
        for (const ttp of g.ttps) {
          ttps.add(ttp.techniqueId);
        }
      }
      if (g.tools) {
        for (const t of g.tools) {
          tools.add(t.name);
        }
      }
    }

    return {
      types: [...types].sort(),
      sectors: [...sectors].sort(),
      ttps: [...ttps].sort(),
      tools: [...tools].sort(),
    };
  }),
});
