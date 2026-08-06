/**
 * Utility Attack Playbooks Router
 * 
 * Exposes pre-built adversary emulation playbooks for critical infrastructure:
 * - Water Treatment / Distribution
 * - Wastewater / Sewage
 * - Electric Power (Generation, Transmission, Distribution)
 * 
 * Each playbook maps real-world threat actor TTPs to executable red team procedures.
 */

import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import {
  getAllPlaybooks,
  getPlaybookById,
  getPlaybooksBySector,
  getPlaybooksByDifficulty,
  getPlaybooksByThreatActor,
  getPlaybooksByCisaAdvisory,
  searchPlaybooks,
  getPlaybookSummary,
} from "../lib/utility-attack-playbooks";

export const utilityPlaybooksRouter = router({
  /** Get all utility attack playbooks */
  list: protectedProcedure
    .input(z.object({
      sector: z.string().optional(),
      difficulty: z.string().optional(),
      threatActor: z.string().optional(),
      cisaAdvisory: z.string().optional(),
      search: z.string().optional(),
    }).optional())
    .query(({ input }) => {
      if (!input) return getAllPlaybooks();
      if (input.search) return searchPlaybooks(input.search);
      if (input.sector) return getPlaybooksBySector(input.sector as any);
      if (input.difficulty) return getPlaybooksByDifficulty(input.difficulty as any);
      if (input.threatActor) return getPlaybooksByThreatActor(input.threatActor);
      if (input.cisaAdvisory) return getPlaybooksByCisaAdvisory(input.cisaAdvisory);
      return getAllPlaybooks();
    }),

  /** Get a specific playbook by ID */
  getById: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(({ input }) => {
      return getPlaybookById(input.id) || null;
    }),

  /** Get playbook summary/statistics */
  summary: protectedProcedure.query(() => {
    return getPlaybookSummary();
  }),

  /** Get playbooks relevant to a specific CISA advisory */
  byCisaAdvisory: protectedProcedure
    .input(z.object({ advisory: z.string() }))
    .query(({ input }) => {
      return getPlaybooksByCisaAdvisory(input.advisory);
    }),

  /** Get playbooks by threat actor */
  byThreatActor: protectedProcedure
    .input(z.object({ actor: z.string() }))
    .query(({ input }) => {
      return getPlaybooksByThreatActor(input.actor);
    }),
});
