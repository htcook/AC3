/**
 * DHS/FBI Advisory Auto-Correlation Router
 * 
 * Exposes advisory correlation capabilities:
 * - List/filter advisories from CISA, FBI, NSA, EPA, DOE
 * - Auto-correlate advisories against client profiles and PLC fleet
 * - Generate actionable intelligence briefs
 */

import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import {
  correlateAdvisory,
  correlateAllAdvisories,
  getAdvisories,
  getAdvisoryById,
  getAdvisoryStats,
  registerClientProfiles,
  registerPlcFleet,
  registerExploitArsenal,
} from "../lib/advisory-correlation-engine";

export const advisoryCorrelationRouter = router({
  /** List all advisories with optional filters */
  list: protectedProcedure
    .input(z.object({
      source: z.enum(["cisa", "fbi", "nsa", "epa", "doe", "uscybercom", "treasury", "joint"]).optional(),
      severity: z.enum(["critical", "high", "medium", "low"]).optional(),
      sector: z.string().optional(),
      vendor: z.string().optional(),
      threatActor: z.string().optional(),
      since: z.string().optional(),
    }).optional())
    .query(({ input }) => {
      return getAdvisories(input ? {
        ...input,
        source: input.source as any,
        severity: input.severity as any,
        since: input.since ? new Date(input.since) : undefined,
      } : undefined);
    }),

  /** Get a specific advisory by ID */
  getById: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(({ input }) => {
      return getAdvisoryById(input.id) || null;
    }),

  /** Get advisory statistics */
  stats: protectedProcedure.query(() => {
    return getAdvisoryStats();
  }),

  /** Correlate a specific advisory against registered profiles */
  correlate: protectedProcedure
    .input(z.object({ advisoryId: z.string() }))
    .query(({ input }) => {
      return correlateAdvisory(input.advisoryId);
    }),

  /** Correlate ALL advisories against registered profiles */
  correlateAll: protectedProcedure.query(() => {
    return correlateAllAdvisories();
  }),

  /** Register client profiles for correlation */
  registerClients: protectedProcedure
    .input(z.object({
      clients: z.array(z.object({
        id: z.number(),
        name: z.string(),
        sector: z.string(),
        equipment: z.array(z.object({
          vendor: z.string(),
          model: z.string(),
        })),
        region: z.string(),
        threatActorsOfConcern: z.array(z.string()),
      })),
    }))
    .mutation(({ input }) => {
      registerClientProfiles(input.clients);
      return { success: true, clientsRegistered: input.clients.length };
    }),

  /** Register PLC fleet for correlation */
  registerFleet: protectedProcedure
    .input(z.object({
      devices: z.array(z.object({
        vendor: z.string(),
        model: z.string(),
        sector: z.string(),
        isExposed: z.boolean(),
      })),
    }))
    .mutation(({ input }) => {
      registerPlcFleet(input);
      return { success: true, devicesRegistered: input.devices.length };
    }),

  /** Register exploit arsenal for correlation */
  registerArsenal: protectedProcedure
    .input(z.object({
      cves: z.array(z.string()),
      targetVendors: z.array(z.string()),
    }))
    .mutation(({ input }) => {
      registerExploitArsenal(input);
      return { success: true };
    }),
});
