/**
 * Empire C2 Router
 *
 * tRPC endpoints for managing Empire C2 operations via the EmpireAdapter.
 * Provides agent management, listener management, module search/execution,
 * stager generation, and health monitoring.
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { EmpireAdapter } from "../lib/c2-abstraction";

// Singleton adapter
let _adapter: EmpireAdapter | null = null;
function getAdapter(): EmpireAdapter {
  if (!_adapter) _adapter = new EmpireAdapter();
  return _adapter;
}

export const empireRouter = router({
  // ─── Health ────────────────────────────────────────────────────────────

  health: protectedProcedure.query(async () => {
    return getAdapter().healthCheck();
  }),

  // ─── Agents ────────────────────────────────────────────────────────────

  listAgents: protectedProcedure.query(async () => {
    return getAdapter().listAgents();
  }),

  getAgent: protectedProcedure
    .input(z.object({ agentId: z.string() }))
    .query(async ({ input }) => {
      return getAdapter().getAgent(input.agentId);
    }),

  killAgent: protectedProcedure
    .input(z.object({ agentId: z.string() }))
    .mutation(async ({ input }) => {
      return getAdapter().killAgent(input.agentId);
    }),

  shellCommand: protectedProcedure
    .input(z.object({
      agentId: z.string(),
      command: z.string(),
    }))
    .mutation(async ({ input }) => {
      return getAdapter().shellCommand(input.agentId, input.command);
    }),

  getAgentResults: protectedProcedure
    .input(z.object({ agentId: z.string() }))
    .query(async ({ input }) => {
      return getAdapter().getAgentResults(input.agentId);
    }),

  // ─── Modules ───────────────────────────────────────────────────────────

  searchModules: protectedProcedure
    .input(z.object({
      query: z.string().default(""),
    }))
    .query(async ({ input }) => {
      return getAdapter().searchModules(input.query);
    }),

  getModule: protectedProcedure
    .input(z.object({ moduleId: z.string() }))
    .query(async ({ input }) => {
      return getAdapter().getModule(input.moduleId);
    }),

  executeModule: protectedProcedure
    .input(z.object({
      agentId: z.string(),
      moduleId: z.string(),
      options: z.record(z.string(), z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      return getAdapter().dispatch({
        agentId: input.agentId,
        moduleId: input.moduleId,
        options: input.options,
      });
    }),

  pollResult: protectedProcedure
    .input(z.object({
      taskId: z.string(),
      agentId: z.string(),
    }))
    .query(async ({ input }) => {
      return getAdapter().pollResult(input.taskId, input.agentId);
    }),

  // ─── Listeners ─────────────────────────────────────────────────────────

  listListeners: protectedProcedure.query(async () => {
    return getAdapter().listListeners();
  }),

  createListener: protectedProcedure
    .input(z.object({
      name: z.string(),
      template: z.string(),
      host: z.string(),
      port: z.number(),
      options: z.record(z.string(), z.any()).optional(),
    }))
    .mutation(async ({ input }) => {
      return getAdapter().createListener(input);
    }),

  // ─── Stagers ───────────────────────────────────────────────────────────

  listStagers: protectedProcedure.query(async () => {
    return getAdapter().listStagers();
  }),

  generateStager: protectedProcedure
    .input(z.object({
      template: z.string(),
      listener: z.string(),
      options: z.record(z.string(), z.any()).optional(),
    }))
    .mutation(async ({ input }) => {
      return getAdapter().generateStager(input);
    }),
});
