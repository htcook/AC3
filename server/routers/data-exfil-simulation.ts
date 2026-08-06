import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import {
  EXFIL_SCENARIOS,
  getScenario,
  getScenariosByDifficulty,
  getScenariosByChannel,
  runExfilSimulation,
  generateTestData,
  buildCampaignAssessment,
  type ExfilChannel,
  type ExfilScenario,
} from "../lib/data-exfil-simulation";

export const dataExfilSimulationRouter = router({
  /** List all exfiltration scenarios */
  listScenarios: protectedProcedure
    .input(z.object({
      difficulty: z.enum(["basic", "intermediate", "advanced", "expert"]).optional(),
      channel: z.string().optional(),
    }).optional())
    .query(({ input }) => {
      if (input?.difficulty) return getScenariosByDifficulty(input.difficulty);
      if (input?.channel) return getScenariosByChannel(input.channel as ExfilChannel);
      return EXFIL_SCENARIOS;
    }),

  /** Get a specific scenario by ID */
  getScenario: protectedProcedure
    .input(z.object({ scenarioId: z.string() }))
    .query(({ input }) => {
      const scenario = getScenario(input.scenarioId);
      if (!scenario) throw new Error(`Scenario not found: ${input.scenarioId}`);
      return scenario;
    }),

  /** Run a data exfiltration simulation */
  runSimulation: protectedProcedure
    .input(z.object({
      scenarioId: z.string(),
      targetHost: z.string(),
      dataSizeKb: z.number().min(1).max(10240).default(100),
      durationSeconds: z.number().min(5).max(3600).default(60),
      encrypted: z.boolean().default(true),
      encoded: z.boolean().default(false),
      chunkSizeBytes: z.number().min(32).max(65536).default(1024),
      chunkDelayMs: z.number().min(0).max(60000).default(100),
      destination: z.string().optional(),
      captureTraffic: z.boolean().default(false),
    }))
    .mutation(async ({ input }) => {
      return await runExfilSimulation(input);
    }),

  /** Preview test data that would be generated for a scenario */
  previewTestData: protectedProcedure
    .input(z.object({
      dataType: z.enum(["pii_sample", "credit_card_sample", "credentials_sample", "source_code_sample", "database_dump_sample", "document_sample", "custom"]),
      sizeKb: z.number().min(1).max(100).default(5),
    }))
    .query(({ input }) => {
      const result = generateTestData(input.dataType, input.sizeKb);
      return {
        ...result,
        sizeBytes: Buffer.byteLength(result.data),
        preview: result.data.slice(0, 2000) + (result.data.length > 2000 ? "\n... [truncated]" : ""),
      };
    }),

  /** Run a campaign of multiple simulations and get aggregate assessment */
  runCampaign: protectedProcedure
    .input(z.object({
      name: z.string(),
      scenarioIds: z.array(z.string()).min(1).max(9),
      targetHost: z.string(),
      dataSizeKb: z.number().min(1).max(1024).default(50),
      durationSeconds: z.number().min(5).max(600).default(30),
    }))
    .mutation(async ({ input }) => {
      const results = [];
      for (const scenarioId of input.scenarioIds) {
        const result = await runExfilSimulation({
          scenarioId,
          targetHost: input.targetHost,
          dataSizeKb: input.dataSizeKb,
          durationSeconds: input.durationSeconds,
          encrypted: true,
          encoded: false,
          chunkSizeBytes: 1024,
          chunkDelayMs: 100,
          captureTraffic: false,
        });
        results.push(result);
      }
      const assessment = buildCampaignAssessment(results);
      return {
        campaignId: `campaign-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        name: input.name,
        scenarioCount: input.scenarioIds.length,
        results,
        overallAssessment: assessment,
        completedAt: Date.now(),
      };
    }),
});
