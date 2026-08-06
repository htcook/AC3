/**
 * Competitive Engines Router
 * ===========================
 * Exposes the three competitive-edge engines as tRPC procedures:
 *   - quickScan.launch — One-click autonomous engagement creation
 *   - firstBlood.execute — Parallel fast-path pipeline for rapid initial access
 *   - cveExploitGen.generate — CVE-to-exploit auto-generation
 *
 * All procedures are protected (require authenticated operator).
 */
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";

export const competitiveEnginesRouter = router({
  // ─── Quick Scan ─────────────────────────────────────────────────────────
  quickScan: router({
    /**
     * Launch a Quick Scan — takes a target and creates a fully-configured engagement
     * in seconds rather than hours.
     */
    launch: protectedProcedure
      .input(z.object({
        target: z.string().min(1).describe("Domain, IP address, or CIDR range"),
        customerName: z.string().optional(),
        sector: z.string().optional().describe("Industry sector for threat actor matching"),
      }))
      .mutation(async ({ input, ctx }) => {
        const { executeQuickScan } = await import("../lib/quick-scan-engine");
        const result = await executeQuickScan({
          target: input.target,
          userId: ctx.user?.id || 0,
          customerName: input.customerName,
          sector: input.sector,
        });
        return result;
      }),

    /**
     * Classify a target string to determine its type (domain, IP, CIDR)
     */
    classifyTarget: protectedProcedure
      .input(z.object({ target: z.string().min(1) }))
      .query(async ({ input }) => {
        const { classifyTarget } = await import("../lib/quick-scan-engine");
        return classifyTarget(input.target);
      }),
  }),

  // ─── First Blood ───────────────────────────────────────────────────────
  firstBlood: router({
    /**
     * Execute the First Blood pipeline — runs 4 parallel attack lanes
     * and returns prioritized findings with "first blood" indicator.
     */
    execute: protectedProcedure
      .input(z.object({
        targets: z.array(z.string()).min(1).describe("Target domains, IPs, or URLs"),
        technologies: z.array(z.string()).optional().describe("Detected technology stack"),
        credentials: z.array(z.object({
          username: z.string(),
          password: z.string(),
        })).optional().describe("Known/leaked credentials to test"),
        cloudProvider: z.enum(["aws", "azure", "gcp"]).optional(),
        maxDurationMs: z.number().optional().describe("Timeout in ms (default 5 min)"),
        engagementId: z.number().optional(),
      }))
      .mutation(async ({ input }) => {
        const { executeFirstBlood } = await import("../lib/first-blood-engine");
        const result = await executeFirstBlood({
          targets: input.targets,
          technologies: input.technologies,
          credentials: input.credentials,
          cloudProvider: input.cloudProvider,
          maxDurationMs: input.maxDurationMs,
          engagementId: input.engagementId,
        });
        return result;
      }),
  }),

  // ─── CVE Exploit Generation ────────────────────────────────────────────
  cveExploitGen: router({
    /**
     * Generate exploit templates (Nuclei + Caldera ability) for a single CVE
     */
    generate: protectedProcedure
      .input(z.object({
        cveId: z.string().regex(/^CVE-\d{4}-\d{4,}$/i).describe("CVE identifier (e.g., CVE-2024-3400)"),
        deployToCaldera: z.boolean().optional().default(false),
        engagementId: z.number().optional(),
      }))
      .mutation(async ({ input }) => {
        const { generateExploitForCve } = await import("../lib/cve-exploit-gen-engine");
        const result = await generateExploitForCve(input.cveId, {
          deployToCaldera: input.deployToCaldera,
          engagementId: input.engagementId,
        });
        return result;
      }),

    /**
     * Batch generate exploits for multiple CVEs, sorted by threat-actor priority
     */
    batchGenerate: protectedProcedure
      .input(z.object({
        cveIds: z.array(z.string().regex(/^CVE-\d{4}-\d{4,}$/i)).min(1).max(20),
        deployToCaldera: z.boolean().optional().default(false),
        maxConcurrent: z.number().optional().default(3),
      }))
      .mutation(async ({ input }) => {
        const { batchGenerateExploits } = await import("../lib/cve-exploit-gen-engine");
        const results = await batchGenerateExploits(input.cveIds, {
          deployToCaldera: input.deployToCaldera,
          maxConcurrent: input.maxConcurrent,
        });
        return results;
      }),

    /**
     * Enrich a CVE with NVD data, KEV status, and threat actor mapping
     * (preview without generating templates)
     */
    enrich: protectedProcedure
      .input(z.object({
        cveId: z.string().regex(/^CVE-\d{4}-\d{4,}$/i),
      }))
      .query(async ({ input }) => {
        const { enrichCve, calculatePriority } = await import("../lib/cve-exploit-gen-engine");
        const enrichment = await enrichCve(input.cveId);
        const priority = calculatePriority(enrichment);
        return { enrichment, priority };
      }),

    /**
     * Deploy a previously generated Caldera ability to the live instance
     */
    deploy: protectedProcedure
      .input(z.object({
        abilityId: z.string(),
        yaml: z.string(),
        name: z.string(),
        tactic: z.string(),
        technique: z.string(),
        platforms: z.array(z.string()),
      }))
      .mutation(async ({ input }) => {
        const { deployToCaldera } = await import("../lib/cve-exploit-gen-engine");
        const success = await deployToCaldera({
          ...input,
          validated: true,
        });
        if (!success) {
          throw new TRPCError({
            code: "INTERNAL_SERVER_ERROR",
            message: "Failed to deploy ability to Caldera",
          });
        }
        return { success: true, abilityId: input.abilityId };
      }),
  }),
});
