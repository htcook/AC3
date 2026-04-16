import { z } from "zod";
import { router, protectedProcedure, publicProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Map a raw cicdPipelines row to the shape the frontend expects */
function mapPipeline(row: any) {
  return {
    id: row.id,
    name: row.cicdName,
    provider: row.cicdProvider,
    webhookUrl: row.cicdWebhookUrl,
    webhookSecret: row.cicdWebhookSecret,
    triggerOn: row.cicdTrigger,
    failThreshold: row.cicdFailThreshold,
    isActive: !!row.cicdIsActive,
    lastTriggered: row.cicdLastTriggered,
    createdBy: row.cicdCreatedBy,
    createdAt: row.cicdCreatedAt,
  };
}

/** Map a raw cicdRuns row */
function mapRun(row: any) {
  return {
    id: row.id,
    pipelineId: row.cicdRunPipelineId,
    commitSha: row.cicdCommitSha,
    branch: row.cicdBranch,
    status: row.cicdRunStatus,
    totalTests: row.cicdTotalTests,
    passedTests: row.cicdPassedTests,
    failedTests: row.cicdFailedTests,
    riskScore: row.cicdRiskScore,
    reportUrl: row.cicdReportUrl,
    startedAt: row.cicdStartedAt,
    completedAt: row.cicdCompletedAt,
    createdAt: row.cicdRunCreatedAt,
    // scan result fields (stored as JSON in reportUrl or separate)
    scanResults: row.cicdReportUrl ? tryParseJson(row.cicdReportUrl) : null,
  };
}

function tryParseJson(s: string) {
  try { return JSON.parse(s); } catch { return null; }
}

// ─── Router ──────────────────────────────────────────────────────────────────

export const cicdPipelineRouter = router({
  // ─── Pipeline CRUD ───────────────────────────────────────────────────────
  listPipelines: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { cicdPipelines } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { desc } = await import("drizzle-orm");
    const rows = await db.select().from(cicdPipelines).orderBy(desc(cicdPipelines.cicdCreatedAt));
    return rows.map(mapPipeline);
  }),

  createPipeline: protectedProcedure
    .input(z.object({
      name: z.string(),
      provider: z.enum(["github_actions", "jenkins", "gitlab_ci", "azure_devops", "custom"]),
      webhookUrl: z.string().optional(),
      triggerOn: z.enum(["push", "pull_request", "release", "manual", "schedule"]).optional(),
      failThreshold: z.number().optional(),
      targetUrl: z.string().optional(),
      scanTypes: z.array(z.enum(["zap", "burp", "nuclei", "config", "cspm", "container", "iac"])).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { cicdPipelines } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      // Generate webhook secret for this pipeline
      const { generateWebhookSecret } = await import("../lib/aws-cicd-connector");
      const webhookSecret = generateWebhookSecret();

      const result = await db.insert(cicdPipelines).values({
        cicdName: input.name,
        cicdProvider: input.provider,
        cicdWebhookUrl: input.webhookUrl || "",
        cicdWebhookSecret: webhookSecret,
        cicdTrigger: input.triggerOn || "manual",
        cicdFailThreshold: input.failThreshold ?? 7.0,
        cicdCreatedBy: String(ctx.user.id),
      });
      return { id: result[0].insertId, webhookSecret };
    }),

  updatePipeline: protectedProcedure
    .input(z.object({
      id: z.number(),
      name: z.string().optional(),
      webhookUrl: z.string().optional(),
      triggerOn: z.enum(["push", "pull_request", "release", "manual", "schedule"]).optional(),
      isActive: z.boolean().optional(),
      failThreshold: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdPipelines } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      const updates: any = {};
      if (input.name !== undefined) updates.cicdName = input.name;
      if (input.webhookUrl !== undefined) updates.cicdWebhookUrl = input.webhookUrl;
      if (input.triggerOn !== undefined) updates.cicdTrigger = input.triggerOn;
      if (input.isActive !== undefined) updates.cicdIsActive = input.isActive ? 1 : 0;
      if (input.failThreshold !== undefined) updates.cicdFailThreshold = input.failThreshold;

      await db.update(cicdPipelines).set(updates).where(eq(cicdPipelines.id, input.id));
      return { success: true };
    }),

  deletePipeline: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdPipelines } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.delete(cicdPipelines).where(eq(cicdPipelines.id, input.id));
      return { success: true };
    }),

  // ─── Run CRUD ────────────────────────────────────────────────────────────
  listRuns: protectedProcedure
    .input(z.object({ pipelineId: z.number().optional() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdRuns } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, desc } = await import("drizzle-orm");
      let rows;
      if (input.pipelineId) {
        rows = await db.select().from(cicdRuns).where(eq(cicdRuns.cicdRunPipelineId, input.pipelineId)).orderBy(desc(cicdRuns.cicdRunCreatedAt));
      } else {
        rows = await db.select().from(cicdRuns).orderBy(desc(cicdRuns.cicdRunCreatedAt));
      }
      return rows.map(mapRun);
    }),

  triggerRun: protectedProcedure
    .input(z.object({
      pipelineId: z.number(),
      commitSha: z.string().optional(),
      branch: z.string().optional(),
      targetUrl: z.string().optional(),
      scanTypes: z.array(z.enum(["zap", "burp", "nuclei", "config", "cspm", "container", "iac"])).optional(),
      containerImage: z.string().optional(),
      iacRepoUrl: z.string().optional(),
      cloudProvider: z.enum(["aws", "azure", "gcp"]).optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdRuns, cicdPipelines } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      // Create the run record
      const result = await db.insert(cicdRuns).values({
        cicdRunPipelineId: input.pipelineId,
        cicdCommitSha: input.commitSha || null,
        cicdBranch: input.branch || null,
        cicdRunStatus: "pending",
      });
      const runId = result[0].insertId;

      // If targetUrl is provided, kick off async scan
      if (input.targetUrl) {
        const scanTypes = input.scanTypes || ["nuclei"];
        // Fire and forget — scan runs in background
        import("../lib/aws-cicd-connector").then(async ({ executeCicdScan }) => {
          try {
            // Mark as running
            await db.update(cicdRuns).set({ cicdRunStatus: "running", cicdStartedAt: new Date().toISOString() } as any).where(eq(cicdRuns.id, runId));

            const scanResult = await executeCicdScan({
              targetUrl: input.targetUrl!,
              scanTypes,
              pipelineId: input.pipelineId,
              runId,
              commitSha: input.commitSha,
              branch: input.branch,
              containerImage: input.containerImage,
              iacRepoUrl: input.iacRepoUrl,
              cloudProvider: input.cloudProvider,
            });

            // Update run with results
            await db.update(cicdRuns).set({
              cicdRunStatus: scanResult.status === "passed" ? "passed" : "failed",
              cicdTotalTests: scanResult.totalFindings,
              cicdPassedTests: scanResult.mediumCount + scanResult.lowCount,
              cicdFailedTests: scanResult.criticalCount + scanResult.highCount,
              cicdRiskScore: scanResult.maxCvss,
              cicdReportUrl: JSON.stringify({
                criticalCount: scanResult.criticalCount,
                highCount: scanResult.highCount,
                mediumCount: scanResult.mediumCount,
                lowCount: scanResult.lowCount,
                maxCvss: scanResult.maxCvss,
                duration: scanResult.duration,
                findings: scanResult.findings.slice(0, 100), // Cap at 100 for storage
              }),
              cicdCompletedAt: new Date().toISOString(),
            } as any).where(eq(cicdRuns.id, runId));

            console.log(`[CICD] Run ${runId} completed: ${scanResult.status}`);
          } catch (err: any) {
            console.error(`[CICD] Run ${runId} error: ${err.message}`);
            await db.update(cicdRuns).set({
              cicdRunStatus: "error",
              cicdCompletedAt: new Date().toISOString(),
            } as any).where(eq(cicdRuns.id, runId));
          }
        });
      }

      return { id: runId };
    }),

  getRunDetails: protectedProcedure
    .input(z.object({ runId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdRuns } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const rows = await db.select().from(cicdRuns).where(eq(cicdRuns.id, input.runId));
      if (!rows[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Run not found" });
      return mapRun(rows[0]);
    }),

  getStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { cicdRuns, cicdPipelines } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { count, eq, sql } = await import("drizzle-orm");
    const totalPipelines = await db.select({ value: count() }).from(cicdPipelines);
    const totalRuns = await db.select({ value: count() }).from(cicdRuns);
    const passedRuns = await db.select({ value: count() }).from(cicdRuns).where(eq(cicdRuns.cicdRunStatus, "passed"));
    const failedRuns = await db.select({ value: count() }).from(cicdRuns).where(eq(cicdRuns.cicdRunStatus, "failed"));
    return {
      totalPipelines: totalPipelines[0].value,
      totalRuns: totalRuns[0].value,
      passedRuns: passedRuns[0].value,
      failedRuns: failedRuns[0].value,
      passRate: totalRuns[0].value > 0 ? Math.round((passedRuns[0].value / totalRuns[0].value) * 100) : 0,
    };
  }),

  // ─── AWS Environment Discovery ──────────────────────────────────────────
  discoverEnvironments: protectedProcedure
    .input(z.object({
      credentialId: z.number(),
      regions: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cloudCredentials } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      // Get stored credentials
      const creds = await db.select().from(cloudCredentials).where(eq(cloudCredentials.id, input.credentialId));
      if (!creds[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Credential not found" });

      const cred = creds[0];
      if (cred.credProvider !== "aws") {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Only AWS credentials are supported for environment discovery" });
      }

      const { assumeRole, discoverEnvironments } = await import("../lib/aws-cicd-connector");

      // If role ARN is set, assume role first
      let awsCreds;
      if (cred.roleArn) {
        awsCreds = await assumeRole({
          roleArn: cred.roleArn,
          externalId: cred.externalId || undefined,
          region: cred.credRegion || "us-east-1",
        });
      } else {
        // Decrypt stored credentials
        const { decryptCredential } = await import("../lib/credential-crypto");
        const decrypted = decryptCredential({
          encryptedData: cred.encryptedData,
          iv: cred.encryptionIv,
          tag: cred.encryptionTag,
        });
        const parsed = JSON.parse(decrypted);
        awsCreds = {
          accessKeyId: parsed.accessKeyId,
          secretAccessKey: parsed.secretAccessKey,
          sessionToken: parsed.sessionToken,
          region: cred.credRegion || "us-east-1",
        };
      }

      const environments = await discoverEnvironments(awsCreds, input.regions);
      return environments;
    }),

  // ─── Validate AWS Credentials ────────────────────────────────────────────
  validateAwsCredentials: protectedProcedure
    .input(z.object({
      roleArn: z.string(),
      externalId: z.string().optional(),
      region: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { assumeRole, validateCredentials } = await import("../lib/aws-cicd-connector");

      try {
        const creds = await assumeRole({
          roleArn: input.roleArn,
          externalId: input.externalId,
          region: input.region || "us-east-1",
        });

        const identity = await validateCredentials(creds);
        return {
          valid: true,
          accountId: identity.accountId,
          arn: identity.arn,
        };
      } catch (err: any) {
        return {
          valid: false,
          error: err.message,
          accountId: "",
          arn: "",
        };
      }
    }),

  // ─── Webhook Config ──────────────────────────────────────────────────────
  getWebhookConfig: protectedProcedure
    .input(z.object({ pipelineId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdPipelines } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      const rows = await db.select().from(cicdPipelines).where(eq(cicdPipelines.id, input.pipelineId));
      if (!rows[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Pipeline not found" });

      const { generateWebhookUrl } = await import("../lib/aws-cicd-connector");
      const webhookUrl = generateWebhookUrl(input.pipelineId);

      return {
        webhookUrl,
        webhookSecret: rows[0].cicdWebhookSecret || "",
        provider: rows[0].cicdProvider,
      };
    }),

  // ─── YAML Snippet Generator ──────────────────────────────────────────────
  generateYamlSnippet: protectedProcedure
    .input(z.object({
      pipelineId: z.number(),
      provider: z.enum(["github_actions", "gitlab_ci", "codepipeline"]),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdPipelines } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      const rows = await db.select().from(cicdPipelines).where(eq(cicdPipelines.id, input.pipelineId));
      if (!rows[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Pipeline not found" });

      const {
        generateWebhookUrl,
        generateGitHubActionsYaml,
        generateGitLabCiYaml,
        generateCodePipelineYaml,
      } = await import("../lib/aws-cicd-connector");

      const webhookUrl = generateWebhookUrl(input.pipelineId);
      const secret = rows[0].cicdWebhookSecret || "";

      switch (input.provider) {
        case "github_actions":
          return { yaml: generateGitHubActionsYaml(webhookUrl, secret) };
        case "gitlab_ci":
          return { yaml: generateGitLabCiYaml(webhookUrl) };
        case "codepipeline":
          return { yaml: generateCodePipelineYaml() };
        default:
          return { yaml: "# No snippet available for this provider" };
      }
    }),

  // ─── Regenerate Webhook Secret ───────────────────────────────────────────
  regenerateWebhookSecret: protectedProcedure
    .input(z.object({ pipelineId: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdPipelines } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      const { generateWebhookSecret } = await import("../lib/aws-cicd-connector");
      const newSecret = generateWebhookSecret();

      await db.update(cicdPipelines).set({ cicdWebhookSecret: newSecret } as any).where(eq(cicdPipelines.id, input.pipelineId));
      return { webhookSecret: newSecret };
    }),
});
