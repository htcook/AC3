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
    allowedDomains: tryParseJson(row.cicd_allowed_domains) || [],
    scanTypes: tryParseJson(row.cicd_scan_types) || [],
    lastBaselineId: row.cicd_last_baseline_id,
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
      scanTypes: z.array(z.enum(["zap", "burp", "nuclei", "config", "cspm", "container", "iac", "secrets"])).optional(),
      allowedDomains: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { cicdPipelines } = await import("../../drizzle/schema");
      const { sql } = await import("drizzle-orm");
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
      const insertId = result[0].insertId;

      // Set JSON columns via raw SQL (not in Drizzle schema)
      if (input.scanTypes?.length || input.allowedDomains?.length) {
        const updates: string[] = [];
        if (input.scanTypes?.length) updates.push(`cicd_scan_types = '${JSON.stringify(input.scanTypes)}'`);
        if (input.allowedDomains?.length) updates.push(`cicd_allowed_domains = '${JSON.stringify(input.allowedDomains)}'`);
        await db.execute(sql.raw(`UPDATE cicd_pipelines SET ${updates.join(", ")} WHERE id = ${insertId}`));
      }

      return { id: insertId, webhookSecret };
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
      scanTypes: z.array(z.enum(["zap", "burp", "nuclei", "config", "cspm", "container", "iac", "secrets"])).optional(),
      containerImage: z.string().optional(),
      iacRepoUrl: z.string().optional(),
      cloudProvider: z.enum(["aws", "azure", "gcp"]).optional(),
      generateSbom: z.boolean().optional(),
      incrementalOnly: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdRuns, cicdPipelines } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, sql } = await import("drizzle-orm");

      // Fetch pipeline for allowedDomains and lastBaselineId
      const pipelineRows = await db.select().from(cicdPipelines).where(eq(cicdPipelines.id, input.pipelineId));
      const pipeline = pipelineRows[0];
      if (!pipeline) throw new TRPCError({ code: "NOT_FOUND", message: "Pipeline not found" });

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
        const allowedDomains = tryParseJson((pipeline as any).cicd_allowed_domains) || [];
        const lastBaselineId = (pipeline as any).cicd_last_baseline_id;

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
              allowedDomains,
              baselineId: lastBaselineId || undefined,
              generateSbom: input.generateSbom,
              incrementalOnly: input.incrementalOnly,
            });

            // Update run with results
            await db.update(cicdRuns).set({
              cicdRunStatus: scanResult.status === "passed" ? "passed" : scanResult.status === "error" ? "error" : "failed",
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
                findings: scanResult.findings.slice(0, 100),
                newFindings: scanResult.newFindings,
                fixedFindings: scanResult.fixedFindings,
                baselineCompared: scanResult.baselineCompared,
                sbomUrl: scanResult.sbomUrl,
                sbomPackageCount: scanResult.sbomPackageCount,
              }),
              cicdCompletedAt: new Date().toISOString(),
            } as any).where(eq(cicdRuns.id, runId));

            // Update baseline and new/fixed counts via raw SQL
            await db.execute(sql.raw(
              `UPDATE cicd_runs SET cicd_new_findings = ${scanResult.newFindings || 0}, cicd_fixed_findings = ${scanResult.fixedFindings || 0} WHERE id = ${runId}`
            ));
            // Set this run as the new baseline
            await db.execute(sql.raw(
              `UPDATE cicd_pipelines SET cicd_last_baseline_id = ${runId} WHERE id = ${input.pipelineId}`
            ));

            console.log(`[CICD] Run ${runId} completed: ${scanResult.status}`);

            // Notify owner on gate failure
            if (scanResult.status === "failed" || scanResult.status === "error") {
              try {
                const { notifyOwner } = await import("../_core/notification");
                const pipelineName = pipeline.cicdName || `Pipeline #${input.pipelineId}`;
                const severity = scanResult.criticalCount > 0 ? "CRITICAL" : scanResult.highCount > 0 ? "HIGH" : "MEDIUM";
                await notifyOwner({
                  title: `\u26a0\ufe0f CI/CD Gate ${scanResult.status === "error" ? "Error" : "Failed"}: ${pipelineName}`,
                  content: [
                    `Pipeline: ${pipelineName} (Run #${runId})`,
                    `Status: ${scanResult.status.toUpperCase()}`,
                    `Target: ${input.targetUrl}`,
                    input.branch ? `Branch: ${input.branch}` : null,
                    input.commitSha ? `Commit: ${input.commitSha.substring(0, 7)}` : null,
                    `Max CVSS: ${scanResult.maxCvss.toFixed(1)} (threshold: ${pipeline.cicdFailThreshold || 7.0})`,
                    `Findings: ${scanResult.criticalCount} critical, ${scanResult.highCount} high, ${scanResult.mediumCount} medium, ${scanResult.lowCount} low`,
                    scanResult.newFindings ? `New since baseline: ${scanResult.newFindings}` : null,
                    `Severity: ${severity}`,
                    `\nTop findings:`,
                    ...scanResult.findings.slice(0, 5).map((f: any, i: number) => `  ${i + 1}. [${f.severity?.toUpperCase()}] ${f.title}`),
                  ].filter(Boolean).join("\n"),
                });
                console.log(`[CICD] Gate failure notification sent for run ${runId}`);
              } catch (notifyErr: any) {
                console.error(`[CICD] Failed to send gate failure notification: ${notifyErr.message}`);
              }
            }
          } catch (err: any) {
            console.error(`[CICD] Run ${runId} error: ${err.message}`);
            await db.update(cicdRuns).set({
              cicdRunStatus: "error",
              cicdCompletedAt: new Date().toISOString(),
            } as any).where(eq(cicdRuns.id, runId));

            // Notify owner on scan error
            try {
              const { notifyOwner } = await import("../_core/notification");
              const pipelineName = pipeline.cicdName || `Pipeline #${input.pipelineId}`;
              await notifyOwner({
                title: `\u274c CI/CD Scan Error: ${pipelineName}`,
                content: `Pipeline "${pipelineName}" (Run #${runId}) encountered an error:\n${err.message}\n\nTarget: ${input.targetUrl || "N/A"}`,
              });
            } catch (notifyErr: any) {
              console.error(`[CICD] Failed to send error notification: ${notifyErr.message}`);
            }
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
      provider: z.enum(["github_actions", "gitlab_ci", "codepipeline", "jenkins", "azure_devops"]),
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
        generateJenkinsfileYaml,
        generateAzureDevOpsYaml,
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
        case "jenkins":
          return { yaml: generateJenkinsfileYaml(webhookUrl) };
        case "azure_devops":
          return { yaml: generateAzureDevOpsYaml(webhookUrl) };
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

  // ─── P0: Update Allowed Domains ─────────────────────────────────────────
  updateAllowedDomains: protectedProcedure
    .input(z.object({
      pipelineId: z.number(),
      allowedDomains: z.array(z.string()),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { sql } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      await db.execute(sql.raw(
        `UPDATE cicd_pipelines SET cicd_allowed_domains = '${JSON.stringify(input.allowedDomains)}' WHERE id = ${input.pipelineId}`
      ));
      return { success: true };
    }),

  // ─── P0: Scan Server Pre-flight ─────────────────────────────────────────
  scanServerHealth: protectedProcedure.query(async () => {
    const { scanServerPreFlight } = await import("../lib/aws-cicd-connector");
    return scanServerPreFlight();
  }),

  // ─── P1: Get Baseline Comparison ────────────────────────────────────────
  getBaselineComparison: protectedProcedure
    .input(z.object({ runId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdRuns } = await import("../../drizzle/schema");
      const { sql } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const rows = await db.execute(sql.raw(
        `SELECT cicd_new_findings, cicd_fixed_findings FROM cicd_runs WHERE id = ${input.runId}`
      ));
      const row = (rows.rows || rows)?.[0] as any;
      return {
        newFindings: row?.cicd_new_findings || 0,
        fixedFindings: row?.cicd_fixed_findings || 0,
      };
    }),

  // ─── P2: Update Scan Types ──────────────────────────────────────────────
  updateScanTypes: protectedProcedure
    .input(z.object({
      pipelineId: z.number(),
      scanTypes: z.array(z.enum(["zap", "burp", "nuclei", "config", "cspm", "container", "iac", "secrets"])),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { sql } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      await db.execute(sql.raw(
        `UPDATE cicd_pipelines SET cicd_scan_types = '${JSON.stringify(input.scanTypes)}' WHERE id = ${input.pipelineId}`
      ));
      return { success: true };
    }),

  // ─── P3: Container Registry Discovery ───────────────────────────────────
  discoverContainerImages: protectedProcedure
    .input(z.object({
      registryType: z.string(),
      registryUrl: z.string().optional(),
      username: z.string().optional(),
      password: z.string().optional(),
      region: z.string().optional(),
      namespace: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { discoverContainerImages } = await import("../lib/aws-cicd-connector");
      return discoverContainerImages(
        input.registryType,
        { url: input.registryUrl, username: input.username, password: input.password, region: input.region },
        input.namespace
      );
    }),

  // ─── Run History for Chart ──────────────────────────────────────────────
  getRunHistory: protectedProcedure
    .input(z.object({
      pipelineId: z.number().optional(),
      days: z.number().min(7).max(90).optional(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { sql } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const days = input.days || 30;
      const pipelineFilter = input.pipelineId ? `AND cicd_run_pipeline_id = ${input.pipelineId}` : "";
      const rows = await db.execute(sql.raw(
        `SELECT 
          DATE(cicd_run_created_at) as run_date,
          SUM(CASE WHEN cicd_run_status = 'passed' THEN 1 ELSE 0 END) as passed,
          SUM(CASE WHEN cicd_run_status = 'failed' THEN 1 ELSE 0 END) as failed,
          SUM(CASE WHEN cicd_run_status = 'error' THEN 1 ELSE 0 END) as errors,
          COUNT(*) as total
        FROM cicd_runs
        WHERE cicd_run_created_at >= DATE_SUB(NOW(), INTERVAL ${days} DAY)
        ${pipelineFilter}
        GROUP BY DATE(cicd_run_created_at)
        ORDER BY run_date ASC`
      ));
      const data = ((rows as any).rows || rows || []) as any[];
      return data.map((r: any) => ({
        date: r.run_date ? String(r.run_date).substring(0, 10) : "",
        passed: Number(r.passed) || 0,
        failed: Number(r.failed) || 0,
        errors: Number(r.errors) || 0,
        total: Number(r.total) || 0,
      }));
    }),

  // ─── Baseline Auto-Refresh ──────────────────────────────────────────────
  refreshBaselines: protectedProcedure.mutation(async () => {
    const { getDb } = await import("../db");
    const { sql } = await import("drizzle-orm");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

    // For each pipeline, find the latest passing run and set it as the baseline
    const result = await db.execute(sql.raw(
      `UPDATE cicd_pipelines p
       INNER JOIN (
         SELECT cicd_run_pipeline_id, MAX(id) as latest_passing_id
         FROM cicd_runs
         WHERE cicd_run_status = 'passed'
         GROUP BY cicd_run_pipeline_id
       ) latest ON p.id = latest.cicd_run_pipeline_id
       SET p.cicd_last_baseline_id = latest.latest_passing_id
       WHERE p.cicd_last_baseline_id IS NULL OR p.cicd_last_baseline_id != latest.latest_passing_id`
    ));
    const affected = (result as any)?.[0]?.affectedRows || (result as any)?.rowsAffected || 0;
    console.log(`[CICD] Baseline auto-refresh: ${affected} pipelines updated`);
    return { updated: affected };
  }),

  // ─── P3: Cloud IAM Enumeration ──────────────────────────────────────────
  enumerateCloudIam: protectedProcedure
    .input(z.object({
      provider: z.enum(["aws", "azure", "gcp"]),
    }))
    .mutation(async ({ input }) => {
      const { enumerateCloudIam } = await import("../lib/aws-cicd-connector");
      return enumerateCloudIam(input.provider);
    }),
});
