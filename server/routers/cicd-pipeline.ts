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
    // Bridge fields
    engagementId: row.cicdEngagementId || null,
    sectorContext: row.cicdSectorContext || null,
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
    // Threat intelligence context
    threatContext: row.cicdThreatContext ? (typeof row.cicdThreatContext === 'string' ? tryParseJson(row.cicdThreatContext) : row.cicdThreatContext) : null,
    engagementId: row.cicdRunEngagementId || null,
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

        // P1: Get sector context for threat-informed scanning
        const sectorContext = (pipeline as any).cicdSectorContext || undefined;

        // Fire and forget — scan runs in background
        import("../lib/aws-cicd-connector").then(async ({ executeCicdScan }) => {
          try {
            // Mark as running
            await db.update(cicdRuns).set({ cicdRunStatus: "running", cicdStartedAt: new Date().toISOString() } as any).where(eq(cicdRuns.id, runId));

            // P1: Sector-aware pre-scan template selection
            let sectorTemplateHint = "";
            if (sectorContext) {
              try {
                const { getPreScanTemplates } = await import("../lib/cicd-threat-correlator");
                const templates = await getPreScanTemplates(sectorContext);
                if (templates.priorityCVEs.length > 0) {
                  sectorTemplateHint = templates.priorityCVEs.slice(0, 10).join(",");
                  console.log(`[CICD] P1: Sector "${sectorContext}" → ${templates.priorityCVEs.length} priority CVEs, ${templates.templateTags.length} tags from ${templates.targetedGroups.length} groups`);
                }
              } catch (e: any) {
                console.warn(`[CICD] P1: Pre-scan template selection failed: ${e.message}`);
              }
            }

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

            // ═══ Auto-Gate Escalation: override pass→fail based on threat intel ═══
            let finalStatus = scanResult.status;
            let gateEscalationReason = "";
            if (scanResult.status === "passed" && scanResult.threatContext?.summary) {
              try {
                // Load escalation config from pipeline's sector_context JSON
                const scRows = await db.execute(sql.raw(
                  `SELECT cicd_sector_context FROM cicd_pipelines WHERE id = ${input.pipelineId}`
                ));
                const scRow = ((scRows as any).rows || scRows)?.[0] as any;
                const scParsed = scRow?.cicd_sector_context
                  ? (typeof scRow.cicd_sector_context === 'string' ? tryParseJson(scRow.cicd_sector_context) : scRow.cicd_sector_context)
                  : null;
                const ge = scParsed?.gateEscalation || {
                  escalateOnRansomware: true,
                  escalateOnApt: true,
                  escalateOnActorCount: 3,
                  escalateOnExposureScore: 60,
                };

                const tc = scanResult.threatContext.summary;
                const reasons: string[] = [];

                if (ge.escalateOnRansomware && tc.ransomwareRiskFindings > 0) {
                  reasons.push(`${tc.ransomwareRiskFindings} finding(s) linked to ransomware groups`);
                }
                if (ge.escalateOnApt && tc.aptRiskFindings > 0) {
                  reasons.push(`${tc.aptRiskFindings} finding(s) linked to APT groups`);
                }
                if (ge.escalateOnActorCount > 0 && tc.uniqueActorsMatched >= ge.escalateOnActorCount) {
                  reasons.push(`${tc.uniqueActorsMatched} threat actors matched (threshold: ${ge.escalateOnActorCount})`);
                }
                if (ge.escalateOnExposureScore > 0 && tc.actorExposureScore >= ge.escalateOnExposureScore) {
                  reasons.push(`Actor exposure score ${tc.actorExposureScore} (threshold: ${ge.escalateOnExposureScore})`);
                }

                if (reasons.length > 0) {
                  finalStatus = "failed";
                  gateEscalationReason = `Auto-gate escalation: ${reasons.join("; ")}`;
                  console.log(`[CICD] Gate escalation for run ${runId}: ${gateEscalationReason}`);
                }
              } catch (geErr: any) {
                console.warn(`[CICD] Gate escalation check failed (non-blocking): ${geErr.message}`);
              }
            }

            // Update run with results
            await db.update(cicdRuns).set({
              cicdRunStatus: finalStatus === "passed" ? "passed" : finalStatus === "error" ? "error" : "failed",
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

            // Store threat context in dedicated JSON column
            if (scanResult.threatContext) {
              try {
                await db.execute(sql.raw(
                  `UPDATE cicd_runs SET cicd_threat_context = '${JSON.stringify(scanResult.threatContext).replace(/'/g, "''")}' WHERE id = ${runId}`
                ));
                console.log(`[CICD] Threat context stored for run ${runId}: ${scanResult.threatContext.summary?.uniqueActorsMatched || 0} actors`);
              } catch (tcErr: any) {
                console.warn(`[CICD] Failed to store threat context: ${tcErr.message}`);
              }
            }

            // Update baseline and new/fixed counts via raw SQL
            await db.execute(sql.raw(
              `UPDATE cicd_runs SET cicd_new_findings = ${scanResult.newFindings || 0}, cicd_fixed_findings = ${scanResult.fixedFindings || 0} WHERE id = ${runId}`
            ));
            // Set this run as the new baseline
            await db.execute(sql.raw(
              `UPDATE cicd_pipelines SET cicd_last_baseline_id = ${runId} WHERE id = ${input.pipelineId}`
            ));

            console.log(`[CICD] Run ${runId} completed: ${finalStatus}${gateEscalationReason ? ` (ESCALATED)` : ``}`);

            // ═══ Engagement Auto-Import: push findings to linked engagement ═══
            const linkedEngagementId = (pipeline as any).cicdEngagementId;
            if (linkedEngagementId && scanResult.findings?.length > 0) {
              try {
                const { engagementFindings } = await import("../../drizzle/schema");
                const { correlateCicdFindings } = await import("../lib/cicd-threat-correlator");
                const enrichedCtx = scanResult.threatContext || await correlateCicdFindings(scanResult.findings).catch(() => null);
                const enrichedMap = new Map<string, any>();
                if (enrichedCtx?.enrichedFindings) {
                  for (const ef of enrichedCtx.enrichedFindings) enrichedMap.set(ef.title, ef);
                }

                const now = Date.now();
                let autoImported = 0;
                for (const finding of scanResult.findings.slice(0, 100)) {
                  const enriched = enrichedMap.get(finding.title);
                  const severity = enriched?.severity || finding.severity || 'medium';
                  const descParts = [finding.description || ''];
                  if (enriched?.attributedGroups?.length > 0) {
                    descParts.push(`\n--- THREAT INTEL (auto-imported from CI/CD run #${runId}) ---`);
                    descParts.push(`Groups: ${enriched.attributedGroups.map((g: any) => g.groupName).join(', ')}`);
                    if (enriched.severityBoosted) descParts.push(`Boosted: ${enriched.originalSeverity} → ${enriched.severity}`);
                    if (enriched.riskTags?.length) descParts.push(`Risk: ${enriched.riskTags.join(', ')}`);
                  }
                  const cveMatch = (finding.title + ' ' + (finding.description || '')).match(/CVE-\d{4}-\d{4,}/i);
                  try {
                    await db.insert(engagementFindings).values({
                      engagementId: linkedEngagementId,
                      title: finding.title?.substring(0, 512) || 'CI/CD Finding',
                      severity: severity as any,
                      cve: cveMatch ? cveMatch[0].toUpperCase().substring(0, 64) : null,
                      cwe: finding.cweId?.substring(0, 128) || null,
                      description: descParts.join('\n'),
                      endpoint: finding.url?.substring(0, 65535) || null,
                      source: `cicd-auto-run-${runId}`,
                      tool: finding.scanner?.substring(0, 128) || 'cicd-pipeline',
                      corroborationTier: 'unverified',
                      owaspCategory: null,
                      mitreTechnique: enriched?.killChainPhases?.[0] || null,
                      createdAt: now,
                    } as any);
                    autoImported++;
                  } catch { /* skip duplicates */ }
                }
                console.log(`[CICD] Auto-imported ${autoImported} findings from run ${runId} to engagement ${linkedEngagementId}`);
              } catch (aiErr: any) {
                console.warn(`[CICD] Engagement auto-import failed (non-blocking): ${aiErr.message}`);
              }
            }

            // P2: Threat-enriched gate failure notifications
            if (finalStatus === "failed" || finalStatus === "error") {
              try {
                const { notifyOwner } = await import("../_core/notification");
                const pipelineName = pipeline.cicdName || `Pipeline #${input.pipelineId}`;
                const severity = scanResult.criticalCount > 0 ? "CRITICAL" : scanResult.highCount > 0 ? "HIGH" : "MEDIUM";

                // Build threat intel section for notification
                const tc = scanResult.threatContext;
                const threatLines: string[] = [];
                if (tc?.summary) {
                  threatLines.push(`\n━━━ THREAT INTELLIGENCE ━━━`);
                  threatLines.push(`Actors Matched: ${tc.summary.uniqueActorsMatched} | Exposure Score: ${tc.summary.actorExposureScore}/100`);
                  threatLines.push(`Severity Boosted: ${tc.summary.severityBoostedCount} findings`);
                  if (tc.summary.ransomwareRiskFindings > 0) threatLines.push(`⚠️ RANSOMWARE RISK: ${tc.summary.ransomwareRiskFindings} findings linked to ransomware groups`);
                  if (tc.summary.aptRiskFindings > 0) threatLines.push(`🛡️ APT RISK: ${tc.summary.aptRiskFindings} findings linked to APT groups`);
                  threatLines.push(`Kill Chain Coverage: ${tc.summary.killChainCoverage}%`);
                  // Top 3 actors
                  if (tc.actorExposure?.length > 0) {
                    threatLines.push(`\nTop Threat Actors:`);
                    for (const actor of tc.actorExposure.slice(0, 3)) {
                      threatLines.push(`  • ${actor.groupName} (${actor.groupType}, ${actor.threatLevel}) — ${actor.findingCount} findings, score: ${actor.exposureScore}`);
                    }
                  }
                }

                await notifyOwner({
                  title: `\u26a0\ufe0f CI/CD Gate ${finalStatus === "error" ? "Error" : "Failed"}${gateEscalationReason ? " (THREAT ESCALATED)" : ""}: ${pipelineName}`,
                  content: [
                    `Pipeline: ${pipelineName} (Run #${runId})`,
                    `Status: ${finalStatus.toUpperCase()}${gateEscalationReason ? " \u2014 THREAT-ESCALATED" : ""}`,
                    gateEscalationReason ? `\n\u26a0\ufe0f ${gateEscalationReason}` : null,
                    `Target: ${input.targetUrl}`,
                    input.branch ? `Branch: ${input.branch}` : null,
                    input.commitSha ? `Commit: ${input.commitSha.substring(0, 7)}` : null,
                    `Max CVSS: ${scanResult.maxCvss.toFixed(1)} (threshold: ${pipeline.cicdFailThreshold || 7.0})`,
                    `Findings: ${scanResult.criticalCount} critical, ${scanResult.highCount} high, ${scanResult.mediumCount} medium, ${scanResult.lowCount} low`,
                    scanResult.newFindings ? `New since baseline: ${scanResult.newFindings}` : null,
                    `Severity: ${severity}`,
                    `\nTop findings:`,
                    ...scanResult.findings.slice(0, 5).map((f: any, i: number) => `  ${i + 1}. [${f.severity?.toUpperCase()}] ${f.title}`),
                    ...threatLines,
                  ].filter(Boolean).join("\n"),
                });
                console.log(`[CICD] Threat-enriched gate failure notification sent for run ${runId}`);
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

  // ═══ P1: Sector-Aware Pre-Scan Template Selection ═══════════════════════
  getPreScanTemplates: protectedProcedure
    .input(z.object({
      sector: z.string().optional(),
      pipelineId: z.number().optional(),
    }))
    .query(async ({ input }) => {
      const { getPreScanTemplates } = await import("../lib/cicd-threat-correlator");
      let sector = input.sector;

      // If pipelineId provided, look up sector from pipeline
      if (!sector && input.pipelineId) {
        const { getDb } = await import("../db");
        const { cicdPipelines } = await import("../../drizzle/schema");
        const db = await getDb();
        if (db) {
          const { eq } = await import("drizzle-orm");
          const rows = await db.select().from(cicdPipelines).where(eq(cicdPipelines.id, input.pipelineId));
          if (rows[0]) sector = rows[0].cicdSectorContext || undefined;
        }
      }

      return getPreScanTemplates(sector);
    }),

  // ═══ P2: Engagement Bridge ══════════════════════════════════════════════
  linkEngagement: protectedProcedure
    .input(z.object({
      pipelineId: z.number(),
      engagementId: z.number(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdPipelines } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.update(cicdPipelines).set({ cicdEngagementId: input.engagementId } as any).where(eq(cicdPipelines.id, input.pipelineId));
      return { success: true };
    }),

  unlinkEngagement: protectedProcedure
    .input(z.object({ pipelineId: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { sql } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      await db.execute(sql.raw(`UPDATE cicd_pipelines SET cicd_engagement_id = NULL WHERE id = ${input.pipelineId}`));
      return { success: true };
    }),

  updateSectorContext: protectedProcedure
    .input(z.object({
      pipelineId: z.number(),
      sector: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdPipelines } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.update(cicdPipelines).set({ cicdSectorContext: input.sector } as any).where(eq(cicdPipelines.id, input.pipelineId));
      return { success: true };
    }),

  // ═══ P3: Threat Analytics Endpoints ═════════════════════════════════════
  getRunThreatContext: protectedProcedure
    .input(z.object({ runId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { sql } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const rows = await db.execute(sql.raw(
        `SELECT cicd_threat_context FROM cicd_runs WHERE id = ${input.runId}`
      ));
      const row = (rows.rows || rows)?.[0] as any;
      if (!row?.cicd_threat_context) return null;
      return typeof row.cicd_threat_context === 'string'
        ? JSON.parse(row.cicd_threat_context)
        : row.cicd_threat_context;
    }),

  getThreatSummaryAcrossRuns: protectedProcedure
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
        `SELECT id, cicd_threat_context FROM cicd_runs
         WHERE cicd_threat_context IS NOT NULL
         AND cicd_run_created_at >= DATE_SUB(NOW(), INTERVAL ${days} DAY)
         ${pipelineFilter}
         ORDER BY id DESC
         LIMIT 50`
      ));
      const data = ((rows as any).rows || rows || []) as any[];

      // Aggregate threat context across runs
      let totalActorsMatched = 0;
      let totalBoosted = 0;
      let totalRansomwareRisk = 0;
      let totalAptRisk = 0;
      const actorFrequency = new Map<string, { name: string; type: string; count: number; threatLevel: string }>();
      const killChainHits = new Map<string, number>();

      for (const row of data) {
        const tc = typeof row.cicd_threat_context === 'string'
          ? tryParseJson(row.cicd_threat_context)
          : row.cicd_threat_context;
        if (!tc?.summary) continue;

        totalActorsMatched += tc.summary.uniqueActorsMatched || 0;
        totalBoosted += tc.summary.severityBoostedCount || 0;
        totalRansomwareRisk += tc.summary.ransomwareRiskFindings || 0;
        totalAptRisk += tc.summary.aptRiskFindings || 0;

        for (const actor of (tc.actorExposure || [])) {
          const existing = actorFrequency.get(actor.groupId);
          if (existing) {
            existing.count += actor.findingCount;
          } else {
            actorFrequency.set(actor.groupId, {
              name: actor.groupName,
              type: actor.groupType,
              count: actor.findingCount,
              threatLevel: actor.threatLevel,
            });
          }
        }

        for (const kc of (tc.killChainMap || [])) {
          if (kc.findingCount > 0) {
            killChainHits.set(kc.phase, (killChainHits.get(kc.phase) || 0) + kc.findingCount);
          }
        }
      }

      // Sort actors by frequency
      const topActors = [...actorFrequency.values()]
        .sort((a, b) => b.count - a.count)
        .slice(0, 15);

      const killChainSummary = [...killChainHits.entries()]
        .map(([phase, count]) => ({ phase, count }))
        .sort((a, b) => b.count - a.count);

      return {
        runsAnalyzed: data.length,
        totalActorsMatched,
        totalBoosted,
        totalRansomwareRisk,
        totalAptRisk,
        topActors,
        killChainSummary,
      };
    }),

  // ═══ Threat Trend Sparklines (30-day time series) ═══════════════════════
  getThreatTrendData: protectedProcedure
    .input(z.object({
      pipelineId: z.number(),
      days: z.number().min(7).max(90).optional(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { sql } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const days = input.days || 30;

      const rows = await db.execute(sql.raw(
        `SELECT id, cicd_threat_context, cicd_run_created_at, cicd_run_status
         FROM cicd_runs
         WHERE cicd_run_pipeline_id = ${input.pipelineId}
         AND cicd_run_created_at >= DATE_SUB(NOW(), INTERVAL ${days} DAY)
         ORDER BY id ASC
         LIMIT 100`
      ));
      const data = ((rows as any).rows || rows || []) as any[];

      // Build time-series data points
      const trendPoints: Array<{
        runId: number;
        date: string;
        status: string;
        actorExposureScore: number;
        killChainCoverage: number;
        uniqueActors: number;
        severityBoosted: number;
        ransomwareRisk: number;
        aptRisk: number;
      }> = [];

      for (const row of data) {
        const tc = typeof row.cicd_threat_context === 'string'
          ? tryParseJson(row.cicd_threat_context)
          : row.cicd_threat_context;

        trendPoints.push({
          runId: row.id,
          date: row.cicd_run_created_at || new Date().toISOString(),
          status: row.cicd_run_status || 'unknown',
          actorExposureScore: tc?.summary?.actorExposureScore || 0,
          killChainCoverage: tc?.summary?.killChainCoverage || 0,
          uniqueActors: tc?.summary?.uniqueActorsMatched || 0,
          severityBoosted: tc?.summary?.severityBoostedCount || 0,
          ransomwareRisk: tc?.summary?.ransomwareRiskFindings || 0,
          aptRisk: tc?.summary?.aptRiskFindings || 0,
        });
      }

      return { trendPoints, totalRuns: data.length };
    }),

  // ═══ Auto-Gate Escalation Config ═══════════════════════════════════════════
  updateGateEscalationConfig: protectedProcedure
    .input(z.object({
      pipelineId: z.number(),
      escalateOnRansomware: z.boolean(),
      escalateOnApt: z.boolean(),
      escalateOnActorCount: z.number().min(0).max(50).optional(),
      escalateOnExposureScore: z.number().min(0).max(100).optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { sql } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const config = JSON.stringify({
        escalateOnRansomware: input.escalateOnRansomware,
        escalateOnApt: input.escalateOnApt,
        escalateOnActorCount: input.escalateOnActorCount || 0,
        escalateOnExposureScore: input.escalateOnExposureScore || 0,
      });

      await db.execute(sql.raw(
        `UPDATE cicd_pipelines SET cicd_sector_context = JSON_SET(COALESCE(cicd_sector_context, '{}'), '$.gateEscalation', CAST('${config.replace(/'/g, "''")}' AS JSON)) WHERE id = ${input.pipelineId}`
      ));
      return { success: true };
    }),

  getGateEscalationConfig: protectedProcedure
    .input(z.object({ pipelineId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { sql } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const rows = await db.execute(sql.raw(
        `SELECT cicd_sector_context FROM cicd_pipelines WHERE id = ${input.pipelineId}`
      ));
      const row = ((rows as any).rows || rows)?.[0] as any;
      if (!row?.cicd_sector_context) {
        return { escalateOnRansomware: true, escalateOnApt: true, escalateOnActorCount: 3, escalateOnExposureScore: 60 };
      }
      const parsed = typeof row.cicd_sector_context === 'string' ? tryParseJson(row.cicd_sector_context) : row.cicd_sector_context;
      const ge = parsed?.gateEscalation;
      return {
        escalateOnRansomware: ge?.escalateOnRansomware ?? true,
        escalateOnApt: ge?.escalateOnApt ?? true,
        escalateOnActorCount: ge?.escalateOnActorCount ?? 3,
        escalateOnExposureScore: ge?.escalateOnExposureScore ?? 60,
      };
    }),

  // ═══ Engagement Auto-Import ════════════════════════════════════════════════
  autoImportToEngagement: protectedProcedure
    .input(z.object({
      runId: z.number(),
      engagementId: z.number(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdRuns, engagementFindings } = await import("../../drizzle/schema");
      const { sql, eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      // Get the run and its threat context
      const runRows = await db.select().from(cicdRuns).where(eq(cicdRuns.id, input.runId));
      if (!runRows[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Run not found" });

      const run = runRows[0];
      const report = run.cicdReportUrl ? tryParseJson(run.cicdReportUrl as string) : null;
      if (!report?.findings?.length) {
        return { imported: 0, message: "No findings to import" };
      }

      // Get threat context for enrichment
      const tcRows = await db.execute(sql.raw(
        `SELECT cicd_threat_context FROM cicd_runs WHERE id = ${input.runId}`
      ));
      const tcRow = ((tcRows as any).rows || tcRows)?.[0] as any;
      const threatContext = tcRow?.cicd_threat_context
        ? (typeof tcRow.cicd_threat_context === 'string' ? tryParseJson(tcRow.cicd_threat_context) : tcRow.cicd_threat_context)
        : null;

      // Build enriched findings map for quick lookup
      const enrichedMap = new Map<string, any>();
      if (threatContext?.enrichedFindings) {
        for (const ef of threatContext.enrichedFindings) {
          enrichedMap.set(ef.title, ef);
        }
      }

      // Insert findings into engagement_findings
      const now = Date.now();
      let imported = 0;

      for (const finding of report.findings) {
        const enriched = enrichedMap.get(finding.title);
        const severity = enriched?.severity || finding.severity || 'medium';
        const riskTags = enriched?.riskTags || [];
        const attributedGroups = enriched?.attributedGroups || [];

        // Build description with threat intel context
        const descParts = [finding.description || ''];
        if (attributedGroups.length > 0) {
          descParts.push(`\n\n--- THREAT INTELLIGENCE ---`);
          descParts.push(`Attributed Groups: ${attributedGroups.map((g: any) => `${g.groupName} (${g.groupType}, ${g.threatLevel})`).join(', ')}`);
          if (enriched?.severityBoosted) {
            descParts.push(`Severity Boosted: ${enriched.originalSeverity} → ${enriched.severity} (${enriched.boostReason})`);
          }
          if (riskTags.length > 0) {
            descParts.push(`Risk Tags: ${riskTags.join(', ')}`);
          }
          if (enriched?.killChainPhases?.length > 0) {
            descParts.push(`Kill Chain Phases: ${enriched.killChainPhases.join(', ')}`);
          }
        }

        // Extract CVE from title/description
        const cveMatch = (finding.title + ' ' + (finding.description || '')).match(/CVE-\d{4}-\d{4,}/i);
        const cve = cveMatch ? cveMatch[0].toUpperCase() : null;

        try {
          await db.insert(engagementFindings).values({
            engagementId: input.engagementId,
            title: finding.title?.substring(0, 512) || 'CI/CD Finding',
            severity: severity as any,
            cve: cve?.substring(0, 64) || null,
            cwe: finding.cweId?.substring(0, 128) || null,
            description: descParts.join('\n'),
            endpoint: finding.url?.substring(0, 65535) || null,
            source: `cicd-run-${input.runId}`,
            tool: finding.scanner?.substring(0, 128) || 'cicd-pipeline',
            corroborationTier: 'unverified',
            owaspCategory: null,
            mitreTechnique: enriched?.killChainPhases?.[0] || null,
            createdAt: now,
          } as any);
          imported++;
        } catch (insertErr: any) {
          console.warn(`[CICD] Failed to import finding "${finding.title}": ${insertErr.message}`);
        }
      }

      // Also store the engagementId on the run for tracking
      await db.execute(sql.raw(
        `UPDATE cicd_runs SET cicd_run_engagement_id = ${input.engagementId} WHERE id = ${input.runId}`
      ));

      console.log(`[CICD] Auto-imported ${imported}/${report.findings.length} findings from run ${input.runId} to engagement ${input.engagementId}`);
      return { imported, total: report.findings.length, message: `Imported ${imported} findings with threat intelligence context` };
    }),

  getQuickThreatScore: protectedProcedure
    .input(z.object({ runId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cicdRuns } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const rows = await db.select().from(cicdRuns).where(eq(cicdRuns.id, input.runId));
      if (!rows[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Run not found" });

      const report = rows[0].cicdReportUrl ? tryParseJson(rows[0].cicdReportUrl as string) : null;
      if (!report?.findings?.length) {
        return { score: 0, actorCount: 0, hasRansomwareRisk: false, hasAptRisk: false, topActor: null };
      }

      const { quickThreatScore } = await import("../lib/cicd-threat-correlator");
      return quickThreatScore(report.findings);
    }),
});
