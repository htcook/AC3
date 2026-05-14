/**
 * CI/CD Webhook Express Routes
 * 
 * Public (unauthenticated) endpoints for receiving webhooks from
 * GitHub Actions, GitLab CI, and AWS CodePipeline.
 * 
 * POST /api/cicd/webhook/:pipelineId
 */
import type { Express, Request, Response } from "express";
import crypto from "crypto";

export function registerCicdWebhookRoutes(app: Express) {
  app.post("/api/cicd/webhook/:pipelineId", async (req: Request, res: Response) => {
    const pipelineId = parseInt(req.params.pipelineId, 10);
    if (isNaN(pipelineId)) {
      return res.status(400).json({ error: "Invalid pipeline ID" });
    }

    console.log(`[CICD-WEBHOOK] Received webhook for pipeline ${pipelineId}`);

    try {
      const { getDb } = await import("../db");
      const { cicdPipelines, cicdRuns } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");

      const db = await getDb();
      if (!db) {
        return res.status(503).json({ error: "Database unavailable" });
      }

      // Look up pipeline
      const rows = await db.select().from(cicdPipelines).where(eq(cicdPipelines.id, pipelineId));
      if (!rows[0]) {
        return res.status(404).json({ error: "Pipeline not found" });
      }

      const pipeline = rows[0];
      if (!pipeline.cicdIsActive) {
        return res.status(403).json({ error: "Pipeline is inactive" });
      }

      // Verify webhook signature
      const secret = pipeline.cicdWebhookSecret;
      if (secret) {
        const rawPayload = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
        const ghSig = req.headers["x-hub-signature-256"] as string;
        const glSig = req.headers["x-webhook-signature"] as string;
        const signature = ghSig || glSig;

        if (signature) {
          const { verifyGitHubWebhook } = await import("./aws-cicd-connector");
          const valid = verifyGitHubWebhook(rawPayload, signature, secret);
          if (!valid) {
            console.warn(`[CICD-WEBHOOK] Invalid signature for pipeline ${pipelineId}`);
            return res.status(401).json({ error: "Invalid webhook signature" });
          }
        }
      }

      // Parse webhook payload
      const body = req.body || {};
      const event = body.event || req.headers["x-github-event"] || "unknown";
      const targetUrl = body.target_url || body.deployment?.url || body.repository?.html_url || "";
      const commitSha = body.commit_sha || body.after || body.head_commit?.id || "";
      const branch = body.branch || body.ref?.replace("refs/heads/", "") || "";
      const repository = body.repository?.full_name || body.repository || "";
      const containerImage = body.container_image || body.image || "";
      const iacRepoUrl = body.iac_repo_url || body.repository?.clone_url || "";
      const cloudProvider = body.cloud_provider || "aws";
      // Allow webhook payload to specify scan types; default to nuclei + config
      const requestedScanTypes = Array.isArray(body.scan_types) ? body.scan_types : ["nuclei", "config"];
      const generateSbom = body.generate_sbom === true;
      const incrementalOnly = body.incremental_only === true;
      const allowedDomains = (() => { try { return JSON.parse((pipeline as any).cicd_allowed_domains || '[]'); } catch { return []; } })();
      const lastBaselineId = (pipeline as any).cicd_last_baseline_id;

      console.log(`[CICD-WEBHOOK] Event: ${event}, Target: ${targetUrl}, Commit: ${commitSha?.substring(0, 7)}`);

      // Create a run record
      const result = await db.insert(cicdRuns).values({
        cicdRunPipelineId: pipelineId,
        cicdCommitSha: commitSha || null,
        cicdBranch: branch || null,
        cicdRunStatus: "pending",
      });
      const runId = result[0].insertId;

      // If we have a target URL, kick off the scan asynchronously
      if (targetUrl) {
        import("./aws-cicd-connector").then(async ({ executeCicdScan }) => {
          try {
            await db.update(cicdRuns).set({
              cicdRunStatus: "running",
              cicdStartedAt: new Date().toISOString(),
            } as any).where(eq(cicdRuns.id, runId));

            const scanResult = await executeCicdScan({
              targetUrl,
              scanTypes: requestedScanTypes as any,
              pipelineId,
              runId,
              commitSha,
              branch,
              failThreshold: pipeline.cicdFailThreshold ?? 7.0,
              containerImage: containerImage || undefined,
              iacRepoUrl: iacRepoUrl || undefined,
              cloudProvider: cloudProvider as any,
              allowedDomains,
              baselineId: lastBaselineId || undefined,
              generateSbom,
              incrementalOnly,
            });

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
                findings: scanResult.findings.slice(0, 100),
                newFindings: scanResult.newFindings,
                fixedFindings: scanResult.fixedFindings,
                baselineCompared: scanResult.baselineCompared,
                sbomUrl: scanResult.sbomUrl,
                sbomPackageCount: scanResult.sbomPackageCount,
              }),
              cicdCompletedAt: new Date().toISOString(),
            } as any).where(eq(cicdRuns.id, runId));

            console.log(`[CICD-WEBHOOK] Run ${runId} completed: ${scanResult.status}`);

            // Notify owner on gate failure
            if (scanResult.status === "failed" || scanResult.status === "error") {
              try {
                const { notifyOwner } = await import("../_core/notification");
                const pipelineName = pipeline.cicdName || `Pipeline #${pipelineId}`;
                const severity = scanResult.criticalCount > 0 ? "CRITICAL" : scanResult.highCount > 0 ? "HIGH" : "MEDIUM";
                await notifyOwner({
                  title: `\u26a0\ufe0f CI/CD Gate ${scanResult.status === "error" ? "Error" : "Failed"}: ${pipelineName} (webhook)`,
                  content: [
                    `Pipeline: ${pipelineName} (Run #${runId})`,
                    `Trigger: Webhook (${event})`,
                    `Status: ${scanResult.status.toUpperCase()}`,
                    `Target: ${targetUrl}`,
                    branch ? `Branch: ${branch}` : null,
                    commitSha ? `Commit: ${commitSha.substring(0, 7)}` : null,
                    `Max CVSS: ${scanResult.maxCvss.toFixed(1)} (threshold: ${pipeline.cicdFailThreshold || 7.0})`,
                    `Findings: ${scanResult.criticalCount} critical, ${scanResult.highCount} high, ${scanResult.mediumCount} medium, ${scanResult.lowCount} low`,
                    scanResult.newFindings ? `New since baseline: ${scanResult.newFindings}` : null,
                    `Severity: ${severity}`,
                    `\nTop findings:`,
                    ...scanResult.findings.slice(0, 5).map((f: any, i: number) => `  ${i + 1}. [${f.severity?.toUpperCase()}] ${f.title}`),
                  ].filter(Boolean).join("\n"),
                });
                console.log(`[CICD-WEBHOOK] Gate failure notification sent for run ${runId}`);
              } catch (notifyErr: any) {
                console.error(`[CICD-WEBHOOK] Failed to send gate failure notification: ${notifyErr.message}`);
              }
            }

            // If GitHub webhook, try to post back as a Check Run
            if (pipeline.cicdProvider === "github_actions" && commitSha && repository) {
              try {
                const githubToken = process.env.GITHUB_PAT || process.env.GITHUB_CLASSIC_TOKEN;
                if (githubToken) {
                  const [owner, repo] = repository.split("/");
                  const { callbackGitHubActions } = await import("./aws-cicd-connector");
                  await callbackGitHubActions(scanResult, githubToken, owner, repo, commitSha);
                  console.log(`[CICD-WEBHOOK] Posted GitHub Check Run for ${repository}@${commitSha.substring(0, 7)}`);
                }
              } catch (cbErr: any) {
                console.warn(`[CICD-WEBHOOK] GitHub callback failed: ${cbErr.message}`);
              }
            }
          } catch (err: any) {
            console.error(`[CICD-WEBHOOK] Run ${runId} error: ${err.message}`);
            await db.update(cicdRuns).set({
              cicdRunStatus: "error",
              cicdCompletedAt: new Date().toISOString(),
            } as any).where(eq(cicdRuns.id, runId));

            // Notify owner on scan error
            try {
              const { notifyOwner } = await import("../_core/notification");
              const pipelineName = pipeline.cicdName || `Pipeline #${pipelineId}`;
              await notifyOwner({
                title: `\u274c CI/CD Scan Error: ${pipelineName} (webhook)`,
                content: `Pipeline "${pipelineName}" (Run #${runId}) encountered an error:\n${err.message}\n\nTarget: ${targetUrl || "N/A"}\nTrigger: Webhook (${event})`,
              });
            } catch (notifyErr: any) {
              console.error(`[CICD-WEBHOOK] Failed to send error notification: ${notifyErr.message}`);
            }
          }
        });
      }

      // Respond immediately (scan runs in background)
      res.status(202).json({
        accepted: true,
        runId,
        message: targetUrl
          ? "Webhook received. Security scan started."
          : "Webhook received. No target URL provided — run created but no scan triggered.",
      });
    } catch (err: any) {
      console.error(`[CICD-WEBHOOK] Error: ${err.message}`);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  console.log("[CICD-WEBHOOK] Routes mounted at /api/cicd/webhook/:pipelineId");
}
