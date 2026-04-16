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
              scanTypes: ["nuclei"], // Default to nuclei for webhook-triggered scans
              pipelineId,
              runId,
              commitSha,
              branch,
              failThreshold: pipeline.cicdFailThreshold ?? 7.0,
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
              }),
              cicdCompletedAt: new Date().toISOString(),
            } as any).where(eq(cicdRuns.id, runId));

            console.log(`[CICD-WEBHOOK] Run ${runId} completed: ${scanResult.status}`);

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
