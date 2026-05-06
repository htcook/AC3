import "./chunk-KFQGP6VL.js";

// server/lib/cicd-webhook-routes.ts
function registerCicdWebhookRoutes(app) {
  app.post("/api/cicd/webhook/:pipelineId", async (req, res) => {
    const pipelineId = parseInt(req.params.pipelineId, 10);
    if (isNaN(pipelineId)) {
      return res.status(400).json({ error: "Invalid pipeline ID" });
    }
    console.log(`[CICD-WEBHOOK] Received webhook for pipeline ${pipelineId}`);
    try {
      const { getDb } = await import("./db-UCRYETLI.js");
      const { cicdPipelines, cicdRuns } = await import("./schema-5274GLXD.js");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) {
        return res.status(503).json({ error: "Database unavailable" });
      }
      const rows = await db.select().from(cicdPipelines).where(eq(cicdPipelines.id, pipelineId));
      if (!rows[0]) {
        return res.status(404).json({ error: "Pipeline not found" });
      }
      const pipeline = rows[0];
      if (!pipeline.cicdIsActive) {
        return res.status(403).json({ error: "Pipeline is inactive" });
      }
      const secret = pipeline.cicdWebhookSecret;
      if (secret) {
        const rawPayload = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
        const ghSig = req.headers["x-hub-signature-256"];
        const glSig = req.headers["x-webhook-signature"];
        const signature = ghSig || glSig;
        if (signature) {
          const { verifyGitHubWebhook } = await import("./aws-cicd-connector-Q6J3KI6Q.js");
          const valid = verifyGitHubWebhook(rawPayload, signature, secret);
          if (!valid) {
            console.warn(`[CICD-WEBHOOK] Invalid signature for pipeline ${pipelineId}`);
            return res.status(401).json({ error: "Invalid webhook signature" });
          }
        }
      }
      const body = req.body || {};
      const event = body.event || req.headers["x-github-event"] || "unknown";
      const targetUrl = body.target_url || body.deployment?.url || body.repository?.html_url || "";
      const commitSha = body.commit_sha || body.after || body.head_commit?.id || "";
      const branch = body.branch || body.ref?.replace("refs/heads/", "") || "";
      const repository = body.repository?.full_name || body.repository || "";
      const containerImage = body.container_image || body.image || "";
      const iacRepoUrl = body.iac_repo_url || body.repository?.clone_url || "";
      const cloudProvider = body.cloud_provider || "aws";
      const requestedScanTypes = Array.isArray(body.scan_types) ? body.scan_types : ["nuclei", "config"];
      const generateSbom = body.generate_sbom === true;
      const incrementalOnly = body.incremental_only === true;
      const allowedDomains = (() => {
        try {
          return JSON.parse(pipeline.cicd_allowed_domains || "[]");
        } catch {
          return [];
        }
      })();
      const lastBaselineId = pipeline.cicd_last_baseline_id;
      console.log(`[CICD-WEBHOOK] Event: ${event}, Target: ${targetUrl}, Commit: ${commitSha?.substring(0, 7)}`);
      const result = await db.insert(cicdRuns).values({
        cicdRunPipelineId: pipelineId,
        cicdCommitSha: commitSha || null,
        cicdBranch: branch || null,
        cicdRunStatus: "pending"
      });
      const runId = result[0].insertId;
      if (targetUrl) {
        import("./aws-cicd-connector-Q6J3KI6Q.js").then(async ({ executeCicdScan }) => {
          try {
            await db.update(cicdRuns).set({
              cicdRunStatus: "running",
              cicdStartedAt: (/* @__PURE__ */ new Date()).toISOString()
            }).where(eq(cicdRuns.id, runId));
            const scanResult = await executeCicdScan({
              targetUrl,
              scanTypes: requestedScanTypes,
              pipelineId,
              runId,
              commitSha,
              branch,
              failThreshold: pipeline.cicdFailThreshold ?? 7,
              containerImage: containerImage || void 0,
              iacRepoUrl: iacRepoUrl || void 0,
              cloudProvider,
              allowedDomains,
              baselineId: lastBaselineId || void 0,
              generateSbom,
              incrementalOnly
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
                sbomPackageCount: scanResult.sbomPackageCount
              }),
              cicdCompletedAt: (/* @__PURE__ */ new Date()).toISOString()
            }).where(eq(cicdRuns.id, runId));
            console.log(`[CICD-WEBHOOK] Run ${runId} completed: ${scanResult.status}`);
            if (scanResult.status === "failed" || scanResult.status === "error") {
              try {
                const { notifyOwner } = await import("./notification-4RFY3TAD.js");
                const pipelineName = pipeline.cicdName || `Pipeline #${pipelineId}`;
                const severity = scanResult.criticalCount > 0 ? "CRITICAL" : scanResult.highCount > 0 ? "HIGH" : "MEDIUM";
                await notifyOwner({
                  title: `\u26A0\uFE0F CI/CD Gate ${scanResult.status === "error" ? "Error" : "Failed"}: ${pipelineName} (webhook)`,
                  content: [
                    `Pipeline: ${pipelineName} (Run #${runId})`,
                    `Trigger: Webhook (${event})`,
                    `Status: ${scanResult.status.toUpperCase()}`,
                    `Target: ${targetUrl}`,
                    branch ? `Branch: ${branch}` : null,
                    commitSha ? `Commit: ${commitSha.substring(0, 7)}` : null,
                    `Max CVSS: ${scanResult.maxCvss.toFixed(1)} (threshold: ${pipeline.cicdFailThreshold || 7})`,
                    `Findings: ${scanResult.criticalCount} critical, ${scanResult.highCount} high, ${scanResult.mediumCount} medium, ${scanResult.lowCount} low`,
                    scanResult.newFindings ? `New since baseline: ${scanResult.newFindings}` : null,
                    `Severity: ${severity}`,
                    `
Top findings:`,
                    ...scanResult.findings.slice(0, 5).map((f, i) => `  ${i + 1}. [${f.severity?.toUpperCase()}] ${f.title}`)
                  ].filter(Boolean).join("\n")
                });
                console.log(`[CICD-WEBHOOK] Gate failure notification sent for run ${runId}`);
              } catch (notifyErr) {
                console.error(`[CICD-WEBHOOK] Failed to send gate failure notification: ${notifyErr.message}`);
              }
            }
            if (pipeline.cicdProvider === "github_actions" && commitSha && repository) {
              try {
                const githubToken = process.env.GITHUB_PAT || process.env.GITHUB_CLASSIC_TOKEN;
                if (githubToken) {
                  const [owner, repo] = repository.split("/");
                  const { callbackGitHubActions } = await import("./aws-cicd-connector-Q6J3KI6Q.js");
                  await callbackGitHubActions(scanResult, githubToken, owner, repo, commitSha);
                  console.log(`[CICD-WEBHOOK] Posted GitHub Check Run for ${repository}@${commitSha.substring(0, 7)}`);
                }
              } catch (cbErr) {
                console.warn(`[CICD-WEBHOOK] GitHub callback failed: ${cbErr.message}`);
              }
            }
          } catch (err) {
            console.error(`[CICD-WEBHOOK] Run ${runId} error: ${err.message}`);
            await db.update(cicdRuns).set({
              cicdRunStatus: "error",
              cicdCompletedAt: (/* @__PURE__ */ new Date()).toISOString()
            }).where(eq(cicdRuns.id, runId));
            try {
              const { notifyOwner } = await import("./notification-4RFY3TAD.js");
              const pipelineName = pipeline.cicdName || `Pipeline #${pipelineId}`;
              await notifyOwner({
                title: `\u274C CI/CD Scan Error: ${pipelineName} (webhook)`,
                content: `Pipeline "${pipelineName}" (Run #${runId}) encountered an error:
${err.message}

Target: ${targetUrl || "N/A"}
Trigger: Webhook (${event})`
              });
            } catch (notifyErr) {
              console.error(`[CICD-WEBHOOK] Failed to send error notification: ${notifyErr.message}`);
            }
          }
        });
      }
      res.status(202).json({
        accepted: true,
        runId,
        message: targetUrl ? "Webhook received. Security scan started." : "Webhook received. No target URL provided \u2014 run created but no scan triggered."
      });
    } catch (err) {
      console.error(`[CICD-WEBHOOK] Error: ${err.message}`);
      res.status(500).json({ error: "Internal server error" });
    }
  });
  console.log("[CICD-WEBHOOK] Routes mounted at /api/cicd/webhook/:pipelineId");
}
export {
  registerCicdWebhookRoutes
};
