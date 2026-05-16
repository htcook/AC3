import "./chunk-KFQGP6VL.js";

// server/lib/sonarqube-webhook-receiver.ts
import crypto from "crypto";
function registerSonarQubeWebhookRoutes(app) {
  app.post("/api/webhooks/sonarqube/:webhookId", async (req, res) => {
    const { webhookId } = req.params;
    if (!webhookId || !webhookId.startsWith("sqw_")) {
      return res.status(400).json({ error: "Invalid webhook ID" });
    }
    console.log(`[SonarQube-Webhook] Received webhook ${webhookId}`);
    try {
      const { getDb } = await import("./db-GNA5CL3K.js");
      const { sonarqubeWebhooks, scannerFindings, scannerScans } = await import("./schema-RLVX4V4P.js");
      const { eq, sql } = await import("drizzle-orm");
      const { randomUUID } = await import("crypto");
      const db = await getDb();
      if (!db) {
        return res.status(503).json({ error: "Database unavailable" });
      }
      const [webhook] = await db.select().from(sonarqubeWebhooks).where(eq(sonarqubeWebhooks.webhookId, webhookId));
      if (!webhook) {
        return res.status(404).json({ error: "Webhook not found" });
      }
      if (!webhook.enabled) {
        return res.status(403).json({ error: "Webhook is disabled" });
      }
      if (webhook.webhookSecret) {
        const rawBody = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
        const expectedSig = crypto.createHmac("sha256", webhook.webhookSecret).update(rawBody).digest("hex");
        const receivedSig = req.headers["x-sonar-webhook-hmac-sha256"];
        if (!receivedSig || !crypto.timingSafeEqual(
          Buffer.from(expectedSig, "hex"),
          Buffer.from(receivedSig, "hex")
        )) {
          console.warn(`[SonarQube-Webhook] Invalid HMAC for ${webhookId}`);
          return res.status(401).json({ error: "Invalid signature" });
        }
      }
      const payload = req.body;
      const { project, qualityGate, branch, status: analysisStatus } = payload;
      console.log(`[SonarQube-Webhook] Project: ${project?.key}, Branch: ${branch?.name || "main"}, QG: ${qualityGate?.status}`);
      const scanId = `scan_sq_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
      await db.insert(scannerScans).values({
        scanId,
        connectorId: webhook.connectorId,
        platform: "sonarqube",
        scanType: "sast",
        status: "completed",
        targetRef: `${project?.key}:${branch?.name || "main"}`,
        externalScanId: payload.taskId || null,
        startedAt: sql`CURRENT_TIMESTAMP`,
        completedAt: sql`CURRENT_TIMESTAMP`
      });
      let findingsImported = 0;
      let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
      if (qualityGate?.conditions) {
        for (const condition of qualityGate.conditions) {
          if (condition.status === "ERROR" || condition.status === "WARN") {
            const severity = mapSonarSeverity(condition.metricKey, condition.status);
            const findingId = `sf_sq_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
            if (severity === "critical") criticalCount++;
            else if (severity === "high") highCount++;
            else if (severity === "medium") mediumCount++;
            else lowCount++;
            await db.insert(scannerFindings).values({
              findingId,
              scanId,
              connectorId: webhook.connectorId,
              platform: "sonarqube",
              title: `Quality Gate: ${formatMetricName(condition.metricKey)} ${condition.status}`,
              severity,
              description: `Metric "${condition.metricKey}" has value ${condition.actualValue} (threshold: ${condition.errorThreshold || condition.warningThreshold})`,
              affectedAsset: `${project?.key}:${branch?.name || "main"}`,
              affectedComponent: project?.key || null,
              status: "open"
            });
            findingsImported++;
          }
        }
      }
      if (payload.properties?.["sonar.analysis.newIssues"]) {
        const newIssueCount = parseInt(payload.properties["sonar.analysis.newIssues"], 10);
        if (newIssueCount > 0) {
          const findingId = `sf_sq_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
          await db.insert(scannerFindings).values({
            findingId,
            scanId,
            connectorId: webhook.connectorId,
            platform: "sonarqube",
            title: `${newIssueCount} new issue(s) introduced`,
            severity: "medium",
            description: `SonarQube detected ${newIssueCount} new issues on branch ${branch?.name || "main"}`,
            affectedAsset: `${project?.key}:${branch?.name || "main"}`,
            affectedComponent: project?.key || null,
            status: "open"
          });
          findingsImported++;
          mediumCount++;
        }
      }
      await db.update(scannerScans).set({
        findingsCount: findingsImported,
        criticalCount,
        highCount,
        mediumCount,
        lowCount
      }).where(eq(scannerScans.scanId, scanId));
      await db.update(sonarqubeWebhooks).set({
        lastTriggeredAt: sql`CURRENT_TIMESTAMP`,
        lastStatus: qualityGate?.status || analysisStatus || "unknown"
      }).where(eq(sonarqubeWebhooks.webhookId, webhookId));
      console.log(`[SonarQube-Webhook] Imported ${findingsImported} findings for ${project?.key}`);
      return res.status(200).json({
        received: true,
        scanId,
        findingsImported,
        qualityGateStatus: qualityGate?.status
      });
    } catch (err) {
      console.error(`[SonarQube-Webhook] Error processing webhook ${webhookId}:`, err.message);
      return res.status(500).json({ error: "Internal error processing webhook" });
    }
  });
}
function mapSonarSeverity(metricKey, conditionStatus) {
  if (metricKey.includes("security_hotspots") || metricKey.includes("vulnerabilities")) {
    return conditionStatus === "ERROR" ? "critical" : "high";
  }
  if (metricKey.includes("bugs") || metricKey.includes("reliability")) {
    return conditionStatus === "ERROR" ? "high" : "medium";
  }
  if (metricKey.includes("code_smells") || metricKey.includes("coverage") || metricKey.includes("duplicated")) {
    return conditionStatus === "ERROR" ? "medium" : "low";
  }
  return conditionStatus === "ERROR" ? "high" : "medium";
}
function formatMetricName(metricKey) {
  return metricKey.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
export {
  registerSonarQubeWebhookRoutes
};
