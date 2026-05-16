/**
 * SonarQube CI/CD Webhook Receiver
 * 
 * Receives analysis-complete webhooks from SonarQube/SonarCloud,
 * automatically imports findings into the scanner connector framework.
 * 
 * POST /api/webhooks/sonarqube/:webhookId
 * 
 * Flow:
 * 1. Developer pushes code → CI pipeline runs SonarQube analysis
 * 2. SonarQube analysis completes → fires webhook to this endpoint
 * 3. We validate the HMAC signature, parse the quality gate result
 * 4. If quality gate fails or new issues found, auto-import findings
 * 5. Findings appear in the Commercial Scanners dashboard
 */
import type { Express, Request, Response } from "express";
import crypto from "crypto";

export function registerSonarQubeWebhookRoutes(app: Express) {
  app.post("/api/webhooks/sonarqube/:webhookId", async (req: Request, res: Response) => {
    const { webhookId } = req.params;

    if (!webhookId || !webhookId.startsWith("sqw_")) {
      return res.status(400).json({ error: "Invalid webhook ID" });
    }

    console.log(`[SonarQube-Webhook] Received webhook ${webhookId}`);

    try {
      const { getDb } = await import("../db");
      const { sonarqubeWebhooks, scannerFindings, scannerScans } = await import("../../drizzle/schema");
      const { eq, sql } = await import("drizzle-orm");
      const { randomUUID } = await import("crypto");

      const db = await getDb();
      if (!db) {
        return res.status(503).json({ error: "Database unavailable" });
      }

      // Look up webhook config
      const [webhook] = await db.select().from(sonarqubeWebhooks)
        .where(eq(sonarqubeWebhooks.webhookId, webhookId));

      if (!webhook) {
        return res.status(404).json({ error: "Webhook not found" });
      }

      if (!webhook.enabled) {
        return res.status(403).json({ error: "Webhook is disabled" });
      }

      // Validate HMAC signature if secret is configured
      if (webhook.webhookSecret) {
        const rawBody = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
        const expectedSig = crypto
          .createHmac("sha256", webhook.webhookSecret)
          .update(rawBody)
          .digest("hex");

        const receivedSig = req.headers["x-sonar-webhook-hmac-sha256"] as string;
        if (!receivedSig || !crypto.timingSafeEqual(
          Buffer.from(expectedSig, "hex"),
          Buffer.from(receivedSig, "hex")
        )) {
          console.warn(`[SonarQube-Webhook] Invalid HMAC for ${webhookId}`);
          return res.status(401).json({ error: "Invalid signature" });
        }
      }

      // Parse SonarQube webhook payload
      const payload = req.body as SonarQubeWebhookPayload;
      const { project, qualityGate, branch, status: analysisStatus } = payload;

      console.log(`[SonarQube-Webhook] Project: ${project?.key}, Branch: ${branch?.name || "main"}, QG: ${qualityGate?.status}`);

      // Create a scan record for this webhook event
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
        completedAt: sql`CURRENT_TIMESTAMP`,
      });

      // Parse quality gate conditions into findings
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
              status: "open",
            });

            findingsImported++;
          }
        }
      }

      // If new issues were reported in the webhook payload
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
            status: "open",
          });
          findingsImported++;
          mediumCount++;
        }
      }

      // Update scan with counts
      await db.update(scannerScans).set({
        findingsCount: findingsImported,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
      }).where(eq(scannerScans.scanId, scanId));

      // Update webhook last triggered
      await db.update(sonarqubeWebhooks).set({
        lastTriggeredAt: sql`CURRENT_TIMESTAMP`,
        lastStatus: qualityGate?.status || analysisStatus || "unknown",
      }).where(eq(sonarqubeWebhooks.webhookId, webhookId));

      console.log(`[SonarQube-Webhook] Imported ${findingsImported} findings for ${project?.key}`);

      return res.status(200).json({
        received: true,
        scanId,
        findingsImported,
        qualityGateStatus: qualityGate?.status,
      });

    } catch (err: any) {
      console.error(`[SonarQube-Webhook] Error processing webhook ${webhookId}:`, err.message);
      return res.status(500).json({ error: "Internal error processing webhook" });
    }
  });
}

// ─── Types ───────────────────────────────────────────────────────────

interface SonarQubeWebhookPayload {
  serverUrl?: string;
  taskId?: string;
  status?: string;
  analysedAt?: string;
  revision?: string;
  changedAt?: string;
  project?: {
    key: string;
    name: string;
    url?: string;
  };
  branch?: {
    name: string;
    type: string;
    isMain: boolean;
    url?: string;
  };
  qualityGate?: {
    name: string;
    status: "OK" | "ERROR" | "WARN";
    conditions: Array<{
      metric: string;
      metricKey: string;
      operator: string;
      status: "OK" | "ERROR" | "WARN" | "NO_VALUE";
      errorThreshold?: string;
      warningThreshold?: string;
      actualValue?: string;
    }>;
  };
  properties?: Record<string, string>;
}

// ─── Helpers ─────────────────────────────────────────────────────────

function mapSonarSeverity(metricKey: string, conditionStatus: string): string {
  // Critical metrics
  if (metricKey.includes("security_hotspots") || metricKey.includes("vulnerabilities")) {
    return conditionStatus === "ERROR" ? "critical" : "high";
  }
  // High-severity metrics
  if (metricKey.includes("bugs") || metricKey.includes("reliability")) {
    return conditionStatus === "ERROR" ? "high" : "medium";
  }
  // Medium-severity metrics
  if (metricKey.includes("code_smells") || metricKey.includes("coverage") || metricKey.includes("duplicated")) {
    return conditionStatus === "ERROR" ? "medium" : "low";
  }
  // Default
  return conditionStatus === "ERROR" ? "high" : "medium";
}

function formatMetricName(metricKey: string): string {
  return metricKey
    .replace(/_/g, " ")
    .replace(/\b\w/g, c => c.toUpperCase());
}
