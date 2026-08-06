/**
 * ScoutSuite Multi-Cloud Security Auditing Router
 *
 * Dedicated router for NCC Group's ScoutSuite — a multi-cloud security auditing tool
 * that supports AWS, Azure, GCP, Alibaba Cloud, and Oracle Cloud.
 *
 * ScoutSuite creates comprehensive HTML reports with findings organized by service,
 * severity, and compliance framework. This router triggers scans via the ScanForge
 * server and parses the structured JSON output.
 *
 * Key differences from Prowler:
 *   - ScoutSuite produces a single consolidated JSON report (vs Prowler's per-check JSONL)
 *   - ScoutSuite supports more cloud providers (Alibaba, Oracle, DigitalOcean)
 *   - ScoutSuite focuses on configuration review (vs Prowler's compliance-first approach)
 *   - ScoutSuite generates interactive HTML reports for client delivery
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { executeRawCommand } from "../lib/scan-server-executor";

// ── Types ──────────────────────────────────────────────────────────────────

export interface ScoutSuiteFinding {
  id: string;
  title: string;
  description: string;
  severity: "danger" | "warning" | "info";
  service: string;
  flaggedItems: number;
  checkedItems: number;
  rationale: string;
  remediation: string;
  references: string[];
  compliance: string[];
  items: ScoutSuiteItem[];
}

export interface ScoutSuiteItem {
  resourceId: string;
  resourceName: string;
  region: string;
  metadata: Record<string, any>;
}

export interface ScoutSuiteScanResult {
  provider: string;
  accountId: string;
  totalRules: number;
  totalFindings: number;
  dangerCount: number;
  warningCount: number;
  infoCount: number;
  serviceBreakdown: Record<string, { danger: number; warning: number; info: number }>;
  findings: ScoutSuiteFinding[];
  rawReportPath: string;
  durationMs: number;
  errors: string[];
}

// ── ScoutSuite output parser ──────────────────────────────────────────────

function parseScoutSuiteReport(stdout: string): {
  findings: ScoutSuiteFinding[];
  accountId: string;
  serviceBreakdown: Record<string, { danger: number; warning: number; info: number }>;
} {
  const findings: ScoutSuiteFinding[] = [];
  const serviceBreakdown: Record<string, { danger: number; warning: number; info: number }> = {};
  let accountId = "";

  try {
    const report = JSON.parse(stdout);
    accountId = report.account_id || report.organization_id || "";

    if (report.services) {
      for (const [serviceName, serviceData] of Object.entries(report.services as Record<string, any>)) {
        const svcFindings = serviceData?.findings || {};
        const svcBreakdown = { danger: 0, warning: 0, info: 0 };

        for (const [findingId, finding] of Object.entries(svcFindings as Record<string, any>)) {
          const severity = normalizeSeverity(finding.level || finding.severity || "info");
          const flagged = finding.flagged_items || 0;
          const checked = finding.checked_items || 0;

          if (flagged > 0 || finding.level === "danger") {
            // Extract individual flagged items
            const items: ScoutSuiteItem[] = [];
            if (finding.items) {
              for (const [itemKey, itemData] of Object.entries(finding.items as Record<string, any>)) {
                items.push({
                  resourceId: (itemData as any)?.id || (itemData as any)?.arn || itemKey,
                  resourceName: (itemData as any)?.name || (itemData as any)?.Name || itemKey,
                  region: (itemData as any)?.region || (itemData as any)?.Region || "global",
                  metadata: itemData as Record<string, any>,
                });
              }
            }

            findings.push({
              id: findingId,
              title: finding.description || finding.display_path || findingId,
              description: finding.rationale || finding.description || "",
              severity,
              service: serviceName,
              flaggedItems: flagged,
              checkedItems: checked,
              rationale: finding.rationale || "",
              remediation: finding.remediation || finding.resolution || "",
              references: Array.isArray(finding.references) ? finding.references : [],
              compliance: Array.isArray(finding.compliance)
                ? finding.compliance
                : finding.compliance
                  ? [String(finding.compliance)]
                  : [],
              items,
            });

            if (severity === "danger") svcBreakdown.danger++;
            else if (severity === "warning") svcBreakdown.warning++;
            else svcBreakdown.info++;
          }
        }

        if (svcBreakdown.danger + svcBreakdown.warning + svcBreakdown.info > 0) {
          serviceBreakdown[serviceName] = svcBreakdown;
        }
      }
    }
  } catch {
    // If not valid JSON, try to extract findings from text output
    const lines = stdout.split("\n").filter(l =>
      l.includes("[DANGER]") || l.includes("[WARNING]") || l.includes("FAIL")
    );
    for (const line of lines) {
      const severity = line.includes("[DANGER]") ? "danger" : line.includes("[WARNING]") ? "warning" : "info";
      findings.push({
        id: `scoutsuite-${findings.length}`,
        title: line.trim().replace(/\[DANGER\]|\[WARNING\]/, "").trim().substring(0, 200),
        description: line.trim(),
        severity,
        service: "unknown",
        flaggedItems: 1,
        checkedItems: 1,
        rationale: "",
        remediation: "",
        references: [],
        compliance: [],
        items: [],
      });
    }
  }

  return { findings, accountId, serviceBreakdown };
}

function normalizeSeverity(s: string): ScoutSuiteFinding["severity"] {
  const lower = s.toLowerCase();
  if (lower === "danger" || lower === "critical" || lower === "high") return "danger";
  if (lower === "warning" || lower === "medium") return "warning";
  return "info";
}

// ── Router ─────────────────────────────────────────────────────────────────

export const scoutsuiteIntegrationRouter = router({

  // ── Check if ScoutSuite is installed on scan server ──
  checkAvailability: protectedProcedure
    .query(async () => {
      try {
        const result = await executeRawCommand(
          "python3 -m ScoutSuite --version 2>&1 || scout --version 2>&1 || echo 'NOT_INSTALLED'",
          15
        );
        const output = (result.stdout || "").trim();
        if (output.includes("NOT_INSTALLED") || output.includes("not found") || output.includes("No module")) {
          return { installed: false, version: "" };
        }
        return {
          installed: true,
          version: output.split("\n")[0].trim(),
        };
      } catch {
        return { installed: false, version: "" };
      }
    }),

  // ── Run ScoutSuite scan with provided credentials ──
  runScan: protectedProcedure
    .input(z.object({
      provider: z.enum(["aws", "azure", "gcp", "aliyun", "oci", "do"]),
      credentials: z.record(z.string()),
      services: z.array(z.string()).optional(),
      regions: z.array(z.string()).optional(),
      maxWorkers: z.number().min(1).max(32).default(4),
      timeoutSeconds: z.number().min(60).max(7200).default(900),
    }))
    .mutation(async ({ input }) => {
      const startTime = Date.now();
      const errors: string[] = [];
      const reportDir = `/tmp/scoutsuite-report-${Date.now()}`;

      let cmd = `python3 -m ScoutSuite --provider ${input.provider} --no-browser --result-format json --report-dir ${reportDir}`;
      cmd += ` --max-workers ${input.maxWorkers}`;

      let envPrefix = "";

      // Provider-specific credential setup
      if (input.provider === "aws") {
        envPrefix = `AWS_ACCESS_KEY_ID='${input.credentials.accessKeyId || ""}' ` +
          `AWS_SECRET_ACCESS_KEY='${input.credentials.secretAccessKey || ""}' `;
        if (input.credentials.sessionToken) {
          envPrefix += `AWS_SESSION_TOKEN='${input.credentials.sessionToken}' `;
        }
        if (input.credentials.region) {
          envPrefix += `AWS_DEFAULT_REGION='${input.credentials.region}' `;
        }
        if (input.credentials.roleArn) {
          cmd += ` --role-arn ${input.credentials.roleArn}`;
          if (input.credentials.externalId) {
            cmd += ` --external-id ${input.credentials.externalId}`;
          }
        }
      } else if (input.provider === "azure") {
        cmd += ` --cli`;
        envPrefix = `AZURE_TENANT_ID='${input.credentials.tenantId || ""}' ` +
          `AZURE_CLIENT_ID='${input.credentials.clientId || ""}' ` +
          `AZURE_CLIENT_SECRET='${input.credentials.clientSecret || ""}' `;
        if (input.credentials.subscriptionId) {
          cmd += ` --subscription-ids ${input.credentials.subscriptionId}`;
        }
      } else if (input.provider === "gcp") {
        // GCP uses service account key file — write to temp file
        cmd += ` --service-account /tmp/scoutsuite-gcp-sa.json`;
        if (input.credentials.projectId) {
          cmd += ` --project-id ${input.credentials.projectId}`;
        }
      } else if (input.provider === "do") {
        envPrefix = `DIGITALOCEAN_ACCESS_TOKEN='${input.credentials.token || ""}' `;
      }

      // Service filters
      if (input.services?.length) {
        cmd += ` --services ${input.services.join(" ")}`;
      }

      // Region filters
      if (input.regions?.length) {
        cmd += ` --regions ${input.regions.join(" ")}`;
      }

      cmd = `${envPrefix}${cmd}`;

      try {
        // For GCP, write the service account key to a temp file
        if (input.provider === "gcp" && input.credentials.serviceAccountKey) {
          await executeRawCommand(
            `echo '${input.credentials.serviceAccountKey.replace(/'/g, "\\'")}' > /tmp/scoutsuite-gcp-sa.json && chmod 600 /tmp/scoutsuite-gcp-sa.json`,
            10
          );
        }

        const result = await executeRawCommand(cmd, input.timeoutSeconds);
        const stdout = result.stdout || "";
        const stderr = result.stderr || "";

        if (stderr) {
          // Extract meaningful errors from stderr
          const errorLines = stderr.split("\n").filter(l =>
            l.includes("ERROR") || l.includes("Exception") || l.includes("CRITICAL")
          );
          errors.push(...errorLines.map(l => l.substring(0, 200)));
        }

        // Try to read the JSON report file
        let reportJson = stdout;
        try {
          const readResult = await executeRawCommand(
            `cat ${reportDir}/scoutsuite-results/scoutsuite_results_*.json 2>/dev/null || echo '{}'`,
            10
          );
          if (readResult.stdout && readResult.stdout.trim() !== "{}") {
            reportJson = readResult.stdout;
          }
        } catch { /* use stdout as fallback */ }

        const { findings, accountId, serviceBreakdown } = parseScoutSuiteReport(reportJson);

        const dangerCount = findings.filter(f => f.severity === "danger").length;
        const warningCount = findings.filter(f => f.severity === "warning").length;
        const infoCount = findings.filter(f => f.severity === "info").length;

        const scanResult: ScoutSuiteScanResult = {
          provider: input.provider,
          accountId,
          totalRules: findings.length,
          totalFindings: findings.reduce((sum, f) => sum + f.flaggedItems, 0),
          dangerCount,
          warningCount,
          infoCount,
          serviceBreakdown,
          findings,
          rawReportPath: reportDir,
          durationMs: Date.now() - startTime,
          errors,
        };

        // Clean up GCP key file
        if (input.provider === "gcp") {
          await executeRawCommand("rm -f /tmp/scoutsuite-gcp-sa.json", 5).catch(() => {});
        }

        return scanResult;
      } catch (e: any) {
        // Clean up on error
        if (input.provider === "gcp") {
          await executeRawCommand("rm -f /tmp/scoutsuite-gcp-sa.json", 5).catch(() => {});
        }
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `ScoutSuite scan failed: ${e.message}`,
        });
      }
    }),

  // ── Run scan using stored credential from DB ──
  runScanFromCredential: protectedProcedure
    .input(z.object({
      credentialId: z.number(),
      services: z.array(z.string()).optional(),
      regions: z.array(z.string()).optional(),
      timeoutSeconds: z.number().min(60).max(7200).default(900),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cloudCredentials } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const { decryptCredential } = await import("../lib/credential-crypto");

      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [cred] = await db
        .select()
        .from(cloudCredentials)
        .where(eq(cloudCredentials.id, input.credentialId))
        .limit(1);

      if (!cred) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Credential not found" });
      }

      const credRow = cred as any;
      const decrypted = decryptCredential({
        encryptedData: credRow.encryptedData,
        iv: credRow.encryptionIv,
        tag: credRow.encryptionTag,
      });
      const provider = credRow.credProvider as string;
      const parsed = JSON.parse(decrypted);

      // Map provider to ScoutSuite provider name
      const providerMap: Record<string, string> = {
        aws: "aws",
        azure: "azure",
        gcp: "gcp",
        digitalocean: "do",
        alibaba: "aliyun",
        oracle: "oci",
      };

      const scoutProvider = providerMap[provider] || provider;

      // Build credentials object based on provider
      const credentials: Record<string, string> = {};
      if (provider === "aws") {
        credentials.accessKeyId = parsed.accessKeyId || parsed.access_key_id || "";
        credentials.secretAccessKey = parsed.secretAccessKey || parsed.secret_access_key || "";
        if (parsed.sessionToken) credentials.sessionToken = parsed.sessionToken;
        if (parsed.roleArn) credentials.roleArn = parsed.roleArn;
        if (parsed.externalId) credentials.externalId = parsed.externalId;
        credentials.region = parsed.region || "us-east-1";
      } else if (provider === "azure") {
        credentials.tenantId = parsed.tenantId || credRow.tenantId || "";
        credentials.clientId = parsed.clientId || "";
        credentials.clientSecret = parsed.clientSecret || "";
        if (parsed.subscriptionId || credRow.subscriptionId) {
          credentials.subscriptionId = parsed.subscriptionId || credRow.subscriptionId;
        }
      } else if (provider === "gcp") {
        credentials.serviceAccountKey = typeof parsed === "string" ? parsed : JSON.stringify(parsed);
        if (parsed.project_id) credentials.projectId = parsed.project_id;
      } else if (provider === "digitalocean") {
        credentials.token = parsed.token || parsed.accessToken || "";
      }

      // Delegate to the inline scan
      // We can't directly call another tRPC procedure, so we replicate the logic
      const startTime = Date.now();
      const errors: string[] = [];
      const reportDir = `/tmp/scoutsuite-report-${Date.now()}`;

      let cmd = `python3 -m ScoutSuite --provider ${scoutProvider} --no-browser --result-format json --report-dir ${reportDir} --max-workers 4`;
      let envPrefix = "";

      if (scoutProvider === "aws") {
        envPrefix = `AWS_ACCESS_KEY_ID='${credentials.accessKeyId}' AWS_SECRET_ACCESS_KEY='${credentials.secretAccessKey}' `;
        if (credentials.sessionToken) envPrefix += `AWS_SESSION_TOKEN='${credentials.sessionToken}' `;
        if (credentials.region) envPrefix += `AWS_DEFAULT_REGION='${credentials.region}' `;
        if (credentials.roleArn) {
          cmd += ` --role-arn ${credentials.roleArn}`;
          if (credentials.externalId) cmd += ` --external-id ${credentials.externalId}`;
        }
      } else if (scoutProvider === "azure") {
        cmd += ` --cli`;
        envPrefix = `AZURE_TENANT_ID='${credentials.tenantId}' AZURE_CLIENT_ID='${credentials.clientId}' AZURE_CLIENT_SECRET='${credentials.clientSecret}' `;
        if (credentials.subscriptionId) cmd += ` --subscription-ids ${credentials.subscriptionId}`;
      } else if (scoutProvider === "gcp") {
        await executeRawCommand(
          `echo '${credentials.serviceAccountKey?.replace(/'/g, "\\'")}' > /tmp/scoutsuite-gcp-sa.json && chmod 600 /tmp/scoutsuite-gcp-sa.json`,
          10
        );
        cmd += ` --service-account /tmp/scoutsuite-gcp-sa.json`;
        if (credentials.projectId) cmd += ` --project-id ${credentials.projectId}`;
      } else if (scoutProvider === "do") {
        envPrefix = `DIGITALOCEAN_ACCESS_TOKEN='${credentials.token}' `;
      }

      cmd = `${envPrefix}${cmd}`;
      if (input.services?.length) cmd += ` --services ${input.services.join(" ")}`;
      if (input.regions?.length) cmd += ` --regions ${input.regions.join(" ")}`;

      try {
        const result = await executeRawCommand(cmd, input.timeoutSeconds);
        let reportJson = result.stdout || "";
        try {
          const readResult = await executeRawCommand(
            `cat ${reportDir}/scoutsuite-results/scoutsuite_results_*.json 2>/dev/null || echo '{}'`,
            10
          );
          if (readResult.stdout && readResult.stdout.trim() !== "{}") reportJson = readResult.stdout;
        } catch {}

        const { findings, accountId, serviceBreakdown } = parseScoutSuiteReport(reportJson);

        if (scoutProvider === "gcp") {
          await executeRawCommand("rm -f /tmp/scoutsuite-gcp-sa.json", 5).catch(() => {});
        }

        return {
          provider: scoutProvider,
          accountId,
          totalRules: findings.length,
          totalFindings: findings.reduce((sum, f) => sum + f.flaggedItems, 0),
          dangerCount: findings.filter(f => f.severity === "danger").length,
          warningCount: findings.filter(f => f.severity === "warning").length,
          infoCount: findings.filter(f => f.severity === "info").length,
          serviceBreakdown,
          findings,
          rawReportPath: reportDir,
          durationMs: Date.now() - startTime,
          errors,
        } as ScoutSuiteScanResult;
      } catch (e: any) {
        if (scoutProvider === "gcp") {
          await executeRawCommand("rm -f /tmp/scoutsuite-gcp-sa.json", 5).catch(() => {});
        }
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `ScoutSuite scan failed: ${e.message}`,
        });
      }
    }),

  // ── Get supported providers and their services ──
  getSupportedProviders: protectedProcedure
    .query(() => {
      return {
        aws: {
          label: "Amazon Web Services",
          services: [
            "acm", "awslambda", "cloudformation", "cloudfront", "cloudtrail",
            "cloudwatch", "config", "directconnect", "dynamodb", "ec2",
            "ecs", "elasticache", "elb", "elbv2", "emr", "iam", "kms",
            "rds", "redshift", "route53", "s3", "ses", "sns", "sqs",
            "vpc",
          ],
        },
        azure: {
          label: "Microsoft Azure",
          services: [
            "aad", "appgateway", "appservice", "keyvault", "loadbalancer",
            "monitor", "network", "rbac", "rediscache", "securitycenter",
            "sqldatabase", "storageaccounts", "virtualmachines",
          ],
        },
        gcp: {
          label: "Google Cloud Platform",
          services: [
            "cloudsql", "cloudstorage", "computeengine", "dns", "iam",
            "kms", "logging", "memorystore", "networking", "stackdriverlogging",
            "stackdrivermonitoring",
          ],
        },
        aliyun: {
          label: "Alibaba Cloud",
          services: ["actiontrail", "ecs", "oss", "ram", "rds", "vpc"],
        },
        oci: {
          label: "Oracle Cloud Infrastructure",
          services: ["compute", "identity", "networking", "objectstorage"],
        },
        do: {
          label: "DigitalOcean",
          services: ["database", "droplet", "firewall", "kubernetes", "networking", "spaces"],
        },
      };
    }),

  // ── Download ScoutSuite HTML report ──
  getReportUrl: protectedProcedure
    .input(z.object({ reportDir: z.string() }))
    .query(async ({ input }) => {
      try {
        const result = await executeRawCommand(
          `ls ${input.reportDir}/report*.html 2>/dev/null | head -1`,
          10
        );
        const reportPath = (result.stdout || "").trim();
        if (!reportPath) {
          return { available: false, path: "" };
        }
        return { available: true, path: reportPath };
      } catch {
        return { available: false, path: "" };
      }
    }),
});
