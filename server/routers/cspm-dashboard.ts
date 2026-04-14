/**
 * CSPM Dashboard Router
 *
 * Unified Cloud Security Posture Management router that wraps
 * Prowler, ScoutSuite, and Trivy scans with DB persistence.
 * Provides scan history, findings queries, and aggregate stats.
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import {
  createScanRun, completeScanRun, failScanRun, storeFindings,
  storeContainerVulnerabilities, getScanRuns, getScanRunById,
  getFindingsForRun, getContainerVulnsForRun, getScanRunStats,
  getComplianceTrend,
} from "../lib/cspm-db";
import { executeRawCommand } from "../lib/scan-server-executor";

// ── Reuse parsers from prowler-integration ────────────────────────────────

function normalizeSeverity(s: string): "critical" | "high" | "medium" | "low" | "informational" {
  const lower = s.toLowerCase();
  if (lower === "critical") return "critical";
  if (lower === "high") return "high";
  if (lower === "medium") return "medium";
  if (lower === "low") return "low";
  return "informational";
}

function normalizeStatus(s: string): "PASS" | "FAIL" | "WARNING" | "INFO" {
  const upper = s.toUpperCase();
  if (upper === "PASS") return "PASS";
  if (upper === "FAIL") return "FAIL";
  if (upper === "WARNING" || upper === "WARN") return "WARNING";
  return "INFO";
}

function extractFrameworks(obj: any): string[] {
  const frameworks: string[] = [];
  if (obj.Compliance) {
    for (const [framework] of Object.entries(obj.Compliance)) {
      frameworks.push(framework);
    }
  }
  if (obj.compliance_frameworks) {
    frameworks.push(...(Array.isArray(obj.compliance_frameworks) ? obj.compliance_frameworks : []));
  }
  return frameworks;
}

interface ProwlerFinding {
  checkId: string;
  checkTitle: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  status: "PASS" | "FAIL" | "WARNING" | "INFO";
  service: string;
  region: string;
  resourceArn: string;
  resourceId: string;
  description: string;
  risk: string;
  remediation: string;
  complianceFrameworks: string[];
}

function parseProwlerJsonOutput(stdout: string): ProwlerFinding[] {
  const findings: ProwlerFinding[] = [];
  const lines = stdout.split("\n").filter(l => l.trim());
  for (const line of lines) {
    try {
      const obj = JSON.parse(line);
      findings.push({
        checkId: obj.CheckID || obj.check_id || obj.Id || "",
        checkTitle: obj.CheckTitle || obj.check_title || obj.Title || "",
        severity: normalizeSeverity(obj.Severity || obj.severity || "medium"),
        status: normalizeStatus(obj.Status || obj.status || "INFO"),
        service: obj.ServiceName || obj.service || obj.Service || "",
        region: obj.Region || obj.region || "",
        resourceArn: obj.ResourceArn || obj.resource_arn || "",
        resourceId: obj.ResourceId || obj.resource_id || obj.ResourceName || "",
        description: obj.StatusExtended || obj.Description || obj.description || "",
        risk: obj.Risk || obj.risk || "",
        remediation: obj.Remediation?.Recommendation?.Text || obj.remediation || "",
        complianceFrameworks: extractFrameworks(obj),
      });
    } catch { /* skip non-JSON lines */ }
  }
  return findings;
}

function parseScoutSuiteOutput(stdout: string): ProwlerFinding[] {
  const findings: ProwlerFinding[] = [];
  try {
    const report = JSON.parse(stdout);
    if (report.services) {
      for (const [serviceName, serviceData] of Object.entries(report.services as Record<string, any>)) {
        const findingsData = serviceData?.findings || {};
        for (const [findingId, finding] of Object.entries(findingsData as Record<string, any>)) {
          if (finding.flagged_items > 0) {
            findings.push({
              checkId: findingId,
              checkTitle: finding.description || findingId,
              severity: normalizeSeverity(finding.level || "medium"),
              status: "FAIL",
              service: serviceName,
              region: "global",
              resourceArn: "",
              resourceId: `${finding.flagged_items} resources`,
              description: finding.rationale || finding.description || "",
              risk: finding.risk || "",
              remediation: finding.remediation || "",
              complianceFrameworks: finding.references || [],
            });
          }
        }
      }
    }
  } catch {
    const lines = stdout.split("\n").filter(l => l.includes("FAIL") || l.includes("WARNING"));
    for (const line of lines) {
      findings.push({
        checkId: "scoutsuite-finding",
        checkTitle: line.trim().substring(0, 200),
        severity: "medium",
        status: line.includes("FAIL") ? "FAIL" : "WARNING",
        service: "unknown",
        region: "global",
        resourceArn: "",
        resourceId: "",
        description: line.trim(),
        risk: "",
        remediation: "",
        complianceFrameworks: [],
      });
    }
  }
  return findings;
}

// ── Router ─────────────────────────────────────────────────────────────────

export const cspmDashboardRouter = router({

  // ── Aggregate Stats ──
  getStats: protectedProcedure
    .input(z.object({ engagementId: z.number().optional() }).optional())
    .query(async ({ input }) => {
      return getScanRunStats(input?.engagementId);
    }),
  // ── Compliance Trend Data ──
  getComplianceTrend: protectedProcedure
    .input(z.object({
      tool: z.enum(["prowler", "scoutsuite", "trivy"]).optional(),
      days: z.number().min(7).max(365).default(90),
      engagementId: z.number().optional(),
    }).optional())
    .query(async ({ input }) => {
      return getComplianceTrend({
        tool: input?.tool,
        days: input?.days,
        engagementId: input?.engagementId,
      });
    }),

  // ── Scan History ──
  getScanHistory: protectedProcedure
    .input(z.object({
      tool: z.enum(["prowler", "scoutsuite", "trivy"]).optional(),
      provider: z.string().optional(),
      engagementId: z.number().optional(),
      limit: z.number().min(1).max(200).default(50),
    }).optional())
    .query(async ({ input }) => {
      return getScanRuns({
        tool: input?.tool,
        provider: input?.provider,
        engagementId: input?.engagementId,
        limit: input?.limit,
      });
    }),

  // ── Get Scan Run Details ──
  getScanRun: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const run = await getScanRunById(input.id);
      if (!run) throw new TRPCError({ code: "NOT_FOUND", message: "Scan run not found" });
      return run;
    }),

  // ── Get Findings for a Scan Run ──
  getFindings: protectedProcedure
    .input(z.object({
      scanRunId: z.number(),
      severity: z.string().optional(),
      status: z.string().optional(),
      limit: z.number().min(1).max(1000).default(500),
    }))
    .query(async ({ input }) => {
      return getFindingsForRun(input.scanRunId, {
        severity: input.severity,
        status: input.status,
        limit: input.limit,
      });
    }),

  // ── Get Container Vulns for a Scan Run ──
  getContainerVulns: protectedProcedure
    .input(z.object({
      scanRunId: z.number(),
      severity: z.string().optional(),
      limit: z.number().min(1).max(1000).default(500),
    }))
    .query(async ({ input }) => {
      return getContainerVulnsForRun(input.scanRunId, {
        severity: input.severity,
        limit: input.limit,
      });
    }),

  // ── Run Prowler Scan with DB Persistence ──
  runProwlerScan: protectedProcedure
    .input(z.object({
      provider: z.enum(["aws", "azure", "gcp"]),
      credentials: z.record(z.string()),
      services: z.array(z.string()).optional(),
      severity: z.array(z.string()).optional(),
      compliance: z.string().optional(),
      credentialId: z.number().optional(),
      engagementId: z.number().optional(),
      timeoutSeconds: z.number().min(60).max(3600).default(600),
    }))
    .mutation(async ({ input, ctx }) => {
      const scanRunId = await createScanRun({
        credentialId: input.credentialId,
        engagementId: input.engagementId,
        scanTool: "prowler",
        scanProvider: input.provider,
        scanScope: { services: input.services, severity: input.severity, compliance: input.compliance },
        triggeredBy: ctx.user?.name || ctx.user?.openId || "unknown",
        complianceFramework: input.compliance,
      });

      if (!scanRunId) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to create scan run record" });
      }

      const startTime = Date.now();
      try {
        let cmd = `prowler ${input.provider} -M json-ocsf --no-banner`;

        if (input.provider === "aws") {
          const envPrefix = `AWS_ACCESS_KEY_ID='${input.credentials.accessKeyId || ""}' ` +
            `AWS_SECRET_ACCESS_KEY='${input.credentials.secretAccessKey || ""}' `;
          const sessionToken = input.credentials.sessionToken
            ? `AWS_SESSION_TOKEN='${input.credentials.sessionToken}' ` : "";
          const region = input.credentials.region || "us-east-1";
          cmd = `${envPrefix}${sessionToken}AWS_DEFAULT_REGION='${region}' ${cmd}`;
          if (input.credentials.roleArn) {
            cmd += ` -R ${input.credentials.roleArn}`;
            if (input.credentials.externalId) cmd += ` -T ${input.credentials.externalId}`;
          }
        } else if (input.provider === "azure") {
          cmd += ` --sp-env-auth`;
          const envPrefix = `AZURE_TENANT_ID='${input.credentials.tenantId || ""}' ` +
            `AZURE_CLIENT_ID='${input.credentials.clientId || ""}' ` +
            `AZURE_CLIENT_SECRET='${input.credentials.clientSecret || ""}' `;
          if (input.credentials.subscriptionId) cmd += ` --subscription-ids ${input.credentials.subscriptionId}`;
          cmd = `${envPrefix}${cmd}`;
        } else if (input.provider === "gcp") {
          cmd += ` --credentials-file /tmp/gcp-sa-key.json`;
        }

        if (input.services?.length) cmd += ` --services ${input.services.join(" ")}`;
        if (input.severity?.length) cmd += ` --severity ${input.severity.join(" ")}`;
        if (input.compliance) cmd += ` --compliance ${input.compliance}`;

        const result = await executeRawCommand(cmd, input.timeoutSeconds);
        const stdout = result.stdout || "";
        const findings = parseProwlerJsonOutput(stdout);

        const scanResult = {
          provider: input.provider,
          totalChecks: findings.length,
          passed: findings.filter(f => f.status === "PASS").length,
          failed: findings.filter(f => f.status === "FAIL").length,
          warnings: findings.filter(f => f.status === "WARNING").length,
          findings,
          rawOutput: stdout.substring(0, 50000),
          durationMs: Date.now() - startTime,
          errors: [] as string[],
        };

        await completeScanRun(scanRunId, scanResult);
        await storeFindings({ scanRunId, scanTool: "prowler", findings, provider: input.provider });

        return { scanRunId, ...scanResult };
      } catch (e: any) {
        await failScanRun(scanRunId, e.message);
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `Prowler scan failed: ${e.message}` });
      }
    }),

  // ── Run ScoutSuite Scan with DB Persistence ──
  runScoutSuiteScan: protectedProcedure
    .input(z.object({
      provider: z.enum(["aws", "azure", "gcp", "do", "alibaba", "oracle"]),
      credentials: z.record(z.string()),
      services: z.array(z.string()).optional(),
      credentialId: z.number().optional(),
      engagementId: z.number().optional(),
      timeoutSeconds: z.number().min(60).max(3600).default(600),
    }))
    .mutation(async ({ input, ctx }) => {
      const providerMap: Record<string, string> = {
        do: "digitalocean", alibaba: "alibaba", oracle: "oracle",
        aws: "aws", azure: "azure", gcp: "gcp",
      };
      const scanProvider = providerMap[input.provider] || input.provider;

      const scanRunId = await createScanRun({
        credentialId: input.credentialId,
        engagementId: input.engagementId,
        scanTool: "scoutsuite",
        scanProvider,
        scanScope: { services: input.services },
        triggeredBy: ctx.user?.name || ctx.user?.openId || "unknown",
      });

      if (!scanRunId) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to create scan run record" });
      }

      const startTime = Date.now();
      try {
        let cmd = `python3 -m ScoutSuite --provider ${input.provider} --no-browser --result-format json`;

        if (input.provider === "aws") {
          const envPrefix = `AWS_ACCESS_KEY_ID='${input.credentials.accessKeyId || ""}' ` +
            `AWS_SECRET_ACCESS_KEY='${input.credentials.secretAccessKey || ""}' `;
          cmd = `${envPrefix}${cmd}`;
        } else if (input.provider === "azure") {
          cmd += ` --cli`;
          const envPrefix = `AZURE_TENANT_ID='${input.credentials.tenantId || ""}' ` +
            `AZURE_CLIENT_ID='${input.credentials.clientId || ""}' ` +
            `AZURE_CLIENT_SECRET='${input.credentials.clientSecret || ""}' `;
          cmd = `${envPrefix}${cmd}`;
        }

        if (input.services?.length) cmd += ` --services ${input.services.join(" ")}`;

        const result = await executeRawCommand(cmd, input.timeoutSeconds);
        const stdout = result.stdout || "";
        const findings = parseScoutSuiteOutput(stdout);

        const scanResult = {
          provider: input.provider,
          totalChecks: findings.length,
          passed: findings.filter(f => f.status === "PASS").length,
          failed: findings.filter(f => f.status === "FAIL").length,
          warnings: findings.filter(f => f.status === "WARNING").length,
          findings,
          rawOutput: stdout.substring(0, 50000),
          durationMs: Date.now() - startTime,
          errors: [] as string[],
        };

        await completeScanRun(scanRunId, scanResult);
        await storeFindings({ scanRunId, scanTool: "scoutsuite", findings, provider: scanProvider });

        return { scanRunId, ...scanResult };
      } catch (e: any) {
        await failScanRun(scanRunId, e.message);
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `ScoutSuite scan failed: ${e.message}` });
      }
    }),

  // ── Launch scan using a stored credential ID ──
  launchScanFromCredential: protectedProcedure
    .input(z.object({
      credentialId: z.number(),
      tool: z.enum(["prowler", "scoutsuite"]),
      services: z.array(z.string()).optional(),
      compliance: z.string().optional(),
      engagementId: z.number().optional(),
      timeoutSeconds: z.number().min(60).max(3600).default(600),
    }))
    .mutation(async ({ input, ctx }) => {
      // Fetch and decrypt the credential
      const { getDb } = await import("../db");
      const { cloudCredentials } = await import("../../drizzle/schema");
      const { decryptCredentialObject } = await import("../lib/credential-crypto");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const [cred] = await db.select().from(cloudCredentials).where(eq(cloudCredentials.id, input.credentialId));
      if (!cred) throw new TRPCError({ code: "NOT_FOUND", message: "Credential not found" });

      const decrypted = decryptCredentialObject({
        encryptedData: cred.encryptedData,
        iv: cred.encryptionIv,
        tag: cred.encryptionTag,
      });

      // Build credentials map based on provider
      const credentials: Record<string, string> = {};
      switch (cred.credProvider) {
        case "aws":
          credentials.accessKeyId = decrypted.accessKeyId || "";
          credentials.secretAccessKey = decrypted.secretAccessKey || "";
          if (decrypted.sessionToken) credentials.sessionToken = decrypted.sessionToken;
          credentials.region = cred.credRegion || "us-east-1";
          if (cred.roleArn) credentials.roleArn = cred.roleArn;
          if (cred.externalId) credentials.externalId = cred.externalId;
          break;
        case "azure":
          credentials.clientId = decrypted.clientId || "";
          credentials.clientSecret = decrypted.clientSecret || "";
          credentials.tenantId = cred.tenantId || decrypted.tenantId || "";
          if (cred.subscriptionId) credentials.subscriptionId = cred.subscriptionId;
          break;
        case "gcp":
          credentials.projectId = cred.projectId || decrypted.projectId || "";
          credentials.serviceAccountKey = typeof decrypted === "string" ? decrypted : JSON.stringify(decrypted);
          break;
        default:
          // For DO, Alibaba, Oracle — pass through all decrypted fields
          Object.assign(credentials, decrypted);
      }

      // Update lastUsedAt
      await db.update(cloudCredentials)
        .set({ lastUsedAt: new Date() })
        .where(eq(cloudCredentials.id, input.credentialId));

      // Determine provider
      const provider = cred.credProvider as any;

      if (input.tool === "prowler") {
        // Prowler only supports aws, azure, gcp
        if (!["aws", "azure", "gcp"].includes(provider)) {
          throw new TRPCError({ code: "BAD_REQUEST", message: `Prowler does not support provider: ${provider}` });
        }
        // Create scan run
        const scanRunId = await createScanRun({
          credentialId: input.credentialId,
          engagementId: input.engagementId,
          scanTool: "prowler",
          scanProvider: provider,
          scanScope: { services: input.services, compliance: input.compliance },
          triggeredBy: ctx.user?.name || ctx.user?.openId || "unknown",
          complianceFramework: input.compliance,
        });
        if (!scanRunId) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to create scan run" });

        const startTime = Date.now();
        try {
          let cmd = `prowler ${provider} -M json-ocsf --no-banner`;
          if (provider === "aws") {
            cmd = `AWS_ACCESS_KEY_ID='${credentials.accessKeyId}' AWS_SECRET_ACCESS_KEY='${credentials.secretAccessKey}' ${credentials.sessionToken ? `AWS_SESSION_TOKEN='${credentials.sessionToken}' ` : ""}AWS_DEFAULT_REGION='${credentials.region}' ${cmd}`;
            if (credentials.roleArn) cmd += ` -R ${credentials.roleArn}`;
          } else if (provider === "azure") {
            cmd = `AZURE_TENANT_ID='${credentials.tenantId}' AZURE_CLIENT_ID='${credentials.clientId}' AZURE_CLIENT_SECRET='${credentials.clientSecret}' ${cmd} --sp-env-auth`;
          }
          if (input.services?.length) cmd += ` --services ${input.services.join(" ")}`;
          if (input.compliance) cmd += ` --compliance ${input.compliance}`;

          const result = await executeRawCommand(cmd, input.timeoutSeconds);
          const findings = parseProwlerJsonOutput(result.stdout || "");
          const scanResult = {
            provider, totalChecks: findings.length,
            passed: findings.filter(f => f.status === "PASS").length,
            failed: findings.filter(f => f.status === "FAIL").length,
            warnings: findings.filter(f => f.status === "WARNING").length,
            findings, rawOutput: (result.stdout || "").substring(0, 50000),
            durationMs: Date.now() - startTime, errors: [] as string[],
          };
          await completeScanRun(scanRunId, scanResult);
          await storeFindings({ scanRunId, scanTool: "prowler", findings, provider });
          return { scanRunId, tool: "prowler", provider, totalFindings: findings.length, durationMs: scanResult.durationMs };
        } catch (e: any) {
          await failScanRun(scanRunId, e.message);
          throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `Prowler scan failed: ${e.message}` });
        }
      } else {
        // ScoutSuite
        const scanRunId = await createScanRun({
          credentialId: input.credentialId,
          engagementId: input.engagementId,
          scanTool: "scoutsuite",
          scanProvider: provider,
          scanScope: { services: input.services },
          triggeredBy: ctx.user?.name || ctx.user?.openId || "unknown",
        });
        if (!scanRunId) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to create scan run" });

        const startTime = Date.now();
        try {
          let cmd = `python3 -m ScoutSuite --provider ${provider} --no-browser --result-format json`;
          if (provider === "aws") {
            cmd = `AWS_ACCESS_KEY_ID='${credentials.accessKeyId}' AWS_SECRET_ACCESS_KEY='${credentials.secretAccessKey}' ${cmd}`;
          } else if (provider === "azure") {
            cmd = `AZURE_TENANT_ID='${credentials.tenantId}' AZURE_CLIENT_ID='${credentials.clientId}' AZURE_CLIENT_SECRET='${credentials.clientSecret}' ${cmd} --cli`;
          }
          if (input.services?.length) cmd += ` --services ${input.services.join(" ")}`;

          const result = await executeRawCommand(cmd, input.timeoutSeconds);
          const findings = parseScoutSuiteOutput(result.stdout || "");
          const scanResult = {
            provider, totalChecks: findings.length,
            passed: findings.filter(f => f.status === "PASS").length,
            failed: findings.filter(f => f.status === "FAIL").length,
            warnings: findings.filter(f => f.status === "WARNING").length,
            findings, rawOutput: (result.stdout || "").substring(0, 50000),
            durationMs: Date.now() - startTime, errors: [] as string[],
          };
          await completeScanRun(scanRunId, scanResult);
          await storeFindings({ scanRunId, scanTool: "scoutsuite", findings, provider });
          return { scanRunId, tool: "scoutsuite", provider, totalFindings: findings.length, durationMs: scanResult.durationMs };
        } catch (e: any) {
          await failScanRun(scanRunId, e.message);
          throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `ScoutSuite scan failed: ${e.message}` });
        }
      }
    }),

  // ── Run Trivy Image Scan with DB Persistence ──
  runTrivyScan: protectedProcedure
    .input(z.object({
      image: z.string(),
      imageTag: z.string().optional(),
      credentialId: z.number().optional(),
      engagementId: z.number().optional(),
      timeoutSeconds: z.number().min(30).max(1800).default(300),
    }))
    .mutation(async ({ input, ctx }) => {
      const scanRunId = await createScanRun({
        credentialId: input.credentialId,
        engagementId: input.engagementId,
        scanTool: "trivy",
        scanProvider: "docker",
        scanScope: { image: input.image },
        triggeredBy: ctx.user?.name || ctx.user?.openId || "unknown",
      });

      if (!scanRunId) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to create scan run record" });
      }

      const startTime = Date.now();
      try {
        const cmd = `trivy image --format json --severity CRITICAL,HIGH,MEDIUM,LOW ${input.image}`;
        const result = await executeRawCommand(cmd, input.timeoutSeconds);
        const stdout = result.stdout || "";

        let vulns: any[] = [];
        let totalVulns = 0;
        try {
          const report = JSON.parse(stdout);
          const results = report.Results || [];
          for (const r of results) {
            for (const v of (r.Vulnerabilities || [])) {
              vulns.push({
                vulnId: v.VulnerabilityID || "",
                severity: v.Severity || "UNKNOWN",
                pkgName: v.PkgName || "",
                installedVersion: v.InstalledVersion || "",
                fixedVersion: v.FixedVersion || "",
                title: v.Title || "",
                description: (v.Description || "").substring(0, 1000),
                primaryUrl: v.PrimaryURL || "",
                dataSource: v.DataSource?.Name || "",
                publishedDate: v.PublishedDate || "",
                cvssScore: v.CVSS?.nvd?.V3Score?.toString() || "",
              });
            }
          }
          totalVulns = vulns.length;
        } catch { /* parse error */ }

        const severityCounts = {
          critical: vulns.filter(v => v.severity.toLowerCase() === "critical").length,
          high: vulns.filter(v => v.severity.toLowerCase() === "high").length,
          medium: vulns.filter(v => v.severity.toLowerCase() === "medium").length,
          low: vulns.filter(v => v.severity.toLowerCase() === "low").length,
        };

        // Build a ProwlerScanResult-compatible object for completeScanRun
        const scanResult = {
          provider: "docker",
          totalChecks: totalVulns,
          passed: 0,
          failed: totalVulns,
          warnings: 0,
          findings: vulns.map(v => ({
            checkId: v.vulnId,
            checkTitle: v.title,
            severity: normalizeSeverity(v.severity),
            status: "FAIL" as const,
            service: "container",
            region: "",
            resourceArn: input.image,
            resourceId: v.pkgName,
            description: v.description,
            risk: `CVSS: ${v.cvssScore}`,
            remediation: v.fixedVersion ? `Upgrade to ${v.fixedVersion}` : "No fix available",
            complianceFrameworks: [],
          })),
          rawOutput: stdout.substring(0, 50000),
          durationMs: Date.now() - startTime,
          errors: [] as string[],
        };

        await completeScanRun(scanRunId, scanResult);
        await storeContainerVulnerabilities({
          scanRunId,
          imageName: input.image,
          imageTag: input.imageTag,
          vulnerabilities: vulns,
        });

        return { scanRunId, totalVulns, severityCounts, durationMs: scanResult.durationMs };
      } catch (e: any) {
        await failScanRun(scanRunId, e.message);
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `Trivy scan failed: ${e.message}` });
      }
    }),
});
