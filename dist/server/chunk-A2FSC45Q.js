import {
  init_trpc,
  protectedProcedure,
  router
} from "./chunk-NUYG4LPV.js";
import {
  executeRawCommand,
  init_scan_server_executor
} from "./chunk-F4SK4FEZ.js";

// server/routers/prowler-integration.ts
init_trpc();
init_scan_server_executor();
import { z } from "zod";
import { TRPCError } from "@trpc/server";
function parseProwlerJsonOutput(stdout) {
  const findings = [];
  const lines = stdout.split("\n").filter((l) => l.trim());
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
        complianceFrameworks: extractFrameworks(obj)
      });
    } catch {
    }
  }
  return findings;
}
function normalizeSeverity(s) {
  const lower = s.toLowerCase();
  if (lower === "critical") return "critical";
  if (lower === "high") return "high";
  if (lower === "medium") return "medium";
  if (lower === "low") return "low";
  return "informational";
}
function normalizeStatus(s) {
  const upper = s.toUpperCase();
  if (upper === "PASS") return "PASS";
  if (upper === "FAIL") return "FAIL";
  if (upper === "WARNING" || upper === "WARN") return "WARNING";
  return "INFO";
}
function extractFrameworks(obj) {
  const frameworks = [];
  if (obj.Compliance) {
    for (const [framework, details] of Object.entries(obj.Compliance)) {
      frameworks.push(framework);
    }
  }
  if (obj.compliance_frameworks) {
    frameworks.push(...Array.isArray(obj.compliance_frameworks) ? obj.compliance_frameworks : []);
  }
  return frameworks;
}
function parseScoutSuiteOutput(stdout) {
  const findings = [];
  try {
    const report = JSON.parse(stdout);
    if (report.services) {
      for (const [serviceName, serviceData] of Object.entries(report.services)) {
        const findings_data = serviceData?.findings || {};
        for (const [findingId, finding] of Object.entries(findings_data)) {
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
              complianceFrameworks: finding.references || []
            });
          }
        }
      }
    }
  } catch {
    const lines = stdout.split("\n").filter((l) => l.includes("FAIL") || l.includes("WARNING"));
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
        complianceFrameworks: []
      });
    }
  }
  return findings;
}
var prowlerIntegrationRouter = router({
  // ── Check if Prowler/ScoutSuite are installed on scan server ──
  checkAvailability: protectedProcedure.query(async () => {
    const tools = {
      prowler: { installed: false, version: "" },
      scoutsuite: { installed: false, version: "" }
    };
    try {
      const prowlerResult = await executeRawCommand("prowler --version 2>&1 || echo 'NOT_INSTALLED'", 15);
      const prowlerOutput = (prowlerResult.stdout || "").trim();
      if (!prowlerOutput.includes("NOT_INSTALLED") && !prowlerOutput.includes("not found")) {
        tools.prowler.installed = true;
        tools.prowler.version = prowlerOutput.replace(/^prowler\s+/i, "").trim();
      }
    } catch {
    }
    try {
      const scoutResult = await executeRawCommand("scout --version 2>&1 || python3 -m ScoutSuite --version 2>&1 || echo 'NOT_INSTALLED'", 15);
      const scoutOutput = (scoutResult.stdout || "").trim();
      if (!scoutOutput.includes("NOT_INSTALLED") && !scoutOutput.includes("not found")) {
        tools.scoutsuite.installed = true;
        tools.scoutsuite.version = scoutOutput.trim();
      }
    } catch {
    }
    return tools;
  }),
  // ── Run Prowler scan with provided credentials ──
  runProwlerScan: protectedProcedure.input(z.object({
    provider: z.enum(["aws", "azure", "gcp"]),
    credentials: z.record(z.string()),
    services: z.array(z.string()).optional(),
    severity: z.array(z.string()).optional(),
    compliance: z.string().optional(),
    timeoutSeconds: z.number().min(60).max(3600).default(600)
  })).mutation(async ({ input }) => {
    const startTime = Date.now();
    const errors = [];
    let cmd = `prowler ${input.provider} -M json-ocsf --no-banner`;
    if (input.provider === "aws") {
      const envPrefix = `AWS_ACCESS_KEY_ID='${input.credentials.accessKeyId || ""}' AWS_SECRET_ACCESS_KEY='${input.credentials.secretAccessKey || ""}' `;
      const sessionToken = input.credentials.sessionToken ? `AWS_SESSION_TOKEN='${input.credentials.sessionToken}' ` : "";
      const region = input.credentials.region || "us-east-1";
      cmd = `${envPrefix}${sessionToken}AWS_DEFAULT_REGION='${region}' ${cmd}`;
      if (input.credentials.roleArn) {
        cmd += ` -R ${input.credentials.roleArn}`;
        if (input.credentials.externalId) {
          cmd += ` -T ${input.credentials.externalId}`;
        }
      }
    } else if (input.provider === "azure") {
      cmd += ` --sp-env-auth`;
      const envPrefix = `AZURE_TENANT_ID='${input.credentials.tenantId || ""}' AZURE_CLIENT_ID='${input.credentials.clientId || ""}' AZURE_CLIENT_SECRET='${input.credentials.clientSecret || ""}' `;
      if (input.credentials.subscriptionId) {
        cmd += ` --subscription-ids ${input.credentials.subscriptionId}`;
      }
      cmd = `${envPrefix}${cmd}`;
    } else if (input.provider === "gcp") {
      cmd += ` --credentials-file /tmp/gcp-sa-key.json`;
    }
    if (input.services?.length) {
      cmd += ` --services ${input.services.join(" ")}`;
    }
    if (input.severity?.length) {
      cmd += ` --severity ${input.severity.join(" ")}`;
    }
    if (input.compliance) {
      cmd += ` --compliance ${input.compliance}`;
    }
    try {
      const result = await executeRawCommand(cmd, input.timeoutSeconds);
      const stdout = result.stdout || "";
      const stderr = result.stderr || "";
      if (stderr && !stdout) {
        errors.push(stderr.substring(0, 500));
      }
      const findings = parseProwlerJsonOutput(stdout);
      const passed = findings.filter((f) => f.status === "PASS").length;
      const failed = findings.filter((f) => f.status === "FAIL").length;
      const warnings = findings.filter((f) => f.status === "WARNING").length;
      const scanResult = {
        provider: input.provider,
        totalChecks: findings.length,
        passed,
        failed,
        warnings,
        findings,
        rawOutput: stdout.substring(0, 5e4),
        // Cap raw output
        durationMs: Date.now() - startTime,
        errors
      };
      return scanResult;
    } catch (e) {
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: `Prowler scan failed: ${e.message}`
      });
    }
  }),
  // ── Run ScoutSuite scan ──
  runScoutSuiteScan: protectedProcedure.input(z.object({
    provider: z.enum(["aws", "azure", "gcp"]),
    credentials: z.record(z.string()),
    services: z.array(z.string()).optional(),
    timeoutSeconds: z.number().min(60).max(3600).default(600)
  })).mutation(async ({ input }) => {
    const startTime = Date.now();
    const errors = [];
    let cmd = `python3 -m ScoutSuite --provider ${input.provider} --no-browser --result-format json`;
    if (input.provider === "aws") {
      const envPrefix = `AWS_ACCESS_KEY_ID='${input.credentials.accessKeyId || ""}' AWS_SECRET_ACCESS_KEY='${input.credentials.secretAccessKey || ""}' `;
      cmd = `${envPrefix}${cmd}`;
    } else if (input.provider === "azure") {
      cmd += ` --cli`;
      const envPrefix = `AZURE_TENANT_ID='${input.credentials.tenantId || ""}' AZURE_CLIENT_ID='${input.credentials.clientId || ""}' AZURE_CLIENT_SECRET='${input.credentials.clientSecret || ""}' `;
      cmd = `${envPrefix}${cmd}`;
    }
    if (input.services?.length) {
      cmd += ` --services ${input.services.join(" ")}`;
    }
    try {
      const result = await executeRawCommand(cmd, input.timeoutSeconds);
      const stdout = result.stdout || "";
      const findings = parseScoutSuiteOutput(stdout);
      return {
        provider: input.provider,
        totalChecks: findings.length,
        passed: findings.filter((f) => f.status === "PASS").length,
        failed: findings.filter((f) => f.status === "FAIL").length,
        warnings: findings.filter((f) => f.status === "WARNING").length,
        findings,
        rawOutput: stdout.substring(0, 5e4),
        durationMs: Date.now() - startTime,
        errors
      };
    } catch (e) {
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: `ScoutSuite scan failed: ${e.message}`
      });
    }
  }),
  // ── Get available Prowler compliance frameworks ──
  getComplianceFrameworks: protectedProcedure.input(z.object({ provider: z.enum(["aws", "azure", "gcp"]) })).query(({ input }) => {
    const frameworks = {
      aws: [
        "cis_1.4_aws",
        "cis_1.5_aws",
        "cis_2.0_aws",
        "cis_3.0_aws",
        "aws_well_architected_framework_security_pillar",
        "aws_foundational_security_best_practices",
        "pci_3.2.1_aws",
        "hipaa_aws",
        "soc2_aws",
        "nist_800_53_revision_5_aws",
        "nist_csf_1.1_aws",
        "gdpr_aws",
        "iso27001_2013_aws",
        "fedramp_moderate_revision_4_aws",
        "ens_rd2022_aws"
      ],
      azure: [
        "cis_1.1_azure",
        "cis_2.0_azure",
        "cis_2.1_azure",
        "nist_sp_800_53_revision_5_azure",
        "pci_3.2.1_azure",
        "hipaa_azure",
        "mitre_attack_azure"
      ],
      gcp: [
        "cis_1.2_gcp",
        "cis_2.0_gcp",
        "nist_800_53_revision_5_gcp",
        "pci_3.2.1_gcp",
        "mitre_attack_gcp"
      ]
    };
    return frameworks[input.provider] || [];
  }),
  // ── Get available Prowler services per provider ──
  getAvailableServices: protectedProcedure.input(z.object({ provider: z.enum(["aws", "azure", "gcp"]) })).query(({ input }) => {
    const services = {
      aws: [
        "accessanalyzer",
        "account",
        "acm",
        "apigateway",
        "autoscaling",
        "cloudformation",
        "cloudfront",
        "cloudtrail",
        "cloudwatch",
        "codebuild",
        "config",
        "dax",
        "dms",
        "dynamodb",
        "ec2",
        "ecr",
        "ecs",
        "efs",
        "eks",
        "elasticache",
        "elb",
        "elbv2",
        "emr",
        "es",
        "firehose",
        "glacier",
        "glue",
        "guardduty",
        "iam",
        "kinesis",
        "kms",
        "lambda",
        "organizations",
        "rds",
        "redshift",
        "route53",
        "s3",
        "sagemaker",
        "secretsmanager",
        "securityhub",
        "ses",
        "shield",
        "sns",
        "sqs",
        "ssm",
        "trustedadvisor",
        "vpc",
        "waf",
        "wafv2"
      ],
      azure: [
        "aks",
        "appservice",
        "cosmosdb",
        "defender",
        "entra",
        "iam",
        "keyvault",
        "monitor",
        "mysql",
        "network",
        "postgresql",
        "sqlserver",
        "storage",
        "vm"
      ],
      gcp: [
        "bigquery",
        "cloudsql",
        "compute",
        "dns",
        "iam",
        "kms",
        "logging",
        "monitoring",
        "networking",
        "storage"
      ]
    };
    return services[input.provider] || [];
  })
});

export {
  prowlerIntegrationRouter
};
