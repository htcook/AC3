import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb as _getDb } from "../db";
import {
  configBaselines,
  configBaselineRules,
  configScanResults,
  configDriftAlerts,
} from "../../drizzle/schema";
import { eq, desc, sql, and, count, gte, lte } from "drizzle-orm";
import crypto from "crypto";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

function generateId(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${crypto.randomBytes(4).toString("hex")}`;
}

// ─── CIS Benchmark Rule Catalog ──────────────────────────────────────────────

interface CisRule {
  ruleId: string;
  benchmark: string;
  section: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  platform: string;
  expectedValue: string;
  remediationGuidance: string;
  ksiIds: string[];
  mitreIds: string[];
}

const CIS_RULE_CATALOG: CisRule[] = [
  // ── AWS CIS Benchmark v3.0 ──
  { ruleId: "CIS-AWS-1.1", benchmark: "CIS AWS v3.0", section: "1.1", title: "Maintain current contact details", description: "Ensure contact email and phone number are current for AWS account", severity: "medium", platform: "aws", expectedValue: "Contact details verified within 90 days", remediationGuidance: "Update AWS account contact information in the AWS Management Console under Account Settings", ksiIds: ["KSI-PPM-PPR", "KSI-AFR-ADS"], mitreIds: [] },
  { ruleId: "CIS-AWS-1.4", benchmark: "CIS AWS v3.0", section: "1.4", title: "Ensure no root user access key exists", description: "The root user is the most privileged user in an AWS account. AWS Access Keys provide programmatic access to a given AWS account", severity: "critical", platform: "aws", expectedValue: "No access keys for root account", remediationGuidance: "Delete root access keys via IAM console. Use IAM users or roles instead.", ksiIds: ["KSI-IAM-PRA", "KSI-IAM-AAM"], mitreIds: ["T1078", "T1548"] },
  { ruleId: "CIS-AWS-1.5", benchmark: "CIS AWS v3.0", section: "1.5", title: "Ensure MFA is enabled for the root user", description: "The root user has unrestricted access to all resources in the AWS account", severity: "critical", platform: "aws", expectedValue: "MFA enabled on root account", remediationGuidance: "Enable MFA for root user via IAM console > Security credentials > Multi-factor authentication", ksiIds: ["KSI-IAM-MFA", "KSI-IAM-PRA"], mitreIds: ["T1078", "T1110", "T1621"] },
  { ruleId: "CIS-AWS-1.10", benchmark: "CIS AWS v3.0", section: "1.10", title: "Ensure multi-factor authentication (MFA) is enabled for all IAM users", description: "MFA adds an extra layer of protection on top of a user name and password", severity: "high", platform: "aws", expectedValue: "MFA enabled for all IAM users", remediationGuidance: "Enable MFA for each IAM user via IAM console > Users > Security credentials", ksiIds: ["KSI-IAM-MFA"], mitreIds: ["T1078", "T1110"] },
  { ruleId: "CIS-AWS-2.1.1", benchmark: "CIS AWS v3.0", section: "2.1.1", title: "Ensure S3 Bucket Policy is set to deny HTTP requests", description: "S3 buckets should enforce HTTPS-only access", severity: "high", platform: "aws", expectedValue: "Bucket policy denies HTTP (non-TLS) requests", remediationGuidance: "Add bucket policy with condition aws:SecureTransport = false to deny", ksiIds: ["KSI-CNA-EDE"], mitreIds: ["T1557", "T1040"] },
  { ruleId: "CIS-AWS-2.1.2", benchmark: "CIS AWS v3.0", section: "2.1.2", title: "Ensure S3 bucket server-side encryption is enabled", description: "Amazon S3 provides server-side encryption to protect data at rest", severity: "high", platform: "aws", expectedValue: "SSE-S3 or SSE-KMS enabled", remediationGuidance: "Enable default encryption on S3 bucket properties", ksiIds: ["KSI-CNA-EDE"], mitreIds: ["T1552"] },
  { ruleId: "CIS-AWS-2.3.1", benchmark: "CIS AWS v3.0", section: "2.3.1", title: "Ensure RDS instances have encryption at rest enabled", description: "Amazon RDS encrypted instances use AES-256 encryption", severity: "high", platform: "aws", expectedValue: "Encryption at rest enabled", remediationGuidance: "Enable encryption when creating RDS instance (cannot be changed after creation)", ksiIds: ["KSI-CNA-EDE"], mitreIds: ["T1552"] },
  { ruleId: "CIS-AWS-3.1", benchmark: "CIS AWS v3.0", section: "3.1", title: "Ensure CloudTrail is enabled in all regions", description: "CloudTrail records AWS API calls for your account", severity: "critical", platform: "aws", expectedValue: "Multi-region trail enabled", remediationGuidance: "Create a trail in CloudTrail console with 'Apply trail to all regions' enabled", ksiIds: ["KSI-MLA-LET", "KSI-MLA-ALE"], mitreIds: ["T1070", "T1562"] },
  { ruleId: "CIS-AWS-3.4", benchmark: "CIS AWS v3.0", section: "3.4", title: "Ensure CloudTrail log file integrity validation is enabled", description: "CloudTrail log file validation creates a digitally signed digest file", severity: "high", platform: "aws", expectedValue: "Log file validation enabled", remediationGuidance: "Enable log file validation in CloudTrail trail settings", ksiIds: ["KSI-MLA-LET"], mitreIds: ["T1070", "T1070.001"] },
  { ruleId: "CIS-AWS-4.1", benchmark: "CIS AWS v3.0", section: "4.1", title: "Ensure a log metric filter and alarm exist for unauthorized API calls", description: "Monitoring unauthorized API calls will help reveal application errors", severity: "medium", platform: "aws", expectedValue: "CloudWatch alarm configured", remediationGuidance: "Create CloudWatch log metric filter for UnauthorizedAccess events", ksiIds: ["KSI-MLA-ALE", "KSI-MLA-OSM"], mitreIds: ["T1078", "T1562.001"] },
  { ruleId: "CIS-AWS-5.1", benchmark: "CIS AWS v3.0", section: "5.1", title: "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote admin ports", description: "Network ACLs should not allow unrestricted access to remote administration ports", severity: "critical", platform: "aws", expectedValue: "No 0.0.0.0/0 rules for ports 22, 3389", remediationGuidance: "Remove or restrict NACL rules allowing 0.0.0.0/0 to ports 22 and 3389", ksiIds: ["KSI-CNA-NSD"], mitreIds: ["T1021", "T1046"] },
  { ruleId: "CIS-AWS-5.2", benchmark: "CIS AWS v3.0", section: "5.2", title: "Ensure no security groups allow ingress from 0.0.0.0/0 to remote admin ports", description: "Security groups should not allow unrestricted access from the internet", severity: "critical", platform: "aws", expectedValue: "No 0.0.0.0/0 rules for ports 22, 3389", remediationGuidance: "Modify security group rules to restrict source IPs for admin ports", ksiIds: ["KSI-CNA-NSD"], mitreIds: ["T1021", "T1046"] },

  // ── Azure CIS Benchmark v2.1 ──
  { ruleId: "CIS-AZ-1.1.1", benchmark: "CIS Azure v2.1", section: "1.1.1", title: "Ensure Security Defaults is enabled on Azure AD", description: "Security defaults provide secure default settings for Azure AD", severity: "high", platform: "azure", expectedValue: "Security Defaults enabled", remediationGuidance: "Enable Security Defaults in Azure AD > Properties > Manage Security defaults", ksiIds: ["KSI-IAM-MFA", "KSI-IAM-AAM"], mitreIds: ["T1078", "T1110"] },
  { ruleId: "CIS-AZ-1.2.1", benchmark: "CIS Azure v2.1", section: "1.2.1", title: "Ensure MFA is enabled for all Azure AD users", description: "Multi-factor authentication requires users to present two or more forms of identification", severity: "critical", platform: "azure", expectedValue: "MFA enabled for all users", remediationGuidance: "Configure Conditional Access policies requiring MFA for all users", ksiIds: ["KSI-IAM-MFA"], mitreIds: ["T1078", "T1110", "T1621"] },
  { ruleId: "CIS-AZ-2.1.1", benchmark: "CIS Azure v2.1", section: "2.1.1", title: "Ensure Microsoft Defender for Servers is set to On", description: "Microsoft Defender for Servers provides threat detection for compute resources", severity: "high", platform: "azure", expectedValue: "Defender for Servers enabled", remediationGuidance: "Enable in Security Center > Pricing & settings > Defender plans", ksiIds: ["KSI-MLA-OSM", "KSI-MLA-ALE"], mitreIds: ["T1562.001"] },
  { ruleId: "CIS-AZ-3.1", benchmark: "CIS Azure v2.1", section: "3.1", title: "Ensure Storage Account access is restricted with virtual network rules", description: "Storage accounts should restrict network access", severity: "high", platform: "azure", expectedValue: "Network rules configured, default action Deny", remediationGuidance: "Configure Storage Account > Networking > Firewalls and virtual networks", ksiIds: ["KSI-CNA-NSD", "KSI-CNA-EDE"], mitreIds: ["T1046", "T1557"] },
  { ruleId: "CIS-AZ-4.1.1", benchmark: "CIS Azure v2.1", section: "4.1.1", title: "Ensure Azure SQL Database auditing is enabled", description: "Auditing tracks database events and writes them to an audit log", severity: "high", platform: "azure", expectedValue: "Auditing enabled", remediationGuidance: "Enable auditing in SQL Database > Auditing settings", ksiIds: ["KSI-MLA-LET", "KSI-MLA-ALE"], mitreIds: ["T1070", "T1562"] },

  // ── GCP CIS Benchmark v2.0 ──
  { ruleId: "CIS-GCP-1.1", benchmark: "CIS GCP v2.0", section: "1.1", title: "Ensure corporate login credentials are used", description: "Use corporate credentials instead of personal Gmail accounts", severity: "high", platform: "gcp", expectedValue: "Corporate domain accounts only", remediationGuidance: "Configure Cloud Identity with corporate domain and enforce via org policy", ksiIds: ["KSI-IAM-AAM", "KSI-IAM-MFA"], mitreIds: ["T1078", "T1136"] },
  { ruleId: "CIS-GCP-1.3", benchmark: "CIS GCP v2.0", section: "1.3", title: "Ensure MFA is enforced for all accounts", description: "Multi-factor authentication adds additional security for user accounts", severity: "critical", platform: "gcp", expectedValue: "2-Step Verification enforced", remediationGuidance: "Enable 2-Step Verification enforcement in Google Admin > Security > 2-Step Verification", ksiIds: ["KSI-IAM-MFA"], mitreIds: ["T1078", "T1110"] },
  { ruleId: "CIS-GCP-2.1", benchmark: "CIS GCP v2.0", section: "2.1", title: "Ensure Cloud Audit Logging is configured properly", description: "Cloud Audit Logs maintain audit trails for all activities", severity: "critical", platform: "gcp", expectedValue: "Admin Activity and Data Access logs enabled", remediationGuidance: "Configure audit logs in IAM & Admin > Audit Logs for all services", ksiIds: ["KSI-MLA-LET", "KSI-MLA-ALE"], mitreIds: ["T1070", "T1562"] },
  { ruleId: "CIS-GCP-3.1", benchmark: "CIS GCP v2.0", section: "3.1", title: "Ensure default network does not exist", description: "The default network has pre-configured firewall rules that are overly permissive", severity: "high", platform: "gcp", expectedValue: "Default network deleted", remediationGuidance: "Delete the default network and create custom VPC networks with appropriate rules", ksiIds: ["KSI-CNA-NSD"], mitreIds: ["T1046", "T1021"] },
  { ruleId: "CIS-GCP-4.1", benchmark: "CIS GCP v2.0", section: "4.1", title: "Ensure VM instances do not have public IP addresses", description: "Compute instances should not be directly exposed to the internet", severity: "high", platform: "gcp", expectedValue: "No public IPs on VMs", remediationGuidance: "Remove external IPs from VM instances and use Cloud NAT or IAP for access", ksiIds: ["KSI-CNA-NSD", "KSI-CNA-HCI"], mitreIds: ["T1046", "T1021", "T1190"] },

  // ── Kubernetes CIS Benchmark v1.8 ──
  { ruleId: "CIS-K8S-1.1.1", benchmark: "CIS K8s v1.8", section: "1.1.1", title: "Ensure API server pod spec permissions are restricted", description: "The API server pod specification file should have restricted permissions", severity: "high", platform: "kubernetes", expectedValue: "File permissions 600 or more restrictive", remediationGuidance: "chmod 600 /etc/kubernetes/manifests/kube-apiserver.yaml", ksiIds: ["KSI-CNA-HCI", "KSI-IAM-PRA"], mitreIds: ["T1610", "T1611", "T1548"] },
  { ruleId: "CIS-K8S-1.2.1", benchmark: "CIS K8s v1.8", section: "1.2.1", title: "Ensure anonymous authentication is disabled", description: "Anonymous requests should be disabled on the API server", severity: "critical", platform: "kubernetes", expectedValue: "--anonymous-auth=false", remediationGuidance: "Set --anonymous-auth=false in API server configuration", ksiIds: ["KSI-IAM-AAM", "KSI-CNA-HCI"], mitreIds: ["T1078", "T1613"] },
  { ruleId: "CIS-K8S-5.1.1", benchmark: "CIS K8s v1.8", section: "5.1.1", title: "Ensure cluster-admin role is only used where required", description: "The cluster-admin role provides wide-ranging powers over the environment", severity: "critical", platform: "kubernetes", expectedValue: "Minimal cluster-admin bindings", remediationGuidance: "Review and remove unnecessary ClusterRoleBindings for cluster-admin", ksiIds: ["KSI-IAM-PRA", "KSI-CNA-HCI"], mitreIds: ["T1078", "T1548"] },
  { ruleId: "CIS-K8S-5.2.1", benchmark: "CIS K8s v1.8", section: "5.2.1", title: "Ensure Pod Security Standards are enforced", description: "Pod Security Standards define three different policies for pod security", severity: "high", platform: "kubernetes", expectedValue: "Baseline or Restricted policy enforced", remediationGuidance: "Configure PodSecurity admission controller with baseline or restricted policy", ksiIds: ["KSI-CNA-HCI"], mitreIds: ["T1610", "T1611", "T1525"] },
];

// ─── Router ───────────────────────────────────────────────────────────────────

export const configBaselineRouter = router({

  /** Get the CIS benchmark rule catalog */
  getRuleCatalog: protectedProcedure
    .input(z.object({
      platform: z.string().optional(),
      severity: z.enum(["critical", "high", "medium", "low"]).optional(),
    }).optional())
    .query(({ input }) => {
      let rules = CIS_RULE_CATALOG;
      if (input?.platform) rules = rules.filter(r => r.platform === input.platform);
      if (input?.severity) rules = rules.filter(r => r.severity === input.severity);
      return {
        rules,
        totalRules: rules.length,
        platforms: Array.from(new Set(CIS_RULE_CATALOG.map(r => r.platform))),
        benchmarks: Array.from(new Set(CIS_RULE_CATALOG.map(r => r.benchmark))),
      };
    }),

  /** Create a configuration baseline */
  createBaseline: protectedProcedure
    .input(z.object({
      name: z.string(),
      description: z.string().optional(),
      platform: z.string(),
      benchmark: z.string(),
      ruleIds: z.array(z.string()),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const baselineId = generateId("BL");

      const [result] = await db.insert(configBaselines).values({
        baselineId,
        name: input.name,
        description: input.description,
        platform: input.platform,
        benchmark: input.benchmark,
        ruleCount: input.ruleIds.length,
        status: "active",
        createdBy: ctx.user?.id,
        createdByName: ctx.user?.name ?? "System",
      });

      // Insert rules
      for (const ruleId of input.ruleIds) {
        const rule = CIS_RULE_CATALOG.find(r => r.ruleId === ruleId);
        if (rule) {
          await db.insert(configBaselineRules).values({
            baselineId,
            ruleId: rule.ruleId,
            benchmark: rule.benchmark,
            section: rule.section,
            title: rule.title,
            description: rule.description,
            severity: rule.severity,
            platform: rule.platform,
            expectedValue: rule.expectedValue,
            remediationGuidance: rule.remediationGuidance,
            ksiIds: JSON.stringify(rule.ksiIds),
            mitreIds: JSON.stringify(rule.mitreIds),
            enabled: true,
          });
        }
      }

      return { baselineId, ruleCount: input.ruleIds.length };
    }),

  /** List all baselines */
  listBaselines: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    const baselines = await db.select().from(configBaselines)
      .orderBy(desc(configBaselines.createdAt));
    return baselines;
  }),

  /** Get baseline details with rules */
  getBaseline: protectedProcedure
    .input(z.object({ baselineId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const baseline = await db.select().from(configBaselines)
        .where(eq(configBaselines.baselineId, input.baselineId))
        .limit(1);
      if (!baseline[0]) throw new Error("Baseline not found");

      const rules = await db.select().from(configBaselineRules)
        .where(eq(configBaselineRules.baselineId, input.baselineId));

      return { ...baseline[0], rules };
    }),

  /** Run a configuration scan against a baseline */
  runScan: protectedProcedure
    .input(z.object({
      baselineId: z.string(),
      targetName: z.string(),
      targetType: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const scanId = generateId("SCAN");

      // Get baseline rules
      const rules = await db.select().from(configBaselineRules)
        .where(and(
          eq(configBaselineRules.baselineId, input.baselineId),
          eq(configBaselineRules.enabled, true),
        ));

      // Simulate scan results (in production, this would call cloud APIs)
      const results: { ruleId: string; status: "pass" | "fail" | "warning" | "error"; currentValue: string; driftDetected: boolean }[] = [];
      let passCount = 0, failCount = 0, warnCount = 0;

      for (const rule of rules) {
        // Simulate: ~60% pass, ~25% fail, ~15% warning
        const rand = Math.random();
        const status = rand < 0.60 ? "pass" : rand < 0.85 ? "fail" : "warning";
        const driftDetected = status === "fail";

        if (status === "pass") passCount++;
        else if (status === "fail") failCount++;
        else warnCount++;

        results.push({
          ruleId: rule.ruleId,
          status,
          currentValue: status === "pass" ? rule.expectedValue : `Non-compliant: ${rule.title}`,
          driftDetected,
        });

        await db.insert(configScanResults).values({
          scanId,
          baselineId: input.baselineId,
          ruleId: rule.ruleId,
          ruleTitle: rule.title,
          severity: rule.severity,
          status,
          expectedValue: rule.expectedValue,
          currentValue: status === "pass" ? rule.expectedValue : `Non-compliant`,
          driftDetected,
          targetName: input.targetName,
          targetType: input.targetType || "cloud_account",
          scannedBy: ctx.user?.id,
          scannedByName: ctx.user?.name ?? "System",
        });

        // Create drift alert for failures
        if (driftDetected) {
          await db.insert(configDriftAlerts).values({
            alertId: generateId("DRIFT"),
            scanId,
            baselineId: input.baselineId,
            ruleId: rule.ruleId,
            ruleTitle: rule.title,
            severity: rule.severity,
            driftType: "non_compliant",
            description: `Configuration drift detected: ${rule.title} — expected: ${rule.expectedValue}`,
            targetName: input.targetName,
            remediationGuidance: rule.remediationGuidance,
            status: "open",
            ksiIds: rule.ksiIds,
            mitreIds: rule.mitreIds,
          });
        }
      }

      // Update baseline with last scan info
      await db.update(configBaselines)
        .set({
          lastScanAt: new Date(),
          lastScanScore: Math.round((passCount / rules.length) * 100),
        })
        .where(eq(configBaselines.baselineId, input.baselineId));

      return {
        scanId,
        baselineId: input.baselineId,
        targetName: input.targetName,
        totalRules: rules.length,
        passed: passCount,
        failed: failCount,
        warnings: warnCount,
        complianceScore: Math.round((passCount / rules.length) * 100),
        driftAlerts: failCount,
      };
    }),

  /** List scan results for a baseline */
  listScanResults: protectedProcedure
    .input(z.object({
      baselineId: z.string().optional(),
      scanId: z.string().optional(),
      status: z.enum(["pass", "fail", "warning", "error"]).optional(),
      limit: z.number().min(1).max(500).default(100),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      let query = db.select().from(configScanResults);
      const conditions = [];
      if (input?.baselineId) conditions.push(eq(configScanResults.baselineId, input.baselineId));
      if (input?.scanId) conditions.push(eq(configScanResults.scanId, input.scanId));
      if (input?.status) conditions.push(eq(configScanResults.status, input.status));
      if (conditions.length > 0) query = query.where(and(...conditions)) as any;
      return query.orderBy(desc(configScanResults.scannedAt)).limit(input?.limit || 100);
    }),

  /** List drift alerts */
  listDriftAlerts: protectedProcedure
    .input(z.object({
      baselineId: z.string().optional(),
      status: z.enum(["open", "acknowledged", "remediated", "accepted", "false_positive"]).optional(),
      severity: z.enum(["critical", "high", "medium", "low"]).optional(),
      limit: z.number().min(1).max(500).default(100),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      let query = db.select().from(configDriftAlerts);
      const conditions = [];
      if (input?.baselineId) conditions.push(eq(configDriftAlerts.baselineId, input.baselineId));
      if (input?.status) conditions.push(eq(configDriftAlerts.status, input.status));
      if (input?.severity) conditions.push(eq(configDriftAlerts.severity, input.severity));
      if (conditions.length > 0) query = query.where(and(...conditions)) as any;
      return query.orderBy(desc(configDriftAlerts.createdAt)).limit(input?.limit || 100);
    }),

  /** Update drift alert status */
  updateDriftAlert: protectedProcedure
    .input(z.object({
      alertId: z.string(),
      status: z.enum(["open", "acknowledged", "remediated", "accepted", "false_positive"]),
      notes: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.update(configDriftAlerts)
        .set({
          status: input.status,
          resolvedAt: ["remediated", "accepted", "false_positive"].includes(input.status) ? new Date() : undefined,
        })
        .where(eq(configDriftAlerts.alertId, input.alertId));
      return { success: true };
    }),

  /** Get configuration baseline dashboard stats */
  getDashboardStats: protectedProcedure.query(async () => {
    const db = await getDbSafe();

    const totalBaselines = await db.select({ count: count() }).from(configBaselines);
    const activeBaselines = await db.select({ count: count() }).from(configBaselines)
      .where(eq(configBaselines.status, "active"));
    const totalRules = await db.select({ count: count() }).from(configBaselineRules);
    const totalScans = await db.select({ count: count() }).from(configScanResults);
    const openDriftAlerts = await db.select({ count: count() }).from(configDriftAlerts)
      .where(eq(configDriftAlerts.status, "open"));
    const criticalDrifts = await db.select({ count: count() }).from(configDriftAlerts)
      .where(and(eq(configDriftAlerts.status, "open"), eq(configDriftAlerts.severity, "critical")));

    // Drift alerts by severity
    const driftBySeverity = await db.select({
      severity: configDriftAlerts.severity,
      count: count(),
    }).from(configDriftAlerts)
      .where(eq(configDriftAlerts.status, "open"))
      .groupBy(configDriftAlerts.severity);

    // Average compliance score from baselines
    const baselines = await db.select().from(configBaselines);
    const avgScore = baselines.length > 0
      ? Math.round(baselines.reduce((sum, b) => sum + (b.lastScanScore || 0), 0) / baselines.length)
      : 0;

    return {
      totalBaselines: totalBaselines[0]?.count || 0,
      activeBaselines: activeBaselines[0]?.count || 0,
      totalRules: totalRules[0]?.count || 0,
      totalScanResults: totalScans[0]?.count || 0,
      openDriftAlerts: openDriftAlerts[0]?.count || 0,
      criticalDrifts: criticalDrifts[0]?.count || 0,
      driftBySeverity,
      averageComplianceScore: avgScore,
      catalogRuleCount: CIS_RULE_CATALOG.length,
      platforms: Array.from(new Set(CIS_RULE_CATALOG.map(r => r.platform))),
    };
  }),
});
