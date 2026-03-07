/**
 * Cloud Workload Testing Dashboard
 * ═══════════════════════════════════════════════════════════════
 * Unified module that combines existing cloud security modules
 * (CIS validation, IAM enumeration, storage scanning, attack paths,
 * attack chain design) into a single testing dashboard, and adds
 * container/Kubernetes and serverless security testing.
 *
 * Features:
 *   1. Unified Cloud Assessment — Orchestrate all cloud tests from one interface
 *   2. Container/K8s Security — CIS Kubernetes benchmarks, image scanning, RBAC audit
 *   3. Serverless Security — Lambda/Functions/Cloud Run permission analysis
 *   4. Multi-Cloud Comparison — Side-by-side risk scoring across providers
 */

import type { CloudProvider, CISCheck, CheckResult, ValidationAssessment } from "./cloud-security-validation";
import { ALL_CIS_CHECKS, getChecksByProvider, runAssessment, generateComplianceSummary, getProviderStats } from "./cloud-security-validation";
import { FULL_CLOUD_CATALOG, analyzeCloudProvider, getCloudMitreTechniques, IAM_MISCONFIG_CHECKS } from "./cloud-attack-paths";
import { detectCloudAsset, getCloudDetectionPromptContext, CLOUD_MISCONFIG_KNOWLEDGE_BASE } from "./cloud-storage-scanner";

// ═══════════════════════════════════════════════════════════════
// §1 — UNIFIED CLOUD ASSESSMENT
// ═══════════════════════════════════════════════════════════════

export type CloudTestCategory = "cis_benchmark" | "iam_audit" | "storage_scan" | "attack_paths" | "container_k8s" | "serverless" | "network";

export interface CloudTestConfig {
  provider: CloudProvider;
  categories: CloudTestCategory[];
  /** Target scope (account ID, subscription, project) */
  scope?: string;
  /** Specific region to test */
  region?: string;
  /** Include remediation recommendations */
  includeRemediation?: boolean;
  /** Run in simulation mode (no real API calls) */
  simulationMode?: boolean;
}

export interface CloudTestResult {
  id: string;
  category: CloudTestCategory;
  provider: CloudProvider;
  status: "pass" | "fail" | "warning" | "error" | "not_assessed";
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  resource?: string;
  remediation?: string;
  mitreTechnique?: string;
  evidence?: string;
  timestamp: number;
}

export interface CloudAssessmentReport {
  id: string;
  provider: CloudProvider;
  scope: string;
  startedAt: number;
  completedAt: number;
  results: CloudTestResult[];
  summary: CloudAssessmentSummary;
  riskScore: number;
  grade: "A" | "B" | "C" | "D" | "F";
}

export interface CloudAssessmentSummary {
  totalChecks: number;
  passed: number;
  failed: number;
  warnings: number;
  errors: number;
  notAssessed: number;
  bySeverity: Record<string, number>;
  byCategory: Record<string, { total: number; passed: number; failed: number }>;
  complianceScore: number;
}

function computeRiskScore(results: CloudTestResult[]): number {
  if (results.length === 0) return 100;
  const weights = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };
  let totalPenalty = 0;
  let maxPenalty = 0;

  for (const r of results) {
    const w = weights[r.severity] || 0;
    maxPenalty += w;
    if (r.status === "fail") totalPenalty += w;
    else if (r.status === "warning") totalPenalty += w * 0.3;
  }

  return maxPenalty > 0 ? Math.max(0, Math.round(100 - (totalPenalty / maxPenalty) * 100)) : 100;
}

function scoreToGrade(score: number): CloudAssessmentReport["grade"] {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

/**
 * Run a unified cloud assessment across all specified categories.
 */
export function runUnifiedAssessment(config: CloudTestConfig): CloudAssessmentReport {
  const id = `cloud-${config.provider}-${Date.now()}`;
  const startedAt = Date.now();
  const results: CloudTestResult[] = [];

  for (const category of config.categories) {
    switch (category) {
      case "cis_benchmark":
        results.push(...runCISBenchmarkTests(config));
        break;
      case "iam_audit":
        results.push(...runIAMAuditTests(config));
        break;
      case "storage_scan":
        results.push(...runStorageScanTests(config));
        break;
      case "attack_paths":
        results.push(...runAttackPathTests(config));
        break;
      case "container_k8s":
        results.push(...runContainerK8sTests(config));
        break;
      case "serverless":
        results.push(...runServerlessTests(config));
        break;
      case "network":
        results.push(...runNetworkTests(config));
        break;
    }
  }

  const summary = computeAssessmentSummary(results);
  const riskScore = computeRiskScore(results);

  return {
    id,
    provider: config.provider,
    scope: config.scope || "default",
    startedAt,
    completedAt: Date.now(),
    results,
    summary,
    riskScore,
    grade: scoreToGrade(riskScore),
  };
}

function computeAssessmentSummary(results: CloudTestResult[]): CloudAssessmentSummary {
  const summary: CloudAssessmentSummary = {
    totalChecks: results.length,
    passed: 0, failed: 0, warnings: 0, errors: 0, notAssessed: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    byCategory: {},
    complianceScore: 0,
  };

  for (const r of results) {
    if (r.status === "pass") summary.passed++;
    else if (r.status === "fail") summary.failed++;
    else if (r.status === "warning") summary.warnings++;
    else if (r.status === "error") summary.errors++;
    else summary.notAssessed++;

    summary.bySeverity[r.severity] = (summary.bySeverity[r.severity] || 0) + 1;

    if (!summary.byCategory[r.category]) {
      summary.byCategory[r.category] = { total: 0, passed: 0, failed: 0 };
    }
    summary.byCategory[r.category].total++;
    if (r.status === "pass") summary.byCategory[r.category].passed++;
    else if (r.status === "fail") summary.byCategory[r.category].failed++;
  }

  summary.complianceScore = summary.totalChecks > 0
    ? Math.round((summary.passed / summary.totalChecks) * 100)
    : 0;

  return summary;
}

// ═══════════════════════════════════════════════════════════════
// §2 — CIS BENCHMARK TESTS
// ═══════════════════════════════════════════════════════════════

function runCISBenchmarkTests(config: CloudTestConfig): CloudTestResult[] {
  const checks = getChecksByProvider(config.provider);
  return checks.map(check => ({
    id: check.id,
    category: "cis_benchmark" as CloudTestCategory,
    provider: config.provider,
    status: config.simulationMode ? "not_assessed" : "not_assessed",
    title: check.title,
    description: check.description,
    severity: check.severity,
    remediation: config.includeRemediation ? check.remediation : undefined,
    mitreTechnique: check.mitreTechnique,
    timestamp: Date.now(),
  }));
}

// ═══════════════════════════════════════════════════════════════
// §3 — IAM AUDIT TESTS
// ═══════════════════════════════════════════════════════════════

const IAM_CHECKS: Record<CloudProvider, Array<{ id: string; title: string; description: string; severity: CloudTestResult["severity"]; mitre?: string; remediation: string }>> = {
  aws: [
    { id: "iam-aws-001", title: "Root Account MFA", description: "Check if root account has MFA enabled", severity: "critical", mitre: "T1078", remediation: "Enable MFA on the AWS root account using a hardware token." },
    { id: "iam-aws-002", title: "IAM Password Policy", description: "Verify IAM password policy meets complexity requirements", severity: "high", mitre: "T1110", remediation: "Set minimum password length to 14, require uppercase, lowercase, numbers, and symbols." },
    { id: "iam-aws-003", title: "Unused IAM Credentials", description: "Check for IAM credentials not used in 90+ days", severity: "medium", mitre: "T1078.004", remediation: "Disable or delete IAM credentials not used in the last 90 days." },
    { id: "iam-aws-004", title: "Overprivileged IAM Roles", description: "Check for roles with AdministratorAccess or * permissions", severity: "high", mitre: "T1078.004", remediation: "Apply least-privilege policies. Replace wildcard permissions with specific resource ARNs." },
    { id: "iam-aws-005", title: "Access Key Rotation", description: "Check if access keys are rotated within 90 days", severity: "medium", mitre: "T1528", remediation: "Rotate access keys every 90 days. Use IAM roles instead of long-lived access keys." },
    { id: "iam-aws-006", title: "Cross-Account Trust", description: "Audit IAM roles with cross-account trust relationships", severity: "high", mitre: "T1199", remediation: "Review and restrict cross-account trust policies. Use external ID conditions." },
  ],
  azure: [
    { id: "iam-azure-001", title: "Global Admin MFA", description: "Check if Global Administrators have MFA enabled", severity: "critical", mitre: "T1078", remediation: "Enforce MFA for all Global Administrator accounts." },
    { id: "iam-azure-002", title: "Privileged Role Assignments", description: "Audit permanent privileged role assignments", severity: "high", mitre: "T1078.004", remediation: "Use Privileged Identity Management (PIM) for just-in-time access." },
    { id: "iam-azure-003", title: "Guest User Access", description: "Check for excessive guest user permissions", severity: "medium", mitre: "T1078", remediation: "Review guest user access and restrict to necessary resources." },
    { id: "iam-azure-004", title: "Conditional Access Policies", description: "Verify conditional access policies are configured", severity: "high", mitre: "T1078", remediation: "Implement conditional access policies for risky sign-ins and locations." },
    { id: "iam-azure-005", title: "Service Principal Secrets", description: "Check for service principals with expiring or long-lived secrets", severity: "medium", mitre: "T1528", remediation: "Use managed identities instead of service principal secrets where possible." },
  ],
  gcp: [
    { id: "iam-gcp-001", title: "Organization Admin MFA", description: "Check if organization admins have 2FA enabled", severity: "critical", mitre: "T1078", remediation: "Enforce 2-Step Verification for all organization admin accounts." },
    { id: "iam-gcp-002", title: "Primitive Roles Usage", description: "Check for use of primitive roles (Owner, Editor, Viewer)", severity: "high", mitre: "T1078.004", remediation: "Replace primitive roles with predefined or custom IAM roles." },
    { id: "iam-gcp-003", title: "Service Account Key Rotation", description: "Check if service account keys are rotated within 90 days", severity: "medium", mitre: "T1528", remediation: "Rotate service account keys regularly. Prefer workload identity federation." },
    { id: "iam-gcp-004", title: "Domain-Wide Delegation", description: "Audit service accounts with domain-wide delegation", severity: "high", mitre: "T1078.004", remediation: "Restrict domain-wide delegation to essential service accounts only." },
    { id: "iam-gcp-005", title: "Public IAM Bindings", description: "Check for allUsers or allAuthenticatedUsers IAM bindings", severity: "critical", mitre: "T1190", remediation: "Remove public IAM bindings. Use specific user or group bindings." },
  ],
};

function runIAMAuditTests(config: CloudTestConfig): CloudTestResult[] {
  const checks = IAM_CHECKS[config.provider] || [];
  return checks.map(check => ({
    id: check.id,
    category: "iam_audit" as CloudTestCategory,
    provider: config.provider,
    status: config.simulationMode ? "not_assessed" as const : "not_assessed" as const,
    title: check.title,
    description: check.description,
    severity: check.severity,
    mitreTechnique: check.mitre,
    remediation: config.includeRemediation ? check.remediation : undefined,
    timestamp: Date.now(),
  }));
}

// ═══════════════════════════════════════════════════════════════
// §4 — STORAGE SCAN TESTS
// ═══════════════════════════════════════════════════════════════

const STORAGE_CHECKS: Record<CloudProvider, Array<{ id: string; title: string; description: string; severity: CloudTestResult["severity"]; remediation: string }>> = {
  aws: [
    { id: "stor-aws-001", title: "S3 Public Access Block", description: "Check if S3 public access block is enabled at account level", severity: "critical", remediation: "Enable S3 Block Public Access at the account level." },
    { id: "stor-aws-002", title: "S3 Bucket Encryption", description: "Check if all S3 buckets have default encryption enabled", severity: "high", remediation: "Enable default encryption (SSE-S3 or SSE-KMS) on all buckets." },
    { id: "stor-aws-003", title: "S3 Bucket Versioning", description: "Check if critical S3 buckets have versioning enabled", severity: "medium", remediation: "Enable versioning on buckets containing critical data." },
    { id: "stor-aws-004", title: "EBS Volume Encryption", description: "Check if EBS volumes are encrypted", severity: "high", remediation: "Enable default EBS encryption in all regions." },
  ],
  azure: [
    { id: "stor-azure-001", title: "Storage Account Public Access", description: "Check if storage accounts allow public blob access", severity: "critical", remediation: "Disable public blob access on all storage accounts." },
    { id: "stor-azure-002", title: "Storage Account Encryption", description: "Check if storage accounts use customer-managed keys", severity: "medium", remediation: "Use customer-managed keys for storage account encryption." },
    { id: "stor-azure-003", title: "Soft Delete Enabled", description: "Check if soft delete is enabled for blobs and containers", severity: "medium", remediation: "Enable soft delete with a retention period of at least 7 days." },
  ],
  gcp: [
    { id: "stor-gcp-001", title: "Bucket Public Access", description: "Check if Cloud Storage buckets are publicly accessible", severity: "critical", remediation: "Remove allUsers and allAuthenticatedUsers from bucket IAM policies." },
    { id: "stor-gcp-002", title: "Bucket Uniform Access", description: "Check if uniform bucket-level access is enabled", severity: "medium", remediation: "Enable uniform bucket-level access to simplify permissions." },
    { id: "stor-gcp-003", title: "Customer-Managed Encryption", description: "Check if buckets use CMEK encryption", severity: "medium", remediation: "Use customer-managed encryption keys (CMEK) for sensitive data." },
  ],
};

function runStorageScanTests(config: CloudTestConfig): CloudTestResult[] {
  const checks = STORAGE_CHECKS[config.provider] || [];
  return checks.map(check => ({
    id: check.id,
    category: "storage_scan" as CloudTestCategory,
    provider: config.provider,
    status: "not_assessed" as const,
    title: check.title,
    description: check.description,
    severity: check.severity,
    remediation: config.includeRemediation ? check.remediation : undefined,
    timestamp: Date.now(),
  }));
}

// ═══════════════════════════════════════════════════════════════
// §5 — ATTACK PATH TESTS
// ═══════════════════════════════════════════════════════════════

function runAttackPathTests(config: CloudTestConfig): CloudTestResult[] {
  const catalog = FULL_CLOUD_CATALOG.filter(p => p.provider === config.provider);
  return catalog.map(path => ({
    id: `atk-${path.id}`,
    category: "attack_paths" as CloudTestCategory,
    provider: config.provider,
    status: "not_assessed" as const,
    title: path.name,
    description: path.description,
    severity: (path.severity || "medium") as CloudTestResult["severity"],
    mitreTechnique: path.mitreTechnique,
    remediation: config.includeRemediation ? path.remediation : undefined,
    timestamp: Date.now(),
  }));
}

// ═══════════════════════════════════════════════════════════════
// §6 — CONTAINER / KUBERNETES SECURITY
// ═══════════════════════════════════════════════════════════════

export interface K8sSecurityCheck {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: "pod_security" | "rbac" | "network_policy" | "image_security" | "secrets" | "runtime";
  cisReference?: string;
  remediation: string;
  mitreTechnique?: string;
}

export const K8S_SECURITY_CHECKS: K8sSecurityCheck[] = [
  // Pod Security
  { id: "k8s-pod-001", title: "Privileged Containers", description: "Check for containers running in privileged mode", severity: "critical", category: "pod_security", cisReference: "5.2.1", remediation: "Set securityContext.privileged to false. Use Pod Security Standards (restricted).", mitreTechnique: "T1611" },
  { id: "k8s-pod-002", title: "Root User Containers", description: "Check for containers running as root user", severity: "high", category: "pod_security", cisReference: "5.2.6", remediation: "Set runAsNonRoot: true and specify a non-root runAsUser.", mitreTechnique: "T1611" },
  { id: "k8s-pod-003", title: "Host Network Access", description: "Check for pods with hostNetwork enabled", severity: "high", category: "pod_security", cisReference: "5.2.4", remediation: "Disable hostNetwork unless absolutely required. Use NetworkPolicies instead.", mitreTechnique: "T1557" },
  { id: "k8s-pod-004", title: "Host PID Namespace", description: "Check for pods sharing host PID namespace", severity: "high", category: "pod_security", cisReference: "5.2.2", remediation: "Set hostPID to false to prevent process visibility across the host.", mitreTechnique: "T1057" },
  { id: "k8s-pod-005", title: "Capability Escalation", description: "Check for containers with dangerous Linux capabilities (SYS_ADMIN, NET_ADMIN)", severity: "critical", category: "pod_security", cisReference: "5.2.7", remediation: "Drop all capabilities and add only required ones. Never use SYS_ADMIN.", mitreTechnique: "T1611" },
  { id: "k8s-pod-006", title: "Read-Only Root Filesystem", description: "Check if containers use read-only root filesystem", severity: "medium", category: "pod_security", remediation: "Set readOnlyRootFilesystem: true and use emptyDir volumes for writable paths." },

  // RBAC
  { id: "k8s-rbac-001", title: "Cluster-Admin Bindings", description: "Audit ClusterRoleBindings to cluster-admin role", severity: "critical", category: "rbac", cisReference: "5.1.1", remediation: "Minimize cluster-admin bindings. Use namespace-scoped roles where possible.", mitreTechnique: "T1078.004" },
  { id: "k8s-rbac-002", title: "Wildcard RBAC Rules", description: "Check for RBAC rules with wildcard (*) permissions", severity: "high", category: "rbac", cisReference: "5.1.3", remediation: "Replace wildcard permissions with specific resource and verb lists.", mitreTechnique: "T1078.004" },
  { id: "k8s-rbac-003", title: "Service Account Token Automount", description: "Check if service account tokens are auto-mounted unnecessarily", severity: "medium", category: "rbac", cisReference: "5.1.6", remediation: "Set automountServiceAccountToken: false for pods that don't need API access.", mitreTechnique: "T1528" },
  { id: "k8s-rbac-004", title: "Default Service Account Usage", description: "Check for pods using the default service account", severity: "medium", category: "rbac", remediation: "Create dedicated service accounts for each workload with minimal permissions." },

  // Network Policy
  { id: "k8s-net-001", title: "Default Deny Network Policy", description: "Check if namespaces have default deny network policies", severity: "high", category: "network_policy", remediation: "Create a default deny-all ingress and egress NetworkPolicy in each namespace.", mitreTechnique: "T1046" },
  { id: "k8s-net-002", title: "Pod-to-Pod Communication", description: "Check for unrestricted pod-to-pod communication", severity: "medium", category: "network_policy", remediation: "Implement NetworkPolicies to restrict pod communication to required paths only.", mitreTechnique: "T1021" },
  { id: "k8s-net-003", title: "External Egress Control", description: "Check if pods can reach external networks without restriction", severity: "high", category: "network_policy", remediation: "Restrict egress traffic to known-good destinations using NetworkPolicies.", mitreTechnique: "T1048" },

  // Image Security
  { id: "k8s-img-001", title: "Image Pull Policy", description: "Check if containers use 'Always' image pull policy", severity: "medium", category: "image_security", remediation: "Set imagePullPolicy to Always and use immutable image tags (digests)." },
  { id: "k8s-img-002", title: "Latest Tag Usage", description: "Check for containers using the 'latest' tag", severity: "high", category: "image_security", remediation: "Use specific version tags or SHA256 digests instead of 'latest'.", mitreTechnique: "T1525" },
  { id: "k8s-img-003", title: "Trusted Registry", description: "Check if images are pulled from trusted registries only", severity: "high", category: "image_security", remediation: "Use admission controllers (OPA/Gatekeeper) to restrict image sources to trusted registries.", mitreTechnique: "T1525" },

  // Secrets
  { id: "k8s-sec-001", title: "Secrets Encryption at Rest", description: "Check if etcd encryption is enabled for secrets", severity: "critical", category: "secrets", cisReference: "1.2.29", remediation: "Enable encryption at rest for etcd using EncryptionConfiguration.", mitreTechnique: "T1552" },
  { id: "k8s-sec-002", title: "Secrets in Environment Variables", description: "Check for secrets passed as environment variables instead of volumes", severity: "medium", category: "secrets", remediation: "Mount secrets as volumes instead of environment variables to reduce exposure.", mitreTechnique: "T1552.001" },

  // Runtime
  { id: "k8s-rt-001", title: "Seccomp Profile", description: "Check if pods have seccomp profiles configured", severity: "medium", category: "runtime", remediation: "Apply RuntimeDefault or custom seccomp profiles to all pods.", mitreTechnique: "T1611" },
  { id: "k8s-rt-002", title: "AppArmor Profile", description: "Check if pods have AppArmor profiles configured", severity: "medium", category: "runtime", remediation: "Apply AppArmor profiles to restrict container system calls.", mitreTechnique: "T1611" },
  { id: "k8s-rt-003", title: "Resource Limits", description: "Check if containers have CPU and memory limits set", severity: "medium", category: "runtime", remediation: "Set resource requests and limits for all containers to prevent resource exhaustion.", mitreTechnique: "T1499" },
];

function runContainerK8sTests(config: CloudTestConfig): CloudTestResult[] {
  return K8S_SECURITY_CHECKS.map(check => ({
    id: check.id,
    category: "container_k8s" as CloudTestCategory,
    provider: config.provider,
    status: "not_assessed" as const,
    title: check.title,
    description: check.description,
    severity: check.severity,
    mitreTechnique: check.mitreTechnique,
    remediation: config.includeRemediation ? check.remediation : undefined,
    timestamp: Date.now(),
  }));
}

// ═══════════════════════════════════════════════════════════════
// §7 — SERVERLESS SECURITY
// ═══════════════════════════════════════════════════════════════

export interface ServerlessSecurityCheck {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  provider: CloudProvider;
  service: string;
  remediation: string;
  mitreTechnique?: string;
}

export const SERVERLESS_SECURITY_CHECKS: ServerlessSecurityCheck[] = [
  // AWS Lambda
  { id: "sls-aws-001", title: "Lambda Execution Role Overprivilege", description: "Check if Lambda functions have overly permissive execution roles", severity: "high", provider: "aws", service: "Lambda", remediation: "Apply least-privilege IAM policies to Lambda execution roles.", mitreTechnique: "T1078.004" },
  { id: "sls-aws-002", title: "Lambda Public URL", description: "Check if Lambda function URLs are publicly accessible without auth", severity: "critical", provider: "aws", service: "Lambda", remediation: "Require IAM authentication for Lambda function URLs.", mitreTechnique: "T1190" },
  { id: "sls-aws-003", title: "Lambda Environment Secrets", description: "Check for sensitive data in Lambda environment variables", severity: "high", provider: "aws", service: "Lambda", remediation: "Use AWS Secrets Manager or SSM Parameter Store instead of environment variables.", mitreTechnique: "T1552.001" },
  { id: "sls-aws-004", title: "Lambda VPC Configuration", description: "Check if Lambda functions accessing private resources are in a VPC", severity: "medium", provider: "aws", service: "Lambda", remediation: "Place Lambda functions in a VPC when they need to access private resources." },
  { id: "sls-aws-005", title: "Lambda Runtime Version", description: "Check if Lambda functions use deprecated or EOL runtimes", severity: "medium", provider: "aws", service: "Lambda", remediation: "Upgrade Lambda functions to supported runtime versions." },
  { id: "sls-aws-006", title: "API Gateway Authorization", description: "Check if API Gateway endpoints have proper authorization", severity: "critical", provider: "aws", service: "API Gateway", remediation: "Enable IAM, Cognito, or Lambda authorizers on all API Gateway endpoints.", mitreTechnique: "T1190" },

  // Azure Functions
  { id: "sls-azure-001", title: "Function App Authentication", description: "Check if Azure Functions have authentication enabled", severity: "high", provider: "azure", service: "Functions", remediation: "Enable App Service Authentication (Easy Auth) for all function apps.", mitreTechnique: "T1190" },
  { id: "sls-azure-002", title: "Function App Managed Identity", description: "Check if functions use managed identities instead of connection strings", severity: "medium", provider: "azure", service: "Functions", remediation: "Use system-assigned managed identities for Azure resource access.", mitreTechnique: "T1528" },
  { id: "sls-azure-003", title: "Function App HTTPS Only", description: "Check if function apps enforce HTTPS", severity: "high", provider: "azure", service: "Functions", remediation: "Enable HTTPS Only in function app configuration.", mitreTechnique: "T1557" },
  { id: "sls-azure-004", title: "Function App Runtime Version", description: "Check if function apps use supported runtime versions", severity: "medium", provider: "azure", service: "Functions", remediation: "Upgrade to the latest supported Azure Functions runtime." },

  // GCP Cloud Functions / Cloud Run
  { id: "sls-gcp-001", title: "Cloud Function Public Access", description: "Check if Cloud Functions allow unauthenticated invocations", severity: "critical", provider: "gcp", service: "Cloud Functions", remediation: "Remove allUsers invoker binding. Require authentication for all functions.", mitreTechnique: "T1190" },
  { id: "sls-gcp-002", title: "Cloud Run Public Access", description: "Check if Cloud Run services allow unauthenticated access", severity: "high", provider: "gcp", service: "Cloud Run", remediation: "Require authentication for Cloud Run services unless they are public APIs.", mitreTechnique: "T1190" },
  { id: "sls-gcp-003", title: "Cloud Function Service Account", description: "Check if functions use the default compute service account", severity: "high", provider: "gcp", service: "Cloud Functions", remediation: "Create dedicated service accounts with minimal permissions for each function.", mitreTechnique: "T1078.004" },
  { id: "sls-gcp-004", title: "Cloud Run Ingress Settings", description: "Check if Cloud Run services restrict ingress to internal traffic", severity: "medium", provider: "gcp", service: "Cloud Run", remediation: "Set ingress to 'internal' or 'internal-and-cloud-load-balancing' where possible." },
];

function runServerlessTests(config: CloudTestConfig): CloudTestResult[] {
  const checks = SERVERLESS_SECURITY_CHECKS.filter(c => c.provider === config.provider);
  return checks.map(check => ({
    id: check.id,
    category: "serverless" as CloudTestCategory,
    provider: config.provider,
    status: "not_assessed" as const,
    title: check.title,
    description: check.description,
    severity: check.severity,
    resource: check.service,
    mitreTechnique: check.mitreTechnique,
    remediation: config.includeRemediation ? check.remediation : undefined,
    timestamp: Date.now(),
  }));
}

// ═══════════════════════════════════════════════════════════════
// §8 — NETWORK SECURITY TESTS
// ═══════════════════════════════════════════════════════════════

const NETWORK_CHECKS: Record<CloudProvider, Array<{ id: string; title: string; description: string; severity: CloudTestResult["severity"]; remediation: string; mitre?: string }>> = {
  aws: [
    { id: "net-aws-001", title: "Security Group Open Ports", description: "Check for security groups with 0.0.0.0/0 inbound rules", severity: "critical", remediation: "Restrict security group inbound rules to specific CIDR ranges.", mitre: "T1190" },
    { id: "net-aws-002", title: "VPC Flow Logs", description: "Check if VPC flow logs are enabled", severity: "high", remediation: "Enable VPC flow logs for all VPCs and send to CloudWatch or S3.", mitre: "T1562.008" },
    { id: "net-aws-003", title: "Default VPC Usage", description: "Check if resources are deployed in the default VPC", severity: "medium", remediation: "Create custom VPCs with proper subnet segmentation." },
  ],
  azure: [
    { id: "net-azure-001", title: "NSG Open Ports", description: "Check for NSGs with Any/Any inbound rules", severity: "critical", remediation: "Restrict NSG inbound rules to specific source addresses and ports.", mitre: "T1190" },
    { id: "net-azure-002", title: "Network Watcher", description: "Check if Network Watcher is enabled in all regions", severity: "high", remediation: "Enable Network Watcher in all regions with active resources.", mitre: "T1562.008" },
    { id: "net-azure-003", title: "Private Endpoints", description: "Check if PaaS services use private endpoints", severity: "medium", remediation: "Use private endpoints for Azure PaaS services to avoid public exposure." },
  ],
  gcp: [
    { id: "net-gcp-001", title: "Firewall Rules Open Ports", description: "Check for firewall rules allowing 0.0.0.0/0 ingress", severity: "critical", remediation: "Restrict firewall rules to specific source ranges.", mitre: "T1190" },
    { id: "net-gcp-002", title: "VPC Flow Logs", description: "Check if VPC flow logs are enabled for all subnets", severity: "high", remediation: "Enable VPC flow logs on all subnets.", mitre: "T1562.008" },
    { id: "net-gcp-003", title: "Private Google Access", description: "Check if Private Google Access is enabled for subnets", severity: "medium", remediation: "Enable Private Google Access to avoid routing through public internet." },
  ],
};

function runNetworkTests(config: CloudTestConfig): CloudTestResult[] {
  const checks = NETWORK_CHECKS[config.provider] || [];
  return checks.map(check => ({
    id: check.id,
    category: "network" as CloudTestCategory,
    provider: config.provider,
    status: "not_assessed" as const,
    title: check.title,
    description: check.description,
    severity: check.severity,
    mitreTechnique: check.mitre,
    remediation: config.includeRemediation ? check.remediation : undefined,
    timestamp: Date.now(),
  }));
}

// ═══════════════════════════════════════════════════════════════
// §9 — MULTI-CLOUD COMPARISON
// ═══════════════════════════════════════════════════════════════

export interface MultiCloudComparison {
  providers: Array<{
    provider: CloudProvider;
    riskScore: number;
    grade: string;
    totalChecks: number;
    passed: number;
    failed: number;
    criticalFindings: number;
    highFindings: number;
    complianceScore: number;
  }>;
  worstProvider: CloudProvider;
  bestProvider: CloudProvider;
  commonGaps: string[];
  generatedAt: number;
}

/**
 * Compare assessment results across multiple cloud providers.
 */
export function compareCloudProviders(reports: CloudAssessmentReport[]): MultiCloudComparison {
  const providers = reports.map(r => ({
    provider: r.provider,
    riskScore: r.riskScore,
    grade: r.grade,
    totalChecks: r.summary.totalChecks,
    passed: r.summary.passed,
    failed: r.summary.failed,
    criticalFindings: r.results.filter(res => res.status === "fail" && res.severity === "critical").length,
    highFindings: r.results.filter(res => res.status === "fail" && res.severity === "high").length,
    complianceScore: r.summary.complianceScore,
  }));

  const sorted = [...providers].sort((a, b) => a.riskScore - b.riskScore);

  // Find common gaps (techniques that failed across multiple providers)
  const failedTechniquesByProvider = reports.map(r =>
    new Set(r.results.filter(res => res.status === "fail" && res.mitreTechnique).map(res => res.mitreTechnique!))
  );
  const commonGaps: string[] = [];
  if (failedTechniquesByProvider.length >= 2) {
    const first = failedTechniquesByProvider[0];
    for (const tech of first) {
      if (failedTechniquesByProvider.every(s => s.has(tech))) {
        commonGaps.push(tech);
      }
    }
  }

  return {
    providers,
    worstProvider: sorted[0]?.provider || "aws",
    bestProvider: sorted[sorted.length - 1]?.provider || "aws",
    commonGaps,
    generatedAt: Date.now(),
  };
}

/**
 * Get all available test categories for a provider.
 */
export function getAvailableCategories(provider: CloudProvider): Array<{ category: CloudTestCategory; checkCount: number; description: string }> {
  return [
    { category: "cis_benchmark", checkCount: getChecksByProvider(provider).length, description: "CIS Benchmark compliance checks" },
    { category: "iam_audit", checkCount: (IAM_CHECKS[provider] || []).length, description: "IAM and identity security audit" },
    { category: "storage_scan", checkCount: (STORAGE_CHECKS[provider] || []).length, description: "Storage and data security scanning" },
    { category: "attack_paths", checkCount: FULL_CLOUD_CATALOG.filter(p => p.provider === provider).length, description: "Known cloud attack path analysis" },
    { category: "container_k8s", checkCount: K8S_SECURITY_CHECKS.length, description: "Container and Kubernetes security" },
    { category: "serverless", checkCount: SERVERLESS_SECURITY_CHECKS.filter(c => c.provider === provider).length, description: "Serverless function security" },
    { category: "network", checkCount: (NETWORK_CHECKS[provider] || []).length, description: "Network security configuration" },
  ];
}
