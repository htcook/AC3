/**
 * Cloud-Native Attack Paths Engine
 * Analyzes AWS IAM, Azure Entra ID, and GCP IAM for privilege escalation,
 * role chaining, cross-account pivots, and misconfigurations.
 */

// ── AWS IAM Attack Catalog ──────────────────────────────────────────────
export const AWS_ATTACK_CATALOG = [
  {
    id: "aws-iam-privesc-01",
    name: "IAM Policy Wildcard Abuse",
    attackType: "privilege_escalation" as const,
    provider: "aws" as const,
    description: "Exploits overly permissive IAM policies with wildcard (*) actions to escalate privileges",
    mitreTechniques: ["T1078.004", "T1098"],
    severity: "critical" as const,
    prerequisites: ["IAM user/role with iam:* or iam:CreatePolicy permissions"],
    remediationSteps: ["Apply least-privilege IAM policies", "Remove wildcard actions", "Enable IAM Access Analyzer"],
  },
  {
    id: "aws-iam-privesc-02",
    name: "AssumeRole Chain Escalation",
    attackType: "role_chaining" as const,
    provider: "aws" as const,
    description: "Chains multiple AssumeRole calls to reach a high-privilege role not directly accessible",
    mitreTechniques: ["T1078.004", "T1550.001"],
    severity: "high" as const,
    prerequisites: ["sts:AssumeRole on at least one intermediate role"],
    remediationSteps: ["Limit trust policies", "Add condition keys (MFA, source IP)", "Monitor CloudTrail for role chaining"],
  },
  {
    id: "aws-iam-privesc-03",
    name: "Cross-Account Pivot via Confused Deputy",
    attackType: "cross_account" as const,
    provider: "aws" as const,
    description: "Exploits cross-account trust relationships lacking ExternalId condition to pivot into target account",
    mitreTechniques: ["T1199", "T1078.004"],
    severity: "critical" as const,
    prerequisites: ["Cross-account role trust without ExternalId"],
    remediationSteps: ["Add ExternalId condition to all cross-account trust policies", "Audit all cross-account roles"],
  },
  {
    id: "aws-s3-exposure-01",
    name: "S3 Bucket Public Access Exploitation",
    attackType: "s3_public_access" as const,
    provider: "aws" as const,
    description: "Identifies and exploits publicly accessible S3 buckets containing sensitive data",
    mitreTechniques: ["T1530", "T1537"],
    severity: "high" as const,
    prerequisites: ["S3 bucket with public ACL or bucket policy"],
    remediationSteps: ["Enable S3 Block Public Access", "Review bucket policies", "Enable S3 access logging"],
  },
  {
    id: "aws-iam-privesc-04",
    name: "Lambda Function Policy Injection",
    attackType: "privilege_escalation" as const,
    provider: "aws" as const,
    description: "Creates or modifies Lambda function to execute with a higher-privilege execution role",
    mitreTechniques: ["T1078.004", "T1059"],
    severity: "high" as const,
    prerequisites: ["lambda:CreateFunction or lambda:UpdateFunctionConfiguration with iam:PassRole"],
    remediationSteps: ["Restrict iam:PassRole to specific roles", "Monitor Lambda function changes"],
  },
];

// ── Azure Entra ID Attack Catalog ───────────────────────────────────────
export const AZURE_ATTACK_CATALOG = [
  {
    id: "azure-entraid-01",
    name: "Consent Grant Abuse (Illicit Consent Grant)",
    attackType: "consent_grant_abuse" as const,
    provider: "azure" as const,
    description: "Tricks a user into granting OAuth permissions to a malicious app registration, enabling data access",
    mitreTechniques: ["T1550.001", "T1098.003"],
    severity: "critical" as const,
    prerequisites: ["User consent settings allow user-level consent", "Phishing vector to target user"],
    remediationSteps: ["Restrict user consent to verified publishers", "Require admin consent for all apps", "Review existing app permissions"],
  },
  {
    id: "azure-entraid-02",
    name: "App Registration Secret/Certificate Abuse",
    attackType: "app_registration_abuse" as const,
    provider: "azure" as const,
    description: "Adds credentials to an existing app registration to impersonate the application's permissions",
    mitreTechniques: ["T1098.001", "T1550.001"],
    severity: "critical" as const,
    prerequisites: ["Application.ReadWrite.All or owner of app registration"],
    remediationSteps: ["Monitor app registration credential changes", "Limit Application.ReadWrite.All assignments", "Use managed identities"],
  },
  {
    id: "azure-entraid-03",
    name: "PIM Role Activation Abuse",
    attackType: "pim_escalation" as const,
    provider: "azure" as const,
    description: "Exploits Privileged Identity Management eligible role assignments to activate Global Admin without proper justification",
    mitreTechniques: ["T1078.004", "T1098"],
    severity: "high" as const,
    prerequisites: ["Eligible PIM role assignment", "Weak approval policies"],
    remediationSteps: ["Require MFA for PIM activation", "Require approval for critical roles", "Set maximum activation duration"],
  },
  {
    id: "azure-storage-01",
    name: "Storage Account Key Extraction",
    attackType: "storage_misconfiguration" as const,
    provider: "azure" as const,
    description: "Extracts storage account access keys to gain full access to blobs, tables, queues, and files",
    mitreTechniques: ["T1530", "T1552.001"],
    severity: "high" as const,
    prerequisites: ["Microsoft.Storage/storageAccounts/listKeys/action permission"],
    remediationSteps: ["Use Azure RBAC instead of shared keys", "Disable shared key access", "Rotate keys regularly"],
  },
];

// ── GCP IAM Attack Catalog ──────────────────────────────────────────────
export const GCP_ATTACK_CATALOG = [
  {
    id: "gcp-iam-01",
    name: "Service Account Impersonation",
    attackType: "service_account_impersonation" as const,
    provider: "gcp" as const,
    description: "Impersonates a high-privilege service account using iam.serviceAccounts.getAccessToken",
    mitreTechniques: ["T1078.004", "T1134.001"],
    severity: "critical" as const,
    prerequisites: ["iam.serviceAccounts.getAccessToken on target SA"],
    remediationSteps: ["Restrict SA impersonation permissions", "Use Workload Identity Federation", "Monitor SA token generation"],
  },
  {
    id: "gcp-iam-02",
    name: "Organization Policy Bypass",
    attackType: "org_policy_bypass" as const,
    provider: "gcp" as const,
    description: "Bypasses organization policy constraints through project-level overrides or API exploitation",
    mitreTechniques: ["T1562.001", "T1078.004"],
    severity: "high" as const,
    prerequisites: ["orgpolicy.policy.set at project level"],
    remediationSteps: ["Enforce org policies at folder/org level", "Restrict orgpolicy.policy.set", "Monitor org policy changes"],
  },
  {
    id: "gcp-iam-03",
    name: "Custom Role Privilege Escalation",
    attackType: "privilege_escalation" as const,
    provider: "gcp" as const,
    description: "Creates or updates a custom IAM role to include high-privilege permissions",
    mitreTechniques: ["T1098", "T1078.004"],
    severity: "high" as const,
    prerequisites: ["iam.roles.create or iam.roles.update"],
    remediationSteps: ["Restrict custom role creation", "Monitor role permission changes", "Use predefined roles where possible"],
  },
  {
    id: "gcp-storage-01",
    name: "GCS Bucket ACL Exploitation",
    attackType: "storage_misconfiguration" as const,
    provider: "gcp" as const,
    description: "Exploits overly permissive GCS bucket ACLs or IAM bindings to access sensitive objects",
    mitreTechniques: ["T1530"],
    severity: "high" as const,
    prerequisites: ["Public or allUsers/allAuthenticatedUsers ACL on bucket"],
    remediationSteps: ["Enable uniform bucket-level access", "Remove allUsers bindings", "Enable bucket logging"],
  },
];

export const FULL_CLOUD_CATALOG = [...AWS_ATTACK_CATALOG, ...AZURE_ATTACK_CATALOG, ...GCP_ATTACK_CATALOG];

// ── IAM Misconfiguration Checks ─────────────────────────────────────────
export const IAM_MISCONFIG_CHECKS = {
  aws: [
    { type: "root_account_mfa", resource: "Root Account", description: "Root account does not have MFA enabled", severity: "critical" as const },
    { type: "access_key_rotation", resource: "IAM Users", description: "Access keys not rotated in >90 days", severity: "high" as const },
    { type: "unused_iam_roles", resource: "IAM Roles", description: "IAM roles not used in >90 days", severity: "medium" as const },
    { type: "wildcard_policies", resource: "IAM Policies", description: "Policies with Action: * or Resource: *", severity: "critical" as const },
    { type: "cross_account_trust", resource: "IAM Roles", description: "Cross-account trust without ExternalId", severity: "high" as const },
    { type: "inline_policies", resource: "IAM Entities", description: "Inline policies instead of managed policies", severity: "low" as const },
    { type: "password_policy", resource: "Account", description: "Weak password policy configuration", severity: "medium" as const },
  ],
  azure: [
    { type: "legacy_auth_enabled", resource: "Entra ID", description: "Legacy authentication protocols enabled", severity: "critical" as const },
    { type: "mfa_not_enforced", resource: "Users", description: "MFA not enforced for all users", severity: "critical" as const },
    { type: "guest_access_unrestricted", resource: "Entra ID", description: "Guest users have unrestricted access", severity: "high" as const },
    { type: "app_consent_unrestricted", resource: "App Registrations", description: "Users can consent to apps without admin approval", severity: "high" as const },
    { type: "pim_not_configured", resource: "Privileged Roles", description: "PIM not configured for privileged roles", severity: "high" as const },
    { type: "conditional_access_gaps", resource: "Conditional Access", description: "Missing conditional access policies for critical scenarios", severity: "medium" as const },
  ],
  gcp: [
    { type: "default_sa_usage", resource: "Compute Engine", description: "Default service account used by compute instances", severity: "high" as const },
    { type: "sa_key_not_rotated", resource: "Service Accounts", description: "Service account keys not rotated in >90 days", severity: "high" as const },
    { type: "primitive_roles", resource: "IAM Bindings", description: "Primitive roles (Owner/Editor/Viewer) used instead of predefined", severity: "medium" as const },
    { type: "public_buckets", resource: "Cloud Storage", description: "Buckets accessible to allUsers or allAuthenticatedUsers", severity: "critical" as const },
    { type: "domain_wide_delegation", resource: "Service Accounts", description: "Service accounts with domain-wide delegation enabled", severity: "critical" as const },
  ],
};

/**
 * Analyze a cloud provider configuration and return discovered attack paths
 */
export function analyzeCloudProvider(provider: "aws" | "azure" | "gcp", config: any) {
  const catalog = provider === "aws" ? AWS_ATTACK_CATALOG : provider === "azure" ? AZURE_ATTACK_CATALOG : GCP_ATTACK_CATALOG;
  const checks = IAM_MISCONFIG_CHECKS[provider];

  return {
    attackPaths: catalog.map(attack => ({
      ...attack,
      status: "open" as const,
      riskScore: attack.severity === "critical" ? 9.5 : attack.severity === "high" ? 7.5 : 5.0,
    })),
    misconfigurations: checks.map(check => ({
      ...check,
      status: "open" as const,
      currentValue: "Not assessed",
      expectedValue: "Compliant",
    })),
  };
}

/**
 * Get MITRE ATT&CK Cloud matrix techniques
 */
export function getCloudMitreTechniques() {
  return {
    "T1078.004": { name: "Valid Accounts: Cloud Accounts", tactic: "Initial Access / Persistence" },
    "T1098": { name: "Account Manipulation", tactic: "Persistence" },
    "T1098.001": { name: "Account Manipulation: Additional Cloud Credentials", tactic: "Persistence" },
    "T1098.003": { name: "Account Manipulation: Additional Cloud Roles", tactic: "Persistence" },
    "T1134.001": { name: "Access Token Manipulation: Token Impersonation", tactic: "Privilege Escalation" },
    "T1199": { name: "Trusted Relationship", tactic: "Initial Access" },
    "T1530": { name: "Data from Cloud Storage", tactic: "Collection" },
    "T1537": { name: "Transfer Data to Cloud Account", tactic: "Exfiltration" },
    "T1550.001": { name: "Use Alternate Authentication Material: Application Access Token", tactic: "Lateral Movement" },
    "T1552.001": { name: "Unsecured Credentials: Credentials In Files", tactic: "Credential Access" },
    "T1059": { name: "Command and Scripting Interpreter", tactic: "Execution" },
    "T1562.001": { name: "Impair Defenses: Disable or Modify Tools", tactic: "Defense Evasion" },
  };
}
