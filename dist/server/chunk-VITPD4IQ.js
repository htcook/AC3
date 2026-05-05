import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/cloud-attack-paths.ts
function analyzeCloudProvider(provider, config) {
  const catalog = provider === "aws" ? AWS_ATTACK_CATALOG : provider === "azure" ? AZURE_ATTACK_CATALOG : GCP_ATTACK_CATALOG;
  const checks = IAM_MISCONFIG_CHECKS[provider];
  return {
    attackPaths: catalog.map((attack) => ({
      ...attack,
      status: "open",
      riskScore: attack.severity === "critical" ? 9.5 : attack.severity === "high" ? 7.5 : 5
    })),
    misconfigurations: checks.map((check) => ({
      ...check,
      status: "open",
      currentValue: "Not assessed",
      expectedValue: "Compliant"
    }))
  };
}
function getCloudMitreTechniques() {
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
    "T1562.001": { name: "Impair Defenses: Disable or Modify Tools", tactic: "Defense Evasion" }
  };
}
var AWS_ATTACK_CATALOG, AZURE_ATTACK_CATALOG, GCP_ATTACK_CATALOG, FULL_CLOUD_CATALOG, IAM_MISCONFIG_CHECKS;
var init_cloud_attack_paths = __esm({
  "server/lib/cloud-attack-paths.ts"() {
    AWS_ATTACK_CATALOG = [
      {
        id: "aws-iam-privesc-01",
        name: "IAM Policy Wildcard Abuse",
        attackType: "privilege_escalation",
        provider: "aws",
        description: "Exploits overly permissive IAM policies with wildcard (*) actions to escalate privileges",
        mitreTechniques: ["T1078.004", "T1098"],
        severity: "critical",
        prerequisites: ["IAM user/role with iam:* or iam:CreatePolicy permissions"],
        remediationSteps: ["Apply least-privilege IAM policies", "Remove wildcard actions", "Enable IAM Access Analyzer"]
      },
      {
        id: "aws-iam-privesc-02",
        name: "AssumeRole Chain Escalation",
        attackType: "role_chaining",
        provider: "aws",
        description: "Chains multiple AssumeRole calls to reach a high-privilege role not directly accessible",
        mitreTechniques: ["T1078.004", "T1550.001"],
        severity: "high",
        prerequisites: ["sts:AssumeRole on at least one intermediate role"],
        remediationSteps: ["Limit trust policies", "Add condition keys (MFA, source IP)", "Monitor CloudTrail for role chaining"]
      },
      {
        id: "aws-iam-privesc-03",
        name: "Cross-Account Pivot via Confused Deputy",
        attackType: "cross_account",
        provider: "aws",
        description: "Exploits cross-account trust relationships lacking ExternalId condition to pivot into target account",
        mitreTechniques: ["T1199", "T1078.004"],
        severity: "critical",
        prerequisites: ["Cross-account role trust without ExternalId"],
        remediationSteps: ["Add ExternalId condition to all cross-account trust policies", "Audit all cross-account roles"]
      },
      {
        id: "aws-s3-exposure-01",
        name: "S3 Bucket Public Access Exploitation",
        attackType: "s3_public_access",
        provider: "aws",
        description: "Identifies and exploits publicly accessible S3 buckets containing sensitive data",
        mitreTechniques: ["T1530", "T1537"],
        severity: "high",
        prerequisites: ["S3 bucket with public ACL or bucket policy"],
        remediationSteps: ["Enable S3 Block Public Access", "Review bucket policies", "Enable S3 access logging"]
      },
      {
        id: "aws-iam-privesc-04",
        name: "Lambda Function Policy Injection",
        attackType: "privilege_escalation",
        provider: "aws",
        description: "Creates or modifies Lambda function to execute with a higher-privilege execution role",
        mitreTechniques: ["T1078.004", "T1059"],
        severity: "high",
        prerequisites: ["lambda:CreateFunction or lambda:UpdateFunctionConfiguration with iam:PassRole"],
        remediationSteps: ["Restrict iam:PassRole to specific roles", "Monitor Lambda function changes"]
      }
    ];
    AZURE_ATTACK_CATALOG = [
      {
        id: "azure-entraid-01",
        name: "Consent Grant Abuse (Illicit Consent Grant)",
        attackType: "consent_grant_abuse",
        provider: "azure",
        description: "Tricks a user into granting OAuth permissions to a malicious app registration, enabling data access",
        mitreTechniques: ["T1550.001", "T1098.003"],
        severity: "critical",
        prerequisites: ["User consent settings allow user-level consent", "Phishing vector to target user"],
        remediationSteps: ["Restrict user consent to verified publishers", "Require admin consent for all apps", "Review existing app permissions"]
      },
      {
        id: "azure-entraid-02",
        name: "App Registration Secret/Certificate Abuse",
        attackType: "app_registration_abuse",
        provider: "azure",
        description: "Adds credentials to an existing app registration to impersonate the application's permissions",
        mitreTechniques: ["T1098.001", "T1550.001"],
        severity: "critical",
        prerequisites: ["Application.ReadWrite.All or owner of app registration"],
        remediationSteps: ["Monitor app registration credential changes", "Limit Application.ReadWrite.All assignments", "Use managed identities"]
      },
      {
        id: "azure-entraid-03",
        name: "PIM Role Activation Abuse",
        attackType: "pim_escalation",
        provider: "azure",
        description: "Exploits Privileged Identity Management eligible role assignments to activate Global Admin without proper justification",
        mitreTechniques: ["T1078.004", "T1098"],
        severity: "high",
        prerequisites: ["Eligible PIM role assignment", "Weak approval policies"],
        remediationSteps: ["Require MFA for PIM activation", "Require approval for critical roles", "Set maximum activation duration"]
      },
      {
        id: "azure-storage-01",
        name: "Storage Account Key Extraction",
        attackType: "storage_misconfiguration",
        provider: "azure",
        description: "Extracts storage account access keys to gain full access to blobs, tables, queues, and files",
        mitreTechniques: ["T1530", "T1552.001"],
        severity: "high",
        prerequisites: ["Microsoft.Storage/storageAccounts/listKeys/action permission"],
        remediationSteps: ["Use Azure RBAC instead of shared keys", "Disable shared key access", "Rotate keys regularly"]
      }
    ];
    GCP_ATTACK_CATALOG = [
      {
        id: "gcp-iam-01",
        name: "Service Account Impersonation",
        attackType: "service_account_impersonation",
        provider: "gcp",
        description: "Impersonates a high-privilege service account using iam.serviceAccounts.getAccessToken",
        mitreTechniques: ["T1078.004", "T1134.001"],
        severity: "critical",
        prerequisites: ["iam.serviceAccounts.getAccessToken on target SA"],
        remediationSteps: ["Restrict SA impersonation permissions", "Use Workload Identity Federation", "Monitor SA token generation"]
      },
      {
        id: "gcp-iam-02",
        name: "Organization Policy Bypass",
        attackType: "org_policy_bypass",
        provider: "gcp",
        description: "Bypasses organization policy constraints through project-level overrides or API exploitation",
        mitreTechniques: ["T1562.001", "T1078.004"],
        severity: "high",
        prerequisites: ["orgpolicy.policy.set at project level"],
        remediationSteps: ["Enforce org policies at folder/org level", "Restrict orgpolicy.policy.set", "Monitor org policy changes"]
      },
      {
        id: "gcp-iam-03",
        name: "Custom Role Privilege Escalation",
        attackType: "privilege_escalation",
        provider: "gcp",
        description: "Creates or updates a custom IAM role to include high-privilege permissions",
        mitreTechniques: ["T1098", "T1078.004"],
        severity: "high",
        prerequisites: ["iam.roles.create or iam.roles.update"],
        remediationSteps: ["Restrict custom role creation", "Monitor role permission changes", "Use predefined roles where possible"]
      },
      {
        id: "gcp-storage-01",
        name: "GCS Bucket ACL Exploitation",
        attackType: "storage_misconfiguration",
        provider: "gcp",
        description: "Exploits overly permissive GCS bucket ACLs or IAM bindings to access sensitive objects",
        mitreTechniques: ["T1530"],
        severity: "high",
        prerequisites: ["Public or allUsers/allAuthenticatedUsers ACL on bucket"],
        remediationSteps: ["Enable uniform bucket-level access", "Remove allUsers bindings", "Enable bucket logging"]
      }
    ];
    FULL_CLOUD_CATALOG = [...AWS_ATTACK_CATALOG, ...AZURE_ATTACK_CATALOG, ...GCP_ATTACK_CATALOG];
    IAM_MISCONFIG_CHECKS = {
      aws: [
        { type: "root_account_mfa", resource: "Root Account", description: "Root account does not have MFA enabled", severity: "critical" },
        { type: "access_key_rotation", resource: "IAM Users", description: "Access keys not rotated in >90 days", severity: "high" },
        { type: "unused_iam_roles", resource: "IAM Roles", description: "IAM roles not used in >90 days", severity: "medium" },
        { type: "wildcard_policies", resource: "IAM Policies", description: "Policies with Action: * or Resource: *", severity: "critical" },
        { type: "cross_account_trust", resource: "IAM Roles", description: "Cross-account trust without ExternalId", severity: "high" },
        { type: "inline_policies", resource: "IAM Entities", description: "Inline policies instead of managed policies", severity: "low" },
        { type: "password_policy", resource: "Account", description: "Weak password policy configuration", severity: "medium" }
      ],
      azure: [
        { type: "legacy_auth_enabled", resource: "Entra ID", description: "Legacy authentication protocols enabled", severity: "critical" },
        { type: "mfa_not_enforced", resource: "Users", description: "MFA not enforced for all users", severity: "critical" },
        { type: "guest_access_unrestricted", resource: "Entra ID", description: "Guest users have unrestricted access", severity: "high" },
        { type: "app_consent_unrestricted", resource: "App Registrations", description: "Users can consent to apps without admin approval", severity: "high" },
        { type: "pim_not_configured", resource: "Privileged Roles", description: "PIM not configured for privileged roles", severity: "high" },
        { type: "conditional_access_gaps", resource: "Conditional Access", description: "Missing conditional access policies for critical scenarios", severity: "medium" }
      ],
      gcp: [
        { type: "default_sa_usage", resource: "Compute Engine", description: "Default service account used by compute instances", severity: "high" },
        { type: "sa_key_not_rotated", resource: "Service Accounts", description: "Service account keys not rotated in >90 days", severity: "high" },
        { type: "primitive_roles", resource: "IAM Bindings", description: "Primitive roles (Owner/Editor/Viewer) used instead of predefined", severity: "medium" },
        { type: "public_buckets", resource: "Cloud Storage", description: "Buckets accessible to allUsers or allAuthenticatedUsers", severity: "critical" },
        { type: "domain_wide_delegation", resource: "Service Accounts", description: "Service accounts with domain-wide delegation enabled", severity: "critical" }
      ]
    };
  }
});

export {
  AWS_ATTACK_CATALOG,
  AZURE_ATTACK_CATALOG,
  GCP_ATTACK_CATALOG,
  FULL_CLOUD_CATALOG,
  IAM_MISCONFIG_CHECKS,
  analyzeCloudProvider,
  getCloudMitreTechniques,
  init_cloud_attack_paths
};
