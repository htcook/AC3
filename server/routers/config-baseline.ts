import * as db from "../db";
// @ts-nocheck
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
  // ── Azure CIS Benchmark v2.1 (Expanded) ──
  { ruleId: "CIS-AZ-1.1.1", benchmark: "CIS Azure v2.1", section: "1.1.1", title: "Ensure Security Defaults is enabled on Azure AD", description: "Security defaults in Azure AD provide secure default settings that manage security-related features", severity: "critical", platform: "azure", expectedValue: "Security Defaults enabled", remediationGuidance: "Enable Security Defaults in Azure AD > Properties > Manage Security Defaults", ksiIds: ["KSI-IAM-MFA", "KSI-IAM-AAM"], mitreIds: ["T1078", "T1110"] },
  { ruleId: "CIS-AZ-1.1.2", benchmark: "CIS Azure v2.1", section: "1.1.2", title: "Ensure MFA is enabled for all users in administrative roles", description: "MFA should be enabled for all users who are assigned administrative roles", severity: "critical", platform: "azure", expectedValue: "MFA enforced for all admin roles", remediationGuidance: "Configure Conditional Access policy requiring MFA for directory roles", ksiIds: ["KSI-IAM-MFA", "KSI-IAM-PRA"], mitreIds: ["T1078", "T1110", "T1621"] },
  { ruleId: "CIS-AZ-1.1.3", benchmark: "CIS Azure v2.1", section: "1.1.3", title: "Ensure MFA is enabled for all users", description: "All users should be required to use MFA for authentication", severity: "high", platform: "azure", expectedValue: "MFA enforced for all users", remediationGuidance: "Create Conditional Access policy requiring MFA for all users", ksiIds: ["KSI-IAM-MFA"], mitreIds: ["T1078", "T1110"] },
  { ruleId: "CIS-AZ-1.2.1", benchmark: "CIS Azure v2.1", section: "1.2.1", title: "Ensure Trusted Locations are defined", description: "Conditional Access policies can use Trusted Locations to define trusted network locations", severity: "medium", platform: "azure", expectedValue: "Trusted Locations configured", remediationGuidance: "Define named locations in Azure AD > Security > Conditional Access > Named locations", ksiIds: ["KSI-IAM-AAM", "KSI-CNA-NSD"], mitreIds: ["T1078"] },
  { ruleId: "CIS-AZ-1.3", benchmark: "CIS Azure v2.1", section: "1.3", title: "Ensure guest users are reviewed on a regular basis", description: "Guest users should be reviewed and removed when no longer needed", severity: "medium", platform: "azure", expectedValue: "Guest user access review configured", remediationGuidance: "Configure Access Reviews in Azure AD > Identity Governance > Access reviews", ksiIds: ["KSI-IAM-AAM", "KSI-IAM-PRA"], mitreIds: ["T1078", "T1136"] },
  { ruleId: "CIS-AZ-2.1.1", benchmark: "CIS Azure v2.1", section: "2.1.1", title: "Ensure Microsoft Defender for Servers is set to On", description: "Microsoft Defender for Servers provides threat detection for compute resources", severity: "high", platform: "azure", expectedValue: "Defender for Servers enabled", remediationGuidance: "Enable in Microsoft Defender for Cloud > Environment settings > Defender plans", ksiIds: ["KSI-SVC-VSR", "KSI-CNA-HCI"], mitreIds: ["T1190", "T1210"] },
  { ruleId: "CIS-AZ-2.1.2", benchmark: "CIS Azure v2.1", section: "2.1.2", title: "Ensure Microsoft Defender for App Service is set to On", description: "Defender for App Service detects attacks targeting applications running over App Service", severity: "high", platform: "azure", expectedValue: "Defender for App Service enabled", remediationGuidance: "Enable in Microsoft Defender for Cloud > Environment settings > Defender plans", ksiIds: ["KSI-SVC-VSR", "KSI-CNA-HCI"], mitreIds: ["T1190", "T1059"] },
  { ruleId: "CIS-AZ-2.1.3", benchmark: "CIS Azure v2.1", section: "2.1.3", title: "Ensure Microsoft Defender for Azure SQL Databases is set to On", description: "Defender for SQL provides advanced threat protection for Azure SQL", severity: "high", platform: "azure", expectedValue: "Defender for SQL enabled", remediationGuidance: "Enable in Microsoft Defender for Cloud > Environment settings > Defender plans", ksiIds: ["KSI-SVC-VSR", "KSI-MLA-ALE"], mitreIds: ["T1190", "T1505"] },
  { ruleId: "CIS-AZ-2.1.7", benchmark: "CIS Azure v2.1", section: "2.1.7", title: "Ensure Microsoft Defender for Storage is set to On", description: "Defender for Storage detects unusual and potentially harmful attempts to access storage accounts", severity: "high", platform: "azure", expectedValue: "Defender for Storage enabled", remediationGuidance: "Enable in Microsoft Defender for Cloud > Environment settings > Defender plans", ksiIds: ["KSI-SVC-VSR", "KSI-CNA-EDE"], mitreIds: ["T1530", "T1537"] },
  { ruleId: "CIS-AZ-2.1.8", benchmark: "CIS Azure v2.1", section: "2.1.8", title: "Ensure Microsoft Defender for Key Vault is set to On", description: "Defender for Key Vault detects unusual and potentially harmful attempts to access key vaults", severity: "high", platform: "azure", expectedValue: "Defender for Key Vault enabled", remediationGuidance: "Enable in Microsoft Defender for Cloud > Environment settings > Defender plans", ksiIds: ["KSI-CNA-EDE", "KSI-MLA-ALE"], mitreIds: ["T1552", "T1555"] },
  { ruleId: "CIS-AZ-3.1", benchmark: "CIS Azure v2.1", section: "3.1", title: "Ensure secure transfer required is set to Enabled", description: "Enforce HTTPS for storage account access to ensure data in transit is encrypted", severity: "high", platform: "azure", expectedValue: "Secure transfer required enabled", remediationGuidance: "Set 'Secure transfer required' to Enabled in Storage account > Configuration", ksiIds: ["KSI-CNA-EDE"], mitreIds: ["T1557", "T1040"] },
  { ruleId: "CIS-AZ-3.2", benchmark: "CIS Azure v2.1", section: "3.2", title: "Ensure private endpoints are used to access Storage Accounts", description: "Private endpoints restrict access to storage accounts through private network connections", severity: "high", platform: "azure", expectedValue: "Private endpoints configured", remediationGuidance: "Configure private endpoints in Storage account > Networking > Private endpoint connections", ksiIds: ["KSI-CNA-NSD", "KSI-CNA-EDE"], mitreIds: ["T1046", "T1557"] },
  { ruleId: "CIS-AZ-3.7", benchmark: "CIS Azure v2.1", section: "3.7", title: "Ensure soft delete is enabled for Azure Storage", description: "Soft delete enables recovery of deleted blobs and containers", severity: "medium", platform: "azure", expectedValue: "Soft delete enabled with 7+ day retention", remediationGuidance: "Enable soft delete in Storage account > Data protection with minimum 7-day retention", ksiIds: ["KSI-DRP-BKR"], mitreIds: ["T1485", "T1490"] },
  { ruleId: "CIS-AZ-3.10", benchmark: "CIS Azure v2.1", section: "3.10", title: "Ensure storage account access keys are periodically regenerated", description: "Access keys should be rotated regularly to reduce the risk of compromised keys", severity: "medium", platform: "azure", expectedValue: "Keys regenerated within 90 days", remediationGuidance: "Regenerate access keys in Storage account > Access keys and update applications", ksiIds: ["KSI-IAM-AAM", "KSI-CMT-CMG"], mitreIds: ["T1528", "T1552"] },
  { ruleId: "CIS-AZ-4.1.2", benchmark: "CIS Azure v2.1", section: "4.1.2", title: "Ensure SQL Database Transparent Data Encryption is enabled", description: "TDE encrypts SQL Database, backups, and transaction logs at rest", severity: "high", platform: "azure", expectedValue: "TDE enabled", remediationGuidance: "Enable TDE in SQL Database > Transparent data encryption settings", ksiIds: ["KSI-CNA-EDE"], mitreIds: ["T1552", "T1005"] },
  { ruleId: "CIS-AZ-4.2.1", benchmark: "CIS Azure v2.1", section: "4.2.1", title: "Ensure Azure Defender is set to On for SQL servers on machines", description: "Azure Defender for SQL provides vulnerability assessment and advanced threat protection", severity: "high", platform: "azure", expectedValue: "Azure Defender for SQL enabled", remediationGuidance: "Enable Azure Defender for SQL in Security Center > Pricing & settings", ksiIds: ["KSI-SVC-VSR", "KSI-MLA-ALE"], mitreIds: ["T1190", "T1505"] },
  { ruleId: "CIS-AZ-5.1.1", benchmark: "CIS Azure v2.1", section: "5.1.1", title: "Ensure Diagnostic Logs are enabled for all services", description: "Diagnostic logs provide insight into operations performed on resources", severity: "high", platform: "azure", expectedValue: "Diagnostic logs enabled for all services", remediationGuidance: "Enable diagnostic settings for each resource in Azure Monitor > Diagnostic settings", ksiIds: ["KSI-MLA-LET", "KSI-MLA-OSM"], mitreIds: ["T1070", "T1562"] },
  { ruleId: "CIS-AZ-5.1.4", benchmark: "CIS Azure v2.1", section: "5.1.4", title: "Ensure Activity Log Alert exists for Delete Security Solution", description: "Monitor for deletion of security solutions to detect potential security degradation", severity: "high", platform: "azure", expectedValue: "Activity log alert configured", remediationGuidance: "Create activity log alert in Azure Monitor > Alerts for Microsoft.Security/securitySolutions/delete", ksiIds: ["KSI-MLA-ALE", "KSI-MLA-OSM"], mitreIds: ["T1562", "T1070"] },
  { ruleId: "CIS-AZ-5.2.1", benchmark: "CIS Azure v2.1", section: "5.2.1", title: "Ensure Activity Log Alert exists for Create Policy Assignment", description: "Monitor policy assignment changes to detect unauthorized modifications", severity: "medium", platform: "azure", expectedValue: "Activity log alert configured", remediationGuidance: "Create activity log alert for Microsoft.Authorization/policyAssignments/write", ksiIds: ["KSI-CMT-CMG", "KSI-MLA-ALE"], mitreIds: ["T1562", "T1098"] },
  { ruleId: "CIS-AZ-6.1", benchmark: "CIS Azure v2.1", section: "6.1", title: "Ensure RDP access is restricted from the Internet", description: "Restrict RDP access to only known IP addresses to prevent brute force attacks", severity: "critical", platform: "azure", expectedValue: "No NSG rules allowing RDP from Internet", remediationGuidance: "Remove or restrict NSG rules allowing inbound RDP (port 3389) from 0.0.0.0/0", ksiIds: ["KSI-CNA-NSD"], mitreIds: ["T1021.001", "T1110"] },
  { ruleId: "CIS-AZ-6.2", benchmark: "CIS Azure v2.1", section: "6.2", title: "Ensure SSH access is restricted from the Internet", description: "Restrict SSH access to only known IP addresses", severity: "critical", platform: "azure", expectedValue: "No NSG rules allowing SSH from Internet", remediationGuidance: "Remove or restrict NSG rules allowing inbound SSH (port 22) from 0.0.0.0/0", ksiIds: ["KSI-CNA-NSD"], mitreIds: ["T1021.004", "T1110"] },
  { ruleId: "CIS-AZ-6.4", benchmark: "CIS Azure v2.1", section: "6.4", title: "Ensure Network Watcher is enabled", description: "Network Watcher provides monitoring, diagnostics, and analytics for Azure networks", severity: "medium", platform: "azure", expectedValue: "Network Watcher enabled in all regions", remediationGuidance: "Enable Network Watcher in each region via Network Watcher > Overview", ksiIds: ["KSI-CNA-NSD", "KSI-MLA-OSM"], mitreIds: ["T1046", "T1557"] },
  { ruleId: "CIS-AZ-7.1", benchmark: "CIS Azure v2.1", section: "7.1", title: "Ensure Virtual Machines utilize Managed Disks", description: "Managed Disks provide better reliability and security for VM storage", severity: "medium", platform: "azure", expectedValue: "All VMs using Managed Disks", remediationGuidance: "Migrate unmanaged disks to managed disks via VM > Disks > Migrate", ksiIds: ["KSI-CNA-HCI", "KSI-CNA-EDE"], mitreIds: ["T1485", "T1530"] },
  { ruleId: "CIS-AZ-7.4", benchmark: "CIS Azure v2.1", section: "7.4", title: "Ensure only approved extensions are installed on VMs", description: "Only install VM extensions that are approved and necessary", severity: "medium", platform: "azure", expectedValue: "Only approved extensions installed", remediationGuidance: "Review and remove unapproved extensions in VM > Extensions + applications", ksiIds: ["KSI-CNA-HCI", "KSI-CMT-CMG"], mitreIds: ["T1059", "T1525"] },
  { ruleId: "CIS-AZ-8.1", benchmark: "CIS Azure v2.1", section: "8.1", title: "Ensure expiration date is set on all keys", description: "Key Vault keys should have an expiration date to enforce key rotation", severity: "high", platform: "azure", expectedValue: "Expiration date set on all keys", remediationGuidance: "Set expiration dates on keys in Key Vault > Keys > Edit key", ksiIds: ["KSI-CNA-EDE", "KSI-CMT-CMG"], mitreIds: ["T1552", "T1555"] },
  { ruleId: "CIS-AZ-8.2", benchmark: "CIS Azure v2.1", section: "8.2", title: "Ensure expiration date is set on all secrets", description: "Key Vault secrets should have an expiration date to enforce rotation", severity: "high", platform: "azure", expectedValue: "Expiration date set on all secrets", remediationGuidance: "Set expiration dates on secrets in Key Vault > Secrets > Edit secret", ksiIds: ["KSI-CNA-EDE", "KSI-CMT-CMG"], mitreIds: ["T1552", "T1555"] },
  { ruleId: "CIS-AZ-9.1", benchmark: "CIS Azure v2.1", section: "9.1", title: "Ensure App Service authentication is set up", description: "App Service Authentication adds identity verification to web applications", severity: "high", platform: "azure", expectedValue: "Authentication enabled", remediationGuidance: "Enable Authentication in App Service > Authentication > Add identity provider", ksiIds: ["KSI-IAM-AAM", "KSI-CNA-HCI"], mitreIds: ["T1078", "T1190"] },
  { ruleId: "CIS-AZ-9.2", benchmark: "CIS Azure v2.1", section: "9.2", title: "Ensure web app redirects all HTTP traffic to HTTPS", description: "All HTTP traffic should be redirected to HTTPS for encrypted communications", severity: "high", platform: "azure", expectedValue: "HTTPS Only enabled", remediationGuidance: "Enable 'HTTPS Only' in App Service > TLS/SSL settings", ksiIds: ["KSI-CNA-EDE"], mitreIds: ["T1557", "T1040"] },
  { ruleId: "CIS-AZ-9.3", benchmark: "CIS Azure v2.1", section: "9.3", title: "Ensure web app is using the latest version of TLS encryption", description: "Use TLS 1.2 or higher to ensure strong encryption", severity: "high", platform: "azure", expectedValue: "Minimum TLS version 1.2", remediationGuidance: "Set minimum TLS version to 1.2 in App Service > TLS/SSL settings", ksiIds: ["KSI-CNA-EDE"], mitreIds: ["T1557", "T1040"] },
  // ── GCP CIS Benchmark v2.0 (Expanded) ──
  { ruleId: "CIS-GCP-1.4", benchmark: "CIS GCP v2.0", section: "1.4", title: "Ensure user-managed/external keys for service accounts are rotated within 90 days", description: "Service account keys should be rotated regularly to reduce compromise risk", severity: "high", platform: "gcp", expectedValue: "Keys rotated within 90 days", remediationGuidance: "Delete old keys and create new ones in IAM > Service accounts > Keys", ksiIds: ["KSI-IAM-AAM", "KSI-CMT-CMG"], mitreIds: ["T1528", "T1552"] },
  { ruleId: "CIS-GCP-1.5", benchmark: "CIS GCP v2.0", section: "1.5", title: "Ensure service account has no admin privileges", description: "Service accounts should not have admin or owner roles", severity: "critical", platform: "gcp", expectedValue: "No admin/owner roles on service accounts", remediationGuidance: "Remove Owner/Editor roles from service accounts in IAM & Admin > IAM", ksiIds: ["KSI-IAM-PRA", "KSI-IAM-AAM"], mitreIds: ["T1078", "T1548"] },
  { ruleId: "CIS-GCP-1.6", benchmark: "CIS GCP v2.0", section: "1.6", title: "Ensure IAM users are not assigned Service Account User or Token Creator roles at project level", description: "Granting these roles at project level gives broad access to all service accounts", severity: "high", platform: "gcp", expectedValue: "No project-level SA User/Token Creator bindings", remediationGuidance: "Remove project-level bindings and grant at service account level instead", ksiIds: ["KSI-IAM-PRA", "KSI-IAM-AAM"], mitreIds: ["T1078", "T1134"] },
  { ruleId: "CIS-GCP-1.7", benchmark: "CIS GCP v2.0", section: "1.7", title: "Ensure user-managed service accounts do not have admin privileges", description: "User-managed service accounts should follow least privilege principle", severity: "critical", platform: "gcp", expectedValue: "Least privilege roles only", remediationGuidance: "Audit and remove excessive permissions from service accounts", ksiIds: ["KSI-IAM-PRA"], mitreIds: ["T1078", "T1548"] },
  { ruleId: "CIS-GCP-2.2", benchmark: "CIS GCP v2.0", section: "2.2", title: "Ensure log metric filter and alerts exist for project ownership changes", description: "Monitor project ownership changes to detect unauthorized modifications", severity: "high", platform: "gcp", expectedValue: "Log metric filter and alert configured", remediationGuidance: "Create log metric filter for protoPayload.methodName=SetIamPolicy and configure alert", ksiIds: ["KSI-MLA-ALE", "KSI-MLA-OSM"], mitreIds: ["T1098", "T1562"] },
  { ruleId: "CIS-GCP-2.3", benchmark: "CIS GCP v2.0", section: "2.3", title: "Ensure log metric filter and alerts exist for audit configuration changes", description: "Monitor audit configuration changes to ensure logging integrity", severity: "high", platform: "gcp", expectedValue: "Log metric filter and alert configured", remediationGuidance: "Create log metric filter for protoPayload.methodName=UpdateSink and configure alert", ksiIds: ["KSI-MLA-LET", "KSI-MLA-ALE"], mitreIds: ["T1070", "T1562"] },
  { ruleId: "CIS-GCP-2.4", benchmark: "CIS GCP v2.0", section: "2.4", title: "Ensure log metric filter and alerts exist for custom role changes", description: "Monitor custom role modifications to detect privilege escalation attempts", severity: "medium", platform: "gcp", expectedValue: "Log metric filter and alert configured", remediationGuidance: "Create log metric filter for resource.type=iam_role AND protoPayload.methodName contains Role", ksiIds: ["KSI-MLA-ALE", "KSI-IAM-PRA"], mitreIds: ["T1098", "T1548"] },
  { ruleId: "CIS-GCP-2.5", benchmark: "CIS GCP v2.0", section: "2.5", title: "Ensure log metric filter and alerts exist for VPC network changes", description: "Monitor VPC network changes to detect unauthorized network modifications", severity: "high", platform: "gcp", expectedValue: "Log metric filter and alert configured", remediationGuidance: "Create log metric filter for resource.type=gce_network and configure alert", ksiIds: ["KSI-MLA-ALE", "KSI-CNA-NSD"], mitreIds: ["T1046", "T1562"] },
  { ruleId: "CIS-GCP-2.6", benchmark: "CIS GCP v2.0", section: "2.6", title: "Ensure log metric filter and alerts exist for VPC network firewall rule changes", description: "Monitor firewall rule changes to detect security policy modifications", severity: "high", platform: "gcp", expectedValue: "Log metric filter and alert configured", remediationGuidance: "Create log metric filter for resource.type=gce_firewall_rule and configure alert", ksiIds: ["KSI-MLA-ALE", "KSI-CNA-NSD"], mitreIds: ["T1046", "T1562"] },
  { ruleId: "CIS-GCP-2.9", benchmark: "CIS GCP v2.0", section: "2.9", title: "Ensure log metric filter and alerts exist for Cloud Storage IAM permission changes", description: "Monitor storage IAM changes to detect unauthorized access modifications", severity: "high", platform: "gcp", expectedValue: "Log metric filter and alert configured", remediationGuidance: "Create log metric filter for resource.type=gcs_bucket AND protoPayload.methodName=storage.setIamPermissions", ksiIds: ["KSI-MLA-ALE", "KSI-CNA-EDE"], mitreIds: ["T1530", "T1098"] },
  { ruleId: "CIS-GCP-2.12", benchmark: "CIS GCP v2.0", section: "2.12", title: "Ensure logging is enabled for Cloud DNS", description: "DNS query logging helps identify DNS-based attacks and data exfiltration", severity: "medium", platform: "gcp", expectedValue: "DNS logging enabled", remediationGuidance: "Enable DNS logging in Cloud DNS > DNS policies", ksiIds: ["KSI-MLA-LET", "KSI-CNA-NSD"], mitreIds: ["T1071", "T1568"] },
  { ruleId: "CIS-GCP-3.2", benchmark: "CIS GCP v2.0", section: "3.2", title: "Ensure legacy networks do not exist", description: "Legacy networks have a single network IPv4 range and are not recommended", severity: "high", platform: "gcp", expectedValue: "No legacy networks", remediationGuidance: "Migrate to VPC networks and delete legacy networks", ksiIds: ["KSI-CNA-NSD"], mitreIds: ["T1046", "T1021"] },
  { ruleId: "CIS-GCP-3.6", benchmark: "CIS GCP v2.0", section: "3.6", title: "Ensure SSH access is restricted from the Internet", description: "Firewall rules should not allow SSH access from 0.0.0.0/0", severity: "critical", platform: "gcp", expectedValue: "No firewall rules allowing SSH from 0.0.0.0/0", remediationGuidance: "Restrict SSH firewall rules to specific source IP ranges", ksiIds: ["KSI-CNA-NSD"], mitreIds: ["T1021.004", "T1110"] },
  { ruleId: "CIS-GCP-3.7", benchmark: "CIS GCP v2.0", section: "3.7", title: "Ensure RDP access is restricted from the Internet", description: "Firewall rules should not allow RDP access from 0.0.0.0/0", severity: "critical", platform: "gcp", expectedValue: "No firewall rules allowing RDP from 0.0.0.0/0", remediationGuidance: "Restrict RDP firewall rules to specific source IP ranges", ksiIds: ["KSI-CNA-NSD"], mitreIds: ["T1021.001", "T1110"] },
  { ruleId: "CIS-GCP-3.8", benchmark: "CIS GCP v2.0", section: "3.8", title: "Ensure VPC Flow Logs are enabled for every subnet", description: "VPC Flow Logs capture network flow information for monitoring and forensics", severity: "high", platform: "gcp", expectedValue: "Flow logs enabled on all subnets", remediationGuidance: "Enable flow logs in VPC Network > Subnets > Edit > Flow logs On", ksiIds: ["KSI-MLA-LET", "KSI-CNA-NSD"], mitreIds: ["T1046", "T1071"] },
  { ruleId: "CIS-GCP-3.9", benchmark: "CIS GCP v2.0", section: "3.9", title: "Ensure Private Google Access is enabled for all subnets", description: "Private Google Access allows VMs without external IPs to reach Google APIs", severity: "medium", platform: "gcp", expectedValue: "Private Google Access enabled", remediationGuidance: "Enable Private Google Access in VPC Network > Subnets > Edit", ksiIds: ["KSI-CNA-NSD", "KSI-CNA-EDE"], mitreIds: ["T1046", "T1557"] },
  { ruleId: "CIS-GCP-4.2", benchmark: "CIS GCP v2.0", section: "4.2", title: "Ensure Block Project-wide SSH keys is enabled for VM instances", description: "Block project-wide SSH keys to prevent lateral movement", severity: "medium", platform: "gcp", expectedValue: "Block project-wide SSH keys enabled", remediationGuidance: "Set metadata key 'block-project-ssh-keys' to TRUE on VM instances", ksiIds: ["KSI-IAM-AAM", "KSI-CNA-HCI"], mitreIds: ["T1021.004", "T1078"] },
  { ruleId: "CIS-GCP-4.3", benchmark: "CIS GCP v2.0", section: "4.3", title: "Ensure OS Login is enabled for VM instances", description: "OS Login ties SSH key management to IAM for centralized access control", severity: "medium", platform: "gcp", expectedValue: "OS Login enabled", remediationGuidance: "Set metadata key 'enable-oslogin' to TRUE at project or instance level", ksiIds: ["KSI-IAM-AAM", "KSI-IAM-MFA"], mitreIds: ["T1078", "T1021.004"] },
  { ruleId: "CIS-GCP-4.8", benchmark: "CIS GCP v2.0", section: "4.8", title: "Ensure Compute instances do not have public IP addresses", description: "VMs should not have external IPs unless absolutely necessary", severity: "high", platform: "gcp", expectedValue: "No public IPs on compute instances", remediationGuidance: "Remove external IPs and use Cloud NAT or IAP tunnels for access", ksiIds: ["KSI-CNA-NSD", "KSI-CNA-HCI"], mitreIds: ["T1046", "T1190"] },
  { ruleId: "CIS-GCP-4.9", benchmark: "CIS GCP v2.0", section: "4.9", title: "Ensure Shielded VM is enabled for compute instances", description: "Shielded VMs provide verifiable integrity of compute instances", severity: "medium", platform: "gcp", expectedValue: "Shielded VM enabled", remediationGuidance: "Enable Shielded VM features (Secure Boot, vTPM, Integrity Monitoring) on VM creation", ksiIds: ["KSI-CNA-HCI"], mitreIds: ["T1542", "T1601"] },
  { ruleId: "CIS-GCP-5.1", benchmark: "CIS GCP v2.0", section: "5.1", title: "Ensure Cloud Storage bucket is not anonymously or publicly accessible", description: "Storage buckets should not be publicly accessible to prevent data exposure", severity: "critical", platform: "gcp", expectedValue: "No public access on buckets", remediationGuidance: "Remove allUsers and allAuthenticatedUsers from bucket IAM bindings", ksiIds: ["KSI-CNA-EDE", "KSI-CNA-NSD"], mitreIds: ["T1530", "T1537"] },
  { ruleId: "CIS-GCP-5.2", benchmark: "CIS GCP v2.0", section: "5.2", title: "Ensure Cloud Storage buckets have uniform bucket-level access enabled", description: "Uniform bucket-level access simplifies permission management", severity: "medium", platform: "gcp", expectedValue: "Uniform bucket-level access enabled", remediationGuidance: "Enable uniform bucket-level access in Storage > Bucket > Permissions", ksiIds: ["KSI-IAM-AAM", "KSI-CNA-EDE"], mitreIds: ["T1530"] },
  { ruleId: "CIS-GCP-6.1.1", benchmark: "CIS GCP v2.0", section: "6.1.1", title: "Ensure Cloud SQL database instances require all incoming connections to use SSL", description: "Enforce SSL for all database connections to encrypt data in transit", severity: "high", platform: "gcp", expectedValue: "SSL required for all connections", remediationGuidance: "Set requireSsl to true in Cloud SQL instance > Connections > Security", ksiIds: ["KSI-CNA-EDE"], mitreIds: ["T1557", "T1040"] },
  { ruleId: "CIS-GCP-6.2.1", benchmark: "CIS GCP v2.0", section: "6.2.1", title: "Ensure Cloud SQL database instances do not have public IPs", description: "Cloud SQL instances should use private IPs to prevent internet exposure", severity: "high", platform: "gcp", expectedValue: "No public IPs on Cloud SQL", remediationGuidance: "Configure private IP in Cloud SQL instance > Connections and remove public IP", ksiIds: ["KSI-CNA-NSD", "KSI-CNA-EDE"], mitreIds: ["T1190", "T1046"] },
  { ruleId: "CIS-GCP-6.4", benchmark: "CIS GCP v2.0", section: "6.4", title: "Ensure Cloud SQL database instances are configured with automated backups", description: "Automated backups ensure data recovery capability", severity: "high", platform: "gcp", expectedValue: "Automated backups enabled", remediationGuidance: "Enable automated backups in Cloud SQL instance > Backups > Edit", ksiIds: ["KSI-DRP-BKR"], mitreIds: ["T1485", "T1490"] },
  { ruleId: "CIS-GCP-7.1", benchmark: "CIS GCP v2.0", section: "7.1", title: "Ensure BigQuery datasets are not anonymously or publicly accessible", description: "BigQuery datasets should not be publicly accessible", severity: "critical", platform: "gcp", expectedValue: "No public access on datasets", remediationGuidance: "Remove allUsers and allAuthenticatedUsers from dataset permissions", ksiIds: ["KSI-CNA-EDE", "KSI-IAM-AAM"], mitreIds: ["T1530", "T1213"] },
  // ── Additional Kubernetes CIS v1.8 ──
  { ruleId: "CIS-K8S-1.2.6", benchmark: "CIS K8s v1.8", section: "1.2.6", title: "Ensure RBAC authorization is enabled", description: "RBAC should be the primary authorization mode for the API server", severity: "critical", platform: "kubernetes", expectedValue: "--authorization-mode includes RBAC", remediationGuidance: "Set --authorization-mode=RBAC,Node in API server configuration", ksiIds: ["KSI-IAM-AAM", "KSI-IAM-PRA"], mitreIds: ["T1078", "T1548"] },
  { ruleId: "CIS-K8S-1.2.16", benchmark: "CIS K8s v1.8", section: "1.2.16", title: "Ensure audit logging is enabled", description: "Audit logging records all API server requests for security monitoring", severity: "critical", platform: "kubernetes", expectedValue: "Audit policy configured and audit log path set", remediationGuidance: "Set --audit-policy-file and --audit-log-path in API server configuration", ksiIds: ["KSI-MLA-LET", "KSI-MLA-ALE"], mitreIds: ["T1070", "T1562"] },
  { ruleId: "CIS-K8S-3.2.1", benchmark: "CIS K8s v1.8", section: "3.2.1", title: "Ensure a minimal audit policy is created", description: "Kubernetes audit policy defines what events are recorded", severity: "high", platform: "kubernetes", expectedValue: "Audit policy file exists with appropriate rules", remediationGuidance: "Create audit-policy.yaml with rules for sensitive resources and apply to API server", ksiIds: ["KSI-MLA-LET"], mitreIds: ["T1070", "T1562"] },
  { ruleId: "CIS-K8S-4.1.1", benchmark: "CIS K8s v1.8", section: "4.1.1", title: "Ensure kubelet authentication is not set to anonymous", description: "Kubelet should require authentication for all requests", severity: "critical", platform: "kubernetes", expectedValue: "anonymous auth disabled", remediationGuidance: "Set authentication.anonymous.enabled to false in kubelet config", ksiIds: ["KSI-IAM-AAM", "KSI-CNA-HCI"], mitreIds: ["T1078", "T1610"] },
  { ruleId: "CIS-K8S-5.1.3", benchmark: "CIS K8s v1.8", section: "5.1.3", title: "Minimize wildcard use in Roles and ClusterRoles", description: "Wildcard permissions grant excessive access and violate least privilege", severity: "high", platform: "kubernetes", expectedValue: "No wildcard (*) in role rules", remediationGuidance: "Replace wildcard permissions with specific resource and verb lists", ksiIds: ["KSI-IAM-PRA"], mitreIds: ["T1078", "T1548"] },
  { ruleId: "CIS-K8S-5.2.2", benchmark: "CIS K8s v1.8", section: "5.2.2", title: "Minimize admission of privileged containers", description: "Privileged containers have unrestricted host access and should be avoided", severity: "critical", platform: "kubernetes", expectedValue: "No privileged containers allowed", remediationGuidance: "Enforce restricted Pod Security Standard or use OPA/Kyverno to block privileged containers", ksiIds: ["KSI-CNA-HCI"], mitreIds: ["T1610", "T1611"] },
  { ruleId: "CIS-K8S-5.3.1", benchmark: "CIS K8s v1.8", section: "5.3.1", title: "Ensure Network Policies are defined for all namespaces", description: "Network Policies control pod-to-pod communication and enforce segmentation", severity: "high", platform: "kubernetes", expectedValue: "Network Policies defined in all namespaces", remediationGuidance: "Create default-deny NetworkPolicy in each namespace and add allow rules as needed", ksiIds: ["KSI-CNA-NSD"], mitreIds: ["T1046", "T1021"] },
  { ruleId: "CIS-K8S-5.4.1", benchmark: "CIS K8s v1.8", section: "5.4.1", title: "Prefer using Secrets as files over environment variables", description: "Secrets mounted as files are more secure than environment variables", severity: "medium", platform: "kubernetes", expectedValue: "Secrets mounted as volumes, not env vars", remediationGuidance: "Mount secrets as volumes instead of using envFrom or env.valueFrom.secretKeyRef", ksiIds: ["KSI-CNA-EDE", "KSI-IAM-AAM"], mitreIds: ["T1552", "T1078"] },
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
