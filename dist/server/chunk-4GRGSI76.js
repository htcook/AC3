// server/lib/cloud-security-validation.ts
var AWS_CIS_CHECKS = [
  // IAM Domain
  {
    id: "aws-cis-1.1",
    provider: "aws",
    domain: "iam",
    cisBenchmark: "CIS AWS 3.0 - 1.4",
    title: "Ensure no root account access key exists",
    description: "The root account has unrestricted access to all resources. Access keys for root should be removed to prevent programmatic access.",
    severity: "critical",
    mitreTechniques: ["T1078.004", "T1552.001"],
    remediationSteps: ["Delete root account access keys via IAM console", "Use IAM users with least-privilege policies", "Enable MFA on root account"],
    defaultResource: "Root Account",
    automatable: true
  },
  {
    id: "aws-cis-1.2",
    provider: "aws",
    domain: "iam",
    cisBenchmark: "CIS AWS 3.0 - 1.5",
    title: "Ensure MFA is enabled for the root account",
    description: "Hardware or virtual MFA should be enabled on the root account to add an additional layer of protection.",
    severity: "critical",
    mitreTechniques: ["T1078.004"],
    remediationSteps: ["Enable hardware MFA on root account", "Store MFA device in secure location", "Test MFA login flow"],
    defaultResource: "Root Account",
    automatable: true
  },
  {
    id: "aws-cis-1.3",
    provider: "aws",
    domain: "iam",
    cisBenchmark: "CIS AWS 3.0 - 1.8",
    title: "Ensure IAM password policy requires minimum length of 14",
    description: "A strong password policy enforces minimum length, complexity, and rotation requirements.",
    severity: "medium",
    mitreTechniques: ["T1110"],
    remediationSteps: ["Set minimum password length to 14", "Require uppercase, lowercase, numbers, and symbols", "Set password expiration to 90 days"],
    defaultResource: "Account Password Policy",
    automatable: true
  },
  {
    id: "aws-cis-1.4",
    provider: "aws",
    domain: "iam",
    cisBenchmark: "CIS AWS 3.0 - 1.12",
    title: "Ensure credentials unused for 45 days are disabled",
    description: "Unused credentials increase the attack surface. Disable or remove credentials not used within 45 days.",
    severity: "high",
    mitreTechniques: ["T1078.004", "T1552.001"],
    remediationSteps: ["Generate IAM credential report", "Identify unused credentials", "Disable or delete unused access keys and passwords"],
    defaultResource: "IAM Users",
    automatable: true
  },
  {
    id: "aws-cis-1.5",
    provider: "aws",
    domain: "iam",
    cisBenchmark: "CIS AWS 3.0 - 1.16",
    title: "Ensure IAM policies are attached only to groups or roles",
    description: "Attaching policies directly to users makes permission management difficult and error-prone.",
    severity: "medium",
    mitreTechniques: ["T1078.004"],
    remediationSteps: ["Create IAM groups for common permission sets", "Attach policies to groups, not users", "Add users to appropriate groups"],
    defaultResource: "IAM Policies",
    automatable: true
  },
  {
    id: "aws-cis-1.6",
    provider: "aws",
    domain: "iam",
    cisBenchmark: "CIS AWS 3.0 - 1.17",
    title: "Ensure a support role has been created for AWS Support access",
    description: "A dedicated support role ensures least-privilege access for managing support cases.",
    severity: "low",
    mitreTechniques: [],
    remediationSteps: ["Create IAM role with AWSSupportAccess policy", "Restrict role assumption to authorized users"],
    defaultResource: "IAM Roles",
    automatable: true
  },
  // Networking Domain
  {
    id: "aws-cis-2.1",
    provider: "aws",
    domain: "networking",
    cisBenchmark: "CIS AWS 3.0 - 5.1",
    title: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
    description: "Unrestricted SSH access exposes instances to brute-force attacks from the internet.",
    severity: "critical",
    mitreTechniques: ["T1190", "T1110"],
    remediationSteps: ["Restrict SSH access to known IP ranges", "Use AWS Systems Manager Session Manager instead", "Implement bastion host architecture"],
    defaultResource: "Security Groups",
    automatable: true
  },
  {
    id: "aws-cis-2.2",
    provider: "aws",
    domain: "networking",
    cisBenchmark: "CIS AWS 3.0 - 5.2",
    title: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
    description: "Unrestricted RDP access exposes Windows instances to brute-force and exploitation attacks.",
    severity: "critical",
    mitreTechniques: ["T1190", "T1110", "T1021.001"],
    remediationSteps: ["Restrict RDP to VPN or bastion hosts only", "Use AWS Systems Manager Fleet Manager", "Enable NLA on Windows instances"],
    defaultResource: "Security Groups",
    automatable: true
  },
  {
    id: "aws-cis-2.3",
    provider: "aws",
    domain: "networking",
    cisBenchmark: "CIS AWS 3.0 - 5.3",
    title: "Ensure the default security group restricts all traffic",
    description: "The default security group in every VPC should deny all inbound and outbound traffic.",
    severity: "high",
    mitreTechniques: ["T1190"],
    remediationSteps: ["Remove all inbound rules from default security group", "Remove all outbound rules from default security group", "Use custom security groups for resources"],
    defaultResource: "Default Security Group",
    automatable: true
  },
  {
    id: "aws-cis-2.4",
    provider: "aws",
    domain: "networking",
    cisBenchmark: "CIS AWS 3.0 - 5.4",
    title: "Ensure VPC flow logging is enabled in all VPCs",
    description: "VPC Flow Logs capture network traffic metadata for security analysis and incident response.",
    severity: "medium",
    mitreTechniques: ["T1562.008"],
    remediationSteps: ["Enable VPC Flow Logs for all VPCs", "Send logs to CloudWatch Logs or S3", "Set log retention policy"],
    defaultResource: "VPCs",
    automatable: true
  },
  // Storage Domain
  {
    id: "aws-cis-3.1",
    provider: "aws",
    domain: "storage",
    cisBenchmark: "CIS AWS 3.0 - 2.1.1",
    title: "Ensure S3 Block Public Access is enabled at account level",
    description: "Account-level S3 Block Public Access prevents any bucket from being made public accidentally.",
    severity: "critical",
    mitreTechniques: ["T1530"],
    remediationSteps: ["Enable S3 Block Public Access at account level", "Review existing bucket policies", "Enable S3 access logging"],
    defaultResource: "S3 Account Settings",
    automatable: true
  },
  {
    id: "aws-cis-3.2",
    provider: "aws",
    domain: "storage",
    cisBenchmark: "CIS AWS 3.0 - 2.1.2",
    title: "Ensure S3 buckets have server-side encryption enabled",
    description: "All S3 buckets should enforce server-side encryption (SSE-S3 or SSE-KMS) for data at rest.",
    severity: "high",
    mitreTechniques: ["T1530", "T1565"],
    remediationSteps: ["Enable default encryption on all buckets", "Use SSE-KMS for sensitive data", "Enable bucket versioning"],
    defaultResource: "S3 Buckets",
    automatable: true
  },
  {
    id: "aws-cis-3.3",
    provider: "aws",
    domain: "storage",
    cisBenchmark: "CIS AWS 3.0 - 2.2.1",
    title: "Ensure EBS volumes are encrypted",
    description: "EBS volume encryption protects data at rest and in transit between EC2 instances and EBS storage.",
    severity: "high",
    mitreTechniques: ["T1530"],
    remediationSteps: ["Enable default EBS encryption in each region", "Encrypt existing unencrypted volumes via snapshot copy", "Use customer-managed KMS keys"],
    defaultResource: "EBS Volumes",
    automatable: true
  },
  // Compute Domain
  {
    id: "aws-cis-4.1",
    provider: "aws",
    domain: "compute",
    cisBenchmark: "CIS AWS 3.0 - 2.3.1",
    title: "Ensure RDS instances are not publicly accessible",
    description: "RDS instances with public accessibility expose databases to internet-based attacks.",
    severity: "critical",
    mitreTechniques: ["T1190", "T1110"],
    remediationSteps: ["Disable public accessibility on RDS instances", "Use VPC security groups to restrict access", "Implement database proxy for application access"],
    defaultResource: "RDS Instances",
    automatable: true
  },
  {
    id: "aws-cis-4.2",
    provider: "aws",
    domain: "compute",
    cisBenchmark: "CIS AWS 3.0 - 5.6",
    title: "Ensure EC2 instances do not have public IP addresses",
    description: "EC2 instances with public IPs are directly reachable from the internet, increasing attack surface.",
    severity: "high",
    mitreTechniques: ["T1190", "T1595"],
    remediationSteps: ["Use NAT Gateway for outbound internet access", "Place instances in private subnets", "Use ALB/NLB for inbound traffic"],
    defaultResource: "EC2 Instances",
    automatable: true
  },
  {
    id: "aws-cis-4.3",
    provider: "aws",
    domain: "compute",
    cisBenchmark: "CIS AWS 3.0 - 2.3.2",
    title: "Ensure auto minor version upgrade is enabled for RDS",
    description: "Automatic minor version upgrades ensure RDS instances receive security patches promptly.",
    severity: "medium",
    mitreTechniques: ["T1190"],
    remediationSteps: ["Enable auto minor version upgrade on all RDS instances", "Schedule maintenance windows during low-traffic periods"],
    defaultResource: "RDS Instances",
    automatable: true
  },
  // Logging Domain
  {
    id: "aws-cis-5.1",
    provider: "aws",
    domain: "logging",
    cisBenchmark: "CIS AWS 3.0 - 3.1",
    title: "Ensure CloudTrail is enabled in all regions",
    description: "Multi-region CloudTrail ensures all API activity is captured regardless of which region it occurs in.",
    severity: "critical",
    mitreTechniques: ["T1562.008", "T1070"],
    remediationSteps: ["Create a multi-region trail", "Enable log file validation", "Send logs to centralized S3 bucket and CloudWatch"],
    defaultResource: "CloudTrail",
    automatable: true
  },
  {
    id: "aws-cis-5.2",
    provider: "aws",
    domain: "logging",
    cisBenchmark: "CIS AWS 3.0 - 3.2",
    title: "Ensure CloudTrail log file validation is enabled",
    description: "Log file validation ensures CloudTrail logs have not been tampered with after delivery.",
    severity: "high",
    mitreTechniques: ["T1070", "T1565"],
    remediationSteps: ["Enable log file validation on all trails", "Monitor for validation failures"],
    defaultResource: "CloudTrail",
    automatable: true
  },
  {
    id: "aws-cis-5.3",
    provider: "aws",
    domain: "logging",
    cisBenchmark: "CIS AWS 3.0 - 3.4",
    title: "Ensure CloudTrail trails are integrated with CloudWatch Logs",
    description: "CloudWatch integration enables real-time monitoring and alerting on API activity.",
    severity: "medium",
    mitreTechniques: ["T1562.008"],
    remediationSteps: ["Configure CloudTrail to send logs to CloudWatch Logs group", "Create metric filters for critical events", "Set up SNS notifications"],
    defaultResource: "CloudTrail",
    automatable: true
  },
  {
    id: "aws-cis-5.4",
    provider: "aws",
    domain: "logging",
    cisBenchmark: "CIS AWS 3.0 - 4.3",
    title: "Ensure GuardDuty is enabled",
    description: "Amazon GuardDuty provides intelligent threat detection for AWS accounts and workloads.",
    severity: "high",
    mitreTechniques: ["T1562.008"],
    remediationSteps: ["Enable GuardDuty in all regions", "Configure findings export to S3", "Integrate with Security Hub"],
    defaultResource: "GuardDuty",
    automatable: true
  }
];
var AZURE_CIS_CHECKS = [
  // IAM Domain
  {
    id: "azure-cis-1.1",
    provider: "azure",
    domain: "iam",
    cisBenchmark: "CIS Azure 3.0 - 1.1",
    title: "Ensure Security Defaults or Conditional Access is enabled",
    description: "Security Defaults enforce baseline security policies including MFA for all users.",
    severity: "critical",
    mitreTechniques: ["T1078.004", "T1110"],
    remediationSteps: ["Enable Security Defaults in Entra ID", "Or implement Conditional Access policies for equivalent coverage", "Require MFA for all users"],
    defaultResource: "Entra ID",
    automatable: true
  },
  {
    id: "azure-cis-1.2",
    provider: "azure",
    domain: "iam",
    cisBenchmark: "CIS Azure 3.0 - 1.2",
    title: "Ensure MFA is enabled for all users in administrative roles",
    description: "Administrative accounts are high-value targets and must require multi-factor authentication.",
    severity: "critical",
    mitreTechniques: ["T1078.004"],
    remediationSteps: ["Create Conditional Access policy requiring MFA for admin roles", "Include Global Admin, Security Admin, Exchange Admin at minimum", "Test with report-only mode first"],
    defaultResource: "Entra ID Admin Roles",
    automatable: true
  },
  {
    id: "azure-cis-1.3",
    provider: "azure",
    domain: "iam",
    cisBenchmark: "CIS Azure 3.0 - 1.5",
    title: "Ensure guest users are reviewed on a regular basis",
    description: "Guest users may retain access after their need has expired, creating unnecessary risk.",
    severity: "high",
    mitreTechniques: ["T1078.004", "T1199"],
    remediationSteps: ["Enable access reviews for guest users", "Set quarterly review cadence", "Auto-remove guests who fail review"],
    defaultResource: "Entra ID Guest Users",
    automatable: true
  },
  {
    id: "azure-cis-1.4",
    provider: "azure",
    domain: "iam",
    cisBenchmark: "CIS Azure 3.0 - 1.11",
    title: "Ensure user consent to applications is restricted",
    description: "Unrestricted user consent allows users to grant third-party apps access to organizational data.",
    severity: "high",
    mitreTechniques: ["T1550.001", "T1098.003"],
    remediationSteps: ["Set user consent to 'Do not allow user consent'", "Or restrict to verified publishers only", "Implement admin consent workflow"],
    defaultResource: "Entra ID App Consent",
    automatable: true
  },
  // Networking Domain
  {
    id: "azure-cis-2.1",
    provider: "azure",
    domain: "networking",
    cisBenchmark: "CIS Azure 3.0 - 6.1",
    title: "Ensure no NSG allows inbound from 0.0.0.0/0 to port 22",
    description: "Unrestricted SSH access from the internet exposes VMs to brute-force attacks.",
    severity: "critical",
    mitreTechniques: ["T1190", "T1110"],
    remediationSteps: ["Restrict SSH source to known IP ranges", "Use Azure Bastion for secure access", "Implement Just-In-Time VM access"],
    defaultResource: "Network Security Groups",
    automatable: true
  },
  {
    id: "azure-cis-2.2",
    provider: "azure",
    domain: "networking",
    cisBenchmark: "CIS Azure 3.0 - 6.2",
    title: "Ensure no NSG allows inbound from 0.0.0.0/0 to port 3389",
    description: "Unrestricted RDP access is one of the most common attack vectors for ransomware.",
    severity: "critical",
    mitreTechniques: ["T1190", "T1110", "T1021.001"],
    remediationSteps: ["Restrict RDP to VPN or Azure Bastion only", "Enable JIT VM access in Defender for Cloud", "Enable NLA on all Windows VMs"],
    defaultResource: "Network Security Groups",
    automatable: true
  },
  {
    id: "azure-cis-2.3",
    provider: "azure",
    domain: "networking",
    cisBenchmark: "CIS Azure 3.0 - 6.5",
    title: "Ensure Network Watcher is enabled for all regions",
    description: "Network Watcher provides network monitoring, diagnostics, and flow logging capabilities.",
    severity: "medium",
    mitreTechniques: ["T1562.008"],
    remediationSteps: ["Enable Network Watcher in all active regions", "Configure NSG flow logs", "Set up traffic analytics"],
    defaultResource: "Network Watcher",
    automatable: true
  },
  // Storage Domain
  {
    id: "azure-cis-3.1",
    provider: "azure",
    domain: "storage",
    cisBenchmark: "CIS Azure 3.0 - 3.1",
    title: "Ensure storage accounts require HTTPS-only traffic",
    description: "Enforcing HTTPS prevents data interception during transit to and from storage accounts.",
    severity: "high",
    mitreTechniques: ["T1557", "T1040"],
    remediationSteps: ["Enable 'Secure transfer required' on all storage accounts", "Update application connection strings to use HTTPS"],
    defaultResource: "Storage Accounts",
    automatable: true
  },
  {
    id: "azure-cis-3.2",
    provider: "azure",
    domain: "storage",
    cisBenchmark: "CIS Azure 3.0 - 3.2",
    title: "Ensure storage account access is restricted using network rules",
    description: "Storage accounts should deny access by default and allow only from specific networks.",
    severity: "high",
    mitreTechniques: ["T1530"],
    remediationSteps: ["Set default action to 'Deny' on storage firewall", "Add VNet rules for authorized networks", "Use private endpoints for sensitive data"],
    defaultResource: "Storage Accounts",
    automatable: true
  },
  {
    id: "azure-cis-3.3",
    provider: "azure",
    domain: "storage",
    cisBenchmark: "CIS Azure 3.0 - 3.9",
    title: "Ensure soft delete is enabled for Azure Storage blobs",
    description: "Soft delete enables recovery of deleted blobs, protecting against accidental or malicious deletion.",
    severity: "medium",
    mitreTechniques: ["T1485", "T1490"],
    remediationSteps: ["Enable soft delete for blobs with 30-day retention", "Enable container soft delete", "Enable versioning for critical data"],
    defaultResource: "Storage Accounts",
    automatable: true
  },
  // Compute Domain
  {
    id: "azure-cis-4.1",
    provider: "azure",
    domain: "compute",
    cisBenchmark: "CIS Azure 3.0 - 7.1",
    title: "Ensure Virtual Machines utilize Managed Disks",
    description: "Managed Disks provide better reliability, security, and simplified management over unmanaged disks.",
    severity: "medium",
    mitreTechniques: ["T1530"],
    remediationSteps: ["Migrate unmanaged disks to managed disks", "Use Azure Disk Encryption for sensitive workloads"],
    defaultResource: "Virtual Machines",
    automatable: true
  },
  {
    id: "azure-cis-4.2",
    provider: "azure",
    domain: "compute",
    cisBenchmark: "CIS Azure 3.0 - 7.4",
    title: "Ensure Defender for Cloud is set to On for Servers",
    description: "Microsoft Defender for Servers provides threat detection and vulnerability assessment for VMs.",
    severity: "high",
    mitreTechniques: ["T1562.001"],
    remediationSteps: ["Enable Defender for Servers Plan 2", "Deploy Log Analytics agent to all VMs", "Configure auto-provisioning"],
    defaultResource: "Defender for Cloud",
    automatable: true
  },
  {
    id: "azure-cis-4.3",
    provider: "azure",
    domain: "compute",
    cisBenchmark: "CIS Azure 3.0 - 7.6",
    title: "Ensure endpoint protection is installed on VMs",
    description: "All VMs should have endpoint protection (antimalware) installed and reporting healthy status.",
    severity: "high",
    mitreTechniques: ["T1562.001"],
    remediationSteps: ["Install Microsoft Antimalware extension on all VMs", "Verify protection status in Defender for Cloud", "Configure real-time protection"],
    defaultResource: "Virtual Machines",
    automatable: true
  },
  // Logging Domain
  {
    id: "azure-cis-5.1",
    provider: "azure",
    domain: "logging",
    cisBenchmark: "CIS Azure 3.0 - 5.1.1",
    title: "Ensure diagnostic settings capture Activity Log categories",
    description: "Activity Log diagnostic settings should capture Administrative, Security, Alert, and Policy categories.",
    severity: "high",
    mitreTechniques: ["T1562.008", "T1070"],
    remediationSteps: ["Create diagnostic setting for Activity Log", "Enable all log categories", "Send to Log Analytics workspace and Storage Account"],
    defaultResource: "Activity Log",
    automatable: true
  },
  {
    id: "azure-cis-5.2",
    provider: "azure",
    domain: "logging",
    cisBenchmark: "CIS Azure 3.0 - 5.1.4",
    title: "Ensure Activity Log retention is set to 365 days or more",
    description: "Adequate log retention ensures historical data is available for incident investigation.",
    severity: "medium",
    mitreTechniques: ["T1070"],
    remediationSteps: ["Set Activity Log retention to at least 365 days", "Archive to storage account for long-term retention"],
    defaultResource: "Activity Log",
    automatable: true
  },
  {
    id: "azure-cis-5.3",
    provider: "azure",
    domain: "logging",
    cisBenchmark: "CIS Azure 3.0 - 5.2.1",
    title: "Ensure Defender for Cloud alerts are configured",
    description: "Security contact and alert notifications ensure the security team is notified of threats.",
    severity: "high",
    mitreTechniques: ["T1562.008"],
    remediationSteps: ["Configure security contact email", "Enable email notifications for high-severity alerts", "Enable notifications to subscription owners"],
    defaultResource: "Defender for Cloud",
    automatable: true
  }
];
var GCP_CIS_CHECKS = [
  // IAM Domain
  {
    id: "gcp-cis-1.1",
    provider: "gcp",
    domain: "iam",
    cisBenchmark: "CIS GCP 3.0 - 1.1",
    title: "Ensure corporate login credentials are used instead of Gmail accounts",
    description: "Using corporate-managed identities ensures proper lifecycle management and MFA enforcement.",
    severity: "high",
    mitreTechniques: ["T1078.004"],
    remediationSteps: ["Restrict IAM bindings to corporate domain", "Remove Gmail-based IAM members", "Use Cloud Identity for identity management"],
    defaultResource: "IAM Bindings",
    automatable: true
  },
  {
    id: "gcp-cis-1.2",
    provider: "gcp",
    domain: "iam",
    cisBenchmark: "CIS GCP 3.0 - 1.4",
    title: "Ensure service account keys are rotated within 90 days",
    description: "Long-lived service account keys increase the window of opportunity for compromised credentials.",
    severity: "high",
    mitreTechniques: ["T1078.004", "T1552.001"],
    remediationSteps: ["Implement key rotation policy", "Use Workload Identity Federation instead of keys", "Delete unused service account keys"],
    defaultResource: "Service Account Keys",
    automatable: true
  },
  {
    id: "gcp-cis-1.3",
    provider: "gcp",
    domain: "iam",
    cisBenchmark: "CIS GCP 3.0 - 1.5",
    title: "Ensure service accounts do not have admin privileges",
    description: "Service accounts with admin roles can be exploited for privilege escalation.",
    severity: "critical",
    mitreTechniques: ["T1078.004", "T1098"],
    remediationSteps: ["Audit service account role bindings", "Replace primitive roles with predefined roles", "Use least-privilege custom roles"],
    defaultResource: "Service Accounts",
    automatable: true
  },
  {
    id: "gcp-cis-1.4",
    provider: "gcp",
    domain: "iam",
    cisBenchmark: "CIS GCP 3.0 - 1.7",
    title: "Ensure user-managed service account keys are not used for project access",
    description: "Workload Identity Federation and attached service accounts are more secure than user-managed keys.",
    severity: "medium",
    mitreTechniques: ["T1552.001"],
    remediationSteps: ["Migrate to Workload Identity Federation", "Use attached service accounts for GCE/GKE", "Delete user-managed keys after migration"],
    defaultResource: "Service Accounts",
    automatable: true
  },
  // Networking Domain
  {
    id: "gcp-cis-2.1",
    provider: "gcp",
    domain: "networking",
    cisBenchmark: "CIS GCP 3.0 - 3.6",
    title: "Ensure SSH access is restricted from the internet",
    description: "Firewall rules should not allow SSH (port 22) from 0.0.0.0/0.",
    severity: "critical",
    mitreTechniques: ["T1190", "T1110"],
    remediationSteps: ["Restrict SSH source ranges to known IPs", "Use Identity-Aware Proxy (IAP) for SSH access", "Remove 0.0.0.0/0 from SSH firewall rules"],
    defaultResource: "Firewall Rules",
    automatable: true
  },
  {
    id: "gcp-cis-2.2",
    provider: "gcp",
    domain: "networking",
    cisBenchmark: "CIS GCP 3.0 - 3.7",
    title: "Ensure RDP access is restricted from the internet",
    description: "Firewall rules should not allow RDP (port 3389) from 0.0.0.0/0.",
    severity: "critical",
    mitreTechniques: ["T1190", "T1110", "T1021.001"],
    remediationSteps: ["Restrict RDP source ranges", "Use IAP tunnel for RDP access", "Remove 0.0.0.0/0 from RDP firewall rules"],
    defaultResource: "Firewall Rules",
    automatable: true
  },
  {
    id: "gcp-cis-2.3",
    provider: "gcp",
    domain: "networking",
    cisBenchmark: "CIS GCP 3.0 - 3.8",
    title: "Ensure VPC Flow Logs are enabled for every subnet",
    description: "VPC Flow Logs capture network traffic metadata for security monitoring and forensics.",
    severity: "medium",
    mitreTechniques: ["T1562.008"],
    remediationSteps: ["Enable flow logs on all subnets", "Set aggregation interval to 5 seconds for security use", "Export to BigQuery for analysis"],
    defaultResource: "VPC Subnets",
    automatable: true
  },
  // Storage Domain
  {
    id: "gcp-cis-3.1",
    provider: "gcp",
    domain: "storage",
    cisBenchmark: "CIS GCP 3.0 - 5.1",
    title: "Ensure Cloud Storage buckets are not anonymously or publicly accessible",
    description: "Buckets with allUsers or allAuthenticatedUsers bindings expose data to the internet.",
    severity: "critical",
    mitreTechniques: ["T1530"],
    remediationSteps: ["Remove allUsers and allAuthenticatedUsers from bucket IAM", "Enable uniform bucket-level access", "Use VPC Service Controls for sensitive data"],
    defaultResource: "Cloud Storage Buckets",
    automatable: true
  },
  {
    id: "gcp-cis-3.2",
    provider: "gcp",
    domain: "storage",
    cisBenchmark: "CIS GCP 3.0 - 5.2",
    title: "Ensure Cloud Storage buckets have uniform bucket-level access enabled",
    description: "Uniform access simplifies permission management and prevents ACL-based misconfigurations.",
    severity: "medium",
    mitreTechniques: ["T1530"],
    remediationSteps: ["Enable uniform bucket-level access on all buckets", "Migrate ACL-based permissions to IAM policies"],
    defaultResource: "Cloud Storage Buckets",
    automatable: true
  },
  // Compute Domain
  {
    id: "gcp-cis-4.1",
    provider: "gcp",
    domain: "compute",
    cisBenchmark: "CIS GCP 3.0 - 4.1",
    title: "Ensure default service account is not used for project access",
    description: "The default Compute Engine service account has Editor role, which is overly permissive.",
    severity: "high",
    mitreTechniques: ["T1078.004"],
    remediationSteps: ["Create custom service accounts with minimal permissions", "Disable automatic role grants for default SA", "Migrate existing instances to custom SAs"],
    defaultResource: "Compute Engine",
    automatable: true
  },
  {
    id: "gcp-cis-4.2",
    provider: "gcp",
    domain: "compute",
    cisBenchmark: "CIS GCP 3.0 - 4.3",
    title: "Ensure Compute instances do not have public IP addresses",
    description: "Instances with public IPs are directly reachable from the internet.",
    severity: "high",
    mitreTechniques: ["T1190", "T1595"],
    remediationSteps: ["Use Cloud NAT for outbound internet access", "Use IAP for inbound access", "Place instances in private subnets"],
    defaultResource: "Compute Instances",
    automatable: true
  },
  {
    id: "gcp-cis-4.3",
    provider: "gcp",
    domain: "compute",
    cisBenchmark: "CIS GCP 3.0 - 4.5",
    title: "Ensure Shielded VM is enabled for compute instances",
    description: "Shielded VMs provide verifiable integrity of instances through Secure Boot and vTPM.",
    severity: "medium",
    mitreTechniques: ["T1542"],
    remediationSteps: ["Enable Shielded VM features on all instances", "Enable Secure Boot, vTPM, and integrity monitoring"],
    defaultResource: "Compute Instances",
    automatable: true
  },
  // Logging Domain
  {
    id: "gcp-cis-5.1",
    provider: "gcp",
    domain: "logging",
    cisBenchmark: "CIS GCP 3.0 - 2.1",
    title: "Ensure Cloud Audit Logging is configured for all services",
    description: "Audit logs should capture Admin Activity, Data Access, and System Event logs for all services.",
    severity: "critical",
    mitreTechniques: ["T1562.008", "T1070"],
    remediationSteps: ["Enable Data Access audit logs for all services", "Configure log sinks to centralized destination", "Set appropriate retention periods"],
    defaultResource: "Cloud Audit Logs",
    automatable: true
  },
  {
    id: "gcp-cis-5.2",
    provider: "gcp",
    domain: "logging",
    cisBenchmark: "CIS GCP 3.0 - 2.2",
    title: "Ensure log metric filters and alerts exist for project ownership changes",
    description: "Monitoring project ownership changes detects unauthorized privilege escalation.",
    severity: "high",
    mitreTechniques: ["T1098", "T1078.004"],
    remediationSteps: ["Create log metric filter for project ownership changes", "Create alerting policy on the metric", "Route alerts to security team"],
    defaultResource: "Cloud Monitoring",
    automatable: true
  },
  {
    id: "gcp-cis-5.3",
    provider: "gcp",
    domain: "logging",
    cisBenchmark: "CIS GCP 3.0 - 2.4",
    title: "Ensure log metric filters and alerts exist for IAM policy changes",
    description: "Monitoring IAM policy changes detects unauthorized permission modifications.",
    severity: "high",
    mitreTechniques: ["T1098", "T1078.004"],
    remediationSteps: ["Create log metric filter for IAM policy changes", "Create alerting policy", "Include SetIamPolicy and related methods"],
    defaultResource: "Cloud Monitoring",
    automatable: true
  }
];
var ALL_CIS_CHECKS = [
  ...AWS_CIS_CHECKS,
  ...AZURE_CIS_CHECKS,
  ...GCP_CIS_CHECKS
];
function getChecksByProvider(provider) {
  return ALL_CIS_CHECKS.filter((c) => c.provider === provider);
}
function getChecksByDomain(provider, domain) {
  return ALL_CIS_CHECKS.filter((c) => c.provider === provider && c.domain === domain);
}
function getCheckById(id) {
  return ALL_CIS_CHECKS.find((c) => c.id === id);
}
function generateAssessmentId() {
  const hex = () => Math.random().toString(16).substring(2, 6);
  return `csva-${hex()}${hex()}`;
}
function runAssessment(provider, accountId, accountAlias, config, selectedDomains) {
  const checks = selectedDomains ? ALL_CIS_CHECKS.filter((c) => c.provider === provider && selectedDomains.includes(c.domain)) : getChecksByProvider(provider);
  const now = Date.now();
  const results = checks.map((check) => {
    const result = evaluateCheck(check, config);
    return {
      checkId: check.id,
      status: result.status,
      resourceId: result.resourceId,
      resourceName: check.defaultResource,
      currentValue: result.currentValue,
      expectedValue: result.expectedValue,
      evidence: result.evidence,
      timestamp: now
    };
  });
  const passed = results.filter((r) => r.status === "pass").length;
  const failed = results.filter((r) => r.status === "fail").length;
  const warnings = results.filter((r) => r.status === "warning").length;
  const errors = results.filter((r) => r.status === "error").length;
  const notAssessed = results.filter((r) => r.status === "not_assessed").length;
  const domains = ["iam", "networking", "storage", "compute", "logging"];
  const domainScores = {};
  for (const domain of domains) {
    const domainResults = results.filter((r) => {
      const check = getCheckById(r.checkId);
      return check?.domain === domain;
    });
    const dp = domainResults.filter((r) => r.status === "pass").length;
    const df = domainResults.filter((r) => r.status === "fail").length;
    const dt = domainResults.length;
    domainScores[domain] = {
      passed: dp,
      failed: df,
      total: dt,
      score: dt > 0 ? Math.round(dp / dt * 100) : 0
    };
  }
  const overallScore = results.length > 0 ? Math.round(passed / results.length * 100) : 0;
  return {
    id: generateAssessmentId(),
    provider,
    accountId,
    accountAlias,
    startedAt: now,
    completedAt: Date.now(),
    status: "completed",
    totalChecks: checks.length,
    passed,
    failed,
    warnings,
    errors,
    notAssessed,
    overallScore,
    domainScores,
    results
  };
}
function evaluateCheck(check, config) {
  const configKey = check.id.replace(/-/g, "_");
  const configValue = config[configKey] ?? config[check.id];
  if (configValue !== void 0) {
    if (configValue === true || configValue === "compliant" || configValue === "pass") {
      return {
        status: "pass",
        resourceId: check.defaultResource,
        currentValue: "Compliant",
        expectedValue: "Compliant",
        evidence: `Configuration check ${check.id} passed \u2014 resource meets CIS benchmark ${check.cisBenchmark}.`
      };
    }
    if (configValue === false || configValue === "non_compliant" || configValue === "fail") {
      return {
        status: "fail",
        resourceId: check.defaultResource,
        currentValue: typeof configValue === "string" ? configValue : "Non-compliant",
        expectedValue: "Compliant",
        evidence: `Configuration check ${check.id} FAILED \u2014 ${check.description}`
      };
    }
    if (typeof configValue === "string") {
      return {
        status: "warning",
        resourceId: check.defaultResource,
        currentValue: configValue,
        expectedValue: "Compliant",
        evidence: `Configuration check ${check.id} returned non-standard value: ${configValue}`
      };
    }
  }
  return {
    status: "not_assessed",
    resourceId: check.defaultResource,
    currentValue: "Not assessed",
    expectedValue: "Compliant",
    evidence: `No configuration data provided for ${check.id}. Connect cloud provider credentials to run live assessment.`
  };
}
function generateComplianceSummary(assessment) {
  const checks = getChecksByProvider(assessment.provider);
  const resultMap = new Map(assessment.results.map((r) => [r.checkId, r]));
  const frameworkMappings = {
    "SOC 2 Type II": checks.filter((c) => ["iam", "logging", "networking"].includes(c.domain)).map((c) => c.id),
    "ISO 27001": checks.map((c) => c.id),
    "NIST 800-53": checks.map((c) => c.id),
    "PCI DSS 4.0": checks.filter((c) => ["iam", "networking", "storage", "logging"].includes(c.domain)).map((c) => c.id),
    "HIPAA": checks.filter((c) => ["iam", "storage", "logging"].includes(c.domain)).map((c) => c.id)
  };
  const frameworks = Object.entries(frameworkMappings).map(([name, checkIds]) => {
    const covered = checkIds.length;
    const passing = checkIds.filter((id) => resultMap.get(id)?.status === "pass").length;
    return {
      name,
      controlsCovered: covered,
      controlsPassing: passing,
      score: covered > 0 ? Math.round(passing / covered * 100) : 0
    };
  });
  return { frameworks };
}
function getProviderStats() {
  return {
    providers: [
      { provider: "aws", totalChecks: AWS_CIS_CHECKS.length, domains: ["iam", "networking", "storage", "compute", "logging"], cisBenchmarkVersion: "CIS AWS Foundations 3.0" },
      { provider: "azure", totalChecks: AZURE_CIS_CHECKS.length, domains: ["iam", "networking", "storage", "compute", "logging"], cisBenchmarkVersion: "CIS Azure Foundations 3.0" },
      { provider: "gcp", totalChecks: GCP_CIS_CHECKS.length, domains: ["iam", "networking", "storage", "compute", "logging"], cisBenchmarkVersion: "CIS GCP Foundations 3.0" }
    ]
  };
}

export {
  AWS_CIS_CHECKS,
  AZURE_CIS_CHECKS,
  GCP_CIS_CHECKS,
  ALL_CIS_CHECKS,
  getChecksByProvider,
  getChecksByDomain,
  getCheckById,
  runAssessment,
  generateComplianceSummary,
  getProviderStats
};
