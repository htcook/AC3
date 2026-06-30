/**
 * Campaign Archetype Templates — built-in attack patterns
 * that auto-populate with actor-specific MITRE techniques.
 */

export interface ArchetypeTemplate {
  slug: string;
  name: string;
  category: string;
  description: string;
  killChainPhases: string[];
  defaultTechniques: { id: string; name: string; tactic: string }[];
  defaultAbilities: { abilityId: string; name: string; step: number; description: string }[];
  targetPlatforms: string[];
  targetServices: string[];
  prerequisites: string[];
  detectionGuidance: string;
  complexity: "low" | "medium" | "high" | "expert";
}

export const BUILT_IN_ARCHETYPES: ArchetypeTemplate[] = [
  // ─── SaaS OAuth Compromise ─────────────────────────────────────────
  {
    slug: "saas-oauth-compromise",
    name: "SaaS OAuth Compromise",
    category: "saas_oauth_compromise",
    description:
      "Simulates an attacker who has obtained a valid OAuth token (via phishing, consent grant abuse, or token theft) and uses it to access SaaS resources, exfiltrate data, and establish persistence through OAuth app registrations.",
    killChainPhases: [
      "initial-access",
      "persistence",
      "collection",
      "exfiltration",
    ],
    defaultTechniques: [
      { id: "T1566.002", name: "Phishing: Spearphishing Link", tactic: "initial-access" },
      { id: "T1550.001", name: "Use Alternate Authentication Material: Application Access Token", tactic: "defense-evasion" },
      { id: "T1098.003", name: "Account Manipulation: Additional Cloud Roles", tactic: "persistence" },
      { id: "T1136.003", name: "Create Account: Cloud Account", tactic: "persistence" },
      { id: "T1213.002", name: "Data from Information Repositories: SharePoint", tactic: "collection" },
      { id: "T1114.002", name: "Email Collection: Remote Email Collection", tactic: "collection" },
      { id: "T1567.002", name: "Exfiltration Over Web Service: Exfiltration to Cloud Storage", tactic: "exfiltration" },
    ],
    defaultAbilities: [
      { abilityId: "oauth-token-enum", name: "Enumerate OAuth Tokens & Permissions", step: 1, description: "List all OAuth app registrations and their granted scopes" },
      { abilityId: "oauth-consent-grant", name: "Illicit Consent Grant", step: 2, description: "Register a malicious OAuth app with broad permissions" },
      { abilityId: "mailbox-access", name: "Access Target Mailbox via Graph API", step: 3, description: "Read emails using delegated or application permissions" },
      { abilityId: "sharepoint-exfil", name: "Exfiltrate SharePoint Documents", step: 4, description: "Download sensitive documents from SharePoint/OneDrive" },
      { abilityId: "persistence-app-reg", name: "Create Persistent App Registration", step: 5, description: "Register a new app with certificate-based auth for long-term access" },
    ],
    targetPlatforms: ["azure", "m365"],
    targetServices: ["Exchange Online", "SharePoint", "OneDrive", "Azure AD"],
    prerequisites: [
      "Valid OAuth token or ability to phish consent grant",
      "Target uses Microsoft 365 or Azure AD",
    ],
    detectionGuidance:
      "Monitor for unusual OAuth app registrations, consent grants with broad scopes (Mail.Read, Files.ReadWrite.All), and Graph API calls from unexpected IP ranges. Alert on new service principals with certificate credentials.",
    complexity: "medium",
  },

  // ─── Token Abuse ───────────────────────────────────────────────────
  {
    slug: "cloud-token-abuse",
    name: "Cloud Token Abuse & Privilege Escalation",
    category: "token_abuse",
    description:
      "Simulates an attacker who has obtained cloud access tokens (AWS STS, Azure AD, GCP service account) and uses them to enumerate permissions, escalate privileges, and move laterally across cloud services.",
    killChainPhases: [
      "initial-access",
      "discovery",
      "privilege-escalation",
      "lateral-movement",
      "impact",
    ],
    defaultTechniques: [
      { id: "T1078.004", name: "Valid Accounts: Cloud Accounts", tactic: "initial-access" },
      { id: "T1580", name: "Cloud Infrastructure Discovery", tactic: "discovery" },
      { id: "T1526", name: "Cloud Service Discovery", tactic: "discovery" },
      { id: "T1098.001", name: "Account Manipulation: Additional Cloud Credentials", tactic: "persistence" },
      { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "privilege-escalation" },
      { id: "T1021.007", name: "Remote Services: Cloud Services", tactic: "lateral-movement" },
      { id: "T1485", name: "Data Destruction", tactic: "impact" },
    ],
    defaultAbilities: [
      { abilityId: "sts-whoami", name: "STS GetCallerIdentity / Token Validation", step: 1, description: "Validate the stolen token and enumerate the identity" },
      { abilityId: "iam-enum", name: "Enumerate IAM Policies & Roles", step: 2, description: "List all attached policies and discover privilege escalation paths" },
      { abilityId: "privesc-iam-attach", name: "Attach Admin Policy to Current Role", step: 3, description: "Escalate privileges by attaching AdministratorAccess policy" },
      { abilityId: "cross-account-assume", name: "Assume Cross-Account Role", step: 4, description: "Pivot to other accounts via role assumption" },
      { abilityId: "s3-exfil", name: "Exfiltrate S3 Buckets", step: 5, description: "List and download sensitive data from S3 buckets" },
      { abilityId: "ec2-backdoor", name: "Deploy EC2 Backdoor Instance", step: 6, description: "Launch a new EC2 instance with attacker SSH key for persistence" },
    ],
    targetPlatforms: ["aws", "azure", "gcp"],
    targetServices: ["IAM", "STS", "S3", "EC2", "Lambda", "Azure AD"],
    prerequisites: [
      "Stolen cloud access token (e.g., from SSRF, leaked .env, metadata service)",
      "Target uses AWS, Azure, or GCP",
    ],
    detectionGuidance:
      "Monitor CloudTrail/Activity Log for GetCallerIdentity from unusual IPs, IAM policy changes, cross-account AssumeRole calls, and new EC2 instances. Alert on privilege escalation patterns (AttachRolePolicy, CreateAccessKey).",
    complexity: "high",
  },

  // ─── Cloud Lateral Movement ────────────────────────────────────────
  {
    slug: "cloud-lateral-movement",
    name: "Cloud Lateral Movement & Resource Hijacking",
    category: "cloud_lateral_movement",
    description:
      "Simulates lateral movement across cloud infrastructure — from a compromised workload to other VMs, containers, serverless functions, and managed databases using service account impersonation and metadata abuse.",
    killChainPhases: [
      "lateral-movement",
      "discovery",
      "credential-access",
      "collection",
      "persistence",
    ],
    defaultTechniques: [
      { id: "T1552.005", name: "Unsecured Credentials: Cloud Instance Metadata API", tactic: "credential-access" },
      { id: "T1021.007", name: "Remote Services: Cloud Services", tactic: "lateral-movement" },
      { id: "T1550.001", name: "Use Alternate Authentication Material: Application Access Token", tactic: "lateral-movement" },
      { id: "T1580", name: "Cloud Infrastructure Discovery", tactic: "discovery" },
      { id: "T1530", name: "Data from Cloud Storage", tactic: "collection" },
      { id: "T1525", name: "Implant Internal Image", tactic: "persistence" },
      { id: "T1578.002", name: "Modify Cloud Compute Infrastructure: Create Snapshot", tactic: "defense-evasion" },
    ],
    defaultAbilities: [
      { abilityId: "imds-harvest", name: "Harvest IMDS Credentials", step: 1, description: "Query instance metadata service for temporary credentials" },
      { abilityId: "service-enum", name: "Enumerate Cloud Services & Endpoints", step: 2, description: "Discover VPCs, subnets, security groups, and accessible services" },
      { abilityId: "container-escape", name: "Container Breakout Attempt", step: 3, description: "Attempt to escape container to host via known techniques" },
      { abilityId: "sa-impersonate", name: "Service Account Impersonation", step: 4, description: "Impersonate a higher-privilege service account" },
      { abilityId: "db-pivot", name: "Pivot to Managed Database", step: 5, description: "Access RDS/Cloud SQL using harvested credentials" },
      { abilityId: "snapshot-exfil", name: "Create & Exfiltrate VM Snapshot", step: 6, description: "Snapshot a target VM and share to attacker account" },
    ],
    targetPlatforms: ["aws", "azure", "gcp"],
    targetServices: ["EC2", "ECS", "Lambda", "RDS", "VPC", "Kubernetes"],
    prerequisites: [
      "Initial access to a cloud workload (VM, container, or serverless function)",
      "IMDS v1 enabled or service account with broad permissions",
    ],
    detectionGuidance:
      "Monitor for IMDS queries from unusual processes, cross-service API calls from compute instances, snapshot creation/sharing events, and service account impersonation. Alert on security group modifications and new VPC peering connections.",
    complexity: "expert",
  },

  // ─── Supply Chain Attack ───────────────────────────────────────────
  {
    slug: "supply-chain-compromise",
    name: "Supply Chain Compromise",
    category: "supply_chain",
    description:
      "Simulates a supply chain attack where a trusted third-party dependency, CI/CD pipeline, or vendor integration is compromised to deliver malicious payloads to downstream targets.",
    killChainPhases: [
      "initial-access",
      "execution",
      "persistence",
      "defense-evasion",
      "collection",
    ],
    defaultTechniques: [
      { id: "T1195.002", name: "Supply Chain Compromise: Compromise Software Supply Chain", tactic: "initial-access" },
      { id: "T1059.004", name: "Command and Scripting Interpreter: Unix Shell", tactic: "execution" },
      { id: "T1554", name: "Compromise Client Software Binary", tactic: "persistence" },
      { id: "T1027", name: "Obfuscated Files or Information", tactic: "defense-evasion" },
      { id: "T1074.001", name: "Data Staged: Local Data Staging", tactic: "collection" },
      { id: "T1071.001", name: "Application Layer Protocol: Web Protocols", tactic: "command-and-control" },
    ],
    defaultAbilities: [
      { abilityId: "dep-poison", name: "Dependency Poisoning", step: 1, description: "Inject malicious code into a trusted npm/pip/maven package" },
      { abilityId: "ci-inject", name: "CI/CD Pipeline Injection", step: 2, description: "Modify build pipeline to include backdoor in artifacts" },
      { abilityId: "artifact-tamper", name: "Tamper Build Artifacts", step: 3, description: "Replace legitimate binaries with trojanized versions" },
      { abilityId: "c2-beacon", name: "Establish C2 Beacon", step: 4, description: "Backdoor phones home via HTTPS to attacker infrastructure" },
      { abilityId: "data-stage", name: "Stage Sensitive Data", step: 5, description: "Collect and stage credentials, keys, and sensitive files" },
    ],
    targetPlatforms: ["linux", "windows", "macos"],
    targetServices: ["npm", "PyPI", "GitHub Actions", "Jenkins", "Docker Hub"],
    prerequisites: [
      "Access to a package registry or CI/CD system",
      "Target organization uses the compromised dependency",
    ],
    detectionGuidance:
      "Monitor for unexpected changes in dependency checksums, new or modified CI/CD pipeline steps, unusual outbound connections from build servers, and binary integrity violations. Implement SBOM tracking and artifact signing.",
    complexity: "expert",
  },

  // ─── Credential Harvesting ─────────────────────────────────────────
  {
    slug: "credential-harvesting",
    name: "Credential Harvesting & Password Spray",
    category: "credential_harvesting",
    description:
      "Simulates credential harvesting through phishing, password spraying, and credential stuffing attacks targeting corporate SSO, VPN, and cloud identity providers.",
    killChainPhases: [
      "reconnaissance",
      "initial-access",
      "credential-access",
      "persistence",
    ],
    defaultTechniques: [
      { id: "T1589.001", name: "Gather Victim Identity Information: Credentials", tactic: "reconnaissance" },
      { id: "T1566.001", name: "Phishing: Spearphishing Attachment", tactic: "initial-access" },
      { id: "T1110.003", name: "Brute Force: Password Spraying", tactic: "credential-access" },
      { id: "T1110.004", name: "Brute Force: Credential Stuffing", tactic: "credential-access" },
      { id: "T1556.006", name: "Modify Authentication Process: Multi-Factor Authentication", tactic: "persistence" },
      { id: "T1539", name: "Steal Web Session Cookie", tactic: "credential-access" },
    ],
    defaultAbilities: [
      { abilityId: "osint-emails", name: "Harvest Employee Emails via OSINT", step: 1, description: "Collect email addresses from LinkedIn, Hunter.io, and breach databases" },
      { abilityId: "phish-cred", name: "Deploy Credential Phishing Page", step: 2, description: "Clone SSO login page and deploy via GoPhish" },
      { abilityId: "pwd-spray", name: "Password Spray Against SSO", step: 3, description: "Spray common passwords against discovered accounts" },
      { abilityId: "mfa-bypass", name: "MFA Fatigue / Push Bombing", step: 4, description: "Repeatedly send MFA push notifications to exhaust the user" },
      { abilityId: "session-hijack", name: "Session Token Hijack", step: 5, description: "Capture and replay session cookies from phished users" },
    ],
    targetPlatforms: ["azure", "okta", "google-workspace"],
    targetServices: ["Azure AD", "Okta", "Google Workspace", "VPN", "OWA"],
    prerequisites: [
      "List of target email addresses",
      "GoPhish or similar phishing framework configured",
    ],
    detectionGuidance:
      "Monitor for password spray patterns (many accounts, few passwords), unusual login locations, MFA fatigue indicators (repeated push notifications), and session token reuse from different IPs. Implement conditional access policies.",
    complexity: "medium",
  },

  // ─── Ransomware Deployment ─────────────────────────────────────────
  {
    slug: "ransomware-deployment",
    name: "Ransomware Deployment Simulation",
    category: "ransomware_deployment",
    description:
      "Simulates the full ransomware kill chain from initial access through lateral movement, privilege escalation, defense evasion, and simulated encryption/exfiltration — without actual destructive payloads.",
    killChainPhases: [
      "initial-access",
      "execution",
      "privilege-escalation",
      "lateral-movement",
      "defense-evasion",
      "exfiltration",
      "impact",
    ],
    defaultTechniques: [
      { id: "T1566.001", name: "Phishing: Spearphishing Attachment", tactic: "initial-access" },
      { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell", tactic: "execution" },
      { id: "T1053.005", name: "Scheduled Task/Job: Scheduled Task", tactic: "privilege-escalation" },
      { id: "T1021.002", name: "Remote Services: SMB/Windows Admin Shares", tactic: "lateral-movement" },
      { id: "T1562.001", name: "Impair Defenses: Disable or Modify Tools", tactic: "defense-evasion" },
      { id: "T1048.003", name: "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol", tactic: "exfiltration" },
      { id: "T1486", name: "Data Encrypted for Impact", tactic: "impact" },
    ],
    defaultAbilities: [
      { abilityId: "macro-exec", name: "Execute Malicious Macro", step: 1, description: "Simulate macro execution from phishing document" },
      { abilityId: "av-disable", name: "Disable AV/EDR", step: 2, description: "Attempt to disable Windows Defender and EDR agents" },
      { abilityId: "mimikatz-dump", name: "Credential Dumping (Mimikatz)", step: 3, description: "Extract credentials from LSASS memory" },
      { abilityId: "smb-lateral", name: "SMB Lateral Movement", step: 4, description: "Move laterally via SMB admin shares" },
      { abilityId: "shadow-delete", name: "Delete Volume Shadow Copies", step: 5, description: "Remove backup snapshots to prevent recovery" },
      { abilityId: "sim-encrypt", name: "Simulated File Encryption", step: 6, description: "Simulate ransomware encryption (non-destructive marker files)" },
    ],
    targetPlatforms: ["windows"],
    targetServices: ["Active Directory", "SMB", "RDP", "Exchange"],
    prerequisites: [
      "Initial access to a Windows endpoint",
      "Active Directory environment",
    ],
    detectionGuidance:
      "Monitor for PowerShell execution policy changes, LSASS access, volume shadow copy deletion (vssadmin), mass file rename operations, and lateral SMB connections. Alert on EDR/AV tampering and scheduled task creation.",
    complexity: "high",
  },

  // ─── Data Exfiltration ─────────────────────────────────────────────
  {
    slug: "data-exfiltration",
    name: "Data Exfiltration via Multiple Channels",
    category: "data_exfiltration",
    description:
      "Simulates data exfiltration through various channels — DNS tunneling, cloud storage, encrypted C2, and steganography — to test DLP and network monitoring controls.",
    killChainPhases: [
      "collection",
      "exfiltration",
      "command-and-control",
    ],
    defaultTechniques: [
      { id: "T1560.001", name: "Archive Collected Data: Archive via Utility", tactic: "collection" },
      { id: "T1048.001", name: "Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol", tactic: "exfiltration" },
      { id: "T1567.002", name: "Exfiltration Over Web Service: Exfiltration to Cloud Storage", tactic: "exfiltration" },
      { id: "T1071.004", name: "Application Layer Protocol: DNS", tactic: "command-and-control" },
      { id: "T1132.001", name: "Data Encoding: Standard Encoding", tactic: "command-and-control" },
    ],
    defaultAbilities: [
      { abilityId: "data-discover", name: "Discover Sensitive Data", step: 1, description: "Scan for PII, credentials, and sensitive documents" },
      { abilityId: "data-stage-archive", name: "Stage & Compress Data", step: 2, description: "Archive target data with password-protected compression" },
      { abilityId: "dns-tunnel", name: "DNS Tunneling Exfiltration", step: 3, description: "Exfiltrate data via DNS TXT record queries" },
      { abilityId: "cloud-exfil", name: "Cloud Storage Upload", step: 4, description: "Upload data to attacker-controlled cloud storage" },
      { abilityId: "stego-exfil", name: "Steganographic Exfiltration", step: 5, description: "Hide data within image files for covert exfiltration" },
    ],
    targetPlatforms: ["windows", "linux", "macos"],
    targetServices: ["DNS", "HTTPS", "S3", "Azure Blob", "Google Drive"],
    prerequisites: [
      "Access to a system with sensitive data",
      "Outbound network access (DNS, HTTPS)",
    ],
    detectionGuidance:
      "Monitor for unusual DNS query volumes, large outbound transfers, connections to new cloud storage endpoints, and archive utility execution. Implement DLP policies and network flow analysis.",
    complexity: "medium",
  },

  // ─── Persistence Implant ───────────────────────────────────────────
  {
    slug: "persistence-implant",
    name: "Persistence Implant & Backdoor Installation",
    category: "persistence_implant",
    description:
      "Simulates establishing multiple persistence mechanisms — scheduled tasks, registry modifications, WMI subscriptions, and cloud-based backdoors — to maintain long-term access.",
    killChainPhases: [
      "persistence",
      "defense-evasion",
      "command-and-control",
    ],
    defaultTechniques: [
      { id: "T1053.005", name: "Scheduled Task/Job: Scheduled Task", tactic: "persistence" },
      { id: "T1547.001", name: "Boot or Logon Autostart Execution: Registry Run Keys", tactic: "persistence" },
      { id: "T1546.003", name: "Event Triggered Execution: WMI Event Subscription", tactic: "persistence" },
      { id: "T1136.003", name: "Create Account: Cloud Account", tactic: "persistence" },
      { id: "T1027.010", name: "Obfuscated Files or Information: Command Obfuscation", tactic: "defense-evasion" },
      { id: "T1573.002", name: "Encrypted Channel: Asymmetric Cryptography", tactic: "command-and-control" },
    ],
    defaultAbilities: [
      { abilityId: "schtask-persist", name: "Create Scheduled Task Backdoor", step: 1, description: "Install a scheduled task that runs a beacon on system startup" },
      { abilityId: "registry-runkey", name: "Registry Run Key Persistence", step: 2, description: "Add a registry run key for automatic execution" },
      { abilityId: "wmi-subscription", name: "WMI Event Subscription", step: 3, description: "Create a WMI event subscription for fileless persistence" },
      { abilityId: "cloud-backdoor", name: "Cloud Account Backdoor", step: 4, description: "Create a hidden cloud admin account with API access" },
      { abilityId: "c2-encrypted", name: "Encrypted C2 Channel", step: 5, description: "Establish encrypted command and control via HTTPS" },
    ],
    targetPlatforms: ["windows", "linux", "azure", "aws"],
    targetServices: ["Active Directory", "Task Scheduler", "WMI", "Azure AD", "IAM"],
    prerequisites: [
      "Local admin or SYSTEM access on target endpoint",
      "Or cloud admin credentials for cloud persistence",
    ],
    detectionGuidance:
      "Monitor for new scheduled tasks, registry run key modifications, WMI event subscriptions, and new cloud accounts. Alert on unusual service installations and encrypted outbound connections to uncommon destinations.",
    complexity: "high",
  },
];

/**
 * Given an actor's technique list and an archetype, compute the overlap
 * and return actor-specific techniques that match the archetype pattern.
 */
export function computeActorArchetypeOverlap(
  actorTechniques: { id: string; name: string; tactic?: string; score?: number }[],
  archetype: ArchetypeTemplate
): { id: string; name: string; tactic: string; actorScore: number }[] {
  const archetypeTechIds = new Set(archetype.defaultTechniques.map((t) => t.id));
  // Also match on parent technique (e.g., T1566 matches T1566.001)
  const archetypeParentIds = new Set(
    archetype.defaultTechniques.map((t) => t.id.split(".")[0])
  );

  const matches: { id: string; name: string; tactic: string; actorScore: number }[] = [];

  for (const tech of actorTechniques) {
    const techParent = tech.id.split(".")[0];
    if (archetypeTechIds.has(tech.id) || archetypeParentIds.has(techParent)) {
      // Find the matching archetype technique for tactic info
      const archetypeTech = archetype.defaultTechniques.find(
        (at) => at.id === tech.id || at.id.startsWith(techParent)
      );
      matches.push({
        id: tech.id,
        name: tech.name,
        tactic: tech.tactic || archetypeTech?.tactic || "unknown",
        actorScore: tech.score || 50,
      });
    }
  }

  return matches.sort((a, b) => b.actorScore - a.actorScore);
}
