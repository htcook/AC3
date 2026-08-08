/**
 * Seed Script: Stack/Network-Based Attack Templates & Campaign Templates
 * 
 * Creates attack templates organized by:
 * 1. Technology Stack (AWS Cloud, Azure/M365, Windows AD, Linux/Container)
 * 2. Network Type (MSP/MSSP, Healthcare, Financial Services, Government/DIB)
 * 3. Combined Campaign Templates (Caldera adversary + phishing + objectives)
 */
import mysql from 'mysql2/promise';
import { randomUUID } from 'crypto';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) { console.error("No DATABASE_URL set"); process.exit(1); }

const conn = await mysql.createConnection(DATABASE_URL + '&ssl={"rejectUnauthorized":true}');

// ═══════════════════════════════════════════════════════════════════════════
// STACK-BASED ATTACK TEMPLATES
// ═══════════════════════════════════════════════════════════════════════════

const STACK_TEMPLATES = [
  // ─── AWS Cloud ─────────────────────────────────────────────────────
  {
    name: "AWS Cloud: IAM Privilege Escalation Chain",
    attackType: "privilege_escalation",
    targetEnvironment: "aws_cloud",
    complexity: "advanced",
    description: "Full IAM privilege escalation from compromised developer credentials through policy attachment, role assumption, and cross-account pivoting to admin access.",
    phases: JSON.stringify([
      { phase: 1, name: "Initial Access via Stolen Keys", techniques: ["T1078.004", "T1552.005"] },
      { phase: 2, name: "IAM Enumeration & Policy Discovery", techniques: ["T1580", "T1526"] },
      { phase: 3, name: "Privilege Escalation via Policy Attachment", techniques: ["T1098.001", "T1548"] },
      { phase: 4, name: "Cross-Account Role Assumption", techniques: ["T1021.007"] },
      { phase: 5, name: "Persistence via Lambda Backdoor", techniques: ["T1525", "T1098"] },
    ]),
    targetSectors: JSON.stringify(["technology", "saas", "fintech", "healthcare"]),
    calderaAbilities: JSON.stringify([
      "AWS - Create Access Key and Secret Key",
      "AWS - CloudTrail Changes",
      "AWS - Create Snapshot from EBS Volume",
    ]),
    calderaAdversaryProfile: JSON.stringify({ name: "APT29 (G0016)", id: null }),
    detectionDifficulty: 6,
    commonDetections: JSON.stringify(["CloudTrail IAM events", "GuardDuty findings", "Config rule violations"]),
    evasionTechniques: JSON.stringify(["Use existing role names", "Operate during business hours", "Leverage trusted IP ranges"]),
    avgDwellTime: "4-12 hours",
    successRate: 0.72,
  },
  {
    name: "AWS Cloud: S3 Data Exfiltration via Misconfigured Buckets",
    attackType: "data_theft",
    targetEnvironment: "aws_cloud",
    complexity: "intermediate",
    description: "Enumerate and exfiltrate data from misconfigured S3 buckets using public access, cross-account policies, and presigned URL abuse.",
    phases: JSON.stringify([
      { phase: 1, name: "S3 Bucket Discovery & Enumeration", techniques: ["T1580", "T1530"] },
      { phase: 2, name: "Access Policy Analysis", techniques: ["T1526"] },
      { phase: 3, name: "Data Staging & Compression", techniques: ["T1074.002", "T1560.001"] },
      { phase: 4, name: "Exfiltration via Presigned URLs", techniques: ["T1567.002"] },
    ]),
    targetSectors: JSON.stringify(["technology", "healthcare", "financial", "government"]),
    calderaAbilities: JSON.stringify(["AWS - Create Snapshot from EBS Volume"]),
    calderaAdversaryProfile: JSON.stringify({ name: "APT41 (G0096)", id: null }),
    detectionDifficulty: 4,
    commonDetections: JSON.stringify(["S3 access logging", "CloudTrail data events", "VPC Flow Logs"]),
    evasionTechniques: JSON.stringify(["Use legitimate IAM roles", "Small batch downloads", "Operate from same region"]),
    avgDwellTime: "2-6 hours",
    successRate: 0.81,
  },
  {
    name: "AWS Cloud: Lambda Persistence & Serverless Backdoor",
    attackType: "persistence",
    targetEnvironment: "aws_cloud",
    complexity: "advanced",
    description: "Establish persistence in serverless environments by injecting backdoor code into Lambda functions, creating malicious layers, and abusing EventBridge triggers.",
    phases: JSON.stringify([
      { phase: 1, name: "Lambda Function Enumeration", techniques: ["T1526"] },
      { phase: 2, name: "Code Injection via Layer Poisoning", techniques: ["T1525"] },
      { phase: 3, name: "EventBridge Trigger Installation", techniques: ["T1546"] },
      { phase: 4, name: "Reverse Shell via Lambda Execution", techniques: ["T1059"] },
      { phase: 5, name: "Data Collection via DynamoDB Streams", techniques: ["T1530"] },
    ]),
    targetSectors: JSON.stringify(["technology", "saas", "fintech"]),
    calderaAbilities: JSON.stringify([]),
    calderaAdversaryProfile: JSON.stringify({ name: "HAFNIUM (G0125)", id: null }),
    detectionDifficulty: 8,
    commonDetections: JSON.stringify(["Lambda function version changes", "Layer updates", "Unusual invocation patterns"]),
    evasionTechniques: JSON.stringify(["Blend with legitimate deployments", "Use existing execution roles", "Minimal code changes"]),
    avgDwellTime: "7-30 days",
    successRate: 0.65,
  },
  // ─── Windows Active Directory ──────────────────────────────────────
  {
    name: "Windows AD: Kerberoasting to Domain Admin",
    attackType: "credential_access",
    targetEnvironment: "windows_ad",
    complexity: "intermediate",
    description: "Classic Active Directory attack path from initial foothold through Kerberoasting, password cracking, and lateral movement to Domain Admin compromise.",
    phases: JSON.stringify([
      { phase: 1, name: "Domain Enumeration via BloodHound", techniques: ["T1087.002", "T1069.002"] },
      { phase: 2, name: "Kerberoasting Service Accounts", techniques: ["T1558.003"] },
      { phase: 3, name: "Offline Password Cracking", techniques: ["T1110.002"] },
      { phase: 4, name: "Lateral Movement via WMI/PSRemoting", techniques: ["T1047", "T1021.006"] },
      { phase: 5, name: "DCSync for Full Domain Compromise", techniques: ["T1003.006"] },
    ]),
    targetSectors: JSON.stringify(["enterprise", "government", "healthcare", "financial"]),
    calderaAbilities: JSON.stringify([
      "Kerberoast (Invoke-Kerberoast.ps1)",
      "BloodHound Collection (SharpHound)",
    ]),
    calderaAdversaryProfile: JSON.stringify({ name: "FIN6 (G0037)", id: null }),
    detectionDifficulty: 5,
    commonDetections: JSON.stringify(["4769 events with RC4 encryption", "Unusual LDAP queries", "DCSync replication traffic"]),
    evasionTechniques: JSON.stringify(["Request RC4 tickets during business hours", "Target accounts with weak passwords", "Use legitimate admin tools"]),
    avgDwellTime: "1-3 days",
    successRate: 0.78,
  },
  {
    name: "Windows AD: Golden Ticket Persistence",
    attackType: "persistence",
    targetEnvironment: "windows_ad",
    complexity: "nation-state",
    description: "After obtaining KRBTGT hash, forge Golden Tickets for unlimited domain access, establish persistence across forest trusts, and maintain access through password resets.",
    phases: JSON.stringify([
      { phase: 1, name: "KRBTGT Hash Extraction via DCSync", techniques: ["T1003.006"] },
      { phase: 2, name: "Golden Ticket Forging", techniques: ["T1558.001"] },
      { phase: 3, name: "Cross-Forest Trust Exploitation", techniques: ["T1134.005"] },
      { phase: 4, name: "SID History Injection", techniques: ["T1134.005"] },
      { phase: 5, name: "Skeleton Key Installation", techniques: ["T1556.001"] },
    ]),
    targetSectors: JSON.stringify(["government", "defense", "financial", "critical_infrastructure"]),
    calderaAbilities: JSON.stringify([]),
    calderaAdversaryProfile: JSON.stringify({ name: "APT29 (G0016)", id: null }),
    detectionDifficulty: 9,
    commonDetections: JSON.stringify(["Ticket lifetime anomalies", "KRBTGT password age", "Unusual cross-domain authentication"]),
    evasionTechniques: JSON.stringify(["Match legitimate ticket lifetimes", "Use valid SIDs", "Operate during maintenance windows"]),
    avgDwellTime: "30-180 days",
    successRate: 0.92,
  },
  {
    name: "Windows AD: ADCS Certificate Abuse (ESC1-ESC8)",
    attackType: "privilege_escalation",
    targetEnvironment: "windows_ad",
    complexity: "advanced",
    description: "Exploit misconfigured Active Directory Certificate Services templates to escalate privileges, impersonate users, and establish persistent access via certificate-based authentication.",
    phases: JSON.stringify([
      { phase: 1, name: "ADCS Template Enumeration (Certify)", techniques: ["T1649"] },
      { phase: 2, name: "ESC1: Misconfigured Template Enrollment", techniques: ["T1649"] },
      { phase: 3, name: "Certificate-Based Authentication as DA", techniques: ["T1556.006"] },
      { phase: 4, name: "NTLM Relay to ADCS (ESC8/PetitPotam)", techniques: ["T1557.001"] },
      { phase: 5, name: "Persistent Access via Long-Lived Certs", techniques: ["T1556.006"] },
    ]),
    targetSectors: JSON.stringify(["enterprise", "government", "healthcare"]),
    calderaAbilities: JSON.stringify([
      "ADFS token signing and encryption certificates theft - Local",
      "ADFS token signing and encryption certificates theft - Remote",
    ]),
    calderaAdversaryProfile: JSON.stringify({ name: "FIN7 (G0046)", id: null }),
    detectionDifficulty: 7,
    commonDetections: JSON.stringify(["Certificate enrollment events (4886/4887)", "Unusual certificate requests", "NTLM relay detection"]),
    evasionTechniques: JSON.stringify(["Use legitimate enrollment processes", "Request certs with normal lifetimes", "Target templates with auto-enrollment"]),
    avgDwellTime: "7-90 days",
    successRate: 0.69,
  },
  // ─── Linux / Container ─────────────────────────────────────────────
  {
    name: "Linux: Container Escape to Host Compromise",
    attackType: "privilege_escalation",
    targetEnvironment: "linux_container",
    complexity: "advanced",
    description: "Escape from a compromised container to the underlying host using kernel exploits, misconfigured capabilities, and mounted host filesystems.",
    phases: JSON.stringify([
      { phase: 1, name: "Container Environment Enumeration", techniques: ["T1082", "T1613"] },
      { phase: 2, name: "Capability & Mount Analysis", techniques: ["T1611"] },
      { phase: 3, name: "Container Escape via Privileged Mode", techniques: ["T1611"] },
      { phase: 4, name: "Host Filesystem Access & Credential Harvest", techniques: ["T1552.001"] },
      { phase: 5, name: "Lateral Movement to Other Containers/Nodes", techniques: ["T1021.004"] },
    ]),
    targetSectors: JSON.stringify(["technology", "saas", "cloud_native"]),
    calderaAbilities: JSON.stringify([]),
    calderaAdversaryProfile: JSON.stringify({ name: "Aquatic Panda (G0143)", id: null }),
    detectionDifficulty: 7,
    commonDetections: JSON.stringify(["Syscall monitoring (seccomp)", "Falco alerts", "Unusual process trees"]),
    evasionTechniques: JSON.stringify(["Use legitimate container tools", "Exploit kernel race conditions", "Leverage existing capabilities"]),
    avgDwellTime: "1-4 hours",
    successRate: 0.58,
  },
  {
    name: "Linux: SSH Key Harvesting & Lateral Movement",
    attackType: "lateral_movement",
    targetEnvironment: "linux_server",
    complexity: "intermediate",
    description: "Harvest SSH keys from compromised Linux servers, enumerate known_hosts and authorized_keys to map the network, and pivot laterally across the infrastructure.",
    phases: JSON.stringify([
      { phase: 1, name: "SSH Key Discovery", techniques: ["T1552.004"] },
      { phase: 2, name: "known_hosts Enumeration", techniques: ["T1018"] },
      { phase: 3, name: "SSH Agent Hijacking", techniques: ["T1563.001"] },
      { phase: 4, name: "Lateral Movement via SSH", techniques: ["T1021.004"] },
      { phase: 5, name: "Persistence via authorized_keys", techniques: ["T1098.004"] },
    ]),
    targetSectors: JSON.stringify(["technology", "hosting", "msp", "education"]),
    calderaAbilities: JSON.stringify([]),
    calderaAdversaryProfile: JSON.stringify({ name: "APT32 (G0050)", id: null }),
    detectionDifficulty: 4,
    commonDetections: JSON.stringify(["SSH login events", "authorized_keys modifications", "Unusual SSH agent forwarding"]),
    evasionTechniques: JSON.stringify(["Use existing SSH keys", "Operate during admin hours", "Leverage jump hosts"]),
    avgDwellTime: "2-7 days",
    successRate: 0.84,
  },
  {
    name: "Linux: Supply Chain via CI/CD Pipeline Compromise",
    attackType: "supply_chain",
    targetEnvironment: "linux_cicd",
    complexity: "nation-state",
    description: "Compromise CI/CD pipelines (Jenkins, GitLab CI, GitHub Actions) to inject malicious code into build artifacts, poison container images, and distribute backdoored software.",
    phases: JSON.stringify([
      { phase: 1, name: "CI/CD Service Discovery & Enumeration", techniques: ["T1526", "T1046"] },
      { phase: 2, name: "Pipeline Configuration Tampering", techniques: ["T1195.002"] },
      { phase: 3, name: "Build Artifact Poisoning", techniques: ["T1195.002"] },
      { phase: 4, name: "Container Image Backdoor", techniques: ["T1525"] },
      { phase: 5, name: "Distribution to Production", techniques: ["T1195.002"] },
    ]),
    targetSectors: JSON.stringify(["technology", "saas", "open_source"]),
    calderaAbilities: JSON.stringify([]),
    calderaAdversaryProfile: JSON.stringify({ name: "APT41 (G0096)", id: null }),
    detectionDifficulty: 9,
    commonDetections: JSON.stringify(["Pipeline config changes", "Unexpected build dependencies", "Image layer diffs"]),
    evasionTechniques: JSON.stringify(["Minimal code changes", "Match existing coding style", "Use legitimate build tools"]),
    avgDwellTime: "14-90 days",
    successRate: 0.55,
  },
  // ─── Azure / M365 ─────────────────────────────────────────────────
  {
    name: "Azure AD: Illicit Consent Grant & Mailbox Compromise",
    attackType: "data_theft",
    targetEnvironment: "azure_m365",
    complexity: "intermediate",
    description: "Phish users into granting OAuth consent to a malicious application, then use delegated permissions to access mailboxes, SharePoint, and Teams data.",
    phases: JSON.stringify([
      { phase: 1, name: "Malicious App Registration", techniques: ["T1098.002"] },
      { phase: 2, name: "Consent Phishing Campaign", techniques: ["T1566.002"] },
      { phase: 3, name: "Graph API Mailbox Access", techniques: ["T1114.002"] },
      { phase: 4, name: "SharePoint/OneDrive Exfiltration", techniques: ["T1213.002"] },
      { phase: 5, name: "Persistent Access via App Credentials", techniques: ["T1098.001"] },
    ]),
    targetSectors: JSON.stringify(["enterprise", "legal", "consulting", "financial"]),
    calderaAbilities: JSON.stringify([]),
    calderaAdversaryProfile: JSON.stringify({ name: "APT29 (G0016)", id: null }),
    detectionDifficulty: 5,
    commonDetections: JSON.stringify(["Consent grant audit logs", "Unusual Graph API calls", "New app registrations"]),
    evasionTechniques: JSON.stringify(["Use legitimate-looking app names", "Request minimal initial scopes", "Gradual scope expansion"]),
    avgDwellTime: "3-14 days",
    successRate: 0.73,
  },
  {
    name: "Azure: Managed Identity Abuse & Resource Pivoting",
    attackType: "lateral_movement",
    targetEnvironment: "azure_cloud",
    complexity: "advanced",
    description: "Exploit compromised Azure VMs or App Services to abuse their Managed Identity tokens, pivot to other Azure resources, and escalate to subscription-level access.",
    phases: JSON.stringify([
      { phase: 1, name: "IMDS Token Extraction", techniques: ["T1552.005"] },
      { phase: 2, name: "Azure Resource Enumeration", techniques: ["T1580"] },
      { phase: 3, name: "Key Vault Secret Extraction", techniques: ["T1552.006"] },
      { phase: 4, name: "Storage Account Data Access", techniques: ["T1530"] },
      { phase: 5, name: "Subscription-Level Privilege Escalation", techniques: ["T1098.001"] },
    ]),
    targetSectors: JSON.stringify(["enterprise", "saas", "government"]),
    calderaAbilities: JSON.stringify([]),
    calderaAdversaryProfile: JSON.stringify({ name: "HAFNIUM (G0125)", id: null }),
    detectionDifficulty: 6,
    commonDetections: JSON.stringify(["Unusual IMDS access patterns", "Key Vault access from unexpected sources", "Role assignment changes"]),
    evasionTechniques: JSON.stringify(["Use existing managed identity permissions", "Access from same region", "Blend with application traffic"]),
    avgDwellTime: "1-7 days",
    successRate: 0.68,
  },
];

// ═══════════════════════════════════════════════════════════════════════════
// NETWORK-TYPE ATTACK TEMPLATES
// ═══════════════════════════════════════════════════════════════════════════

const NETWORK_TEMPLATES = [
  // ─── MSP/MSSP ─────────────────────────────────────────────────────
  {
    name: "MSP Network: RMM Tool Compromise & Multi-Tenant Pivot",
    attackType: "supply_chain",
    targetEnvironment: "msp_network",
    complexity: "advanced",
    description: "Compromise an MSP's Remote Monitoring & Management (RMM) tool to gain access to all managed client networks simultaneously. Simulates real-world MSP supply chain attacks.",
    phases: JSON.stringify([
      { phase: 1, name: "MSP Admin Portal Credential Access", techniques: ["T1078.004", "T1110.003"] },
      { phase: 2, name: "RMM Agent Enumeration Across Tenants", techniques: ["T1018", "T1526"] },
      { phase: 3, name: "Malicious Script Deployment via RMM", techniques: ["T1072"] },
      { phase: 4, name: "Multi-Tenant Lateral Movement", techniques: ["T1021.006", "T1570"] },
      { phase: 5, name: "Ransomware Staging Across Client Networks", techniques: ["T1486", "T1490"] },
    ]),
    targetSectors: JSON.stringify(["msp", "mssp", "it_services"]),
    calderaAbilities: JSON.stringify([]),
    calderaAdversaryProfile: JSON.stringify({ name: "MSP_Target_AD_RMM_Backup_Compromise", id: null }),
    detectionDifficulty: 8,
    commonDetections: JSON.stringify(["Unusual RMM script executions", "Mass deployment events", "Cross-tenant activity spikes"]),
    evasionTechniques: JSON.stringify(["Use legitimate RMM channels", "Deploy during maintenance windows", "Mimic patch deployments"]),
    avgDwellTime: "1-7 days",
    successRate: 0.71,
  },
  {
    name: "MSP Network: Backup Infrastructure Destruction",
    attackType: "ransomware",
    targetEnvironment: "msp_network",
    complexity: "advanced",
    description: "Target MSP backup infrastructure (Veeam, Datto, Acronis) to destroy recovery capabilities before deploying ransomware across managed client environments.",
    phases: JSON.stringify([
      { phase: 1, name: "Backup Server Discovery", techniques: ["T1018", "T1046"] },
      { phase: 2, name: "Backup Admin Credential Harvesting", techniques: ["T1003.001", "T1552.001"] },
      { phase: 3, name: "Backup Repository Deletion", techniques: ["T1490"] },
      { phase: 4, name: "VSS Shadow Copy Destruction", techniques: ["T1490"] },
      { phase: 5, name: "Ransomware Deployment", techniques: ["T1486"] },
    ]),
    targetSectors: JSON.stringify(["msp", "mssp", "smb_clients"]),
    calderaAbilities: JSON.stringify([]),
    calderaAdversaryProfile: JSON.stringify({ name: "MSP_Target_AD_RMM_Backup_Compromise", id: null }),
    detectionDifficulty: 6,
    commonDetections: JSON.stringify(["Backup job failures", "VSS deletion events", "Unusual admin access to backup servers"]),
    evasionTechniques: JSON.stringify(["Disable backup monitoring alerts first", "Operate outside backup windows", "Use legitimate backup admin tools"]),
    avgDwellTime: "12-48 hours",
    successRate: 0.76,
  },
  // ─── Healthcare ────────────────────────────────────────────────────
  {
    name: "Healthcare: EHR System Compromise & PHI Exfiltration",
    attackType: "data_theft",
    targetEnvironment: "healthcare_network",
    complexity: "advanced",
    description: "Target Electronic Health Record systems to exfiltrate Protected Health Information (PHI). Simulates attacks on Epic, Cerner, and other EHR platforms.",
    phases: JSON.stringify([
      { phase: 1, name: "Clinical Workstation Compromise", techniques: ["T1566.001", "T1204.002"] },
      { phase: 2, name: "EHR Credential Harvesting", techniques: ["T1056.001", "T1003.001"] },
      { phase: 3, name: "Database Query & PHI Collection", techniques: ["T1213", "T1005"] },
      { phase: 4, name: "Data Staging in Temp Directories", techniques: ["T1074.001"] },
      { phase: 5, name: "Exfiltration via HTTPS", techniques: ["T1048.002"] },
    ]),
    targetSectors: JSON.stringify(["healthcare", "hospital", "clinic", "pharmacy"]),
    calderaAbilities: JSON.stringify([]),
    calderaAdversaryProfile: JSON.stringify({ name: "FIN8 (G0061)", id: null }),
    detectionDifficulty: 5,
    commonDetections: JSON.stringify(["Unusual EHR query patterns", "Large data exports", "After-hours access to patient records"]),
    evasionTechniques: JSON.stringify(["Use legitimate clinical credentials", "Query during shift changes", "Small batch exports"]),
    avgDwellTime: "3-14 days",
    successRate: 0.67,
  },
  {
    name: "Healthcare: Medical IoT Device Exploitation",
    attackType: "ot_disruption",
    targetEnvironment: "healthcare_iot",
    complexity: "nation-state",
    description: "Exploit vulnerable medical IoT devices (infusion pumps, imaging systems, patient monitors) to establish network footholds and potentially disrupt patient care.",
    phases: JSON.stringify([
      { phase: 1, name: "Medical Device Network Scanning", techniques: ["T1046", "T1040"] },
      { phase: 2, name: "Default Credential Exploitation", techniques: ["T1078.001"] },
      { phase: 3, name: "Firmware Analysis & Vulnerability Exploitation", techniques: ["T1190"] },
      { phase: 4, name: "Pivot from IoT VLAN to Clinical Network", techniques: ["T1599"] },
      { phase: 5, name: "Patient Safety Impact Assessment", techniques: ["T1489"] },
    ]),
    targetSectors: JSON.stringify(["healthcare", "hospital", "medical_device"]),
    calderaAbilities: JSON.stringify([]),
    calderaAdversaryProfile: JSON.stringify({ name: "APT33 (G0064)", id: null }),
    detectionDifficulty: 8,
    commonDetections: JSON.stringify(["Unusual traffic from medical devices", "VLAN boundary violations", "Firmware update anomalies"]),
    evasionTechniques: JSON.stringify(["Blend with device telemetry", "Use expected protocols (HL7/DICOM)", "Operate during high-activity periods"]),
    avgDwellTime: "7-30 days",
    successRate: 0.45,
  },
  // ─── Financial Services ────────────────────────────────────────────
  {
    name: "Financial: SWIFT Network Attack Simulation",
    attackType: "financial_fraud",
    targetEnvironment: "financial_network",
    complexity: "nation-state",
    description: "Simulate attacks against financial messaging systems (SWIFT) including operator credential theft, transaction manipulation, and evidence destruction.",
    phases: JSON.stringify([
      { phase: 1, name: "SWIFT Operator Workstation Compromise", techniques: ["T1566.001", "T1204.002"] },
      { phase: 2, name: "SWIFT Alliance Credential Harvesting", techniques: ["T1056.001", "T1003.001"] },
      { phase: 3, name: "Transaction Message Manipulation", techniques: ["T1565.002"] },
      { phase: 4, name: "Fraudulent Transfer Initiation", techniques: ["T1565.002"] },
      { phase: 5, name: "Log Deletion & Evidence Destruction", techniques: ["T1070.001", "T1070.002"] },
    ]),
    targetSectors: JSON.stringify(["banking", "financial_services", "credit_union"]),
    calderaAbilities: JSON.stringify([]),
    calderaAdversaryProfile: JSON.stringify({ name: "APT38 (G0082)", id: null }),
    detectionDifficulty: 7,
    commonDetections: JSON.stringify(["Unusual SWIFT message patterns", "After-hours operator access", "Log tampering indicators"]),
    evasionTechniques: JSON.stringify(["Match legitimate transaction patterns", "Use valid operator credentials", "Target low-monitoring periods"]),
    avgDwellTime: "14-60 days",
    successRate: 0.35,
  },
  {
    name: "Financial: ATM/POS Malware Deployment",
    attackType: "financial_fraud",
    targetEnvironment: "financial_pos",
    complexity: "advanced",
    description: "Deploy RAM-scraping malware to ATM and Point-of-Sale systems to harvest payment card data. Simulates FIN groups' known TTPs.",
    phases: JSON.stringify([
      { phase: 1, name: "POS Network Segment Discovery", techniques: ["T1046", "T1018"] },
      { phase: 2, name: "POS Terminal Compromise", techniques: ["T1021.001", "T1078"] },
      { phase: 3, name: "Memory Scraping Malware Deployment", techniques: ["T1005"] },
      { phase: 4, name: "Track Data Collection & Staging", techniques: ["T1074.001"] },
      { phase: 5, name: "Exfiltration to C2 Infrastructure", techniques: ["T1041"] },
    ]),
    targetSectors: JSON.stringify(["retail_banking", "hospitality", "retail"]),
    calderaAbilities: JSON.stringify([]),
    calderaAdversaryProfile: JSON.stringify({ name: "FIN6 (G0037)", id: null }),
    detectionDifficulty: 6,
    commonDetections: JSON.stringify(["Unusual processes on POS systems", "Network traffic to unknown IPs", "Memory access patterns"]),
    evasionTechniques: JSON.stringify(["Fileless execution", "Blend with POS software processes", "Encrypted exfiltration"]),
    avgDwellTime: "7-90 days",
    successRate: 0.62,
  },
  // ─── Government / DIB ──────────────────────────────────────────────
  {
    name: "Government: Spear-Phishing to CUI Exfiltration",
    attackType: "apt_espionage",
    targetEnvironment: "government_network",
    complexity: "nation-state",
    description: "Nation-state style campaign targeting government contractors to exfiltrate Controlled Unclassified Information (CUI) through spear-phishing and living-off-the-land techniques.",
    phases: JSON.stringify([
      { phase: 1, name: "Target Reconnaissance & Social Engineering", techniques: ["T1598.003", "T1589.002"] },
      { phase: 2, name: "Spear-Phishing with Weaponized Document", techniques: ["T1566.001", "T1204.002"] },
      { phase: 3, name: "Living-off-the-Land Persistence", techniques: ["T1059.001", "T1053.005"] },
      { phase: 4, name: "Internal Reconnaissance & CUI Discovery", techniques: ["T1083", "T1119"] },
      { phase: 5, name: "Staged Exfiltration via DNS Tunneling", techniques: ["T1048.001"] },
    ]),
    targetSectors: JSON.stringify(["government", "defense_industrial_base", "aerospace"]),
    calderaAbilities: JSON.stringify([]),
    calderaAdversaryProfile: JSON.stringify({ name: "APT28 (G0007)", id: null }),
    detectionDifficulty: 8,
    commonDetections: JSON.stringify(["DNS query anomalies", "Scheduled task creation", "Unusual PowerShell execution"]),
    evasionTechniques: JSON.stringify(["Use only built-in Windows tools", "DNS tunneling for C2", "Operate within normal business hours"]),
    avgDwellTime: "30-180 days",
    successRate: 0.58,
  },
  {
    name: "Government: Zero-Day Web Application Exploitation",
    attackType: "apt_espionage",
    targetEnvironment: "government_dmz",
    complexity: "nation-state",
    description: "Exploit zero-day vulnerabilities in internet-facing government web applications to establish initial access, deploy web shells, and pivot to internal networks.",
    phases: JSON.stringify([
      { phase: 1, name: "Internet-Facing Application Reconnaissance", techniques: ["T1595.002"] },
      { phase: 2, name: "Zero-Day Exploitation", techniques: ["T1190"] },
      { phase: 3, name: "Web Shell Deployment", techniques: ["T1505.003"] },
      { phase: 4, name: "Internal Network Pivot", techniques: ["T1021.001", "T1021.002"] },
      { phase: 5, name: "Credential Dumping & Domain Compromise", techniques: ["T1003.001", "T1003.006"] },
    ]),
    targetSectors: JSON.stringify(["government", "military", "intelligence"]),
    calderaAbilities: JSON.stringify([]),
    calderaAdversaryProfile: JSON.stringify({ name: "HAFNIUM (G0125)", id: null }),
    detectionDifficulty: 9,
    commonDetections: JSON.stringify(["Web shell indicators", "Unusual outbound connections from DMZ", "Post-exploitation tool signatures"]),
    evasionTechniques: JSON.stringify(["Encrypted web shell traffic", "Blend with legitimate web requests", "Use living-off-the-land binaries"]),
    avgDwellTime: "60-365 days",
    successRate: 0.42,
  },
];

// ═══════════════════════════════════════════════════════════════════════════
// CAMPAIGN TEMPLATES (Caldera Adversary + Phishing + Objectives)
// ═══════════════════════════════════════════════════════════════════════════

const CAMPAIGN_TEMPLATES = [
  {
    name: "Full-Spectrum MSP Compromise",
    description: "End-to-end MSP attack combining credential phishing of MSP admins, RMM tool compromise, and multi-tenant ransomware deployment. Uses APT29 VCD techniques adapted for MSP environments.",
    targetEnvironment: "MSP/MSSP Network",
    adversaryName: "MSP_Target_Complete_APT29_VCD_CrowdStrike",
    status: "ready",
  },
  {
    name: "Healthcare Ransomware Exercise",
    description: "Simulates a ransomware attack against healthcare infrastructure starting with phishing of clinical staff, EHR credential harvesting, backup destruction, and ransomware deployment.",
    targetEnvironment: "Healthcare Network (EHR + Clinical)",
    adversaryName: "BlackByte (G1043)",
    status: "ready",
  },
  {
    name: "Financial Sector APT Campaign",
    description: "Nation-state style campaign targeting financial institutions. Combines spear-phishing of SWIFT operators with credential harvesting, transaction manipulation, and evidence destruction.",
    targetEnvironment: "Financial Services (SWIFT + Core Banking)",
    adversaryName: "APT38 (G0082)",
    status: "ready",
  },
  {
    name: "Cloud Infrastructure Takeover",
    description: "Full cloud compromise campaign starting with developer credential phishing, IAM privilege escalation, cross-account pivoting, and data exfiltration from S3/Azure Storage.",
    targetEnvironment: "AWS/Azure Cloud Infrastructure",
    adversaryName: "APT29 (G0016)",
    status: "ready",
  },
  {
    name: "Active Directory Domain Takeover",
    description: "Classic AD attack campaign combining initial phishing, Kerberoasting, ADCS abuse, and Golden Ticket persistence. Targets enterprise Windows environments.",
    targetEnvironment: "Windows Active Directory Enterprise",
    adversaryName: "FIN7 (G0046)",
    status: "ready",
  },
  {
    name: "Supply Chain CI/CD Poisoning",
    description: "Advanced supply chain attack targeting software development pipelines. Combines developer phishing with CI/CD compromise, artifact poisoning, and backdoored deployments.",
    targetEnvironment: "DevOps/CI-CD Pipeline (GitHub/GitLab)",
    adversaryName: "APT41 (G0096)",
    status: "ready",
  },
  {
    name: "Government CUI Exfiltration",
    description: "Nation-state espionage campaign targeting government contractors. Uses spear-phishing, living-off-the-land techniques, and DNS tunneling for CUI exfiltration.",
    targetEnvironment: "Government/DIB Network (NIST 800-171)",
    adversaryName: "APT28 (G0007)",
    status: "ready",
  },
  {
    name: "IoT/OT Network Infiltration",
    description: "Attack campaign targeting industrial IoT and OT networks. Starts with IT network compromise, pivots to OT through engineering workstations, and targets PLCs/SCADA systems.",
    targetEnvironment: "ICS/SCADA + Corporate IT",
    adversaryName: "Dragonfly (G0035)",
    status: "ready",
  },
  {
    name: "SaaS OAuth Token Abuse",
    description: "Cloud-native attack targeting SaaS applications through OAuth consent phishing, token abuse, and API-based data exfiltration from M365, Google Workspace, and Salesforce.",
    targetEnvironment: "SaaS/M365/Google Workspace",
    adversaryName: "APT29 (G0016)",
    status: "ready",
  },
  {
    name: "Insider Threat Simulation",
    description: "Simulates a malicious insider with legitimate access escalating privileges, accessing unauthorized data, and exfiltrating sensitive information through covert channels.",
    targetEnvironment: "Corporate Enterprise (Any)",
    adversaryName: "Chimera (G0114)",
    status: "ready",
  },
];

// ═══════════════════════════════════════════════════════════════════════════
// SEED EXECUTION
// ═══════════════════════════════════════════════════════════════════════════

console.log("╔══════════════════════════════════════════════════════════════╗");
console.log("║  SEEDING STACK/NETWORK ATTACK TEMPLATES & CAMPAIGNS        ║");
console.log("╚══════════════════════════════════════════════════════════════╝");

// 1. Seed stack-based attack templates
console.log("\n=== Phase 1: Stack-Based Attack Templates ===");
let stackCreated = 0;
for (const t of STACK_TEMPLATES) {
  const id = randomUUID();
  const templateId = `stack-${t.targetEnvironment}-${t.attackType}-${Date.now()}`;
  try {
    await conn.query(`
      INSERT INTO attack_sequence_templates 
      (templateId, name, description, phases, totalPhases, attackType, ast_complexity, 
       targetEnvironment, ast_targetSectors, ast_calderaAbilities, calderaAdversaryProfile,
       detectionDifficulty, commonDetections, evasionTechniques, avgDwellTime, successRate,
       useCount, ast_confidence, ast_status, ast_created_at, ast_updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 85, 'production', NOW(), NOW())
    `, [
      templateId, t.name, t.description, t.phases,
      JSON.parse(t.phases).length, t.attackType, t.complexity,
      t.targetEnvironment, t.targetSectors, t.calderaAbilities, t.calderaAdversaryProfile,
      t.detectionDifficulty, t.commonDetections, t.evasionTechniques, t.avgDwellTime, t.successRate,
    ]);
    stackCreated++;
    console.log(`  ✓ ${t.name}`);
  } catch (e) {
    console.log(`  ✗ ${t.name}: ${e.message}`);
  }
}
console.log(`  → Created ${stackCreated}/${STACK_TEMPLATES.length} stack templates`);

// 2. Seed network-type attack templates
console.log("\n=== Phase 2: Network-Type Attack Templates ===");
let networkCreated = 0;
for (const t of NETWORK_TEMPLATES) {
  const id = randomUUID();
  const templateId = `net-${t.targetEnvironment}-${t.attackType}-${Date.now()}`;
  try {
    await conn.query(`
      INSERT INTO attack_sequence_templates 
      (templateId, name, description, phases, totalPhases, attackType, ast_complexity, 
       targetEnvironment, ast_targetSectors, ast_calderaAbilities, calderaAdversaryProfile,
       detectionDifficulty, commonDetections, evasionTechniques, avgDwellTime, successRate,
       useCount, ast_confidence, ast_status, ast_created_at, ast_updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 90, 'production', NOW(), NOW())
    `, [
      templateId, t.name, t.description, t.phases,
      JSON.parse(t.phases).length, t.attackType, t.complexity,
      t.targetEnvironment, t.targetSectors, t.calderaAbilities, t.calderaAdversaryProfile,
      t.detectionDifficulty, t.commonDetections, t.evasionTechniques, t.avgDwellTime, t.successRate,
    ]);
    networkCreated++;
    console.log(`  ✓ ${t.name}`);
  } catch (e) {
    console.log(`  ✗ ${t.name}: ${e.message}`);
  }
}
console.log(`  → Created ${networkCreated}/${NETWORK_TEMPLATES.length} network templates`);

// 3. Seed campaign templates
console.log("\n=== Phase 3: Campaign Templates ===");
let campaignCreated = 0;
for (const c of CAMPAIGN_TEMPLATES) {
  try {
    await conn.query(`
      INSERT INTO campaigns (name, description, targetEnvironment, adversaryName, status, createdAt, updatedAt)
      VALUES (?, ?, ?, ?, ?, NOW(), NOW())
    `, [c.name, c.description, c.targetEnvironment, c.adversaryName, c.status]);
    campaignCreated++;
    console.log(`  ✓ ${c.name}`);
  } catch (e) {
    console.log(`  ✗ ${c.name}: ${e.message}`);
  }
}
console.log(`  → Created ${campaignCreated}/${CAMPAIGN_TEMPLATES.length} campaign templates`);

// 4. Summary
console.log("\n╔══════════════════════════════════════════════════════════════╗");
console.log("║  SEEDING COMPLETE                                           ║");
console.log("╠══════════════════════════════════════════════════════════════╣");
console.log(`║  Stack Attack Templates:   ${stackCreated} created`);
console.log(`║  Network Attack Templates: ${networkCreated} created`);
console.log(`║  Campaign Templates:       ${campaignCreated} created`);
console.log("╚══════════════════════════════════════════════════════════════╝");

// 5. Verify totals
const [totalTemplates] = await conn.query("SELECT COUNT(*) as cnt FROM attack_sequence_templates");
const [totalCampaigns] = await conn.query("SELECT COUNT(*) as cnt FROM campaigns");
const [envBreakdown] = await conn.query("SELECT targetEnvironment, COUNT(*) as cnt FROM attack_sequence_templates WHERE ast_status = 'production' GROUP BY targetEnvironment ORDER BY cnt DESC");
console.log(`\n  Total attack templates in DB: ${totalTemplates[0].cnt}`);
console.log(`  Total campaigns in DB: ${totalCampaigns[0].cnt}`);
console.log(`\n  Production templates by environment:`);
envBreakdown.forEach(e => console.log(`    ${e.targetEnvironment}: ${e.cnt}`));

await conn.end();
console.log("\nDone.");
