/**
 * Seed Client-Specific Engagement Bundles
 * 
 * Creates engagement bundles (campaign archetypes) that combine
 * attack templates, phishing templates, and Caldera adversary profiles
 * into one-click deployment packages for common client types.
 */
import mysql from "mysql2/promise";

const DATABASE_URL = process.env.DATABASE_URL || "mysql://root:password@localhost:3306/ac3";

const BUNDLES = [
  {
    slug: "msp-full-assessment",
    name: "MSP Full Assessment Package",
    archetypeCategory: "supply_chain",
    description: "Complete MSP assessment combining supply chain attacks, credential harvesting via phishing, AD compromise, and RMM tool abuse. Designed for Managed Service Providers with typical Windows AD + RMM + backup infrastructure.",
    killChainPhases: ["reconnaissance", "initial_access", "execution", "persistence", "privilege_escalation", "credential_access", "lateral_movement", "collection", "exfiltration"],
    defaultTechniques: ["T1199", "T1078", "T1059.001", "T1547.001", "T1068", "T1003.001", "T1021.001", "T1560", "T1048"],
    defaultAbilities: [],
    targetPlatforms: ["windows", "linux"],
    targetServices: ["Active Directory", "RMM Tools", "Backup Solutions", "VPN", "M365"],
    prerequisites: ["Network access", "Valid email addresses for phishing", "Target domain enumeration"],
    detectionGuidance: "Monitor RMM tool API calls, backup solution access patterns, unusual AD authentication from service accounts, and lateral movement via SMB/WinRM.",
    archetypeComplexity: "high",
    templateIds: "msp_network",
    phishingThemes: ["IT Support Alert", "RMM Update Required", "Backup Verification", "Password Expiry"],
    adversaryProfiles: ["APT29 (G0016)", "FIN7 (G0046)", "Scattered Spider"],
  },
  {
    slug: "healthcare-compliance-pentest",
    name: "Healthcare Compliance Assessment",
    archetypeCategory: "data_exfiltration",
    description: "HIPAA-focused assessment targeting healthcare networks with PHI exfiltration scenarios, medical IoT compromise, and EHR system access. Tests both IT and OT/IoT segments common in hospital environments.",
    killChainPhases: ["reconnaissance", "initial_access", "execution", "persistence", "lateral_movement", "collection", "exfiltration"],
    defaultTechniques: ["T1566.001", "T1059.001", "T1547.001", "T1021.001", "T1005", "T1048.002", "T1071.001"],
    defaultAbilities: [],
    targetPlatforms: ["windows", "linux", "iot"],
    targetServices: ["EHR Systems", "PACS/DICOM", "Medical IoT", "Active Directory", "VPN"],
    prerequisites: ["Network access to clinical segment", "Email addresses for clinical staff", "Understanding of EHR vendor"],
    detectionGuidance: "Monitor for unusual DICOM traffic, EHR database queries outside business hours, lateral movement between IT and clinical VLANs, and bulk PHI access patterns.",
    archetypeComplexity: "high",
    templateIds: "healthcare_network,healthcare_iot",
    phishingThemes: ["Patient Record Update", "HIPAA Training Required", "EHR System Maintenance", "Benefits Enrollment"],
    adversaryProfiles: ["APT41 (G0096)", "FIN12", "Lazarus Group (G0032)"],
  },
  {
    slug: "financial-apt-simulation",
    name: "Financial Services APT Simulation",
    archetypeCategory: "data_exfiltration",
    description: "Advanced persistent threat simulation targeting financial institutions. Covers SWIFT/payment system compromise, trading platform manipulation, and customer PII exfiltration. Aligned with FFIEC and PCI-DSS requirements.",
    killChainPhases: ["reconnaissance", "initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion", "credential_access", "lateral_movement", "collection", "exfiltration"],
    defaultTechniques: ["T1566.002", "T1059.001", "T1547.001", "T1068", "T1562.001", "T1003.001", "T1021.001", "T1005", "T1048.001"],
    defaultAbilities: [],
    targetPlatforms: ["windows", "linux"],
    targetServices: ["Core Banking", "SWIFT", "Trading Platforms", "Active Directory", "Payment Processing"],
    prerequisites: ["Network access", "Understanding of payment systems in use", "Employee email addresses"],
    detectionGuidance: "Monitor SWIFT message anomalies, unusual database queries on customer tables, privilege escalation on payment servers, and data staging in temp directories.",
    archetypeComplexity: "expert",
    templateIds: "financial_network,financial_pos",
    phishingThemes: ["Wire Transfer Confirmation", "Compliance Audit Notice", "Trading Platform Update", "Account Verification"],
    adversaryProfiles: ["APT38 (G0082)", "FIN6 (G0037)", "Carbanak (G0008)"],
  },
  {
    slug: "government-cui-assessment",
    name: "Government CUI Protection Assessment",
    archetypeCategory: "data_exfiltration",
    description: "CMMC/NIST 800-171 focused assessment targeting government contractor networks handling Controlled Unclassified Information (CUI). Tests boundary protections, access controls, and data loss prevention for CUI enclaves.",
    killChainPhases: ["reconnaissance", "initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion", "lateral_movement", "collection", "exfiltration"],
    defaultTechniques: ["T1566.001", "T1059.001", "T1547.001", "T1068", "T1562.004", "T1021.002", "T1005", "T1048.002"],
    defaultAbilities: [],
    targetPlatforms: ["windows", "linux"],
    targetServices: ["Active Directory", "File Servers", "VPN", "Email (GCC High)", "SharePoint"],
    prerequisites: ["Network access to CUI enclave boundary", "Understanding of CUI marking schema", "Employee directory"],
    detectionGuidance: "Monitor for CUI file access outside normal patterns, lateral movement between CUI and non-CUI segments, unusual VPN connections, and bulk file transfers from CUI repositories.",
    archetypeComplexity: "expert",
    templateIds: "government_network,government_dmz",
    phishingThemes: ["Security Clearance Renewal", "CMMC Assessment Notice", "IT Policy Update", "VPN Certificate Expiry"],
    adversaryProfiles: ["APT28 (G0007)", "APT29 (G0016)", "Turla (G0010)"],
  },
  {
    slug: "cloud-native-aws-assessment",
    name: "AWS Cloud-Native Assessment",
    archetypeCategory: "cloud_lateral_movement",
    description: "Comprehensive AWS cloud assessment covering IAM privilege escalation, cross-account lateral movement, serverless exploitation, and data exfiltration via S3/RDS. Targets organizations with cloud-first architecture.",
    killChainPhases: ["reconnaissance", "initial_access", "privilege_escalation", "defense_evasion", "credential_access", "lateral_movement", "collection", "exfiltration"],
    defaultTechniques: ["T1078.004", "T1098.001", "T1548", "T1562.008", "T1552.005", "T1580", "T1530", "T1537"],
    defaultAbilities: [],
    targetPlatforms: ["aws", "linux", "containers"],
    targetServices: ["AWS IAM", "S3", "RDS", "Lambda", "ECS/EKS", "CloudTrail", "VPC"],
    prerequisites: ["AWS account access (even read-only)", "Understanding of AWS org structure", "Target service endpoints"],
    detectionGuidance: "Monitor CloudTrail for IAM policy changes, unusual AssumeRole calls, S3 bucket policy modifications, Lambda function updates, and cross-account API calls.",
    archetypeComplexity: "high",
    templateIds: "aws_cloud",
    phishingThemes: ["AWS Security Alert", "IAM Policy Review", "Cost Optimization Report", "Compliance Scan Results"],
    adversaryProfiles: ["SCATTERED SPIDER", "TeamTNT", "APT29 (G0016)"],
  },
  {
    slug: "azure-m365-compromise",
    name: "Azure / M365 Tenant Compromise",
    archetypeCategory: "token_abuse",
    description: "Full Azure AD and Microsoft 365 tenant compromise assessment. Covers OAuth app consent phishing, token theft, mailbox delegation abuse, SharePoint data exfiltration, and Azure resource lateral movement.",
    killChainPhases: ["reconnaissance", "initial_access", "persistence", "privilege_escalation", "credential_access", "lateral_movement", "collection", "exfiltration"],
    defaultTechniques: ["T1566.002", "T1550.001", "T1098.003", "T1078.004", "T1528", "T1021.007", "T1114.002", "T1537"],
    defaultAbilities: [],
    targetPlatforms: ["azure", "windows", "m365"],
    targetServices: ["Azure AD", "Microsoft 365", "SharePoint", "Exchange Online", "Teams", "Azure Resources"],
    prerequisites: ["Target tenant domain", "Employee email addresses", "Understanding of Azure subscription structure"],
    detectionGuidance: "Monitor Azure AD sign-in logs for impossible travel, OAuth app consent events, mailbox delegation changes, bulk SharePoint downloads, and Azure resource creation in unusual regions.",
    archetypeComplexity: "high",
    templateIds: "azure_cloud,azure_m365",
    phishingThemes: ["M365 Password Expiry", "Teams Meeting Invite", "SharePoint Document Shared", "Azure Security Alert"],
    adversaryProfiles: ["Midnight Blizzard (APT29)", "Storm-0558", "DEV-0537 (LAPSUS$)"],
  },
  {
    slug: "ransomware-readiness",
    name: "Ransomware Readiness Assessment",
    archetypeCategory: "ransomware_deployment",
    description: "Simulates a full ransomware attack lifecycle from initial phishing through domain compromise to simulated encryption. Tests backup integrity, segmentation, and incident response capabilities without actual data destruction.",
    killChainPhases: ["initial_access", "execution", "persistence", "privilege_escalation", "credential_access", "lateral_movement", "impact"],
    defaultTechniques: ["T1566.001", "T1059.001", "T1547.001", "T1068", "T1003.001", "T1021.002", "T1486"],
    defaultAbilities: [],
    targetPlatforms: ["windows", "linux"],
    targetServices: ["Active Directory", "Backup Solutions", "File Servers", "Hypervisors", "Domain Controllers"],
    prerequisites: ["Network access", "Employee email addresses", "Understanding of backup architecture"],
    detectionGuidance: "Monitor for mass file enumeration, VSS deletion attempts, backup service disruption, GPO modifications for deployment, and unusual SMB traffic patterns indicating lateral spread.",
    archetypeComplexity: "expert",
    templateIds: "windows_ad",
    phishingThemes: ["Invoice Attached", "Resume/CV Submission", "Delivery Notification", "Voicemail Transcript"],
    adversaryProfiles: ["BlackByte (G1043)", "ALPHV/BlackCat", "LockBit", "Royal"],
  },
  {
    slug: "supply-chain-cicd",
    name: "Supply Chain / CI/CD Pipeline Attack",
    archetypeCategory: "supply_chain",
    description: "Targets software development pipelines and supply chain trust relationships. Covers source code repository compromise, build pipeline injection, artifact poisoning, and downstream customer impact assessment.",
    killChainPhases: ["reconnaissance", "initial_access", "execution", "persistence", "privilege_escalation", "lateral_movement", "impact"],
    defaultTechniques: ["T1195.002", "T1059.004", "T1554", "T1098.001", "T1021.004", "T1195.001"],
    defaultAbilities: [],
    targetPlatforms: ["linux", "containers", "cloud"],
    targetServices: ["GitHub/GitLab", "Jenkins/GitHub Actions", "Docker Registry", "Artifact Repository", "Kubernetes"],
    prerequisites: ["Access to development environment", "Understanding of CI/CD tooling", "Developer email addresses"],
    detectionGuidance: "Monitor for unauthorized pipeline modifications, unusual artifact pushes, secret scanning alerts, repository permission changes, and container image provenance violations.",
    archetypeComplexity: "expert",
    templateIds: "linux_cicd",
    phishingThemes: ["GitHub Security Alert", "NPM Package Vulnerability", "CI/CD Pipeline Failure", "Code Review Request"],
    adversaryProfiles: ["APT29 (G0016)", "Lazarus Group (G0032)", "UNC2452"],
  },
];

async function main() {
  const conn = await mysql.createConnection(DATABASE_URL);
  console.log("Connected to database");

  let inserted = 0;
  let skipped = 0;

  for (const bundle of BUNDLES) {
    // Check if slug already exists
    const [existing] = await conn.execute(
      "SELECT id FROM campaign_archetypes WHERE slug = ?",
      [bundle.slug]
    );
    if (existing.length > 0) {
      console.log(`  SKIP: ${bundle.slug} (already exists)`);
      skipped++;
      continue;
    }

    await conn.execute(
      `INSERT INTO campaign_archetypes (slug, name, archetypeCategory, description, killChainPhases, defaultTechniques, defaultAbilities, targetPlatforms, targetServices, prerequisites, detectionGuidance, archetypeComplexity, isBuiltIn)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
      [
        bundle.slug,
        bundle.name,
        bundle.archetypeCategory,
        bundle.description,
        JSON.stringify(bundle.killChainPhases),
        JSON.stringify(bundle.defaultTechniques),
        JSON.stringify(bundle.defaultAbilities),
        JSON.stringify(bundle.targetPlatforms),
        JSON.stringify(bundle.targetServices),
        JSON.stringify(bundle.prerequisites),
        bundle.detectionGuidance,
        bundle.archetypeComplexity,
      ]
    );
    console.log(`  INSERT: ${bundle.name}`);
    inserted++;
  }

  console.log(`\n=== Done: ${inserted} inserted, ${skipped} skipped ===`);
  await conn.end();
}

main().catch(console.error);
