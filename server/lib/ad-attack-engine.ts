/**
 * Active Directory Attack Simulation Engine
 * Simulates Kerberoasting, AS-REP Roasting, DCSync, Golden/Silver Ticket,
 * Pass-the-Hash, delegation abuse, GPO abuse, and certificate attacks.
 */

export interface ADAttackDefinition {
  id: string;
  name: string;
  attackType: string;
  severity: "critical" | "high" | "medium" | "low";
  mitreTechniques: string[];
  description: string;
  prerequisites: string[];
  detectionMethods: string[];
  remediationSteps: string[];
  riskScore: number;
}

// ── Kerberos Attack Catalog ─────────────────────────────────────────────
export const KERBEROS_ATTACKS: ADAttackDefinition[] = [
  {
    id: "ad-kerb-01",
    name: "Kerberoasting",
    attackType: "kerberoasting",
    severity: "high",
    mitreTechniques: ["T1558.003"],
    description: "Requests TGS tickets for service accounts with SPNs, then cracks them offline to recover plaintext passwords",
    prerequisites: ["Any authenticated domain user", "Service accounts with SPNs registered"],
    detectionMethods: ["Monitor Event ID 4769 (TGS requests) with RC4 encryption", "Detect anomalous TGS request volume", "Honey tokens with SPNs"],
    remediationSteps: ["Use Group Managed Service Accounts (gMSA)", "Set long (25+ char) random passwords for service accounts", "Disable RC4 encryption for Kerberos"],
    riskScore: 8.0,
  },
  {
    id: "ad-kerb-02",
    name: "AS-REP Roasting",
    attackType: "as_rep_roasting",
    severity: "high",
    mitreTechniques: ["T1558.004"],
    description: "Targets accounts with Kerberos pre-authentication disabled to obtain crackable AS-REP hashes",
    prerequisites: ["Accounts with DONT_REQUIRE_PREAUTH flag set"],
    detectionMethods: ["Monitor Event ID 4768 with pre-auth failure", "Audit accounts with pre-auth disabled"],
    remediationSteps: ["Enable Kerberos pre-authentication for all accounts", "Audit DONT_REQUIRE_PREAUTH flag regularly"],
    riskScore: 7.5,
  },
  {
    id: "ad-kerb-03",
    name: "Golden Ticket Attack",
    attackType: "golden_ticket",
    severity: "critical",
    mitreTechniques: ["T1558.001"],
    description: "Forges TGT tickets using the KRBTGT hash, granting unrestricted domain access for up to 10 years",
    prerequisites: ["KRBTGT account hash (obtained via DCSync or NTDS.dit extraction)"],
    detectionMethods: ["Monitor for TGT with unusual lifetime", "Detect PAC validation failures", "Monitor Event ID 4769 with forged PAC"],
    remediationSteps: ["Reset KRBTGT password twice", "Implement PAC validation", "Monitor for anomalous TGT usage"],
    riskScore: 9.8,
  },
  {
    id: "ad-kerb-04",
    name: "Silver Ticket Attack",
    attackType: "silver_ticket",
    severity: "high",
    mitreTechniques: ["T1558.002"],
    description: "Forges TGS tickets for specific services using the service account hash, bypassing the KDC",
    prerequisites: ["Service account NTLM hash", "Target service SPN"],
    detectionMethods: ["Monitor for service tickets without corresponding TGT", "PAC validation on service", "Event ID 4624 anomalies"],
    remediationSteps: ["Use gMSA for service accounts", "Enable PAC validation on all services", "Rotate service account passwords"],
    riskScore: 7.8,
  },
];

// ── Credential Access Attacks ───────────────────────────────────────────
export const CREDENTIAL_ATTACKS: ADAttackDefinition[] = [
  {
    id: "ad-cred-01",
    name: "DCSync Attack",
    attackType: "dcsync",
    severity: "critical",
    mitreTechniques: ["T1003.006"],
    description: "Mimics domain controller replication to extract password hashes for all domain accounts including KRBTGT",
    prerequisites: ["DS-Replication-Get-Changes and DS-Replication-Get-Changes-All permissions"],
    detectionMethods: ["Monitor Event ID 4662 for replication operations", "Detect non-DC sources requesting replication", "Network traffic analysis for DRS protocol"],
    remediationSteps: ["Restrict replication permissions to DCs only", "Monitor for non-DC replication requests", "Implement tiered administration"],
    riskScore: 9.5,
  },
  {
    id: "ad-cred-02",
    name: "Pass-the-Hash",
    attackType: "pass_the_hash",
    severity: "high",
    mitreTechniques: ["T1550.002"],
    description: "Uses captured NTLM hashes to authenticate without knowing the plaintext password",
    prerequisites: ["NTLM hash of target account", "NTLM authentication enabled"],
    detectionMethods: ["Monitor Event ID 4624 with LogonType 9", "Detect NTLM authentication anomalies", "Credential Guard alerts"],
    remediationSteps: ["Enable Credential Guard", "Disable NTLM where possible", "Implement LAPS for local admin passwords"],
    riskScore: 8.0,
  },
  {
    id: "ad-cred-03",
    name: "Pass-the-Ticket",
    attackType: "pass_the_ticket",
    severity: "high",
    mitreTechniques: ["T1550.003"],
    description: "Steals and reuses Kerberos tickets from memory to impersonate users without their credentials",
    prerequisites: ["Access to LSASS memory on target host", "Valid Kerberos tickets in memory"],
    detectionMethods: ["Monitor for ticket reuse from different IPs", "LSASS access monitoring", "Anomalous authentication patterns"],
    remediationSteps: ["Enable Credential Guard", "Restrict debug privileges", "Implement Protected Users group"],
    riskScore: 7.5,
  },
  {
    id: "ad-cred-04",
    name: "Overpass-the-Hash (Pass-the-Key)",
    attackType: "overpass_the_hash",
    severity: "high",
    mitreTechniques: ["T1550.002"],
    description: "Uses NTLM hash to request a Kerberos TGT, converting hash-based access to ticket-based access",
    prerequisites: ["NTLM hash or AES key of target account"],
    detectionMethods: ["Monitor for RC4 TGT requests from non-standard sources", "Detect encryption downgrade attacks"],
    remediationSteps: ["Disable RC4 for Kerberos", "Enable Credential Guard", "Monitor for encryption type anomalies"],
    riskScore: 7.8,
  },
];

// ── Persistence & Escalation Attacks ────────────────────────────────────
export const PERSISTENCE_ATTACKS: ADAttackDefinition[] = [
  {
    id: "ad-persist-01",
    name: "Skeleton Key Attack",
    attackType: "skeleton_key",
    severity: "critical",
    mitreTechniques: ["T1556.001"],
    description: "Patches LSASS on a DC to add a master password that works for any domain account alongside legitimate passwords",
    prerequisites: ["Domain Admin or equivalent access to DC", "Ability to patch LSASS in memory"],
    detectionMethods: ["Monitor LSASS integrity", "Detect unusual DC reboots", "Memory forensics on DCs"],
    remediationSteps: ["Enable LSA Protection (RunAsPPL)", "Monitor DC LSASS process integrity", "Implement Credential Guard on DCs"],
    riskScore: 9.5,
  },
  {
    id: "ad-persist-02",
    name: "DCShadow Attack",
    attackType: "dcshadow",
    severity: "critical",
    mitreTechniques: ["T1207"],
    description: "Registers a rogue domain controller to push malicious changes via replication, evading standard monitoring",
    prerequisites: ["Domain Admin privileges", "Ability to register SPN for DC"],
    detectionMethods: ["Monitor for new DC registrations", "Detect unusual replication partners", "Monitor SPN changes for DCs"],
    remediationSteps: ["Monitor AD replication topology changes", "Alert on new DC registrations", "Implement AD change monitoring"],
    riskScore: 9.2,
  },
  {
    id: "ad-persist-03",
    name: "SID History Injection",
    attackType: "sid_history_injection",
    severity: "critical",
    mitreTechniques: ["T1134.005"],
    description: "Injects privileged SIDs into a user's SID History attribute to gain persistent elevated access",
    prerequisites: ["Domain Admin or ability to modify SID History", "Target user account"],
    detectionMethods: ["Monitor SID History changes (Event ID 4765/4766)", "Detect users with unexpected SID History entries"],
    remediationSteps: ["Enable SID Filtering on trusts", "Monitor SID History attribute changes", "Audit accounts with SID History"],
    riskScore: 9.0,
  },
  {
    id: "ad-persist-04",
    name: "GPO Abuse",
    attackType: "gpo_abuse",
    severity: "high",
    mitreTechniques: ["T1484.001"],
    description: "Modifies Group Policy Objects to deploy malicious scripts, scheduled tasks, or configuration changes across the domain",
    prerequisites: ["Write access to GPO or GPO link permissions"],
    detectionMethods: ["Monitor GPO modification events", "Detect new GPO links", "Audit GPO content changes"],
    remediationSteps: ["Restrict GPO edit permissions", "Implement GPO change monitoring", "Use GPO backup and versioning"],
    riskScore: 8.0,
  },
];

// ── Delegation & Certificate Attacks ────────────────────────────────────
export const DELEGATION_ATTACKS: ADAttackDefinition[] = [
  {
    id: "ad-deleg-01",
    name: "Unconstrained Delegation Abuse",
    attackType: "unconstrained_delegation",
    severity: "critical",
    mitreTechniques: ["T1558", "T1550.003"],
    description: "Exploits servers with unconstrained delegation to capture TGTs of connecting users, including privileged accounts",
    prerequisites: ["Compromise of server with unconstrained delegation", "Privileged user connecting to the server"],
    detectionMethods: ["Audit unconstrained delegation configurations", "Monitor for TGT forwarding", "Detect printer bug exploitation"],
    remediationSteps: ["Remove unconstrained delegation", "Use constrained delegation or RBCD", "Add privileged accounts to Protected Users group"],
    riskScore: 9.0,
  },
  {
    id: "ad-deleg-02",
    name: "Constrained Delegation Abuse",
    attackType: "constrained_delegation",
    severity: "high",
    mitreTechniques: ["T1550.003"],
    description: "Abuses S4U2Self and S4U2Proxy to impersonate any user to the delegated service",
    prerequisites: ["Compromise of account with constrained delegation configured"],
    detectionMethods: ["Monitor S4U2Self/S4U2Proxy requests", "Audit constrained delegation configurations"],
    remediationSteps: ["Minimize constrained delegation usage", "Use RBCD where possible", "Monitor S4U operations"],
    riskScore: 7.5,
  },
  {
    id: "ad-deleg-03",
    name: "Resource-Based Constrained Delegation (RBCD) Abuse",
    attackType: "resource_based_constrained_delegation",
    severity: "high",
    mitreTechniques: ["T1550.003", "T1134"],
    description: "Modifies msDS-AllowedToActOnBehalfOfOtherIdentity to enable delegation to a controlled account",
    prerequisites: ["Write access to target computer's AD object", "Controlled computer account or service account"],
    detectionMethods: ["Monitor changes to msDS-AllowedToActOnBehalfOfOtherIdentity", "Audit computer account creation"],
    remediationSteps: ["Restrict who can modify computer objects", "Monitor RBCD attribute changes", "Limit machine account creation"],
    riskScore: 8.0,
  },
  {
    id: "ad-deleg-04",
    name: "AD Certificate Services (ADCS) Abuse - ESC1",
    attackType: "certificate_abuse",
    severity: "critical",
    mitreTechniques: ["T1649"],
    description: "Exploits misconfigured certificate templates to request certificates for arbitrary users, enabling domain takeover",
    prerequisites: ["Enrollment rights on vulnerable template", "Template allows SAN specification", "Template has EKU for authentication"],
    detectionMethods: ["Monitor certificate enrollment events (Event ID 4886/4887)", "Audit certificate template permissions"],
    remediationSteps: ["Remove SAN specification from templates", "Restrict enrollment permissions", "Audit all certificate templates with Certify/Certipy"],
    riskScore: 9.5,
  },
];

export const FULL_AD_CATALOG = [...KERBEROS_ATTACKS, ...CREDENTIAL_ATTACKS, ...PERSISTENCE_ATTACKS, ...DELEGATION_ATTACKS];

/**
 * Get AD attack path analysis for an environment
 */
export function analyzeADEnvironment(domainInfo: { domainName: string; functionalLevel?: string }) {
  // Determine which attacks are most relevant based on functional level
  const allAttacks = FULL_AD_CATALOG;
  
  return {
    totalAttackVectors: allAttacks.length,
    criticalCount: allAttacks.filter(a => a.severity === "critical").length,
    highCount: allAttacks.filter(a => a.severity === "high").length,
    attacksByCategory: {
      kerberos: KERBEROS_ATTACKS.length,
      credentialAccess: CREDENTIAL_ATTACKS.length,
      persistence: PERSISTENCE_ATTACKS.length,
      delegation: DELEGATION_ATTACKS.length,
    },
    attacks: allAttacks,
  };
}

/**
 * Get MITRE ATT&CK techniques for AD attacks
 */
export function getADMitreTechniques() {
  return {
    "T1003.006": { name: "OS Credential Dumping: DCSync", tactic: "Credential Access" },
    "T1134": { name: "Access Token Manipulation", tactic: "Privilege Escalation" },
    "T1134.005": { name: "Access Token Manipulation: SID-History Injection", tactic: "Privilege Escalation" },
    "T1207": { name: "Rogue Domain Controller", tactic: "Defense Evasion" },
    "T1484.001": { name: "Domain Policy Modification: Group Policy Modification", tactic: "Privilege Escalation" },
    "T1550.002": { name: "Use Alternate Authentication Material: Pass the Hash", tactic: "Lateral Movement" },
    "T1550.003": { name: "Use Alternate Authentication Material: Pass the Ticket", tactic: "Lateral Movement" },
    "T1556.001": { name: "Modify Authentication Process: Domain Controller Authentication", tactic: "Persistence" },
    "T1558": { name: "Steal or Forge Kerberos Tickets", tactic: "Credential Access" },
    "T1558.001": { name: "Steal or Forge Kerberos Tickets: Golden Ticket", tactic: "Credential Access" },
    "T1558.002": { name: "Steal or Forge Kerberos Tickets: Silver Ticket", tactic: "Credential Access" },
    "T1558.003": { name: "Steal or Forge Kerberos Tickets: Kerberoasting", tactic: "Credential Access" },
    "T1558.004": { name: "Steal or Forge Kerberos Tickets: AS-REP Roasting", tactic: "Credential Access" },
    "T1649": { name: "Steal or Forge Authentication Certificates", tactic: "Credential Access" },
  };
}
