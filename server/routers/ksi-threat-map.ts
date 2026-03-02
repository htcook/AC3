import * as db from "../db";
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb as _getDb } from "../db";
import {
  ksiDefinitions,
  threatActors,
  threatActorAbilities,
  unifiedExploitCatalog,
  atomicTests,
} from "../../drizzle/schema";
import { eq, desc, sql, and, like, inArray, isNotNull, count } from "drizzle-orm";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

// ─── KSI-to-MITRE ATT&CK Technique Mapping ──────────────────────────────────
// Maps each KSI to the MITRE ATT&CK techniques it defends against

interface KsiTtpMapping {
  ksiId: string;
  techniques: { id: string; name: string; tactic: string }[];
  description: string;
}

const KSI_TTP_CATALOG: KsiTtpMapping[] = [
  // ── Vulnerability Scanning & Remediation ──
  { ksiId: "KSI-SVC-VSR", techniques: [
    { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
    { id: "T1210", name: "Exploitation of Remote Services", tactic: "Lateral Movement" },
    { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
    { id: "T1211", name: "Exploitation for Defense Evasion", tactic: "Defense Evasion" },
    { id: "T1212", name: "Exploitation for Credential Access", tactic: "Credential Access" },
  ], description: "Vulnerability scanning detects exploitable weaknesses that threat actors use for initial access and lateral movement" },
  { ksiId: "KSI-SVC-VRM", techniques: [
    { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
    { id: "T1210", name: "Exploitation of Remote Services", tactic: "Lateral Movement" },
    { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
  ], description: "Vulnerability remediation closes attack vectors before threat actors can exploit them" },

  // ── Identity & Access Management ──
  { ksiId: "KSI-IAM-MFA", techniques: [
    { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" },
    { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
    { id: "T1556", name: "Modify Authentication Process", tactic: "Credential Access" },
    { id: "T1621", name: "Multi-Factor Authentication Request Generation", tactic: "Credential Access" },
    { id: "T1528", name: "Steal Application Access Token", tactic: "Credential Access" },
  ], description: "MFA enforcement prevents credential-based attacks including brute force and token theft" },
  { ksiId: "KSI-IAM-AAM", techniques: [
    { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" },
    { id: "T1098", name: "Account Manipulation", tactic: "Persistence" },
    { id: "T1136", name: "Create Account", tactic: "Persistence" },
    { id: "T1087", name: "Account Discovery", tactic: "Discovery" },
  ], description: "Account and access management prevents unauthorized persistence and privilege abuse" },
  { ksiId: "KSI-IAM-PRA", techniques: [
    { id: "T1078.002", name: "Valid Accounts: Domain Accounts", tactic: "Defense Evasion" },
    { id: "T1098", name: "Account Manipulation", tactic: "Persistence" },
    { id: "T1078.004", name: "Valid Accounts: Cloud Accounts", tactic: "Defense Evasion" },
    { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  ], description: "Privileged access management limits lateral movement and privilege escalation paths" },

  // ── Monitoring, Logging, Auditing ──
  { ksiId: "KSI-MLA-LET", techniques: [
    { id: "T1070", name: "Indicator Removal", tactic: "Defense Evasion" },
    { id: "T1562", name: "Impair Defenses", tactic: "Defense Evasion" },
    { id: "T1070.001", name: "Clear Windows Event Logs", tactic: "Defense Evasion" },
  ], description: "Log enforcement and tamper-resistance prevents adversaries from covering their tracks" },
  { ksiId: "KSI-MLA-OSM", techniques: [
    { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" },
    { id: "T1573", name: "Encrypted Channel", tactic: "Command and Control" },
    { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration" },
    { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
  ], description: "Operational security monitoring detects C2 communications and data exfiltration" },
  { ksiId: "KSI-MLA-ALE", techniques: [
    { id: "T1562.001", name: "Disable or Modify Tools", tactic: "Defense Evasion" },
    { id: "T1562.002", name: "Disable Windows Event Logging", tactic: "Defense Evasion" },
    { id: "T1070", name: "Indicator Removal", tactic: "Defense Evasion" },
  ], description: "Alert and event management ensures detection capabilities remain operational" },

  // ── Cloud Native Architecture ──
  { ksiId: "KSI-CNA-HCI", techniques: [
    { id: "T1610", name: "Deploy Container", tactic: "Defense Evasion" },
    { id: "T1611", name: "Escape to Host", tactic: "Privilege Escalation" },
    { id: "T1525", name: "Implant Internal Image", tactic: "Persistence" },
    { id: "T1613", name: "Container and Resource Discovery", tactic: "Discovery" },
  ], description: "Hardened container images prevent supply chain attacks and container escape" },
  { ksiId: "KSI-CNA-EDE", techniques: [
    { id: "T1557", name: "Adversary-in-the-Middle", tactic: "Credential Access" },
    { id: "T1040", name: "Network Sniffing", tactic: "Credential Access" },
    { id: "T1552", name: "Unsecured Credentials", tactic: "Credential Access" },
    { id: "T1588.004", name: "Obtain Capabilities: Digital Certificates", tactic: "Resource Development" },
  ], description: "Encryption of data in transit and at rest prevents interception and credential theft" },
  { ksiId: "KSI-CNA-NSD", techniques: [
    { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" },
    { id: "T1021", name: "Remote Services", tactic: "Lateral Movement" },
    { id: "T1570", name: "Lateral Tool Transfer", tactic: "Lateral Movement" },
    { id: "T1090", name: "Proxy", tactic: "Command and Control" },
  ], description: "Network segmentation and defense limits lateral movement and service discovery" },

  // ── Incident Response ──
  { ksiId: "KSI-INR-IRP", techniques: [
    { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
    { id: "T1485", name: "Data Destruction", tactic: "Impact" },
    { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact" },
  ], description: "Incident response planning prepares for destructive attacks including ransomware" },
  { ksiId: "KSI-INR-TIF", techniques: [
    { id: "T1595", name: "Active Scanning", tactic: "Reconnaissance" },
    { id: "T1592", name: "Gather Victim Host Information", tactic: "Reconnaissance" },
    { id: "T1589", name: "Gather Victim Identity Information", tactic: "Reconnaissance" },
    { id: "T1590", name: "Gather Victim Network Information", tactic: "Reconnaissance" },
  ], description: "Threat intelligence feeds detect reconnaissance and pre-attack activity" },
  { ksiId: "KSI-INR-TIU", techniques: [
    { id: "T1595", name: "Active Scanning", tactic: "Reconnaissance" },
    { id: "T1583", name: "Acquire Infrastructure", tactic: "Resource Development" },
    { id: "T1588", name: "Obtain Capabilities", tactic: "Resource Development" },
  ], description: "Threat intelligence utilization informs defensive posture against known adversary infrastructure" },
  { ksiId: "KSI-INR-IOC", techniques: [
    { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" },
    { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control" },
    { id: "T1204", name: "User Execution", tactic: "Execution" },
    { id: "T1566", name: "Phishing", tactic: "Initial Access" },
  ], description: "IOC management enables detection of known malicious indicators across the kill chain" },

  // ── Security Assessments ──
  { ksiId: "KSI-SCR-PEN", techniques: [
    { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
    { id: "T1133", name: "External Remote Services", tactic: "Initial Access" },
    { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" },
  ], description: "Penetration testing validates defenses against real-world attack techniques" },
  { ksiId: "KSI-SCR-APT", techniques: [
    { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
    { id: "T1053", name: "Scheduled Task/Job", tactic: "Execution" },
    { id: "T1547", name: "Boot or Logon Autostart Execution", tactic: "Persistence" },
    { id: "T1543", name: "Create or Modify System Process", tactic: "Persistence" },
  ], description: "APT emulation tests detection and response against advanced persistent threat TTPs" },
  { ksiId: "KSI-SCR-SAT", techniques: [
    { id: "T1566", name: "Phishing", tactic: "Initial Access" },
    { id: "T1566.001", name: "Spearphishing Attachment", tactic: "Initial Access" },
    { id: "T1566.002", name: "Spearphishing Link", tactic: "Initial Access" },
    { id: "T1598", name: "Phishing for Information", tactic: "Reconnaissance" },
  ], description: "Security awareness training reduces susceptibility to social engineering attacks" },

  // ── Secure Development ──
  { ksiId: "KSI-SDE-SST", techniques: [
    { id: "T1195", name: "Supply Chain Compromise", tactic: "Initial Access" },
    { id: "T1195.002", name: "Compromise Software Supply Chain", tactic: "Initial Access" },
    { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
  ], description: "Secure software testing prevents supply chain compromise and code injection" },
  { ksiId: "KSI-SDE-SDP", techniques: [
    { id: "T1195", name: "Supply Chain Compromise", tactic: "Initial Access" },
    { id: "T1072", name: "Software Deployment Tools", tactic: "Execution" },
  ], description: "Secure development practices prevent introduction of vulnerabilities in the SDLC" },

  // ── Change Management ──
  { ksiId: "KSI-CMT-CMG", techniques: [
    { id: "T1072", name: "Software Deployment Tools", tactic: "Execution" },
    { id: "T1195", name: "Supply Chain Compromise", tactic: "Initial Access" },
    { id: "T1543", name: "Create or Modify System Process", tactic: "Persistence" },
  ], description: "Change management controls prevent unauthorized modifications and supply chain attacks" },

  // ── Policy & Procedure ──
  { ksiId: "KSI-PPM-PPR", techniques: [
    { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" },
    { id: "T1098", name: "Account Manipulation", tactic: "Persistence" },
  ], description: "Policy and procedure reviews ensure security controls remain effective against evolving threats" },
  { ksiId: "KSI-PPM-PPI", techniques: [
    { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" },
    { id: "T1136", name: "Create Account", tactic: "Persistence" },
  ], description: "Policy implementation enforcement ensures security controls are consistently applied" },

  // ── Authorization by FedRAMP ──
  { ksiId: "KSI-AFR-PVA", techniques: [
    { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
    { id: "T1210", name: "Exploitation of Remote Services", tactic: "Lateral Movement" },
  ], description: "Periodic vulnerability assessments identify exploitable weaknesses on a recurring basis" },
  { ksiId: "KSI-AFR-SCG", techniques: [
    { id: "T1562", name: "Impair Defenses", tactic: "Defense Evasion" },
    { id: "T1543", name: "Create or Modify System Process", tactic: "Persistence" },
  ], description: "Secure configuration guides harden systems against defense evasion and persistence" },
  { ksiId: "KSI-AFR-MAS", techniques: [
    { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" },
    { id: "T1018", name: "Remote System Discovery", tactic: "Discovery" },
  ], description: "Minimum assessment scope ensures all assets are covered by security testing" },
];

// ─── Threat Group-to-KSI Mapping ─────────────────────────────────────────────
// Maps major threat groups to the KSIs that defend against their known TTPs

interface ThreatGroupKsiMapping {
  groupId: string;
  groupName: string;
  origin: string;
  type: string;
  ksiIds: string[];
  primaryTechniques: string[];
}

const THREAT_GROUP_KSI_MAP: ThreatGroupKsiMapping[] = [
  { groupId: "apt29", groupName: "APT29 (Cozy Bear)", origin: "Russia", type: "apt",
    ksiIds: ["KSI-IAM-MFA", "KSI-IAM-AAM", "KSI-IAM-PRA", "KSI-MLA-LET", "KSI-MLA-OSM", "KSI-CNA-EDE", "KSI-INR-TIF", "KSI-SCR-APT"],
    primaryTechniques: ["T1078", "T1556", "T1621", "T1071", "T1573", "T1557"] },
  { groupId: "apt28", groupName: "APT28 (Fancy Bear)", origin: "Russia", type: "apt",
    ksiIds: ["KSI-SVC-VSR", "KSI-SCR-SAT", "KSI-IAM-MFA", "KSI-MLA-OSM", "KSI-INR-IOC", "KSI-SCR-PEN"],
    primaryTechniques: ["T1190", "T1566", "T1110", "T1071", "T1105"] },
  { groupId: "apt41", groupName: "APT41 (Double Dragon)", origin: "China", type: "apt",
    ksiIds: ["KSI-SVC-VSR", "KSI-SDE-SST", "KSI-CNA-HCI", "KSI-MLA-LET", "KSI-SCR-APT", "KSI-INR-TIF"],
    primaryTechniques: ["T1190", "T1195", "T1059", "T1070", "T1610"] },
  { groupId: "lazarus", groupName: "Lazarus Group", origin: "North Korea", type: "apt",
    ksiIds: ["KSI-SVC-VSR", "KSI-SDE-SST", "KSI-SCR-SAT", "KSI-INR-IOC", "KSI-MLA-OSM", "KSI-CNA-EDE"],
    primaryTechniques: ["T1190", "T1195", "T1566", "T1486", "T1573"] },
  { groupId: "fin7", groupName: "FIN7 (Carbanak)", origin: "Russia", type: "cybercrime",
    ksiIds: ["KSI-SCR-SAT", "KSI-MLA-ALE", "KSI-IAM-MFA", "KSI-INR-IOC", "KSI-SCR-PEN"],
    primaryTechniques: ["T1566", "T1204", "T1059", "T1078", "T1105"] },
  { groupId: "sandworm", groupName: "Sandworm Team", origin: "Russia", type: "apt",
    ksiIds: ["KSI-SVC-VSR", "KSI-CNA-NSD", "KSI-INR-IRP", "KSI-MLA-LET", "KSI-SCR-APT", "KSI-CMT-CMG"],
    primaryTechniques: ["T1190", "T1486", "T1485", "T1490", "T1070"] },
  { groupId: "turla", groupName: "Turla (Snake)", origin: "Russia", type: "apt",
    ksiIds: ["KSI-MLA-OSM", "KSI-CNA-EDE", "KSI-IAM-PRA", "KSI-MLA-LET", "KSI-INR-TIF", "KSI-SCR-APT"],
    primaryTechniques: ["T1071", "T1573", "T1090", "T1078", "T1070"] },
  { groupId: "apt40", groupName: "APT40 (Leviathan)", origin: "China", type: "apt",
    ksiIds: ["KSI-SVC-VSR", "KSI-SCR-SAT", "KSI-CNA-NSD", "KSI-MLA-OSM", "KSI-INR-IOC"],
    primaryTechniques: ["T1190", "T1566", "T1021", "T1071", "T1046"] },
  { groupId: "kimsuky", groupName: "Kimsuky", origin: "North Korea", type: "apt",
    ksiIds: ["KSI-SCR-SAT", "KSI-IAM-MFA", "KSI-INR-IOC", "KSI-MLA-ALE", "KSI-INR-TIF"],
    primaryTechniques: ["T1566", "T1598", "T1110", "T1204", "T1105"] },
  { groupId: "lockbit", groupName: "LockBit", origin: "Russia", type: "ransomware",
    ksiIds: ["KSI-SVC-VSR", "KSI-IAM-MFA", "KSI-IAM-PRA", "KSI-INR-IRP", "KSI-MLA-ALE", "KSI-CNA-EDE"],
    primaryTechniques: ["T1190", "T1078", "T1486", "T1490", "T1548"] },
  { groupId: "alphv", groupName: "ALPHV (BlackCat)", origin: "Russia", type: "ransomware",
    ksiIds: ["KSI-SVC-VSR", "KSI-IAM-MFA", "KSI-IAM-AAM", "KSI-INR-IRP", "KSI-CNA-EDE", "KSI-MLA-LET"],
    primaryTechniques: ["T1190", "T1078", "T1486", "T1070", "T1552"] },
  { groupId: "clop", groupName: "Cl0p", origin: "Russia", type: "ransomware",
    ksiIds: ["KSI-SVC-VSR", "KSI-SDE-SST", "KSI-INR-IRP", "KSI-CNA-EDE", "KSI-MLA-OSM"],
    primaryTechniques: ["T1190", "T1195", "T1486", "T1048", "T1041"] },
  { groupId: "volt-typhoon", groupName: "Volt Typhoon", origin: "China", type: "apt",
    ksiIds: ["KSI-MLA-LET", "KSI-MLA-OSM", "KSI-CNA-NSD", "KSI-IAM-PRA", "KSI-INR-TIF", "KSI-SCR-APT"],
    primaryTechniques: ["T1078", "T1021", "T1070", "T1090", "T1046"] },
  { groupId: "scattered-spider", groupName: "Scattered Spider", origin: "US/UK", type: "cybercrime",
    ksiIds: ["KSI-IAM-MFA", "KSI-SCR-SAT", "KSI-IAM-AAM", "KSI-MLA-ALE", "KSI-INR-IOC"],
    primaryTechniques: ["T1621", "T1566", "T1078", "T1136", "T1098"] },
  { groupId: "muddywater", groupName: "MuddyWater", origin: "Iran", type: "apt",
    ksiIds: ["KSI-SCR-SAT", "KSI-SVC-VSR", "KSI-MLA-OSM", "KSI-INR-IOC", "KSI-INR-TIF"],
    primaryTechniques: ["T1566", "T1190", "T1059", "T1071", "T1105"] },
  { groupId: "charming-kitten", groupName: "Charming Kitten (APT35)", origin: "Iran", type: "apt",
    ksiIds: ["KSI-SCR-SAT", "KSI-IAM-MFA", "KSI-INR-IOC", "KSI-INR-TIF", "KSI-MLA-ALE"],
    primaryTechniques: ["T1566", "T1598", "T1528", "T1078", "T1204"] },
];

// ─── Router ───────────────────────────────────────────────────────────────────

export const ksiThreatMapRouter = router({

  /** Get the full KSI-to-TTP mapping catalog */
  getTtpMappings: protectedProcedure
    .input(z.object({ ksiId: z.string().optional() }).optional())
    .query(({ input }) => {
      if (input?.ksiId) {
        const mapping = KSI_TTP_CATALOG.find(m => m.ksiId === input.ksiId);
        return mapping ? [mapping] : [];
      }
      return KSI_TTP_CATALOG;
    }),

  /** Get the threat group-to-KSI mapping catalog */
  getThreatGroupMappings: protectedProcedure
    .input(z.object({ groupId: z.string().optional() }).optional())
    .query(({ input }) => {
      if (input?.groupId) {
        const mapping = THREAT_GROUP_KSI_MAP.find(m => m.groupId === input.groupId);
        return mapping ? [mapping] : [];
      }
      return THREAT_GROUP_KSI_MAP;
    }),

  /** Get threat coverage analysis — which KSIs defend against which threat groups */
  getThreatCoverageMatrix: protectedProcedure.query(async () => {
    const db = await getDbSafe();

    // Get KSI definitions from DB (or fallback to catalog)
    const defs = await db.select().from(ksiDefinitions);

    // Build matrix: for each KSI, list which threat groups it defends against
    const matrix = KSI_TTP_CATALOG.map(ttpMap => {
      const def = defs.find(d => d.ksiId === ttpMap.ksiId);
      const threatGroups = THREAT_GROUP_KSI_MAP.filter(g => g.ksiIds.includes(ttpMap.ksiId));
      return {
        ksiId: ttpMap.ksiId,
        ksiTitle: def?.title || ttpMap.ksiId,
        themeCode: def?.themeCode || "UNK",
        techniqueCount: ttpMap.techniques.length,
        techniques: ttpMap.techniques,
        threatGroupCount: threatGroups.length,
        threatGroups: threatGroups.map(g => ({
          groupId: g.groupId,
          groupName: g.groupName,
          origin: g.origin,
          type: g.type,
        })),
        coverageStatus: def?.coverageStatus || "planned",
      };
    });

    // Summary stats
    const totalKsisWithTtps = matrix.length;
    const totalTechniques = new Set(KSI_TTP_CATALOG.flatMap(m => m.techniques.map(t => t.id))).size;
    const totalThreatGroups = THREAT_GROUP_KSI_MAP.length;

    // Tactic distribution
    const tacticCounts: Record<string, number> = {};
    for (const m of KSI_TTP_CATALOG) {
      for (const t of m.techniques) {
        tacticCounts[t.tactic] = (tacticCounts[t.tactic] || 0) + 1;
      }
    }

    return {
      matrix,
      summary: {
        totalKsisWithTtps,
        totalTechniques,
        totalThreatGroups,
        tacticDistribution: Object.entries(tacticCounts).map(([tactic, count]) => ({ tactic, count })).sort((a, b) => b.count - a.count),
      },
    };
  }),

  /** Match exploits from the unified catalog to a specific KSI */
  getExploitsForKsi: protectedProcedure
    .input(z.object({ ksiId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();

      // Find the TTP mapping for this KSI
      const ttpMapping = KSI_TTP_CATALOG.find(m => m.ksiId === input.ksiId);
      if (!ttpMapping) return { exploits: [], atomicTests: [], totalExploits: 0, totalAtomicTests: 0 };

      const techniqueIds = ttpMapping.techniques.map(t => t.id);

      // Find exploits that match these MITRE techniques
      const matchedExploits = await db.select({
        id: unifiedExploitCatalog.id,
        catalogId: unifiedExploitCatalog.catalogId,
        name: unifiedExploitCatalog.name,
        description: unifiedExploitCatalog.description,
        tier: unifiedExploitCatalog.tier,
        category: unifiedExploitCatalog.category,
        source: unifiedExploitCatalog.source,
        cveIds: unifiedExploitCatalog.cveIds,
        cvssScore: unifiedExploitCatalog.cvssScore,
        severity: unifiedExploitCatalog.severity,
        mitreId: unifiedExploitCatalog.mitreId,
        mitreName: unifiedExploitCatalog.mitreName,
        mitreTactic: unifiedExploitCatalog.mitreTactic,
        platform: unifiedExploitCatalog.platform,
        exploitType: unifiedExploitCatalog.exploitType,
        reliability: unifiedExploitCatalog.reliability,
        difficulty: unifiedExploitCatalog.difficulty,
        msfModule: unifiedExploitCatalog.msfModule,
        verified: unifiedExploitCatalog.verified,
        enabled: unifiedExploitCatalog.enabled,
      }).from(unifiedExploitCatalog)
        .where(inArray(unifiedExploitCatalog.mitreId, techniqueIds))
        .orderBy(desc(unifiedExploitCatalog.cvssScore))
        .limit(50);

      // Find Atomic Red Team tests that match these techniques
      const matchedAtomicTests = await db.select({
        id: atomicTests.id,
        guid: atomicTests.guid,
        techniqueId: atomicTests.techniqueId,
        techniqueName: atomicTests.techniqueName,
        testName: atomicTests.testName,
        description: atomicTests.description,
        supportedPlatforms: atomicTests.supportedPlatforms,
        executorType: atomicTests.executorType,
        elevationRequired: atomicTests.elevationRequired,
        mitreTactic: atomicTests.mitreTactic,
      }).from(atomicTests)
        .where(inArray(atomicTests.techniqueId, techniqueIds))
        .limit(50);

      return {
        ksiId: input.ksiId,
        techniques: ttpMapping.techniques,
        exploits: matchedExploits,
        atomicTests: matchedAtomicTests,
        totalExploits: matchedExploits.length,
        totalAtomicTests: matchedAtomicTests.length,
      };
    }),

  /** Get exploit coverage summary across all KSIs */
  getExploitCoverageSummary: protectedProcedure.query(async () => {
    const db = await getDbSafe();

    // Count total exploits with MITRE mappings
    const totalExploits = await db.select({ count: count() }).from(unifiedExploitCatalog)
      .where(isNotNull(unifiedExploitCatalog.mitreId));

    // Count total atomic tests
    const totalAtomicTests = await db.select({ count: count() }).from(atomicTests);

    // Get all unique MITRE technique IDs from KSI catalog
    const allKsiTechniques = new Set(KSI_TTP_CATALOG.flatMap(m => m.techniques.map(t => t.id)));

    // Count exploits per technique
    const exploitsByTechnique = await db.select({
      mitreId: unifiedExploitCatalog.mitreId,
      count: count(),
    }).from(unifiedExploitCatalog)
      .where(isNotNull(unifiedExploitCatalog.mitreId))
      .groupBy(unifiedExploitCatalog.mitreId);

    // Count atomic tests per technique
    const atomicsByTechnique = await db.select({
      techniqueId: atomicTests.techniqueId,
      count: count(),
    }).from(atomicTests)
      .groupBy(atomicTests.techniqueId);

    // Build per-KSI exploit availability
    const ksiExploitCoverage = KSI_TTP_CATALOG.map(ttpMap => {
      const techniqueIds = ttpMap.techniques.map(t => t.id);
      const exploitCount = exploitsByTechnique
        .filter(e => e.mitreId && techniqueIds.includes(e.mitreId))
        .reduce((sum, e) => sum + (e.count || 0), 0);
      const atomicCount = atomicsByTechnique
        .filter(a => techniqueIds.includes(a.techniqueId))
        .reduce((sum, a) => sum + (a.count || 0), 0);
      return {
        ksiId: ttpMap.ksiId,
        techniqueCount: ttpMap.techniques.length,
        exploitCount,
        atomicTestCount: atomicCount,
        hasValidationTools: exploitCount > 0 || atomicCount > 0,
      };
    });

    return {
      totalExploitsWithMitre: totalExploits[0]?.count || 0,
      totalAtomicTests: totalAtomicTests[0]?.count || 0,
      totalKsiTechniques: allKsiTechniques.size,
      ksiExploitCoverage,
      ksisWithExploits: ksiExploitCoverage.filter(k => k.hasValidationTools).length,
      ksisWithoutExploits: ksiExploitCoverage.filter(k => !k.hasValidationTools).length,
    };
  }),

  /** Cross-reference with live threat actor data from the database */
  getLiveThreatActorCrossRef: protectedProcedure
    .input(z.object({ ksiId: z.string() }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();

      // Get threat actors from DB with their techniques
      const actors = await db.select({
        actorId: threatActors.actorId,
        name: threatActors.name,
        type: threatActors.type,
        origin: threatActors.origin,
        threatLevel: threatActors.threatLevel,
        sophistication: threatActors.sophistication,
        techniques: threatActors.techniques,
        tools: threatActors.tools,
        malware: threatActors.malware,
      }).from(threatActors)
        .where(and(
          isNotNull(threatActors.techniques),
          inArray(threatActors.threatLevel, ["critical", "high"]),
        ))
        .orderBy(desc(threatActors.updatedAt))
        .limit(100);

      // If filtering by KSI, find which techniques that KSI covers
      const targetTechniques = input?.ksiId
        ? KSI_TTP_CATALOG.find(m => m.ksiId === input.ksiId)?.techniques.map(t => t.id) || []
        : KSI_TTP_CATALOG.flatMap(m => m.techniques.map(t => t.id));

      const targetTechniqueSet = new Set(targetTechniques);

      // Cross-reference actors with KSI techniques
      const crossRef = actors.map(actor => {
        const actorTechniques = Array.isArray(actor.techniques) ? actor.techniques as any[] : [];
        const matchingTechniques = actorTechniques.filter((t: any) =>
          targetTechniqueSet.has(t.id || t.techniqueId || "")
        );
        return {
          actorId: actor.actorId,
          name: actor.name,
          type: actor.type,
          origin: actor.origin,
          threatLevel: actor.threatLevel,
          sophistication: actor.sophistication,
          totalTechniques: actorTechniques.length,
          matchingTechniqueCount: matchingTechniques.length,
          matchingTechniques: matchingTechniques.slice(0, 10).map((t: any) => ({
            id: t.id || t.techniqueId,
            name: t.name || t.techniqueName,
          })),
          toolCount: Array.isArray(actor.tools) ? actor.tools.length : 0,
          malwareCount: Array.isArray(actor.malware) ? actor.malware.length : 0,
          relevanceScore: matchingTechniques.length / Math.max(actorTechniques.length, 1),
        };
      }).filter(a => a.matchingTechniqueCount > 0)
        .sort((a, b) => b.relevanceScore - a.relevanceScore);

      return {
        ksiId: input?.ksiId || "all",
        totalActorsAnalyzed: actors.length,
        matchingActors: crossRef.length,
        actors: crossRef,
      };
    }),

  /** Get a comprehensive threat-informed defense report for a specific KSI */
  getKsiThreatReport: protectedProcedure
    .input(z.object({ ksiId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();

      const ttpMapping = KSI_TTP_CATALOG.find(m => m.ksiId === input.ksiId);
      const threatGroups = THREAT_GROUP_KSI_MAP.filter(g => g.ksiIds.includes(input.ksiId));
      const def = await db.select().from(ksiDefinitions).where(eq(ksiDefinitions.ksiId, input.ksiId)).limit(1);

      if (!ttpMapping) {
        return {
          ksiId: input.ksiId,
          ksiTitle: def[0]?.title || input.ksiId,
          hasTtpMapping: false,
          techniques: [],
          threatGroups: [],
          exploitCount: 0,
          atomicTestCount: 0,
          riskScore: 0,
        };
      }

      const techniqueIds = ttpMapping.techniques.map(t => t.id);

      // Count matching exploits
      const exploitCount = await db.select({ count: count() }).from(unifiedExploitCatalog)
        .where(inArray(unifiedExploitCatalog.mitreId, techniqueIds));

      // Count matching atomic tests
      const atomicCount = await db.select({ count: count() }).from(atomicTests)
        .where(inArray(atomicTests.techniqueId, techniqueIds));

      // Calculate risk score based on threat group count and technique coverage
      const riskScore = Math.min(100, (threatGroups.length * 15) + (ttpMapping.techniques.length * 10));

      return {
        ksiId: input.ksiId,
        ksiTitle: def[0]?.title || input.ksiId,
        themeCode: def[0]?.themeCode || "UNK",
        coverageStatus: def[0]?.coverageStatus || "planned",
        hasTtpMapping: true,
        description: ttpMapping.description,
        techniques: ttpMapping.techniques,
        threatGroups: threatGroups.map(g => ({
          groupId: g.groupId,
          groupName: g.groupName,
          origin: g.origin,
          type: g.type,
          overlappingTechniques: g.primaryTechniques.filter(t => techniqueIds.includes(t)),
        })),
        exploitCount: exploitCount[0]?.count || 0,
        atomicTestCount: atomicCount[0]?.count || 0,
        riskScore,
        validationReady: (exploitCount[0]?.count || 0) > 0 || (atomicCount[0]?.count || 0) > 0,
      };
    }),
});
