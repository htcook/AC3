// @ts-nocheck
/**
 * Attack Vector Identification Engine
 *
 * Cross-references OSINT findings, dark web intel, vuln scans, web app findings,
 * exploit catalogs, and threat actor TTPs to automatically identify and score
 * attack vectors. Integrates into pre-exploitation workflows.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import crypto from "crypto";

function generateId() { return crypto.randomUUID(); }

// ── MITRE ATT&CK Kill Chain Phases ──────────────────────────────────────────
const KILL_CHAIN_PHASES = [
  { id: "reconnaissance", name: "Reconnaissance", order: 1, preExploit: true },
  { id: "resource_development", name: "Resource Development", order: 2, preExploit: true },
  { id: "initial_access", name: "Initial Access", order: 3, preExploit: false },
  { id: "execution", name: "Execution", order: 4, preExploit: false },
  { id: "persistence", name: "Persistence", order: 5, preExploit: false },
  { id: "privilege_escalation", name: "Privilege Escalation", order: 6, preExploit: false },
  { id: "defense_evasion", name: "Defense Evasion", order: 7, preExploit: false },
  { id: "credential_access", name: "Credential Access", order: 8, preExploit: false },
  { id: "discovery", name: "Discovery", order: 9, preExploit: false },
  { id: "lateral_movement", name: "Lateral Movement", order: 10, preExploit: false },
  { id: "collection", name: "Collection", order: 11, preExploit: false },
  { id: "command_and_control", name: "Command and Control", order: 12, preExploit: false },
  { id: "exfiltration", name: "Exfiltration", order: 13, preExploit: false },
  { id: "impact", name: "Impact", order: 14, preExploit: false },
] as const;

// ── Vector Type → Technique Mapping ─────────────────────────────────────────
const VECTOR_TECHNIQUE_MAP: Record<string, { techniques: string[]; killChain: string; baseScore: number }> = {
  initial_access: {
    techniques: ["T1190", "T1133", "T1078", "T1189", "T1566", "T1195"],
    killChain: "initial_access",
    baseScore: 7.0,
  },
  credential_compromise: {
    techniques: ["T1110", "T1003", "T1558", "T1552", "T1555", "T1528"],
    killChain: "credential_access",
    baseScore: 8.0,
  },
  supply_chain: {
    techniques: ["T1195.001", "T1195.002", "T1199"],
    killChain: "initial_access",
    baseScore: 9.0,
  },
  social_engineering: {
    techniques: ["T1566.001", "T1566.002", "T1598", "T1204"],
    killChain: "initial_access",
    baseScore: 6.5,
  },
  web_application: {
    techniques: ["T1190", "T1059.007", "T1505.003"],
    killChain: "initial_access",
    baseScore: 7.5,
  },
  network_exploitation: {
    techniques: ["T1210", "T1046", "T1040", "T1557"],
    killChain: "lateral_movement",
    baseScore: 7.0,
  },
  cloud_misconfiguration: {
    techniques: ["T1078.004", "T1530", "T1537", "T1580"],
    killChain: "initial_access",
    baseScore: 7.5,
  },
  wireless: {
    techniques: ["T1557.002", "T1200"],
    killChain: "initial_access",
    baseScore: 5.0,
  },
  insider_threat: {
    techniques: ["T1078", "T1534", "T1199"],
    killChain: "initial_access",
    baseScore: 8.5,
  },
  physical: {
    techniques: ["T1200", "T1091"],
    killChain: "initial_access",
    baseScore: 4.0,
  },
};

// ── Caldera Ability Catalog (by technique) ──────────────────────────────────
const CALDERA_ABILITY_MAP: Record<string, { abilityName: string; executor: string; tactic: string; platform: string; description: string }[]> = {
  "T1190": [
    { abilityName: "Exploit Public-Facing Application", executor: "sh", tactic: "initial-access", platform: "linux", description: "Scan and exploit public-facing web applications" },
  ],
  "T1133": [
    { abilityName: "Exploit External Remote Services", executor: "psh", tactic: "initial-access", platform: "windows", description: "Leverage exposed RDP/VPN/SSH services" },
  ],
  "T1078": [
    { abilityName: "Valid Accounts - Default Credentials", executor: "sh", tactic: "initial-access", platform: "linux", description: "Use discovered default or leaked credentials" },
    { abilityName: "Valid Accounts - Domain Accounts", executor: "psh", tactic: "persistence", platform: "windows", description: "Leverage compromised domain credentials" },
  ],
  "T1566.001": [
    { abilityName: "Spearphishing Attachment", executor: "psh", tactic: "initial-access", platform: "windows", description: "Deliver malicious attachment via email" },
  ],
  "T1566.002": [
    { abilityName: "Spearphishing Link", executor: "psh", tactic: "initial-access", platform: "windows", description: "Deliver malicious link via email" },
  ],
  "T1110": [
    { abilityName: "Brute Force - Password Spraying", executor: "sh", tactic: "credential-access", platform: "linux", description: "Password spray against discovered accounts" },
    { abilityName: "Brute Force - Credential Stuffing", executor: "sh", tactic: "credential-access", platform: "linux", description: "Test leaked credentials against target services" },
  ],
  "T1003": [
    { abilityName: "OS Credential Dumping - LSASS", executor: "psh", tactic: "credential-access", platform: "windows", description: "Dump credentials from LSASS memory" },
    { abilityName: "OS Credential Dumping - SAM", executor: "psh", tactic: "credential-access", platform: "windows", description: "Extract credentials from SAM database" },
    { abilityName: "OS Credential Dumping - /etc/shadow", executor: "sh", tactic: "credential-access", platform: "linux", description: "Extract password hashes from shadow file" },
  ],
  "T1059": [
    { abilityName: "Command and Scripting Interpreter", executor: "sh", tactic: "execution", platform: "linux", description: "Execute commands via shell interpreter" },
  ],
  "T1059.001": [
    { abilityName: "PowerShell Execution", executor: "psh", tactic: "execution", platform: "windows", description: "Execute PowerShell commands for post-exploitation" },
  ],
  "T1053": [
    { abilityName: "Scheduled Task/Job", executor: "psh", tactic: "persistence", platform: "windows", description: "Create scheduled task for persistence" },
  ],
  "T1547.001": [
    { abilityName: "Registry Run Keys", executor: "psh", tactic: "persistence", platform: "windows", description: "Add registry run key for persistence" },
  ],
  "T1055": [
    { abilityName: "Process Injection", executor: "psh", tactic: "defense-evasion", platform: "windows", description: "Inject code into running process" },
  ],
  "T1210": [
    { abilityName: "Exploitation of Remote Services", executor: "sh", tactic: "lateral-movement", platform: "linux", description: "Exploit vulnerable services on adjacent hosts" },
  ],
  "T1021.001": [
    { abilityName: "Remote Desktop Protocol", executor: "psh", tactic: "lateral-movement", platform: "windows", description: "Move laterally via RDP" },
  ],
  "T1021.002": [
    { abilityName: "SMB/Windows Admin Shares", executor: "psh", tactic: "lateral-movement", platform: "windows", description: "Move laterally via SMB shares" },
  ],
  "T1021.004": [
    { abilityName: "SSH Lateral Movement", executor: "sh", tactic: "lateral-movement", platform: "linux", description: "Move laterally via SSH" },
  ],
  "T1558": [
    { abilityName: "Kerberoasting", executor: "psh", tactic: "credential-access", platform: "windows", description: "Request service tickets for offline cracking" },
  ],
  "T1046": [
    { abilityName: "Network Service Discovery", executor: "sh", tactic: "discovery", platform: "linux", description: "Scan for network services" },
  ],
  "T1082": [
    { abilityName: "System Information Discovery", executor: "psh", tactic: "discovery", platform: "windows", description: "Gather system information" },
  ],
  "T1083": [
    { abilityName: "File and Directory Discovery", executor: "sh", tactic: "discovery", platform: "linux", description: "Enumerate files and directories" },
  ],
  "T1005": [
    { abilityName: "Data from Local System", executor: "sh", tactic: "collection", platform: "linux", description: "Collect sensitive data from local filesystem" },
  ],
  "T1048": [
    { abilityName: "Exfiltration Over Alternative Protocol", executor: "sh", tactic: "exfiltration", platform: "linux", description: "Exfiltrate data over DNS/HTTPS tunnel" },
  ],
  "T1041": [
    { abilityName: "Exfiltration Over C2 Channel", executor: "sh", tactic: "exfiltration", platform: "linux", description: "Exfiltrate data over existing C2 channel" },
  ],
  "T1070": [
    { abilityName: "Indicator Removal", executor: "psh", tactic: "defense-evasion", platform: "windows", description: "Clear event logs and artifacts" },
  ],
  "T1070.001": [
    { abilityName: "Clear Windows Event Logs", executor: "psh", tactic: "defense-evasion", platform: "windows", description: "Clear Windows event logs to cover tracks" },
  ],
};

// ── Metasploit Module Catalog (by technique/CVE pattern) ────────────────────
const MSF_MODULE_MAP: Record<string, { modulePath: string; moduleType: string; platform: string; description: string; reliability: string }[]> = {
  "T1190": [
    { modulePath: "exploit/multi/http/apache_mod_cgi_bash_env_exec", moduleType: "exploit", platform: "linux", description: "Shellshock - Apache mod_cgi", reliability: "excellent" },
    { modulePath: "exploit/multi/http/struts2_content_type_ognl", moduleType: "exploit", platform: "multi", description: "Apache Struts 2 RCE", reliability: "great" },
    { modulePath: "exploit/windows/http/exchange_proxyshell_rce", moduleType: "exploit", platform: "windows", description: "Exchange ProxyShell RCE", reliability: "excellent" },
    { modulePath: "exploit/multi/http/log4shell_header_injection", moduleType: "exploit", platform: "multi", description: "Log4Shell RCE", reliability: "great" },
  ],
  "T1133": [
    { modulePath: "auxiliary/scanner/ssh/ssh_login", moduleType: "auxiliary", platform: "multi", description: "SSH Login Scanner", reliability: "excellent" },
    { modulePath: "auxiliary/scanner/rdp/rdp_scanner", moduleType: "auxiliary", platform: "windows", description: "RDP Service Scanner", reliability: "great" },
    { modulePath: "exploit/windows/rdp/cve_2019_0708_bluekeep_rce", moduleType: "exploit", platform: "windows", description: "BlueKeep RDP RCE", reliability: "good" },
  ],
  "T1110": [
    { modulePath: "auxiliary/scanner/ssh/ssh_login", moduleType: "auxiliary", platform: "multi", description: "SSH Brute Force", reliability: "excellent" },
    { modulePath: "auxiliary/scanner/smb/smb_login", moduleType: "auxiliary", platform: "windows", description: "SMB Login Scanner", reliability: "excellent" },
    { modulePath: "auxiliary/scanner/http/http_login", moduleType: "auxiliary", platform: "multi", description: "HTTP Login Scanner", reliability: "great" },
    { modulePath: "auxiliary/scanner/ftp/ftp_login", moduleType: "auxiliary", platform: "multi", description: "FTP Login Scanner", reliability: "excellent" },
  ],
  "T1003": [
    { modulePath: "post/windows/gather/hashdump", moduleType: "post", platform: "windows", description: "Windows Password Hash Dump", reliability: "excellent" },
    { modulePath: "post/windows/gather/credentials/credential_collector", moduleType: "post", platform: "windows", description: "Credential Collector", reliability: "great" },
    { modulePath: "post/windows/gather/lsa_secrets", moduleType: "post", platform: "windows", description: "LSA Secrets Dump", reliability: "great" },
    { modulePath: "post/linux/gather/hashdump", moduleType: "post", platform: "linux", description: "Linux Password Hash Dump", reliability: "excellent" },
  ],
  "T1558": [
    { modulePath: "auxiliary/gather/get_user_spns", moduleType: "auxiliary", platform: "windows", description: "Kerberoast - Get User SPNs", reliability: "excellent" },
  ],
  "T1210": [
    { modulePath: "exploit/windows/smb/ms17_010_eternalblue", moduleType: "exploit", platform: "windows", description: "EternalBlue SMB RCE", reliability: "excellent" },
    { modulePath: "exploit/windows/smb/ms08_067_netapi", moduleType: "exploit", platform: "windows", description: "MS08-067 NetAPI RCE", reliability: "excellent" },
    { modulePath: "exploit/linux/samba/is_known_pipename", moduleType: "exploit", platform: "linux", description: "Samba is_known_pipename() RCE", reliability: "great" },
  ],
  "T1021.002": [
    { modulePath: "exploit/windows/smb/psexec", moduleType: "exploit", platform: "windows", description: "PsExec via SMB", reliability: "excellent" },
    { modulePath: "auxiliary/admin/smb/samba_symlink_traversal", moduleType: "auxiliary", platform: "linux", description: "Samba Symlink Traversal", reliability: "good" },
  ],
  "T1055": [
    { modulePath: "post/windows/manage/migrate", moduleType: "post", platform: "windows", description: "Process Migration", reliability: "excellent" },
    { modulePath: "post/windows/manage/inject_host", moduleType: "post", platform: "windows", description: "Inject into Host Process", reliability: "great" },
  ],
  "T1053": [
    { modulePath: "exploit/windows/local/persistence_service", moduleType: "exploit", platform: "windows", description: "Service Persistence", reliability: "great" },
  ],
  "T1547.001": [
    { modulePath: "post/windows/manage/persistence_exe", moduleType: "post", platform: "windows", description: "Registry Persistence", reliability: "great" },
  ],
  "T1046": [
    { modulePath: "auxiliary/scanner/portscan/tcp", moduleType: "auxiliary", platform: "multi", description: "TCP Port Scanner", reliability: "excellent" },
    { modulePath: "auxiliary/scanner/portscan/syn", moduleType: "auxiliary", platform: "multi", description: "SYN Port Scanner", reliability: "excellent" },
    { modulePath: "auxiliary/scanner/smb/smb_version", moduleType: "auxiliary", platform: "windows", description: "SMB Version Scanner", reliability: "excellent" },
  ],
  "T1082": [
    { modulePath: "post/windows/gather/enum_patches", moduleType: "post", platform: "windows", description: "Enumerate Patches", reliability: "excellent" },
    { modulePath: "post/multi/gather/env", moduleType: "post", platform: "multi", description: "Environment Enumeration", reliability: "excellent" },
  ],
  "T1005": [
    { modulePath: "post/multi/gather/firefox_creds", moduleType: "post", platform: "multi", description: "Firefox Credential Dump", reliability: "great" },
    { modulePath: "post/windows/gather/enum_chrome", moduleType: "post", platform: "windows", description: "Chrome Data Extraction", reliability: "great" },
  ],
  "T1048": [
    { modulePath: "post/multi/manage/shell_to_meterpreter", moduleType: "post", platform: "multi", description: "Upgrade to Meterpreter for exfil", reliability: "great" },
  ],
  "T1070": [
    { modulePath: "post/windows/manage/delete_user", moduleType: "post", platform: "windows", description: "Delete Created User Account", reliability: "great" },
  ],
  "T1070.001": [
    { modulePath: "post/windows/manage/event_log_clear", moduleType: "post", platform: "windows", description: "Clear Windows Event Logs", reliability: "excellent" },
  ],
};

// ── Post-Exploitation Phase Templates ───────────────────────────────────────
const POST_EXPLOIT_PHASES = {
  persistence: {
    name: "Persistence",
    order: 1,
    techniques: ["T1053", "T1547.001", "T1078", "T1136"],
    calderaAbilities: ["Scheduled Task/Job", "Registry Run Keys", "Valid Accounts - Domain Accounts"],
    msfModules: ["post/windows/manage/persistence_exe", "exploit/windows/local/persistence_service"],
    description: "Establish persistent access mechanisms to maintain foothold",
  },
  privilege_escalation: {
    name: "Privilege Escalation",
    order: 2,
    techniques: ["T1068", "T1548", "T1134"],
    calderaAbilities: ["Process Injection"],
    msfModules: ["exploit/windows/local/bypassuac_eventvwr", "exploit/linux/local/sudo_baron_samedit"],
    description: "Escalate privileges to gain higher-level access",
  },
  lateral_movement: {
    name: "Lateral Movement",
    order: 3,
    techniques: ["T1021.001", "T1021.002", "T1021.004", "T1210"],
    calderaAbilities: ["Remote Desktop Protocol", "SMB/Windows Admin Shares", "SSH Lateral Movement"],
    msfModules: ["exploit/windows/smb/psexec", "auxiliary/scanner/ssh/ssh_login"],
    description: "Move laterally across the network to reach high-value targets",
  },
  collection: {
    name: "Collection",
    order: 4,
    techniques: ["T1005", "T1039", "T1114", "T1213"],
    calderaAbilities: ["Data from Local System"],
    msfModules: ["post/multi/gather/firefox_creds", "post/windows/gather/enum_chrome"],
    description: "Collect sensitive data from compromised systems",
  },
  exfiltration: {
    name: "Exfiltration",
    order: 5,
    techniques: ["T1041", "T1048", "T1567"],
    calderaAbilities: ["Exfiltration Over C2 Channel", "Exfiltration Over Alternative Protocol"],
    msfModules: ["post/multi/manage/shell_to_meterpreter"],
    description: "Exfiltrate collected data through covert channels",
  },
  cleanup: {
    name: "Cleanup",
    order: 6,
    techniques: ["T1070", "T1070.001", "T1070.004"],
    calderaAbilities: ["Indicator Removal", "Clear Windows Event Logs"],
    msfModules: ["post/windows/manage/event_log_clear", "post/windows/manage/delete_user"],
    description: "Remove artifacts and restore systems to pre-engagement state",
  },
};

export const attackVectorEngineRouter = router({
  // ── Get Kill Chain Phases ─────────────────────────────────────────────
  getKillChainPhases: protectedProcedure.query(() => KILL_CHAIN_PHASES),

  // ── Get Post-Exploitation Phases ──────────────────────────────────────
  getPostExploitPhases: protectedProcedure.query(() => POST_EXPLOIT_PHASES),

  // ── Identify Attack Vectors from OSINT/Discovery Data ─────────────────
  identifyVectors: protectedProcedure
    .input(z.object({ engagementId: z.number().optional() }))
    .mutation(async ({ ctx, input }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { desc, sql } = await import("drizzle-orm");
      const {
        osintFindings, darkwebEnrichedRecords, vulnScanFindings,
        webAppFindings, exploitScripts, domainRecon, threatActors,
        attackVectors, attackVectorEvidence,
      } = await import("../../drizzle/schema");

      const now = Date.now();
      const vectors: any[] = [];

      // 1. OSINT Findings → Attack Vectors
      const osintRows = await db.select().from(osintFindings).orderBy(desc(osintFindings.createdAt)).limit(200);
      for (const finding of osintRows) {
        let vectorType: string | null = null;
        let techniques: string[] = [];
        let baseScore = 5.0;

        if (finding.category === "credential_leak") {
          vectorType = "credential_compromise";
          techniques = ["T1078", "T1110"];
          baseScore = 8.5;
        } else if (finding.category === "subdomain" || (finding as any).category === "open_port") {
          vectorType = "network_exploitation";
          techniques = ["T1046", "T1190"];
          baseScore = 6.0;
        } else if (finding.category === "dns_misconfiguration") {
          vectorType = "social_engineering";
          techniques = ["T1566.002", "T1598"];
          baseScore = 7.0;
        } else if (finding.category === "tech_stack") {
          vectorType = "web_application";
          techniques = ["T1190", "T1059.007"];
          baseScore = 5.5;
        } else if (finding.category === "email") {
          vectorType = "social_engineering";
          techniques = ["T1566.001", "T1566.002"];
          baseScore = 6.0;
        } else if (finding.category === "dark_web") {
          vectorType = "credential_compromise";
          techniques = ["T1078", "T1552"];
          baseScore = 8.0;
        }

        if (vectorType) {
          const severityBoost = (finding as any).severity === "critical" ? 2.0 : (finding as any).severity === "high" ? 1.5 : (finding as any).severity === "medium" ? 0.5 : 0;
          const score = Math.min(10, baseScore + severityBoost);
          vectors.push({
            id: generateId(),
            engagementId: input.engagementId || (finding as any).engagementId,
            name: `OSINT: ${(finding as any).title}`,
            description: (finding as any).description || `Attack vector identified from OSINT finding: ${(finding as any).category}`,
            vectorType,
            killChainPhase: VECTOR_TECHNIQUE_MAP[vectorType]?.killChain || "initial_access",
            mitreTechniqueIds: techniques,
            exploitabilityScore: score * 0.8,
            impactScore: score * 0.9,
            overallRiskScore: score,
            confidence: (finding as any).severity === "critical" || (finding as any).severity === "high" ? "high" : "medium",
            status: "identified",
            targetAsset: (finding as any).title,
            sourceModules: ["osint-recon"],
            evidenceSummary: `Source: ${(finding as any).source || "OSINT"} | Category: ${(finding as any).category} | Severity: ${(finding as any).severity}`,
            createdBy: String(ctx.user.id),
            createdAt: now,
            updatedAt: now,
            _evidence: { sourceType: "osint_finding" as const, sourceId: String(finding.id), sourceTitle: (finding as any).title },
          });
        }
      }

      // 2. Dark Web Records → Attack Vectors
      const darkwebRows = await db.select().from(darkwebEnrichedRecords).orderBy(desc(darkwebEnrichedRecords.createdAt)).limit(100);
      for (const record of darkwebRows) {
        const enrichment = record.enrichment as any;
        const riskLevel = enrichment?.riskLevel || "medium";
        const baseScore = riskLevel === "critical" ? 9.5 : riskLevel === "high" ? 8.0 : riskLevel === "medium" ? 6.5 : 5.0;
        vectors.push({
          id: generateId(),
          engagementId: input.engagementId || null,
          name: `Dark Web: ${record.title || "Intelligence Record"}`,
          description: `Dark web intelligence: ${record.summary || "Potential threat indicator from dark web monitoring"}`,
          vectorType: "credential_compromise",
          killChainPhase: "credential_access",
          mitreTechniqueIds: ["T1078", "T1552", "T1589"],
          exploitabilityScore: baseScore * 0.9,
          impactScore: baseScore * 0.95,
          overallRiskScore: baseScore,
          confidence: riskLevel === "critical" ? "high" : "medium",
          status: "identified",
          targetAsset: record.title,
          sourceModules: ["dark-web-intel"],
          evidenceSummary: `Source: Dark Web | Type: ${record.feedId || "unknown"} | Risk: ${riskLevel}`,
          createdBy: String(ctx.user.id),
          createdAt: now,
          updatedAt: now,
          _evidence: { sourceType: "darkweb_record" as const, sourceId: String(record.id), sourceTitle: record.title },
        });
      }

      // 3. Vulnerability Scan Findings → Attack Vectors
      const vulnRows = await db.select().from(vulnScanFindings).orderBy(desc(vulnScanFindings.createdAt)).limit(200);
      for (const vuln of vulnRows) {
        const cvss = vuln.cvssScore ? Number(vuln.cvssScore) : 5.0;
        if (cvss < 4.0) continue; // Skip low-severity vulns
        const techniques = vuln.cveId ? ["T1190", "T1210"] : ["T1190"];
        vectors.push({
          id: generateId(),
          engagementId: input.engagementId || null,
          name: `Vuln: ${vuln.cveId || vuln.title || "Vulnerability"}`,
          description: vuln.description || `Vulnerability with CVSS ${cvss}`,
          vectorType: "network_exploitation",
          killChainPhase: "initial_access",
          mitreTechniqueIds: techniques,
          cvssScore: cvss,
          exploitabilityScore: cvss * 0.85,
          impactScore: cvss * 0.9,
          overallRiskScore: cvss,
          confidence: cvss >= 9.0 ? "high" : cvss >= 7.0 ? "medium" : "low",
          status: "identified",
          targetAsset: vuln.host || vuln.title,
          targetService: vuln.port ? `${vuln.port}` : undefined,
          sourceModules: ["vuln-scanner"],
          evidenceSummary: `CVE: ${vuln.cveId || "N/A"} | CVSS: ${cvss} | Host: ${vuln.host || "N/A"}`,
          createdBy: String(ctx.user.id),
          createdAt: now,
          updatedAt: now,
          _evidence: { sourceType: "vuln_scan" as const, sourceId: String(vuln.id), sourceTitle: vuln.cveId || vuln.title },
        });
      }

      // 4. Web App Findings → Attack Vectors
      const webRows = await db.select().from(webAppFindings).orderBy(desc(webAppFindings.createdAt)).limit(100);
      for (const finding of webRows) {
        const riskNum = (finding as any).riskCode ? Number(finding.riskCode) : 1;
        if (riskNum < 2) continue;
        const score = riskNum === 3 ? 9.0 : riskNum === 2 ? 7.0 : 5.0;
        vectors.push({
          id: generateId(),
          engagementId: input.engagementId || null,
          name: `WebApp: ${(finding as any).alert || "Web Application Finding"}`,
          description: (finding as any).description || `Web application vulnerability: ${(finding as any).alert}`,
          vectorType: "web_application",
          killChainPhase: "initial_access",
          mitreTechniqueIds: ["T1190", "T1059.007", "T1505.003"],
          exploitabilityScore: score * 0.85,
          impactScore: score * 0.8,
          overallRiskScore: score,
          confidence: riskNum >= 3 ? "high" : "medium",
          status: "identified",
          targetAsset: (finding as any).url || (finding as any).alert,
          sourceModules: ["web-app-scanning"],
          evidenceSummary: `Alert: ${(finding as any).alert} | Risk: ${riskNum} | URL: ${(finding as any).url || "N/A"}`,
          createdBy: String(ctx.user.id),
          createdAt: now,
          updatedAt: now,
          _evidence: { sourceType: "web_app_finding" as const, sourceId: String(finding.id), sourceTitle: (finding as any).alert },
        });
      }

      // 5. Domain Recon → Attack Vectors (spoofable domains)
      const reconRows = await db.select().from(domainRecon).orderBy(desc(domainRecon.createdAt)).limit(50);
      for (const recon of reconRows) {
        if (recon.spoofable) {
          vectors.push({
            id: generateId(),
            engagementId: input.engagementId || recon.engagementId,
            name: `Spoofable Domain: ${recon.domain}`,
            description: `Domain ${recon.domain} is spoofable (score: ${recon.spoofScore}/100). ${recon.spoofAnalysis || ""}`,
            vectorType: "social_engineering",
            killChainPhase: "initial_access",
            mitreTechniqueIds: ["T1566.001", "T1566.002", "T1598"],
            exploitabilityScore: (recon.spoofScore || 50) / 10,
            impactScore: 7.5,
            overallRiskScore: Math.min(10, (recon.spoofScore || 50) / 10),
            confidence: (recon.spoofScore || 0) > 70 ? "high" : "medium",
            status: "identified",
            targetAsset: recon.domain,
            sourceModules: ["osint-recon"],
            evidenceSummary: `Domain: ${recon.domain} | Spoof Score: ${recon.spoofScore}/100 | SPF: ${recon.spfRecord ? "present" : "missing"}`,
            createdBy: String(ctx.user.id),
            createdAt: now,
            updatedAt: now,
            _evidence: { sourceType: "domain_recon" as const, sourceId: String(recon.id), sourceTitle: recon.domain },
          });
        }
      }

      // Insert all vectors and evidence into DB
      let insertedCount = 0;
      for (const v of vectors) {
        const evidence = v._evidence;
        delete v._evidence;
        try {
          await db.insert(attackVectors).values(v);
          await db.insert(attackVectorEvidence).values({
            id: generateId(),
            vectorId: v.id,
            sourceType: evidence.sourceType,
            sourceId: evidence.sourceId,
            sourceTitle: evidence.sourceTitle || null,
            relevanceScore: v.overallRiskScore / 10,
            evidenceDetail: v.evidenceSummary,
            createdAt: now,
          });
          insertedCount++;
        } catch (_e) {
          // Skip duplicates
        }
      }

      return {
        totalIdentified: insertedCount,
        byType: {
          credential_compromise: vectors.filter(v => v.vectorType === "credential_compromise").length,
          social_engineering: vectors.filter(v => v.vectorType === "social_engineering").length,
          network_exploitation: vectors.filter(v => v.vectorType === "network_exploitation").length,
          web_application: vectors.filter(v => v.vectorType === "web_application").length,
          cloud_misconfiguration: vectors.filter(v => v.vectorType === "cloud_misconfiguration").length,
          other: vectors.filter(v => !["credential_compromise", "social_engineering", "network_exploitation", "web_application", "cloud_misconfiguration"].includes(v.vectorType)).length,
        },
        byKillChain: KILL_CHAIN_PHASES.map(phase => ({
          ...phase,
          count: vectors.filter(v => v.killChainPhase === phase.id).length,
        })),
        avgRiskScore: vectors.length > 0 ? Math.round((vectors.reduce((sum, v) => sum + v.overallRiskScore, 0) / vectors.length) * 10) / 10 : 0,
      };
    }),

  // ── List Attack Vectors ───────────────────────────────────────────────
  listVectors: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      vectorType: z.string().optional(),
      killChainPhase: z.string().optional(),
      status: z.string().optional(),
      minRiskScore: z.number().optional(),
      limit: z.number().default(100),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { desc, eq, gte, and, sql } = await import("drizzle-orm");
      const { attackVectors } = await import("../../drizzle/schema");

      const conditions: any[] = [];
      if (input.engagementId) conditions.push(eq(attackVectors.engagementId, input.engagementId));
      if (input.vectorType) conditions.push(eq(attackVectors.vectorType, input.vectorType as any));
      if (input.killChainPhase) conditions.push(eq(attackVectors.killChainPhase, input.killChainPhase));
      if (input.status) conditions.push(eq(attackVectors.status, input.status as any));
      if (input.minRiskScore) conditions.push(gte(attackVectors.overallRiskScore, input.minRiskScore));

      const where = conditions.length > 0 ? and(...conditions) : undefined;
      const rows = await db.select().from(attackVectors)
        .where(where)
        .orderBy(desc(attackVectors.overallRiskScore))
        .limit(input.limit);

      return rows;
    }),

  // ── Get Vector Detail with Evidence + Mapped Exploits ─────────────────
  getVectorDetail: protectedProcedure
    .input(z.object({ vectorId: z.string() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const { attackVectors, attackVectorEvidence } = await import("../../drizzle/schema");

      const [vector] = await db.select().from(attackVectors).where(eq(attackVectors.id, input.vectorId));
      if (!vector) throw new TRPCError({ code: "NOT_FOUND", message: "Vector not found" });

      const evidence = await db.select().from(attackVectorEvidence).where(eq(attackVectorEvidence.vectorId, input.vectorId));

      // Map techniques to Caldera abilities and MSF modules
      const techniques = (vector.mitreTechniqueIds as string[]) || [];
      const calderaAbilities = techniques.flatMap(t => CALDERA_ABILITY_MAP[t] || []);
      const msfModules = techniques.flatMap(t => MSF_MODULE_MAP[t] || []);

      // Get recommended post-exploitation phases
      const postExploitRecommendations = Object.entries(POST_EXPLOIT_PHASES).map(([key, phase]) => ({
        phaseId: key,
        ...phase,
        calderaAbilities: phase.techniques.flatMap(t => CALDERA_ABILITY_MAP[t] || []),
        msfModules: phase.techniques.flatMap(t => MSF_MODULE_MAP[t] || []),
      }));

      return {
        vector,
        evidence,
        calderaAbilities,
        msfModules,
        postExploitRecommendations,
        killChainPosition: KILL_CHAIN_PHASES.find(p => p.id === vector.killChainPhase),
      };
    }),

  // ── Update Vector Status ──────────────────────────────────────────────
  updateVectorStatus: protectedProcedure
    .input(z.object({
      vectorId: z.string(),
      status: z.enum(["identified", "validated", "exploited", "mitigated", "accepted"]),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const { attackVectors } = await import("../../drizzle/schema");

      await db.update(attackVectors).set({ status: input.status, updatedAt: Date.now() }).where(eq(attackVectors.id, input.vectorId));
      return { success: true };
    }),

  // ── Get Caldera Abilities for Techniques ──────────────────────────────
  getCalderaAbilities: protectedProcedure
    .input(z.object({ techniqueIds: z.array(z.string()) }))
    .query(({ input }) => {
      const abilities = input.techniqueIds.flatMap(t => (CALDERA_ABILITY_MAP[t] || []).map(a => ({ ...a, techniqueId: t })));
      return abilities;
    }),

  // ── Get MSF Modules for Techniques ────────────────────────────────────
  getMsfModules: protectedProcedure
    .input(z.object({ techniqueIds: z.array(z.string()) }))
    .query(({ input }) => {
      const modules = input.techniqueIds.flatMap(t => (MSF_MODULE_MAP[t] || []).map(m => ({ ...m, techniqueId: t })));
      return modules;
    }),

  // ── Match Exploit Scripts from Arsenal ────────────────────────────────
  matchExploitScripts: protectedProcedure
    .input(z.object({ vectorId: z.string() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, or, like, desc } = await import("drizzle-orm");
      const { attackVectors, exploitScripts } = await import("../../drizzle/schema");

      const [vector] = await db.select().from(attackVectors).where(eq(attackVectors.id, input.vectorId));
      if (!vector) return [];

      const techniques = (vector.mitreTechniqueIds as string[]) || [];
      if (techniques.length === 0) return [];

      // Search exploit scripts by MITRE technique ID
      const conditions = techniques.map(t => like(exploitScripts.mitreAttackId, `%${t}%`));
      const scripts = await db.select({
        id: exploitScripts.id,
        title: exploitScripts.title,
        sourceType: exploitScripts.sourceType,
        sourceId: exploitScripts.sourceId,
        cveId: exploitScripts.cveId,
        platform: exploitScripts.platform,
        exploitType: exploitScripts.exploitType,
        reliability: exploitScripts.reliability,
        verified: exploitScripts.verified,
        mitreAttackId: exploitScripts.mitreAttackId,
        calderaAbilityGenerated: exploitScripts.calderaAbilityGenerated,
        successRate: exploitScripts.successRate,
        timesDeployed: exploitScripts.timesDeployed,
      }).from(exploitScripts)
        .where(or(...conditions))
        .orderBy(desc(exploitScripts.successRate))
        .limit(20);

      return scripts;
    }),

  // ── Generate Attack Playbook from Vectors ─────────────────────────────
  generatePlaybook: protectedProcedure
    .input(z.object({
      name: z.string(),
      engagementId: z.number().optional(),
      vectorIds: z.array(z.string()),
      targetPlatform: z.enum(["windows", "linux", "multi"]).default("multi"),
      targetEnvironment: z.string().optional(),
      includePostExploit: z.boolean().default(true),
      includeCleanup: z.boolean().default(true),
    }))
    .mutation(async ({ ctx, input }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, inArray } = await import("drizzle-orm");
      const { attackVectors, attackPlaybooks } = await import("../../drizzle/schema");

      // Fetch selected vectors
      const selectedVectors = await db.select().from(attackVectors)
        .where(inArray(attackVectors.id, input.vectorIds));

      if (selectedVectors.length === 0) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "No valid vectors selected" });
      }

      // Collect all techniques from selected vectors
      const allTechniques = Array.from(new Set(
        selectedVectors.flatMap(v => (v.mitreTechniqueIds as string[]) || [])
      ));

      // Build pre-exploitation steps (recon + initial access)
      const preExploitSteps = selectedVectors.map(v => ({
        vectorId: v.id,
        vectorName: v.name,
        vectorType: v.vectorType,
        killChainPhase: v.killChainPhase,
        riskScore: v.overallRiskScore,
        techniques: v.mitreTechniqueIds,
        calderaAbilities: ((v.mitreTechniqueIds as string[]) || []).flatMap(t => CALDERA_ABILITY_MAP[t] || [])
          .filter(a => input.targetPlatform === "multi" || a.platform === input.targetPlatform || a.platform === "multi"),
        msfModules: ((v.mitreTechniqueIds as string[]) || []).flatMap(t => MSF_MODULE_MAP[t] || [])
          .filter(m => input.targetPlatform === "multi" || m.platform === input.targetPlatform || m.platform === "multi"),
      }));

      // Build exploit steps
      const exploitSteps = preExploitSteps.filter(s =>
        s.killChainPhase === "initial_access" || s.killChainPhase === "credential_access"
      ).map(s => ({
        ...s,
        phase: "exploitation",
        priority: s.riskScore >= 8 ? "high" : s.riskScore >= 6 ? "medium" : "low",
      }));

      // Build post-exploitation steps
      const postExploitSteps = input.includePostExploit
        ? Object.entries(POST_EXPLOIT_PHASES)
          .filter(([key]) => key !== "cleanup" || input.includeCleanup)
          .map(([key, phase]) => ({
            phaseId: key,
            phaseName: phase.name,
            order: phase.order,
            description: phase.description,
            techniques: phase.techniques,
            calderaAbilities: phase.techniques.flatMap(t => CALDERA_ABILITY_MAP[t] || [])
              .filter(a => input.targetPlatform === "multi" || a.platform === input.targetPlatform || a.platform === "multi"),
            msfModules: phase.techniques.flatMap(t => MSF_MODULE_MAP[t] || [])
              .filter(m => input.targetPlatform === "multi" || m.platform === input.targetPlatform || m.platform === "multi"),
          }))
        : [];

      // Build cleanup steps
      const cleanupSteps = input.includeCleanup
        ? [{
          phaseName: "Cleanup & Restoration",
          techniques: ["T1070", "T1070.001", "T1070.004"],
          calderaAbilities: ["T1070", "T1070.001"].flatMap(t => CALDERA_ABILITY_MAP[t] || []),
          msfModules: ["T1070", "T1070.001"].flatMap(t => MSF_MODULE_MAP[t] || []),
          steps: [
            "Remove all persistence mechanisms installed during engagement",
            "Clear event logs on compromised systems",
            "Delete uploaded tools and payloads",
            "Restore modified configurations to original state",
            "Verify no residual access remains",
            "Document all cleanup actions for engagement report",
          ],
        }]
        : [];

      // Aggregate all Caldera abilities and MSF modules
      const allCalderaAbilities = [
        ...preExploitSteps.flatMap(s => s.calderaAbilities),
        ...postExploitSteps.flatMap(s => s.calderaAbilities),
      ];
      const allMsfModules = [
        ...preExploitSteps.flatMap(s => s.msfModules),
        ...postExploitSteps.flatMap(s => s.msfModules),
      ];

      // Kill chain coverage
      const coveredPhases = Array.from(new Set([
        ...selectedVectors.map(v => v.killChainPhase),
        ...(input.includePostExploit ? ["persistence", "privilege_escalation", "lateral_movement", "collection", "exfiltration"] : []),
        ...(input.includeCleanup ? ["defense_evasion"] : []),
      ]));

      const maxRisk = Math.max(...selectedVectors.map(v => v.overallRiskScore));
      const riskLevel = maxRisk >= 9 ? "critical" : maxRisk >= 7 ? "high" : maxRisk >= 5 ? "medium" : "low";

      const now = Date.now();
      const playbookId = generateId();

      await db.insert(attackPlaybooks).values({
        id: playbookId,
        engagementId: input.engagementId || null,
        name: input.name,
        description: `Auto-generated playbook from ${selectedVectors.length} attack vectors targeting ${input.targetPlatform} environment`,
        targetEnvironment: input.targetEnvironment || null,
        targetPlatform: input.targetPlatform,
        killChainCoverage: coveredPhases,
        preExploitSteps: preExploitSteps,
        exploitSteps: exploitSteps,
        postExploitSteps: postExploitSteps,
        cleanupSteps: cleanupSteps,
        calderaAbilities: allCalderaAbilities,
        msfModules: allMsfModules,
        atomicTests: null,
        estimatedDuration: `${Math.max(2, selectedVectors.length * 2)}h`,
        riskLevel: riskLevel as any,
        roeCompliant: true,
        status: "draft",
        createdBy: String(ctx.user.id),
        createdAt: now,
        updatedAt: now,
      });

      return {
        playbookId,
        name: input.name,
        vectorCount: selectedVectors.length,
        techniqueCount: allTechniques.length,
        calderaAbilityCount: allCalderaAbilities.length,
        msfModuleCount: allMsfModules.length,
        killChainCoverage: coveredPhases,
        riskLevel,
        estimatedDuration: `${Math.max(2, selectedVectors.length * 2)}h`,
      };
    }),

  // ── List Playbooks ────────────────────────────────────────────────────
  listPlaybooks: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      status: z.string().optional(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { desc, eq, and } = await import("drizzle-orm");
      const { attackPlaybooks } = await import("../../drizzle/schema");

      const conditions: any[] = [];
      if (input.engagementId) conditions.push(eq(attackPlaybooks.engagementId, input.engagementId));
      if (input.status) conditions.push(eq(attackPlaybooks.status, input.status as any));

      const where = conditions.length > 0 ? and(...conditions) : undefined;
      return db.select().from(attackPlaybooks).where(where).orderBy(desc(attackPlaybooks.createdAt));
    }),

  // ── Get Playbook Detail ───────────────────────────────────────────────
  getPlaybookDetail: protectedProcedure
    .input(z.object({ playbookId: z.string() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const { attackPlaybooks, attackPlaybookExecutions } = await import("../../drizzle/schema");

      const [playbook] = await db.select().from(attackPlaybooks).where(eq(attackPlaybooks.id, input.playbookId));
      if (!playbook) throw new TRPCError({ code: "NOT_FOUND", message: "Playbook not found" });

      const executions = await db.select().from(attackPlaybookExecutions).where(eq(attackPlaybookExecutions.playbookId, input.playbookId));

      return { playbook, executions };
    }),

  // ── Start Playbook Execution ──────────────────────────────────────────
  startExecution: protectedProcedure
    .input(z.object({
      playbookId: z.string(),
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ ctx, input }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const { attackPlaybooks, attackPlaybookExecutions } = await import("../../drizzle/schema");

      const [playbook] = await db.select().from(attackPlaybooks).where(eq(attackPlaybooks.id, input.playbookId));
      if (!playbook) throw new TRPCError({ code: "NOT_FOUND", message: "Playbook not found" });

      const execId = generateId();
      const now = Date.now();

      await db.insert(attackPlaybookExecutions).values({
        id: execId,
        playbookId: input.playbookId,
        engagementId: input.engagementId || playbook.engagementId,
        currentPhase: "pre_exploit",
        currentStepIndex: 0,
        stepResults: [],
        startedAt: now,
        executedBy: String(ctx.user.id),
        status: "running",
      });

      // Update playbook status
      await db.update(attackPlaybooks).set({ status: "executing", updatedAt: now })
        .where(eq(attackPlaybooks.id, input.playbookId));

      return { executionId: execId, status: "running", currentPhase: "pre_exploit" };
    }),

  // ── Advance Execution Phase ───────────────────────────────────────────
  advanceExecution: protectedProcedure
    .input(z.object({
      executionId: z.string(),
      stepResult: z.object({
        phase: z.string(),
        stepIndex: z.number(),
        status: z.enum(["success", "failure", "skipped"]),
        output: z.string().optional(),
        toolUsed: z.string().optional(),
      }),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const { attackPlaybookExecutions } = await import("../../drizzle/schema");

      const [execution] = await db.select().from(attackPlaybookExecutions).where(eq(attackPlaybookExecutions.id, input.executionId));
      if (!execution) throw new TRPCError({ code: "NOT_FOUND", message: "Execution not found" });

      const existingResults = (execution.stepResults as any[]) || [];
      existingResults.push({ ...input.stepResult, timestamp: Date.now() });

      const phaseOrder = ["pre_exploit", "initial_access", "execution", "persistence", "priv_escalation", "lateral_movement", "collection", "exfiltration", "cleanup", "completed"];
      const currentIdx = phaseOrder.indexOf(execution.currentPhase);
      const nextPhase = currentIdx < phaseOrder.length - 1 ? phaseOrder[currentIdx + 1] : "completed";

      const isCompleted = nextPhase === "completed";

      await db.update(attackPlaybookExecutions).set({
        currentPhase: nextPhase as any,
        currentStepIndex: isCompleted ? execution.currentStepIndex : (execution.currentStepIndex || 0) + 1,
        stepResults: existingResults,
        status: isCompleted ? "completed" : "running",
        completedAt: isCompleted ? Date.now() : null,
      }).where(eq(attackPlaybookExecutions.id, input.executionId));

      return { executionId: input.executionId, currentPhase: nextPhase, status: isCompleted ? "completed" : "running" };
    }),

  // ── Dashboard Stats ───────────────────────────────────────────────────
  getDashboardStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { sql } = await import("drizzle-orm");
    const { attackVectors, attackPlaybooks, attackPlaybookExecutions } = await import("../../drizzle/schema");

    const [vectorStats] = await db.select({
      total: sql<number>`COUNT(*)`,
      avgRisk: sql<number>`ROUND(AVG(overall_risk_score), 1)`,
      critical: sql<number>`SUM(CASE WHEN overall_risk_score >= 9 THEN 1 ELSE 0 END)`,
      high: sql<number>`SUM(CASE WHEN overall_risk_score >= 7 AND overall_risk_score < 9 THEN 1 ELSE 0 END)`,
      medium: sql<number>`SUM(CASE WHEN overall_risk_score >= 5 AND overall_risk_score < 7 THEN 1 ELSE 0 END)`,
      low: sql<number>`SUM(CASE WHEN overall_risk_score < 5 THEN 1 ELSE 0 END)`,
      identified: sql<number>`SUM(CASE WHEN status = 'identified' THEN 1 ELSE 0 END)`,
      validated: sql<number>`SUM(CASE WHEN status = 'validated' THEN 1 ELSE 0 END)`,
      exploited: sql<number>`SUM(CASE WHEN status = 'exploited' THEN 1 ELSE 0 END)`,
      mitigated: sql<number>`SUM(CASE WHEN status = 'mitigated' THEN 1 ELSE 0 END)`,
    }).from(attackVectors);

    const [playbookStats] = await db.select({
      total: sql<number>`COUNT(*)`,
      draft: sql<number>`SUM(CASE WHEN status = 'draft' THEN 1 ELSE 0 END)`,
      executing: sql<number>`SUM(CASE WHEN status = 'executing' THEN 1 ELSE 0 END)`,
      completed: sql<number>`SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END)`,
    }).from(attackPlaybooks);

    const [execStats] = await db.select({
      total: sql<number>`COUNT(*)`,
      running: sql<number>`SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END)`,
      completed: sql<number>`SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END)`,
      failed: sql<number>`SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END)`,
    }).from(attackPlaybookExecutions);

    // Vector type distribution
    const typeDistribution = await db.select({
      vectorType: attackVectors.vectorType,
      count: sql<number>`COUNT(*)`,
      avgScore: sql<number>`ROUND(AVG(overall_risk_score), 1)`,
    }).from(attackVectors).groupBy(attackVectors.vectorType);

    return {
      vectors: vectorStats,
      playbooks: playbookStats,
      executions: execStats,
      typeDistribution,
      calderaAbilityCount: Object.values(CALDERA_ABILITY_MAP).flat().length,
      msfModuleCount: Object.values(MSF_MODULE_MAP).flat().length,
      killChainPhases: KILL_CHAIN_PHASES.length,
      postExploitPhases: Object.keys(POST_EXPLOIT_PHASES).length,
    };
  }),
});
