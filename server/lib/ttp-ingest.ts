/**
 * TTP Knowledge Ingestion Service
 * 
 * Downloads and parses structured data from authoritative GitHub repositories:
 * 1. MITRE ATT&CK STIX Data (enterprise-attack.json) - master technique catalog
 * 2. Atomic Red Team (atomics index) - test commands per technique
 * 3. SigmaHQ (sigma rules) - detection rules mapped to ATT&CK
 * 4. LOLBAS Project - Windows LOLBins with ATT&CK mappings
 * 5. Caldera Stockpile - official Caldera ability definitions
 * 6. Metasploit Framework - exploit module catalog
 * 7. Kali Linux Tools - offensive tool catalog
 */

import * as db from "../db";
import type { InsertTtpKnowledge } from "../../drizzle/schema";

const GITHUB_RAW = "https://raw.githubusercontent.com";

// ─── Source URLs ─────────────────────────────────────────────────────────

const SOURCES = {
  // MITRE ATT&CK Enterprise STIX 2.1 (latest release)
  attackStix: `${GITHUB_RAW}/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`,
  // Atomic Red Team index of all atomics
  atomicIndex: `${GITHUB_RAW}/redcanaryco/atomic-red-team/master/atomics/Indexes/Indexes-CSV/index.csv`,
  // Atomic Red Team YAML for a specific technique
  atomicYaml: (techId: string) => `${GITHUB_RAW}/redcanaryco/atomic-red-team/master/atomics/${techId}/${techId}.yaml`,
  // LOLBAS API endpoint (compiled JSON)
  lolbasApi: "https://lolbas-project.github.io/api/lolbas.json",
  // Sigma rules (we'll fetch the index)
  sigmaRules: `${GITHUB_RAW}/SigmaHQ/sigma/master/rules/`,
  // Kali tools page (we'll parse the tool list)
  kaliTools: "https://www.kali.org/tools/",
  // Metasploit module database
  metasploitDb: `${GITHUB_RAW}/rapid7/metasploit-framework/master/db/modules_metadata_base.json`,
};

// ─── MITRE ATT&CK STIX Ingestion ────────────────────────────────────────

interface StixObject {
  type: string;
  id: string;
  name?: string;
  description?: string;
  external_references?: Array<{ source_name: string; external_id?: string; url?: string }>;
  kill_chain_phases?: Array<{ kill_chain_name: string; phase_name: string }>;
  x_mitre_platforms?: string[];
  x_mitre_data_sources?: string[];
  x_mitre_detection?: string;
  x_mitre_is_subtechnique?: boolean;
  x_mitre_deprecated?: boolean;
  x_mitre_version?: string;
  revoked?: boolean;
}

/**
 * Download and parse the MITRE ATT&CK Enterprise STIX data.
 * Extracts all techniques with their IDs, names, tactics, descriptions, platforms, data sources.
 */
export async function ingestAttackStix(): Promise<{
  techniques: Array<{
    id: string;
    name: string;
    tactic: string;
    description: string;
    platforms: string[];
    dataSources: string[];
    detection: string;
    isSubtechnique: boolean;
    url: string;
  }>;
  groups: Array<{ id: string; name: string; aliases: string[]; description: string }>;
  software: Array<{ id: string; name: string; type: string; description: string }>;
  stats: { techniques: number; groups: number; software: number };
}> {
  console.log("[TTP Ingest] Downloading MITRE ATT&CK STIX data...");
  const resp = await fetch(SOURCES.attackStix);
  if (!resp.ok) throw new Error(`Failed to fetch ATT&CK STIX: ${resp.status}`);
  
  const data = await resp.json() as { objects: StixObject[] };
  const objects = data.objects || [];

  // Extract techniques (attack-pattern)
  const techniques = objects
    .filter((o) => o.type === "attack-pattern" && !o.revoked && !o.x_mitre_deprecated)
    .map((o) => {
      const extRef = o.external_references?.find((r) => r.source_name === "mitre-attack");
      const tactics = (o.kill_chain_phases || [])
        .filter((p) => p.kill_chain_name === "mitre-attack")
        .map((p) => p.phase_name);
      return {
        id: extRef?.external_id || "",
        name: o.name || "",
        tactic: tactics.join(", ") || "unknown",
        description: (o.description || "").substring(0, 5000),
        platforms: o.x_mitre_platforms || [],
        dataSources: o.x_mitre_data_sources || [],
        detection: (o.x_mitre_detection || "").substring(0, 3000),
        isSubtechnique: o.x_mitre_is_subtechnique || false,
        url: extRef?.url || "",
      };
    })
    .filter((t) => t.id.startsWith("T"));

  // Extract groups (intrusion-set)
  const groups = objects
    .filter((o) => o.type === "intrusion-set" && !o.revoked)
    .map((o) => {
      const extRef = o.external_references?.find((r) => r.source_name === "mitre-attack");
      return {
        id: extRef?.external_id || o.id,
        name: o.name || "",
        aliases: (o as any).aliases || [],
        description: (o.description || "").substring(0, 2000),
      };
    });

  // Extract software (malware + tool)
  const software = objects
    .filter((o) => (o.type === "malware" || o.type === "tool") && !o.revoked)
    .map((o) => {
      const extRef = o.external_references?.find((r) => r.source_name === "mitre-attack");
      return {
        id: extRef?.external_id || o.id,
        name: o.name || "",
        type: o.type,
        description: (o.description || "").substring(0, 2000),
      };
    });

  console.log(`[TTP Ingest] Parsed ${techniques.length} techniques, ${groups.length} groups, ${software.length} software`);
  return {
    techniques,
    groups,
    software,
    stats: { techniques: techniques.length, groups: groups.length, software: software.length },
  };
}

// ─── Atomic Red Team Ingestion ───────────────────────────────────────────

/**
 * Download the Atomic Red Team index to get a list of all available tests per technique.
 */
export async function ingestAtomicRedTeamIndex(): Promise<Map<string, Array<{ name: string; description: string; platforms: string[] }>>> {
  console.log("[TTP Ingest] Downloading Atomic Red Team index...");
  const resp = await fetch(SOURCES.atomicIndex);
  if (!resp.ok) {
    console.warn(`[TTP Ingest] Atomic Red Team index not available: ${resp.status}`);
    return new Map();
  }
  
  const csv = await resp.text();
  const lines = csv.split("\n").slice(1); // skip header
  const testsByTechnique = new Map<string, Array<{ name: string; description: string; platforms: string[] }>>();

  for (const line of lines) {
    if (!line.trim()) continue;
    // CSV format: Tactic,Technique #,Technique Name,Test #,Test Name,Test GUID,Executor Name
    const parts = line.split(",");
    if (parts.length < 5) continue;
    const techId = parts[1]?.trim();
    const testName = parts[4]?.trim();
    const executor = parts[6]?.trim();
    if (!techId || !testName) continue;

    if (!testsByTechnique.has(techId)) {
      testsByTechnique.set(techId, []);
    }
    testsByTechnique.get(techId)!.push({
      name: testName,
      description: `Atomic test: ${testName}`,
      platforms: executor ? [executor] : [],
    });
  }

  console.log(`[TTP Ingest] Parsed Atomic Red Team tests for ${testsByTechnique.size} techniques`);
  return testsByTechnique;
}

// ─── LOLBAS Ingestion ────────────────────────────────────────────────────

interface LolbasEntry {
  Name: string;
  Description: string;
  Author: string;
  Created: string;
  Commands: Array<{
    Command: string;
    Description: string;
    Usecase: string;
    Category: string;
    Privileges: string;
    MitreID: string;
    OperatingSystem: string;
  }>;
  "Full_Path": Array<{ Path: string }>;
  "Code_Sample": Array<{ Code: string }>;
  Detection: Array<{ IOC: string }>;
  Resources: Array<{ Link: string }>;
}

/**
 * Download and parse the LOLBAS project data.
 * Maps LOLBins to MITRE ATT&CK technique IDs.
 */
export async function ingestLolbas(): Promise<Map<string, Array<{
  binary: string;
  command: string;
  description: string;
  usecase: string;
  category: string;
  iocs: string[];
}>>> {
  console.log("[TTP Ingest] Downloading LOLBAS data...");
  const resp = await fetch(SOURCES.lolbasApi);
  if (!resp.ok) {
    console.warn(`[TTP Ingest] LOLBAS API not available: ${resp.status}`);
    return new Map();
  }

  const entries: LolbasEntry[] = await resp.json();
  const lolbasByTechnique = new Map<string, Array<{
    binary: string;
    command: string;
    description: string;
    usecase: string;
    category: string;
    iocs: string[];
  }>>();

  for (const entry of entries) {
    const iocs = (entry.Detection || []).map((d) => d.IOC).filter(Boolean);
    for (const cmd of entry.Commands || []) {
      const mitreId = cmd.MitreID;
      if (!mitreId) continue;
      
      // MitreID can be comma-separated
      const ids = mitreId.split(",").map((id) => id.trim()).filter((id) => id.startsWith("T"));
      for (const techId of ids) {
        if (!lolbasByTechnique.has(techId)) {
          lolbasByTechnique.set(techId, []);
        }
        lolbasByTechnique.get(techId)!.push({
          binary: entry.Name,
          command: cmd.Command || "",
          description: cmd.Description || entry.Description,
          usecase: cmd.Usecase || "",
          category: cmd.Category || "",
          iocs,
        });
      }
    }
  }

  console.log(`[TTP Ingest] Parsed LOLBAS entries for ${lolbasByTechnique.size} techniques`);
  return lolbasByTechnique;
}

// ─── Metasploit Module Ingestion ─────────────────────────────────────────

interface MetasploitModule {
  name: string;
  fullname: string;
  aliases: string[];
  rank: number;
  disclosure_date: string;
  type: string;
  author: string[];
  description: string;
  references: string[];
  platform: string;
  arch: string;
  rport: string;
  autofilter_ports: string[];
  autofilter_services: string[];
  targets: string[];
  mod_time: string;
  path: string;
  is_install_path: boolean;
  ref_name: string;
  check: boolean;
  post_auth: boolean;
  default_credential: boolean;
  notes: Record<string, string[]>;
}

/**
 * Download and parse the Metasploit module metadata database.
 * Maps modules to CVEs and categorizes by type.
 */
export async function ingestMetasploitModules(): Promise<{
  exploits: Array<{ name: string; fullname: string; description: string; cves: string[]; platform: string; rank: number }>;
  auxiliary: Array<{ name: string; fullname: string; description: string; type: string }>;
  post: Array<{ name: string; fullname: string; description: string; platform: string }>;
  stats: { exploits: number; auxiliary: number; post: number; total: number };
}> {
  console.log("[TTP Ingest] Downloading Metasploit module database...");
  const resp = await fetch(SOURCES.metasploitDb);
  if (!resp.ok) {
    console.warn(`[TTP Ingest] Metasploit DB not available: ${resp.status}`);
    return { exploits: [], auxiliary: [], post: [], stats: { exploits: 0, auxiliary: 0, post: 0, total: 0 } };
  }

  const text = await resp.text();
  let modules: Record<string, MetasploitModule>;
  try {
    modules = JSON.parse(text);
  } catch {
    console.warn("[TTP Ingest] Failed to parse Metasploit DB JSON");
    return { exploits: [], auxiliary: [], post: [], stats: { exploits: 0, auxiliary: 0, post: 0, total: 0 } };
  }

  const exploits: Array<{ name: string; fullname: string; description: string; cves: string[]; platform: string; rank: number }> = [];
  const auxiliary: Array<{ name: string; fullname: string; description: string; type: string }> = [];
  const post: Array<{ name: string; fullname: string; description: string; platform: string }> = [];

  for (const [key, mod] of Object.entries(modules)) {
    const cves = (mod.references || []).filter((r) => r.startsWith("CVE-"));
    
    if (mod.type === "exploit" || key.startsWith("exploit")) {
      exploits.push({
        name: mod.name,
        fullname: mod.fullname || key,
        description: (mod.description || "").substring(0, 500),
        cves,
        platform: mod.platform || "",
        rank: mod.rank || 0,
      });
    } else if (mod.type === "auxiliary" || key.startsWith("auxiliary")) {
      auxiliary.push({
        name: mod.name,
        fullname: mod.fullname || key,
        description: (mod.description || "").substring(0, 500),
        type: key.split("/")[1] || "unknown",
      });
    } else if (mod.type === "post" || key.startsWith("post")) {
      post.push({
        name: mod.name,
        fullname: mod.fullname || key,
        description: (mod.description || "").substring(0, 500),
        platform: mod.platform || "",
      });
    }
  }

  console.log(`[TTP Ingest] Parsed ${exploits.length} exploits, ${auxiliary.length} auxiliary, ${post.length} post modules`);
  return {
    exploits,
    auxiliary,
    post,
    stats: { exploits: exploits.length, auxiliary: auxiliary.length, post: post.length, total: exploits.length + auxiliary.length + post.length },
  };
}

// ─── Kali Linux Tools Catalog ────────────────────────────────────────────

// Curated list of major Kali Linux tools with categories and ATT&CK mappings
const KALI_TOOLS_CATALOG = [
  // Information Gathering
  { name: "scanforge-discovery", category: "Information Gathering", description: "Network discovery and security auditing", techniques: ["T1046", "T1018", "T1135"] },
  { name: "masscan", category: "Information Gathering", description: "Mass IP port scanner", techniques: ["T1046"] },
  { name: "recon-ng", category: "Information Gathering", description: "Web reconnaissance framework", techniques: ["T1589", "T1590", "T1591", "T1592", "T1593"] },
  { name: "theHarvester", category: "Information Gathering", description: "Email, subdomain, and people name harvester", techniques: ["T1589", "T1590", "T1593"] },
  { name: "maltego", category: "Information Gathering", description: "Open source intelligence and forensics", techniques: ["T1589", "T1590", "T1591", "T1592"] },
  { name: "dnsenum", category: "Information Gathering", description: "DNS enumeration tool", techniques: ["T1590.002"] },
  { name: "fierce", category: "Information Gathering", description: "DNS reconnaissance tool", techniques: ["T1590.002"] },
  { name: "amass", category: "Information Gathering", description: "In-depth attack surface mapping", techniques: ["T1590", "T1593"] },
  { name: "enum4linux", category: "Information Gathering", description: "Windows/Samba enumeration tool", techniques: ["T1087", "T1135"] },
  { name: "smbclient", category: "Information Gathering", description: "SMB/CIFS access utility", techniques: ["T1021.002", "T1135"] },
  { name: "snmpwalk", category: "Information Gathering", description: "SNMP network management", techniques: ["T1046", "T1018"] },
  { name: "nbtscan", category: "Information Gathering", description: "NetBIOS name network scanner", techniques: ["T1018", "T1016"] },
  { name: "dnsrecon", category: "Information Gathering", description: "DNS enumeration script", techniques: ["T1590.002"] },
  { name: "sublist3r", category: "Information Gathering", description: "Subdomain enumeration tool", techniques: ["T1590.002", "T1593"] },
  // Vulnerability Analysis
  { name: "nikto", category: "Vulnerability Analysis", description: "Web server scanner", techniques: ["T1595.002"] },
  { name: "openvas", category: "Vulnerability Analysis", description: "Vulnerability scanner", techniques: ["T1595.002"] },
  { name: "wpscan", category: "Vulnerability Analysis", description: "WordPress security scanner", techniques: ["T1595.002", "T1190"] },
  { name: "sqlmap", category: "Vulnerability Analysis", description: "SQL injection detection and exploitation", techniques: ["T1190", "T1059.004"] },
  { name: "lynis", category: "Vulnerability Analysis", description: "Security auditing tool for Unix", techniques: ["T1595.002"] },
  { name: "nessus", category: "Vulnerability Analysis", description: "Vulnerability scanner", techniques: ["T1595.002"] },
  // Exploitation Tools
  { name: "metasploit-framework", category: "Exploitation Tools", description: "Penetration testing framework", techniques: ["T1190", "T1203", "T1210", "T1059"] },
  { name: "searchsploit", category: "Exploitation Tools", description: "Exploit-DB search tool", techniques: ["T1588.005", "T1588.006"] },
  { name: "crackmapexec", category: "Exploitation Tools", description: "Swiss army knife for pentesting networks", techniques: ["T1021.002", "T1047", "T1053.005", "T1110"] },
  { name: "evil-winrm", category: "Exploitation Tools", description: "WinRM shell for hacking", techniques: ["T1021.006"] },
  { name: "impacket", category: "Exploitation Tools", description: "Network protocol toolkit", techniques: ["T1021.002", "T1021.003", "T1047", "T1550.002", "T1558"] },
  { name: "responder", category: "Exploitation Tools", description: "LLMNR/NBT-NS/mDNS poisoner", techniques: ["T1557.001", "T1040"] },
  { name: "bettercap", category: "Exploitation Tools", description: "Network attack and monitoring framework", techniques: ["T1557", "T1040", "T1071"] },
  // Password Attacks
  { name: "john", category: "Password Attacks", description: "John the Ripper password cracker", techniques: ["T1110.002", "T1003"] },
  { name: "hashcat", category: "Password Attacks", description: "Advanced password recovery", techniques: ["T1110.002", "T1003"] },
  { name: "hydra", category: "Password Attacks", description: "Network logon cracker", techniques: ["T1110.001", "T1110.003"] },
  { name: "medusa", category: "Password Attacks", description: "Parallel network login auditor", techniques: ["T1110.001"] },
  { name: "cewl", category: "Password Attacks", description: "Custom word list generator", techniques: ["T1589.001", "T1110.002"] },
  { name: "crunch", category: "Password Attacks", description: "Wordlist generator", techniques: ["T1110.002"] },
  { name: "mimikatz", category: "Password Attacks", description: "Windows credential extraction", techniques: ["T1003.001", "T1003.002", "T1003.004", "T1003.005", "T1558.003", "T1550.002"] },
  { name: "rubeus", category: "Password Attacks", description: "Kerberos abuse toolkit", techniques: ["T1558.003", "T1558.004", "T1550.003"] },
  // Wireless Attacks
  { name: "aircrack-ng", category: "Wireless Attacks", description: "WiFi security auditing tools", techniques: ["T1557", "T1040"] },
  { name: "wifite", category: "Wireless Attacks", description: "Automated wireless attack tool", techniques: ["T1557"] },
  { name: "fern-wifi-cracker", category: "Wireless Attacks", description: "WiFi security auditing", techniques: ["T1557"] },
  // Web Application Analysis
  { name: "burpsuite", category: "Web Application Analysis", description: "Web vulnerability scanner", techniques: ["T1190", "T1595.002"] },
  { name: "zaproxy", category: "Web Application Analysis", description: "OWASP ZAP web app scanner", techniques: ["T1190", "T1595.002"] },
  { name: "gobuster", category: "Web Application Analysis", description: "Directory/file brute-forcer", techniques: ["T1595.003"] },
  { name: "dirb", category: "Web Application Analysis", description: "Web content scanner", techniques: ["T1595.003"] },
  { name: "ffuf", category: "Web Application Analysis", description: "Fast web fuzzer", techniques: ["T1595.003", "T1190"] },
  { name: "wfuzz", category: "Web Application Analysis", description: "Web application fuzzer", techniques: ["T1190", "T1595.003"] },
  // Sniffing & Spoofing
  { name: "wireshark", category: "Sniffing & Spoofing", description: "Network protocol analyzer", techniques: ["T1040"] },
  { name: "tcpdump", category: "Sniffing & Spoofing", description: "Command-line packet analyzer", techniques: ["T1040"] },
  { name: "ettercap", category: "Sniffing & Spoofing", description: "Man-in-the-middle attack suite", techniques: ["T1557", "T1040"] },
  { name: "mitmproxy", category: "Sniffing & Spoofing", description: "Interactive HTTPS proxy", techniques: ["T1557", "T1040"] },
  // Post Exploitation
  { name: "powershell-empire", category: "Post Exploitation", description: "PowerShell post-exploitation agent", techniques: ["T1059.001", "T1071.001", "T1132", "T1573"] },
  { name: "bloodhound", category: "Post Exploitation", description: "Active Directory attack path mapping", techniques: ["T1087.002", "T1069.002", "T1482"] },
  { name: "covenant", category: "Post Exploitation", description: ".NET C2 framework", techniques: ["T1059.001", "T1071.001", "T1573"] },
  { name: "chisel", category: "Post Exploitation", description: "TCP/UDP tunnel over HTTP", techniques: ["T1572", "T1090"] },
  { name: "ligolo-ng", category: "Post Exploitation", description: "Tunneling/pivoting tool", techniques: ["T1572", "T1090"] },
  { name: "linpeas", category: "Post Exploitation", description: "Linux privilege escalation audit", techniques: ["T1548", "T1068"] },
  { name: "winpeas", category: "Post Exploitation", description: "Windows privilege escalation audit", techniques: ["T1548", "T1068"] },
  { name: "pspy", category: "Post Exploitation", description: "Monitor Linux processes without root", techniques: ["T1057", "T1049"] },
  // Reverse Engineering
  { name: "ghidra", category: "Reverse Engineering", description: "Software reverse engineering framework", techniques: ["T1588.002"] },
  { name: "radare2", category: "Reverse Engineering", description: "Reverse engineering framework", techniques: ["T1588.002"] },
  { name: "gdb", category: "Reverse Engineering", description: "GNU debugger", techniques: ["T1588.002"] },
  // Social Engineering
  { name: "set", category: "Social Engineering", description: "Social Engineering Toolkit", techniques: ["T1566.001", "T1566.002", "T1204.001", "T1204.002"] },
  { name: "gophish", category: "Social Engineering", description: "Phishing framework", techniques: ["T1566.001", "T1566.002", "T1598"] },
  { name: "king-phisher", category: "Social Engineering", description: "Phishing campaign toolkit", techniques: ["T1566.001", "T1566.002"] },
  // Forensics
  { name: "autopsy", category: "Forensics", description: "Digital forensics platform", techniques: [] },
  { name: "volatility", category: "Forensics", description: "Memory forensics framework", techniques: ["T1003"] },
  { name: "binwalk", category: "Forensics", description: "Firmware analysis tool", techniques: [] },
  // Reporting
  { name: "faraday", category: "Reporting", description: "Collaborative penetration test IDE", techniques: [] },
  { name: "dradis", category: "Reporting", description: "Collaboration and reporting platform", techniques: [] },
];

/**
 * Get the Kali Linux tools catalog with ATT&CK mappings.
 */
export function getKaliToolsCatalog() {
  return KALI_TOOLS_CATALOG;
}

/**
 * Get Kali tools mapped to a specific technique ID.
 */
export function getKaliToolsForTechnique(techniqueId: string): typeof KALI_TOOLS_CATALOG {
  return KALI_TOOLS_CATALOG.filter((t) => t.techniques.includes(techniqueId));
}

// ─── Full Ingestion Pipeline ─────────────────────────────────────────────

/**
 * Run the full ingestion pipeline:
 * 1. Download ATT&CK STIX → create base technique entries
 * 2. Download Atomic Red Team → add test commands
 * 3. Download LOLBAS → add LOLBin data
 * 4. Map Kali tools → add offensive tool mappings
 * 5. Download Metasploit → add exploit data
 * 
 * This creates the foundation that the LLM enrichment engine then enhances.
 */
export async function runFullIngestion(options?: {
  skipAttack?: boolean;
  skipAtomic?: boolean;
  skipLolbas?: boolean;
  skipMetasploit?: boolean;
  maxTechniques?: number;
}): Promise<{
  attackStats: { techniques: number; groups: number; software: number } | null;
  atomicStats: { techniquesWithTests: number } | null;
  lolbasStats: { techniquesWithLolbins: number; totalLolbins: number } | null;
  metasploitStats: { exploits: number; auxiliary: number; post: number; total: number } | null;
  kaliStats: { tools: number; categories: number };
  totalTechniquesIngested: number;
  errors: string[];
}> {
  const errors: string[] = [];
  let attackData: Awaited<ReturnType<typeof ingestAttackStix>> | null = null;
  let atomicData: Map<string, any> | null = null;
  let lolbasData: Map<string, any> | null = null;
  let metasploitData: Awaited<ReturnType<typeof ingestMetasploitModules>> | null = null;

  // Step 1: Download ATT&CK STIX
  if (!options?.skipAttack) {
    try {
      attackData = await ingestAttackStix();
    } catch (err: any) {
      errors.push(`ATT&CK STIX: ${err.message}`);
    }
  }

  // Step 2: Download Atomic Red Team
  if (!options?.skipAtomic) {
    try {
      atomicData = await ingestAtomicRedTeamIndex();
    } catch (err: any) {
      errors.push(`Atomic Red Team: ${err.message}`);
    }
  }

  // Step 3: Download LOLBAS
  if (!options?.skipLolbas) {
    try {
      lolbasData = await ingestLolbas();
    } catch (err: any) {
      errors.push(`LOLBAS: ${err.message}`);
    }
  }

  // Step 4: Download Metasploit
  if (!options?.skipMetasploit) {
    try {
      metasploitData = await ingestMetasploitModules();
    } catch (err: any) {
      errors.push(`Metasploit: ${err.message}`);
    }
  }

  // Step 5: Combine and store
  let totalIngested = 0;
  if (attackData) {
    const techniques = options?.maxTechniques
      ? attackData.techniques.slice(0, options.maxTechniques)
      : attackData.techniques;

    for (const tech of techniques) {
      try {
        // Check if already exists with full enrichment
        const existing = await db.getTtpKnowledge(tech.id);
        if (existing && existing.dataSource === "llm-enriched" && existing.confidence && existing.confidence >= 75) {
          // Already fully enriched, just update base data
          continue;
        }

        // Build base entry from ATT&CK data
        const entry: InsertTtpKnowledge = {
          techniqueId: tech.id,
          techniqueName: tech.name,
          tactic: tech.tactic,
          description: tech.description,
          executionMethods: [],
          toolsUsed: [],
          iocPatterns: [],
          artifacts: [],
          detectionRules: [],
          eventLogSources: [],
          calderaAbilities: [],
          attackChainPosition: tech.tactic.split(",")[0]?.trim() || "unknown",
          prerequisiteTechniques: [],
          followUpTechniques: [],
          defensiveGaps: [],
          redTeamValue: 5,
          blueTeamPriority: 5,
          purpleTeamNotes: "",
          dataSource: "mitre-stix",
          confidence: 40,
          lastEnriched: new Date(),
        };

        // Add Atomic Red Team test data
        if (atomicData?.has(tech.id)) {
          const tests = atomicData.get(tech.id)!;
          entry.executionMethods = tests.map((t: any) => ({
            method: t.name,
            tools: ["Atomic Red Team"],
            commands: [],
            prerequisites: [],
            platforms: t.platforms,
          }));
          entry.confidence = 50; // Higher confidence with atomic tests
        }

        // Add LOLBAS data
        if (lolbasData?.has(tech.id)) {
          const lolbins = lolbasData.get(tech.id)!;
          const existingTools = entry.toolsUsed as any[] || [];
          for (const lb of lolbins) {
            existingTools.push({
              name: lb.binary,
              type: "native",
              description: `LOLBin: ${lb.description}. Command: ${lb.command.substring(0, 200)}`,
              commonActors: [],
            });
          }
          entry.toolsUsed = existingTools;
          // Add LOLBAS IOCs
          const existingIocs = entry.iocPatterns as any[] || [];
          for (const lb of lolbins) {
            for (const ioc of lb.iocs) {
              existingIocs.push({
                type: "process",
                pattern: ioc,
                description: `LOLBAS detection: ${lb.binary}`,
                confidence: "medium",
                volatility: "low",
              });
            }
          }
          entry.iocPatterns = existingIocs;
          entry.confidence = Math.max(entry.confidence || 0, 55);
        }

        // Add Kali tools
        const kaliTools = getKaliToolsForTechnique(tech.id);
        if (kaliTools.length > 0) {
          const existingTools = entry.toolsUsed as any[] || [];
          for (const kt of kaliTools) {
            existingTools.push({
              name: kt.name,
              type: "offensive",
              description: `Kali Linux: ${kt.description} (${kt.category})`,
              commonActors: [],
            });
          }
          entry.toolsUsed = existingTools;
        }

        // Add Metasploit module references
        if (metasploitData) {
          const relatedExploits = metasploitData.exploits
            .filter((e) => {
              const pathParts = e.fullname.toLowerCase();
              const techName = tech.name.toLowerCase().split(" ").slice(0, 2).join(" ");
              return pathParts.includes(techName) || e.description.toLowerCase().includes(techName);
            })
            .slice(0, 5);

          if (relatedExploits.length > 0) {
            const existingTools = entry.toolsUsed as any[] || [];
            for (const exploit of relatedExploits) {
              existingTools.push({
                name: `Metasploit: ${exploit.fullname}`,
                type: "offensive",
                description: exploit.description.substring(0, 200),
                commonActors: [],
              });
            }
            entry.toolsUsed = existingTools;
            entry.confidence = Math.max(entry.confidence || 0, 55);
          }
        }

        await db.upsertTtpKnowledge(entry);
        totalIngested++;
      } catch (err: any) {
        errors.push(`Technique ${tech.id}: ${err.message}`);
      }
    }
  }

  const kaliCategories = new Set(KALI_TOOLS_CATALOG.map((t) => t.category));

  return {
    attackStats: attackData?.stats || null,
    atomicStats: atomicData ? { techniquesWithTests: atomicData.size } : null,
    lolbasStats: lolbasData ? {
      techniquesWithLolbins: lolbasData.size,
      totalLolbins: Array.from(lolbasData.values()).reduce((sum, arr) => sum + arr.length, 0),
    } : null,
    metasploitStats: metasploitData?.stats || null,
    kaliStats: { tools: KALI_TOOLS_CATALOG.length, categories: kaliCategories.size },
    totalTechniquesIngested: totalIngested,
    errors,
  };
}
