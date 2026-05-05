/**
 * DI Threat Matching & Attack Path Analysis
 *
 * Deterministic (non-LLM) engine that cross-references the DI scan's discovered
 * attack surface against the master threat group catalog to:
 *
 * 1. Identify which threat groups' TTPs overlap with the target's profile
 * 2. Synthesize realistic attack paths from confirmed scan findings
 * 3. Build a MITRE ATT&CK technique heatmap showing surface-relevant techniques
 *
 * Scoring Dimensions (weighted):
 *   - CVE exploitation overlap (30%)  — groups that exploit CVEs found on target
 *   - MITRE ATT&CK technique alignment (25%) — technique overlap with discovered services
 *   - Tooling/technology correlation (20%) — tools that match detected tech stack
 *   - Sector targeting relevance (15%) — groups known to target this sector
 *   - Initial access method applicability (10%) — IA methods viable against surface
 *
 * Sources: threat-group-knowledge.ts master catalog, DI pipeline scan data
 */

import type { AssetAnalysis, KevEnrichment, OrgProfile } from "../domainIntel";
import type { CrossModuleEnrichmentResult } from "./cross-module-enrichment";
import {
  getAllGroups,
  type ThreatGroupKnowledge,
  type ThreatGroupTTP,
} from "./threat-group-knowledge";

// ─── Output Types ──────────────────────────────────────────────────────────

export interface DIThreatMatchResult {
  matchedGroups: MatchedThreatGroup[];
  attackPaths: SynthesizedAttackPath[];
  techniqueHeatmap: TechniqueHeatmapEntry[];
  summary: {
    totalGroupsAnalyzed: number;
    totalMatched: number;
    topGroupName: string | null;
    topGroupScore: number;
    totalAttackPaths: number;
    uniqueTechniques: number;
    uniqueTactics: number;
  };
}

export interface MatchedThreatGroup {
  groupId: string;
  groupName: string;
  aliases: string[];
  groupType: string;
  origin: string;
  threatLevel: string;
  active: boolean;
  motivation: string;
  targetSectors: string[];
  matchScore: number;           // 0-100
  riskLevel: string;            // critical | high | medium | low
  matchRationale: string;       // Human-readable reasoning paragraph
  // Evidence of overlap
  matchedCVEs: string[];
  matchedTechniques: Array<{ id: string; name: string; tactic: string }>;
  matchedTools: string[];
  matchedInitialAccess: string[];
  sectorRelevance: number;      // 0-100
  // Group's primary TTPs for display
  primaryTTPs: Array<{ id: string; name: string; tactic: string }>;
  defenseRecommendations: string[];
  // Scoring breakdown
  scoreBreakdown: {
    cveScore: number;
    techniqueScore: number;
    toolScore: number;
    sectorScore: number;
    initialAccessScore: number;
  };
}

export interface SynthesizedAttackPath {
  id: string;
  name: string;
  description: string;
  steps: AttackPathStep[];
  overallRisk: number;          // 0-100
  likelihood: number;           // 1-5
  impact: number;               // 1-5
  attributedGroups: string[];   // Group names that use this pattern
  tacticsTraversed: string[];   // Kill chain phases covered
}

export interface AttackPathStep {
  order: number;
  phase: string;                // Kill chain phase
  mitreTechnique: string;       // T-code
  techniqueName: string;
  targetAsset: string;          // Hostname
  evidence: string;             // What scan finding supports this step
  difficulty: string;           // trivial | easy | moderate | hard
}

export interface TechniqueHeatmapEntry {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  groups: string[];             // Group names that use this technique
  surfaceRelevant: boolean;     // True if technique maps to a scan finding
  relatedFinding: string | null;
}

// ─── Technique-to-Service Mapping ──────────────────────────────────────────
// Maps MITRE ATT&CK technique IDs to services/technologies they target.
// Used to determine if a technique is "surface relevant" given discovered services.

const TECHNIQUE_SERVICE_MAP: Record<string, string[]> = {
  "T1190": ["http", "https", "web", "apache", "nginx", "iis", "tomcat", "wordpress", "drupal", "joomla", "php", "java", "node", "express", "next.js", "react", "vue"],
  "T1133": ["vpn", "rdp", "ssh", "citrix", "pulse", "fortinet", "paloalto", "sonicwall"],
  "T1078": ["ssh", "rdp", "ftp", "smtp", "imap", "pop3", "ldap", "active directory", "microsoft 365", "google workspace"],
  "T1566": ["smtp", "email", "exchange", "microsoft 365", "google workspace", "mail"],
  "T1059": ["powershell", "cmd", "bash", "python", "javascript", "node"],
  "T1021": ["smb", "rdp", "ssh", "winrm", "wmi", "psexec"],
  "T1110": ["ssh", "rdp", "ftp", "smtp", "http", "https", "ldap", "mysql", "postgres", "mssql"],
  "T1505": ["http", "https", "apache", "nginx", "iis", "tomcat", "php", "asp", "jsp"],
  "T1071": ["http", "https", "dns", "smtp"],
  "T1048": ["ftp", "http", "https", "dns", "smtp", "cloud"],
  "T1053": ["cron", "at", "scheduled task", "systemd"],
  "T1098": ["active directory", "azure ad", "ldap", "iam"],
  "T1136": ["active directory", "ldap", "iam", "cloud"],
  "T1003": ["active directory", "lsass", "sam", "ntds"],
  "T1486": ["smb", "cifs", "nfs", "file server"],
  "T1499": ["http", "https", "dns", "web"],
  "T1595": ["http", "https", "dns", "web", "shodan"],
  "T1592": ["http", "https", "web", "dns"],
  "T1589": ["email", "linkedin", "social media"],
  "T1583": ["dns", "domain", "hosting"],
  "T1588": ["exploit", "malware", "c2"],
  "T1203": ["pdf", "office", "browser", "flash", "java"],
  "T1210": ["smb", "rdp", "ssh", "rpc", "ms17-010", "eternalblue"],
  "T1046": ["nmap", "port scan", "network"],
  "T1018": ["active directory", "dns", "ldap", "network"],
  "T1082": ["system", "os", "kernel"],
  "T1083": ["file system", "smb", "nfs"],
  "T1105": ["http", "https", "ftp", "smb", "dns"],
  "T1027": ["malware", "obfuscation"],
  "T1070": ["log", "syslog", "event log"],
  "T1562": ["edr", "antivirus", "firewall", "waf"],
  "T1219": ["rdp", "vnc", "teamviewer", "anydesk"],
  "T1572": ["ssh", "dns", "http", "https"],
  "T1573": ["ssl", "tls", "https", "c2"],
  "T1041": ["http", "https", "ftp", "dns", "c2"],
  "T1567": ["cloud", "google drive", "dropbox", "onedrive", "s3"],
  "T1557": ["arp", "dns", "llmnr", "nbns", "network"],
  "T1040": ["network", "wireshark", "tcpdump"],
  "T1560": ["archive", "zip", "rar", "7z"],
  "T1114": ["email", "exchange", "microsoft 365", "gmail", "imap"],
  "T1213": ["sharepoint", "confluence", "wiki", "intranet"],
  "T1530": ["s3", "azure blob", "gcs", "cloud storage"],
  "T1552": ["git", "github", "config", "env", "credentials"],
  "T1087": ["active directory", "ldap", "net user"],
  "T1069": ["active directory", "ldap", "group policy"],
  "T1016": ["network", "ipconfig", "ifconfig"],
  "T1049": ["network", "netstat", "ss"],
  "T1518": ["software", "installed programs"],
  "T1047": ["wmi", "wmic", "windows"],
  "T1543": ["systemd", "service", "daemon", "windows service"],
  "T1547": ["registry", "startup", "autorun", "cron"],
  "T1053.005": ["cron", "crontab", "scheduled task"],
  "T1059.001": ["powershell"],
  "T1059.003": ["cmd", "command prompt", "windows"],
  "T1059.004": ["bash", "sh", "linux", "unix"],
};

// ─── Initial Access Method Mapping ─────────────────────────────────────────
// Maps initial access method descriptions to services/ports that enable them.

const IA_METHOD_SERVICE_MAP: Record<string, string[]> = {
  "spear phishing": ["smtp", "email", "exchange", "mail"],
  "phishing": ["smtp", "email", "exchange", "mail"],
  "exploit public-facing application": ["http", "https", "web", "apache", "nginx", "iis", "tomcat"],
  "valid accounts": ["ssh", "rdp", "vpn", "ftp", "smtp"],
  "external remote services": ["vpn", "rdp", "ssh", "citrix"],
  "drive-by compromise": ["http", "https", "web"],
  "supply chain compromise": ["npm", "pypi", "maven", "docker", "github"],
  "trusted relationship": ["vpn", "api", "oauth"],
  "hardware additions": ["usb", "physical"],
  "replication through removable media": ["usb", "physical"],
  "brute force": ["ssh", "rdp", "ftp", "http", "smtp", "mysql", "postgres"],
  "default credentials": ["ssh", "ftp", "telnet", "http", "snmp"],
  "sql injection": ["http", "https", "mysql", "postgres", "mssql", "web"],
  "remote code execution": ["http", "https", "web", "rpc", "smb"],
  "watering hole": ["http", "https", "web", "dns"],
};

// ─── Core Matching Engine ──────────────────────────────────────────────────

/**
 * Extract a fingerprint from the DI scan results for matching.
 */
function extractScanFingerprint(
  analyses: AssetAnalysis[],
  org: OrgProfile,
  kevEnrichment?: KevEnrichment,
  crossModuleEnrichment?: CrossModuleEnrichmentResult,
): {
  cves: Set<string>;
  technologies: Set<string>;
  services: Set<string>;
  ports: Set<number>;
  sectors: string[];
  techniques: Set<string>;
  findings: Map<string, { hostname: string; title: string; severity: number }>;
} {
  const cves = new Set<string>();
  const technologies = new Set<string>();
  const services = new Set<string>();
  const ports = new Set<number>();
  const techniques = new Set<string>();
  const findings = new Map<string, { hostname: string; title: string; severity: number }>();

  for (const analysis of analyses) {
    // Technologies
    if (analysis.asset.technologies) {
      for (const tech of analysis.asset.technologies) {
        technologies.add(tech.toLowerCase());
      }
    }

    // Tags as services
    if (analysis.asset.tags) {
      for (const tag of analysis.asset.tags) {
        services.add(tag.toLowerCase());
      }
    }

    // Asset type as service indicator
    if (analysis.asset.assetType) {
      services.add(analysis.asset.assetType.toLowerCase());
    }

    // Posture findings → CVEs and techniques
    for (const finding of analysis.postureFindings || []) {
      if (finding.cveIds) {
        for (const cve of finding.cveIds) {
          cves.add(cve);
          findings.set(cve, {
            hostname: analysis.asset.hostname,
            title: finding.title,
            severity: finding.severity,
          });
        }
      }
      // Extract CVEs from title
      const titleCves = finding.title?.match(/CVE-\d{4}-\d+/g) || [];
      for (const cve of titleCves) {
        cves.add(cve);
        if (!findings.has(cve)) {
          findings.set(cve, {
            hostname: analysis.asset.hostname,
            title: finding.title,
            severity: finding.severity,
          });
        }
      }
    }

    // Test vectors → techniques
    for (const tv of analysis.testVectors || []) {
      if (tv.suggestedEmulation?.technique) {
        techniques.add(tv.suggestedEmulation.technique);
      }
    }
  }

  // KEV enrichment → additional CVEs
  if (kevEnrichment?.matches) {
    for (const m of kevEnrichment.matches) {
      cves.add(m.cveId);
    }
  }

  // Cross-module threat intel → additional techniques
  if (crossModuleEnrichment?.threatIntel?.matchingThreatActors) {
    for (const actor of crossModuleEnrichment.threatIntel.matchingThreatActors) {
      for (const tech of actor.techniques || []) {
        techniques.add(tech);
      }
    }
  }

  // Infer services from technologies
  const techServiceMap: Record<string, string[]> = {
    "apache": ["http", "web"], "nginx": ["http", "web"], "iis": ["http", "web"],
    "tomcat": ["http", "web", "java"], "wordpress": ["http", "web", "php"],
    "drupal": ["http", "web", "php"], "joomla": ["http", "web", "php"],
    "exchange": ["smtp", "email"], "postfix": ["smtp", "email"],
    "openssh": ["ssh"], "proftpd": ["ftp"], "vsftpd": ["ftp"],
    "mysql": ["mysql", "database"], "postgres": ["postgres", "database"],
    "mongodb": ["mongodb", "database"], "redis": ["redis", "database"],
    "docker": ["docker", "container"], "kubernetes": ["kubernetes", "container"],
    "jenkins": ["jenkins", "ci"], "gitlab": ["gitlab", "ci"],
    "microsoft 365": ["email", "cloud"], "google workspace": ["email", "cloud"],
  };
  for (const tech of technologies) {
    const mapped = Object.entries(techServiceMap).find(([k]) => tech.includes(k));
    if (mapped) {
      for (const svc of mapped[1]) services.add(svc);
    }
  }

  return {
    cves,
    technologies,
    services,
    ports,
    sectors: [org.sector, ...(org.complianceFlags || [])].filter(Boolean),
    techniques,
    findings,
  };
}

/**
 * Score a single threat group against the scan fingerprint.
 */
function scoreGroup(
  group: ThreatGroupKnowledge,
  fingerprint: ReturnType<typeof extractScanFingerprint>,
): MatchedThreatGroup | null {
  const matchedCVEs: string[] = [];
  const matchedTechniques: Array<{ id: string; name: string; tactic: string }> = [];
  const matchedTools: string[] = [];
  const matchedInitialAccess: string[] = [];

  // 1. CVE overlap (weight: 30%)
  for (const cve of group.exploitedCVEs) {
    if (fingerprint.cves.has(cve)) {
      matchedCVEs.push(cve);
    }
  }
  const cveScore = group.exploitedCVEs.length > 0
    ? Math.min(100, (matchedCVEs.length / Math.min(group.exploitedCVEs.length, 5)) * 100)
    : 0;

  // 2. Technique overlap (weight: 25%)
  const allServices = [...fingerprint.services, ...fingerprint.technologies];
  for (const ttp of group.ttps) {
    // Direct technique match
    if (fingerprint.techniques.has(ttp.techniqueId)) {
      matchedTechniques.push({ id: ttp.techniqueId, name: ttp.techniqueName, tactic: ttp.tactic });
      continue;
    }
    // Service-based technique relevance
    const relevantServices = TECHNIQUE_SERVICE_MAP[ttp.techniqueId] || [];
    const hasRelevantService = relevantServices.some(svc =>
      allServices.some(s => s.includes(svc))
    );
    if (hasRelevantService) {
      matchedTechniques.push({ id: ttp.techniqueId, name: ttp.techniqueName, tactic: ttp.tactic });
    }
  }
  const techniqueScore = group.ttps.length > 0
    ? Math.min(100, (matchedTechniques.length / Math.min(group.ttps.length, 8)) * 100)
    : 0;

  // 3. Tool/technology overlap (weight: 20%)
  for (const tool of group.tools) {
    const toolLower = tool.name.toLowerCase();
    if (fingerprint.technologies.has(toolLower) ||
        [...fingerprint.technologies].some(t => t.includes(toolLower) || toolLower.includes(t))) {
      matchedTools.push(tool.name);
    }
  }
  const toolScore = group.tools.length > 0
    ? Math.min(100, (matchedTools.length / Math.min(group.tools.length, 5)) * 100)
    : 0;

  // 4. Sector relevance (weight: 15%)
  const sectorLower = fingerprint.sectors.map(s => s.toLowerCase());
  const sectorMatches = group.targetSectors.filter(gs =>
    sectorLower.some(s => s.includes(gs.toLowerCase()) || gs.toLowerCase().includes(s))
  );
  const sectorScore = group.targetSectors.length > 0
    ? Math.min(100, (sectorMatches.length / Math.min(group.targetSectors.length, 3)) * 100)
    : 0;

  // 5. Initial access method applicability (weight: 10%)
  for (const method of group.initialAccessMethods) {
    const methodLower = method.toLowerCase();
    const relevantServices = Object.entries(IA_METHOD_SERVICE_MAP).find(([k]) =>
      methodLower.includes(k)
    );
    if (relevantServices) {
      const hasService = relevantServices[1].some(svc =>
        allServices.some(s => s.includes(svc))
      );
      if (hasService) {
        matchedInitialAccess.push(method);
      }
    }
  }
  const iaScore = group.initialAccessMethods.length > 0
    ? Math.min(100, (matchedInitialAccess.length / Math.min(group.initialAccessMethods.length, 3)) * 100)
    : 0;

  // Weighted total
  const matchScore = Math.round(
    cveScore * 0.30 +
    techniqueScore * 0.25 +
    toolScore * 0.20 +
    sectorScore * 0.15 +
    iaScore * 0.10
  );

  // Minimum threshold: at least 15 to be considered a match
  if (matchScore < 15 && matchedCVEs.length === 0) return null;

  // Risk level
  const riskLevel = matchScore >= 70 ? "critical" :
    matchScore >= 50 ? "high" :
    matchScore >= 30 ? "medium" : "low";

  // Build match rationale — the key reasoning paragraph
  const rationaleParts: string[] = [];
  if (matchedCVEs.length > 0) {
    const cveDetails = matchedCVEs.slice(0, 3).map(cve => {
      const f = fingerprint.findings.get(cve);
      return f ? `${cve} (found on ${f.hostname}, severity ${f.severity}/10)` : cve;
    });
    rationaleParts.push(`${group.name} is known to exploit ${matchedCVEs.length} CVE(s) that were discovered on the target's attack surface: ${cveDetails.join(', ')}. This indicates the group has demonstrated capability and intent to leverage these specific vulnerabilities.`);
  }
  if (matchedTechniques.length > 0) {
    const tacticSet = [...new Set(matchedTechniques.map(t => t.tactic))];
    rationaleParts.push(`${matchedTechniques.length} of the group's preferred MITRE ATT&CK techniques align with services discovered on the target, spanning ${tacticSet.length} tactic(s): ${tacticSet.join(', ')}. Key techniques include ${matchedTechniques.slice(0, 3).map(t => `${t.id} (${t.name})`).join(', ')}.`);
  }
  if (matchedTools.length > 0) {
    rationaleParts.push(`The group's known toolset includes ${matchedTools.join(', ')}, which correlate with technologies detected on the target infrastructure.`);
  }
  if (sectorMatches.length > 0) {
    rationaleParts.push(`${group.name} actively targets the ${sectorMatches.join(', ')} sector(s), which aligns with the target organization's profile.`);
  }
  if (matchedInitialAccess.length > 0) {
    rationaleParts.push(`The group's initial access methods (${matchedInitialAccess.join(', ')}) are viable against the discovered attack surface.`);
  }

  // Attribution hedging: prefix with confidence qualifier to avoid definitive attribution
  // Reports should say "patterns consistent with" not "targeted by"
  const hedgingPrefix = matchScore >= 80
    ? `The observed attack surface exhibits patterns strongly consistent with ${group.name}'s known operational profile. `
    : matchScore >= 60
    ? `The target's infrastructure shows characteristics moderately consistent with ${group.name}'s documented TTPs. `
    : `Some indicators suggest possible — but unconfirmed — alignment with ${group.name}'s operational patterns. `;
  const hedgingSuffix = ` Note: This is a behavioral pattern match, not a definitive attribution. Multiple threat actors may exhibit similar TTPs.`;
  const matchRationale = rationaleParts.length > 0
    ? hedgingPrefix + rationaleParts.join(' ') + hedgingSuffix
    : `${group.name} shows general profile overlap based on sector targeting and technique applicability. This represents pattern similarity, not confirmed attribution.`;

  return {
    groupId: group.id,
    groupName: group.name,
    aliases: group.aliases,
    groupType: group.type,
    origin: group.origin,
    threatLevel: group.threatLevel,
    active: group.active,
    motivation: group.motivation,
    targetSectors: group.targetSectors,
    matchScore,
    riskLevel,
    matchRationale,
    matchedCVEs,
    matchedTechniques,
    matchedTools,
    matchedInitialAccess,
    sectorRelevance: sectorScore,
    primaryTTPs: group.ttps
      .filter(t => t.frequency === "primary")
      .slice(0, 10)
      .map(t => ({ id: t.techniqueId, name: t.techniqueName, tactic: t.tactic })),
    defenseRecommendations: group.defenseRecommendations
      .filter(r => r.priority === "critical" || r.priority === "high")
      .slice(0, 5)
      .map(r => r.recommendation),
    scoreBreakdown: {
      cveScore: Math.round(cveScore),
      techniqueScore: Math.round(techniqueScore),
      toolScore: Math.round(toolScore),
      sectorScore: Math.round(sectorScore),
      initialAccessScore: Math.round(iaScore),
    },
  };
}

// ─── Attack Path Synthesis ─────────────────────────────────────────────────

/**
 * Synthesize attack paths from confirmed findings, grounded in matched groups' TTPs.
 */
function synthesizeAttackPaths(
  analyses: AssetAnalysis[],
  matchedGroups: MatchedThreatGroup[],
  fingerprint: ReturnType<typeof extractScanFingerprint>,
): SynthesizedAttackPath[] {
  const paths: SynthesizedAttackPath[] = [];
  let pathId = 0;

  // Collect all confirmed findings with CVEs
  const confirmedFindings: Array<{
    hostname: string;
    finding: string;
    severity: number;
    cves: string[];
    tier: string;
    technologies: string[];
  }> = [];

  for (const analysis of analyses) {
    for (const f of analysis.postureFindings || []) {
      if (f.corroborationTier === "confirmed" || f.corroborationTier === "probable") {
        const cves = f.cveIds || [];
        const titleCves = f.title?.match(/CVE-\d{4}-\d+/g) || [];
        confirmedFindings.push({
          hostname: analysis.asset.hostname,
          finding: f.title,
          severity: f.severity,
          cves: [...new Set([...cves, ...titleCves])],
          tier: f.corroborationTier,
          technologies: analysis.asset.technologies || [],
        });
      }
    }
  }

  // Sort by severity (highest first)
  confirmedFindings.sort((a, b) => b.severity - a.severity);

  // Path 1: External Exploitation → Credential Access → Lateral Movement
  const webFindings = confirmedFindings.filter(f =>
    f.technologies.some(t => ["http", "https", "web", "apache", "nginx", "iis", "tomcat", "php", "java", "node"].some(s => t.toLowerCase().includes(s))) ||
    f.finding.toLowerCase().includes("rce") || f.finding.toLowerCase().includes("injection") || f.finding.toLowerCase().includes("xss")
  );
  if (webFindings.length > 0) {
    const topWebFinding = webFindings[0];
    const steps: AttackPathStep[] = [
      {
        order: 1,
        phase: "Reconnaissance",
        mitreTechnique: "T1595",
        techniqueName: "Active Scanning",
        targetAsset: topWebFinding.hostname,
        evidence: `Discovered ${webFindings.length} web-facing asset(s) with confirmed vulnerabilities via passive scanning`,
        difficulty: "trivial",
      },
      {
        order: 2,
        phase: "Initial Access",
        mitreTechnique: "T1190",
        techniqueName: "Exploit Public-Facing Application",
        targetAsset: topWebFinding.hostname,
        evidence: `${topWebFinding.finding} (severity: ${topWebFinding.severity}/10, ${topWebFinding.tier})`,
        difficulty: topWebFinding.severity >= 8 ? "easy" : "moderate",
      },
    ];

    // Add credential access step if breach data or default creds exist
    const hasBreachData = fingerprint.findings.size > 0;
    if (hasBreachData) {
      steps.push({
        order: 3,
        phase: "Credential Access",
        mitreTechnique: "T1078",
        techniqueName: "Valid Accounts",
        targetAsset: topWebFinding.hostname,
        evidence: `${fingerprint.cves.size} CVE(s) discovered across attack surface; credential exposure likely via breach data or default credentials`,
        difficulty: "moderate",
      });
    }

    // Add lateral movement if multiple assets
    if (analyses.length > 1) {
      const otherAssets = analyses.filter(a => a.asset.hostname !== topWebFinding.hostname);
      if (otherAssets.length > 0) {
        steps.push({
          order: steps.length + 1,
          phase: "Lateral Movement",
          mitreTechnique: "T1021",
          techniqueName: "Remote Services",
          targetAsset: otherAssets[0].asset.hostname,
          evidence: `${otherAssets.length} additional asset(s) in the same infrastructure could be reached via pivoting`,
          difficulty: "moderate",
        });
      }
    }

    // Attribution
    const relevantGroups = matchedGroups
      .filter(g => g.matchedTechniques.some(t => t.id === "T1190" || t.id === "T1595"))
      .slice(0, 3)
      .map(g => g.groupName);

    const overallRisk = Math.min(100, Math.round(topWebFinding.severity * 10 + (steps.length * 5)));
    paths.push({
      id: `AP-${++pathId}`,
      name: "External Web Application Exploitation Chain",
      description: `An adversary exploits a confirmed vulnerability on ${topWebFinding.hostname} to gain initial access, then leverages the compromised position to access credentials and move laterally across ${analyses.length} discovered asset(s). This path is grounded in ${topWebFinding.finding}.`,
      steps,
      overallRisk,
      likelihood: topWebFinding.severity >= 8 ? 4 : 3,
      impact: 4,
      attributedGroups: relevantGroups,
      tacticsTraversed: [...new Set(steps.map(s => s.phase))],
    });
  }

  // Path 2: Credential Stuffing / Breach-Based Access
  const sshFindings = confirmedFindings.filter(f =>
    f.technologies.some(t => t.toLowerCase().includes("ssh") || t.toLowerCase().includes("openssh")) ||
    f.finding.toLowerCase().includes("ssh")
  );
  const emailFindings = confirmedFindings.filter(f =>
    f.technologies.some(t => ["smtp", "email", "exchange", "mail"].some(s => t.toLowerCase().includes(s)))
  );

  if (sshFindings.length > 0 || emailFindings.length > 0) {
    const targetFinding = sshFindings[0] || emailFindings[0];
    const steps: AttackPathStep[] = [
      {
        order: 1,
        phase: "Reconnaissance",
        mitreTechnique: "T1589",
        techniqueName: "Gather Victim Identity Information",
        targetAsset: targetFinding.hostname,
        evidence: `Employee email patterns and organizational structure discoverable via OSINT`,
        difficulty: "trivial",
      },
      {
        order: 2,
        phase: "Initial Access",
        mitreTechnique: "T1078",
        techniqueName: "Valid Accounts",
        targetAsset: targetFinding.hostname,
        evidence: `${targetFinding.finding} — credentials potentially available from breach databases`,
        difficulty: "easy",
      },
      {
        order: 3,
        phase: "Persistence",
        mitreTechnique: "T1098",
        techniqueName: "Account Manipulation",
        targetAsset: targetFinding.hostname,
        evidence: `Once authenticated, adversary can establish persistence via account modification`,
        difficulty: "moderate",
      },
    ];

    const relevantGroups = matchedGroups
      .filter(g => g.matchedInitialAccess.some(ia => ia.toLowerCase().includes("credential") || ia.toLowerCase().includes("brute") || ia.toLowerCase().includes("valid")))
      .slice(0, 3)
      .map(g => g.groupName);

    paths.push({
      id: `AP-${++pathId}`,
      name: "Credential-Based Initial Access",
      description: `An adversary leverages compromised credentials from breach databases or credential stuffing to authenticate to ${targetFinding.hostname}. The ${targetFinding.finding} finding indicates potential exposure. Once authenticated, the adversary establishes persistence.`,
      steps,
      overallRisk: Math.min(100, Math.round(targetFinding.severity * 8 + 20)),
      likelihood: 3,
      impact: 4,
      attributedGroups: relevantGroups,
      tacticsTraversed: [...new Set(steps.map(s => s.phase))],
    });
  }

  // Path 3: Phishing → Malware Delivery (if email services detected)
  const hasEmailService = [...fingerprint.services].some(s =>
    ["smtp", "email", "exchange", "mail", "microsoft 365", "google workspace"].some(e => s.includes(e))
  );
  if (hasEmailService) {
    const emailAsset = analyses.find(a =>
      (a.asset.technologies || []).some(t =>
        ["smtp", "email", "exchange", "mail"].some(e => t.toLowerCase().includes(e))
      )
    );
    const targetHost = emailAsset?.asset.hostname || analyses[0]?.asset.hostname || "target";

    const steps: AttackPathStep[] = [
      {
        order: 1,
        phase: "Reconnaissance",
        mitreTechnique: "T1592",
        techniqueName: "Gather Victim Host Information",
        targetAsset: targetHost,
        evidence: `Email infrastructure detected; employee email patterns discoverable via OSINT`,
        difficulty: "trivial",
      },
      {
        order: 2,
        phase: "Initial Access",
        mitreTechnique: "T1566",
        techniqueName: "Phishing",
        targetAsset: targetHost,
        evidence: `Email services present — spear phishing viable as initial access vector`,
        difficulty: "moderate",
      },
      {
        order: 3,
        phase: "Execution",
        mitreTechnique: "T1059",
        techniqueName: "Command and Scripting Interpreter",
        targetAsset: targetHost,
        evidence: `Post-phishing payload execution via scripting interpreter`,
        difficulty: "moderate",
      },
      {
        order: 4,
        phase: "Command and Control",
        mitreTechnique: "T1071",
        techniqueName: "Application Layer Protocol",
        targetAsset: targetHost,
        evidence: `C2 communication over standard HTTP/HTTPS to blend with legitimate traffic`,
        difficulty: "moderate",
      },
    ];

    const relevantGroups = matchedGroups
      .filter(g => g.matchedInitialAccess.some(ia => ia.toLowerCase().includes("phish")))
      .slice(0, 3)
      .map(g => g.groupName);

    paths.push({
      id: `AP-${++pathId}`,
      name: "Spear Phishing to Command & Control",
      description: `An adversary crafts targeted phishing emails leveraging discovered email infrastructure on ${targetHost}. After successful payload delivery, a C2 channel is established over standard protocols to evade detection.`,
      steps,
      overallRisk: 55,
      likelihood: 3,
      impact: 4,
      attributedGroups: relevantGroups,
      tacticsTraversed: [...new Set(steps.map(s => s.phase))],
    });
  }

  // Path 4: KEV-based exploitation (if KEV matches exist)
  const kevCves = [...fingerprint.cves].filter(cve => {
    const f = fingerprint.findings.get(cve);
    return f && f.severity >= 7;
  });
  if (kevCves.length > 0) {
    const topKevCve = kevCves[0];
    const topFinding = fingerprint.findings.get(topKevCve)!;
    const steps: AttackPathStep[] = [
      {
        order: 1,
        phase: "Initial Access",
        mitreTechnique: "T1190",
        techniqueName: "Exploit Public-Facing Application",
        targetAsset: topFinding.hostname,
        evidence: `${topKevCve}: ${topFinding.title} (severity: ${topFinding.severity}/10) — known exploited vulnerability`,
        difficulty: "easy",
      },
      {
        order: 2,
        phase: "Execution",
        mitreTechnique: "T1059",
        techniqueName: "Command and Scripting Interpreter",
        targetAsset: topFinding.hostname,
        evidence: `Post-exploitation command execution via ${topKevCve}`,
        difficulty: "easy",
      },
      {
        order: 3,
        phase: "Impact",
        mitreTechnique: "T1486",
        techniqueName: "Data Encrypted for Impact",
        targetAsset: topFinding.hostname,
        evidence: `Ransomware deployment possible after gaining execution capability`,
        difficulty: "moderate",
      },
    ];

    const relevantGroups = matchedGroups
      .filter(g => g.matchedCVEs.includes(topKevCve))
      .slice(0, 3)
      .map(g => g.groupName);

    paths.push({
      id: `AP-${++pathId}`,
      name: "Known Exploited Vulnerability to Ransomware",
      description: `An adversary exploits ${topKevCve} on ${topFinding.hostname}, a known exploited vulnerability with active exploitation in the wild. After gaining code execution, ransomware is deployed for maximum impact. This path represents the highest-confidence threat given the confirmed vulnerability.`,
      steps,
      overallRisk: Math.min(100, Math.round(topFinding.severity * 10 + 15)),
      likelihood: 4,
      impact: 5,
      attributedGroups: relevantGroups,
      tacticsTraversed: [...new Set(steps.map(s => s.phase))],
    });
  }

  // Sort paths by risk
  paths.sort((a, b) => b.overallRisk - a.overallRisk);
  return paths.slice(0, 6);
}

// ─── Technique Heatmap ─────────────────────────────────────────────────────

function buildTechniqueHeatmap(
  matchedGroups: MatchedThreatGroup[],
  fingerprint: ReturnType<typeof extractScanFingerprint>,
): TechniqueHeatmapEntry[] {
  const techniqueMap = new Map<string, {
    name: string;
    tactic: string;
    groups: Set<string>;
    surfaceRelevant: boolean;
    relatedFinding: string | null;
  }>();

  const allServices = [...fingerprint.services, ...fingerprint.technologies];

  for (const group of matchedGroups) {
    for (const ttp of group.primaryTTPs) {
      const existing = techniqueMap.get(ttp.id);
      if (existing) {
        existing.groups.add(group.groupName);
      } else {
        // Check surface relevance
        const relevantServices = TECHNIQUE_SERVICE_MAP[ttp.id] || [];
        const surfaceRelevant = relevantServices.some(svc =>
          allServices.some(s => s.includes(svc))
        );
        let relatedFinding: string | null = null;
        if (surfaceRelevant) {
          // Find a related finding
          for (const [cve, f] of fingerprint.findings) {
            if (f.severity >= 5) {
              relatedFinding = `${cve} on ${f.hostname}`;
              break;
            }
          }
        }

        techniqueMap.set(ttp.id, {
          name: ttp.name,
          tactic: ttp.tactic,
          groups: new Set([group.groupName]),
          surfaceRelevant,
          relatedFinding,
        });
      }
    }

    // Also add matched techniques
    for (const mt of group.matchedTechniques) {
      if (!techniqueMap.has(mt.id)) {
        techniqueMap.set(mt.id, {
          name: mt.name,
          tactic: mt.tactic,
          groups: new Set([group.groupName]),
          surfaceRelevant: true,
          relatedFinding: null,
        });
      } else {
        techniqueMap.get(mt.id)!.groups.add(group.groupName);
        techniqueMap.get(mt.id)!.surfaceRelevant = true;
      }
    }
  }

  return [...techniqueMap.entries()]
    .map(([id, data]) => ({
      techniqueId: id,
      techniqueName: data.name,
      tactic: data.tactic,
      groups: [...data.groups],
      surfaceRelevant: data.surfaceRelevant,
      relatedFinding: data.relatedFinding,
    }))
    .sort((a, b) => {
      // Surface-relevant first, then by group count
      if (a.surfaceRelevant !== b.surfaceRelevant) return a.surfaceRelevant ? -1 : 1;
      return b.groups.length - a.groups.length;
    });
}

// ─── Main Entry Point ──────────────────────────────────────────────────────

/**
 * Run deterministic threat actor matching and attack path analysis
 * against the DI scan results using the master threat group catalog.
 */
export function runDIThreatMatching(
  analyses: AssetAnalysis[],
  org: OrgProfile,
  kevEnrichment?: KevEnrichment,
  crossModuleEnrichment?: CrossModuleEnrichmentResult,
): DIThreatMatchResult {
  const allGroups = getAllGroups();
  const fingerprint = extractScanFingerprint(analyses, org, kevEnrichment, crossModuleEnrichment);

  // Score all groups
  const scored: MatchedThreatGroup[] = [];
  for (const group of allGroups) {
    const match = scoreGroup(group, fingerprint);
    if (match) scored.push(match);
  }

  // Sort by match score descending
  scored.sort((a, b) => b.matchScore - a.matchScore);
  const matchedGroups = scored.slice(0, 15);

  // Synthesize attack paths
  const attackPaths = synthesizeAttackPaths(analyses, matchedGroups, fingerprint);

  // Build technique heatmap
  const techniqueHeatmap = buildTechniqueHeatmap(matchedGroups, fingerprint);

  // Compute summary
  const allTechniques = new Set<string>();
  const allTactics = new Set<string>();
  for (const g of matchedGroups) {
    for (const t of g.matchedTechniques) {
      allTechniques.add(t.id);
      allTactics.add(t.tactic);
    }
    for (const t of g.primaryTTPs) {
      allTechniques.add(t.id);
      allTactics.add(t.tactic);
    }
  }

  return {
    matchedGroups,
    attackPaths,
    techniqueHeatmap,
    summary: {
      totalGroupsAnalyzed: allGroups.length,
      totalMatched: matchedGroups.length,
      topGroupName: matchedGroups[0]?.groupName || null,
      topGroupScore: matchedGroups[0]?.matchScore || 0,
      totalAttackPaths: attackPaths.length,
      uniqueTechniques: allTechniques.size,
      uniqueTactics: allTactics.size,
    },
  };
}
