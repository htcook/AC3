/**
 * Dynamic Attack Mapper — ScanForge Engine Module
 *
 * Maps discovered vulnerabilities and exploit results to the MITRE ATT&CK
 * kill chain to provide coverage analysis. Identifies:
 *   - Which kill chain phases were covered during the engagement
 *   - Which phases have gaps (no techniques exercised)
 *   - Attack path visualization data for reports
 *   - Contextual prompts for the LLM based on current coverage
 *
 * Used by the report pipeline for the "Kill Chain Coverage Analysis" section
 * and by the engagement orchestrator to guide exploitation decisions.
 *
 * Roadmap alignment: Gap R-4 (Attack Path Intelligence)
 */

// ─── MITRE ATT&CK Kill Chain Taxonomy ───────────────────────────────────────

export const MITRE_TACTICS = [
  { id: "TA0043", name: "Reconnaissance", shortName: "recon", order: 1 },
  { id: "TA0042", name: "Resource Development", shortName: "resource_dev", order: 2 },
  { id: "TA0001", name: "Initial Access", shortName: "initial_access", order: 3 },
  { id: "TA0002", name: "Execution", shortName: "execution", order: 4 },
  { id: "TA0003", name: "Persistence", shortName: "persistence", order: 5 },
  { id: "TA0004", name: "Privilege Escalation", shortName: "priv_esc", order: 6 },
  { id: "TA0005", name: "Defense Evasion", shortName: "defense_evasion", order: 7 },
  { id: "TA0006", name: "Credential Access", shortName: "cred_access", order: 8 },
  { id: "TA0007", name: "Discovery", shortName: "discovery", order: 9 },
  { id: "TA0008", name: "Lateral Movement", shortName: "lateral_movement", order: 10 },
  { id: "TA0009", name: "Collection", shortName: "collection", order: 11 },
  { id: "TA0011", name: "Command and Control", shortName: "c2", order: 12 },
  { id: "TA0010", name: "Exfiltration", shortName: "exfiltration", order: 13 },
  { id: "TA0040", name: "Impact", shortName: "impact", order: 14 },
] as const;

/** Map technique ID prefixes to their primary tactic */
const TECHNIQUE_TO_TACTIC: Record<string, string> = {
  "T1595": "TA0043", "T1592": "TA0043", "T1589": "TA0043", "T1590": "TA0043",
  "T1591": "TA0043", "T1598": "TA0043", "T1597": "TA0043", "T1596": "TA0043",
  "T1593": "TA0043", "T1594": "TA0043",
  "T1583": "TA0042", "T1584": "TA0042", "T1587": "TA0042", "T1588": "TA0042",
  "T1585": "TA0042", "T1586": "TA0042", "T1608": "TA0042",
  "T1189": "TA0001", "T1190": "TA0001", "T1133": "TA0001", "T1200": "TA0001",
  "T1566": "TA0001", "T1091": "TA0001", "T1195": "TA0001", "T1199": "TA0001",
  "T1078": "TA0001",
  "T1059": "TA0002", "T1203": "TA0002", "T1559": "TA0002", "T1106": "TA0002",
  "T1053": "TA0002", "T1129": "TA0002", "T1204": "TA0002", "T1047": "TA0002",
  "T1098": "TA0003", "T1197": "TA0003", "T1547": "TA0003", "T1037": "TA0003",
  "T1136": "TA0003", "T1543": "TA0003", "T1546": "TA0003", "T1133.001": "TA0003",
  "T1574": "TA0004", "T1055": "TA0004", "T1068": "TA0004",
  "T1140": "TA0005", "T1036": "TA0005", "T1027": "TA0005", "T1070": "TA0005",
  "T1202": "TA0005", "T1218": "TA0005", "T1562": "TA0005",
  "T1110": "TA0006", "T1003": "TA0006", "T1552": "TA0006", "T1555": "TA0006",
  "T1056": "TA0006", "T1557": "TA0006", "T1539": "TA0006", "T1528": "TA0006",
  "T1558": "TA0006",
  "T1087": "TA0007", "T1010": "TA0007", "T1217": "TA0007", "T1580": "TA0007",
  "T1046": "TA0007", "T1135": "TA0007", "T1040": "TA0007", "T1201": "TA0007",
  "T1018": "TA0007", "T1518": "TA0007", "T1082": "TA0007", "T1016": "TA0007",
  "T1049": "TA0007", "T1033": "TA0007",
  "T1210": "TA0008", "T1534": "TA0008", "T1570": "TA0008", "T1021": "TA0008",
  "T1080": "TA0008", "T1550": "TA0008",
  "T1560": "TA0009", "T1123": "TA0009", "T1119": "TA0009", "T1115": "TA0009",
  "T1530": "TA0009", "T1213": "TA0009", "T1005": "TA0009", "T1039": "TA0009",
  "T1025": "TA0009", "T1074": "TA0009", "T1114": "TA0009", "T1113": "TA0009",
  "T1125": "TA0009",
  "T1071": "TA0011", "T1132": "TA0011", "T1001": "TA0011", "T1568": "TA0011",
  "T1573": "TA0011", "T1008": "TA0011", "T1104": "TA0011", "T1095": "TA0011",
  "T1572": "TA0011", "T1090": "TA0011", "T1219": "TA0011", "T1102": "TA0011",
  "T1048": "TA0010", "T1041": "TA0010", "T1011": "TA0010", "T1052": "TA0010",
  "T1567": "TA0010", "T1029": "TA0010", "T1537": "TA0010",
  "T1531": "TA0040", "T1485": "TA0040", "T1486": "TA0040", "T1565": "TA0040",
  "T1491": "TA0040", "T1561": "TA0040", "T1499": "TA0040", "T1495": "TA0040",
  "T1489": "TA0040", "T1529": "TA0040",
};

// ─── Types ──────────────────────────────────────────────────────────────────

export interface TechniqueMapping {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
}

export interface KillChainCoverage {
  /** Overall coverage percentage (0.0 - 1.0) */
  coverage: number;
  /** Tactics that have at least one technique exercised */
  coveredTactics: string[];
  /** Tactics with no techniques exercised */
  gaps: string[];
  /** Per-tactic detail */
  tacticDetails: TacticDetail[];
  /** Total unique techniques observed */
  totalTechniques: number;
}

export interface TacticDetail {
  tacticId: string;
  tacticName: string;
  covered: boolean;
  techniques: string[];
  techniqueCount: number;
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Analyze kill chain coverage from a set of technique mappings.
 * Used by the report pipeline to generate the coverage analysis section.
 */
export function analyzeKillChainCoverage(
  techniques: TechniqueMapping[]
): KillChainCoverage {
  // Build a set of covered tactic IDs
  const coveredTacticIds = new Set<string>();
  const tacticTechniques = new Map<string, Set<string>>();

  // Initialize all tactics
  for (const tactic of MITRE_TACTICS) {
    tacticTechniques.set(tactic.id, new Set());
  }

  for (const tech of techniques) {
    // Resolve tactic from technique ID
    const baseId = tech.techniqueId.split(".")[0]; // Handle sub-techniques like T1059.001
    const tacticId = TECHNIQUE_TO_TACTIC[baseId] || resolveTacticFromName(tech.tactic);

    if (tacticId) {
      coveredTacticIds.add(tacticId);
      const techSet = tacticTechniques.get(tacticId);
      if (techSet) {
        techSet.add(tech.techniqueId);
      }
    }
  }

  const coveredTactics = MITRE_TACTICS
    .filter(t => coveredTacticIds.has(t.id))
    .map(t => t.name);

  const gaps = MITRE_TACTICS
    .filter(t => !coveredTacticIds.has(t.id))
    .map(t => t.name);

  const tacticDetails: TacticDetail[] = MITRE_TACTICS.map(t => {
    const techSet = tacticTechniques.get(t.id) || new Set();
    return {
      tacticId: t.id,
      tacticName: t.name,
      covered: coveredTacticIds.has(t.id),
      techniques: Array.from(techSet),
      techniqueCount: techSet.size,
    };
  });

  const totalTechniques = new Set(techniques.map(t => t.techniqueId)).size;

  return {
    coverage: MITRE_TACTICS.length > 0
      ? coveredTacticIds.size / MITRE_TACTICS.length
      : 0,
    coveredTactics,
    gaps,
    tacticDetails,
    totalTechniques,
  };
}

/**
 * Generate attack context for LLM prompts based on current kill chain coverage.
 * Tells the LLM which phases are covered and which gaps to prioritize.
 */
export function generateAttackContextForPrompt(
  techniques: TechniqueMapping[]
): string {
  const coverage = analyzeKillChainCoverage(techniques);

  if (coverage.totalTechniques === 0) {
    return "No MITRE ATT&CK techniques have been mapped yet. Focus on initial reconnaissance and access.";
  }

  const lines: string[] = [];
  lines.push(`Kill Chain Coverage: ${(coverage.coverage * 100).toFixed(0)}% (${coverage.coveredTactics.length}/${MITRE_TACTICS.length} tactics)`);
  lines.push("");

  if (coverage.coveredTactics.length > 0) {
    lines.push(`Covered: ${coverage.coveredTactics.join(", ")}`);
  }

  if (coverage.gaps.length > 0) {
    lines.push(`Gaps: ${coverage.gaps.join(", ")}`);
    lines.push("");
    lines.push("Priority: Focus exploitation on techniques that fill the following gaps:");

    // Suggest specific techniques for each gap
    for (const gap of coverage.gaps.slice(0, 5)) {
      const tactic = MITRE_TACTICS.find(t => t.name === gap);
      if (tactic) {
        const suggestions = getSuggestedTechniques(tactic.id);
        if (suggestions.length > 0) {
          lines.push(`  - ${gap}: ${suggestions.join(", ")}`);
        }
      }
    }
  }

  return lines.join("\n");
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function resolveTacticFromName(tacticName: string): string | null {
  if (!tacticName) return null;
  const normalized = tacticName.toLowerCase().replace(/[^a-z]/g, "");
  const tactic = MITRE_TACTICS.find(t =>
    t.name.toLowerCase().replace(/[^a-z]/g, "") === normalized ||
    t.shortName === normalized
  );
  return tactic?.id || null;
}

function getSuggestedTechniques(tacticId: string): string[] {
  const suggestions: Record<string, string[]> = {
    "TA0043": ["T1595 Active Scanning", "T1592 Gather Victim Host Info"],
    "TA0042": ["T1588 Obtain Capabilities", "T1583 Acquire Infrastructure"],
    "TA0001": ["T1190 Exploit Public-Facing App", "T1078 Valid Accounts", "T1566 Phishing"],
    "TA0002": ["T1059 Command & Scripting Interpreter", "T1203 Exploitation for Client Execution"],
    "TA0003": ["T1547 Boot/Logon Autostart", "T1136 Create Account", "T1098 Account Manipulation"],
    "TA0004": ["T1068 Exploitation for Privilege Escalation", "T1055 Process Injection"],
    "TA0005": ["T1027 Obfuscated Files", "T1036 Masquerading", "T1562 Impair Defenses"],
    "TA0006": ["T1110 Brute Force", "T1003 OS Credential Dumping", "T1552 Unsecured Credentials"],
    "TA0007": ["T1046 Network Service Discovery", "T1082 System Information Discovery"],
    "TA0008": ["T1021 Remote Services", "T1210 Exploitation of Remote Services"],
    "TA0009": ["T1005 Data from Local System", "T1114 Email Collection"],
    "TA0011": ["T1071 Application Layer Protocol", "T1573 Encrypted Channel"],
    "TA0010": ["T1041 Exfiltration Over C2", "T1048 Exfiltration Over Alternative Protocol"],
    "TA0040": ["T1486 Data Encrypted for Impact", "T1489 Service Stop"],
  };
  return suggestions[tacticId] || [];
}
