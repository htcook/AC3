/**
 * ScanForge Threat Intelligence Engine
 *
 * Proactively enriches scan planning and finding analysis with data from:
 *   - CISA KEV (Known Exploited Vulnerabilities)
 *   - EPSS (Exploit Prediction Scoring System)
 *   - abuse.ch (Malware/Botnet indicators)
 *   - MITRE ATT&CK (Technique-to-CVE mapping)
 *   - DFIR artifact knowledge (persistence, lateral movement, exfil patterns)
 *   - Threat actor profiles (industry-specific targeting)
 *
 * The engine is used in two modes:
 *   1. Pre-scan: Select and prioritize templates based on target context
 *   2. Post-scan: Enrich findings with TI data for risk scoring
 */

import type {
  ScanTemplate,
  ScanTarget,
  ScanFinding,
  RiskScore,
  IntelligenceConfig,
} from "../types";

// ─── TI Feed Types ─────────────────────────────────────────────────────────

interface KEVEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
}

interface EPSSEntry {
  cve: string;
  epss: number;
  percentile: number;
}

interface ThreatActorProfile {
  name: string;
  aliases: string[];
  targetIndustries: string[];
  targetRegions: string[];
  commonTechniques: string[];
  commonCVEs: string[];
  tools: string[];
}

// ─── DFIR Artifact Patterns ────────────────────────────────────────────────

interface DFIRArtifact {
  category: "persistence" | "lateral_movement" | "exfiltration" | "credential_access" | "defense_evasion";
  indicator: string;
  description: string;
  attackTechniques: string[];
  scanChecks: string[];
}

const DFIR_ARTIFACTS: DFIRArtifact[] = [
  // Persistence mechanisms
  {
    category: "persistence",
    indicator: "web_shell",
    description: "Web shells in common upload directories or writable paths",
    attackTechniques: ["T1505.003"],
    scanChecks: ["webshell-detection", "file-upload-vuln", "directory-listing"],
  },
  {
    category: "persistence",
    indicator: "cron_backdoor",
    description: "Cron jobs or scheduled tasks creating reverse shells",
    attackTechniques: ["T1053.003"],
    scanChecks: ["ssh-weak-auth", "command-injection"],
  },
  {
    category: "persistence",
    indicator: "ssh_authorized_keys",
    description: "Unauthorized SSH keys in authorized_keys files",
    attackTechniques: ["T1098.004"],
    scanChecks: ["ssh-key-enum", "ssh-weak-config"],
  },
  {
    category: "persistence",
    indicator: "startup_script_modification",
    description: "Modified startup scripts or init.d entries",
    attackTechniques: ["T1037"],
    scanChecks: ["os-command-injection", "privilege-escalation"],
  },
  // Lateral movement
  {
    category: "lateral_movement",
    indicator: "smb_relay",
    description: "SMB relay attacks via NTLM authentication",
    attackTechniques: ["T1557.001"],
    scanChecks: ["smb-signing", "ntlm-relay", "smb-vuln"],
  },
  {
    category: "lateral_movement",
    indicator: "rdp_hijack",
    description: "RDP session hijacking or BlueKeep exploitation",
    attackTechniques: ["T1563.002"],
    scanChecks: ["rdp-vuln", "rdp-nla-check"],
  },
  {
    category: "lateral_movement",
    indicator: "pass_the_hash",
    description: "Pass-the-hash attacks using stolen NTLM hashes",
    attackTechniques: ["T1550.002"],
    scanChecks: ["smb-brute", "ntlm-info", "kerberos-enum"],
  },
  {
    category: "lateral_movement",
    indicator: "wmi_exec",
    description: "Remote code execution via WMI",
    attackTechniques: ["T1047"],
    scanChecks: ["smb-enum", "wmi-access"],
  },
  // Credential access
  {
    category: "credential_access",
    indicator: "credential_dumping",
    description: "Credential dumping from memory or registry",
    attackTechniques: ["T1003"],
    scanChecks: ["smb-vuln", "rdp-vuln", "default-creds"],
  },
  {
    category: "credential_access",
    indicator: "kerberoasting",
    description: "Kerberoasting attacks against Active Directory",
    attackTechniques: ["T1558.003"],
    scanChecks: ["ldap-enum", "kerberos-enum", "ad-enum"],
  },
  {
    category: "credential_access",
    indicator: "database_credential_theft",
    description: "Extraction of credentials from database servers",
    attackTechniques: ["T1555"],
    scanChecks: ["mysql-brute", "postgres-brute", "mongodb-brute", "redis-noauth"],
  },
  // Exfiltration
  {
    category: "exfiltration",
    indicator: "dns_tunneling",
    description: "Data exfiltration via DNS queries",
    attackTechniques: ["T1048.003"],
    scanChecks: ["dns-zone-transfer", "dns-enum"],
  },
  {
    category: "exfiltration",
    indicator: "cloud_storage_exfil",
    description: "Exfiltration to misconfigured cloud storage",
    attackTechniques: ["T1567.002"],
    scanChecks: ["s3-bucket-enum", "cloud-storage-misconfig"],
  },
  // Defense evasion
  {
    category: "defense_evasion",
    indicator: "log_tampering",
    description: "Log file deletion or modification",
    attackTechniques: ["T1070"],
    scanChecks: ["file-inclusion", "command-injection"],
  },
  {
    category: "defense_evasion",
    indicator: "waf_bypass",
    description: "WAF bypass techniques for payload delivery",
    attackTechniques: ["T1562.001"],
    scanChecks: ["waf-detection", "xss-bypass", "sqli-bypass"],
  },
];

// ─── Intelligence Engine ───────────────────────────────────────────────────

export class IntelligenceEngine {
  private kevCatalog: Map<string, KEVEntry> = new Map();
  private epssScores: Map<string, EPSSEntry> = new Map();
  private threatActors: ThreatActorProfile[] = [];
  private initialized = false;
  private lastFeedUpdate = 0;
  private feedUpdateIntervalMs = 24 * 60 * 60 * 1000; // 24 hours

  /**
   * Initialize the intelligence engine by loading TI feeds.
   */
  async initialize(): Promise<void> {
    if (this.initialized && Date.now() - this.lastFeedUpdate < this.feedUpdateIntervalMs) {
      return;
    }

    await Promise.allSettled([
      this.loadKEV(),
      this.loadThreatActors(),
    ]);

    this.initialized = true;
    this.lastFeedUpdate = Date.now();
    console.log(`[TIEngine] Initialized: ${this.kevCatalog.size} KEV entries, ${this.threatActors.length} threat actors`);
  }

  /**
   * Pre-scan: Prioritize templates based on target context and TI data.
   * Returns templates sorted by relevance (most important first).
   */
  async prioritizeTemplates(
    templates: ScanTemplate[],
    target: ScanTarget,
    config?: IntelligenceConfig
  ): Promise<ScanTemplate[]> {
    const scored = templates.map(t => ({
      template: t,
      score: this.scoreTemplateRelevance(t, target, config),
    }));

    // Sort by relevance score (highest first)
    scored.sort((a, b) => b.score - a.score);

    return scored.map(s => s.template);
  }

  /**
   * Post-scan: Enrich a finding with TI data and compute risk score.
   */
  async enrichFinding(finding: ScanFinding): Promise<ScanFinding> {
    const riskScore: RiskScore = {
      composite: 0,
    };

    // CVSS base score (from severity if not provided)
    riskScore.cvss = finding.severity === "critical" ? 9.5
      : finding.severity === "high" ? 7.5
      : finding.severity === "medium" ? 5.0
      : finding.severity === "low" ? 3.0
      : 1.0;

    // KEV check
    if (finding.cves?.length) {
      for (const cve of finding.cves) {
        const kev = this.kevCatalog.get(cve);
        if (kev) {
          riskScore.kevListed = true;
          riskScore.kevDueDate = kev.dueDate;
          riskScore.ransomwareUse = kev.knownRansomwareCampaignUse === "Known";
          // KEV listing dramatically increases risk
          riskScore.cvss = Math.max(riskScore.cvss || 0, 8.0);
          break;
        }
      }
    }

    // EPSS score
    if (finding.cves?.length) {
      for (const cve of finding.cves) {
        const epss = this.epssScores.get(cve);
        if (epss) {
          riskScore.epss = epss.epss;
          riskScore.epssPercentile = epss.percentile;
          break;
        }
      }
    }

    // DFIR precedent check
    if (finding.techniqueIds?.length) {
      const dfirMatches = DFIR_ARTIFACTS.filter(a =>
        a.attackTechniques.some(t => finding.techniqueIds!.includes(t))
      );
      if (dfirMatches.length > 0) {
        riskScore.dfirPrecedent = true;
        riskScore.dfirCategories = [...new Set(dfirMatches.map(d => d.category))];
      }
    }

    // Threat actor relevance
    if (finding.cves?.length) {
      const relevantActors = this.threatActors.filter(actor =>
        actor.commonCVEs.some(cve => finding.cves!.includes(cve))
      );
      if (relevantActors.length > 0) {
        riskScore.threatActorRelevance = relevantActors.map(a => a.name);
      }
    }

    // Compute composite score (0-100)
    riskScore.composite = this.computeCompositeScore(riskScore, finding);

    finding.riskScore = riskScore;
    return finding;
  }

  /**
   * Get DFIR-informed scan checks for a target.
   * Returns additional template IDs/tags that should be run based on
   * DFIR artifact knowledge.
   */
  getDFIRInformedChecks(target: ScanTarget): string[] {
    const checks: string[] = [];

    // Based on discovered services, add DFIR-relevant checks
    if (target.services) {
      const serviceStr = Object.values(target.services).join(" ").toLowerCase();

      if (serviceStr.includes("smb") || serviceStr.includes("microsoft-ds")) {
        checks.push(...DFIR_ARTIFACTS
          .filter(a => a.category === "lateral_movement" && a.scanChecks.some(c => c.includes("smb")))
          .flatMap(a => a.scanChecks));
      }

      if (serviceStr.includes("rdp")) {
        checks.push(...DFIR_ARTIFACTS
          .filter(a => a.scanChecks.some(c => c.includes("rdp")))
          .flatMap(a => a.scanChecks));
      }

      if (serviceStr.includes("ldap")) {
        checks.push(...DFIR_ARTIFACTS
          .filter(a => a.scanChecks.some(c => c.includes("ldap") || c.includes("kerberos")))
          .flatMap(a => a.scanChecks));
      }

      if (serviceStr.includes("mysql") || serviceStr.includes("postgres") || serviceStr.includes("redis") || serviceStr.includes("mongo")) {
        checks.push(...DFIR_ARTIFACTS
          .filter(a => a.category === "credential_access" && a.scanChecks.some(c => c.includes("brute") || c.includes("noauth")))
          .flatMap(a => a.scanChecks));
      }

      if (serviceStr.includes("http") || serviceStr.includes("nginx") || serviceStr.includes("apache")) {
        checks.push(...DFIR_ARTIFACTS
          .filter(a => a.indicator === "web_shell" || a.indicator === "waf_bypass")
          .flatMap(a => a.scanChecks));
      }

      if (serviceStr.includes("dns")) {
        checks.push(...DFIR_ARTIFACTS
          .filter(a => a.indicator === "dns_tunneling")
          .flatMap(a => a.scanChecks));
      }
    }

    return [...new Set(checks)];
  }

  // ─── Internal ──────────────────────────────────────────────────────────

  private scoreTemplateRelevance(
    template: ScanTemplate,
    target: ScanTarget,
    config?: IntelligenceConfig
  ): number {
    let score = 50; // Base score

    // Severity boost
    if (template.severity === "critical") score += 30;
    else if (template.severity === "high") score += 20;
    else if (template.severity === "medium") score += 10;

    // KEV-listed CVE boost
    if (template.references?.cves?.some(cve => this.kevCatalog.has(cve))) {
      score += 40;
    }

    // DFIR relevance boost
    if (template.attack?.techniqueIds?.length) {
      const dfirMatch = DFIR_ARTIFACTS.some(a =>
        a.attackTechniques.some(t => template.attack!.techniqueIds!.includes(t))
      );
      if (dfirMatch) score += 25;
    }

    // Threat actor targeting boost
    if (config?.targetIndustry) {
      const relevantActors = this.threatActors.filter(a =>
        a.targetIndustries.includes(config.targetIndustry!)
      );
      if (template.references?.cves?.some(cve =>
        relevantActors.some(a => a.commonCVEs.includes(cve))
      )) {
        score += 35;
      }
    }

    // Protocol match boost
    if (target.services) {
      const serviceStr = Object.values(target.services).join(" ").toLowerCase();
      if (serviceStr.includes(template.protocol)) score += 15;
    }

    // TI feed tags boost
    if (template.intelligence?.feeds?.length) {
      score += 10;
    }

    return Math.min(100, score);
  }

  private computeCompositeScore(riskScore: RiskScore, finding: ScanFinding): number {
    let score = 0;

    // CVSS component (40% weight)
    score += ((riskScore.cvss || 5.0) / 10) * 40;

    // EPSS component (20% weight)
    if (riskScore.epss !== undefined) {
      score += riskScore.epss * 20;
    } else {
      score += 5; // Default 25% EPSS if unknown
    }

    // KEV component (15% weight)
    if (riskScore.kevListed) {
      score += 15;
      if (riskScore.ransomwareUse) score += 5; // Bonus for ransomware association
    }

    // DFIR precedent (10% weight)
    if (riskScore.dfirPrecedent) {
      score += 10;
    }

    // Threat actor relevance (10% weight)
    if (riskScore.threatActorRelevance?.length) {
      score += Math.min(10, riskScore.threatActorRelevance.length * 3);
    }

    // Confidence modifier (5% weight)
    score += (finding.confidence / 100) * 5;

    return Math.round(Math.min(100, score));
  }

  private async loadKEV(): Promise<void> {
    try {
      const response = await fetch(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        { signal: AbortSignal.timeout(30000) }
      );
      if (!response.ok) throw new Error(`KEV feed HTTP ${response.status}`);
      const data = await response.json() as { vulnerabilities: KEVEntry[] };

      this.kevCatalog.clear();
      for (const vuln of data.vulnerabilities || []) {
        this.kevCatalog.set(vuln.cveID, vuln);
      }
      console.log(`[TIEngine] Loaded ${this.kevCatalog.size} KEV entries`);
    } catch (err: any) {
      console.warn(`[TIEngine] Failed to load KEV feed: ${err.message}`);
    }
  }

  private async loadThreatActors(): Promise<void> {
    // Built-in threat actor profiles based on DFIR/TI knowledge
    // In production, these would be loaded from a database or TI feed
    this.threatActors = [
      {
        name: "APT28 (Fancy Bear)",
        aliases: ["Sofacy", "Sednit", "STRONTIUM"],
        targetIndustries: ["government", "defense", "energy", "media"],
        targetRegions: ["US", "EU", "NATO"],
        commonTechniques: ["T1566.001", "T1203", "T1059.001", "T1071.001"],
        commonCVEs: ["CVE-2017-0199", "CVE-2017-11882", "CVE-2023-23397"],
        tools: ["X-Agent", "Zebrocy", "Koadic"],
      },
      {
        name: "APT29 (Cozy Bear)",
        aliases: ["NOBELIUM", "Midnight Blizzard", "The Dukes"],
        targetIndustries: ["government", "technology", "healthcare", "think_tanks"],
        targetRegions: ["US", "EU", "UK"],
        commonTechniques: ["T1195.002", "T1078", "T1550.001", "T1071.001"],
        commonCVEs: ["CVE-2021-21972", "CVE-2021-26855", "CVE-2023-42793"],
        tools: ["SUNBURST", "TEARDROP", "EnvyScout"],
      },
      {
        name: "Lazarus Group",
        aliases: ["HIDDEN COBRA", "Zinc", "Diamond Sleet"],
        targetIndustries: ["finance", "cryptocurrency", "defense", "technology"],
        targetRegions: ["US", "KR", "JP", "Global"],
        commonTechniques: ["T1566.001", "T1059.007", "T1055", "T1486"],
        commonCVEs: ["CVE-2021-44228", "CVE-2022-47966", "CVE-2023-42793"],
        tools: ["DTrack", "BLINDINGCAN", "AppleJeus"],
      },
      {
        name: "LockBit",
        aliases: ["LockBit 3.0", "LockBit Black"],
        targetIndustries: ["healthcare", "finance", "manufacturing", "education"],
        targetRegions: ["Global"],
        commonTechniques: ["T1486", "T1490", "T1078", "T1021.001"],
        commonCVEs: ["CVE-2021-22986", "CVE-2023-0669", "CVE-2023-4966"],
        tools: ["StealBit", "Cobalt Strike"],
      },
      {
        name: "ALPHV/BlackCat",
        aliases: ["BlackCat", "Noberus"],
        targetIndustries: ["healthcare", "finance", "legal", "technology"],
        targetRegions: ["US", "EU", "Global"],
        commonTechniques: ["T1486", "T1567", "T1078", "T1048"],
        commonCVEs: ["CVE-2021-27065", "CVE-2023-27350", "CVE-2023-22515"],
        tools: ["ExMatter", "Eamfo"],
      },
      {
        name: "Volt Typhoon",
        aliases: ["BRONZE SILHOUETTE", "Vanguard Panda"],
        targetIndustries: ["critical_infrastructure", "telecommunications", "government"],
        targetRegions: ["US", "Guam", "Pacific"],
        commonTechniques: ["T1190", "T1133", "T1078", "T1059"],
        commonCVEs: ["CVE-2021-40539", "CVE-2021-27860", "CVE-2023-46805"],
        tools: ["Living-off-the-land", "Impacket", "Fast Reverse Proxy"],
      },
    ];
  }
}

// ─── Singleton ─────────────────────────────────────────────────────────────

let _engine: IntelligenceEngine | null = null;

export function getIntelligenceEngine(): IntelligenceEngine {
  if (!_engine) {
    _engine = new IntelligenceEngine();
  }
  return _engine;
}
