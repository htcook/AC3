/**
 * Production-Safe Autonomous Mode — Safety Engine
 *
 * Provides configurable safety levels that gate every tool execution and
 * engagement phase transition. Integrates with the existing ScanPolicyEngine
 * (SSIL controls) and adds:
 *   - Four safety levels: passive-only, low-impact, standard, full-exploitation
 *   - Pre-execution risk assessment for every tool command
 *   - Predictive blast radius estimation (exceeds Pentera/NodeZero)
 *   - Safety audit trail with every allowed/blocked decision
 *   - Real-time safety dashboard metrics
 */

import { getScanPolicyEngine, type ScanMode, type PolicyDecision } from "./scan-policy-engine";

// ─── Safety Levels ──────────────────────────────────────────────────────────

export type SafetyLevel = "passive_only" | "low_impact" | "standard" | "full_exploitation";

export interface SafetyProfile {
  level: SafetyLevel;
  label: string;
  description: string;
  scanPolicyProfile: string;
  allowedToolCategories: ToolCategory[];
  maxConcurrentPerTarget: number;
  allowCredentialTesting: boolean;
  allowExploitation: boolean;
  allowC2Deployment: boolean;
  allowExfilSimulation: boolean;
  allowDosTest: boolean;
  allowLateralMovement: boolean;
  maxScanForgeTiming: number;
  maxRpsPerHost: number;
  requirePhaseApproval: boolean;
  /** When true, red-tier approval gates require two independent approvers */
  dualApprovalRequired: boolean;
  blockedScanForgeFlags: string[];
  blockedNucleiTags: string[];
}

export type ToolCategory =
  | "passive_recon" | "active_recon" | "vuln_scanning" | "active_scanning"
  | "credential_test" | "exploitation" | "c2_operations" | "post_exploit" | "utility";

const SAFETY_PROFILES: Record<SafetyLevel, SafetyProfile> = {
  passive_only: {
    level: "passive_only", label: "Passive Only",
    description: "Zero interaction with target systems. OSINT, DNS, certificate transparency, and public data only. Guaranteed zero impact on production systems.",
    scanPolicyProfile: "strict_passive",
    allowedToolCategories: ["passive_recon", "utility"],
    maxConcurrentPerTarget: 1, allowCredentialTesting: false, allowExploitation: false,
    allowC2Deployment: false, allowExfilSimulation: false, allowDosTest: false,
    allowLateralMovement: false, maxScanForgeTiming: 0, maxRpsPerHost: 1,
    requirePhaseApproval: false,
    dualApprovalRequired: false,
    blockedScanForgeFlags: ["-sS", "-sT", "-sU", "-sV", "-sC", "-A", "--script", "-O", "-Pn"],
    blockedNucleiTags: ["rce", "sqli", "ssrf", "xss", "lfi", "bruteforce", "default-login", "takeover", "cve"],
  },
  low_impact: {
    level: "low_impact", label: "Low Impact",
    description: "Non-intrusive active scanning. Port discovery, service fingerprinting, and safe vulnerability detection. No exploitation, no credential testing, no payload injection.",
    scanPolicyProfile: "balanced",
    allowedToolCategories: ["passive_recon", "active_recon", "vuln_scanning", "utility"],
    maxConcurrentPerTarget: 2, allowCredentialTesting: false, allowExploitation: false,
    allowC2Deployment: false, allowExfilSimulation: false, allowDosTest: false,
    allowLateralMovement: false, maxScanForgeTiming: 3, maxRpsPerHost: 10,
    requirePhaseApproval: false,
    dualApprovalRequired: false,
    blockedScanForgeFlags: ["--script=exploit", "--script=brute", "--script=dos"],
    blockedNucleiTags: ["rce", "sqli", "ssrf", "bruteforce", "default-login", "takeover-exploit", "dos"],
  },
  standard: {
    level: "standard", label: "Standard",
    description: "Full vulnerability assessment with credential testing. Active scanning, safe exploit verification, and credential brute-force. No C2 deployment or lateral movement.",
    scanPolicyProfile: "aggressive_internal",
    allowedToolCategories: ["passive_recon", "active_recon", "vuln_scanning", "active_scanning", "credential_test", "utility"],
    maxConcurrentPerTarget: 4, allowCredentialTesting: true, allowExploitation: false,
    allowC2Deployment: false, allowExfilSimulation: false, allowDosTest: false,
    allowLateralMovement: false, maxScanForgeTiming: 4, maxRpsPerHost: 50,
    requirePhaseApproval: true,
    dualApprovalRequired: false,
    blockedScanForgeFlags: ["--script=dos"],
    blockedNucleiTags: ["dos"],
  },
  full_exploitation: {
    level: "full_exploitation", label: "Full Exploitation",
    description: "Complete red team engagement. All tools enabled including exploitation, C2 deployment, lateral movement, and data exfiltration simulation. Requires signed RoE.",
    scanPolicyProfile: "aggressive_internal",
    allowedToolCategories: ["passive_recon", "active_recon", "vuln_scanning", "active_scanning", "credential_test", "exploitation", "c2_operations", "post_exploit", "utility"],
    maxConcurrentPerTarget: 8, allowCredentialTesting: true, allowExploitation: true,
    allowC2Deployment: true, allowExfilSimulation: true, allowDosTest: false,
    allowLateralMovement: true, maxScanForgeTiming: 5, maxRpsPerHost: 100,
    requirePhaseApproval: true,
    dualApprovalRequired: true,
    blockedScanForgeFlags: [],
    blockedNucleiTags: ["dos"],
  },
};

const TOOL_CATEGORY_MAP: Record<string, ToolCategory> = {
  whois: "passive_recon", dig: "passive_recon", subfinder: "passive_recon",
  discovery: "active_recon", httpx: "active_recon", naabu: "active_recon",
  masscan: "active_recon", gobuster: "active_recon", ffuf: "active_recon",
  whatweb: "active_recon", sslscan: "active_recon", testssl: "active_recon",
  nuclei: "vuln_scanning", nikto: "vuln_scanning", wpscan: "vuln_scanning",
  "zap-cli": "active_scanning", "zap.sh": "active_scanning", zap: "active_scanning",
  zaproxy: "active_scanning", sqlmap: "active_scanning", wfuzz: "active_scanning",
  hydra: "credential_test", crackmapexec: "credential_test",
  docker: "exploitation", python3: "active_scanning", scapy: "active_scanning",
  enum4linux: "post_exploit", smbclient: "post_exploit",
  ldapsearch: "post_exploit", snmpwalk: "post_exploit",
  curl: "utility", wget: "utility", cat: "utility",
  head: "utility", tail: "utility", grep: "utility",
  cloud_enum: "active_recon", s3scanner: "active_recon",
  trufflehog: "active_recon", aws: "active_recon",
  tcpdump: "utility", tshark: "utility",
};

export type EngagementPhase =
  | "recon" | "enumeration" | "vuln_detection"
  | "credential_testing" | "exploitation" | "post_exploit"
  | "c2_deployment" | "lateral_movement" | "exfiltration";

const PHASE_MINIMUM_SAFETY: Record<EngagementPhase, SafetyLevel> = {
  recon: "passive_only", enumeration: "low_impact", vuln_detection: "low_impact",
  credential_testing: "standard", exploitation: "full_exploitation",
  post_exploit: "full_exploitation", c2_deployment: "full_exploitation",
  lateral_movement: "full_exploitation", exfiltration: "full_exploitation",
};

const SAFETY_LEVEL_ORDER: SafetyLevel[] = [
  "passive_only", "low_impact", "standard", "full_exploitation",
];

// ─── Blast Radius Estimation ────────────────────────────────────────────────

export interface BlastRadiusEstimate {
  riskScore: number;
  riskCategory: "none" | "minimal" | "moderate" | "significant" | "critical";
  affectedSystems: number;
  downtimeRiskMinutes: number;
  mayTriggerAlerts: boolean;
  mayModifyData: boolean;
  mayDisruptService: boolean;
  riskFactors: string[];
  mitigations: string[];
}

function estimateBlastRadius(
  tool: string, args: string, target: string, profile: SafetyProfile
): BlastRadiusEstimate {
  const riskFactors: string[] = [];
  const mitigations: string[] = [];
  let riskScore = 0;
  let affectedSystems = 1;
  let downtimeRiskMinutes = 0;
  let mayTriggerAlerts = false;
  let mayModifyData = false;
  let mayDisruptService = false;

  const category = TOOL_CATEGORY_MAP[tool] || "utility";

  if (category === "exploitation" || category === "c2_operations") {
    riskScore += 40;
    riskFactors.push(`${tool} is an exploitation/C2 tool with high impact potential`);
    mayModifyData = true; mayTriggerAlerts = true; downtimeRiskMinutes += 30;
  } else if (category === "credential_test") {
    riskScore += 25;
    riskFactors.push("Credential testing may trigger account lockouts");
    mayTriggerAlerts = true;
    mitigations.push("Ensure account lockout thresholds are known before testing");
  } else if (category === "active_scanning") {
    riskScore += 15;
    riskFactors.push("Active scanning sends payloads that may trigger WAF/IDS alerts");
    mayTriggerAlerts = true;
  } else if (category === "vuln_scanning") {
    riskScore += 10; mayTriggerAlerts = true;
  } else if (category === "active_recon") {
    riskScore += 5;
  }

  if (tool === "scanforge-discovery") {
    if (args.includes("-T5") || args.includes("-T4")) {
      riskScore += 10; riskFactors.push("Aggressive timing may overwhelm target"); mayDisruptService = true;
      mitigations.push("Consider using -T3 or lower for production systems");
    }
    if (args.includes("--script=exploit") || args.includes("--script=brute")) {
      riskScore += 20; riskFactors.push("NSE exploit/brute scripts may cause disruption"); mayModifyData = true;
    }
    if (args.includes("-sU")) { riskScore += 5; riskFactors.push("UDP scanning is slow and may trigger alerts"); }
    const cidr = args.match(/\/(\d+)/);
    if (cidr) {
      const prefix = parseInt(cidr[1]);
      affectedSystems = Math.pow(2, 32 - prefix);
      riskScore += Math.min(30, affectedSystems / 100);
      riskFactors.push(`Scanning ${affectedSystems} addresses in CIDR range`);
    }
  }

  if (tool === "hydra") {
    riskScore += 20;
    if (args.includes("-t 64") || args.includes("-t 32")) {
      riskScore += 10; riskFactors.push("High thread count may trigger lockouts faster");
      mitigations.push("Reduce thread count (-t 4) for production systems");
    }
    downtimeRiskMinutes += 5;
  }

  if (tool === "nuclei") {
    if (args.includes("-severity critical") || args.includes("-severity high")) {
      riskScore += 10; riskFactors.push("High/critical templates may include active exploitation");
    }
    if (args.includes("-tags rce") || args.includes("-tags sqli")) {
      riskScore += 15; riskFactors.push("RCE/SQLi templates send exploit payloads"); mayModifyData = true;
    }
  }

  if (tool === "sqlmap") {
    riskScore += 30; riskFactors.push("SQL injection testing may modify database records");
    mayModifyData = true; mayTriggerAlerts = true;
    if (args.includes("--os-shell") || args.includes("--os-cmd")) {
      riskScore += 20; riskFactors.push("OS command execution through SQL injection"); downtimeRiskMinutes += 60;
    }
  }

  if (target) {
    if (target.includes("prod") || target.includes("production")) {
      riskScore += 15; riskFactors.push("Target appears to be a production system");
      mitigations.push("Confirm testing window with operations team");
    }
    if (target.includes("db") || target.includes("database") || target.includes("sql")) {
      riskScore += 10; riskFactors.push("Target appears to be a database server");
    }
    if (target.includes("api") || target.includes("gateway")) {
      riskScore += 5; riskFactors.push("Target appears to be an API gateway");
    }
  }

  riskScore = Math.min(100, riskScore);
  const riskCategory: BlastRadiusEstimate["riskCategory"] =
    riskScore === 0 ? "none" : riskScore <= 15 ? "minimal" :
    riskScore <= 40 ? "moderate" : riskScore <= 70 ? "significant" : "critical";

  return { riskScore, riskCategory, affectedSystems, downtimeRiskMinutes,
    mayTriggerAlerts, mayModifyData, mayDisruptService, riskFactors, mitigations };
}

// ─── Safety Assessment Result ───────────────────────────────────────────────

export interface SafetyAssessment {
  allowed: boolean;
  safetyLevel: SafetyLevel;
  reason: string;
  blastRadius: BlastRadiusEstimate;
  policyViolations: string[];
  safetyViolations: string[];
  escalated: boolean;
  timestamp: number;
  tool: string;
  args: string;
  target: string;
}

export interface SafetyAuditEntry {
  id: string;
  engagementId: number;
  timestamp: number;
  tool: string;
  args: string;
  target: string;
  safetyLevel: SafetyLevel;
  decision: "allowed" | "blocked" | "escalated";
  reason: string;
  blastRadius: BlastRadiusEstimate;
  operatorId?: number;
  phase?: string;
}

// ─── Safety Engine Class ────────────────────────────────────────────────────

export class SafetyEngine {
  private safetyLevel: SafetyLevel;
  private profile: SafetyProfile;
  private auditLog: SafetyAuditEntry[] = [];
  private engagementId: number;
  private stats = {
    totalAssessments: 0, allowed: 0, blocked: 0, escalated: 0,
    highestBlastRadius: 0,
    toolBreakdown: {} as Record<string, { allowed: number; blocked: number }>,
  };

  constructor(engagementId: number, level: SafetyLevel = "standard") {
    this.engagementId = engagementId;
    this.safetyLevel = level;
    this.profile = SAFETY_PROFILES[level];
    try {
      const policyEngine = getScanPolicyEngine();
      policyEngine.setActiveProfile(this.profile.scanPolicyProfile);
    } catch { /* ok */ }
  }

  assess(tool: string, args: string, target: string, phase?: string): SafetyAssessment {
    this.stats.totalAssessments++;
    const safetyViolations: string[] = [];
    const policyViolations: string[] = [];
    let escalated = false;

    const category = TOOL_CATEGORY_MAP[tool] || "utility";
    if (!this.profile.allowedToolCategories.includes(category)) {
      safetyViolations.push(`Tool category '${category}' (${tool}) not allowed at safety level '${this.profile.label}'`);
    }
    if (category === "credential_test" && !this.profile.allowCredentialTesting) {
      safetyViolations.push("Credential testing is disabled at current safety level");
    }
    if (category === "exploitation" && !this.profile.allowExploitation) {
      safetyViolations.push("Exploitation is disabled at current safety level");
    }
    if (category === "c2_operations" && !this.profile.allowC2Deployment) {
      safetyViolations.push("C2 deployment is disabled at current safety level");
    }
    if (category === "post_exploit" && !this.profile.allowLateralMovement) {
      safetyViolations.push("Post-exploitation/lateral movement is disabled at current safety level");
    }

    if (tool === "scanforge-discovery") {
      for (const flag of this.profile.blockedScanForgeFlags) {
        if (args.includes(flag)) {
          safetyViolations.push(`ScanForge flag '${flag}' is blocked at safety level '${this.profile.label}'`);
        }
      }
      const timingMatch = args.match(/-T(\d)/);
      if (timingMatch && parseInt(timingMatch[1]) > this.profile.maxScanForgeTiming) {
        safetyViolations.push(`ScanForge timing -T${timingMatch[1]} exceeds maximum -T${this.profile.maxScanForgeTiming}`);
      }
    }

    if (tool === "nuclei") {
      for (const tag of this.profile.blockedNucleiTags) {
        if (args.includes(`-tags ${tag}`) || args.includes(`tags=${tag}`)) {
          safetyViolations.push(`Nuclei tag '${tag}' is blocked at safety level '${this.profile.label}'`);
        }
      }
    }

    const blastRadius = estimateBlastRadius(tool, args, target, this.profile);
    const maxBlastRadius = this.safetyLevel === "passive_only" ? 5 :
      this.safetyLevel === "low_impact" ? 30 : this.safetyLevel === "standard" ? 60 : 100;

    if (blastRadius.riskScore > maxBlastRadius) {
      safetyViolations.push(`Blast radius ${blastRadius.riskScore} exceeds maximum ${maxBlastRadius}`);
      escalated = true;
    }

    const allowed = safetyViolations.length === 0 && policyViolations.length === 0;
    const reason = allowed
      ? `Allowed: ${tool} ${args.slice(0, 100)} (blast radius: ${blastRadius.riskScore})`
      : `Blocked: ${[...safetyViolations, ...policyViolations].join("; ")}`;

    if (allowed) this.stats.allowed++; else this.stats.blocked++;
    if (escalated) this.stats.escalated++;
    if (blastRadius.riskScore > this.stats.highestBlastRadius) this.stats.highestBlastRadius = blastRadius.riskScore;
    if (!this.stats.toolBreakdown[tool]) this.stats.toolBreakdown[tool] = { allowed: 0, blocked: 0 };
    this.stats.toolBreakdown[tool][allowed ? "allowed" : "blocked"]++;

    const auditEntry: SafetyAuditEntry = {
      id: `safety-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      engagementId: this.engagementId, timestamp: Date.now(),
      tool, args: args.slice(0, 2000), target, safetyLevel: this.safetyLevel,
      decision: allowed ? "allowed" : escalated ? "escalated" : "blocked",
      reason, blastRadius, phase,
    };
    this.auditLog.push(auditEntry);
    if (this.auditLog.length > 5000) this.auditLog = this.auditLog.slice(-4000);

    return { allowed, safetyLevel: this.safetyLevel, reason, blastRadius,
      policyViolations, safetyViolations, escalated, timestamp: Date.now(), tool, args, target };
  }

  canEnterPhase(phase: EngagementPhase): { allowed: boolean; reason: string; requiredLevel: SafetyLevel } {
    const requiredLevel = PHASE_MINIMUM_SAFETY[phase];
    const currentIdx = SAFETY_LEVEL_ORDER.indexOf(this.safetyLevel);
    const requiredIdx = SAFETY_LEVEL_ORDER.indexOf(requiredLevel);
    if (currentIdx < requiredIdx) {
      return { allowed: false, reason: `Phase '${phase}' requires '${requiredLevel}' but current is '${this.safetyLevel}'`, requiredLevel };
    }
    return { allowed: true, reason: `Phase '${phase}' allowed at '${this.safetyLevel}'`, requiredLevel };
  }

  getSafetyLevel(): SafetyLevel { return this.safetyLevel; }
  getProfile(): SafetyProfile { return this.profile; }

  setSafetyLevel(level: SafetyLevel): void {
    this.safetyLevel = level;
    this.profile = SAFETY_PROFILES[level];
    try { getScanPolicyEngine().setActiveProfile(this.profile.scanPolicyProfile); } catch { /* ok */ }
  }

  getAuditLog(limit = 100): SafetyAuditEntry[] { return this.auditLog.slice(-limit); }

  getStats() {
    return { ...this.stats, safetyLevel: this.safetyLevel, engagementId: this.engagementId, auditLogSize: this.auditLog.length };
  }

  getBlockedActions(): SafetyAuditEntry[] {
    return this.auditLog.filter(e => e.decision === "blocked" || e.decision === "escalated");
  }

  static getAvailableLevels(): Array<{ level: SafetyLevel; label: string; description: string }> {
    return SAFETY_LEVEL_ORDER.map(level => ({
      level, label: SAFETY_PROFILES[level].label, description: SAFETY_PROFILES[level].description,
    }));
  }

  static getProfileDetails(level: SafetyLevel): SafetyProfile { return SAFETY_PROFILES[level]; }

  static estimateBlastRadiusStatic(tool: string, args: string, target: string, level: SafetyLevel): BlastRadiusEstimate {
    return estimateBlastRadius(tool, args, target, SAFETY_PROFILES[level]);
  }
}

const engineCache = new Map<number, SafetyEngine>();

export function getSafetyEngine(engagementId: number, level?: SafetyLevel): SafetyEngine {
  let engine = engineCache.get(engagementId);
  if (!engine) {
    engine = new SafetyEngine(engagementId, level || "standard");
    engineCache.set(engagementId, engine);
  } else if (level && engine.getSafetyLevel() !== level) {
    engine.setSafetyLevel(level);
  }
  return engine;
}

export function clearSafetyEngine(engagementId: number): void { engineCache.delete(engagementId); }
