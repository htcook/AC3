/**
 * Graduated Autonomy Framework — Level 0-3
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Governs AI decision-making authority during engagements.
 * 4-level model with hard caps from ROE type, graduation tier, and operator override.
 *
 * Levels:
 *   0 — Advisory:   AI recommends only, operator executes everything
 *   1 — Assisted:   AI executes low-risk scans, operator approves medium+
 *   2 — Supervised:  AI runs full chains, pauses between phases for approval
 *   3 — Autonomous:  AI operates independently within ROE scope boundaries
 *
 * Compliance: NIST AI 600-1, NIST SP 800-115, FedRAMP
 */

export type AutonomyLevel = 0 | 1 | 2 | 3;

export type RoeEngagementType =
  | "vulnerability_scanning"
  | "penetration_testing"
  | "red_purple_team"
  | "cicd_integration"
  | "phishing";

export type GraduationTier = 1 | 2 | 3 | 4 | 5;
export type RiskTier = "green" | "yellow" | "orange" | "red";

export type ActionCategory =
  | "passive_recon" | "active_recon" | "port_scanning"
  | "vulnerability_scanning" | "web_crawling" | "credential_testing"
  | "exploitation" | "post_exploitation" | "lateral_movement"
  | "c2_deployment" | "data_exfiltration" | "social_engineering"
  | "phishing_execution" | "report_generation" | "evidence_collection";

export interface AutonomyState {
  currentLevel: AutonomyLevel;
  roeCap: AutonomyLevel;
  graduationCap: AutonomyLevel;
  operatorOverride: AutonomyLevel | null;
  suspended: boolean;
  reason: string;
  lastChanged: number;
  auditTrail: AutonomyAuditEntry[];
}

export interface AutonomyAuditEntry {
  timestamp: number;
  previousLevel: AutonomyLevel;
  newLevel: AutonomyLevel;
  reason: string;
  actor: "system" | "operator" | "anomaly_detector" | "graduation_engine";
  details?: string;
}

export interface ActionEvaluation {
  permitted: boolean;
  requiresApproval: boolean;
  requiresDualApproval: boolean;
  riskTier: RiskTier;
  explanation: string;
  alternatives?: string[];
}

/** Hard caps per ROE engagement type */
export const ROE_AUTONOMY_CAPS: Record<RoeEngagementType, AutonomyLevel> = {
  vulnerability_scanning: 3,
  cicd_integration: 3,
  penetration_testing: 2,
  red_purple_team: 2,
  phishing: 1,
};

/** Hard caps per graduation tier */
export const GRADUATION_AUTONOMY_CAPS: Record<GraduationTier, AutonomyLevel> = {
  1: 3, 2: 2, 3: 1, 4: 1, 5: 0,
};

/** Risk tier per action category */
export const ACTION_RISK_TIERS: Record<ActionCategory, RiskTier> = {
  passive_recon: "green",
  active_recon: "green",
  port_scanning: "yellow",
  vulnerability_scanning: "yellow",
  web_crawling: "yellow",
  credential_testing: "orange",
  exploitation: "orange",
  post_exploitation: "red",
  lateral_movement: "red",
  c2_deployment: "red",
  data_exfiltration: "red",
  social_engineering: "orange",
  phishing_execution: "orange",
  report_generation: "green",
  evidence_collection: "green",
};

/** Min autonomy level for auto-execution without approval */
const ACTION_AUTO_EXECUTE_LEVEL: Record<ActionCategory, AutonomyLevel> = {
  passive_recon: 0,
  active_recon: 1,
  port_scanning: 1,
  vulnerability_scanning: 1,
  web_crawling: 1,
  credential_testing: 2,
  exploitation: 2,
  post_exploitation: 3,
  lateral_movement: 3,
  c2_deployment: 3,
  data_exfiltration: 3,
  social_engineering: 2,
  phishing_execution: 2,
  report_generation: 0,
  evidence_collection: 0,
};

/** Actions that ALWAYS require dual-operator approval */
const ALWAYS_DUAL_APPROVAL: Set<ActionCategory> = new Set([
  "c2_deployment", "data_exfiltration", "lateral_movement",
]);

// ─── Core Functions ─────────────────────────────────────────────────────────

export function evaluateAutonomyLevel(params: {
  roeType: RoeEngagementType;
  graduationTier: GraduationTier;
  operatorOverride?: AutonomyLevel | null;
  isTrainingLab?: boolean;
  anomalyDetected?: boolean;
}): AutonomyState {
  const { roeType, graduationTier, operatorOverride, isTrainingLab, anomalyDetected } = params;

  if (isTrainingLab) {
    return {
      currentLevel: 3, roeCap: 3, graduationCap: 3,
      operatorOverride: null, suspended: false,
      reason: "Training lab mode — all safety gates bypassed",
      lastChanged: Date.now(),
      auditTrail: [{ timestamp: Date.now(), previousLevel: 0, newLevel: 3, reason: "Training lab mode", actor: "system" }],
    };
  }

  if (anomalyDetected) {
    return {
      currentLevel: 0, roeCap: ROE_AUTONOMY_CAPS[roeType],
      graduationCap: GRADUATION_AUTONOMY_CAPS[graduationTier],
      operatorOverride: 0, suspended: true,
      reason: "SUSPENDED — Anomaly detected, reverted to advisory mode",
      lastChanged: Date.now(),
      auditTrail: [{ timestamp: Date.now(), previousLevel: 3, newLevel: 0, reason: "Anomaly suspension", actor: "anomaly_detector" }],
    };
  }

  const roeCap = ROE_AUTONOMY_CAPS[roeType];
  const graduationCap = GRADUATION_AUTONOMY_CAPS[graduationTier];
  let effectiveLevel = Math.min(roeCap, graduationCap) as AutonomyLevel;

  if (operatorOverride !== null && operatorOverride !== undefined) {
    effectiveLevel = Math.min(effectiveLevel, operatorOverride) as AutonomyLevel;
  }

  const reasons: string[] = [];
  if (effectiveLevel === roeCap) reasons.push(`ROE '${roeType}' caps at L${roeCap}`);
  if (effectiveLevel === graduationCap) reasons.push(`Tier ${graduationTier} caps at L${graduationCap}`);
  if (operatorOverride !== null && operatorOverride !== undefined && effectiveLevel === operatorOverride) {
    reasons.push(`Operator override L${operatorOverride}`);
  }

  return {
    currentLevel: effectiveLevel, roeCap, graduationCap,
    operatorOverride: operatorOverride ?? null, suspended: false,
    reason: reasons.join("; ") || `Autonomy Level ${effectiveLevel}`,
    lastChanged: Date.now(),
    auditTrail: [{ timestamp: Date.now(), previousLevel: 0, newLevel: effectiveLevel, reason: reasons.join("; "), actor: "system" }],
  };
}

export function canExecuteAction(params: {
  autonomyState: AutonomyState;
  actionCategory: ActionCategory;
  isInScope: boolean;
}): ActionEvaluation {
  const { autonomyState, actionCategory, isInScope } = params;
  const { currentLevel, suspended } = autonomyState;

  if (!isInScope) {
    return {
      permitted: false, requiresApproval: false, requiresDualApproval: false,
      riskTier: ACTION_RISK_TIERS[actionCategory],
      explanation: "BLOCKED: Target outside ROE scope boundaries.",
      alternatives: ["Verify target is within authorized scope", "Request ROE amendment"],
    };
  }

  if (suspended) {
    return {
      permitted: false, requiresApproval: true, requiresDualApproval: false,
      riskTier: ACTION_RISK_TIERS[actionCategory],
      explanation: "SUSPENDED: All actions require operator review.",
    };
  }

  const riskTier = ACTION_RISK_TIERS[actionCategory];
  const autoExecLevel = ACTION_AUTO_EXECUTE_LEVEL[actionCategory];
  const needsDual = ALWAYS_DUAL_APPROVAL.has(actionCategory);

  if (currentLevel === 0 && autoExecLevel > 0) {
    return {
      permitted: false, requiresApproval: true, requiresDualApproval: needsDual,
      riskTier,
      explanation: `L0 Advisory: '${actionCategory}' requires operator execution.`,
      alternatives: [`Request operator to execute`, `Provide recommendations for review`],
    };
  }

  if (currentLevel >= autoExecLevel) {
    if (needsDual) {
      return {
        permitted: true, requiresApproval: true, requiresDualApproval: true, riskTier,
        explanation: `L${currentLevel}: '${actionCategory}' permitted — DUAL approval required (red-tier).`,
      };
    }
    if (riskTier === "red" && currentLevel < 3) {
      return {
        permitted: true, requiresApproval: true, requiresDualApproval: false, riskTier,
        explanation: `L${currentLevel}: '${actionCategory}' permitted with approval (red-tier at non-autonomous level).`,
      };
    }
    return {
      permitted: true, requiresApproval: false, requiresDualApproval: false, riskTier,
      explanation: `L${currentLevel}: '${actionCategory}' auto-approved (${riskTier} risk).`,
    };
  }

  return {
    permitted: false, requiresApproval: true, requiresDualApproval: needsDual, riskTier,
    explanation: `L${currentLevel}: '${actionCategory}' requires L${autoExecLevel}+. Operator approval needed.`,
    alternatives: [`Request operator approval`, `Use lower-risk alternative`],
  };
}

export function getAutonomyDescription(level: AutonomyLevel): {
  name: string; description: string; capabilities: string[]; restrictions: string[];
} {
  const descriptions: Record<AutonomyLevel, ReturnType<typeof getAutonomyDescription>> = {
    0: {
      name: "Advisory",
      description: "AI recommends only. All actions executed by operator.",
      capabilities: ["Passive recon (DNS, certs, OSINT)", "Report generation", "Evidence collection", "Vuln assessment recommendations", "Attack path analysis"],
      restrictions: ["No active scanning", "No target interaction", "No exploitation", "All tool execution by operator"],
    },
    1: {
      name: "Assisted",
      description: "AI executes low-risk scans. Medium+ risk needs approval.",
      capabilities: ["All L0 capabilities", "Active recon (DNS brute, crawling)", "Port scanning", "Vulnerability scanning", "Web crawling"],
      restrictions: ["No credential testing", "No exploitation", "No C2 deployment", "Medium+ risk needs approval"],
    },
    2: {
      name: "Supervised",
      description: "AI runs full chains, pauses between phases for approval.",
      capabilities: ["All L1 capabilities", "Credential testing", "Exploitation", "Social engineering prep", "Phishing execution (with approval)"],
      restrictions: ["Phase-level pauses", "Post-exploitation needs approval", "C2/data exfil needs dual approval", "Lateral movement needs dual approval"],
    },
    3: {
      name: "Autonomous",
      description: "AI operates independently within ROE. Red-tier still needs dual approval.",
      capabilities: ["All L2 capabilities", "Post-exploitation", "Lateral movement (dual approval)", "C2 deployment (dual approval)", "Full kill chain within ROE"],
      restrictions: ["Must stay within ROE scope", "C2/exfil/lateral always dual approval", "Anomaly detection can suspend to L0", "Cannot modify ROE"],
    },
  };
  return descriptions[level];
}

// ─── Anomaly Detection ──────────────────────────────────────────────────────

export interface AnomalyEvent {
  type: "scope_boundary_approach" | "unexpected_response" | "rate_limit_exceeded" |
        "authentication_failure" | "target_unreachable" | "collateral_detection" |
        "roe_violation_attempt" | "tool_crash" | "unexpected_privilege";
  severity: "info" | "warning" | "critical";
  description: string;
  timestamp: number;
  triggersSuspension: boolean;
}

export const CRITICAL_ANOMALIES: Set<AnomalyEvent["type"]> = new Set([
  "scope_boundary_approach", "roe_violation_attempt", "collateral_detection", "unexpected_privilege",
]);

export function evaluateAnomaly(event: AnomalyEvent): {
  shouldSuspend: boolean; newLevel: AutonomyLevel; reason: string; requiredAction: string;
} {
  if (CRITICAL_ANOMALIES.has(event.type) || event.severity === "critical") {
    return {
      shouldSuspend: true, newLevel: 0,
      reason: `Critical anomaly: ${event.type} — ${event.description}`,
      requiredAction: "Operator must review and clear suspension.",
    };
  }
  if (event.severity === "warning") {
    return {
      shouldSuspend: false, newLevel: 1,
      reason: `Warning: ${event.type} — reducing autonomy`,
      requiredAction: "Operator should review. Auto-restore after acknowledgment.",
    };
  }
  return {
    shouldSuspend: false, newLevel: 3,
    reason: `Info: ${event.type} — logged`,
    requiredAction: "No action required.",
  };
}

export function buildAutonomyContext(state: AutonomyState): string {
  const desc = getAutonomyDescription(state.currentLevel);
  let ctx = `## Autonomy: Level ${state.currentLevel} — ${desc.name}\n`;
  ctx += `${desc.description}\n`;
  ctx += `Reason: ${state.reason}\n`;
  if (state.suspended) ctx += `⚠️ SUSPENDED — All actions require operator approval\n`;
  ctx += `ROE Cap: L${state.roeCap} | Graduation Cap: L${state.graduationCap}`;
  if (state.operatorOverride !== null) ctx += ` | Override: L${state.operatorOverride}`;
  ctx += `\n\nCapabilities: ${desc.capabilities.join(", ")}\n`;
  ctx += `Restrictions: ${desc.restrictions.join(", ")}\n`;
  return ctx;
}
