/**
 * Ember OPSEC Integration Module
 * 
 * Wires Ember agent operations into the AC3 OPSEC Risk Engine and
 * OPSEC Monitor for comprehensive detection simulation and burn
 * prevention. Features:
 * 
 * 1. Pre-Execution Risk Scoring — Score every Ember task before dispatch
 * 2. Post-Execution Detection Analysis — Analyze completed tasks for detection indicators
 * 3. Burn Detection & Auto-Response — Monitor agent health and trigger evasive actions
 * 4. Engagement OPSEC State Tracking — Track cumulative risk across all Ember agents
 * 5. Traffic Pattern Analysis — Score beacon patterns against detection technologies
 * 6. Automatic Evasion Escalation — Progressive response to increasing detection risk
 */

import {
  scoreActionRisk,
  deterministicScoreActionRisk,
  checkBurnIndicators,
  calculateEngagementOpsecStatus,
  getDetectionTechnologies,
  type OpsecScore,
  type BurnIndicator,
  type EngagementOpsecState,
} from "./opsec-risk-engine";
import {
  createAlert,
  type OpSecAlert,
} from "./opsec-monitor";
import {
  emitEmberOpsecScored,
  emitEmberBurnResponse,
  emitOpsecActionScored,
  emitOpsecBurnDetected,
  emitOpsecThresholdWarning,
} from "./ws-event-hub";
import {
  EMBER_CAPABILITY_CATALOG,
  EMBER_TRAFFIC_PROFILES,
  type EmberTaskType,
} from "./ember-agent-core";
import {
  needsKeyRotation,
  getAgentCryptoState,
} from "./ember-crypto";

// ── Types ──────────────────────────────────────────────────────────────────

export interface EmberOpsecAssessment {
  taskType: string;
  preExecutionScore: OpsecScore;
  approved: boolean;
  reason: string;
  requiredMitigations: string[];
  alternativeSuggested: boolean;
  saferAlternative?: string;
}

export interface EmberAgentOpsecProfile {
  agentId: string;
  totalActions: number;
  cumulativeRisk: number;
  averageRisk: number;
  highRiskActions: number;
  burnIndicators: BurnIndicator[];
  overallStatus: "green" | "yellow" | "orange" | "red";
  actionHistory: Array<{
    taskType: string;
    riskScore: number;
    timestamp: number;
    detected: boolean;
  }>;
  trafficAnalysis: {
    beaconRegularity: number; // 0-100 (100 = perfectly regular = suspicious)
    trafficVolume: "low" | "medium" | "high";
    protocolDiversity: number; // Number of different channels used
    encryptionConsistency: boolean;
  };
  recommendations: string[];
}

export interface EmberFleetOpsecSummary {
  totalAgents: number;
  activeAgents: number;
  overallStatus: "green" | "yellow" | "orange" | "red";
  totalActions: number;
  averageRisk: number;
  burnedAgents: number;
  agentsNeedingRotation: number;
  topRisks: Array<{ agentId: string; riskScore: number; lastAction: string }>;
  recommendations: string[];
}

// ── In-Memory OPSEC State per Agent ────────────────────────────────────────

interface AgentOpsecState {
  agentId: string;
  engagementId?: number;
  actionHistory: Array<{
    action: string;
    risk: number;
    timestamp: number;
    detected: boolean;
  }>;
  cumulativeRisk: number;
  burnEvents: Array<{
    type: string;
    success: boolean;
    timestamp: number;
    details?: string;
  }>;
  lastAssessment: number;
  evasionLevel: number; // 0-4 escalation level
}

const agentOpsecStates = new Map<string, AgentOpsecState>();

// ── OPSEC Risk Thresholds ──────────────────────────────────────────────────

const RISK_THRESHOLDS = {
  /** Maximum allowed risk score for auto-approved tasks */
  autoApproveMax: 40,
  /** Risk score that triggers a warning */
  warningThreshold: 60,
  /** Risk score that blocks execution */
  blockThreshold: 85,
  /** Cumulative risk that triggers fleet-wide alert */
  cumulativeWarning: 200,
  /** Cumulative risk that triggers emergency response */
  cumulativeCritical: 400,
};

// ── Task-to-OPSEC Action Mapping ───────────────────────────────────────────

const EMBER_TASK_OPSEC_MAP: Record<string, {
  actionType: string;
  baseDescription: string;
  inherentRisk: "low" | "medium" | "high" | "critical";
}> = {
  shell_exec: {
    actionType: "command_execution",
    baseDescription: "Executing shell command on target host",
    inherentRisk: "medium",
  },
  file_ops: {
    actionType: "file_access",
    baseDescription: "File system operation (read/write/delete)",
    inherentRisk: "low",
  },
  cred_dump: {
    actionType: "credential_harvest",
    baseDescription: "Credential dumping (LSASS, SAM, cached creds)",
    inherentRisk: "critical",
  },
  lateral_move: {
    actionType: "lateral_movement",
    baseDescription: "Lateral movement to adjacent host",
    inherentRisk: "high",
  },
  persist: {
    actionType: "persistence",
    baseDescription: "Establishing persistence mechanism",
    inherentRisk: "high",
  },
  screenshot: {
    actionType: "data_collection",
    baseDescription: "Capturing screenshot of target desktop",
    inherentRisk: "low",
  },
  keylog: {
    actionType: "data_collection",
    baseDescription: "Keystroke logging on target",
    inherentRisk: "medium",
  },
  exfil: {
    actionType: "data_exfil",
    baseDescription: "Exfiltrating data from target network",
    inherentRisk: "high",
  },
  recon: {
    actionType: "port_scan",
    baseDescription: "Network reconnaissance and service enumeration",
    inherentRisk: "low",
  },
  privesc: {
    actionType: "privesc_attempt",
    baseDescription: "Privilege escalation attempt",
    inherentRisk: "high",
  },
  inject: {
    actionType: "command_execution",
    baseDescription: "Process injection / code injection",
    inherentRisk: "critical",
  },
  self_destruct: {
    actionType: "c2_callback",
    baseDescription: "Agent self-termination and cleanup",
    inherentRisk: "low",
  },
};

// ── Evasion Escalation Levels ──────────────────────────────────────────────

const EVASION_LEVELS = [
  { level: 0, name: "Normal", actions: ["standard_jitter"], description: "Normal operation with standard jitter" },
  { level: 1, name: "Cautious", actions: ["jitter_increase", "reduce_frequency"], description: "Increased jitter, reduced beacon frequency" },
  { level: 2, name: "Evasive", actions: ["channel_hop", "traffic_morph"], description: "Channel hopping, traffic profile morphing" },
  { level: 3, name: "Stealth", actions: ["sleep_extend", "minimal_ops"], description: "Extended sleep, minimal operations only" },
  { level: 4, name: "Emergency", actions: ["go_dormant", "self_destruct"], description: "Go dormant or self-destruct" },
];

// ── Core Functions ─────────────────────────────────────────────────────────

/**
 * Get or create OPSEC state for an agent.
 */
function getOrCreateAgentOpsecState(agentId: string, engagementId?: number): AgentOpsecState {
  let state = agentOpsecStates.get(agentId);
  if (!state) {
    state = {
      agentId,
      engagementId,
      actionHistory: [],
      cumulativeRisk: 0,
      burnEvents: [],
      lastAssessment: Date.now(),
      evasionLevel: 0,
    };
    agentOpsecStates.set(agentId, state);
  }
  return state;
}

/**
 * Pre-execution OPSEC assessment for an Ember task.
 * Scores the task risk and determines whether to approve, warn, or block.
 */
export async function assessEmberTask(
  agentId: string,
  taskType: string,
  taskDetails: string,
  engagementId?: number,
  targetEnvironment?: { edr?: string; siem?: string; ndr?: string; av?: string },
): Promise<EmberOpsecAssessment> {
  const state = getOrCreateAgentOpsecState(agentId, engagementId);
  const taskMapping = EMBER_TASK_OPSEC_MAP[taskType] || {
    actionType: "command_execution",
    baseDescription: `Ember task: ${taskType}`,
    inherentRisk: "medium" as const,
  };

  const fullDescription = `${taskMapping.baseDescription}. Details: ${taskDetails}. Agent: ${agentId}. Cumulative exposure: ${state.cumulativeRisk}.`;

  let score: OpsecScore;
  try {
    score = await scoreActionRisk(
      taskMapping.actionType,
      fullDescription,
      targetEnvironment,
      state.cumulativeRisk,
      { stealthRequired: state.evasionLevel >= 2 },
    );
  } catch {
    score = deterministicScoreActionRisk(taskMapping.actionType, fullDescription, state.cumulativeRisk);
  }

  // Determine approval
  let approved = true;
  let reason = "Task approved — risk within acceptable limits.";
  const requiredMitigations: string[] = [];

  if (score.riskScore >= RISK_THRESHOLDS.blockThreshold) {
    approved = false;
    reason = `BLOCKED — Risk score ${score.riskScore}/100 exceeds block threshold (${RISK_THRESHOLDS.blockThreshold}). ${score.reasoning}`;
  } else if (score.riskScore >= RISK_THRESHOLDS.warningThreshold) {
    approved = true;
    reason = `WARNING — Risk score ${score.riskScore}/100 is elevated. Proceed with caution. ${score.reasoning}`;
    requiredMitigations.push(...score.mitigations);
  } else if (score.riskScore > RISK_THRESHOLDS.autoApproveMax) {
    approved = true;
    reason = `Approved with mitigations — Risk score ${score.riskScore}/100. ${score.reasoning}`;
    requiredMitigations.push(...score.mitigations.slice(0, 2));
  }

  // Check if evasion level should block this task type
  if (state.evasionLevel >= 3 && taskMapping.inherentRisk !== "low") {
    approved = false;
    reason = `BLOCKED — Agent is in ${EVASION_LEVELS[state.evasionLevel].name} mode. Only low-risk operations permitted.`;
  }

  if (state.evasionLevel >= 4) {
    approved = false;
    reason = "BLOCKED — Agent is in Emergency mode. All operations suspended.";
  }

  // Emit events
  emitEmberOpsecScored({
    agentId,
    taskType,
    riskScore: score.riskScore,
    riskLevel: score.riskLevel,
    detectionProbability: score.detectionProbability,
    burnRisk: score.burnRisk,
    engagementId,
  });

  emitOpsecActionScored({
    action: `ember:${taskType}`,
    riskScore: score.riskScore,
    detectionTechnologies: score.detectedBy.map(d => d.technology),
    mitigations: score.mitigations,
    engagementId,
  });

  // Update state
  state.lastAssessment = Date.now();

  return {
    taskType,
    preExecutionScore: score,
    approved,
    reason,
    requiredMitigations,
    alternativeSuggested: score.saferAlternatives.length > 0,
    saferAlternative: score.saferAlternatives[0]?.action,
  };
}

/**
 * Record a completed Ember task execution for OPSEC tracking.
 */
export function recordEmberTaskExecution(
  agentId: string,
  taskType: string,
  riskScore: number,
  detected: boolean = false,
  engagementId?: number,
): void {
  const state = getOrCreateAgentOpsecState(agentId, engagementId);

  state.actionHistory.push({
    action: `ember:${taskType}`,
    risk: riskScore,
    timestamp: Date.now(),
    detected,
  });

  // Keep history bounded
  if (state.actionHistory.length > 500) {
    state.actionHistory = state.actionHistory.slice(-250);
  }

  state.cumulativeRisk += riskScore;

  // Check cumulative thresholds
  if (state.cumulativeRisk >= RISK_THRESHOLDS.cumulativeCritical && state.evasionLevel < 4) {
    escalateEvasion(agentId, "cumulative_risk_critical");
  } else if (state.cumulativeRisk >= RISK_THRESHOLDS.cumulativeWarning && state.evasionLevel < 2) {
    escalateEvasion(agentId, "cumulative_risk_warning");

    emitOpsecThresholdWarning({
      cumulativeScore: state.cumulativeRisk,
      threshold: RISK_THRESHOLDS.cumulativeWarning,
      recommendation: "Consider reducing agent activity or rotating infrastructure.",
      engagementId,
    });
  }

  // If detected, escalate immediately
  if (detected) {
    state.burnEvents.push({
      type: "av_alert",
      success: false,
      timestamp: Date.now(),
      details: `Task ${taskType} was detected`,
    });
    escalateEvasion(agentId, "detection_confirmed");
  }
}

/**
 * Escalate the evasion level for an agent.
 */
function escalateEvasion(agentId: string, reason: string): void {
  const state = agentOpsecStates.get(agentId);
  if (!state) return;

  const previousLevel = state.evasionLevel;
  state.evasionLevel = Math.min(state.evasionLevel + 1, 4);

  if (state.evasionLevel === previousLevel) return; // Already at max

  const level = EVASION_LEVELS[state.evasionLevel];
  const responseAction = level.actions[0] as "jitter_increase" | "channel_hop" | "sleep_extend" | "go_dormant" | "self_destruct";

  emitEmberBurnResponse({
    agentId,
    burnIndicator: reason,
    severity: state.evasionLevel >= 3 ? "critical" : state.evasionLevel >= 2 ? "high" : "medium",
    action: responseAction,
    engagementId: state.engagementId,
  });

  createAlert({
    type: "opsec_violation",
    severity: state.evasionLevel >= 3 ? "critical" : state.evasionLevel >= 2 ? "high" : "medium",
    title: `Ember Evasion Escalated: ${agentId} → Level ${state.evasionLevel} (${level.name})`,
    description: `Agent ${agentId} evasion escalated from level ${previousLevel} to ${state.evasionLevel} due to: ${reason}. Actions: ${level.actions.join(", ")}.`,
    source: "ember-opsec-integration",
    recommendation: level.description,
  });
}

/**
 * Check burn indicators for an Ember agent based on recent events.
 */
export function checkEmberBurnIndicators(agentId: string): {
  indicators: BurnIndicator[];
  evasionLevel: number;
  recommendedAction: string;
} {
  const state = agentOpsecStates.get(agentId);
  if (!state) {
    return { indicators: [], evasionLevel: 0, recommendedAction: "No OPSEC state — agent not tracked." };
  }

  const indicators = checkBurnIndicators(state.burnEvents);

  if (indicators.length > 0) {
    // Escalate based on worst indicator
    const hasCritical = indicators.some(i => i.severity === "critical");
    const hasHigh = indicators.some(i => i.severity === "high");

    if (hasCritical && state.evasionLevel < 4) {
      escalateEvasion(agentId, `burn_indicator:${indicators[0].id}`);
    } else if (hasHigh && state.evasionLevel < 3) {
      escalateEvasion(agentId, `burn_indicator:${indicators[0].id}`);
    }
  }

  const level = EVASION_LEVELS[state.evasionLevel];
  return {
    indicators,
    evasionLevel: state.evasionLevel,
    recommendedAction: level.description,
  };
}

/**
 * Analyze an agent's traffic pattern for detection risk.
 */
export function analyzeEmberTrafficPattern(
  agentId: string,
  beaconTimestamps: number[],
  channels: string[],
): {
  regularity: number;
  suspiciousPatterns: string[];
  recommendations: string[];
} {
  const suspiciousPatterns: string[] = [];
  const recommendations: string[] = [];

  // Analyze beacon interval regularity
  let regularity = 0;
  if (beaconTimestamps.length >= 3) {
    const intervals: number[] = [];
    for (let i = 1; i < beaconTimestamps.length; i++) {
      intervals.push(beaconTimestamps[i] - beaconTimestamps[i - 1]);
    }

    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((sum, i) => sum + Math.pow(i - avgInterval, 2), 0) / intervals.length;
    const stdDev = Math.sqrt(variance);
    const coeffOfVariation = stdDev / avgInterval;

    // Low coefficient of variation = very regular = suspicious
    regularity = Math.max(0, Math.min(100, Math.round((1 - coeffOfVariation) * 100)));

    if (regularity > 80) {
      suspiciousPatterns.push(`Beacon interval is highly regular (${regularity}% regularity). NDR/SIEM beaconing detection will flag this.`);
      recommendations.push("Increase jitter to at least 30% to reduce beacon regularity.");
    }

    // Check for exact intervals (no jitter at all)
    const uniqueIntervals = new Set(intervals.map(i => Math.round(i / 1000))); // Round to seconds
    if (uniqueIntervals.size <= 2 && intervals.length >= 5) {
      suspiciousPatterns.push("Beacon intervals are nearly identical — no jitter detected.");
      recommendations.push("Enable jitter immediately. Fixed-interval beaconing is a primary C2 detection indicator.");
    }
  }

  // Analyze channel diversity
  const uniqueChannels = new Set(channels);
  if (uniqueChannels.size === 1 && channels.length > 10) {
    suspiciousPatterns.push(`Single channel used for all ${channels.length} beacons. Channel diversity improves resilience.`);
    recommendations.push("Enable fallback channels to improve resilience and reduce single-channel fingerprinting.");
  }

  // Check against known detection technologies
  const ndrs = getDetectionTechnologies("network");
  if (regularity > 70) {
    for (const ndr of ndrs) {
      if (ndr.name.toLowerCase().includes("beacon") || ndr.name.toLowerCase().includes("traffic")) {
        suspiciousPatterns.push(`${ndr.name} (bypass difficulty: ${ndr.bypassDifficulty}/10) would likely detect this pattern.`);
      }
    }
  }

  return { regularity, suspiciousPatterns, recommendations };
}

/**
 * Get comprehensive OPSEC profile for an Ember agent.
 */
export function getEmberAgentOpsecProfile(agentId: string): EmberAgentOpsecProfile | null {
  const state = agentOpsecStates.get(agentId);
  if (!state) return null;

  const totalActions = state.actionHistory.length;
  const avgRisk = totalActions > 0
    ? state.actionHistory.reduce((sum, a) => sum + a.risk, 0) / totalActions
    : 0;
  const highRiskActions = state.actionHistory.filter(a => a.risk >= 60).length;
  const overallStatus = calculateEngagementOpsecStatus(state.actionHistory);

  const burnIndicators = checkBurnIndicators(state.burnEvents);

  const recommendations: string[] = [];
  if (avgRisk > 50) recommendations.push("Average risk is elevated. Consider using lower-risk alternatives.");
  if (highRiskActions > 5) recommendations.push(`${highRiskActions} high-risk actions recorded. Review necessity of each.`);
  if (state.evasionLevel >= 2) recommendations.push("Agent is in evasive mode. Limit operations to essential tasks only.");
  if (needsKeyRotation(agentId)) recommendations.push("Session key rotation is overdue. Rotate immediately.");

  const cryptoState = getAgentCryptoState(agentId);
  if (cryptoState && cryptoState.rotationCount === 0 && Date.now() - cryptoState.currentKeyCreatedAt > 7200_000) {
    recommendations.push("No key rotation performed in 2+ hours. Enable automatic rotation.");
  }

  return {
    agentId,
    totalActions,
    cumulativeRisk: state.cumulativeRisk,
    averageRisk: Math.round(avgRisk),
    highRiskActions,
    burnIndicators,
    overallStatus,
    actionHistory: state.actionHistory.slice(-50).map(a => ({
      taskType: a.action.replace("ember:", ""),
      riskScore: a.risk,
      timestamp: a.timestamp,
      detected: a.detected,
    })),
    trafficAnalysis: {
      beaconRegularity: 0, // Populated by analyzeEmberTrafficPattern
      trafficVolume: totalActions < 10 ? "low" : totalActions < 50 ? "medium" : "high",
      protocolDiversity: 1, // Default — updated by traffic analysis
      encryptionConsistency: true,
    },
    recommendations,
  };
}

/**
 * Get fleet-wide OPSEC summary across all Ember agents.
 */
export function getEmberFleetOpsecSummary(): EmberFleetOpsecSummary {
  const agents = Array.from(agentOpsecStates.values());
  const totalAgents = agents.length;
  const activeAgents = agents.filter(a => a.evasionLevel < 4).length;
  const burnedAgents = agents.filter(a => a.evasionLevel >= 3).length;
  const agentsNeedingRotation = agents.filter(a => needsKeyRotation(a.agentId)).length;

  const allActions = agents.flatMap(a => a.actionHistory);
  const totalActions = allActions.length;
  const averageRisk = totalActions > 0
    ? Math.round(allActions.reduce((sum, a) => sum + a.risk, 0) / totalActions)
    : 0;

  const overallStatus = totalAgents === 0 ? "green" as const
    : burnedAgents > 0 ? "red" as const
    : averageRisk > 55 ? "orange" as const
    : averageRisk > 35 ? "yellow" as const
    : "green" as const;

  const topRisks = agents
    .filter(a => a.actionHistory.length > 0)
    .map(a => ({
      agentId: a.agentId,
      riskScore: Math.round(a.cumulativeRisk / Math.max(a.actionHistory.length, 1)),
      lastAction: a.actionHistory[a.actionHistory.length - 1]?.action || "none",
    }))
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 5);

  const recommendations: string[] = [];
  if (burnedAgents > 0) recommendations.push(`${burnedAgents} agent(s) in critical evasion mode. Consider termination.`);
  if (agentsNeedingRotation > 0) recommendations.push(`${agentsNeedingRotation} agent(s) need key rotation.`);
  if (averageRisk > 50) recommendations.push("Fleet average risk is elevated. Review operational tempo.");
  if (totalAgents > 10) recommendations.push("Large fleet detected. Ensure agents are not creating correlated traffic patterns.");

  return {
    totalAgents,
    activeAgents,
    overallStatus,
    totalActions,
    averageRisk,
    burnedAgents,
    agentsNeedingRotation,
    topRisks,
    recommendations,
  };
}

/**
 * Reset OPSEC state for an agent (on termination or re-deployment).
 */
export function resetAgentOpsecState(agentId: string): void {
  agentOpsecStates.delete(agentId);
}

/**
 * Get the current evasion level for an agent.
 */
export function getAgentEvasionLevel(agentId: string): {
  level: number;
  name: string;
  actions: string[];
  description: string;
} {
  const state = agentOpsecStates.get(agentId);
  const level = state?.evasionLevel || 0;
  return EVASION_LEVELS[level];
}

/**
 * Manually set evasion level (operator override).
 */
export function setAgentEvasionLevel(agentId: string, level: number): void {
  const state = getOrCreateAgentOpsecState(agentId);
  state.evasionLevel = Math.max(0, Math.min(4, level));
}

/**
 * Add a burn event for an agent (external detection signal).
 */
export function reportEmberBurnEvent(
  agentId: string,
  eventType: string,
  success: boolean,
  details?: string,
): void {
  const state = getOrCreateAgentOpsecState(agentId);
  state.burnEvents.push({
    type: eventType,
    success,
    timestamp: Date.now(),
    details,
  });

  // Keep bounded
  if (state.burnEvents.length > 200) {
    state.burnEvents = state.burnEvents.slice(-100);
  }

  // Check for burn indicators after adding the event
  checkEmberBurnIndicators(agentId);
}
