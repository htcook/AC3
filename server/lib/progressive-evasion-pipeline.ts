// @ts-nocheck
/**
 * Progressive Evasion Pipeline
 * ═════════════════════════════
 * Operator-controlled evasion system for Red Team and Pentest engagements.
 * 
 * Philosophy: Start quiet, get louder. The operator controls escalation —
 * NOT the system. Auto-escalation is disabled by default.
 * 
 * Flow:
 *   1. WAF/IDS fingerprint → determine what's in front of targets
 *   2. Operator selects starting evasion level (default: stealth)
 *   3. Scan runs with selected evasion profile
 *   4. Pipeline PAUSES between scan types for operator review
 *   5. Operator can: resume, re-scan (same/different level), upload manual results, send to client
 *   6. Operator manually escalates when ready → next scan runs louder
 *   7. Track which level triggered detection per target
 * 
 * Available for: pentest, red_team engagement types
 */

// ═══════════════════════════════════════════════════════════════════════
// §1 — EVASION LEVEL DEFINITIONS (Operator-Facing)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Operator-facing evasion levels ordered from quietest to loudest.
 * This is the REVERSE of the existing escalation engine (which goes 1=Normal → 5=Stealth).
 * Here: stealth is the STARTING point, noisy is the last resort.
 */
export type OperatorEvasionLevel = "stealth" | "low" | "medium" | "aggressive" | "noisy";

export const EVASION_LEVELS: Record<OperatorEvasionLevel, EvasionLevelConfig> = {
  stealth: {
    level: 1,
    name: "Stealth",
    description: "Minimum footprint. Slowest but hardest to detect. Mimics normal user traffic.",
    nmapTiming: "T1",
    requestsPerSecond: 1,
    delayBetweenRequestsMs: 5000,
    jitterRangeMs: 3000,
    fragmentation: true,
    decoys: true,
    randomizeHosts: true,
    dataLengthPadding: true,
    sourcePortSpoofing: true,
    userAgentStrategy: "browser_mimic" as const,
    encodingTricks: [],
    headerManipulation: false,
    chunkedTransfer: false,
    useHttp2: false,
    ipRotation: "none" as const,
    scanBatchSize: 5,
    cooldownBetweenBatchesMs: 30000,
    maxConcurrentTargets: 1,
    dnsResolutionDelay: 2000,
    tcpConnectTimeout: 10000,
    retryOnBlock: false,
    autoEscalate: false,
  },
  low: {
    level: 2,
    name: "Low",
    description: "Cautious scanning. Slightly faster, still avoids most detection thresholds.",
    nmapTiming: "T2",
    requestsPerSecond: 5,
    delayBetweenRequestsMs: 2000,
    jitterRangeMs: 1500,
    fragmentation: true,
    decoys: true,
    randomizeHosts: true,
    dataLengthPadding: true,
    sourcePortSpoofing: false,
    userAgentStrategy: "browser_mimic" as const,
    encodingTricks: ["mixed_case"],
    headerManipulation: false,
    chunkedTransfer: false,
    useHttp2: true,
    ipRotation: "none" as const,
    scanBatchSize: 10,
    cooldownBetweenBatchesMs: 15000,
    maxConcurrentTargets: 2,
    dnsResolutionDelay: 1000,
    tcpConnectTimeout: 8000,
    retryOnBlock: false,
    autoEscalate: false,
  },
  medium: {
    level: 3,
    name: "Medium",
    description: "Balanced speed vs. detection risk. Standard pentest pace with basic evasion.",
    nmapTiming: "T3",
    requestsPerSecond: 15,
    delayBetweenRequestsMs: 500,
    jitterRangeMs: 500,
    fragmentation: true,
    decoys: false,
    randomizeHosts: true,
    dataLengthPadding: false,
    sourcePortSpoofing: false,
    userAgentStrategy: "browser_mimic" as const,
    encodingTricks: ["double_url_encode", "mixed_case"],
    headerManipulation: true,
    chunkedTransfer: false,
    useHttp2: true,
    ipRotation: "none" as const,
    scanBatchSize: 25,
    cooldownBetweenBatchesMs: 5000,
    maxConcurrentTargets: 3,
    dnsResolutionDelay: 500,
    tcpConnectTimeout: 5000,
    retryOnBlock: true,
    autoEscalate: false,
  },
  aggressive: {
    level: 4,
    name: "Aggressive",
    description: "Fast scanning with active WAF bypass techniques. Will likely trigger alerts.",
    nmapTiming: "T4",
    requestsPerSecond: 40,
    delayBetweenRequestsMs: 100,
    jitterRangeMs: 100,
    fragmentation: false,
    decoys: false,
    randomizeHosts: false,
    dataLengthPadding: false,
    sourcePortSpoofing: false,
    userAgentStrategy: "scanner" as const,
    encodingTricks: ["double_url_encode", "unicode_normalization", "mixed_case", "null_byte_insertion", "hex_encoding"],
    headerManipulation: true,
    chunkedTransfer: true,
    useHttp2: true,
    ipRotation: "proxy_chain" as const,
    scanBatchSize: 50,
    cooldownBetweenBatchesMs: 1000,
    maxConcurrentTargets: 5,
    dnsResolutionDelay: 0,
    tcpConnectTimeout: 3000,
    retryOnBlock: true,
    autoEscalate: false,
  },
  noisy: {
    level: 5,
    name: "Noisy",
    description: "Maximum speed, no evasion. Used to test detection thresholds or when stealth is unnecessary.",
    nmapTiming: "T5",
    requestsPerSecond: 100,
    delayBetweenRequestsMs: 0,
    jitterRangeMs: 0,
    fragmentation: false,
    decoys: false,
    randomizeHosts: false,
    dataLengthPadding: false,
    sourcePortSpoofing: false,
    userAgentStrategy: "scanner" as const,
    encodingTricks: [],
    headerManipulation: false,
    chunkedTransfer: false,
    useHttp2: false,
    ipRotation: "none" as const,
    scanBatchSize: 100,
    cooldownBetweenBatchesMs: 0,
    maxConcurrentTargets: 10,
    dnsResolutionDelay: 0,
    tcpConnectTimeout: 2000,
    retryOnBlock: false,
    autoEscalate: false,
  },
};

export interface EvasionLevelConfig {
  level: number;
  name: string;
  description: string;
  nmapTiming: string;
  requestsPerSecond: number;
  delayBetweenRequestsMs: number;
  jitterRangeMs: number;
  fragmentation: boolean;
  decoys: boolean;
  randomizeHosts: boolean;
  dataLengthPadding: boolean;
  sourcePortSpoofing: boolean;
  userAgentStrategy: "browser_mimic" | "scanner" | "bot" | "custom";
  encodingTricks: string[];
  headerManipulation: boolean;
  chunkedTransfer: boolean;
  useHttp2: boolean;
  ipRotation: "none" | "proxy_chain" | "tor";
  scanBatchSize: number;
  cooldownBetweenBatchesMs: number;
  maxConcurrentTargets: number;
  dnsResolutionDelay: number;
  tcpConnectTimeout: number;
  retryOnBlock: boolean;
  autoEscalate: boolean;
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — OPERATOR EVASION OVERRIDES
// ═══════════════════════════════════════════════════════════════════════

/**
 * Operator can override individual settings within a level.
 * Partial overrides are merged on top of the base level config.
 */
export interface OperatorEvasionOverrides {
  /** Override timing template (T0-T5) */
  nmapTiming?: string;
  /** Override requests per second */
  requestsPerSecond?: number;
  /** Override delay between requests */
  delayBetweenRequestsMs?: number;
  /** Override jitter range */
  jitterRangeMs?: number;
  /** Override fragmentation setting */
  fragmentation?: boolean;
  /** Override decoy usage */
  decoys?: boolean;
  /** Override host randomization */
  randomizeHosts?: boolean;
  /** Override data length padding */
  dataLengthPadding?: boolean;
  /** Override source port spoofing */
  sourcePortSpoofing?: boolean;
  /** Override user agent strategy */
  userAgentStrategy?: "browser_mimic" | "scanner" | "bot" | "custom";
  /** Custom user agent string (when strategy is 'custom') */
  customUserAgent?: string;
  /** Override encoding tricks */
  encodingTricks?: string[];
  /** Override header manipulation */
  headerManipulation?: boolean;
  /** Override chunked transfer */
  chunkedTransfer?: boolean;
  /** Override HTTP/2 usage */
  useHttp2?: boolean;
  /** Override IP rotation strategy */
  ipRotation?: "none" | "proxy_chain" | "tor";
  /** Override scan batch size */
  scanBatchSize?: number;
  /** Override cooldown between batches */
  cooldownBetweenBatchesMs?: number;
  /** Override max concurrent targets */
  maxConcurrentTargets?: number;
  /** Enable auto-escalation (operator opt-in) */
  autoEscalate?: boolean;
  /** Custom nmap flags to append */
  customNmapFlags?: string[];
  /** Custom nuclei rate limit */
  nucleiRateLimit?: number;
  /** Custom httpx threads */
  httpxThreads?: number;
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — PIPELINE PAUSE GATES
// ═══════════════════════════════════════════════════════════════════════

export type PipelinePauseReason =
  | "between_scan_types"        // Pause between recon → port scan → vuln scan → exploit
  | "waf_detected"              // WAF/IDS detected, pause for operator decision
  | "detection_triggered"       // Scan was detected/blocked, pause for operator
  | "pre_exploit"               // Before exploitation phase, require approval
  | "operator_requested"        // Operator manually paused
  | "evasion_level_change"      // Operator changed evasion level, pause to confirm
  | "client_approval_required"; // Waiting for client sign-off

export type PipelineGateAction =
  | "resume"                    // Continue pipeline at current evasion level
  | "rescan_same_level"         // Re-run the last scan at the same evasion level
  | "rescan_different_level"    // Re-run the last scan at a different evasion level
  | "escalate"                  // Move to next (louder) evasion level and continue
  | "deescalate"                // Move to previous (quieter) evasion level and continue
  | "upload_manual_results"     // Operator uploads results from external tools
  | "send_to_client"            // Send current findings to client for review/approval
  | "skip_phase"                // Skip the next phase entirely
  | "abort";                    // Stop the pipeline

export interface PipelinePauseGate {
  id: string;
  engagementId: number;
  phase: string;
  nextPhase: string;
  reason: PipelinePauseReason;
  title: string;
  description: string;
  currentEvasionLevel: OperatorEvasionLevel;
  currentOverrides?: OperatorEvasionOverrides;
  /** What the operator can do at this gate */
  availableActions: PipelineGateAction[];
  /** Findings so far that inform the operator's decision */
  findingsSummary: {
    hostsScanned: number;
    portsFound: number;
    vulnsFound: number;
    wafDetections: string[];
    blockedAttempts: number;
    detectionEvents: DetectionEvent[];
  };
  /** Scan results from the just-completed phase */
  lastScanResults?: {
    scanType: string;
    duration: number;
    targetsScanned: number;
    evasionLevelUsed: OperatorEvasionLevel;
    wasDetected: boolean;
    detectionDetails?: string;
  };
  status: "pending" | "resolved";
  createdAt: number;
  resolvedAt?: number;
  resolvedBy?: string;
  resolution?: {
    action: PipelineGateAction;
    newEvasionLevel?: OperatorEvasionLevel;
    newOverrides?: OperatorEvasionOverrides;
    notes?: string;
    manualResultsUploaded?: boolean;
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — DETECTION TRACKING
// ═══════════════════════════════════════════════════════════════════════

export interface DetectionEvent {
  id: string;
  engagementId: number;
  target: string;
  timestamp: number;
  evasionLevel: OperatorEvasionLevel;
  /** What detected us */
  detectedBy: "waf" | "ids" | "ips" | "rate_limiter" | "captcha" | "ip_ban" | "siem" | "unknown";
  /** Detection product name if known */
  detectionProduct?: string;
  /** How we know we were detected */
  evidence: string;
  /** HTTP status code if applicable */
  statusCode?: number;
  /** Response snippet showing the block */
  responseSnippet?: string;
  /** Which scan tool was running when detected */
  scanTool: string;
  /** Impact on scan coverage */
  impact: "scan_blocked" | "scan_degraded" | "scan_unaffected";
  /** Operator notes */
  notes?: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — PIPELINE STATE (per-engagement)
// ═══════════════════════════════════════════════════════════════════════

export interface ProgressiveEvasionState {
  engagementId: number;
  engagementType: "pentest" | "red_team";
  /** Current operator-selected evasion level */
  currentLevel: OperatorEvasionLevel;
  /** Operator overrides on top of the current level */
  overrides: OperatorEvasionOverrides;
  /** History of evasion level changes */
  levelHistory: Array<{
    level: OperatorEvasionLevel;
    changedAt: number;
    changedBy: string;
    reason: string;
    phase: string;
  }>;
  /** All detection events across the engagement */
  detectionEvents: DetectionEvent[];
  /** Per-target detection tracking: which level triggered detection */
  targetDetectionMap: Record<string, {
    firstDetectedAt: OperatorEvasionLevel;
    lastSuccessfulLevel: OperatorEvasionLevel;
    detectionCount: number;
    blockedCompletely: boolean;
  }>;
  /** Active pause gates */
  pauseGates: PipelinePauseGate[];
  /** Scan run history with evasion level used */
  scanHistory: ScanRunRecord[];
  /** Whether auto-escalation is enabled (operator opt-in) */
  autoEscalateEnabled: boolean;
  /** Pipeline configuration */
  pipelineConfig: {
    /** Pause between all scan types (default: true for red_team, false for pentest) */
    pauseBetweenScans: boolean;
    /** Always pause before exploitation (default: true) */
    pauseBeforeExploit: boolean;
    /** Pause on any detection event (default: true for red_team) */
    pauseOnDetection: boolean;
    /** Require client approval before exploit (default: true) */
    requireClientApproval: boolean;
  };
}

export interface ScanRunRecord {
  id: string;
  engagementId: number;
  phase: string;
  scanType: string;
  evasionLevel: OperatorEvasionLevel;
  overrides?: OperatorEvasionOverrides;
  startedAt: number;
  completedAt?: number;
  status: "running" | "completed" | "blocked" | "aborted";
  targetsScanned: number;
  findingsCount: number;
  detectionEvents: DetectionEvent[];
  /** Whether this was a re-scan (operator chose to re-run) */
  isRescan: boolean;
  /** Previous scan ID if this is a re-scan */
  previousScanId?: string;
  /** Effective config after overrides applied */
  effectiveConfig: EvasionLevelConfig;
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — CORE FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

/** In-memory state store for progressive evasion pipelines */
const pipelineStates = new Map<number, ProgressiveEvasionState>();

/**
 * Initialize the progressive evasion pipeline for an engagement.
 * Called when an operator starts a pentest or red_team engagement.
 */
export function initProgressiveEvasion(
  engagementId: number,
  engagementType: "pentest" | "red_team",
  startingLevel: OperatorEvasionLevel = "stealth",
  operatorId: string,
  config?: Partial<ProgressiveEvasionState["pipelineConfig"]>
): ProgressiveEvasionState {
  const defaultConfig: ProgressiveEvasionState["pipelineConfig"] = {
    pauseBetweenScans: engagementType === "red_team",
    pauseBeforeExploit: true,
    pauseOnDetection: engagementType === "red_team",
    requireClientApproval: true,
    ...config,
  };

  const state: ProgressiveEvasionState = {
    engagementId,
    engagementType,
    currentLevel: startingLevel,
    overrides: {},
    levelHistory: [{
      level: startingLevel,
      changedAt: Date.now(),
      changedBy: operatorId,
      reason: "Initial evasion level selection",
      phase: "initialization",
    }],
    detectionEvents: [],
    targetDetectionMap: {},
    pauseGates: [],
    scanHistory: [],
    autoEscalateEnabled: false,
    pipelineConfig: defaultConfig,
  };

  pipelineStates.set(engagementId, state);
  return state;
}

/**
 * Get the current progressive evasion state for an engagement.
 */
export function getProgressiveEvasionState(engagementId: number): ProgressiveEvasionState | null {
  return pipelineStates.get(engagementId) || null;
}

/**
 * Resolve the effective evasion config for the current level + overrides.
 * This is what gets passed to scan tools.
 */
export function getEffectiveEvasionConfig(
  engagementId: number
): EvasionLevelConfig {
  const state = pipelineStates.get(engagementId);
  if (!state) {
    // Default to stealth if no pipeline initialized
    return { ...EVASION_LEVELS.stealth };
  }
  const baseConfig = { ...EVASION_LEVELS[state.currentLevel] };
  const overrides = state.overrides;

  // Apply operator overrides on top of base level
  if (overrides.nmapTiming !== undefined) baseConfig.nmapTiming = overrides.nmapTiming;
  if (overrides.requestsPerSecond !== undefined) baseConfig.requestsPerSecond = overrides.requestsPerSecond;
  if (overrides.delayBetweenRequestsMs !== undefined) baseConfig.delayBetweenRequestsMs = overrides.delayBetweenRequestsMs;
  if (overrides.jitterRangeMs !== undefined) baseConfig.jitterRangeMs = overrides.jitterRangeMs;
  if (overrides.fragmentation !== undefined) baseConfig.fragmentation = overrides.fragmentation;
  if (overrides.decoys !== undefined) baseConfig.decoys = overrides.decoys;
  if (overrides.randomizeHosts !== undefined) baseConfig.randomizeHosts = overrides.randomizeHosts;
  if (overrides.dataLengthPadding !== undefined) baseConfig.dataLengthPadding = overrides.dataLengthPadding;
  if (overrides.sourcePortSpoofing !== undefined) baseConfig.sourcePortSpoofing = overrides.sourcePortSpoofing;
  if (overrides.userAgentStrategy !== undefined) baseConfig.userAgentStrategy = overrides.userAgentStrategy;
  if (overrides.encodingTricks !== undefined) baseConfig.encodingTricks = overrides.encodingTricks;
  if (overrides.headerManipulation !== undefined) baseConfig.headerManipulation = overrides.headerManipulation;
  if (overrides.chunkedTransfer !== undefined) baseConfig.chunkedTransfer = overrides.chunkedTransfer;
  if (overrides.useHttp2 !== undefined) baseConfig.useHttp2 = overrides.useHttp2;
  if (overrides.ipRotation !== undefined) baseConfig.ipRotation = overrides.ipRotation;
  if (overrides.scanBatchSize !== undefined) baseConfig.scanBatchSize = overrides.scanBatchSize;
  if (overrides.cooldownBetweenBatchesMs !== undefined) baseConfig.cooldownBetweenBatchesMs = overrides.cooldownBetweenBatchesMs;
  if (overrides.maxConcurrentTargets !== undefined) baseConfig.maxConcurrentTargets = overrides.maxConcurrentTargets;
  if (overrides.autoEscalate !== undefined) baseConfig.autoEscalate = overrides.autoEscalate;

  return baseConfig;
}

/**
 * Convert effective evasion config to nmap command-line flags.
 */
export function evasionToNmapFlags(config: EvasionLevelConfig): string[] {
  const flags: string[] = [];

  // Timing template
  flags.push(`-${config.nmapTiming}`);

  // Fragmentation
  if (config.fragmentation) flags.push("-f", "--mtu", "24");

  // Decoys
  if (config.decoys) flags.push("-D", "RND:5");

  // Randomize hosts
  if (config.randomizeHosts) flags.push("--randomize-hosts");

  // Data length padding
  if (config.dataLengthPadding) flags.push("--data-length", "32");

  // Source port spoofing
  if (config.sourcePortSpoofing) flags.push("-g", "53");

  // Rate limiting via max-rate
  if (config.requestsPerSecond < 100) {
    flags.push("--max-rate", String(config.requestsPerSecond));
  }

  // Scan delay
  if (config.delayBetweenRequestsMs > 0) {
    flags.push("--scan-delay", `${config.delayBetweenRequestsMs}ms`);
  }

  // Max retries (lower for stealth)
  if (config.level <= 2) {
    flags.push("--max-retries", "1");
  }

  // Host timeout
  flags.push("--host-timeout", `${config.tcpConnectTimeout}ms`);

  return flags;
}

/**
 * Convert effective evasion config to nuclei rate/concurrency settings.
 */
export function evasionToNucleiConfig(config: EvasionLevelConfig, overrides?: OperatorEvasionOverrides): {
  rateLimit: number;
  concurrency: number;
  bulkSize: number;
  timeout: number;
  retries: number;
  interactshDisable: boolean;
} {
  return {
    rateLimit: overrides?.nucleiRateLimit || Math.max(1, Math.floor(config.requestsPerSecond / 2)),
    concurrency: config.maxConcurrentTargets,
    bulkSize: Math.min(config.scanBatchSize, 25),
    timeout: config.level <= 2 ? 15 : config.level <= 3 ? 10 : 5,
    retries: config.level <= 2 ? 0 : 1,
    interactshDisable: config.level <= 2, // Disable OOB interactions in stealth
  };
}

/**
 * Convert effective evasion config to httpx settings.
 */
export function evasionToHttpxConfig(config: EvasionLevelConfig, overrides?: OperatorEvasionOverrides): {
  threads: number;
  rateLimit: number;
  timeout: number;
  retries: number;
  randomAgent: boolean;
  followRedirects: boolean;
} {
  return {
    threads: overrides?.httpxThreads || config.maxConcurrentTargets,
    rateLimit: config.requestsPerSecond,
    timeout: config.tcpConnectTimeout / 1000,
    retries: config.level <= 2 ? 0 : 1,
    randomAgent: config.userAgentStrategy === "browser_mimic",
    followRedirects: true,
  };
}

/**
 * Operator changes the evasion level.
 */
export function changeEvasionLevel(
  engagementId: number,
  newLevel: OperatorEvasionLevel,
  operatorId: string,
  reason: string,
  currentPhase: string
): { success: boolean; previousLevel: OperatorEvasionLevel; newLevel: OperatorEvasionLevel } {
  const state = pipelineStates.get(engagementId);
  if (!state) return { success: false, previousLevel: "stealth", newLevel };

  const previousLevel = state.currentLevel;
  state.currentLevel = newLevel;
  state.levelHistory.push({
    level: newLevel,
    changedAt: Date.now(),
    changedBy: operatorId,
    reason,
    phase: currentPhase,
  });

  return { success: true, previousLevel, newLevel };
}

/**
 * Operator updates evasion overrides (fine-tuning individual settings).
 */
export function updateEvasionOverrides(
  engagementId: number,
  overrides: OperatorEvasionOverrides
): { success: boolean; effectiveConfig: EvasionLevelConfig } {
  const state = pipelineStates.get(engagementId);
  if (!state) return { success: false, effectiveConfig: EVASION_LEVELS.stealth };

  state.overrides = { ...state.overrides, ...overrides };
  const effectiveConfig = getEffectiveEvasionConfig(engagementId);
  return { success: true, effectiveConfig };
}

/**
 * Reset overrides back to the base level defaults.
 */
export function resetEvasionOverrides(engagementId: number): boolean {
  const state = pipelineStates.get(engagementId);
  if (!state) return false;
  state.overrides = {};
  return true;
}

// ═══════════════════════════════════════════════════════════════════════
// §7 — PAUSE GATE MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════

/**
 * Create a pause gate between pipeline phases.
 * The pipeline will not proceed until the operator resolves this gate.
 */
export function createPauseGate(
  engagementId: number,
  params: {
    phase: string;
    nextPhase: string;
    reason: PipelinePauseReason;
    title: string;
    description: string;
    findingsSummary: PipelinePauseGate["findingsSummary"];
    lastScanResults?: PipelinePauseGate["lastScanResults"];
  }
): PipelinePauseGate | null {
  const state = pipelineStates.get(engagementId);
  if (!state) return null;

  // Determine available actions based on reason
  const availableActions = getAvailableActions(params.reason, state.pipelineConfig);

  const gate: PipelinePauseGate = {
    id: `pg_${engagementId}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    engagementId,
    phase: params.phase,
    nextPhase: params.nextPhase,
    reason: params.reason,
    title: params.title,
    description: params.description,
    currentEvasionLevel: state.currentLevel,
    currentOverrides: Object.keys(state.overrides).length > 0 ? { ...state.overrides } : undefined,
    availableActions,
    findingsSummary: params.findingsSummary,
    lastScanResults: params.lastScanResults,
    status: "pending",
    createdAt: Date.now(),
  };

  state.pauseGates.push(gate);
  return gate;
}

/**
 * Determine which actions are available at a pause gate.
 */
function getAvailableActions(
  reason: PipelinePauseReason,
  config: ProgressiveEvasionState["pipelineConfig"]
): PipelineGateAction[] {
  const base: PipelineGateAction[] = ["resume", "abort"];

  switch (reason) {
    case "between_scan_types":
      return [...base, "rescan_same_level", "rescan_different_level", "escalate", "deescalate", "upload_manual_results", "skip_phase"];
    case "waf_detected":
      return [...base, "rescan_different_level", "escalate", "deescalate", "upload_manual_results"];
    case "detection_triggered":
      return [...base, "rescan_different_level", "deescalate", "upload_manual_results"];
    case "pre_exploit":
      return [...base, "rescan_same_level", "rescan_different_level", "upload_manual_results", "send_to_client"];
    case "operator_requested":
      return [...base, "rescan_same_level", "rescan_different_level", "escalate", "deescalate", "upload_manual_results", "send_to_client", "skip_phase"];
    case "evasion_level_change":
      return [...base, "rescan_same_level"];
    case "client_approval_required":
      return ["resume", "abort", "send_to_client"];
    default:
      return base;
  }
}

/**
 * Resolve a pause gate with the operator's chosen action.
 */
export function resolvePauseGate(
  engagementId: number,
  gateId: string,
  resolution: {
    action: PipelineGateAction;
    operatorId: string;
    newEvasionLevel?: OperatorEvasionLevel;
    newOverrides?: OperatorEvasionOverrides;
    notes?: string;
    manualResultsUploaded?: boolean;
  }
): { success: boolean; gate?: PipelinePauseGate; error?: string } {
  const state = pipelineStates.get(engagementId);
  if (!state) return { success: false, error: "No pipeline state found" };

  const gate = state.pauseGates.find(g => g.id === gateId);
  if (!gate) return { success: false, error: "Gate not found" };
  if (gate.status !== "pending") return { success: false, error: "Gate already resolved" };

  // Validate action is available
  if (!gate.availableActions.includes(resolution.action)) {
    return { success: false, error: `Action '${resolution.action}' not available at this gate` };
  }

  // Apply evasion level change if escalating/de-escalating
  if (resolution.action === "escalate") {
    const nextLevel = getNextLevel(state.currentLevel);
    if (nextLevel) {
      changeEvasionLevel(engagementId, nextLevel, resolution.operatorId, "Operator escalated at pause gate", gate.phase);
    }
  } else if (resolution.action === "deescalate") {
    const prevLevel = getPreviousLevel(state.currentLevel);
    if (prevLevel) {
      changeEvasionLevel(engagementId, prevLevel, resolution.operatorId, "Operator de-escalated at pause gate", gate.phase);
    }
  } else if (resolution.action === "rescan_different_level" && resolution.newEvasionLevel) {
    changeEvasionLevel(engagementId, resolution.newEvasionLevel, resolution.operatorId, "Operator selected different level for re-scan", gate.phase);
  }

  // Apply override changes
  if (resolution.newOverrides) {
    updateEvasionOverrides(engagementId, resolution.newOverrides);
  }

  // Resolve the gate
  gate.status = "resolved";
  gate.resolvedAt = Date.now();
  gate.resolvedBy = resolution.operatorId;
  gate.resolution = {
    action: resolution.action,
    newEvasionLevel: resolution.newEvasionLevel,
    newOverrides: resolution.newOverrides,
    notes: resolution.notes,
    manualResultsUploaded: resolution.manualResultsUploaded,
  };

  return { success: true, gate };
}

/**
 * Get the next louder evasion level.
 */
export function getNextLevel(current: OperatorEvasionLevel): OperatorEvasionLevel | null {
  const order: OperatorEvasionLevel[] = ["stealth", "low", "medium", "aggressive", "noisy"];
  const idx = order.indexOf(current);
  return idx < order.length - 1 ? order[idx + 1] : null;
}

/**
 * Get the previous quieter evasion level.
 */
export function getPreviousLevel(current: OperatorEvasionLevel): OperatorEvasionLevel | null {
  const order: OperatorEvasionLevel[] = ["stealth", "low", "medium", "aggressive", "noisy"];
  const idx = order.indexOf(current);
  return idx > 0 ? order[idx - 1] : null;
}

// ═══════════════════════════════════════════════════════════════════════
// §8 — DETECTION EVENT RECORDING
// ═══════════════════════════════════════════════════════════════════════

/**
 * Record a detection event (scan was blocked/detected).
 */
export function recordDetection(
  engagementId: number,
  event: Omit<DetectionEvent, "id">
): DetectionEvent | null {
  const state = pipelineStates.get(engagementId);
  if (!state) return null;

  const detection: DetectionEvent = {
    ...event,
    id: `det_${engagementId}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
  };

  state.detectionEvents.push(detection);

  // Update per-target tracking
  const targetKey = event.target;
  if (!state.targetDetectionMap[targetKey]) {
    state.targetDetectionMap[targetKey] = {
      firstDetectedAt: event.evasionLevel,
      lastSuccessfulLevel: getPreviousLevel(event.evasionLevel) || "stealth",
      detectionCount: 1,
      blockedCompletely: event.impact === "scan_blocked",
    };
  } else {
    state.targetDetectionMap[targetKey].detectionCount++;
    if (event.impact === "scan_blocked") {
      state.targetDetectionMap[targetKey].blockedCompletely = true;
    }
  }

  // Auto-pause if configured
  if (state.pipelineConfig.pauseOnDetection) {
    createPauseGate(engagementId, {
      phase: event.scanTool,
      nextPhase: "operator_decision",
      reason: "detection_triggered",
      title: `Detection: ${event.detectedBy} blocked scan on ${event.target}`,
      description: `${event.detectionProduct || event.detectedBy} detected our ${event.scanTool} scan at evasion level "${event.evasionLevel}". ${event.evidence}`,
      findingsSummary: {
        hostsScanned: 0,
        portsFound: 0,
        vulnsFound: 0,
        wafDetections: [event.detectionProduct || event.detectedBy],
        blockedAttempts: 1,
        detectionEvents: [detection],
      },
    });
  }

  return detection;
}

/**
 * Get detection summary for an engagement — shows which targets were detected at which levels.
 */
export function getDetectionSummary(engagementId: number): {
  totalDetections: number;
  detectionsByLevel: Record<OperatorEvasionLevel, number>;
  detectionsByProduct: Record<string, number>;
  targetMap: ProgressiveEvasionState["targetDetectionMap"];
  recommendations: string[];
} | null {
  const state = pipelineStates.get(engagementId);
  if (!state) return null;

  const byLevel: Record<OperatorEvasionLevel, number> = { stealth: 0, low: 0, medium: 0, aggressive: 0, noisy: 0 };
  const byProduct: Record<string, number> = {};

  for (const event of state.detectionEvents) {
    byLevel[event.evasionLevel]++;
    const product = event.detectionProduct || event.detectedBy;
    byProduct[product] = (byProduct[product] || 0) + 1;
  }

  const recommendations: string[] = [];
  if (byLevel.stealth > 0) {
    recommendations.push("Target has aggressive detection — even stealth scans are being caught. Consider manual testing only.");
  }
  if (byLevel.low > 0 && byLevel.stealth === 0) {
    recommendations.push("Stealth level works. Stay at stealth for sensitive targets, escalate cautiously.");
  }
  if (Object.keys(state.targetDetectionMap).some(t => state.targetDetectionMap[t].blockedCompletely)) {
    recommendations.push("Some targets are completely blocking scans. Upload manual tool results or request client to whitelist scan IP.");
  }

  return {
    totalDetections: state.detectionEvents.length,
    detectionsByLevel: byLevel,
    detectionsByProduct: byProduct,
    targetMap: state.targetDetectionMap,
    recommendations,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §9 — SCAN RUN RECORDING
// ═══════════════════════════════════════════════════════════════════════

/**
 * Record the start of a scan run.
 */
export function startScanRun(
  engagementId: number,
  params: {
    phase: string;
    scanType: string;
    targetsCount: number;
    isRescan?: boolean;
    previousScanId?: string;
  }
): ScanRunRecord | null {
  const state = pipelineStates.get(engagementId);
  if (!state) return null;

  const effectiveConfig = getEffectiveEvasionConfig(engagementId);
  const record: ScanRunRecord = {
    id: `scan_${engagementId}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    engagementId,
    phase: params.phase,
    scanType: params.scanType,
    evasionLevel: state.currentLevel,
    overrides: Object.keys(state.overrides).length > 0 ? { ...state.overrides } : undefined,
    startedAt: Date.now(),
    status: "running",
    targetsScanned: params.targetsCount,
    findingsCount: 0,
    detectionEvents: [],
    isRescan: params.isRescan || false,
    previousScanId: params.previousScanId,
    effectiveConfig,
  };

  state.scanHistory.push(record);
  return record;
}

/**
 * Complete a scan run with results.
 */
export function completeScanRun(
  engagementId: number,
  scanId: string,
  results: {
    status: "completed" | "blocked" | "aborted";
    findingsCount: number;
    detectionEvents?: DetectionEvent[];
  }
): boolean {
  const state = pipelineStates.get(engagementId);
  if (!state) return false;

  const record = state.scanHistory.find(s => s.id === scanId);
  if (!record) return false;

  record.completedAt = Date.now();
  record.status = results.status;
  record.findingsCount = results.findingsCount;
  if (results.detectionEvents) {
    record.detectionEvents = results.detectionEvents;
  }

  return true;
}

// ═══════════════════════════════════════════════════════════════════════
// §10 — PIPELINE PHASE TRANSITION LOGIC
// ═══════════════════════════════════════════════════════════════════════

/**
 * Determine if the pipeline should pause before transitioning to the next phase.
 * Called by the engagement orchestrator at each phase boundary.
 */
export function shouldPauseBeforePhase(
  engagementId: number,
  currentPhase: string,
  nextPhase: string,
  stats: PipelinePauseGate["findingsSummary"]
): { shouldPause: boolean; reason?: PipelinePauseReason } {
  const state = pipelineStates.get(engagementId);
  if (!state) return { shouldPause: false };

  // Always pause before exploitation
  if (nextPhase === "exploitation" && state.pipelineConfig.pauseBeforeExploit) {
    return { shouldPause: true, reason: "pre_exploit" };
  }

  // Pause between scan types if configured
  const scanPhases = ["enumeration", "vuln_detection"];
  if (state.pipelineConfig.pauseBetweenScans && scanPhases.includes(nextPhase)) {
    return { shouldPause: true, reason: "between_scan_types" };
  }

  // Pause if WAF was detected and we haven't acknowledged it yet
  if (stats.wafDetections.length > 0 && !state.pauseGates.some(g => g.reason === "waf_detected" && g.status === "resolved")) {
    return { shouldPause: true, reason: "waf_detected" };
  }

  // Pause if there were recent detection events
  if (state.pipelineConfig.pauseOnDetection && stats.detectionEvents.length > 0) {
    return { shouldPause: true, reason: "detection_triggered" };
  }

  return { shouldPause: false };
}

/**
 * Check if the pipeline has an unresolved pause gate blocking progression.
 */
export function hasPendingPauseGate(engagementId: number): PipelinePauseGate | null {
  const state = pipelineStates.get(engagementId);
  if (!state) return null;
  return state.pauseGates.find(g => g.status === "pending") || null;
}

/**
 * Get all evasion levels with their descriptions (for UI display).
 */
export function getEvasionLevels(): Array<{
  id: OperatorEvasionLevel;
  level: number;
  name: string;
  description: string;
  keySettings: string[];
}> {
  return Object.entries(EVASION_LEVELS).map(([id, config]) => ({
    id: id as OperatorEvasionLevel,
    level: config.level,
    name: config.name,
    description: config.description,
    keySettings: [
      `Timing: ${config.nmapTiming}`,
      `Rate: ${config.requestsPerSecond} req/s`,
      `Fragmentation: ${config.fragmentation ? "Yes" : "No"}`,
      `Decoys: ${config.decoys ? "Yes" : "No"}`,
      `IP Rotation: ${config.ipRotation}`,
      `Batch Size: ${config.scanBatchSize}`,
    ],
  }));
}

/**
 * Convert the discoveryEvasionProfile format (used by scan plan LLM) to our operator-facing format.
 * Bridges the existing LLM-generated scan plan with the operator's evasion selection.
 */
export function operatorLevelToDiscoveryProfile(level: OperatorEvasionLevel, overrides?: OperatorEvasionOverrides): {
  timing: string;
  fragmentation: boolean;
  decoys: boolean;
  randomizeHosts: boolean;
  dataLengthPadding: boolean;
  sourcePortSpoofing: boolean;
  rationale: string;
} {
  const config = EVASION_LEVELS[level];
  return {
    timing: overrides?.nmapTiming || config.nmapTiming,
    fragmentation: overrides?.fragmentation ?? config.fragmentation,
    decoys: overrides?.decoys ?? config.decoys,
    randomizeHosts: overrides?.randomizeHosts ?? config.randomizeHosts,
    dataLengthPadding: overrides?.dataLengthPadding ?? config.dataLengthPadding,
    sourcePortSpoofing: overrides?.sourcePortSpoofing ?? config.sourcePortSpoofing,
    rationale: `Operator-selected evasion level: ${config.name}. ${config.description}`,
  };
}
