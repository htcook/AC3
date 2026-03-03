/**
 * Cross-C2 Orchestrator — Coordinates operations across Caldera, Metasploit,
 * Sliver, Empire, and GoPhish for unified kill chain execution.
 *
 * Features:
 * - Cross-C2 ability chains (GoPhish → Caldera → MSF → Sliver → Empire)
 * - Automatic C2 handoff based on kill chain phase and framework strengths
 * - Shared agent context (credentials, sessions, pivots) between frameworks
 * - Coordinated timing with configurable delays and synchronization
 * - Fallback chains when primary C2 fails
 * - GoPhish phishing-to-C2 pipeline (payload delivery → callback → post-exploitation)
 * - Unified result aggregation across all frameworks
 */

import {
  C2FrameworkType,
  C2Agent,
  C2TaskRequest,
  C2TaskResult,
  C2HealthStatus,
  getC2Registry,
} from "./c2-abstraction";
import {
  processExecutionFeedback,
  recommendFramework,
  type ExecutionFeedback,
  type TargetContext,
} from "./c2-learning-engine";
import type { ScanMode } from "./scan-policy-engine";
import type { AbilityNodeData, AbilityEdgeData, EnvironmentContext } from "./ability-graph-engine";

// ─── Types ──────────────────────────────────────────────────────────────────

/** Extended framework type including GoPhish */
export type OrchestratedFramework = C2FrameworkType | "gophish";

export type KillChainPhase =
  | "reconnaissance"
  | "weaponization"
  | "delivery"         // GoPhish primary phase
  | "exploitation"
  | "installation"
  | "command_and_control"
  | "actions_on_objectives";

export type OrchestrationStatus =
  | "planning"
  | "initializing"
  | "running"
  | "paused"
  | "completed"
  | "failed"
  | "aborted";

export interface OrchestrationStep {
  id: string;
  order: number;
  phase: KillChainPhase;
  framework: OrchestratedFramework;
  fallbackFrameworks: OrchestratedFramework[];
  // Task details
  label: string;
  description: string;
  techniqueId?: string;
  moduleId: string;
  options: Record<string, any>;
  // Agent targeting
  targetAgentId?: string;        // Specific agent, or null for auto-select
  targetPlatform?: string;
  requiredPrivilege?: string;
  // Timing
  delayBeforeMs: number;         // Delay before executing this step
  timeoutMs: number;             // Max execution time
  // Dependencies
  dependsOn: string[];           // Step IDs that must complete first
  providesContext: string[];     // Context keys this step produces
  requiresContext: string[];     // Context keys this step needs
  // GoPhish-specific
  gophishConfig?: GoPhishStepConfig;
  // Execution state
  status: "pending" | "waiting" | "running" | "success" | "failed" | "skipped" | "fallback";
  result?: C2TaskResult;
  startedAt?: string;
  completedAt?: string;
  error?: string;
  usedFramework?: OrchestratedFramework;  // Which framework actually executed (may differ if fallback)
}

export interface GoPhishStepConfig {
  campaignName: string;
  templateId?: number;
  landingPageId?: number;
  sendingProfileId?: number;
  targetGroupId?: number;
  // Payload integration
  payloadUrl?: string;           // URL to C2 agent payload
  payloadFramework?: C2FrameworkType;  // Which C2 catches the callback
  callbackListenerId?: string;   // Listener ID on the callback C2
  // Trigger conditions
  triggerOnClick?: boolean;      // Auto-trigger C2 action when target clicks
  triggerOnSubmit?: boolean;     // Auto-trigger when target submits credentials
  credentialForwardTo?: C2FrameworkType;  // Forward captured creds to this C2
}

export interface SharedContext {
  // Discovered credentials shared across C2s
  credentials: Array<{
    username: string;
    password?: string;
    hash?: string;
    domain?: string;
    source: OrchestratedFramework;
    discoveredAt: string;
    usedBy: OrchestratedFramework[];
  }>;
  // Active sessions/pivots
  sessions: Array<{
    id: string;
    framework: OrchestratedFramework;
    targetHost: string;
    targetPort: number;
    type: "shell" | "meterpreter" | "beacon" | "implant" | "socks" | "portfwd";
    active: boolean;
  }>;
  // Discovered network information
  networkMap: Array<{
    host: string;
    ports: number[];
    os?: string;
    services: string[];
    discoveredBy: OrchestratedFramework;
  }>;
  // Phishing results from GoPhish
  phishingResults: Array<{
    campaignId: number;
    targetEmail: string;
    clicked: boolean;
    submitted: boolean;
    capturedCredentials?: Record<string, string>;
    timestamp: string;
  }>;
  // Custom key-value context
  facts: Record<string, string | number | boolean>;
}

export interface OrchestrationPlan {
  id: string;
  name: string;
  description: string;
  // Kill chain mapping
  phases: KillChainPhase[];
  steps: OrchestrationStep[];
  // Framework configuration
  frameworkPriority: Record<KillChainPhase, OrchestratedFramework[]>;
  // Shared state
  sharedContext: SharedContext;
  // Execution config
  scanMode: ScanMode;
  maxParallel: number;           // Max steps executing simultaneously
  abortOnFailure: boolean;       // Stop entire plan on step failure
  autoHandoff: boolean;          // Automatically switch C2 between phases
  // Status
  status: OrchestrationStatus;
  currentPhase: KillChainPhase | null;
  stepsCompleted: number;
  stepsFailed: number;
  stepsSkipped: number;
  startedAt?: string;
  completedAt?: string;
  // Audit
  log: OrchestrationLogEntry[];
}

export interface OrchestrationLogEntry {
  timestamp: string;
  level: "info" | "warn" | "error" | "success";
  phase: KillChainPhase | null;
  stepId: string | null;
  framework: OrchestratedFramework | null;
  message: string;
  details?: Record<string, any>;
}

// ─── Framework Strength Map ─────────────────────────────────────────────────

/**
 * Default framework priority per kill chain phase based on each framework's
 * strengths. This is the starting point — the learning engine refines it.
 */
const DEFAULT_FRAMEWORK_PRIORITY: Record<KillChainPhase, OrchestratedFramework[]> = {
  reconnaissance: ["caldera", "metasploit", "cobaltstrike", "empire", "manjusaka"],
  weaponization: ["cobaltstrike", "metasploit", "empire", "sliver", "manjusaka"],
  delivery: ["gophish", "cobaltstrike", "caldera", "empire", "manjusaka"],
  exploitation: ["metasploit", "cobaltstrike", "caldera", "sliver", "empire", "manjusaka"],
  installation: ["cobaltstrike", "sliver", "manjusaka", "empire", "caldera", "metasploit"],
  command_and_control: ["cobaltstrike", "sliver", "manjusaka", "empire", "caldera", "metasploit"],
  actions_on_objectives: ["cobaltstrike", "caldera", "manjusaka", "metasploit", "empire", "sliver"],
};

/**
 * Framework capability matrix — what each framework does best.
 */
const FRAMEWORK_CAPABILITIES: Record<OrchestratedFramework, {
  strengths: string[];
  weaknesses: string[];
  bestFor: KillChainPhase[];
  agentTypes: string[];
}> = {
  caldera: {
    strengths: ["ATT&CK mapping", "automated adversary emulation", "ability chaining", "fact-based decisions"],
    weaknesses: ["limited exploit library", "no built-in phishing"],
    bestFor: ["reconnaissance", "actions_on_objectives"],
    agentTypes: ["sandcat", "manx", "ragdoll"],
  },
  metasploit: {
    strengths: ["exploit library (2000+)", "payload generation", "post-exploitation", "pivoting"],
    weaknesses: ["noisy by default", "well-signatured"],
    bestFor: ["exploitation", "actions_on_objectives"],
    agentTypes: ["meterpreter", "shell"],
  },
  sliver: {
    strengths: ["modern C2", "mTLS/WireGuard", "BOF support", "evasion", "cross-platform implants"],
    weaknesses: ["smaller module library", "newer community"],
    bestFor: ["installation", "command_and_control"],
    agentTypes: ["beacon", "session"],
  },
  empire: {
    strengths: ["PowerShell/Python agents", "persistence modules", "credential harvesting", "situational awareness"],
    weaknesses: ["Python dependency", "detection signatures"],
    bestFor: ["installation", "command_and_control", "actions_on_objectives"],
    agentTypes: ["powershell", "python", "csharp"],
  },
  gophish: {
    strengths: ["phishing campaigns", "credential harvesting", "email templates", "landing pages", "campaign tracking"],
    weaknesses: ["no post-exploitation", "no C2 channel", "email-only delivery"],
    bestFor: ["delivery"],
    agentTypes: [],
  },
  cobaltstrike: {
    strengths: ["malleable C2 profiles", "beacon object files (BOFs)", "process injection", "lateral movement", "credential theft", "OPSEC features", "sleep/jitter control", "SMB/TCP/DNS beacons", "in-memory execution"],
    weaknesses: ["commercial license required", "well-known signatures", "high detection rate without tuning"],
    bestFor: ["weaponization", "installation", "command_and_control", "actions_on_objectives"],
    agentTypes: ["beacon"],
  },
  manjusaka: {
    strengths: ["Rust-native implants", "low EDR signature coverage", "staged NPC1/NPC2 loading", "VNC remote desktop", "BOF compatibility", "multi-protocol transport (HTTP/HTTPS/WS/KCP/SSH)", "Noise protocol encryption", "credential harvesting (browser/WiFi/Navicat)", "chunked file transfer with resume", "network tunneling"],
    weaknesses: ["smaller community", "Windows + Linux only (no macOS)", "Chinese-language NPS interface", "single maintainer"],
    bestFor: ["installation", "command_and_control", "actions_on_objectives"],
    agentTypes: ["npc1", "npc2"],
  },
};

// ─── Orchestration Engine ───────────────────────────────────────────────────

/** Active orchestration plans */
const activePlans = new Map<string, OrchestrationPlan>();

/**
 * Create a new orchestration plan from ability graph nodes.
 */
export function createOrchestrationPlan(params: {
  name: string;
  description: string;
  nodes: AbilityNodeData[];
  edges: AbilityEdgeData[];
  scanMode: ScanMode;
  maxParallel?: number;
  abortOnFailure?: boolean;
  autoHandoff?: boolean;
  includePhishing?: boolean;
  phishingConfig?: GoPhishStepConfig;
  frameworkOverrides?: Partial<Record<KillChainPhase, OrchestratedFramework[]>>;
}): OrchestrationPlan {
  const planId = generateId();

  // Map nodes to orchestration steps
  const steps: OrchestrationStep[] = [];
  const phases = new Set<KillChainPhase>();

  // If phishing is included, add GoPhish delivery step first
  if (params.includePhishing && params.phishingConfig) {
    phases.add("delivery");
    steps.push({
      id: `${planId}-gophish-delivery`,
      order: 0,
      phase: "delivery",
      framework: "gophish",
      fallbackFrameworks: ["caldera"],
      label: `Phishing Campaign: ${params.phishingConfig.campaignName}`,
      description: "Launch phishing campaign to deliver initial payload",
      moduleId: "gophish-campaign",
      options: {},
      delayBeforeMs: 0,
      timeoutMs: 3600000,  // 1 hour for phishing campaigns
      dependsOn: [],
      providesContext: ["phishing_results", "captured_credentials", "clicked_targets"],
      requiresContext: [],
      gophishConfig: params.phishingConfig,
      status: "pending",
    });
  }

  // Convert graph nodes to orchestration steps
  for (const node of params.nodes) {
    const phase = tacticToKillChainPhase(node.tactic);
    phases.add(phase);

    // Determine best framework for this step
    const priority = params.frameworkOverrides?.[phase] ||
                     DEFAULT_FRAMEWORK_PRIORITY[phase];
    const primaryFramework = selectBestFramework(node, priority);

    // Build dependency list from edges
    const incomingEdges = params.edges.filter(e => e.targetNodeId === node.id);
    const dependsOn = incomingEdges.map(e => e.sourceNodeId);

    // If phishing is included and this is the first non-delivery step, depend on phishing
    const isFirstPostDelivery = params.includePhishing &&
      phase !== "delivery" &&
      dependsOn.length === 0;

    steps.push({
      id: node.id,
      order: node.order,
      phase,
      framework: primaryFramework as OrchestratedFramework,
      fallbackFrameworks: priority.filter(f => f !== primaryFramework) as OrchestratedFramework[],
      label: node.label,
      description: node.description,
      techniqueId: node.techniqueId,
      moduleId: node.calderaAbilityId || node.techniqueId,
      options: {},
      targetPlatform: node.platform,
      delayBeforeMs: 0,
      timeoutMs: (node.timeout || 60) * 1000,
      dependsOn: isFirstPostDelivery
        ? [`${planId}-gophish-delivery`]
        : dependsOn,
      providesContext: inferProvidedContext(node),
      requiresContext: inferRequiredContext(node),
      status: "pending",
    });
  }

  // Sort steps by order
  steps.sort((a, b) => a.order - b.order);

  const plan: OrchestrationPlan = {
    id: planId,
    name: params.name,
    description: params.description,
    phases: Array.from(phases),
    steps,
    frameworkPriority: {
      ...DEFAULT_FRAMEWORK_PRIORITY,
      ...(params.frameworkOverrides || {}),
    },
    sharedContext: {
      credentials: [],
      sessions: [],
      networkMap: [],
      phishingResults: [],
      facts: {},
    },
    scanMode: params.scanMode,
    maxParallel: params.maxParallel || 1,
    abortOnFailure: params.abortOnFailure ?? true,
    autoHandoff: params.autoHandoff ?? true,
    status: "planning",
    currentPhase: null,
    stepsCompleted: 0,
    stepsFailed: 0,
    stepsSkipped: 0,
    log: [],
  };

  activePlans.set(planId, plan);
  return plan;
}

/**
 * Execute an orchestration plan — runs steps in dependency order,
 * handles C2 handoff, shared context, and fallback chains.
 */
export async function executeOrchestrationPlan(
  planId: string,
  environment: EnvironmentContext,
): Promise<OrchestrationPlan> {
  const plan = activePlans.get(planId);
  if (!plan) throw new Error(`Orchestration plan ${planId} not found`);

  plan.status = "running";
  plan.startedAt = new Date().toISOString();
  logEntry(plan, "info", null, null, null, `Orchestration plan "${plan.name}" started with ${plan.steps.length} steps across ${plan.phases.length} phases`);

  const registry = getC2Registry();

  // Health check all frameworks before starting
  const health = await registry.healthCheckAll();
  for (const h of health) {
    logEntry(plan, h.connected ? "info" : "warn", null, null, h.framework,
      `${h.framework}: ${h.connected ? "connected" : "disconnected"} (${h.agentCount} agents)`);
  }

  // Execute steps in dependency order
  const completed = new Set<string>();
  const failed = new Set<string>();

  while (true) {
    // Find steps ready to execute (all dependencies met)
    const readySteps = plan.steps.filter(s =>
      s.status === "pending" &&
      s.dependsOn.every(dep => completed.has(dep))
    );

    if (readySteps.length === 0) {
      // Check if we're done or stuck
      const pendingSteps = plan.steps.filter(s => s.status === "pending" || s.status === "waiting");
      if (pendingSteps.length === 0) break;

      // Check for blocked steps (dependencies failed)
      const blockedSteps = pendingSteps.filter(s =>
        s.dependsOn.some(dep => failed.has(dep))
      );
      for (const blocked of blockedSteps) {
        blocked.status = "skipped";
        plan.stepsSkipped++;
        logEntry(plan, "warn", blocked.phase, blocked.id, blocked.framework,
          `Step "${blocked.label}" skipped — dependency failed`);
      }

      if (blockedSteps.length === pendingSteps.length) break;
      continue;
    }

    // Execute ready steps (up to maxParallel)
    const batch = readySteps.slice(0, plan.maxParallel);
    const batchPromises = batch.map(step => executeStep(plan, step, environment, registry));
    const results = await Promise.allSettled(batchPromises);

    for (let i = 0; i < results.length; i++) {
      const step = batch[i];
      const result = results[i];

      if (result.status === "fulfilled" && result.value) {
        completed.add(step.id);
        plan.stepsCompleted++;

        // Extract context from successful step
        await extractAndShareContext(plan, step);

        // Feed results to learning engine
        await feedToLearningEngine(step, environment);
      } else {
        // Try fallback frameworks
        let recovered = false;
        for (const fallbackFw of step.fallbackFrameworks) {
          logEntry(plan, "warn", step.phase, step.id, fallbackFw as any,
            `Attempting fallback to ${fallbackFw} for "${step.label}"`);

          step.framework = fallbackFw;
          step.status = "pending";

          try {
            const fallbackResult = await executeStep(plan, step, environment, registry);
            if (fallbackResult) {
              completed.add(step.id);
              plan.stepsCompleted++;
              step.usedFramework = fallbackFw;
              step.status = "fallback";
              recovered = true;
              await extractAndShareContext(plan, step);
              break;
            }
          } catch {
            continue;
          }
        }

        if (!recovered) {
          failed.add(step.id);
          plan.stepsFailed++;

          if (plan.abortOnFailure) {
            plan.status = "failed";
            plan.completedAt = new Date().toISOString();
            logEntry(plan, "error", step.phase, step.id, step.framework,
              `Plan aborted — step "${step.label}" failed with no fallback`);
            return plan;
          }
        }
      }
    }

    // Update current phase
    const runningPhases = plan.steps
      .filter(s => s.status === "running" || s.status === "pending")
      .map(s => s.phase);
    plan.currentPhase = runningPhases[0] || null;
  }

  plan.status = plan.stepsFailed > 0 ? "completed" : "completed";
  plan.completedAt = new Date().toISOString();
  logEntry(plan, "success", null, null, null,
    `Orchestration complete: ${plan.stepsCompleted} succeeded, ${plan.stepsFailed} failed, ${plan.stepsSkipped} skipped`);

  return plan;
}

/**
 * Execute a single orchestration step.
 */
async function executeStep(
  plan: OrchestrationPlan,
  step: OrchestrationStep,
  environment: EnvironmentContext,
  registry: ReturnType<typeof getC2Registry>,
): Promise<boolean> {
  step.status = "running";
  step.startedAt = new Date().toISOString();

  // Apply delay
  if (step.delayBeforeMs > 0) {
    logEntry(plan, "info", step.phase, step.id, step.framework,
      `Waiting ${step.delayBeforeMs}ms before execution`);
    await sleep(step.delayBeforeMs);
  }

  logEntry(plan, "info", step.phase, step.id, step.framework,
    `Executing "${step.label}" via ${step.framework}`);

  try {
    // Handle GoPhish steps differently
    if (step.framework === "gophish") {
      return await executeGoPhishStep(plan, step);
    }

    // Resolve context requirements
    resolveContextRequirements(plan, step);

    // Find or select agent
    const agentId = step.targetAgentId || await selectAgent(
      step.framework as C2FrameworkType,
      step.targetPlatform || environment.os,
      step.requiredPrivilege,
      registry,
    );

    if (!agentId) {
      step.status = "failed";
      step.error = `No suitable ${step.framework} agent found for platform ${step.targetPlatform || environment.os}`;
      logEntry(plan, "error", step.phase, step.id, step.framework, step.error);
      return false;
    }

    // Dispatch task
    const taskRequest: C2TaskRequest & { framework: C2FrameworkType } = {
      framework: step.framework as C2FrameworkType,
      agentId,
      moduleId: step.moduleId,
      options: {
        ...step.options,
        // Inject shared context into options
        ...buildContextOptions(plan.sharedContext, step),
      },
      timeout: Math.floor(step.timeoutMs / 1000),
    };

    const result = await registry.dispatch(taskRequest);
    step.result = result;

    // Poll for completion if pending
    if (result.status === "pending" || result.status === "running") {
      const finalResult = await pollForCompletion(
        step.framework as C2FrameworkType,
        result.taskId,
        agentId,
        step.timeoutMs,
        registry,
      );
      step.result = finalResult;
    }

    if (step.result.status === "success") {
      step.status = "success";
      step.completedAt = new Date().toISOString();
      logEntry(plan, "success", step.phase, step.id, step.framework,
        `Step "${step.label}" completed successfully`);
      return true;
    } else {
      step.status = "failed";
      step.error = step.result.stderr || step.result.metadata?.error || "Task failed";
      step.completedAt = new Date().toISOString();
      logEntry(plan, "error", step.phase, step.id, step.framework,
        `Step "${step.label}" failed: ${step.error}`);
      return false;
    }
  } catch (err: any) {
    step.status = "failed";
    step.error = err.message || "Unknown error";
    step.completedAt = new Date().toISOString();
    logEntry(plan, "error", step.phase, step.id, step.framework,
      `Step "${step.label}" error: ${step.error}`);
    return false;
  }
}

/**
 * Execute a GoPhish phishing step.
 */
async function executeGoPhishStep(
  plan: OrchestrationPlan,
  step: OrchestrationStep,
): Promise<boolean> {
  const config = step.gophishConfig;
  if (!config) {
    step.status = "failed";
    step.error = "No GoPhish configuration provided";
    return false;
  }

  try {
    const { fetchGophish } = await import("../routers/phishing/shared");

    // Create or use existing campaign
    let campaignId: number;

    if (config.templateId && config.landingPageId && config.sendingProfileId && config.targetGroupId) {
      // Launch new campaign
      const campaignData = {
        name: config.campaignName,
        template: { id: config.templateId },
        page: { id: config.landingPageId },
        smtp: { id: config.sendingProfileId },
        groups: [{ id: config.targetGroupId }],
        url: config.payloadUrl || "",
        launch_date: new Date().toISOString(),
      };

      const result = await fetchGophish("/api/campaigns/", "POST", campaignData);
      campaignId = result.id;

      logEntry(plan, "info", "delivery", step.id, "gophish",
        `GoPhish campaign "${config.campaignName}" launched (ID: ${campaignId})`);
    } else {
      // Use existing campaign — poll for results
      logEntry(plan, "warn", "delivery", step.id, "gophish",
        "No complete GoPhish config — skipping campaign launch");
      step.status = "success";
      step.completedAt = new Date().toISOString();
      return true;
    }

    // Poll campaign for results (wait for clicks/submissions)
    const pollStart = Date.now();
    const maxWait = step.timeoutMs || 3600000;  // Default 1 hour

    while (Date.now() - pollStart < maxWait) {
      await sleep(30000);  // Poll every 30 seconds

      try {
        const campaign = await fetchGophish(`/api/campaigns/${campaignId}`);
        const results = campaign.results || [];

        // Track phishing results
        for (const r of results) {
          const existing = plan.sharedContext.phishingResults.find(
            pr => pr.targetEmail === r.email && pr.campaignId === campaignId
          );

          if (!existing) {
            plan.sharedContext.phishingResults.push({
              campaignId,
              targetEmail: r.email,
              clicked: r.status === "Clicked Link" || r.status === "Submitted Data",
              submitted: r.status === "Submitted Data",
              timestamp: r.modified_date || new Date().toISOString(),
            });
          }

          // If target submitted credentials, forward to C2
          if (r.status === "Submitted Data" && config.credentialForwardTo) {
            const creds = r.details || {};
            plan.sharedContext.credentials.push({
              username: creds.username || creds.email || r.email,
              password: creds.password,
              source: "gophish",
              discoveredAt: new Date().toISOString(),
              usedBy: [],
            });

            logEntry(plan, "success", "delivery", step.id, "gophish",
              `Credentials captured from ${r.email} — forwarding to ${config.credentialForwardTo}`);
          }

          // If target clicked and auto-trigger is enabled
          if ((r.status === "Clicked Link" && config.triggerOnClick) ||
              (r.status === "Submitted Data" && config.triggerOnSubmit)) {
            plan.sharedContext.facts["phishing_target_clicked"] = true;
            plan.sharedContext.facts["phishing_target_email"] = r.email;

            logEntry(plan, "success", "delivery", step.id, "gophish",
              `Target ${r.email} triggered — ready for C2 callback`);
          }
        }

        // Check if we have enough results to proceed
        const clickCount = plan.sharedContext.phishingResults.filter(pr => pr.clicked).length;
        if (clickCount > 0) {
          logEntry(plan, "success", "delivery", step.id, "gophish",
            `${clickCount} target(s) clicked — phishing delivery successful`);
          break;
        }
      } catch (pollErr: any) {
        logEntry(plan, "warn", "delivery", step.id, "gophish",
          `Campaign poll error: ${pollErr.message}`);
      }
    }

    step.status = "success";
    step.completedAt = new Date().toISOString();
    return true;
  } catch (err: any) {
    step.status = "failed";
    step.error = err.message;
    logEntry(plan, "error", "delivery", step.id, "gophish",
      `GoPhish step failed: ${err.message}`);
    return false;
  }
}

// ─── C2 Handoff ─────────────────────────────────────────────────────────────

/**
 * Perform a C2 handoff — deploy a new agent from one framework to another
 * on the same target host, transferring session context.
 */
export async function performC2Handoff(params: {
  planId: string;
  fromFramework: C2FrameworkType;
  toFramework: C2FrameworkType;
  fromAgentId: string;
  targetHost: string;
  targetPlatform: string;
  reason: string;
}): Promise<{
  success: boolean;
  newAgentId?: string;
  error?: string;
}> {
  const plan = activePlans.get(params.planId);
  if (!plan) throw new Error(`Plan ${params.planId} not found`);

  logEntry(plan, "info", null, null, params.toFramework,
    `C2 handoff: ${params.fromFramework} → ${params.toFramework} on ${params.targetHost} (${params.reason})`);

  const registry = getC2Registry();

  try {
    // Step 1: Generate payload for the target framework
    const payloadModuleId = getPayloadModuleId(params.toFramework, params.targetPlatform);

    // Step 2: Use the source framework's agent to deploy the target framework's payload
    const deployResult = await registry.dispatch({
      framework: params.fromFramework,
      agentId: params.fromAgentId,
      moduleId: payloadModuleId,
      options: {
        target_host: params.targetHost,
        platform: params.targetPlatform,
      },
      timeout: 120,
    });

    if (deployResult.status !== "success") {
      logEntry(plan, "error", null, null, params.toFramework,
        `Handoff payload deployment failed: ${deployResult.stderr}`);
      return { success: false, error: deployResult.stderr };
    }

    // Step 3: Wait for new agent to check in on the target framework
    const newAgent = await waitForNewAgent(params.toFramework, params.targetHost, 120000, registry);

    if (newAgent) {
      // Record the session in shared context
      plan.sharedContext.sessions.push({
        id: newAgent.id,
        framework: params.toFramework,
        targetHost: params.targetHost,
        targetPort: 0,
        type: frameworkToSessionType(params.toFramework),
        active: true,
      });

      logEntry(plan, "success", null, null, params.toFramework,
        `C2 handoff successful — new ${params.toFramework} agent: ${newAgent.id}`);

      return { success: true, newAgentId: newAgent.id };
    } else {
      logEntry(plan, "error", null, null, params.toFramework,
        `C2 handoff failed — no new agent checked in within timeout`);
      return { success: false, error: "New agent did not check in within timeout" };
    }
  } catch (err: any) {
    logEntry(plan, "error", null, null, params.toFramework,
      `C2 handoff error: ${err.message}`);
    return { success: false, error: err.message };
  }
}

// ─── Context Sharing ────────────────────────────────────────────────────────

/**
 * Extract discovered context from a completed step and share it across the plan.
 */
async function extractAndShareContext(
  plan: OrchestrationPlan,
  step: OrchestrationStep,
): Promise<void> {
  if (!step.result || step.result.status !== "success") return;

  const stdout = step.result.stdout || "";

  // Extract credentials from output
  const credPatterns = [
    /(?:username|user|login)\s*[:=]\s*(\S+)\s+(?:password|pass|pwd)\s*[:=]\s*(\S+)/gi,
    /(\w+):(\$\w+\$[^\s]+)/g,  // Unix hash format
    /(\w+):::([a-f0-9]{32})/gi, // NTLM hash format
  ];

  for (const pattern of credPatterns) {
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(stdout)) !== null) {
      plan.sharedContext.credentials.push({
        username: match[1],
        password: match[2],
        source: step.framework,
        discoveredAt: new Date().toISOString(),
        usedBy: [],
      });
    }
  }

  // Extract network information from discovery steps
  if (step.phase === "reconnaissance" || step.techniqueId?.startsWith("T108")) {
    const hostPattern = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+.*?(?:open|listening)\s+(\d+)/g;
    let match2: RegExpExecArray | null;
    while ((match2 = hostPattern.exec(stdout)) !== null) {
      const existing = plan.sharedContext.networkMap.find(n => n.host === match2![1]);
      if (existing) {
        if (!existing.ports.includes(parseInt(match2![2]))) {
          existing.ports.push(parseInt(match2![2]));
        }
      } else {
        plan.sharedContext.networkMap.push({
          host: match2![1],
          ports: [parseInt(match2![2])],
          discoveredBy: step.framework,
          services: [],
        });
      }
    }
  }

  // Update custom facts from step's providesContext
  for (const key of step.providesContext) {
    plan.sharedContext.facts[key] = true;
  }
}

/**
 * Resolve context requirements for a step by injecting shared context into options.
 */
function resolveContextRequirements(
  plan: OrchestrationPlan,
  step: OrchestrationStep,
): void {
  for (const key of step.requiresContext) {
    if (key === "captured_credentials" && plan.sharedContext.credentials.length > 0) {
      const cred = plan.sharedContext.credentials[0];
      step.options.username = cred.username;
      step.options.password = cred.password || cred.hash;
      cred.usedBy.push(step.framework);
    }
    if (key === "phishing_results") {
      step.options.phishing_results = plan.sharedContext.phishingResults;
    }
    if (key === "network_map") {
      step.options.targets = plan.sharedContext.networkMap;
    }
  }
}

/**
 * Build context-aware options for a task dispatch.
 */
function buildContextOptions(
  context: SharedContext,
  step: OrchestrationStep,
): Record<string, any> {
  const opts: Record<string, any> = {};

  // If step needs credentials and we have them, inject
  if (step.requiresContext.includes("captured_credentials") && context.credentials.length > 0) {
    const bestCred = context.credentials.find(c => !c.usedBy.includes(step.framework)) || context.credentials[0];
    opts._injected_username = bestCred.username;
    opts._injected_password = bestCred.password || bestCred.hash;
  }

  // If step needs network info, inject discovered hosts
  if (step.requiresContext.includes("network_map")) {
    opts._injected_targets = context.networkMap.map(n => `${n.host}:${n.ports.join(",")}`);
  }

  return opts;
}

// ─── Plan Management ────────────────────────────────────────────────────────

export function getOrchestrationPlan(planId: string): OrchestrationPlan | null {
  return activePlans.get(planId) || null;
}

export function listOrchestrationPlans(): OrchestrationPlan[] {
  return Array.from(activePlans.values());
}

export function abortOrchestrationPlan(planId: string): OrchestrationPlan | null {
  const plan = activePlans.get(planId);
  if (!plan) return null;

  plan.status = "aborted";
  plan.completedAt = new Date().toISOString();

  // Mark all pending steps as skipped
  for (const step of plan.steps) {
    if (step.status === "pending" || step.status === "waiting") {
      step.status = "skipped";
      plan.stepsSkipped++;
    }
  }

  logEntry(plan, "warn", null, null, null, `Orchestration plan "${plan.name}" aborted`);
  return plan;
}

export function pauseOrchestrationPlan(planId: string): OrchestrationPlan | null {
  const plan = activePlans.get(planId);
  if (!plan || plan.status !== "running") return null;

  plan.status = "paused";
  logEntry(plan, "info", null, null, null, `Orchestration plan "${plan.name}" paused`);
  return plan;
}

export function resumeOrchestrationPlan(planId: string): OrchestrationPlan | null {
  const plan = activePlans.get(planId);
  if (!plan || plan.status !== "paused") return null;

  plan.status = "running";
  logEntry(plan, "info", null, null, null, `Orchestration plan "${plan.name}" resumed`);
  return plan;
}

/**
 * Get orchestration statistics across all plans.
 */
export function getOrchestrationStats(): {
  totalPlans: number;
  activePlans: number;
  completedPlans: number;
  failedPlans: number;
  totalSteps: number;
  frameworkUsage: Record<string, number>;
  phaseDistribution: Record<string, number>;
  handoffCount: number;
  averageCompletionRate: number;
} {
  const plans = Array.from(activePlans.values());
  const frameworkUsage: Record<string, number> = {};
  const phaseDistribution: Record<string, number> = {};
  let totalSteps = 0;
  let totalCompleted = 0;
  let handoffCount = 0;

  for (const plan of plans) {
    for (const step of plan.steps) {
      totalSteps++;
      const fw = step.usedFramework || step.framework;
      frameworkUsage[fw] = (frameworkUsage[fw] || 0) + 1;
      phaseDistribution[step.phase] = (phaseDistribution[step.phase] || 0) + 1;
      if (step.status === "success" || step.status === "fallback") totalCompleted++;
      if (step.status === "fallback") handoffCount++;
    }
  }

  return {
    totalPlans: plans.length,
    activePlans: plans.filter(p => p.status === "running").length,
    completedPlans: plans.filter(p => p.status === "completed").length,
    failedPlans: plans.filter(p => p.status === "failed").length,
    totalSteps,
    frameworkUsage,
    phaseDistribution,
    handoffCount,
    averageCompletionRate: totalSteps > 0 ? Math.round((totalCompleted / totalSteps) * 100) : 0,
  };
}

/**
 * Get framework capability information.
 */
export function getFrameworkCapabilities(): typeof FRAMEWORK_CAPABILITIES {
  return FRAMEWORK_CAPABILITIES;
}

/**
 * Get default framework priority per kill chain phase.
 */
export function getDefaultFrameworkPriority(): typeof DEFAULT_FRAMEWORK_PRIORITY {
  return DEFAULT_FRAMEWORK_PRIORITY;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function generateId(): string {
  return "orch-" + Math.random().toString(36).substring(2, 10) + "-" + Date.now().toString(36);
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function tacticToKillChainPhase(tactic: string): KillChainPhase {
  const map: Record<string, KillChainPhase> = {
    "reconnaissance": "reconnaissance",
    "resource-development": "weaponization",
    "initial-access": "delivery",
    "execution": "exploitation",
    "persistence": "installation",
    "privilege-escalation": "exploitation",
    "defense-evasion": "installation",
    "credential-access": "actions_on_objectives",
    "discovery": "reconnaissance",
    "lateral-movement": "actions_on_objectives",
    "collection": "actions_on_objectives",
    "command-and-control": "command_and_control",
    "exfiltration": "actions_on_objectives",
    "impact": "actions_on_objectives",
  };
  return map[tactic] || "actions_on_objectives";
}

function selectBestFramework(
  node: AbilityNodeData,
  priority: OrchestratedFramework[],
): OrchestratedFramework {
  // If node has a Caldera ability mapped, prefer Caldera
  if (node.calderaAbilityId && priority.includes("caldera")) {
    return "caldera";
  }

  // Check learning engine recommendation
  if (node.techniqueId && node.platform) {
    const recommendation = recommendFramework(node.techniqueId, node.platform);
    if (recommendation && recommendation.confidence > 70) {
      const recFw = recommendation.framework as OrchestratedFramework;
      if (priority.includes(recFw)) return recFw;
    }
  }

  // Use priority order
  return priority[0] || "caldera";
}

function inferProvidedContext(node: AbilityNodeData): string[] {
  const context: string[] = [];
  const tactic = node.tactic.toLowerCase();

  if (tactic.includes("credential")) context.push("captured_credentials");
  if (tactic.includes("discovery")) context.push("network_map", "host_info");
  if (tactic.includes("initial-access")) context.push("initial_foothold");
  if (tactic.includes("persistence")) context.push("persistent_access");
  if (tactic.includes("lateral")) context.push("lateral_access");
  if (tactic.includes("collection")) context.push("collected_data");
  if (tactic.includes("privilege")) context.push("elevated_access");

  return context;
}

function inferRequiredContext(node: AbilityNodeData): string[] {
  const context: string[] = [];
  const tactic = node.tactic.toLowerCase();

  if (tactic.includes("lateral")) context.push("captured_credentials", "network_map");
  if (tactic.includes("exfiltration")) context.push("collected_data");
  if (tactic.includes("privilege") && node.preconditions.some(p => p.key === "credential")) {
    context.push("captured_credentials");
  }

  return context;
}

async function selectAgent(
  framework: C2FrameworkType,
  platform: string,
  privilege: string | undefined,
  registry: ReturnType<typeof getC2Registry>,
): Promise<string | null> {
  const adapter = registry.get(framework);
  if (!adapter) return null;

  try {
    const agents = await adapter.listAgents();
    const matching = agents.filter(a => {
      if (a.status !== "active") return false;
      if (platform && a.platform !== platform) return false;
      if (privilege && a.privileges !== privilege) return false;
      return true;
    });

    if (matching.length === 0) return null;

    // Prefer most recently seen agent
    matching.sort((a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime());
    return matching[0].id;
  } catch {
    return null;
  }
}

async function pollForCompletion(
  framework: C2FrameworkType,
  taskId: string,
  agentId: string,
  timeoutMs: number,
  registry: ReturnType<typeof getC2Registry>,
): Promise<C2TaskResult> {
  const adapter = registry.get(framework);
  if (!adapter) throw new Error(`No adapter for ${framework}`);

  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const result = await adapter.pollResult(taskId, agentId);
    if (result.status !== "pending" && result.status !== "running") {
      return result;
    }
    await sleep(3000);
  }

  return {
    taskId,
    framework,
    agentId,
    moduleId: "",
    status: "timeout",
    exitCode: -1,
    stdout: "",
    stderr: "Execution timed out",
    startedAt: new Date(start).toISOString(),
    completedAt: new Date().toISOString(),
  };
}

async function waitForNewAgent(
  framework: C2FrameworkType,
  targetHost: string,
  timeoutMs: number,
  registry: ReturnType<typeof getC2Registry>,
): Promise<C2Agent | null> {
  const adapter = registry.get(framework);
  if (!adapter) return null;

  // Get current agent list
  const beforeAgents = await adapter.listAgents();
  const beforeIds = new Set(beforeAgents.map(a => a.id));

  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    await sleep(5000);
    const currentAgents = await adapter.listAgents();
    const newAgents = currentAgents.filter(a =>
      !beforeIds.has(a.id) &&
      (a.hostname === targetHost || a.ipAddress === targetHost)
    );
    if (newAgents.length > 0) return newAgents[0];
  }

  return null;
}

function getPayloadModuleId(framework: C2FrameworkType, platform: string): string {
  const payloads: Record<C2FrameworkType, Record<string, string>> = {
    caldera: {
      windows: "deploy-sandcat-windows",
      linux: "deploy-sandcat-linux",
      macos: "deploy-sandcat-macos",
    },
    metasploit: {
      windows: "exploit/multi/handler",
      linux: "exploit/multi/handler",
      macos: "exploit/multi/handler",
    },
    sliver: {
      windows: "generate-implant-windows",
      linux: "generate-implant-linux",
      macos: "generate-implant-macos",
    },
    empire: {
      windows: "stager/windows/launcher_bat",
      linux: "stager/multi/bash",
      macos: "stager/osx/launcher",
    },
    cobaltstrike: {
      windows: "beacon_https",
      linux: "beacon_https",
      macos: "beacon_https",
    },
    manjusaka: {
      windows: "generate-npc1-windows",
      linux: "generate-npc1-linux",
    },
  };

  return payloads[framework]?.[platform] || payloads[framework]?.["linux"] || "unknown";
}

function frameworkToSessionType(framework: C2FrameworkType): "shell" | "meterpreter" | "beacon" | "implant" {
  const map: Record<C2FrameworkType, "shell" | "meterpreter" | "beacon" | "implant"> = {
    caldera: "shell",
    metasploit: "meterpreter",
    sliver: "beacon",
    empire: "implant",
    cobaltstrike: "beacon",
    manjusaka: "implant",
  };
  return map[framework] || "shell";
}

function logEntry(
  plan: OrchestrationPlan,
  level: OrchestrationLogEntry["level"],
  phase: KillChainPhase | null,
  stepId: string | null,
  framework: OrchestratedFramework | null,
  message: string,
  details?: Record<string, any>,
): void {
  plan.log.push({
    timestamp: new Date().toISOString(),
    level,
    phase,
    stepId,
    framework,
    message,
    details,
  });
}

async function feedToLearningEngine(
  step: OrchestrationStep,
  environment: EnvironmentContext,
): Promise<void> {
  if (!step.result || step.framework === "gophish") return;

  try {
    const feedback: ExecutionFeedback = {
      techniqueId: step.techniqueId || "",
      framework: step.framework as C2FrameworkType,
      taskResult: step.result,
      targetContext: {
        platform: step.targetPlatform || environment.os,
        architecture: "x64",
        hostname: environment.hostname || "unknown",
        privileges: step.requiredPrivilege || environment.privilegeLevel,
        networkSegment: environment.networkAccess,
      },
    };

    await processExecutionFeedback(feedback);
  } catch {
    // Non-critical — don't fail the step
  }
}
