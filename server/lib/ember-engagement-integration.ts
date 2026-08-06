/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * EMBER ENGAGEMENT INTEGRATION
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * Hooks the Ember agent system into the engagement orchestrator pipeline.
 * When an exploitation succeeds and a shell is obtained, this module can:
 *   1. Auto-generate an Ember payload tailored to the target
 *   2. Deploy the agent through the established session
 *   3. Register the agent in the fleet and link it to the engagement
 *   4. Enable post-exploitation intelligence collection
 *
 * Integration points:
 *   - Post-exploitation phase (Phase 5b) — alongside or replacing Caldera deployment
 *   - Shell-obtained callback — auto-trigger Ember deployment
 *   - Engagement results — aggregate Ember intelligence into findings
 */

import {
  type EmberProfile,
  type EmberPayloadFormat,
  type EmberPlatform,
  EMBER_PROFILE_DESCRIPTIONS,
  generateEmberPayload,
  type EmberPayloadConfig,
} from "./ember-agent-core";
import { getSafetyEngine } from "./safety-engine";
import { emitAgentDeployed, emitSystemNotification } from "./ws-event-hub";
import { getDb } from "../db";
import { emberAgents, emberPayloads, emberTasks } from "../../drizzle/schema";
import { randomUUID } from "crypto";
import { eq, inArray } from "drizzle-orm";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ExploitedTarget {
  hostname: string;
  ip: string;
  platform: "linux" | "windows" | "macos";
  arch: "x64" | "x86" | "arm64";
  shellType: "reverse_shell" | "bind_shell" | "web_shell" | "meterpreter";
  sessionId?: string;
  exploitModule?: string;
  privilegeLevel?: "user" | "root" | "system";
  detectedProducts?: string[];  // AV/EDR products detected
  engagementId: number;
  engagementType: "pentest" | "red_team";
  safetyLevel?: number;
}

export interface EmberDeploymentResult {
  success: boolean;
  agentId?: string;
  agentName?: string;
  payloadFormat?: string;
  error?: string;
  safetyBlocked?: boolean;
  deploymentMethod?: string;
}

// ─── Platform Detection ─────────────────────────────────────────────────────

function detectPlatform(target: ExploitedTarget): EmberPlatform {
  const os = target.platform;
  const arch = target.arch || "x64";
  if (os === "windows") return arch === "x86" ? "windows_x86" : "windows_x64";
  if (os === "macos") return arch === "arm64" ? "macos_arm64" : "macos_x64";
  return arch === "arm64" ? "linux_arm64" : "linux_x64";
}

// ─── Profile Selection ──────────────────────────────────────────────────────

/**
 * Automatically select the best Ember profile based on engagement context.
 *
 * - Ghost: High-security targets with EDR, or when stealth is paramount
 * - Scout: Initial access — gather intel before escalating
 * - Striker: Exploitation phase — active offensive operations
 * - Sentinel: Defensive validation engagements
 * - Hydra: Multi-host persistence for red team operations
 */
function selectProfile(target: ExploitedTarget): EmberProfile {
  const hasEDR = target.detectedProducts?.some(p =>
    /crowdstrike|sentinel|defender|carbon|cylance|cortex|falcon/i.test(p)
  );

  if (target.engagementType === "pentest") {
    // Pentests use sentinel for controlled validation
    return "sentinel";
  }

  if (hasEDR) {
    // High-security environment — use ghost for maximum stealth
    return "ghost";
  }

  if (target.privilegeLevel === "root" || target.privilegeLevel === "system") {
    // Already have high privileges — deploy hydra for persistence
    return "hydra";
  }

  // Default to scout for initial intel gathering
  return "scout";
}

// ─── Payload Format Selection ───────────────────────────────────────────────

/**
 * Select the optimal payload format based on target platform and shell type.
 */
function selectPayloadFormat(target: ExploitedTarget): EmberPayloadFormat {
  if (target.platform === "linux") {
    if (target.shellType === "web_shell") return "python_stager";
    return "bash_script";
  }
  if (target.platform === "windows") {
    if (target.shellType === "meterpreter") return "powershell_script";
    if (target.privilegeLevel === "system") return "service_executable";
    return "powershell_oneliner";
  }
  if (target.platform === "macos") {
    return "bash_script";
  }
  return "python_stager";
}

// ─── Capability Selection ───────────────────────────────────────────────────

/**
 * Select capabilities based on engagement type and target context.
 */
function selectCapabilities(target: ExploitedTarget): string[] {
  const caps: string[] = [
    "system_survey",
    "network_scan",
    "process_list",
  ];

  if (target.engagementType === "red_team") {
    caps.push("credential_harvest", "lateral_movement", "persist_registry");
    if (target.privilegeLevel === "root" || target.privilegeLevel === "system") {
      caps.push("token_impersonation");
    }
  }

  if (target.engagementType === "pentest") {
    caps.push("screenshot", "file_search");
  }

  return caps;
}

// ─── Safety Check ───────────────────────────────────────────────────────────

/**
 * Validate Ember deployment against the safety engine.
 * C2 agent deployment is a red-tier action that requires appropriate safety level.
 */
async function checkSafetyForDeployment(target: ExploitedTarget): Promise<{
  allowed: boolean;
  reason?: string;
}> {
  try {
    const safetyEngine = getSafetyEngine();
    const assessment = safetyEngine.assessCommand(
      `ember_deploy --target ${target.ip} --profile ${selectProfile(target)} --engagement ${target.engagementId}`,
      "ember_agent",
      target.safetyLevel || 3
    );

    if (assessment.decision === "block") {
      return {
        allowed: false,
        reason: `Safety engine blocked: ${assessment.reason}`,
      };
    }

    return { allowed: true };
  } catch {
    // If safety engine is unavailable, default to allowed (operator already approved)
    return { allowed: true };
  }
}

// ─── Main Deployment Function ───────────────────────────────────────────────

/**
 * Deploy an Ember agent to an exploited target.
 *
 * This is the primary integration point called from the engagement orchestrator
 * when a shell is obtained and the operator approves C2 deployment.
 */
export async function deployEmberAgent(
  target: ExploitedTarget,
  callbackUrls: string[],
  options?: {
    profile?: EmberProfile;
    format?: EmberPayloadFormat;
    beaconInterval?: number;
    jitterPercent?: number;
    killDate?: number;
    autonomy?: "manual" | "guided" | "semi_auto" | "full_auto";
  }
): Promise<EmberDeploymentResult> {
  // 1. Safety check
  const safetyCheck = await checkSafetyForDeployment(target);
  if (!safetyCheck.allowed) {
    return {
      success: false,
      error: safetyCheck.reason,
      safetyBlocked: true,
    };
  }

  // 2. Determine deployment parameters
  const profile = options?.profile || selectProfile(target);
  const platform = detectPlatform(target);
  const format = options?.format || selectPayloadFormat(target);
  const profileDesc = EMBER_PROFILE_DESCRIPTIONS[profile];
  const beaconInterval = options?.beaconInterval || 30;
  const jitterPercent = options?.jitterPercent || 20;

  // 3. Generate the payload
  const payloadConfig: EmberPayloadConfig = {
    profile,
    platform,
    format,
    callback: {
      urls: callbackUrls,
      primaryChannel: "https_beacon",
      fallbackChannels: ["dns_covert"],
    },
    beacon: {
      intervalSeconds: beaconInterval,
      jitterPercent,
      killDate: options?.killDate,
    },
    evasion: {
      obfuscationLevel: profileDesc.stealthRating >= 80 ? 4 : 2,
      stringEncryption: profileDesc.stealthRating >= 70,
      controlFlowObfuscation: profileDesc.stealthRating >= 85,
      antiDebugging: profileDesc.stealthRating >= 60,
      antiVM: profileDesc.stealthRating >= 70,
      sandboxDetection: profileDesc.stealthRating >= 50,
      initialSleepMs: profileDesc.stealthRating >= 80 ? 5000 : 0,
    },
    registrationToken: `ember-${randomUUID().slice(0, 8)}-${Date.now().toString(36)}`,
  };

  const payload = generateEmberPayload(payloadConfig);

  // 4. Register the agent in the database
  const agentId = randomUUID();
  const agentName = `ember-${target.hostname.replace(/[^a-zA-Z0-9]/g, "").slice(0, 12)}-${agentId.slice(0, 6)}`;

  try {
    const db = await getDb();

    // Save payload record
    await db.insert(emberPayloads).values({
      payloadId: `payload-${randomUUID().slice(0, 8)}`,
      profile,
      platform,
      format,
      callbackUrls: JSON.stringify(callbackUrls),
      primaryChannel: "https_beacon",
      beaconConfig: JSON.stringify(payloadConfig.beacon),
      evasionConfig: JSON.stringify(payloadConfig.evasion),
      registrationToken: payloadConfig.registrationToken,
      filename: payload.filename,
      hash: payload.hash,
      size: payload.size,
      estimatedDetectionRate: payload.estimatedDetectionRate,
      engagementId: target.engagementId,
      createdAt: Date.now(),
    });

    // Register agent (will be confirmed when first beacon arrives)
    await db.insert(emberAgents).values({
      agentId,
      name: agentName,
      profile,
      platform,
      hostname: target.hostname,
      internalIp: target.ip,
      externalIp: target.ip,
      username: target.privilegeLevel === "root" ? "root" : "unknown",
      integrity: target.privilegeLevel || "user",
      state: "initializing",
      primaryChannel: "https_beacon",
      beaconInterval,
      jitterPercent,
      killDate: options?.killDate || null,
      autonomy: options?.autonomy || "guided",
      capabilities: JSON.stringify(selectCapabilities(target)),
      engagementId: target.engagementId,
      firstSeen: Date.now(),
      lastSeen: null,
    });

    // Create initial recon task
    await db.insert(emberTasks).values({
      taskId: randomUUID(),
      agentId,
      taskType: "system_survey",
      params: JSON.stringify({ full: true }),
      status: "pending",
      priority: 10,
      createdAt: Date.now(),
    });

    // 5. Emit events
    emitAgentDeployed({
      paw: agentId,
      host: target.hostname,
      platform: target.platform,
      executors: ["ember"],
      engagementId: target.engagementId,
    });

    emitSystemNotification({
      type: "agent_deployed",
      title: `Ember Agent Deployed: ${agentName}`,
      message: `${profile} profile on ${target.hostname} (${target.ip}) via ${format}`,
      severity: "info",
    });

    return {
      success: true,
      agentId,
      agentName,
      payloadFormat: format,
      deploymentMethod: `${format} via ${target.shellType}`,
    };
  } catch (error: any) {
    return {
      success: false,
      error: error.message || "Failed to register agent",
    };
  }
}

// ─── Orchestrator Hook ──────────────────────────────────────────────────────

/**
 * Hook for the engagement orchestrator's post-exploitation phase.
 * Called when the orchestrator decides to deploy C2 agents on compromised hosts.
 *
 * This function replaces or augments the existing Caldera deployment with Ember.
 */
export async function orchestratorDeployEmber(
  engagementId: number,
  compromisedAssets: Array<{
    hostname: string;
    ip: string;
    platform?: string;
    arch?: string;
    shellType?: string;
    sessionId?: string;
    exploitModule?: string;
    privilegeLevel?: string;
    detectedProducts?: string[];
  }>,
  engagementType: "pentest" | "red_team",
  callbackUrls: string[],
  safetyLevel?: number,
): Promise<EmberDeploymentResult[]> {
  const results: EmberDeploymentResult[] = [];

  for (const asset of compromisedAssets) {
    const target: ExploitedTarget = {
      hostname: asset.hostname,
      ip: asset.ip,
      platform: (asset.platform as any) || "linux",
      arch: (asset.arch as any) || "x64",
      shellType: (asset.shellType as any) || "reverse_shell",
      sessionId: asset.sessionId,
      exploitModule: asset.exploitModule,
      privilegeLevel: (asset.privilegeLevel as any) || "user",
      detectedProducts: asset.detectedProducts,
      engagementId,
      engagementType,
      safetyLevel,
    };

    const result = await deployEmberAgent(target, callbackUrls);
    results.push(result);
  }

  return results;
}

// ─── Intelligence Aggregation ───────────────────────────────────────────────

/**
 * Aggregate Ember intelligence into engagement findings.
 * Called during report generation to include agent-collected data.
 */
export async function getEmberIntelForEngagement(engagementId: number): Promise<{
  agents: number;
  activeAgents: number;
  tasksCompleted: number;
  credentialsFound: number;
  networksDiscovered: number;
  vulnerabilitiesFound: number;
  summary: string;
}> {
  try {
    const db = await getDb();
    const agents = await db.select().from(emberAgents)
      .where(eq(emberAgents.engagementId, engagementId));

    const activeCount = agents.filter(a => a.state === "active").length;

    const tasks = agents.length > 0
      ? await db.select().from(emberTasks)
          .where(inArray(emberTasks.agentId, agents.map(a => a.agentId)))
      : [];

    const completedTasks = tasks.filter(t => t.status === "success").length;

    return {
      agents: agents.length,
      activeAgents: activeCount,
      tasksCompleted: completedTasks,
      credentialsFound: 0, // Will be populated from intelligence table
      networksDiscovered: 0,
      vulnerabilitiesFound: 0,
      summary: agents.length > 0
        ? `${agents.length} Ember agent(s) deployed (${activeCount} active). ${completedTasks} tasks completed.`
        : "No Ember agents deployed for this engagement.",
    };
  } catch {
    return {
      agents: 0,
      activeAgents: 0,
      tasksCompleted: 0,
      credentialsFound: 0,
      networksDiscovered: 0,
      vulnerabilitiesFound: 0,
      summary: "Ember intelligence unavailable.",
    };
  }
}

// ─── Export ─────────────────────────────────────────────────────────────────

export {
  selectProfile,
  selectPayloadFormat,
  selectCapabilities,
  detectPlatform,
  checkSafetyForDeployment,
};
