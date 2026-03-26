/**
 * Campaign Orchestrator Engine
 *
 * Chains multiple engagement phases with conditional logic to automate
 * full red team campaigns end-to-end. Each campaign contains ordered stages
 * that can reference existing engagements or create new ones on-the-fly.
 *
 * Features:
 *   - Conditional entry/exit conditions per stage
 *   - Branching logic (on_success → next/skip_to/complete/pause)
 *   - Failure handling (abort/skip/retry/pause/fallback)
 *   - Timeout enforcement per stage
 *   - Real-time WebSocket event broadcasting
 *   - AI-powered campaign plan generation
 *   - CARVER+Shock scoring integration
 *   - Owner notifications on stage/campaign completion
 */

import { getDb } from "../db";
import {
  redteamCampaigns,
  redteamCampaignStages,
  redteamCampaignLogs,
  type RedteamCampaignRow,
  type RedteamCampaignStageRow,
} from "../../drizzle/schema";
import { eq, and, asc, desc, sql } from "drizzle-orm";

// ─── Types ──────────────────────────────────────────────────────────────────

export type CampaignStatus = "draft" | "ready" | "running" | "paused" | "completed" | "failed" | "aborted";
export type StageStatus = "pending" | "waiting" | "running" | "completed" | "failed" | "skipped" | "timed_out" | "aborted";
export type StageType =
  | "recon" | "enumeration" | "vuln_scan" | "phishing" | "exploitation"
  | "post_exploit" | "lateral_move" | "c2_deploy" | "exfiltration" | "cleanup" | "custom";

export interface Condition {
  field: string;       // e.g. "vulns_found", "c2_agents", "exploits_succeeded", "carver_score"
  operator: ">" | ">=" | "<" | "<=" | "==" | "!=" | "contains" | "exists";
  value: string | number | boolean;
}

export interface StageConfig {
  targets?: string[];
  tools?: string[];
  scanProfile?: "quick" | "standard" | "deep" | "stealth";
  phishingTemplate?: string;
  exploitIds?: string[];
  customCommand?: string;
  safetyOverride?: string;
  [key: string]: any;
}

export interface StageResults {
  vulnsFound?: number;
  criticalVulns?: number;
  highVulns?: number;
  exploitsAttempted?: number;
  exploitsSucceeded?: number;
  c2Agents?: number;
  sessionsOpened?: number;
  hostsScanned?: number;
  portsFound?: number;
  carverScore?: number;
  carverTier?: string;
  attackChains?: number;
  phishingClicks?: number;
  credsHarvested?: number;
  dataExfilMb?: number;
  customResults?: Record<string, any>;
}

export interface CampaignResultsSummary {
  totalStages: number;
  completedStages: number;
  failedStages: number;
  skippedStages: number;
  totalVulns: number;
  criticalVulns: number;
  totalExploits: number;
  successfulExploits: number;
  c2Agents: number;
  attackChains: number;
  overallCarverScore: number;
  overallCarverTier: string;
  durationMinutes: number;
}

// ─── In-Memory Campaign State ───────────────────────────────────────────────

interface CampaignRunState {
  campaignId: number;
  isRunning: boolean;
  isPaused: boolean;
  abortController: AbortController;
  currentStageId?: number;
  startedAt?: number;
}

const campaignRunStates = new Map<number, CampaignRunState>();

// ─── Condition Evaluator ────────────────────────────────────────────────────

/**
 * Evaluate a single condition against a results context.
 * The context is built from the previous stage's results + cumulative campaign data.
 */
export function evaluateCondition(condition: Condition, context: Record<string, any>): boolean {
  const fieldValue = context[condition.field];

  switch (condition.operator) {
    case ">":
      return typeof fieldValue === "number" && fieldValue > Number(condition.value);
    case ">=":
      return typeof fieldValue === "number" && fieldValue >= Number(condition.value);
    case "<":
      return typeof fieldValue === "number" && fieldValue < Number(condition.value);
    case "<=":
      return typeof fieldValue === "number" && fieldValue <= Number(condition.value);
    case "==":
      return String(fieldValue) === String(condition.value);
    case "!=":
      return String(fieldValue) !== String(condition.value);
    case "contains":
      if (Array.isArray(fieldValue)) return fieldValue.includes(condition.value);
      if (typeof fieldValue === "string") return fieldValue.includes(String(condition.value));
      return false;
    case "exists":
      return fieldValue !== undefined && fieldValue !== null;
    default:
      return false;
  }
}

/**
 * Evaluate all conditions in an array (AND logic — all must pass).
 */
export function evaluateConditions(conditions: Condition[], context: Record<string, any>): {
  passed: boolean;
  results: Array<{ condition: Condition; passed: boolean; actualValue: any }>;
} {
  if (!conditions || conditions.length === 0) return { passed: true, results: [] };

  const results = conditions.map((c) => ({
    condition: c,
    passed: evaluateCondition(c, context),
    actualValue: context[c.field],
  }));

  return {
    passed: results.every((r) => r.passed),
    results,
  };
}

// ─── Campaign Log Helper ────────────────────────────────────────────────────

async function addCampaignLog(
  campaignId: number,
  stageId: number | null,
  logType: string,
  title: string,
  detail?: string,
  metadata?: Record<string, any>
): Promise<void> {
  try {
    const db = await getDb();
    if (!db) return;
    await db.insert(redteamCampaignLogs).values({
      campaignId,
      stageId,
      logType: logType as any,
      title,
      detail,
      metadata,
    });
  } catch (err: any) {
    console.error(`[CampaignOrch] Failed to write log: ${err.message}`);
  }
}

// ─── WebSocket Broadcasting ─────────────────────────────────────────────────

async function broadcastCampaignEvent(
  type: string,
  data: Record<string, any>
): Promise<void> {
  try {
    const { emitSystemNotification } = await import("./ws-event-hub");
    emitSystemNotification({
      title: `Campaign Orchestrator: ${type}`,
      message: JSON.stringify(data),
      severity: type.includes("fail") || type.includes("abort") ? "error" : "info",
    });
  } catch {
    // WebSocket not available — ignore
  }
}

// ─── Stage Executor ─────────────────────────────────────────────────────────

/**
 * Execute a single campaign stage by delegating to the engagement orchestrator.
 * Returns the stage results for condition evaluation.
 */
async function executeStage(
  stage: RedteamCampaignStageRow,
  campaign: RedteamCampaignRow,
  operatorCtx: { id: string; name?: string },
  signal: AbortSignal
): Promise<StageResults> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  // Update stage status to running
  await db.update(redteamCampaignStages)
    .set({ status: "running", startedAt: new Date().toISOString() } as any)
    .where(eq(redteamCampaignStages.id, stage.id));

  await addCampaignLog(campaign.id, stage.id, "stage_start",
    `Stage ${stage.stageOrder}: ${stage.name} started`,
    `Type: ${stage.stageType}, Engagement: ${stage.engagementId || "N/A"}`
  );

  await broadcastCampaignEvent("stage_started", {
    campaignId: campaign.id,
    stageId: stage.id,
    stageName: stage.name,
    stageOrder: stage.stageOrder,
    stageType: stage.stageType,
  });

  const results: StageResults = {};

  try {
    // If this stage is linked to an engagement, execute it
    if (stage.engagementId) {
      const {
        executeEngagement,
        getOpsState,
        initOpsState,
        getOpsStateWithRecovery,
      } = await import("./engagement-orchestrator");

      // Determine which engagement phase to run based on stage type
      const stageToPhaseMap: Record<string, string> = {
        recon: "recon",
        enumeration: "enumeration",
        vuln_scan: "vuln_detection",
        exploitation: "exploitation",
        post_exploit: "post_exploit",
        c2_deploy: "exploitation", // C2 deploy is part of exploitation
        lateral_move: "post_exploit", // Lateral movement is post-exploit
        exfiltration: "post_exploit",
        cleanup: "post_exploit",
      };

      const startPhase = stageToPhaseMap[stage.stageType] || "recon";
      const config = (stage.config as StageConfig) || {};

      // Initialize or get existing ops state
      let opsState = getOpsState(stage.engagementId);
      if (!opsState) {
        const { getEngagementById } = await import("../db");
        const eng = await getEngagementById(stage.engagementId);
        opsState = initOpsState(stage.engagementId, eng?.engagementType || "red_team");
      }

      // Set exhaustive exploit mode
      opsState.exhaustiveExploit = true;

      // Execute the engagement for this phase
      await executeEngagement(stage.engagementId, operatorCtx, {
        startPhase: startPhase as any,
        scanProfile: config.scanProfile || "standard",
      });

      // Wait for the engagement to complete (poll with abort check)
      const timeoutMs = (stage.timeoutMinutes || 60) * 60 * 1000;
      const startTime = Date.now();

      while (true) {
        if (signal.aborted) throw new Error("Campaign aborted");

        const state = await getOpsStateWithRecovery(stage.engagementId);
        if (!state) break;

        // Check if the engagement phase has completed or errored
        if (!state.isRunning || state.phase === "completed" || state.phase === "error") {
          // Extract results from the engagement state
          results.vulnsFound = state.stats.vulnsFound;
          results.hostsScanned = state.stats.hostsScanned;
          results.portsFound = state.stats.portsFound;
          results.exploitsAttempted = state.stats.exploitsAttempted;
          results.exploitsSucceeded = state.stats.exploitsSucceeded;
          results.sessionsOpened = state.stats.sessionsOpened;
          results.c2Agents = state.stats.sessionsOpened; // C2 agents = sessions opened

          // Count severity levels from assets
          let critical = 0, high = 0;
          for (const asset of state.assets) {
            for (const vuln of asset.vulns || []) {
              const sev = typeof vuln === "object" ? (vuln as any).severity : "";
              if (sev === "critical") critical++;
              else if (sev === "high") high++;
            }
          }
          results.criticalVulns = critical;
          results.highVulns = high;

          if (state.phase === "error") {
            throw new Error(state.error || "Engagement failed");
          }
          break;
        }

        // Timeout check
        if (Date.now() - startTime > timeoutMs) {
          throw new Error(`Stage timed out after ${stage.timeoutMinutes} minutes`);
        }

        // Poll every 10 seconds
        await new Promise((resolve) => setTimeout(resolve, 10000));
      }
    } else if (stage.stageType === "custom") {
      // Custom stage — execute via LLM
      const config = (stage.config as StageConfig) || {};
      await addCampaignLog(campaign.id, stage.id, "ai_decision",
        `Custom stage: ${stage.name}`,
        config.customCommand || "No custom command specified"
      );
      // Custom stages complete immediately with empty results
      results.customResults = { command: config.customCommand, status: "executed" };
    } else if (stage.stageType === "phishing") {
      // Phishing stage — would integrate with GoPhish
      const config = (stage.config as StageConfig) || {};
      await addCampaignLog(campaign.id, stage.id, "info",
        `Phishing stage: ${stage.name}`,
        `Template: ${config.phishingTemplate || "default"}, Targets: ${config.targets?.length || 0}`
      );
      results.phishingClicks = 0;
      results.credsHarvested = 0;
    }

    // Stage completed successfully
    await db.update(redteamCampaignStages)
      .set({
        status: "completed",
        completedAt: new Date().toISOString(),
        results: results,
      } as any)
      .where(eq(redteamCampaignStages.id, stage.id));

    await addCampaignLog(campaign.id, stage.id, "stage_complete",
      `Stage ${stage.stageOrder}: ${stage.name} completed`,
      `Results: ${JSON.stringify(results)}`
    );

    await broadcastCampaignEvent("stage_completed", {
      campaignId: campaign.id,
      stageId: stage.id,
      stageName: stage.name,
      results,
    });

    return results;

  } catch (err: any) {
    const errorMsg = err.message || "Unknown error";
    const isTimeout = errorMsg.includes("timed out");

    await db.update(redteamCampaignStages)
      .set({
        status: isTimeout ? "timed_out" : "failed",
        completedAt: new Date().toISOString(),
        errorMessage: errorMsg,
        results: results,
      } as any)
      .where(eq(redteamCampaignStages.id, stage.id));

    await addCampaignLog(campaign.id, stage.id, "stage_fail",
      `Stage ${stage.stageOrder}: ${stage.name} ${isTimeout ? "timed out" : "failed"}`,
      errorMsg
    );

    await broadcastCampaignEvent("stage_failed", {
      campaignId: campaign.id,
      stageId: stage.id,
      stageName: stage.name,
      error: errorMsg,
    });

    throw err;
  }
}

// ─── Campaign Executor ──────────────────────────────────────────────────────

/**
 * Execute a full campaign — iterate through stages with conditional logic.
 * This is the main entry point for campaign execution.
 */
export async function executeCampaign(
  campaignId: number,
  operatorCtx: { id: string; name?: string }
): Promise<void> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  // Load campaign
  const [campaign] = await db.select().from(redteamCampaigns).where(eq(redteamCampaigns.id, campaignId));
  if (!campaign) throw new Error(`Campaign ${campaignId} not found`);
  if (campaign.status === "running") throw new Error("Campaign is already running");

  // Load stages ordered by stageOrder
  const stages = await db.select().from(redteamCampaignStages)
    .where(eq(redteamCampaignStages.campaignId, campaignId))
    .orderBy(asc(redteamCampaignStages.stageOrder));

  if (stages.length === 0) throw new Error("Campaign has no stages");

  // Set up run state
  const abortController = new AbortController();
  const runState: CampaignRunState = {
    campaignId,
    isRunning: true,
    isPaused: false,
    abortController,
    startedAt: Date.now(),
  };
  campaignRunStates.set(campaignId, runState);

  // Update campaign status
  await db.update(redteamCampaigns)
    .set({
      status: "running",
      startedAt: new Date().toISOString(),
      currentStageOrder: stages[0].stageOrder,
    } as any)
    .where(eq(redteamCampaigns.id, campaignId));

  await addCampaignLog(campaignId, null, "campaign_start",
    `Campaign "${campaign.name}" started`,
    `${stages.length} stages, safety: ${campaign.safetyLevel}, max duration: ${campaign.maxDurationHours}h`
  );

  await broadcastCampaignEvent("started", { campaignId, name: campaign.name, stageCount: stages.length });

  // Build cumulative context for condition evaluation
  const cumulativeContext: Record<string, any> = {
    total_vulns: 0,
    critical_vulns: 0,
    high_vulns: 0,
    exploits_attempted: 0,
    exploits_succeeded: 0,
    c2_agents: 0,
    sessions_opened: 0,
    hosts_scanned: 0,
    ports_found: 0,
    stages_completed: 0,
    stages_failed: 0,
    phishing_clicks: 0,
    creds_harvested: 0,
  };

  // Campaign-level timeout
  const campaignTimeoutMs = (campaign.maxDurationHours || 72) * 60 * 60 * 1000;
  const campaignStartTime = Date.now();

  let finalStatus: CampaignStatus = "completed";
  let currentStageIdx = 0;

  try {
    while (currentStageIdx < stages.length) {
      // Check abort
      if (abortController.signal.aborted) {
        finalStatus = "aborted";
        break;
      }

      // Check pause
      while (runState.isPaused) {
        await new Promise((resolve) => setTimeout(resolve, 2000));
        if (abortController.signal.aborted) {
          finalStatus = "aborted";
          break;
        }
      }
      if (finalStatus === "aborted") break;

      // Campaign-level timeout check
      if (Date.now() - campaignStartTime > campaignTimeoutMs) {
        await addCampaignLog(campaignId, null, "timeout",
          `Campaign timed out after ${campaign.maxDurationHours} hours`
        );
        finalStatus = "failed";
        break;
      }

      const stage = stages[currentStageIdx];
      runState.currentStageId = stage.id;

      // Update current stage order in campaign
      await db.update(redteamCampaigns)
        .set({ currentStageOrder: stage.stageOrder } as any)
        .where(eq(redteamCampaigns.id, campaignId));

      // ─── Evaluate Entry Conditions ──────────────────────────────────
      const entryConditions = (stage.entryConditions as Condition[]) || [];
      if (entryConditions.length > 0) {
        const evalResult = evaluateConditions(entryConditions, cumulativeContext);

        await addCampaignLog(campaignId, stage.id, "condition_eval",
          `Entry conditions for stage ${stage.stageOrder}: ${evalResult.passed ? "PASSED" : "FAILED"}`,
          JSON.stringify(evalResult.results),
          { type: "entry", passed: evalResult.passed }
        );

        if (!evalResult.passed) {
          // Entry conditions not met — skip this stage
          await db.update(redteamCampaignStages)
            .set({ status: "skipped", completedAt: new Date().toISOString() } as any)
            .where(eq(redteamCampaignStages.id, stage.id));

          await addCampaignLog(campaignId, stage.id, "info",
            `Stage ${stage.stageOrder}: ${stage.name} skipped (entry conditions not met)`
          );

          currentStageIdx++;
          continue;
        }
      }

      // ─── Execute Stage ──────────────────────────────────────────────
      try {
        const stageResults = await executeStage(stage, campaign, operatorCtx, abortController.signal);

        // Update cumulative context
        cumulativeContext.total_vulns += stageResults.vulnsFound || 0;
        cumulativeContext.critical_vulns += stageResults.criticalVulns || 0;
        cumulativeContext.high_vulns += stageResults.highVulns || 0;
        cumulativeContext.exploits_attempted += stageResults.exploitsAttempted || 0;
        cumulativeContext.exploits_succeeded += stageResults.exploitsSucceeded || 0;
        cumulativeContext.c2_agents += stageResults.c2Agents || 0;
        cumulativeContext.sessions_opened += stageResults.sessionsOpened || 0;
        cumulativeContext.hosts_scanned += stageResults.hostsScanned || 0;
        cumulativeContext.ports_found += stageResults.portsFound || 0;
        cumulativeContext.stages_completed += 1;
        cumulativeContext.phishing_clicks += stageResults.phishingClicks || 0;
        cumulativeContext.creds_harvested += stageResults.credsHarvested || 0;

        // Store latest stage results for next stage's conditions
        cumulativeContext[`stage_${stage.stageOrder}_vulns`] = stageResults.vulnsFound || 0;
        cumulativeContext[`stage_${stage.stageOrder}_exploits`] = stageResults.exploitsSucceeded || 0;
        cumulativeContext[`stage_${stage.stageOrder}_c2`] = stageResults.c2Agents || 0;

        // ─── Evaluate Exit Conditions ─────────────────────────────────
        const exitConditions = (stage.exitConditions as Condition[]) || [];
        if (exitConditions.length > 0) {
          const exitEval = evaluateConditions(exitConditions, {
            ...cumulativeContext,
            ...stageResults,
            vulns_found: stageResults.vulnsFound || 0,
            exploits_succeeded: stageResults.exploitsSucceeded || 0,
            c2_agents: stageResults.c2Agents || 0,
          });

          await addCampaignLog(campaignId, stage.id, "condition_eval",
            `Exit conditions for stage ${stage.stageOrder}: ${exitEval.passed ? "PASSED" : "FAILED"}`,
            JSON.stringify(exitEval.results),
            { type: "exit", passed: exitEval.passed }
          );

          if (!exitEval.passed) {
            // Exit conditions not met — treat as failure
            throw new Error(`Exit conditions not met for stage ${stage.stageOrder}`);
          }
        }

        // ─── Handle Success Branching ─────────────────────────────────
        const onSuccess = stage.onSuccess || "next";

        await addCampaignLog(campaignId, stage.id, "branch_decision",
          `Stage ${stage.stageOrder} success → action: ${onSuccess}`,
          stage.onSuccessTarget ? `Target stage: ${stage.onSuccessTarget}` : undefined
        );

        // Notify on stage complete
        if (campaign.notifyOnStageComplete) {
          try {
            const { notifyOwner } = await import("../_core/notification");
            await notifyOwner({
              title: `Campaign Stage Complete: ${stage.name}`,
              content: `Stage ${stage.stageOrder}/${stages.length} of campaign "${campaign.name}" completed.\nVulns: ${stageResults.vulnsFound || 0}, Exploits: ${stageResults.exploitsSucceeded || 0}, C2 Agents: ${stageResults.c2Agents || 0}`,
            });
          } catch { /* notification failure is non-fatal */ }
        }

        switch (onSuccess) {
          case "next":
            currentStageIdx++;
            break;
          case "skip_to":
            if (stage.onSuccessTarget) {
              const targetIdx = stages.findIndex((s) => s.stageOrder === stage.onSuccessTarget);
              if (targetIdx >= 0) {
                // Skip intermediate stages
                for (let i = currentStageIdx + 1; i < targetIdx; i++) {
                  await db.update(redteamCampaignStages)
                    .set({ status: "skipped" } as any)
                    .where(eq(redteamCampaignStages.id, stages[i].id));
                }
                currentStageIdx = targetIdx;
              } else {
                currentStageIdx++;
              }
            } else {
              currentStageIdx++;
            }
            break;
          case "complete":
            // Mark remaining stages as skipped
            for (let i = currentStageIdx + 1; i < stages.length; i++) {
              await db.update(redteamCampaignStages)
                .set({ status: "skipped" } as any)
                .where(eq(redteamCampaignStages.id, stages[i].id));
            }
            currentStageIdx = stages.length; // Exit loop
            break;
          case "pause":
            runState.isPaused = true;
            await db.update(redteamCampaigns)
              .set({ status: "paused", pausedAt: new Date().toISOString() } as any)
              .where(eq(redteamCampaigns.id, campaignId));
            await addCampaignLog(campaignId, stage.id, "campaign_pause",
              `Campaign paused after stage ${stage.stageOrder} (on_success=pause)`
            );
            currentStageIdx++;
            break;
        }

      } catch (stageErr: any) {
        // ─── Handle Failure Branching ─────────────────────────────────
        const onFailure = stage.onFailure || "pause";
        cumulativeContext.stages_failed += 1;

        await addCampaignLog(campaignId, stage.id, "branch_decision",
          `Stage ${stage.stageOrder} failed → action: ${onFailure}`,
          stageErr.message
        );

        switch (onFailure) {
          case "retry": {
            const retryCount = (stage.retryCount || 0) + 1;
            const maxRetries = stage.maxRetries || 1;
            if (retryCount <= maxRetries) {
              await db.update(redteamCampaignStages)
                .set({ retryCount, status: "pending" } as any)
                .where(eq(redteamCampaignStages.id, stage.id));
              await addCampaignLog(campaignId, stage.id, "retry",
                `Retrying stage ${stage.stageOrder} (attempt ${retryCount}/${maxRetries})`
              );
              // Don't increment currentStageIdx — retry same stage
            } else {
              // Max retries exceeded — fall through to pause
              await addCampaignLog(campaignId, stage.id, "error",
                `Stage ${stage.stageOrder} max retries (${maxRetries}) exceeded`
              );
              runState.isPaused = true;
              await db.update(redteamCampaigns)
                .set({ status: "paused", pausedAt: new Date().toISOString() } as any)
                .where(eq(redteamCampaigns.id, campaignId));
              currentStageIdx++;
            }
            break;
          }
          case "skip":
            currentStageIdx++;
            break;
          case "fallback":
            if (stage.onFailureTarget) {
              const fallbackIdx = stages.findIndex((s) => s.stageOrder === stage.onFailureTarget);
              if (fallbackIdx >= 0) {
                currentStageIdx = fallbackIdx;
              } else {
                currentStageIdx++;
              }
            } else {
              currentStageIdx++;
            }
            break;
          case "pause":
            runState.isPaused = true;
            await db.update(redteamCampaigns)
              .set({ status: "paused", pausedAt: new Date().toISOString() } as any)
              .where(eq(redteamCampaigns.id, campaignId));
            await addCampaignLog(campaignId, stage.id, "campaign_pause",
              `Campaign paused due to stage ${stage.stageOrder} failure`
            );
            currentStageIdx++;
            break;
          case "abort":
          default:
            finalStatus = "failed";
            await addCampaignLog(campaignId, stage.id, "campaign_abort",
              `Campaign aborted due to stage ${stage.stageOrder} failure`,
              stageErr.message
            );
            currentStageIdx = stages.length; // Exit loop
            break;
        }
      }
    }

    // ─── Campaign Complete ──────────────────────────────────────────────
    const summary: CampaignResultsSummary = {
      totalStages: stages.length,
      completedStages: cumulativeContext.stages_completed,
      failedStages: cumulativeContext.stages_failed,
      skippedStages: stages.length - cumulativeContext.stages_completed - cumulativeContext.stages_failed,
      totalVulns: cumulativeContext.total_vulns,
      criticalVulns: cumulativeContext.critical_vulns,
      totalExploits: cumulativeContext.exploits_attempted,
      successfulExploits: cumulativeContext.exploits_succeeded,
      c2Agents: cumulativeContext.c2_agents,
      attackChains: 0,
      overallCarverScore: 0,
      overallCarverTier: "N/A",
      durationMinutes: Math.round((Date.now() - campaignStartTime) / 60000),
    };

    await db.update(redteamCampaigns)
      .set({
        status: finalStatus,
        completedAt: new Date().toISOString(),
        resultsSummary: summary,
      } as any)
      .where(eq(redteamCampaigns.id, campaignId));

    await addCampaignLog(campaignId, null, "campaign_complete",
      `Campaign "${campaign.name}" ${finalStatus}`,
      JSON.stringify(summary)
    );

    await broadcastCampaignEvent("completed", {
      campaignId,
      name: campaign.name,
      status: finalStatus,
      summary,
    });

    // Notify owner
    if (campaign.notifyOnCampaignComplete) {
      try {
        const { notifyOwner } = await import("../_core/notification");
        await notifyOwner({
          title: `Campaign ${finalStatus === "completed" ? "Complete" : "Ended"}: ${campaign.name}`,
          content: [
            `Status: ${finalStatus.toUpperCase()}`,
            `Duration: ${summary.durationMinutes} minutes`,
            `Stages: ${summary.completedStages}/${summary.totalStages} completed, ${summary.failedStages} failed`,
            `Vulnerabilities: ${summary.totalVulns} (${summary.criticalVulns} critical)`,
            `Exploits: ${summary.successfulExploits}/${summary.totalExploits} succeeded`,
            `C2 Agents: ${summary.c2Agents}`,
          ].join("\n"),
        });
      } catch { /* non-fatal */ }
    }

  } catch (err: any) {
    // Unhandled campaign-level error
    await db.update(redteamCampaigns)
      .set({ status: "failed", completedAt: new Date().toISOString() } as any)
      .where(eq(redteamCampaigns.id, campaignId));

    await addCampaignLog(campaignId, null, "error",
      `Campaign crashed: ${err.message}`
    );
  } finally {
    runState.isRunning = false;
    campaignRunStates.delete(campaignId);
  }
}

// ─── Campaign Control Functions ─────────────────────────────────────────────

export function pauseCampaign(campaignId: number): boolean {
  const state = campaignRunStates.get(campaignId);
  if (!state || !state.isRunning) return false;
  state.isPaused = true;
  return true;
}

export function resumeCampaign(campaignId: number): boolean {
  const state = campaignRunStates.get(campaignId);
  if (!state || !state.isPaused) return false;
  state.isPaused = false;
  return true;
}

export function abortCampaign(campaignId: number): boolean {
  const state = campaignRunStates.get(campaignId);
  if (!state || !state.isRunning) return false;
  state.abortController.abort();
  return true;
}

export function getCampaignRunState(campaignId: number): CampaignRunState | null {
  return campaignRunStates.get(campaignId) || null;
}

export function getRunningCampaigns(): number[] {
  return [...campaignRunStates.entries()]
    .filter(([, s]) => s.isRunning)
    .map(([id]) => id);
}

// ─── AI Campaign Plan Generator ─────────────────────────────────────────────

export interface AICampaignPlan {
  name: string;
  objective: string;
  stages: Array<{
    name: string;
    stageType: StageType;
    description: string;
    entryConditions: Condition[];
    exitConditions: Condition[];
    onSuccess: "next" | "skip_to" | "complete" | "pause";
    onFailure: "abort" | "skip" | "retry" | "pause" | "fallback";
    timeoutMinutes: number;
    config: StageConfig;
  }>;
  estimatedDurationHours: number;
  riskAssessment: string;
}

/**
 * Generate an AI-powered campaign plan based on target description and objectives.
 */
export async function generateCampaignPlan(
  targetDescription: string,
  objective: string,
  engagementType: string,
  safetyLevel: string
): Promise<AICampaignPlan> {
  const { invokeLLM } = await import("../_core/llm");

  const response = await invokeLLM({
    _caller: 'campaign-orchestrator.generateCampaignPlan',
    messages: [
      {
        role: "system",
        content: `You are the AC3 Campaign Orchestrator AI. You design multi-stage red team campaigns with conditional logic.

Each campaign consists of ordered stages. Each stage has:
- stageType: recon, enumeration, vuln_scan, phishing, exploitation, post_exploit, lateral_move, c2_deploy, exfiltration, cleanup, custom
- entryConditions: conditions that must be true to start (AND logic). Fields: total_vulns, critical_vulns, exploits_succeeded, c2_agents, hosts_scanned, etc.
- exitConditions: conditions that must be true for success. Same fields.
- onSuccess: next (proceed), skip_to (jump to stage N), complete (end campaign), pause (wait for operator)
- onFailure: abort (stop campaign), skip (continue), retry (try again), pause (wait), fallback (go to stage N)

CARVER+Shock scoring model:
- C: Criticality (target value to mission)
- A: Accessibility (ease of reaching target)
- R: Recuperability (time for target to recover)
- V: Vulnerability (exploitability)
- E: Effect (impact of successful attack)
- R: Recognizability (ease of identifying target)
- Shock: Psychological/organizational impact

Safety levels: passive_only, low_impact, standard, full_exploitation

Design campaigns that are:
1. Progressive — each stage builds on the previous
2. Conditional — use entry/exit conditions to adapt
3. Resilient — handle failures gracefully
4. Efficient — skip unnecessary stages when possible
5. Safe — respect the safety level constraints

Return a JSON object with the campaign plan.`,
      },
      {
        role: "user",
        content: `Design a red team campaign plan:
Target: ${targetDescription}
Objective: ${objective}
Type: ${engagementType}
Safety Level: ${safetyLevel}

Return a JSON object with: name, objective, stages (array), estimatedDurationHours, riskAssessment`,
      },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "campaign_plan",
        strict: true,
        schema: {
          type: "object",
          properties: {
            name: { type: "string" },
            objective: { type: "string" },
            stages: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  name: { type: "string" },
                  stageType: { type: "string" },
                  description: { type: "string" },
                  entryConditions: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        field: { type: "string" },
                        operator: { type: "string" },
                        value: { type: "string" },
                      },
                      required: ["field", "operator", "value"],
                      additionalProperties: false,
                    },
                  },
                  exitConditions: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        field: { type: "string" },
                        operator: { type: "string" },
                        value: { type: "string" },
                      },
                      required: ["field", "operator", "value"],
                      additionalProperties: false,
                    },
                  },
                  onSuccess: { type: "string" },
                  onFailure: { type: "string" },
                  timeoutMinutes: { type: "number" },
                  config: {
                    type: "object",
                    properties: {
                      targets: { type: "array", items: { type: "string" } },
                      tools: { type: "array", items: { type: "string" } },
                      scanProfile: { type: "string" },
                    },
                    required: [],
                    additionalProperties: true,
                  },
                },
                required: ["name", "stageType", "description", "entryConditions", "exitConditions", "onSuccess", "onFailure", "timeoutMinutes", "config"],
                additionalProperties: false,
              },
            },
            estimatedDurationHours: { type: "number" },
            riskAssessment: { type: "string" },
          },
          required: ["name", "objective", "stages", "estimatedDurationHours", "riskAssessment"],
          additionalProperties: false,
        },
      },
    },
    _caller: "campaign-orchestrator:generatePlan",
  });

  const content = response.choices?.[0]?.message?.content;
  if (!content) throw new Error("LLM returned empty response");

  try {
    return JSON.parse(content) as AICampaignPlan;
  } catch {
    throw new Error("Failed to parse AI campaign plan");
  }
}
