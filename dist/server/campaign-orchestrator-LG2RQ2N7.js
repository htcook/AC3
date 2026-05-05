import {
  persistCampaignRunState,
  removeCampaignRunState
} from "./chunk-WVL2ZNPQ.js";
import {
  getDb,
  init_db
} from "./chunk-AGW4B7XR.js";
import "./chunk-NRYVRXXR.js";
import {
  init_schema,
  redteamCampaignLogs,
  redteamCampaignStages,
  redteamCampaigns
} from "./chunk-YB6W7YNA.js";
import "./chunk-KFQGP6VL.js";

// server/lib/campaign-orchestrator.ts
init_db();
init_schema();
import { eq, asc } from "drizzle-orm";
var campaignRunStates = /* @__PURE__ */ new Map();
function persistCampaignAsync(state) {
  persistCampaignRunState({
    campaignId: state.campaignId,
    isRunning: state.isRunning,
    isPaused: state.isPaused,
    currentStageId: state.currentStageId,
    startedAt: state.startedAt
  }).catch(() => {
  });
}
function evaluateCondition(condition, context) {
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
      return fieldValue !== void 0 && fieldValue !== null;
    default:
      return false;
  }
}
function evaluateConditions(conditions, context) {
  if (!conditions || conditions.length === 0) return { passed: true, results: [] };
  const results = conditions.map((c) => ({
    condition: c,
    passed: evaluateCondition(c, context),
    actualValue: context[c.field]
  }));
  return {
    passed: results.every((r) => r.passed),
    results
  };
}
async function addCampaignLog(campaignId, stageId, logType, title, detail, metadata) {
  try {
    const db = await getDb();
    if (!db) return;
    await db.insert(redteamCampaignLogs).values({
      campaignId,
      stageId,
      logType,
      title,
      detail,
      metadata
    });
  } catch (err) {
    console.error(`[CampaignOrch] Failed to write log: ${err.message}`);
  }
}
async function broadcastCampaignEvent(type, data) {
  try {
    const { emitSystemNotification } = await import("./ws-event-hub-GYTLNKYI.js");
    emitSystemNotification({
      title: `Campaign Orchestrator: ${type}`,
      message: JSON.stringify(data),
      severity: type.includes("fail") || type.includes("abort") ? "error" : "info"
    });
  } catch {
  }
}
async function executeStage(stage, campaign, operatorCtx, signal) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  await db.update(redteamCampaignStages).set({ status: "running", startedAt: (/* @__PURE__ */ new Date()).toISOString() }).where(eq(redteamCampaignStages.id, stage.id));
  await addCampaignLog(
    campaign.id,
    stage.id,
    "stage_start",
    `Stage ${stage.stageOrder}: ${stage.name} started`,
    `Type: ${stage.stageType}, Engagement: ${stage.engagementId || "N/A"}`
  );
  await broadcastCampaignEvent("stage_started", {
    campaignId: campaign.id,
    stageId: stage.id,
    stageName: stage.name,
    stageOrder: stage.stageOrder,
    stageType: stage.stageType
  });
  const results = {};
  try {
    if (stage.engagementId) {
      const {
        executeEngagement,
        getOpsState,
        initOpsState,
        getOpsStateWithRecovery
      } = await import("./engagement-orchestrator-XHR6CX64.js");
      const stageToPhaseMap = {
        recon: "recon",
        enumeration: "enumeration",
        vuln_scan: "vuln_detection",
        exploitation: "exploitation",
        post_exploit: "post_exploit",
        c2_deploy: "exploitation",
        // C2 deploy is part of exploitation
        lateral_move: "post_exploit",
        // Lateral movement is post-exploit
        exfiltration: "post_exploit",
        cleanup: "post_exploit"
      };
      const startPhase = stageToPhaseMap[stage.stageType] || "recon";
      const config = stage.config || {};
      let opsState = getOpsState(stage.engagementId);
      if (!opsState) {
        const { getEngagementById } = await import("./db-JLHOBMS4.js");
        const eng = await getEngagementById(stage.engagementId);
        opsState = initOpsState(stage.engagementId, eng?.engagementType || "red_team");
      }
      opsState.exhaustiveExploit = true;
      await executeEngagement(stage.engagementId, operatorCtx, {
        startPhase,
        scanProfile: config.scanProfile || "standard"
      });
      const timeoutMs = (stage.timeoutMinutes || 60) * 60 * 1e3;
      const startTime = Date.now();
      while (true) {
        if (signal.aborted) throw new Error("Campaign aborted");
        const state = await getOpsStateWithRecovery(stage.engagementId);
        if (!state) break;
        if (!state.isRunning || state.phase === "completed" || state.phase === "error") {
          results.vulnsFound = state.stats.vulnsFound;
          results.hostsScanned = state.stats.hostsScanned;
          results.portsFound = state.stats.portsFound;
          results.exploitsAttempted = state.stats.exploitsAttempted;
          results.exploitsSucceeded = state.stats.exploitsSucceeded;
          results.sessionsOpened = state.stats.sessionsOpened;
          results.c2Agents = state.stats.sessionsOpened;
          let critical = 0, high = 0;
          for (const asset of state.assets) {
            for (const vuln of asset.vulns || []) {
              const sev = typeof vuln === "object" ? vuln.severity : "";
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
        if (Date.now() - startTime > timeoutMs) {
          throw new Error(`Stage timed out after ${stage.timeoutMinutes} minutes`);
        }
        await new Promise((resolve) => setTimeout(resolve, 1e4));
      }
    } else if (stage.stageType === "custom") {
      const config = stage.config || {};
      await addCampaignLog(
        campaign.id,
        stage.id,
        "ai_decision",
        `Custom stage: ${stage.name}`,
        config.customCommand || "No custom command specified"
      );
      results.customResults = { command: config.customCommand, status: "executed" };
    } else if (stage.stageType === "phishing") {
      const config = stage.config || {};
      await addCampaignLog(
        campaign.id,
        stage.id,
        "info",
        `Phishing stage: ${stage.name}`,
        `Template: ${config.phishingTemplate || "default"}, Targets: ${config.targets?.length || 0}`
      );
      results.phishingClicks = 0;
      results.credsHarvested = 0;
    }
    await db.update(redteamCampaignStages).set({
      status: "completed",
      completedAt: (/* @__PURE__ */ new Date()).toISOString(),
      results
    }).where(eq(redteamCampaignStages.id, stage.id));
    await addCampaignLog(
      campaign.id,
      stage.id,
      "stage_complete",
      `Stage ${stage.stageOrder}: ${stage.name} completed`,
      `Results: ${JSON.stringify(results)}`
    );
    await broadcastCampaignEvent("stage_completed", {
      campaignId: campaign.id,
      stageId: stage.id,
      stageName: stage.name,
      results
    });
    return results;
  } catch (err) {
    const errorMsg = err.message || "Unknown error";
    const isTimeout = errorMsg.includes("timed out");
    await db.update(redteamCampaignStages).set({
      status: isTimeout ? "timed_out" : "failed",
      completedAt: (/* @__PURE__ */ new Date()).toISOString(),
      errorMessage: errorMsg,
      results
    }).where(eq(redteamCampaignStages.id, stage.id));
    await addCampaignLog(
      campaign.id,
      stage.id,
      "stage_fail",
      `Stage ${stage.stageOrder}: ${stage.name} ${isTimeout ? "timed out" : "failed"}`,
      errorMsg
    );
    await broadcastCampaignEvent("stage_failed", {
      campaignId: campaign.id,
      stageId: stage.id,
      stageName: stage.name,
      error: errorMsg
    });
    throw err;
  }
}
async function executeCampaign(campaignId, operatorCtx) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const [campaign] = await db.select().from(redteamCampaigns).where(eq(redteamCampaigns.id, campaignId));
  if (!campaign) throw new Error(`Campaign ${campaignId} not found`);
  if (campaign.status === "running") throw new Error("Campaign is already running");
  const stages = await db.select().from(redteamCampaignStages).where(eq(redteamCampaignStages.campaignId, campaignId)).orderBy(asc(redteamCampaignStages.stageOrder));
  if (stages.length === 0) throw new Error("Campaign has no stages");
  const abortController = new AbortController();
  const runState = {
    campaignId,
    isRunning: true,
    isPaused: false,
    abortController,
    startedAt: Date.now()
  };
  campaignRunStates.set(campaignId, runState);
  persistCampaignAsync(runState);
  await db.update(redteamCampaigns).set({
    status: "running",
    startedAt: (/* @__PURE__ */ new Date()).toISOString(),
    currentStageOrder: stages[0].stageOrder
  }).where(eq(redteamCampaigns.id, campaignId));
  await addCampaignLog(
    campaignId,
    null,
    "campaign_start",
    `Campaign "${campaign.name}" started`,
    `${stages.length} stages, safety: ${campaign.safetyLevel}, max duration: ${campaign.maxDurationHours}h`
  );
  await broadcastCampaignEvent("started", { campaignId, name: campaign.name, stageCount: stages.length });
  const cumulativeContext = {
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
    creds_harvested: 0
  };
  const campaignTimeoutMs = (campaign.maxDurationHours || 72) * 60 * 60 * 1e3;
  const campaignStartTime = Date.now();
  let finalStatus = "completed";
  let currentStageIdx = 0;
  try {
    while (currentStageIdx < stages.length) {
      if (abortController.signal.aborted) {
        finalStatus = "aborted";
        break;
      }
      while (runState.isPaused) {
        await new Promise((resolve) => setTimeout(resolve, 2e3));
        if (abortController.signal.aborted) {
          finalStatus = "aborted";
          break;
        }
      }
      if (finalStatus === "aborted") break;
      if (Date.now() - campaignStartTime > campaignTimeoutMs) {
        await addCampaignLog(
          campaignId,
          null,
          "timeout",
          `Campaign timed out after ${campaign.maxDurationHours} hours`
        );
        finalStatus = "failed";
        break;
      }
      const stage = stages[currentStageIdx];
      runState.currentStageId = stage.id;
      await db.update(redteamCampaigns).set({ currentStageOrder: stage.stageOrder }).where(eq(redteamCampaigns.id, campaignId));
      const entryConditions = stage.entryConditions || [];
      if (entryConditions.length > 0) {
        const evalResult = evaluateConditions(entryConditions, cumulativeContext);
        await addCampaignLog(
          campaignId,
          stage.id,
          "condition_eval",
          `Entry conditions for stage ${stage.stageOrder}: ${evalResult.passed ? "PASSED" : "FAILED"}`,
          JSON.stringify(evalResult.results),
          { type: "entry", passed: evalResult.passed }
        );
        if (!evalResult.passed) {
          await db.update(redteamCampaignStages).set({ status: "skipped", completedAt: (/* @__PURE__ */ new Date()).toISOString() }).where(eq(redteamCampaignStages.id, stage.id));
          await addCampaignLog(
            campaignId,
            stage.id,
            "info",
            `Stage ${stage.stageOrder}: ${stage.name} skipped (entry conditions not met)`
          );
          currentStageIdx++;
          continue;
        }
      }
      try {
        const stageResults = await executeStage(stage, campaign, operatorCtx, abortController.signal);
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
        cumulativeContext[`stage_${stage.stageOrder}_vulns`] = stageResults.vulnsFound || 0;
        cumulativeContext[`stage_${stage.stageOrder}_exploits`] = stageResults.exploitsSucceeded || 0;
        cumulativeContext[`stage_${stage.stageOrder}_c2`] = stageResults.c2Agents || 0;
        const exitConditions = stage.exitConditions || [];
        if (exitConditions.length > 0) {
          const exitEval = evaluateConditions(exitConditions, {
            ...cumulativeContext,
            ...stageResults,
            vulns_found: stageResults.vulnsFound || 0,
            exploits_succeeded: stageResults.exploitsSucceeded || 0,
            c2_agents: stageResults.c2Agents || 0
          });
          await addCampaignLog(
            campaignId,
            stage.id,
            "condition_eval",
            `Exit conditions for stage ${stage.stageOrder}: ${exitEval.passed ? "PASSED" : "FAILED"}`,
            JSON.stringify(exitEval.results),
            { type: "exit", passed: exitEval.passed }
          );
          if (!exitEval.passed) {
            throw new Error(`Exit conditions not met for stage ${stage.stageOrder}`);
          }
        }
        const onSuccess = stage.onSuccess || "next";
        await addCampaignLog(
          campaignId,
          stage.id,
          "branch_decision",
          `Stage ${stage.stageOrder} success \u2192 action: ${onSuccess}`,
          stage.onSuccessTarget ? `Target stage: ${stage.onSuccessTarget}` : void 0
        );
        if (campaign.notifyOnStageComplete) {
          try {
            const { notifyOwner } = await import("./notification-4RFY3TAD.js");
            await notifyOwner({
              title: `Campaign Stage Complete: ${stage.name}`,
              content: `Stage ${stage.stageOrder}/${stages.length} of campaign "${campaign.name}" completed.
Vulns: ${stageResults.vulnsFound || 0}, Exploits: ${stageResults.exploitsSucceeded || 0}, C2 Agents: ${stageResults.c2Agents || 0}`
            });
          } catch {
          }
        }
        switch (onSuccess) {
          case "next":
            currentStageIdx++;
            break;
          case "skip_to":
            if (stage.onSuccessTarget) {
              const targetIdx = stages.findIndex((s) => s.stageOrder === stage.onSuccessTarget);
              if (targetIdx >= 0) {
                for (let i = currentStageIdx + 1; i < targetIdx; i++) {
                  await db.update(redteamCampaignStages).set({ status: "skipped" }).where(eq(redteamCampaignStages.id, stages[i].id));
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
            for (let i = currentStageIdx + 1; i < stages.length; i++) {
              await db.update(redteamCampaignStages).set({ status: "skipped" }).where(eq(redteamCampaignStages.id, stages[i].id));
            }
            currentStageIdx = stages.length;
            break;
          case "pause":
            runState.isPaused = true;
            await db.update(redteamCampaigns).set({ status: "paused", pausedAt: (/* @__PURE__ */ new Date()).toISOString() }).where(eq(redteamCampaigns.id, campaignId));
            await addCampaignLog(
              campaignId,
              stage.id,
              "campaign_pause",
              `Campaign paused after stage ${stage.stageOrder} (on_success=pause)`
            );
            currentStageIdx++;
            break;
        }
      } catch (stageErr) {
        const onFailure = stage.onFailure || "pause";
        cumulativeContext.stages_failed += 1;
        await addCampaignLog(
          campaignId,
          stage.id,
          "branch_decision",
          `Stage ${stage.stageOrder} failed \u2192 action: ${onFailure}`,
          stageErr.message
        );
        switch (onFailure) {
          case "retry": {
            const retryCount = (stage.retryCount || 0) + 1;
            const maxRetries = stage.maxRetries || 1;
            if (retryCount <= maxRetries) {
              await db.update(redteamCampaignStages).set({ retryCount, status: "pending" }).where(eq(redteamCampaignStages.id, stage.id));
              await addCampaignLog(
                campaignId,
                stage.id,
                "retry",
                `Retrying stage ${stage.stageOrder} (attempt ${retryCount}/${maxRetries})`
              );
            } else {
              await addCampaignLog(
                campaignId,
                stage.id,
                "error",
                `Stage ${stage.stageOrder} max retries (${maxRetries}) exceeded`
              );
              runState.isPaused = true;
              await db.update(redteamCampaigns).set({ status: "paused", pausedAt: (/* @__PURE__ */ new Date()).toISOString() }).where(eq(redteamCampaigns.id, campaignId));
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
            await db.update(redteamCampaigns).set({ status: "paused", pausedAt: (/* @__PURE__ */ new Date()).toISOString() }).where(eq(redteamCampaigns.id, campaignId));
            await addCampaignLog(
              campaignId,
              stage.id,
              "campaign_pause",
              `Campaign paused due to stage ${stage.stageOrder} failure`
            );
            currentStageIdx++;
            break;
          case "abort":
          default:
            finalStatus = "failed";
            await addCampaignLog(
              campaignId,
              stage.id,
              "campaign_abort",
              `Campaign aborted due to stage ${stage.stageOrder} failure`,
              stageErr.message
            );
            currentStageIdx = stages.length;
            break;
        }
      }
    }
    const summary = {
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
      durationMinutes: Math.round((Date.now() - campaignStartTime) / 6e4)
    };
    await db.update(redteamCampaigns).set({
      status: finalStatus,
      completedAt: (/* @__PURE__ */ new Date()).toISOString(),
      resultsSummary: summary
    }).where(eq(redteamCampaigns.id, campaignId));
    await addCampaignLog(
      campaignId,
      null,
      "campaign_complete",
      `Campaign "${campaign.name}" ${finalStatus}`,
      JSON.stringify(summary)
    );
    await broadcastCampaignEvent("completed", {
      campaignId,
      name: campaign.name,
      status: finalStatus,
      summary
    });
    if (campaign.notifyOnCampaignComplete) {
      try {
        const { notifyOwner } = await import("./notification-4RFY3TAD.js");
        await notifyOwner({
          title: `Campaign ${finalStatus === "completed" ? "Complete" : "Ended"}: ${campaign.name}`,
          content: [
            `Status: ${finalStatus.toUpperCase()}`,
            `Duration: ${summary.durationMinutes} minutes`,
            `Stages: ${summary.completedStages}/${summary.totalStages} completed, ${summary.failedStages} failed`,
            `Vulnerabilities: ${summary.totalVulns} (${summary.criticalVulns} critical)`,
            `Exploits: ${summary.successfulExploits}/${summary.totalExploits} succeeded`,
            `C2 Agents: ${summary.c2Agents}`
          ].join("\n")
        });
      } catch {
      }
    }
  } catch (err) {
    await db.update(redteamCampaigns).set({ status: "failed", completedAt: (/* @__PURE__ */ new Date()).toISOString() }).where(eq(redteamCampaigns.id, campaignId));
    await addCampaignLog(
      campaignId,
      null,
      "error",
      `Campaign crashed: ${err.message}`
    );
  } finally {
    runState.isRunning = false;
    campaignRunStates.delete(campaignId);
    removeCampaignRunState(campaignId).catch(() => {
    });
  }
}
function pauseCampaign(campaignId) {
  const state = campaignRunStates.get(campaignId);
  if (!state || !state.isRunning) return false;
  state.isPaused = true;
  persistCampaignAsync(state);
  return true;
}
function resumeCampaign(campaignId) {
  const state = campaignRunStates.get(campaignId);
  if (!state || !state.isPaused) return false;
  state.isPaused = false;
  persistCampaignAsync(state);
  return true;
}
function abortCampaign(campaignId) {
  const state = campaignRunStates.get(campaignId);
  if (!state || !state.isRunning) return false;
  state.abortController.abort();
  return true;
}
function getCampaignRunState(campaignId) {
  return campaignRunStates.get(campaignId) || null;
}
function getRunningCampaigns() {
  return [...campaignRunStates.entries()].filter(([, s]) => s.isRunning).map(([id]) => id);
}
async function generateCampaignPlan(targetDescription, objective, engagementType, safetyLevel) {
  const { invokeLLM } = await import("./llm-QLF4WTEY.js");
  const response = await invokeLLM({
    _caller: "campaign-orchestrator.generateCampaignPlan",
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
1. Progressive \u2014 each stage builds on the previous
2. Conditional \u2014 use entry/exit conditions to adapt
3. Resilient \u2014 handle failures gracefully
4. Efficient \u2014 skip unnecessary stages when possible
5. Safe \u2014 respect the safety level constraints

Return a JSON object with the campaign plan.`
      },
      {
        role: "user",
        content: `Design a red team campaign plan:
Target: ${targetDescription}
Objective: ${objective}
Type: ${engagementType}
Safety Level: ${safetyLevel}

Return a JSON object with: name, objective, stages (array), estimatedDurationHours, riskAssessment`
      }
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
                        value: { type: "string" }
                      },
                      required: ["field", "operator", "value"],
                      additionalProperties: false
                    }
                  },
                  exitConditions: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        field: { type: "string" },
                        operator: { type: "string" },
                        value: { type: "string" }
                      },
                      required: ["field", "operator", "value"],
                      additionalProperties: false
                    }
                  },
                  onSuccess: { type: "string" },
                  onFailure: { type: "string" },
                  timeoutMinutes: { type: "number" },
                  config: {
                    type: "object",
                    properties: {
                      targets: { type: "array", items: { type: "string" } },
                      tools: { type: "array", items: { type: "string" } },
                      scanProfile: { type: "string" }
                    },
                    required: [],
                    additionalProperties: true
                  }
                },
                required: ["name", "stageType", "description", "entryConditions", "exitConditions", "onSuccess", "onFailure", "timeoutMinutes", "config"],
                additionalProperties: false
              }
            },
            estimatedDurationHours: { type: "number" },
            riskAssessment: { type: "string" }
          },
          required: ["name", "objective", "stages", "estimatedDurationHours", "riskAssessment"],
          additionalProperties: false
        }
      }
    }
  });
  const content = response.choices?.[0]?.message?.content;
  if (!content) throw new Error("LLM returned empty response");
  try {
    return JSON.parse(content);
  } catch {
    throw new Error("Failed to parse AI campaign plan");
  }
}
export {
  abortCampaign,
  evaluateCondition,
  evaluateConditions,
  executeCampaign,
  generateCampaignPlan,
  getCampaignRunState,
  getRunningCampaigns,
  pauseCampaign,
  resumeCampaign
};
