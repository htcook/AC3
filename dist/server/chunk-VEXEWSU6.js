import {
  getDb,
  init_db
} from "./chunk-MZ5XD5V3.js";
import {
  campaignRunStates,
  init_schema,
  orchestrationPlans
} from "./chunk-GM677ZS3.js";

// server/lib/operation-state-persistence.ts
init_db();
init_schema();
import { eq } from "drizzle-orm";
var NODE_ID = `node-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
var HEARTBEAT_INTERVAL_MS = 3e4;
var STALE_THRESHOLD_MS = 12e4;
async function persistCampaignRunState(state) {
  try {
    const db = await getDb();
    const existing = await db.select().from(campaignRunStates).where(eq(campaignRunStates.campaignId, state.campaignId)).limit(1);
    if (existing.length > 0) {
      await db.update(campaignRunStates).set({
        isRunning: state.isRunning ? 1 : 0,
        isPaused: state.isPaused ? 1 : 0,
        currentStageId: state.currentStageId ?? null,
        startedAt: state.startedAt ?? null,
        lastHeartbeat: Date.now(),
        nodeId: NODE_ID
      }).where(eq(campaignRunStates.campaignId, state.campaignId));
    } else {
      await db.insert(campaignRunStates).values({
        campaignId: state.campaignId,
        isRunning: state.isRunning ? 1 : 0,
        isPaused: state.isPaused ? 1 : 0,
        currentStageId: state.currentStageId ?? null,
        startedAt: state.startedAt ?? null,
        lastHeartbeat: Date.now(),
        nodeId: NODE_ID
      });
    }
    return true;
  } catch (err) {
    console.error(`[OpStatePersistence] Failed to persist campaign run state for campaign ${state.campaignId}:`, err);
    return false;
  }
}
async function removeCampaignRunState(campaignId) {
  try {
    const db = await getDb();
    await db.delete(campaignRunStates).where(eq(campaignRunStates.campaignId, campaignId));
    return true;
  } catch (err) {
    console.error(`[OpStatePersistence] Failed to remove campaign run state for campaign ${campaignId}:`, err);
    return false;
  }
}
async function loadCampaignRunStates() {
  try {
    const db = await getDb();
    const rows = await db.select().from(campaignRunStates);
    return rows.map((row) => ({
      campaignId: row.campaignId,
      isRunning: row.isRunning === 1,
      isPaused: row.isPaused === 1,
      currentStageId: row.currentStageId ?? void 0,
      startedAt: row.startedAt ?? void 0,
      lastHeartbeat: row.lastHeartbeat ?? void 0,
      nodeId: row.nodeId ?? void 0
    }));
  } catch (err) {
    console.error("[OpStatePersistence] Failed to load campaign run states:", err);
    return [];
  }
}
async function persistOrchestrationPlan(plan) {
  try {
    const db = await getDb();
    const existing = await db.select({ id: orchestrationPlans.id }).from(orchestrationPlans).where(eq(orchestrationPlans.planId, plan.planId)).limit(1);
    const values = {
      planId: plan.planId,
      engagementId: plan.engagementId ?? null,
      campaignId: plan.campaignId ?? null,
      name: plan.name,
      description: plan.description ?? null,
      targetDomain: plan.targetDomain ?? null,
      scanMode: plan.scanMode ?? null,
      status: plan.status,
      currentPhase: plan.currentPhase ?? null,
      stepsCompleted: plan.stepsCompleted,
      stepsFailed: plan.stepsFailed,
      stepsSkipped: plan.stepsSkipped,
      maxParallel: plan.maxParallel,
      abortOnFailure: plan.abortOnFailure ? 1 : 0,
      autoHandoff: plan.autoHandoff ? 1 : 0,
      phases: plan.phases ?? null,
      steps: plan.steps ?? null,
      frameworkPriority: plan.frameworkPriority ?? null,
      sharedContext: plan.sharedContext ?? null,
      log: plan.log ?? null,
      startedAt: plan.startedAt ?? null,
      completedAt: plan.completedAt ?? null,
      lastHeartbeat: Date.now(),
      nodeId: NODE_ID,
      opTenantId: plan.tenantId ?? null
    };
    if (existing.length > 0) {
      await db.update(orchestrationPlans).set(values).where(eq(orchestrationPlans.planId, plan.planId));
    } else {
      await db.insert(orchestrationPlans).values(values);
    }
    return true;
  } catch (err) {
    console.error(`[OpStatePersistence] Failed to persist orchestration plan ${plan.planId}:`, err);
    return false;
  }
}
async function updateOrchestrationPlanStatus(planId, updates) {
  try {
    const db = await getDb();
    const setValues = { lastHeartbeat: Date.now() };
    if (updates.status !== void 0) setValues.status = updates.status;
    if (updates.currentPhase !== void 0) setValues.currentPhase = updates.currentPhase;
    if (updates.stepsCompleted !== void 0) setValues.stepsCompleted = updates.stepsCompleted;
    if (updates.stepsFailed !== void 0) setValues.stepsFailed = updates.stepsFailed;
    if (updates.stepsSkipped !== void 0) setValues.stepsSkipped = updates.stepsSkipped;
    if (updates.completedAt !== void 0) setValues.completedAt = updates.completedAt;
    if (updates.log !== void 0) setValues.log = updates.log;
    if (updates.sharedContext !== void 0) setValues.sharedContext = updates.sharedContext;
    await db.update(orchestrationPlans).set(setValues).where(eq(orchestrationPlans.planId, planId));
    return true;
  } catch (err) {
    console.error(`[OpStatePersistence] Failed to update orchestration plan ${planId}:`, err);
    return false;
  }
}
async function loadOrchestrationPlans() {
  try {
    const db = await getDb();
    const rows = await db.select().from(orchestrationPlans);
    return rows.map((row) => ({
      planId: row.planId,
      engagementId: row.engagementId ?? void 0,
      campaignId: row.campaignId ?? void 0,
      name: row.name,
      description: row.description ?? void 0,
      targetDomain: row.targetDomain ?? void 0,
      scanMode: row.scanMode ?? void 0,
      status: row.status,
      currentPhase: row.currentPhase ?? void 0,
      stepsCompleted: row.stepsCompleted,
      stepsFailed: row.stepsFailed,
      stepsSkipped: row.stepsSkipped,
      maxParallel: row.maxParallel,
      abortOnFailure: row.abortOnFailure === 1,
      autoHandoff: row.autoHandoff === 1,
      phases: row.phases ?? void 0,
      steps: row.steps ?? void 0,
      frameworkPriority: row.frameworkPriority ?? void 0,
      sharedContext: row.sharedContext ?? void 0,
      log: row.log ?? void 0,
      startedAt: row.startedAt ?? void 0,
      completedAt: row.completedAt ?? void 0,
      lastHeartbeat: row.lastHeartbeat ?? void 0,
      nodeId: row.nodeId ?? void 0,
      tenantId: row.opTenantId ?? void 0
    }));
  } catch (err) {
    console.error("[OpStatePersistence] Failed to load orchestration plans:", err);
    return [];
  }
}
async function detectOrphanedOperations() {
  const cutoff = Date.now() - STALE_THRESHOLD_MS;
  const campaigns = await loadCampaignRunStates();
  const orphanedCampaigns = campaigns.filter(
    (c) => c.isRunning && c.lastHeartbeat && c.lastHeartbeat < cutoff
  );
  const plans = await loadOrchestrationPlans();
  const orphanedPlans = plans.filter(
    (p) => p.status === "running" && p.lastHeartbeat && p.lastHeartbeat < cutoff
  );
  return { orphanedCampaigns, orphanedPlans };
}
async function markOrphanedAsFailed() {
  const { orphanedCampaigns, orphanedPlans } = await detectOrphanedOperations();
  let campaignCount = 0;
  for (const c of orphanedCampaigns) {
    const success = await persistCampaignRunState({ ...c, isRunning: false, isPaused: false });
    if (success) campaignCount++;
  }
  let planCount = 0;
  for (const p of orphanedPlans) {
    const success = await updateOrchestrationPlanStatus(p.planId, {
      status: "failed",
      completedAt: (/* @__PURE__ */ new Date()).toISOString()
    });
    if (success) planCount++;
  }
  if (campaignCount > 0 || planCount > 0) {
    console.log(`[OpStatePersistence] Marked orphaned operations as failed: ${campaignCount} campaigns, ${planCount} plans`);
  }
  return { campaigns: campaignCount, plans: planCount };
}
async function recoverOperationState() {
  const report = {
    campaignsRecovered: 0,
    plansRecovered: 0,
    orphanedCampaigns: 0,
    orphanedPlans: 0,
    errors: []
  };
  try {
    const { campaigns: orphanedC, plans: orphanedP } = await markOrphanedAsFailed();
    report.orphanedCampaigns = orphanedC;
    report.orphanedPlans = orphanedP;
    const campaigns = await loadCampaignRunStates();
    report.campaignsRecovered = campaigns.filter((c) => c.isPaused).length;
    const plans = await loadOrchestrationPlans();
    report.plansRecovered = plans.filter((p) => p.status === "paused").length;
    console.log(`[OpStatePersistence] Recovery complete: ${report.campaignsRecovered} campaigns resumable, ${report.plansRecovered} plans resumable, ${report.orphanedCampaigns} orphaned campaigns, ${report.orphanedPlans} orphaned plans`);
  } catch (err) {
    report.errors.push(err.message || String(err));
    console.error("[OpStatePersistence] Recovery failed:", err);
  }
  return report;
}
var heartbeatInterval = null;
function startHeartbeat(getRunningCampaignIds, getRunningPlanIds) {
  if (heartbeatInterval) return;
  heartbeatInterval = setInterval(async () => {
    try {
      const db = await getDb();
      const campaignIds = getRunningCampaignIds();
      for (const id of campaignIds) {
        await db.update(campaignRunStates).set({ lastHeartbeat: Date.now(), nodeId: NODE_ID }).where(eq(campaignRunStates.campaignId, id));
      }
      const planIds = getRunningPlanIds();
      for (const id of planIds) {
        await db.update(orchestrationPlans).set({ lastHeartbeat: Date.now(), nodeId: NODE_ID }).where(eq(orchestrationPlans.planId, id));
      }
    } catch (err) {
      console.error("[OpStatePersistence] Heartbeat update failed:", err);
    }
  }, HEARTBEAT_INTERVAL_MS);
}
function stopHeartbeat() {
  if (heartbeatInterval) {
    clearInterval(heartbeatInterval);
    heartbeatInterval = null;
  }
}

export {
  NODE_ID,
  HEARTBEAT_INTERVAL_MS,
  STALE_THRESHOLD_MS,
  persistCampaignRunState,
  removeCampaignRunState,
  loadCampaignRunStates,
  persistOrchestrationPlan,
  updateOrchestrationPlanStatus,
  loadOrchestrationPlans,
  detectOrphanedOperations,
  markOrphanedAsFailed,
  recoverOperationState,
  startHeartbeat,
  stopHeartbeat
};
