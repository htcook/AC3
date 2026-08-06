/**
 * Operation State Persistence Layer
 * 
 * Write-through cache pattern for P0 active operation state:
 * - campaignRunStates (campaign-orchestrator.ts)
 * - activePlans (c2-orchestrator.ts)
 * 
 * Architecture:
 * 1. In-memory Map remains the hot read path (zero-latency reads)
 * 2. All mutations write-through to DB (async, non-blocking)
 * 3. On startup, DB state is loaded to restore in-memory cache
 * 4. Heartbeat mechanism detects stale/orphaned operations
 * 5. Graceful degradation: falls back to in-memory-only on DB failure
 * 
 * This survives Cloud Run instance restarts, cold starts, and scale-to-zero.
 */

import { getDb } from "../db";
import { campaignRunStates as campaignRunStatesTable, orchestrationPlans as orchestrationPlansTable } from "../../drizzle/schema";
import { eq, and } from "drizzle-orm";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface PersistedCampaignRunState {
  campaignId: number;
  isRunning: boolean;
  isPaused: boolean;
  currentStageId?: number;
  startedAt?: number;
  lastHeartbeat?: number;
  nodeId?: string;
}

export interface PersistedOrchestrationPlan {
  planId: string;
  engagementId?: number;
  campaignId?: number;
  name: string;
  description?: string;
  targetDomain?: string;
  scanMode?: string;
  status: 'pending' | 'running' | 'paused' | 'completed' | 'failed' | 'aborted';
  currentPhase?: string;
  stepsCompleted: number;
  stepsFailed: number;
  stepsSkipped: number;
  maxParallel: number;
  abortOnFailure: boolean;
  autoHandoff: boolean;
  phases?: any;
  steps?: any;
  frameworkPriority?: any;
  sharedContext?: any;
  log?: any[];
  startedAt?: string;
  completedAt?: string;
  lastHeartbeat?: number;
  nodeId?: string;
  tenantId?: number;
}

export interface StateRecoveryReport {
  campaignsRecovered: number;
  plansRecovered: number;
  orphanedCampaigns: number;
  orphanedPlans: number;
  errors: string[];
}

// ─── Node Identity ──────────────────────────────────────────────────────────

const NODE_ID = `node-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
const HEARTBEAT_INTERVAL_MS = 30_000; // 30s
const STALE_THRESHOLD_MS = 120_000;   // 2min — consider orphaned after this

// ─── Campaign Run State Persistence ─────────────────────────────────────────

export async function persistCampaignRunState(state: PersistedCampaignRunState): Promise<boolean> {
  try {
    const db = await getDb();
    const existing = await db.select()
      .from(campaignRunStatesTable)
      .where(eq(campaignRunStatesTable.campaignId, state.campaignId))
      .limit(1);

    if (existing.length > 0) {
      await db.update(campaignRunStatesTable)
        .set({
          isRunning: state.isRunning ? 1 : 0,
          isPaused: state.isPaused ? 1 : 0,
          currentStageId: state.currentStageId ?? null,
          startedAt: state.startedAt ?? null,
          lastHeartbeat: Date.now(),
          nodeId: NODE_ID,
        })
        .where(eq(campaignRunStatesTable.campaignId, state.campaignId));
    } else {
      await db.insert(campaignRunStatesTable).values({
        campaignId: state.campaignId,
        isRunning: state.isRunning ? 1 : 0,
        isPaused: state.isPaused ? 1 : 0,
        currentStageId: state.currentStageId ?? null,
        startedAt: state.startedAt ?? null,
        lastHeartbeat: Date.now(),
        nodeId: NODE_ID,
      });
    }
    return true;
  } catch (err) {
    console.error(`[OpStatePersistence] Failed to persist campaign run state for campaign ${state.campaignId}:`, err);
    return false;
  }
}

export async function removeCampaignRunState(campaignId: number): Promise<boolean> {
  try {
    const db = await getDb();
    await db.delete(campaignRunStatesTable)
      .where(eq(campaignRunStatesTable.campaignId, campaignId));
    return true;
  } catch (err) {
    console.error(`[OpStatePersistence] Failed to remove campaign run state for campaign ${campaignId}:`, err);
    return false;
  }
}

export async function loadCampaignRunStates(): Promise<PersistedCampaignRunState[]> {
  try {
    const db = await getDb();
    const rows = await db.select().from(campaignRunStatesTable);
    return rows.map(row => ({
      campaignId: row.campaignId,
      isRunning: row.isRunning === 1,
      isPaused: row.isPaused === 1,
      currentStageId: row.currentStageId ?? undefined,
      startedAt: row.startedAt ?? undefined,
      lastHeartbeat: row.lastHeartbeat ?? undefined,
      nodeId: row.nodeId ?? undefined,
    }));
  } catch (err) {
    console.error("[OpStatePersistence] Failed to load campaign run states:", err);
    return [];
  }
}

// ─── Orchestration Plan Persistence ─────────────────────────────────────────

export async function persistOrchestrationPlan(plan: PersistedOrchestrationPlan): Promise<boolean> {
  try {
    const db = await getDb();
    const existing = await db.select({ id: orchestrationPlansTable.id })
      .from(orchestrationPlansTable)
      .where(eq(orchestrationPlansTable.planId, plan.planId))
      .limit(1);

    const values = {
      planId: plan.planId,
      engagementId: plan.engagementId ?? null,
      campaignId: plan.campaignId ?? null,
      name: plan.name,
      description: plan.description ?? null,
      targetDomain: plan.targetDomain ?? null,
      scanMode: plan.scanMode ?? null,
      status: plan.status as any,
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
      opTenantId: plan.tenantId ?? null,
    };

    if (existing.length > 0) {
      await db.update(orchestrationPlansTable)
        .set(values)
        .where(eq(orchestrationPlansTable.planId, plan.planId));
    } else {
      await db.insert(orchestrationPlansTable).values(values as any);
    }
    return true;
  } catch (err) {
    console.error(`[OpStatePersistence] Failed to persist orchestration plan ${plan.planId}:`, err);
    return false;
  }
}

export async function updateOrchestrationPlanStatus(
  planId: string,
  updates: Partial<Pick<PersistedOrchestrationPlan, 'status' | 'currentPhase' | 'stepsCompleted' | 'stepsFailed' | 'stepsSkipped' | 'completedAt' | 'log' | 'sharedContext'>>
): Promise<boolean> {
  try {
    const db = await getDb();
    const setValues: Record<string, any> = { lastHeartbeat: Date.now() };
    if (updates.status !== undefined) setValues.status = updates.status;
    if (updates.currentPhase !== undefined) setValues.currentPhase = updates.currentPhase;
    if (updates.stepsCompleted !== undefined) setValues.stepsCompleted = updates.stepsCompleted;
    if (updates.stepsFailed !== undefined) setValues.stepsFailed = updates.stepsFailed;
    if (updates.stepsSkipped !== undefined) setValues.stepsSkipped = updates.stepsSkipped;
    if (updates.completedAt !== undefined) setValues.completedAt = updates.completedAt;
    if (updates.log !== undefined) setValues.log = updates.log;
    if (updates.sharedContext !== undefined) setValues.sharedContext = updates.sharedContext;

    await db.update(orchestrationPlansTable)
      .set(setValues)
      .where(eq(orchestrationPlansTable.planId, planId));
    return true;
  } catch (err) {
    console.error(`[OpStatePersistence] Failed to update orchestration plan ${planId}:`, err);
    return false;
  }
}

export async function loadOrchestrationPlans(): Promise<PersistedOrchestrationPlan[]> {
  try {
    const db = await getDb();
    const rows = await db.select().from(orchestrationPlansTable);
    return rows.map(row => ({
      planId: row.planId,
      engagementId: row.engagementId ?? undefined,
      campaignId: row.campaignId ?? undefined,
      name: row.name,
      description: row.description ?? undefined,
      targetDomain: row.targetDomain ?? undefined,
      scanMode: row.scanMode ?? undefined,
      status: row.status as PersistedOrchestrationPlan['status'],
      currentPhase: row.currentPhase ?? undefined,
      stepsCompleted: row.stepsCompleted,
      stepsFailed: row.stepsFailed,
      stepsSkipped: row.stepsSkipped,
      maxParallel: row.maxParallel,
      abortOnFailure: row.abortOnFailure === 1,
      autoHandoff: row.autoHandoff === 1,
      phases: row.phases ?? undefined,
      steps: row.steps ?? undefined,
      frameworkPriority: row.frameworkPriority ?? undefined,
      sharedContext: row.sharedContext ?? undefined,
      log: (row.log as any[]) ?? undefined,
      startedAt: row.startedAt ?? undefined,
      completedAt: row.completedAt ?? undefined,
      lastHeartbeat: row.lastHeartbeat ?? undefined,
      nodeId: row.nodeId ?? undefined,
      tenantId: row.opTenantId ?? undefined,
    }));
  } catch (err) {
    console.error("[OpStatePersistence] Failed to load orchestration plans:", err);
    return [];
  }
}

// ─── Orphan Detection & Recovery ────────────────────────────────────────────

export async function detectOrphanedOperations(): Promise<{
  orphanedCampaigns: PersistedCampaignRunState[];
  orphanedPlans: PersistedOrchestrationPlan[];
}> {
  const cutoff = Date.now() - STALE_THRESHOLD_MS;
  
  const campaigns = await loadCampaignRunStates();
  const orphanedCampaigns = campaigns.filter(c => 
    c.isRunning && c.lastHeartbeat && c.lastHeartbeat < cutoff
  );

  const plans = await loadOrchestrationPlans();
  const orphanedPlans = plans.filter(p => 
    p.status === 'running' && p.lastHeartbeat && p.lastHeartbeat < cutoff
  );

  return { orphanedCampaigns, orphanedPlans };
}

export async function markOrphanedAsFailed(): Promise<{ campaigns: number; plans: number }> {
  const { orphanedCampaigns, orphanedPlans } = await detectOrphanedOperations();
  
  let campaignCount = 0;
  for (const c of orphanedCampaigns) {
    const success = await persistCampaignRunState({ ...c, isRunning: false, isPaused: false });
    if (success) campaignCount++;
  }

  let planCount = 0;
  for (const p of orphanedPlans) {
    const success = await updateOrchestrationPlanStatus(p.planId, {
      status: 'failed',
      completedAt: new Date().toISOString(),
    });
    if (success) planCount++;
  }

  if (campaignCount > 0 || planCount > 0) {
    console.log(`[OpStatePersistence] Marked orphaned operations as failed: ${campaignCount} campaigns, ${planCount} plans`);
  }

  return { campaigns: campaignCount, plans: planCount };
}

// ─── Startup Recovery ───────────────────────────────────────────────────────

export async function recoverOperationState(): Promise<StateRecoveryReport> {
  const report: StateRecoveryReport = {
    campaignsRecovered: 0,
    plansRecovered: 0,
    orphanedCampaigns: 0,
    orphanedPlans: 0,
    errors: [],
  };

  try {
    // 1. Mark orphaned operations as failed
    const { campaigns: orphanedC, plans: orphanedP } = await markOrphanedAsFailed();
    report.orphanedCampaigns = orphanedC;
    report.orphanedPlans = orphanedP;

    // 2. Load surviving paused campaigns (can be resumed)
    const campaigns = await loadCampaignRunStates();
    report.campaignsRecovered = campaigns.filter(c => c.isPaused).length;

    // 3. Load surviving paused plans (can be resumed)
    const plans = await loadOrchestrationPlans();
    report.plansRecovered = plans.filter(p => p.status === 'paused').length;

    console.log(`[OpStatePersistence] Recovery complete: ${report.campaignsRecovered} campaigns resumable, ${report.plansRecovered} plans resumable, ${report.orphanedCampaigns} orphaned campaigns, ${report.orphanedPlans} orphaned plans`);
  } catch (err: any) {
    report.errors.push(err.message || String(err));
    console.error("[OpStatePersistence] Recovery failed:", err);
  }

  return report;
}

// ─── Heartbeat Manager ──────────────────────────────────────────────────────

let heartbeatInterval: ReturnType<typeof setInterval> | null = null;

export function startHeartbeat(
  getRunningCampaignIds: () => number[],
  getRunningPlanIds: () => string[]
): void {
  if (heartbeatInterval) return;

  heartbeatInterval = setInterval(async () => {
    try {
      const db = await getDb();
      const campaignIds = getRunningCampaignIds();
      for (const id of campaignIds) {
        await db.update(campaignRunStatesTable)
          .set({ lastHeartbeat: Date.now(), nodeId: NODE_ID })
          .where(eq(campaignRunStatesTable.campaignId, id));
      }

      const planIds = getRunningPlanIds();
      for (const id of planIds) {
        await db.update(orchestrationPlansTable)
          .set({ lastHeartbeat: Date.now(), nodeId: NODE_ID })
          .where(eq(orchestrationPlansTable.planId, id));
      }
    } catch (err) {
      console.error("[OpStatePersistence] Heartbeat update failed:", err);
    }
  }, HEARTBEAT_INTERVAL_MS);
}

export function stopHeartbeat(): void {
  if (heartbeatInterval) {
    clearInterval(heartbeatInterval);
    heartbeatInterval = null;
  }
}

// ─── Exports for integration ────────────────────────────────────────────────

export { NODE_ID, HEARTBEAT_INTERVAL_MS, STALE_THRESHOLD_MS };
