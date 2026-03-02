import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

describe('Ops State Persistence & Crash Recovery', () => {
  const orchestratorPath = path.resolve(__dirname, 'lib/engagement-orchestrator.ts');
  const dbPath = path.resolve(__dirname, 'db.ts');
  const opsCorePath = path.resolve(__dirname, 'routers/engagement-ops-core.ts');
  const indexPath = path.resolve(__dirname, '_core/index.ts');
  const schemaPath = path.resolve(__dirname, '../drizzle/schema.ts');

  it('engagement_ops_snapshots table exists in schema', () => {
    const schema = fs.readFileSync(schemaPath, 'utf-8');
    expect(schema).toContain('engagementOpsSnapshots');
    expect(schema).toContain('engagement_ops_snapshots');
    expect(schema).toContain('state_json');
    expect(schema).toContain('engagement_id');
  });

  it('db.ts exports saveOpsSnapshot, loadOpsSnapshot, and deleteOpsSnapshot', () => {
    const dbContent = fs.readFileSync(dbPath, 'utf-8');
    expect(dbContent).toContain('export async function saveOpsSnapshot');
    expect(dbContent).toContain('export async function loadOpsSnapshot');
    expect(dbContent).toContain('export async function deleteOpsSnapshot');
  });

  it('saveOpsSnapshot serializes Set to Array for skippedDomains', () => {
    const dbContent = fs.readFileSync(dbPath, 'utf-8');
    expect(dbContent).toContain('instanceof Set');
    expect(dbContent).toContain('Array.from(state.skippedDomains)');
  });

  it('loadOpsSnapshot restores Set from Array and handles crash recovery', () => {
    const dbContent = fs.readFileSync(dbPath, 'utf-8');
    // Should restore Set from array
    expect(dbContent).toContain('new Set(state.skippedDomains)');
    // Should mark running scans as crashed on recovery
    expect(dbContent).toContain('state.isRunning');
    expect(dbContent).toContain("state.phase = 'error'");
    expect(dbContent).toContain('Server restarted during scan');
  });

  it('orchestrator exports getOpsStateWithRecovery', () => {
    const orch = fs.readFileSync(orchestratorPath, 'utf-8');
    expect(orch).toContain('export async function getOpsStateWithRecovery');
  });

  it('getOpsStateWithRecovery tries DB recovery when in-memory state is missing', () => {
    const orch = fs.readFileSync(orchestratorPath, 'utf-8');
    expect(orch).toContain('loadOpsSnapshot');
    expect(orch).toContain('Recovered state for engagement');
  });

  it('orchestrator exports persistOpsStateNow', () => {
    const orch = fs.readFileSync(orchestratorPath, 'utf-8');
    expect(orch).toContain('export async function persistOpsStateNow');
  });

  it('initOpsState triggers debounced persistence', () => {
    const orch = fs.readFileSync(orchestratorPath, 'utf-8');
    // initOpsState should call persistOpsStateDebounced
    const initBlock = orch.slice(orch.indexOf('export function initOpsState'), orch.indexOf('// ─── State Persistence'));
    expect(initBlock).toContain('persistOpsStateDebounced');
  });

  it('addLog triggers debounced persistence', () => {
    const orch = fs.readFileSync(orchestratorPath, 'utf-8');
    const addLogBlock = orch.slice(orch.indexOf('function addLog'), orch.indexOf('// ─── Scan Result Persistence'));
    expect(addLogBlock).toContain('persistOpsStateDebounced');
  });

  it('broadcastOpsUpdate is wrapped in try/catch for crash protection', () => {
    const orch = fs.readFileSync(orchestratorPath, 'utf-8');
    const broadcastBlock = orch.slice(orch.indexOf('export function broadcastOpsUpdate'), orch.indexOf('function addLog'));
    expect(broadcastBlock).toContain('try {');
    expect(broadcastBlock).toContain('catch (e');
    expect(broadcastBlock).toContain('WebSocket broadcast failed');
  });

  it('getState uses getOpsStateWithRecovery for auto-recovery from DB', () => {
    const opsCore = fs.readFileSync(opsCorePath, 'utf-8');
    expect(opsCore).toContain('getOpsStateWithRecovery');
  });

  it('passive scan force-persists at critical transitions', () => {
    const opsCore = fs.readFileSync(opsCorePath, 'utf-8');
    // After assets populated (before pipeline)
    expect(opsCore).toContain('Force-persist state immediately so assets survive');
    // After each domain completes
    expect(opsCore).toContain('Force-persist after each domain so assets survive');
    // On completion
    expect(opsCore).toContain('Force-persist final state on completion');
    // On error
    expect(opsCore).toContain('Force-persist error state so assets are preserved');
  });

  it('resetOps persists state to DB after reset', () => {
    const opsCore = fs.readFileSync(opsCorePath, 'utf-8');
    const resetBlock = opsCore.slice(opsCore.indexOf('resetOps:'), opsCore.indexOf('resolveApproval:'));
    expect(resetBlock).toContain('persistOpsStateNow');
  });

  it('server has global crash protection handlers', () => {
    const index = fs.readFileSync(indexPath, 'utf-8');
    expect(index).toContain("process.on('unhandledRejection'");
    expect(index).toContain("process.on('uncaughtException'");
    expect(index).toContain('CRASH PROTECTION');
  });
});
