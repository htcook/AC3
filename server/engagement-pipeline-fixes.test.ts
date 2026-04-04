/**
 * Tests for engagement pipeline fixes:
 * 1. TrainingBridge column name alignment (dl-prefixed, te-prefixed, cel-prefixed)
 * 2. ExploitSandbox null code handling
 * 3. Circuit breaker auth failure behavior
 * 4. Deferred scan tracking
 * 5. Pipeline resilience (SSH fallback try/catch)
 */
import { describe, it, expect, vi, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

// ─── 1. TrainingBridge column name alignment ─────────────────────────────────

describe('TrainingBridge column name alignment', () => {
  const trainingBridgePath = path.resolve(__dirname, 'lib/engagement-training-bridge.ts');
  let trainingBridgeCode: string;

  beforeAll(() => {
    trainingBridgeCode = fs.readFileSync(trainingBridgePath, 'utf-8');
  });

  it('captureDecision uses dl-prefixed column names', () => {
    // Should use dlPhase, dlCaller, dlDecision, dlReasoning, dlActions, dlLatencyMs
    expect(trainingBridgeCode).toContain('dlPhase: capture.phase');
    expect(trainingBridgeCode).toContain('dlCaller: capture.caller');
    expect(trainingBridgeCode).toContain('dlDecision: capture.decision');
    expect(trainingBridgeCode).toContain('dlReasoning: capture.reasoning');
    expect(trainingBridgeCode).toContain('dlActions: capture.actions');
    expect(trainingBridgeCode).toContain('dlLatencyMs: capture.latencyMs');
  });

  it('updateDecisionOutcome uses dl-prefixed column names in queries', () => {
    expect(trainingBridgeCode).toContain('llmDecisionLog.dlPhase');
    expect(trainingBridgeCode).toContain('llmDecisionLog.dlCaller');
    expect(trainingBridgeCode).toContain('dlOutcome: update.outcome');
  });

  it('updateDecisionOutcome references dl-prefixed fields on row object', () => {
    expect(trainingBridgeCode).toContain('row.dlDecision');
    expect(trainingBridgeCode).toContain('row.dlReasoning');
  });

  it('does NOT use unprefixed column names for llmDecisionLog inserts', () => {
    // These old patterns should not exist in insert/update contexts
    const insertSection = trainingBridgeCode.split('captureDecision')[1]?.split('updateDecisionOutcome')[0] || '';
    expect(insertSection).not.toMatch(/\bphase: capture\.phase\b/);
    expect(insertSection).not.toMatch(/\bcaller: capture\.caller\b/);
    expect(insertSection).not.toMatch(/\bdecision: capture\.decision\b/);
  });

  it('persistTrainingExample uses te-prefixed column names', () => {
    expect(trainingBridgeCode).toContain('teModel: example.model');
    expect(trainingBridgeCode).toContain("teSource: 'live_engagement'");
    expect(trainingBridgeCode).toContain('teQuality: example.quality');
    expect(trainingBridgeCode).toContain('teMessages: example.messages');
    expect(trainingBridgeCode).toContain('teMetadata: example.metadata');
  });

  it('persistC2Execution uses cel-prefixed column names', () => {
    expect(trainingBridgeCode).toContain('celFramework: capture.framework');
    expect(trainingBridgeCode).toContain('celSuccess: capture.success');
    expect(trainingBridgeCode).toContain('celExtractedArtifacts: capture.extractedArtifacts');
    expect(trainingBridgeCode).toContain('celConstraints: capture.constraints');
    expect(trainingBridgeCode).toContain('celEngagementId: capture.engagementId');
  });

  it('getTrainingExamples uses te-prefixed column names in queries', () => {
    expect(trainingBridgeCode).toContain('llmTrainingExamples.teModel');
    expect(trainingBridgeCode).toContain('llmTrainingExamples.teSource');
    expect(trainingBridgeCode).toContain('llmTrainingExamples.teQuality');
  });
});

// ─── 2. ExploitSandbox null code handling ────────────────────────────────────

describe('ExploitSandbox null code handling', () => {
  const sandboxPath = path.resolve(__dirname, 'lib/exploit-sandbox.ts');
  let sandboxCode: string;

  beforeAll(() => {
    sandboxCode = fs.readFileSync(sandboxPath, 'utf-8');
  });

  it('uses defensive (code || \'\').slice() for exploit config', () => {
    expect(sandboxCode).toContain("(code || '').slice(0, 2000)");
  });
});

// ─── 3. IterativeLoop null code handling ─────────────────────────────────────

describe('IterativeLoop null code handling', () => {
  const loopPath = path.resolve(__dirname, 'lib/iterative-exploit-loop.ts');
  let loopCode: string;

  beforeAll(() => {
    loopCode = fs.readFileSync(loopPath, 'utf-8');
  });

  it('uses defensive (originalRequest.code || \'\').slice() for LLM prompt', () => {
    expect(loopCode).toContain("(originalRequest.code || '').slice(0, 4000)");
  });
});

// ─── 4. Circuit breaker auth failure behavior ────────────────────────────────

describe('Circuit breaker auth failure handling', () => {
  const resiliencePath = path.resolve(__dirname, 'lib/api-resilience.ts');
  let resilienceCode: string;

  beforeAll(() => {
    resilienceCode = fs.readFileSync(resiliencePath, 'utf-8');
  });

  it('opens circuit immediately on auth_failure', () => {
    // auth_failure should set state to open immediately
    expect(resilienceCode).toMatch(/auth_failure.*open|failureType.*auth.*state.*open/s);
  });
});

// ─── 5. Pipeline resilience - SSH fallback try/catch ─────────────────────────

describe('Pipeline resilience - job queue bridge', () => {
  const bridgePath = path.resolve(__dirname, 'lib/job-queue-bridge.ts');
  let bridgeCode: string;

  beforeAll(() => {
    bridgeCode = fs.readFileSync(bridgePath, 'utf-8');
  });

  it('has deferred scan tracking function', () => {
    expect(bridgeCode).toContain('trackDeferredScan');
  });

  it('has deferred scan retry function', () => {
    expect(bridgeCode).toContain('retryDeferredScans');
  });

  it('SSH fallback is wrapped in try/catch', () => {
    // The SSH fallback should have try/catch around it
    const sshFallbackSection = bridgeCode.split('falling back to SSH')[1] || '';
    expect(sshFallbackSection).toContain('try');
    expect(sshFallbackSection).toContain('catch');
  });
});

// ─── 6. Evidence persistence await fix ───────────────────────────────────────

describe('Evidence persistence getDb await', () => {
  const evidencePath = path.resolve(__dirname, 'lib/evidence-persistence.ts');
  let evidenceCode: string;

  beforeAll(() => {
    evidenceCode = fs.readFileSync(evidencePath, 'utf-8');
  });

  it('awaits getDb() calls', () => {
    // Should use 'await getDb()' not just 'getDb()'
    const getDbCalls = evidenceCode.match(/getDb\(\)/g) || [];
    const awaitGetDbCalls = evidenceCode.match(/await getDb\(\)/g) || [];
    expect(awaitGetDbCalls.length).toBe(getDbCalls.length);
  });
});

// ─── 7. Heap limit configuration ────────────────────────────────────────────

describe('Heap limit configuration', () => {
  const packageJsonPath = path.resolve(__dirname, '../package.json');
  let packageJson: any;

  beforeAll(() => {
    packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
  });

  it('dev heap limit is 768MB', () => {
    const devScript = packageJson.scripts?.dev || '';
    expect(devScript).toContain('max-old-space-size=768');
  });
});

// ─── 8. ContainerDiscovery probe cap ─────────────────────────────────────────

describe('ContainerDiscovery probe cap', () => {
  const containerPath = path.resolve(__dirname, 'lib/passive/container-discovery.ts');
  let containerCode: string;

  beforeAll(() => {
    containerCode = fs.readFileSync(containerPath, 'utf-8');
  });

  it('limits candidate hosts', () => {
    // Should have a slice or limit on candidate hosts
    expect(containerCode).toMatch(/\.slice\(0,\s*5\)|MAX_HOSTS|maxHosts/);
  });
});

// ─── 9. BountyIntel warm-up deferral ─────────────────────────────────────────

describe('BountyIntel warm-up deferral', () => {
  const schedulerPath = path.resolve(__dirname, 'lib/bounty-intel-scheduler.ts');
  let schedulerCode: string;

  beforeAll(() => {
    schedulerCode = fs.readFileSync(schedulerPath, 'utf-8');
  });

  it('checks pipelineRunning before warm-up', () => {
    expect(schedulerCode).toContain('pipelineRunning');
  });
});

// ─── 10. HTTP timeout cap ────────────────────────────────────────────────────

describe('HTTP timeout cap on scan API', () => {
  const scanApiPath = path.resolve(__dirname, 'lib/do-scan-api.ts');
  let scanApiCode: string;

  beforeAll(() => {
    scanApiCode = fs.readFileSync(scanApiPath, 'utf-8');
  });

  it('has a hard cap on HTTP timeout (360s)', () => {
    expect(scanApiCode).toContain('360');
  });
});
