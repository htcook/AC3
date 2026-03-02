import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

describe('Scan UX Improvements', () => {
  // ── Feature 1: Elapsed Timer ──
  describe('Elapsed Timer Support', () => {
    it('EngagementOpsState has currentDomain and currentDomainStartedAt fields', () => {
      const orchestratorPath = path.join(__dirname, 'lib/engagement-orchestrator.ts');
      const content = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(content).toContain('currentDomain?: string');
      expect(content).toContain('currentDomainStartedAt?: number');
    });

    it('initOpsState initializes skippedDomains as a Set', () => {
      const orchestratorPath = path.join(__dirname, 'lib/engagement-orchestrator.ts');
      const content = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(content).toContain('skippedDomains: new Set()');
    });

    it('passive scan sets currentDomain and currentDomainStartedAt before each domain', () => {
      const routerPath = path.join(__dirname, 'routers/engagement-ops-core.ts');
      const content = fs.readFileSync(routerPath, 'utf-8');
      expect(content).toContain('state!.currentDomain = domain');
      expect(content).toContain('state!.currentDomainStartedAt = Date.now()');
    });

    it('passive scan clears currentDomain in the finally block', () => {
      const routerPath = path.join(__dirname, 'routers/engagement-ops-core.ts');
      const content = fs.readFileSync(routerPath, 'utf-8');
      expect(content).toContain("state!.currentDomain = undefined");
      expect(content).toContain("state!.currentDomainStartedAt = undefined");
    });

    it('frontend OpsState interface includes currentDomain and currentDomainStartedAt', () => {
      const uiPath = path.join(__dirname, '../client/src/pages/EngagementOps.tsx');
      const content = fs.readFileSync(uiPath, 'utf-8');
      expect(content).toContain('currentDomain?: string');
      expect(content).toContain('currentDomainStartedAt?: number');
    });

    it('frontend has elapsed timer with formatElapsed helper', () => {
      const uiPath = path.join(__dirname, '../client/src/pages/EngagementOps.tsx');
      const content = fs.readFileSync(uiPath, 'utf-8');
      expect(content).toContain('formatElapsed');
      expect(content).toContain('setElapsedNow');
      // Timer ticks every second
      expect(content).toMatch(/setInterval.*1000/);
    });

    it('frontend displays total elapsed and per-domain elapsed', () => {
      const uiPath = path.join(__dirname, '../client/src/pages/EngagementOps.tsx');
      const content = fs.readFileSync(uiPath, 'utf-8');
      expect(content).toContain('Total: {formatElapsed(ops.startedAt)}');
      expect(content).toContain('{ops.currentDomain}: {formatElapsed(ops.currentDomainStartedAt)}');
    });
  });

  // ── Feature 2: Per-Connector Progress ──
  describe('Per-Connector Progress Logging', () => {
    it('PassiveReconConfig has onConnectorProgress callback', () => {
      const passivePath = path.join(__dirname, 'lib/passive/index.ts');
      const content = fs.readFileSync(passivePath, 'utf-8');
      expect(content).toContain('onConnectorProgress?:');
      expect(content).toContain("status: 'started' | 'completed' | 'failed' | 'skipped'");
    });

    it('runPassiveRecon fires onConnectorProgress on start', () => {
      const passivePath = path.join(__dirname, 'lib/passive/index.ts');
      const content = fs.readFileSync(passivePath, 'utf-8');
      expect(content).toContain("onConnectorProgress?.({ connector: serviceName, status: 'started' })");
    });

    it('runPassiveRecon fires onConnectorProgress on completion with observations and duration', () => {
      const passivePath = path.join(__dirname, 'lib/passive/index.ts');
      const content = fs.readFileSync(passivePath, 'utf-8');
      expect(content).toContain("status: 'completed', observations: result.observations.length, durationMs: connDuration");
    });

    it('runPassiveRecon fires onConnectorProgress on failure', () => {
      const passivePath = path.join(__dirname, 'lib/passive/index.ts');
      const content = fs.readFileSync(passivePath, 'utf-8');
      expect(content).toContain("status: 'failed', error: err.message");
    });

    it('runPassiveRecon fires onConnectorProgress on circuit breaker skip', () => {
      const passivePath = path.join(__dirname, 'lib/passive/index.ts');
      const content = fs.readFileSync(passivePath, 'utf-8');
      expect(content).toContain("status: 'skipped', error: cbCheck.reason");
    });

    it('runDomainIntelPipeline passes onConnectorProgress to runPassiveRecon', () => {
      const domainIntelPath = path.join(__dirname, 'domainIntel.ts');
      const content = fs.readFileSync(domainIntelPath, 'utf-8');
      expect(content).toContain('onConnectorProgress: options?.onConnectorProgress');
    });

    it('engagement-ops-core provides onConnectorProgress callback with status icons', () => {
      const routerPath = path.join(__dirname, 'routers/engagement-ops-core.ts');
      const content = fs.readFileSync(routerPath, 'utf-8');
      expect(content).toContain('onConnectorProgress: async (event)');
      // Should include status icons for different states
      expect(content).toContain("event.status === 'started'");
      expect(content).toContain("event.status === 'completed'");
    });
  });

  // ── Feature 3: Skip Domain ──
  describe('Skip Domain Button', () => {
    it('EngagementOpsState has skippedDomains field', () => {
      const orchestratorPath = path.join(__dirname, 'lib/engagement-orchestrator.ts');
      const content = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(content).toContain('skippedDomains?: Set<string>');
    });

    it('skipCurrentDomain mutation exists in engagement-ops-core', () => {
      const routerPath = path.join(__dirname, 'routers/engagement-ops-core.ts');
      const content = fs.readFileSync(routerPath, 'utf-8');
      expect(content).toContain('skipCurrentDomain: protectedProcedure');
    });

    it('skipCurrentDomain adds domain to skippedDomains set', () => {
      const routerPath = path.join(__dirname, 'routers/engagement-ops-core.ts');
      const content = fs.readFileSync(routerPath, 'utf-8');
      expect(content).toContain('state.skippedDomains.add(domain)');
    });

    it('skipCurrentDomain throws BAD_REQUEST when no domain is scanning', () => {
      const routerPath = path.join(__dirname, 'routers/engagement-ops-core.ts');
      const content = fs.readFileSync(routerPath, 'utf-8');
      expect(content).toContain("'No domain is currently being scanned'");
    });

    it('passive scan loop checks skippedDomains before starting a domain', () => {
      const routerPath = path.join(__dirname, 'routers/engagement-ops-core.ts');
      const content = fs.readFileSync(routerPath, 'utf-8');
      expect(content).toContain("state!.skippedDomains?.has(domain)");
    });

    it('progress callback throws when domain is skipped mid-pipeline', () => {
      const routerPath = path.join(__dirname, 'routers/engagement-ops-core.ts');
      const content = fs.readFileSync(routerPath, 'utf-8');
      expect(content).toContain("throw new Error(`Domain ${domain} skipped by operator`)");
    });

    it('catch block handles skip errors gracefully (not as error)', () => {
      const routerPath = path.join(__dirname, 'routers/engagement-ops-core.ts');
      const content = fs.readFileSync(routerPath, 'utf-8');
      expect(content).toContain("e.message?.includes('skipped by operator')");
      expect(content).toContain("Skipped:");
    });

    it('getState serializes skippedDomains Set to array for JSON', () => {
      const routerPath = path.join(__dirname, 'routers/engagement-ops-core.ts');
      const content = fs.readFileSync(routerPath, 'utf-8');
      expect(content).toContain('state.skippedDomains instanceof Set');
      expect(content).toContain('[...state.skippedDomains]');
    });

    it('frontend has skipDomainMut mutation', () => {
      const uiPath = path.join(__dirname, '../client/src/pages/EngagementOps.tsx');
      const content = fs.readFileSync(uiPath, 'utf-8');
      expect(content).toContain('trpc.engagementOps.skipCurrentDomain.useMutation');
    });

    it('frontend shows Skip Domain button when currentDomain is set', () => {
      const uiPath = path.join(__dirname, '../client/src/pages/EngagementOps.tsx');
      const content = fs.readFileSync(uiPath, 'utf-8');
      expect(content).toContain('Skip Domain');
      expect(content).toContain('ops.currentDomain &&');
    });
  });
});
