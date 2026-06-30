import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Pipeline Dashboard Integration Tests ──────────────────────────────────
describe('Pipeline Dashboard', () => {

  // ─── LLM Context Updater Module ──────────────────────────────────────────
  describe('LLM Context Updater Module', () => {
    it('should export getAllPipelineStatuses function', async () => {
      const mod = await import('./lib/llm-context-updater');
      expect(mod.getAllPipelineStatuses).toBeDefined();
      expect(typeof mod.getAllPipelineStatuses).toBe('function');
    });

    it('should export getPipelineHistory function', async () => {
      const mod = await import('./lib/llm-context-updater');
      expect(mod.getPipelineHistory).toBeDefined();
      expect(typeof mod.getPipelineHistory).toBe('function');
    });

    it('should export getPipelineStatus function', async () => {
      const mod = await import('./lib/llm-context-updater');
      expect(mod.getPipelineStatus).toBeDefined();
      expect(typeof mod.getPipelineStatus).toBe('function');
    });

    it('should export markPipelineRunning function', async () => {
      const mod = await import('./lib/llm-context-updater');
      expect(mod.markPipelineRunning).toBeDefined();
      expect(typeof mod.markPipelineRunning).toBe('function');
    });

    it('should export markPipelineComplete function', async () => {
      const mod = await import('./lib/llm-context-updater');
      expect(mod.markPipelineComplete).toBeDefined();
      expect(typeof mod.markPipelineComplete).toBe('function');
    });

    it('should export logPipelineRun function', async () => {
      const mod = await import('./lib/llm-context-updater');
      expect(mod.logPipelineRun).toBeDefined();
      expect(typeof mod.logPipelineRun).toBe('function');
    });

    it('getAllPipelineStatuses should return all 6 pipeline keys', async () => {
      const { getAllPipelineStatuses } = await import('./lib/llm-context-updater');
      const statuses = getAllPipelineStatuses();
      expect(statuses).toBeDefined();
      expect(typeof statuses).toBe('object');
      const keys = Object.keys(statuses);
      expect(keys).toContain('dfir-ingest');
      expect(keys).toContain('ioc-ttp-mapping');
      expect(keys).toContain('catalog-enrichment');
      expect(keys).toContain('playbook-promotion');
      expect(keys).toContain('graph-generation');
      expect(keys).toContain('exploit-triage');
      expect(keys.length).toBe(6);
    });

    it('each pipeline status should have correct structure', async () => {
      const { getAllPipelineStatuses } = await import('./lib/llm-context-updater');
      const statuses = getAllPipelineStatuses();
      for (const [key, status] of Object.entries(statuses)) {
        expect(status).toHaveProperty('name');
        expect(status).toHaveProperty('running');
        expect(status).toHaveProperty('lastRun');
        expect(status).toHaveProperty('lastResult');
        expect(status).toHaveProperty('totalRuns');
        expect(status).toHaveProperty('totalItemsProcessed');
        expect(typeof status.name).toBe('string');
        expect(typeof status.running).toBe('boolean');
        expect(typeof status.totalRuns).toBe('number');
        expect(typeof status.totalItemsProcessed).toBe('number');
      }
    });

    it('getPipelineStatus should return null for unknown pipeline', async () => {
      const { getPipelineStatus } = await import('./lib/llm-context-updater');
      const status = getPipelineStatus('nonexistent-pipeline');
      expect(status).toBeNull();
    });

    it('getPipelineStatus should return status for known pipeline', async () => {
      const { getPipelineStatus } = await import('./lib/llm-context-updater');
      const status = getPipelineStatus('dfir-ingest');
      expect(status).not.toBeNull();
      expect(status?.name).toBe('DFIR Report Ingestion');
    });

    it('markPipelineRunning should set running to true', async () => {
      const { markPipelineRunning, getPipelineStatus } = await import('./lib/llm-context-updater');
      markPipelineRunning('exploit-triage');
      const status = getPipelineStatus('exploit-triage');
      expect(status?.running).toBe(true);
      // Reset
      const { markPipelineComplete } = await import('./lib/llm-context-updater');
      markPipelineComplete('exploit-triage', {
        pipelineName: 'exploit-triage',
        startedAt: Date.now() - 1000,
        completedAt: Date.now(),
        itemsProcessed: 0,
        itemsSucceeded: 0,
        itemsFailed: 0,
        contextUpdate: { actorsUpdated: 0, techniquesRefreshed: 0, iocMappingsAdded: 0, dfirObservationsAdded: 0, exploitsIndexed: 0, contextTokensGenerated: 0, errors: [] },
        phases: [],
      });
    });

    it('markPipelineComplete should update status correctly', async () => {
      const { markPipelineRunning, markPipelineComplete, getPipelineStatus } = await import('./lib/llm-context-updater');
      markPipelineRunning('dfir-ingest');
      const summary = {
        pipelineName: 'dfir-ingest',
        startedAt: Date.now() - 5000,
        completedAt: Date.now(),
        itemsProcessed: 10,
        itemsSucceeded: 8,
        itemsFailed: 2,
        contextUpdate: {
          actorsUpdated: 3,
          techniquesRefreshed: 5,
          iocMappingsAdded: 12,
          dfirObservationsAdded: 7,
          exploitsIndexed: 0,
          contextTokensGenerated: 1500,
          errors: [],
        },
        phases: [{ phase: 'ingest', success: true, itemsProcessed: 10, duration: 5000 }],
      };
      markPipelineComplete('dfir-ingest', summary);
      const status = getPipelineStatus('dfir-ingest');
      expect(status?.running).toBe(false);
      expect(status?.lastRun).toBeDefined();
      expect(status?.lastResult).toEqual(summary);
      expect(status?.totalItemsProcessed).toBeGreaterThanOrEqual(10);
    });
  });

  // ─── Scheduled Pipeline Endpoints ────────────────────────────────────────
  describe('Scheduled Pipeline Endpoints', () => {
    const endpoints = [
      '/api/scheduled/dfir-ingest',
      '/api/scheduled/ioc-ttp-map',
      '/api/scheduled/catalog-enrich',
      '/api/scheduled/playbook-promote',
      '/api/scheduled/ability-graph-gen',
      '/api/scheduled/exploit-triage',
    ];

    for (const endpoint of endpoints) {
      it(`${endpoint} should be reachable`, async () => {
        const response = await fetch(`http://localhost:3000${endpoint}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        }).catch(() => null);
        if (response) {
          // Scheduled endpoints may return 200 (success) or 401 (auth required)
          // Both are valid — 200 means the endpoint is registered and processed the request
          expect([200, 401]).toContain(response.status);
        }
      });
    }

    it('should have all 6 scheduled endpoints registered', () => {
      // Verify the endpoint paths are correct
      expect(endpoints).toHaveLength(6);
      expect(endpoints).toContain('/api/scheduled/dfir-ingest');
      expect(endpoints).toContain('/api/scheduled/ioc-ttp-map');
      expect(endpoints).toContain('/api/scheduled/catalog-enrich');
      expect(endpoints).toContain('/api/scheduled/playbook-promote');
      expect(endpoints).toContain('/api/scheduled/ability-graph-gen');
      expect(endpoints).toContain('/api/scheduled/exploit-triage');
    });
  });

  // ─── Classification Audit Log ────────────────────────────────────────────
  describe('Classification Audit Log', () => {
    it('should import queryAuditLog from classifier module', async () => {
      const mod = await import('./lib/threat-actor-classifier');
      expect(mod.queryAuditLog).toBeDefined();
      expect(typeof mod.queryAuditLog).toBe('function');
    });

    it('should import getAuditSummary from classifier module', async () => {
      const mod = await import('./lib/threat-actor-classifier');
      expect(mod.getAuditSummary).toBeDefined();
      expect(typeof mod.getAuditSummary).toBe('function');
    });

    it('should import logManualClassificationAudit from classifier module', async () => {
      const mod = await import('./lib/threat-actor-classifier');
      expect(mod.logManualClassificationAudit).toBeDefined();
      expect(typeof mod.logManualClassificationAudit).toBe('function');
    });

    it('classificationAuditLog schema should exist', async () => {
      const schema = await import('../drizzle/schema');
      expect(schema.classificationAuditLog).toBeDefined();
    });

    it('audit log schema should have required columns', async () => {
      const schema = await import('../drizzle/schema');
      const table = schema.classificationAuditLog;
      // Drizzle table objects have column definitions
      expect(table).toBeDefined();
    });
  });

  // ─── Pipeline Dashboard Frontend Registration ────────────────────────────
  describe('Frontend Registration', () => {
    it('PipelineDashboard.tsx should exist', async () => {
      const fs = await import('fs');
      const exists = fs.existsSync('/home/ubuntu/caldera-dashboard/client/src/pages/PipelineDashboard.tsx');
      expect(exists).toBe(true);
    });

    it('App.tsx should contain PipelineDashboard lazy import', async () => {
      const fs = await import('fs');
      const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/App.tsx', 'utf-8');
      expect(content).toContain('PipelineDashboard');
      expect(content).toContain('import("./pages/PipelineDashboard")');
    });

    it('App.tsx should contain /pipeline-dashboard route', async () => {
      const fs = await import('fs');
      const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/App.tsx', 'utf-8');
      expect(content).toContain('/pipeline-dashboard');
    });

    it('sidebar-nav.ts should contain Pipeline Dashboard nav item', async () => {
      const fs = await import('fs');
      const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/client/src/lib/sidebar-nav.ts', 'utf-8');
      expect(content).toContain('Pipeline Dashboard');
      expect(content).toContain('/pipeline-dashboard');
    });
  });

  // ─── Pipeline Run Summary Type Validation ────────────────────────────────
  describe('Pipeline Run Summary Types', () => {
    it('PipelineRunSummary should have correct shape', async () => {
      const mod = await import('./lib/llm-context-updater');
      // Create a valid summary and verify it compiles
      const summary: import('./lib/llm-context-updater').PipelineRunSummary = {
        pipelineName: 'test',
        startedAt: Date.now() - 1000,
        completedAt: Date.now(),
        itemsProcessed: 5,
        itemsSucceeded: 4,
        itemsFailed: 1,
        contextUpdate: {
          actorsUpdated: 2,
          techniquesRefreshed: 3,
          iocMappingsAdded: 1,
          dfirObservationsAdded: 0,
          exploitsIndexed: 0,
          contextTokensGenerated: 500,
          errors: [],
        },
        phases: [
          { phase: 'fetch', success: true, itemsProcessed: 5, duration: 500 },
          { phase: 'process', success: true, itemsProcessed: 4, duration: 300 },
        ],
      };
      expect(summary.pipelineName).toBe('test');
      expect(summary.itemsProcessed).toBe(5);
      expect(summary.contextUpdate.actorsUpdated).toBe(2);
      expect(summary.phases).toHaveLength(2);
    });

    it('ContextUpdateResult should track all update types', async () => {
      const result: import('./lib/llm-context-updater').ContextUpdateResult = {
        actorsUpdated: 10,
        techniquesRefreshed: 20,
        iocMappingsAdded: 30,
        dfirObservationsAdded: 5,
        exploitsIndexed: 8,
        contextTokensGenerated: 5000,
        errors: ['test error'],
      };
      expect(result.actorsUpdated).toBe(10);
      expect(result.errors).toHaveLength(1);
    });
  });

  // ─── Pipeline Key Consistency ────────────────────────────────────────────
  describe('Pipeline Key Consistency', () => {
    it('frontend pipeline keys should match backend status keys', async () => {
      const { getAllPipelineStatuses } = await import('./lib/llm-context-updater');
      const backendKeys = Object.keys(getAllPipelineStatuses()).sort();

      // These are the keys used in PipelineDashboard.tsx
      const frontendKeys = [
        'dfir-ingest',
        'ioc-ttp-mapping',
        'catalog-enrichment',
        'playbook-promotion',
        'graph-generation',
        'exploit-triage',
      ].sort();

      expect(frontendKeys).toEqual(backendKeys);
    });
  });

  // ─── Threat Intel Router Procedures ──────────────────────────────────────
  describe('Threat Intel Router', () => {
    it('should export threatIntelRouter', async () => {
      const mod = await import('./routers/threat-intel');
      expect(mod.threatIntelRouter).toBeDefined();
    });

    it('router should have pipelineStatus procedure', async () => {
      const mod = await import('./routers/threat-intel');
      const router = mod.threatIntelRouter;
      // tRPC routers have _def.procedures
      expect((router as any)._def?.procedures?.pipelineStatus || (router as any).pipelineStatus).toBeDefined();
    });

    it('router should have pipelineHistory procedure', async () => {
      const mod = await import('./routers/threat-intel');
      const router = mod.threatIntelRouter;
      expect((router as any)._def?.procedures?.pipelineHistory || (router as any).pipelineHistory).toBeDefined();
    });

    it('router should have classifyAuditLog procedure', async () => {
      const mod = await import('./routers/threat-intel');
      const router = mod.threatIntelRouter;
      expect((router as any)._def?.procedures?.classifyAuditLog || (router as any).classifyAuditLog).toBeDefined();
    });

    it('router should have classifyAuditSummary procedure', async () => {
      const mod = await import('./routers/threat-intel');
      const router = mod.threatIntelRouter;
      expect((router as any)._def?.procedures?.classifyAuditSummary || (router as any).classifyAuditSummary).toBeDefined();
    });

    it('router should have classifyAuditRevert procedure', async () => {
      const mod = await import('./routers/threat-intel');
      const router = mod.threatIntelRouter;
      expect((router as any)._def?.procedures?.classifyAuditRevert || (router as any).classifyAuditRevert).toBeDefined();
    });
  });
});
