/**
 * Phase 7 (Exploitation) Wiring + Phase 8 (Post-Exploit) Extraction Tests
 */
import { describe, it, expect } from 'vitest';

describe('Phase 7: Exploitation Sub-Modules', () => {
  describe('credential-harvester', () => {
    it('exports parseCredentials and CREDENTIAL_PATTERNS', async () => {
      const mod = await import('./lib/exploitation/credential-harvester');
      expect(mod.parseCredentials).toBeDefined();
      expect(typeof mod.parseCredentials).toBe('function');
      expect(mod.CREDENTIAL_PATTERNS).toBeDefined();
      expect(Array.isArray(mod.CREDENTIAL_PATTERNS)).toBe(true);
    });

    it('parseCredentials extracts key=value pairs from .env content', async () => {
      const { parseCredentials } = await import('./lib/exploitation/credential-harvester');
      const envContent = 'DB_PASSWORD=secret123\nAPI_KEY=abc-def-ghi\nEMPTY=\nNO_EQUALS';
      const result = parseCredentials(envContent);
      expect(result.length).toBeGreaterThanOrEqual(2);
      const dbCred = result.find((c: any) => c.key === 'DB_PASSWORD');
      expect(dbCred?.value).toBe('secret123');
    });
  });

  describe('exploit-planner', () => {
    it('exports buildExploitContextBlocks', async () => {
      const mod = await import('./lib/exploitation/exploit-planner');
      expect(mod.buildExploitContextBlocks).toBeDefined();
      expect(typeof mod.buildExploitContextBlocks).toBe('function');
    });

    it('buildExploitContextBlocks returns array of context blocks', async () => {
      const { buildExploitContextBlocks } = await import('./lib/exploitation/exploit-planner');
      const mockCtx = {
        state: {
          assets: [{ hostname: 'test.local', ip: '10.0.0.1', ports: [], vulns: [{ cve: 'CVE-2023-1234', severity: 'critical' }] }],
          engagementType: 'pentest',
          engagementId: 1,
        },
        addLog: () => {},
      };
      const blocks = await buildExploitContextBlocks(mockCtx as any);
      expect(Array.isArray(blocks)).toBe(true);
      expect(blocks.length).toBeGreaterThan(0);
    });
  });

  describe('target-selector', () => {
    it('exports scoreExploitAction and PRIORITY_WEIGHTS', async () => {
      const mod = await import('./lib/exploitation/target-selector');
      expect(mod.scoreExploitAction).toBeDefined();
      expect(mod.PRIORITY_WEIGHTS).toBeDefined();
    });

    it('PRIORITY_WEIGHTS has kevListed and cvssMultiplier', async () => {
      const { PRIORITY_WEIGHTS } = await import('./lib/exploitation/target-selector');
      expect(PRIORITY_WEIGHTS).toHaveProperty('kevListed');
      expect(PRIORITY_WEIGHTS).toHaveProperty('cvssMultiplier');
      expect(PRIORITY_WEIGHTS.kevListed).toBeGreaterThan(0);
    });

    it('scoreExploitAction returns higher score for KEV-listed vulns', async () => {
      const { scoreExploitAction } = await import('./lib/exploitation/target-selector');
      const state = {
        assets: [
          { hostname: 'kev-host', ip: '10.0.0.1', ports: [], vulns: [{ cve: 'CVE-2023-1111', severity: 'critical', kevListed: true, title: 'KEV vuln in apache' }] },
          { hostname: 'normal-host', ip: '10.0.0.2', ports: [], vulns: [{ cve: 'CVE-2023-2222', severity: 'medium', kevListed: false, title: 'Medium vuln in postgres' }] },
        ],
      };
      const kevAction = { params: { cve: 'CVE-2023-1111', module: 'exploit/apache', service: 'apache', target: '10.0.0.1' } };
      const normalAction = { params: { cve: 'CVE-2023-2222', module: 'exploit/postgres', service: 'postgres', target: '10.0.0.2' } };
      const kevResult = scoreExploitAction(kevAction as any, state as any);
      const normalResult = scoreExploitAction(normalAction as any, state as any);
      expect(kevResult.score).toBeGreaterThan(normalResult.score);
    });
  });

  describe('exploit-executor', () => {
    it('exports executeExploitLoop', async () => {
      const mod = await import('./lib/exploitation/exploit-executor');
      expect(mod.executeExploitLoop).toBeDefined();
      expect(typeof mod.executeExploitLoop).toBe('function');
    });
  });

  describe('evidence-collector', () => {
    it('exports collectExploitEvidence', async () => {
      const mod = await import('./lib/exploitation/evidence-collector');
      expect(mod.collectExploitEvidence).toBeDefined();
      expect(typeof mod.collectExploitEvidence).toBe('function');
    });
  });

  describe('Phase 7 wiring integrity', () => {
    it('exploitation orchestrator imports delegation modules', async () => {
      const fs = await import('fs');
      const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/server/lib/engagement-phase-exploitation.ts', 'utf8');
      expect(content).toContain("import('./exploitation/credential-harvester')");
      expect(content).toContain("import('./exploitation/evidence-collector')");
    });

    it('exploitation orchestrator reduced from 1441 to ~1220 lines', async () => {
      const fs = await import('fs');
      const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/server/lib/engagement-phase-exploitation.ts', 'utf8');
      const lineCount = content.split('\n').length;
      expect(lineCount).toBeLessThan(1300);
      expect(lineCount).toBeGreaterThan(1000);
    });
  });
});

describe('Phase 8: Post-Exploit Sub-Modules', () => {
  describe('c2-deployer', () => {
    it('exports deployC2Agents and getDeploymentConfig', async () => {
      const mod = await import('./lib/post-exploit/c2-deployer');
      expect(mod.deployC2Agents).toBeDefined();
      expect(mod.getDeploymentConfig).toBeDefined();
    });

    it('getDeploymentConfig returns expected structure', async () => {
      const { getDeploymentConfig } = await import('./lib/post-exploit/c2-deployer');
      const config = getDeploymentConfig();
      expect(config).toHaveProperty('agentType');
      expect(config).toHaveProperty('deploymentTimeout');
      expect(config.deploymentTimeout).toBeGreaterThan(0);
    });
  });

  describe('operation-launcher', () => {
    it('exports launchCalderaOperation and buildOperationName', async () => {
      const mod = await import('./lib/post-exploit/operation-launcher');
      expect(mod.launchCalderaOperation).toBeDefined();
      expect(mod.buildOperationName).toBeDefined();
    });

    it('buildOperationName generates correct format', async () => {
      const { buildOperationName } = await import('./lib/post-exploit/operation-launcher');
      const autoName = buildOperationName(42, 'auto');
      const builderName = buildOperationName(42, 'builder');
      expect(autoName).toContain('AC3-AutoLaunch');
      expect(autoName).toContain('Eng42');
      expect(builderName).toContain('AC3-AutoBuild');
    });

    it('buildLaunchConfig returns valid Caldera operation config', async () => {
      const { buildLaunchConfig } = await import('./lib/post-exploit/operation-launcher');
      const config = buildLaunchConfig('test-op', 'adversary-123');
      expect(config.name).toBe('test-op');
      expect(config.adversaryId).toBe('adversary-123');
      expect(config.autonomous).toBe(true);
      expect(config.jitter).toBeDefined();
      expect(config.planner).toBeDefined();
    });

    it('selectAdversaryProfile picks platform-matching profile', async () => {
      const { selectAdversaryProfile } = await import('./lib/post-exploit/operation-launcher');
      const state = { assets: [{ exploitAttempts: [{ success: true }], platform: 'windows' }] };
      const profiles = [
        { adversary_id: 'linux-apt', platform: 'linux', name: 'Linux APT' },
        { adversary_id: 'win-apt', platform: 'windows', name: 'Windows APT' },
      ];
      const selected = selectAdversaryProfile(state, profiles);
      expect(selected.adversary_id).toBe('win-apt');
    });
  });

  describe('c2-poller', () => {
    it('exports monitorC2Callbacks and helper functions', async () => {
      const mod = await import('./lib/post-exploit/c2-poller');
      expect(mod.monitorC2Callbacks).toBeDefined();
      expect(mod.isOperationComplete).toBeDefined();
      expect(mod.detectStall).toBeDefined();
      expect(mod.getPollingConfig).toBeDefined();
    });

    it('isOperationComplete correctly identifies terminal states', async () => {
      const { isOperationComplete } = await import('./lib/post-exploit/c2-poller');
      expect(isOperationComplete('finished')).toBe(true);
      expect(isOperationComplete('cleanup')).toBe(true);
      expect(isOperationComplete('paused')).toBe(true);
      expect(isOperationComplete('running')).toBe(false);
      expect(isOperationComplete('queued')).toBe(false);
    });

    it('detectStall returns true when no new links for N cycles', async () => {
      const { detectStall } = await import('./lib/post-exploit/c2-poller');
      expect(detectStall([0, 0, 0, 0, 0, 0], 6)).toBe(true);
      expect(detectStall([1, 0, 0, 0, 0, 0], 6)).toBe(false);
      expect(detectStall([0, 0, 0], 6)).toBe(false);
    });

    it('getPollingConfig returns valid configuration', async () => {
      const { getPollingConfig } = await import('./lib/post-exploit/c2-poller');
      const config = getPollingConfig();
      expect(config.intervalMs).toBe(15_000);
      expect(config.maxCycles).toBe(40);
      expect(config.stallThreshold).toBe(6);
    });

    it('buildPollUrl constructs correct URL', async () => {
      const { buildPollUrl } = await import('./lib/post-exploit/c2-poller');
      const url = buildPollUrl('http://caldera:8888', 'op-abc-123');
      expect(url).toBe('http://caldera:8888/api/v2/operations/op-abc-123');
    });

    it('extractNewLinks filters out previously seen links', async () => {
      const { extractNewLinks } = await import('./lib/post-exploit/c2-poller');
      const current = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];
      const seen = new Set(['a', 'b']);
      const newLinks = extractNewLinks(current, seen);
      expect(newLinks.length).toBe(1);
      expect(newLinks[0].id).toBe('c');
    });
  });

  describe('evidence-capture', () => {
    it('exports capturePostExploitEvidence and helpers', async () => {
      const mod = await import('./lib/post-exploit/evidence-capture');
      expect(mod.capturePostExploitEvidence).toBeDefined();
      expect(mod.shouldCaptureCalderaEvidence).toBeDefined();
      expect(mod.getCompromisedAssets).toBeDefined();
      expect(mod.buildLearningStats).toBeDefined();
    });

    it('shouldCaptureCalderaEvidence returns true for red_team with c2', async () => {
      const { shouldCaptureCalderaEvidence } = await import('./lib/post-exploit/evidence-capture');
      expect(shouldCaptureCalderaEvidence({ engagementType: 'red_team', assets: [{ c2Deployed: true }] })).toBe(true);
      expect(shouldCaptureCalderaEvidence({ engagementType: 'pentest', assets: [{ c2Deployed: true }] })).toBe(false);
      expect(shouldCaptureCalderaEvidence({ engagementType: 'red_team', assets: [{ c2Deployed: false }] })).toBe(false);
    });

    it('getCompromisedAssets filters correctly', async () => {
      const { getCompromisedAssets } = await import('./lib/post-exploit/evidence-capture');
      const state = { assets: [{ hostname: 'a', compromised: true }, { hostname: 'b', compromised: false }, { hostname: 'c', compromised: true }] };
      const result = getCompromisedAssets(state);
      expect(result.length).toBe(2);
    });

    it('buildLearningStats computes correct metrics', async () => {
      const { buildLearningStats } = await import('./lib/post-exploit/evidence-capture');
      const state = {
        assets: [
          { exploitAttempts: [{ success: true }, { success: false }], c2Deployed: true },
          { exploitAttempts: [{ success: true }, { success: true }], c2Deployed: false },
        ],
        evidenceChain: [1, 2, 3],
      };
      const stats = buildLearningStats(state);
      expect(stats.totalExploitAttempts).toBe(4);
      expect(stats.successfulExploits).toBe(3);
      expect(stats.successRate).toBeCloseTo(0.75);
      expect(stats.c2Deployments).toBe(1);
      expect(stats.evidenceItems).toBe(3);
    });

    it('isValidEvidenceType validates correctly', async () => {
      const { isValidEvidenceType } = await import('./lib/post-exploit/evidence-capture');
      expect(isValidEvidenceType('screenshot')).toBe(true);
      expect(isValidEvidenceType('caldera_output')).toBe(true);
      expect(isValidEvidenceType('invalid_type')).toBe(false);
    });
  });

  describe('Phase 8 wiring integrity', () => {
    it('post-exploit orchestrator imports delegation modules', async () => {
      const fs = await import('fs');
      const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/server/lib/engagement-phase-post-exploit.ts', 'utf8');
      expect(content).toContain("import('./post-exploit/c2-deployer')");
      expect(content).toContain("import('./post-exploit/operation-launcher')");
      expect(content).toContain("import('./post-exploit/c2-poller')");
      expect(content).toContain("import('./post-exploit/evidence-capture')");
    });

    it('post-exploit orchestrator reduced from 748 to ~120 lines', async () => {
      const fs = await import('fs');
      const content = fs.readFileSync('/home/ubuntu/caldera-dashboard/server/lib/engagement-phase-post-exploit.ts', 'utf8');
      const lineCount = content.split('\n').length;
      expect(lineCount).toBeLessThan(150);
      expect(lineCount).toBeGreaterThan(80);
    });
  });
});
