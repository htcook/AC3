/**
 * Phase 5 (Active Enumeration) Sub-Module Extraction Tests
 *
 * Tests the extracted sub-modules under server/lib/active-enumeration/
 * following the same pattern as phase78-wiring.test.ts
 */
import { describe, it, expect } from 'vitest';

describe('Phase 5: Active Enumeration Sub-Modules', () => {
  describe('enumeration-context', () => {
    it('exports buildEnumerationHelpers factory', async () => {
      const mod = await import('./lib/active-enumeration/enumeration-context');
      expect(mod.buildEnumerationHelpers).toBeDefined();
      expect(typeof mod.buildEnumerationHelpers).toBe('function');
    });

    it('exports EngagementOpsState type and helper functions', async () => {
      const mod = await import('./lib/active-enumeration/enumeration-context');
      expect(mod.addLog).toBeDefined();
      expect(mod.broadcastOpsUpdate).toBeDefined();
      expect(mod.broadcastReconFinding).toBeDefined();
      expect(mod.getEffectiveTarget).toBeDefined();
      expect(mod.getEngagementAbortSignal).toBeDefined();
      expect(mod.pushVulnDeduped).toBeDefined();
      expect(mod.parseToolOutput).toBeDefined();
      expect(mod.persistScanResult).toBeDefined();
      expect(mod.persistOpsStateDebounced).toBeDefined();
      expect(mod.KNOWN_INFRA_IPS).toBeDefined();
    });

    it('exports scan profile helpers', async () => {
      const mod = await import('./lib/active-enumeration/enumeration-context');
      expect(mod.getScanProfile).toBeDefined();
      expect(mod.buildGobusterCommand).toBeDefined();
      expect(mod.enrichPortServices).toBeDefined();
    });

    it('exports job queue bridge functions', async () => {
      const mod = await import('./lib/active-enumeration/enumeration-context');
      expect(mod.executeToolViaQueue).toBeDefined();
      expect(mod.executeRawCommandViaQueue).toBeDefined();
    });
  });

  describe('dns-resolver', () => {
    it('exports resolveAssetDns function', async () => {
      const mod = await import('./lib/active-enumeration/dns-resolver');
      expect(mod.resolveAssetDns).toBeDefined();
      expect(typeof mod.resolveAssetDns).toBe('function');
    });
  });

  describe('port-discovery', () => {
    it('exports executePortDiscovery function', async () => {
      const mod = await import('./lib/active-enumeration/port-discovery');
      expect(mod.executePortDiscovery).toBeDefined();
      expect(typeof mod.executePortDiscovery).toBe('function');
    });
  });

  describe('service-fingerprinter-runner', () => {
    it('exports runServiceFingerprinting function', async () => {
      const mod = await import('./lib/active-enumeration/service-fingerprinter-runner');
      expect(mod.runServiceFingerprinting).toBeDefined();
      expect(typeof mod.runServiceFingerprinting).toBe('function');
    });
  });

  describe('httpx-prober', () => {
    it('exports runHttpxProbing function', async () => {
      const mod = await import('./lib/active-enumeration/httpx-prober');
      expect(mod.runHttpxProbing).toBeDefined();
      expect(typeof mod.runHttpxProbing).toBe('function');
    });
  });

  describe('cloud-scanner-runner', () => {
    it('exports runCloudAssetDetection function', async () => {
      const mod = await import('./lib/active-enumeration/cloud-scanner-runner');
      expect(mod.runCloudAssetDetection).toBeDefined();
      expect(typeof mod.runCloudAssetDetection).toBe('function');
    });
  });

  describe('target-profiler', () => {
    it('exports runTargetProfiling function', async () => {
      const mod = await import('./lib/active-enumeration/target-profiler');
      expect(mod.runTargetProfiling).toBeDefined();
      expect(typeof mod.runTargetProfiling).toBe('function');
    });
  });

  describe('targeted-tool-runner', () => {
    it('exports executeTargetedToolDeployment function', async () => {
      const mod = await import('./lib/active-enumeration/targeted-tool-runner');
      expect(mod.executeTargetedToolDeployment).toBeDefined();
      expect(typeof mod.executeTargetedToolDeployment).toBe('function');
    });
  });

  describe('barrel index', () => {
    it('re-exports all sub-modules from index.ts', async () => {
      const mod = await import('./lib/active-enumeration/index');
      expect(mod.resolveAssetDns).toBeDefined();
      expect(mod.executePortDiscovery).toBeDefined();
      expect(mod.runServiceFingerprinting).toBeDefined();
      expect(mod.runHttpxProbing).toBeDefined();
      expect(mod.runCloudAssetDetection).toBeDefined();
      expect(mod.runTargetProfiling).toBeDefined();
      expect(mod.executeTargetedToolDeployment).toBeDefined();
      expect(mod.buildEnumerationHelpers).toBeDefined();
    });
  });

  describe('enumeration-context helpers factory', () => {
    it('buildEnumerationHelpers returns object with all required methods', async () => {
      const { buildEnumerationHelpers } = await import('./lib/active-enumeration/enumeration-context');
      // Create a minimal mock state
      const mockState = {
        engagementId: 999,
        roeScopeGuard: { authorizedDomains: ['test.com'], authorizedIps: ['10.0.0.1'] },
        logs: [],
        assets: [],
        stats: { hostsScanned: 0, portsFound: 0, vulnsFound: 0 },
      } as any;

      const helpers = buildEnumerationHelpers(mockState);

      // Check all expected methods exist
      expect(typeof helpers.addLog).toBe('function');
      expect(typeof helpers.broadcastOpsUpdate).toBe('function');
      expect(typeof helpers.broadcastReconFinding).toBe('function');
      expect(typeof helpers.getEffectiveTarget).toBe('function');
      expect(typeof helpers.isInRoeScope).toBe('function');
      expect(typeof helpers.fmtTarget).toBe('function');
      expect(typeof helpers.parseToolOutput).toBe('function');
      expect(typeof helpers.pushVulnDeduped).toBe('function');
      expect(typeof helpers.enrichPortServices).toBe('function');
      expect(typeof helpers.getScanProfile).toBe('function');
      expect(typeof helpers.buildGobusterCommand).toBe('function');
      expect(typeof helpers.executeTool).toBe('function');
      expect(typeof helpers.executeRawCommand).toBe('function');
      expect(typeof helpers.persistScanResult).toBe('function');
      expect(typeof helpers.persistOpsStateDebounced).toBe('function');
      expect(helpers.KNOWN_INFRA_IPS).toBeDefined();
      expect(typeof helpers.genId).toBe('function');
    });

    it('genId produces unique 8-char strings', async () => {
      const { buildEnumerationHelpers } = await import('./lib/active-enumeration/enumeration-context');
      const mockState = { engagementId: 1, roeScopeGuard: { authorizedDomains: [], authorizedIps: [] }, logs: [], assets: [], stats: {} } as any;
      const helpers = buildEnumerationHelpers(mockState);
      const id1 = helpers.genId();
      const id2 = helpers.genId();
      expect(id1).not.toBe(id2);
      expect(id1.length).toBe(8);
    });

    it('isInRoeScope correctly validates authorized domains', async () => {
      const { buildEnumerationHelpers } = await import('./lib/active-enumeration/enumeration-context');
      const mockState = {
        engagementId: 1,
        roeScopeGuard: { authorizedDomains: ['example.com', 'sub.example.com'], authorizedIps: ['192.168.1.1'] },
        logs: [],
        assets: [],
        stats: {},
      } as any;
      const helpers = buildEnumerationHelpers(mockState);
      expect(helpers.isInRoeScope('example.com')).toBe(true);
      expect(helpers.isInRoeScope('sub.example.com')).toBe(true);
      expect(helpers.isInRoeScope('evil.com')).toBe(false);
    });

    it('fmtTarget formats asset display string', async () => {
      const { buildEnumerationHelpers } = await import('./lib/active-enumeration/enumeration-context');
      const mockState = { engagementId: 1, roeScopeGuard: { authorizedDomains: [], authorizedIps: [] }, logs: [], assets: [], stats: {} } as any;
      const helpers = buildEnumerationHelpers(mockState);
      const formatted = helpers.fmtTarget({ hostname: 'test.com', ip: '10.0.0.1' });
      expect(formatted).toContain('test.com');
    });

    it('getScanProfile returns a valid profile object', async () => {
      const { buildEnumerationHelpers } = await import('./lib/active-enumeration/enumeration-context');
      const mockState = { engagementId: 1, roeScopeGuard: { authorizedDomains: [], authorizedIps: [] }, logs: [], assets: [], stats: {} } as any;
      const helpers = buildEnumerationHelpers(mockState);
      const profile = helpers.getScanProfile('standard');
      expect(profile).toBeDefined();
      expect(profile).toHaveProperty('name');
    });
  });

  describe('targeted-tool-runner sanitization', () => {
    it('sanitizeNucleiCommand is internally used (module loads without error)', async () => {
      // The targeted-tool-runner module should load cleanly
      const mod = await import('./lib/active-enumeration/targeted-tool-runner');
      expect(mod.executeTargetedToolDeployment).toBeDefined();
    });
  });

  describe('integration: orchestrator exports for sub-modules', () => {
    it('engagement-orchestrator exports persistScanResult', async () => {
      const mod = await import('./lib/engagement-orchestrator');
      expect(mod.persistScanResult).toBeDefined();
      expect(typeof mod.persistScanResult).toBe('function');
    });

    it('engagement-orchestrator exports persistOpsStateDebounced', async () => {
      const mod = await import('./lib/engagement-orchestrator');
      expect(mod.persistOpsStateDebounced).toBeDefined();
      expect(typeof mod.persistOpsStateDebounced).toBe('function');
    });

    it('engagement-orchestrator exports KNOWN_INFRA_IPS as a Set', async () => {
      const mod = await import('./lib/engagement-orchestrator');
      expect(mod.KNOWN_INFRA_IPS).toBeDefined();
      expect(mod.KNOWN_INFRA_IPS instanceof Set).toBe(true);
    });
  });
});
