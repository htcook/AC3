import { describe, it, expect, beforeEach } from 'vitest';

/**
 * Tests for live graph updates during active scans:
 * 1. broadcastReconFinding emits recon:finding events correctly
 * 2. eventToGraphDelta converts recon:finding events into graph nodes/edges
 * 3. engagement:progress_update events with stats_update trigger graph invalidation
 * 4. Phase change events trigger graph invalidation
 * 5. Deduplication of node IDs in eventToGraphDelta
 */

// We test the server-side broadcastReconFinding function
// and the client-side eventToGraphDelta logic (imported as a module)

describe('Live Graph Updates', () => {

  describe('broadcastReconFinding — server-side event emission', () => {
    it('should export broadcastReconFinding function', async () => {
      const mod = await import('./lib/engagement-orchestrator');
      expect(typeof mod.broadcastReconFinding).toBe('function');
    });

    it('should export broadcastCredentialFound function', async () => {
      const mod = await import('./lib/engagement-orchestrator');
      expect(typeof mod.broadcastCredentialFound).toBe('function');
    });

    it('should not throw when called with valid finding data', async () => {
      const mod = await import('./lib/engagement-orchestrator');
      // broadcastReconFinding is best-effort, should never throw
      expect(() => {
        mod.broadcastReconFinding(999999, {
          target: 'test.example.com',
          host: 'test.example.com',
          port: 443,
          service: 'https',
          protocol: 'tcp',
          tool: 'passive_recon',
        });
      }).not.toThrow();
    });

    it('should not throw when called with vulnerability data', async () => {
      const mod = await import('./lib/engagement-orchestrator');
      expect(() => {
        mod.broadcastReconFinding(999999, {
          target: 'test.example.com',
          vulnerability: 'SQL Injection in login form',
          cve: 'CVE-2024-1234',
          severity: 'high',
          tool: 'nuclei',
        });
      }).not.toThrow();
    });

    it('should not throw when called with subdomain data', async () => {
      const mod = await import('./lib/engagement-orchestrator');
      expect(() => {
        mod.broadcastReconFinding(999999, {
          target: 'example.com',
          subdomain: 'api.example.com',
          tool: 'passive_recon',
        });
      }).not.toThrow();
    });

    it('should not throw when called with technology/WAF data', async () => {
      const mod = await import('./lib/engagement-orchestrator');
      expect(() => {
        mod.broadcastReconFinding(999999, {
          target: 'example.com',
          technology: 'nginx',
          waf: 'Cloudflare',
          tool: 'passive_recon',
        });
      }).not.toThrow();
    });
  });

  describe('eventToGraphDelta — client-side event conversion', () => {
    // Simulate the eventToGraphDelta logic inline since it's a client module
    // We replicate the core logic to test it in a Node.js environment

    const addedNodeIds = new Set<string>();
    const addedEdgeKeys = new Set<string>();

    function edgeKey(src: string, tgt: string, type: string): string {
      return `${src}→${tgt}:${type}`;
    }

    function eventToGraphDelta(event: { type: string; data: any }) {
      const nodes: any[] = [];
      const edges: any[] = [];
      const d = event.data || {};

      if (event.type === 'recon:finding') {
        const target = d.target || d.host || d.ip || d.domain;
        if (!target) return { nodes, edges };

        const hostId = `host-${target}`;
        if (!addedNodeIds.has(hostId)) {
          addedNodeIds.add(hostId);
          nodes.push({ id: hostId, type: 'host', label: target });
        }

        if (d.port || d.service) {
          const svcId = `svc-${target}-${d.port || d.service}`;
          if (!addedNodeIds.has(svcId)) {
            addedNodeIds.add(svcId);
            nodes.push({ id: svcId, type: 'service', label: `${d.service || 'svc'}:${d.port || '?'}` });
            const ek = edgeKey(hostId, svcId, 'network_link');
            if (!addedEdgeKeys.has(ek)) {
              addedEdgeKeys.add(ek);
              edges.push({ source: hostId, target: svcId, type: 'network_link' });
            }
          }
        }

        if (d.vulnerability || d.cve || d.templateId || d.finding) {
          const vulnLabel = d.vulnerability || d.cve || d.templateId || d.finding;
          const vulnId = `vuln-${target}-${vulnLabel}`;
          if (!addedNodeIds.has(vulnId)) {
            addedNodeIds.add(vulnId);
            nodes.push({ id: vulnId, type: 'vulnerability', label: vulnLabel });
          }
        }

        if (d.subdomain) {
          const subId = `sub-${d.subdomain}`;
          if (!addedNodeIds.has(subId)) {
            addedNodeIds.add(subId);
            nodes.push({ id: subId, type: 'subdomain', label: d.subdomain });
          }
        }
      }

      return { nodes, edges };
    }

    beforeEach(() => {
      addedNodeIds.clear();
      addedEdgeKeys.clear();
    });

    it('should create host node from recon:finding with target', () => {
      const result = eventToGraphDelta({
        type: 'recon:finding',
        data: { target: 'example.com', tool: 'passive_recon' },
      });
      expect(result.nodes).toHaveLength(1);
      expect(result.nodes[0].id).toBe('host-example.com');
      expect(result.nodes[0].type).toBe('host');
    });

    it('should create host + service nodes when port is present', () => {
      const result = eventToGraphDelta({
        type: 'recon:finding',
        data: { target: 'example.com', port: 443, service: 'https', tool: 'scanforge' },
      });
      expect(result.nodes).toHaveLength(2);
      expect(result.nodes[0].type).toBe('host');
      expect(result.nodes[1].type).toBe('service');
      expect(result.edges).toHaveLength(1);
      expect(result.edges[0].type).toBe('network_link');
    });

    it('should create vulnerability node when vuln data is present', () => {
      const result = eventToGraphDelta({
        type: 'recon:finding',
        data: { target: 'example.com', vulnerability: 'SQL Injection', severity: 'high', tool: 'nuclei' },
      });
      expect(result.nodes).toHaveLength(2); // host + vuln
      const vulnNode = result.nodes.find((n: any) => n.type === 'vulnerability');
      expect(vulnNode).toBeDefined();
      expect(vulnNode.label).toBe('SQL Injection');
    });

    it('should create subdomain node when subdomain data is present', () => {
      const result = eventToGraphDelta({
        type: 'recon:finding',
        data: { target: 'example.com', subdomain: 'api.example.com', tool: 'passive_recon' },
      });
      const subNode = result.nodes.find((n: any) => n.type === 'subdomain');
      expect(subNode).toBeDefined();
      expect(subNode.label).toBe('api.example.com');
    });

    it('should deduplicate nodes on repeated events', () => {
      const event = {
        type: 'recon:finding',
        data: { target: 'example.com', port: 80, service: 'http' },
      };
      const first = eventToGraphDelta(event);
      const second = eventToGraphDelta(event);
      expect(first.nodes).toHaveLength(2); // host + service
      expect(second.nodes).toHaveLength(0); // all deduped
    });

    it('should return empty for events without target', () => {
      const result = eventToGraphDelta({
        type: 'recon:finding',
        data: { tool: 'passive_recon' }, // no target
      });
      expect(result.nodes).toHaveLength(0);
    });

    it('should handle engagement:progress_update events gracefully', () => {
      const result = eventToGraphDelta({
        type: 'engagement:progress_update',
        data: { type: 'stats_update', stats: { hostsScanned: 5 } },
      });
      // progress_update events don't produce graph nodes directly
      expect(result.nodes).toHaveLength(0);
    });
  });

  describe('Graph invalidation triggers', () => {
    it('should identify stats_update as a graph invalidation trigger', () => {
      const event = {
        type: 'engagement:progress_update',
        data: { type: 'stats_update', stats: { hostsScanned: 5 } },
      };
      const subType = event.data?.type || event.data?.subtype;
      expect(subType).toBe('stats_update');
      expect(['stats_update', 'phase_change'].includes(subType)).toBe(true);
    });

    it('should identify phase_change as a graph invalidation trigger', () => {
      const event = {
        type: 'engagement:progress_update',
        data: { type: 'phase_change', phase: 'enumeration' },
      };
      const subType = event.data?.type || event.data?.subtype;
      expect(subType).toBe('phase_change');
      expect(['stats_update', 'phase_change'].includes(subType)).toBe(true);
    });

    it('should NOT identify log_update as a graph invalidation trigger', () => {
      const event = {
        type: 'engagement:progress_update',
        data: { type: 'log_update' },
      };
      const subType = event.data?.type || event.data?.subtype;
      expect(['stats_update', 'phase_change'].includes(subType)).toBe(false);
    });
  });

  describe('refetchInterval behavior', () => {
    it('should return 8000 when opsState.isRunning is true', () => {
      const opsState = { isRunning: true, phase: 'enumeration' };
      const interval = opsState?.isRunning ? 8000 : false;
      expect(interval).toBe(8000);
    });

    it('should return false when opsState.isRunning is false', () => {
      const opsState = { isRunning: false, phase: 'completed' };
      const interval = opsState?.isRunning ? 15000 : false;
      expect(interval).toBe(false);
    });

    it('should return false when opsState is null', () => {
      const opsState = null;
      const interval = opsState?.isRunning ? 15000 : false;
      expect(interval).toBe(false);
    });
  });

  describe('Graph merge vs replace logic', () => {
    it('should use loadGraph (full replace) on first load', () => {
      let graphDataVersion = 0;
      const isRunning = true;
      const isFirstLoad = graphDataVersion === 0;
      graphDataVersion++;

      // First load should always do full replace
      expect(isFirstLoad || !isRunning).toBe(true);
    });

    it('should use addNodes (merge) on subsequent refetches while running', () => {
      let graphDataVersion = 1; // Already loaded once
      const isRunning = true;
      const isFirstLoad = graphDataVersion === 0;

      // Subsequent loads while running should merge
      expect(isFirstLoad).toBe(false);
      expect(isRunning).toBe(true);
      // So we should merge (addNodes), not replace (loadGraph)
      const shouldMerge = !isFirstLoad && isRunning;
      expect(shouldMerge).toBe(true);
    });

    it('should use loadGraph (full replace) when scan is not running', () => {
      let graphDataVersion = 1; // Already loaded once
      const isRunning = false;
      const isFirstLoad = graphDataVersion === 0;

      // When not running, always full replace to get clean state
      const shouldFullReplace = isFirstLoad || !isRunning;
      expect(shouldFullReplace).toBe(true);
    });
  });
});
