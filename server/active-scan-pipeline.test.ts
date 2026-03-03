import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

describe('Active Scan Pipeline Audit', () => {
  const orchestratorPath = path.resolve(__dirname, 'lib/engagement-orchestrator.ts');
  const opsCoreRouterPath = path.resolve(__dirname, 'routers/engagement-ops-core.ts');
  const scanServerPath = path.resolve(__dirname, 'lib/scan-server-executor.ts');

  describe('db.default fix verification', () => {
    it('executeEngagement uses db.getEngagementById (not db.default)', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      const execBlock = orch.slice(orch.indexOf('export async function executeEngagement'));
      // Should use db.getEngagementById, NOT db.default.getEngagementById
      expect(execBlock).toContain('db.getEngagementById(engagementId)');
      expect(execBlock).not.toContain('db.default.getEngagementById');
    });

    it('no db.default references exist anywhere in orchestrator', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(orch).not.toContain('db.default.');
    });
  });

  describe('Target insertion in nmap commands', () => {
    it('executeEnumeration builds nmap commands with target variable', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      // The nmap command is built as: `${discoveryFlags} ${target}`
      expect(orch).toContain('`${discoveryFlags} ${target}`');
    });

    it('targets are extracted from state.assets', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(orch).toContain('state.assets.map(a => a.ip || a.hostname)');
    });

    it('executeTool is called with the constructed command', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(orch).toContain("executeTool({ tool: 'nmap', args: nmapArgs");
    });
  });

  describe('Scan server executor', () => {
    it('executeTool validates tool against whitelist', () => {
      const executor = fs.readFileSync(scanServerPath, 'utf-8');
      expect(executor).toContain('ALLOWED_TOOLS');
      expect(executor).toContain('if (!ALLOWED_TOOLS.has(tool))');
    });

    it('executeTool sends command via SSH', () => {
      const executor = fs.readFileSync(scanServerPath, 'utf-8');
      expect(executor).toContain('executeSSH(command');
    });

    it('nmap is in the allowed tools whitelist', () => {
      const executor = fs.readFileSync(scanServerPath, 'utf-8');
      expect(executor).toContain('"nmap"');
      expect(executor).toContain('"naabu"');
      expect(executor).toContain('"httpx"');
      expect(executor).toContain('"nuclei"');
    });
  });

  describe('Error handling for fire-and-forget calls', () => {
    it('startOps catches executeEngagement crashes and reports to UI', () => {
      const router = fs.readFileSync(opsCoreRouterPath, 'utf-8');
      // The startOps call should have .catch() error handling
      const startOpsBlock = router.slice(
        router.indexOf('// Fire and forget'),
        router.indexOf('return { started: true, engagementId:')
      );
      expect(startOpsBlock).toContain('.catch(');
      expect(startOpsBlock).toContain('executeEngagement crashed');
      expect(startOpsBlock).toContain("state.phase = 'error'");
      expect(startOpsBlock).toContain('persistOpsStateNow');
    });

    it('startActiveScan catches executeEngagement crashes and reports to UI', () => {
      const router = fs.readFileSync(opsCoreRouterPath, 'utf-8');
      // The startActiveScan async IIFE should have try/catch around executeEngagement
      const activeScanBlock = router.slice(
        router.indexOf('startActiveScan:'),
        router.indexOf('loadExploits:')
      );
      expect(activeScanBlock).toContain('await executeEngagement(');
      expect(activeScanBlock).toContain('catch (execErr');
      expect(activeScanBlock).toContain('Active Scan Execution Failed');
      expect(activeScanBlock).toContain('persistOpsStateNow');
    });
  });

  describe('LLM scan plan generation', () => {
    it('generateScanPlan sends asset data to LLM with hostnames and IPs', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      const genBlock = orch.slice(
        orch.indexOf('export async function generateScanPlan'),
        orch.indexOf('// ─── LLM Decision Engine')
      );
      // Should map assets to summaries with hostname and IP
      expect(genBlock).toContain('hostname: a.hostname');
      expect(genBlock).toContain("ip: a.ip || 'unknown'");
      // Should use invokeLLM
      expect(genBlock).toContain('invokeLLM');
      // Should use structured JSON response format
      expect(genBlock).toContain("type: 'json_schema'");
    });

    it('scan plan includes per-asset nmap flags and tools', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      const genBlock = orch.slice(
        orch.indexOf('export async function generateScanPlan'),
        orch.indexOf('// ─── LLM Decision Engine')
      );
      expect(genBlock).toContain('discoveryNmapFlags');
      expect(genBlock).toContain('httpxFlags');
      expect(genBlock).toContain('activeTools');
      expect(genBlock).toContain('evasionTechniques');
      // naabu removed — nmap is the primary port scanner
      expect(genBlock).not.toContain("naabuFlags: { type: 'string'");
    });
  });

  describe('LLM placeholder stripping', () => {
    it('strips {naabu_ports} placeholder from nmap flags', () => {
      const flags = '-Pn -sV -sC -O -p {naabu_ports} -f -D RND:5';
      const result = flags
        .replace(/(?:^|\s)-p\s*(?:\{[^}]+\}|[\d,\-]+)(?=\s|$)/g, '')  // Remove -p with any value
        .replace(/\{[^}]+\}/g, '')  // Remove remaining placeholders
        .replace(/\s+/g, ' ').trim();
      expect(result).not.toContain('{naabu_ports}');
      expect(result).not.toContain('-p ');
    });

    it('strips {target} placeholder from nmap flags', () => {
      const flags = '-Pn -sV -sC {target} -T3';
      const result = flags
        .replace(/\{[^}]*\}/g, '')
        .replace(/\s+/g, ' ').trim();
      expect(result).not.toContain('{target}');
      expect(result).toBe('-Pn -sV -sC -T3');
    });

    it('orchestrator strips curly-brace placeholders from discovery flags', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      // Should strip any {placeholder} patterns from LLM-generated flags
      expect(orch).toContain("\\{[^}]+\\}");
    });

    it('activeTools command replaces {target} with actual hostname/IP', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(orch).toContain(".replace(/\\{target\\}/g, asset.ip || asset.hostname)");
    });

    it('activeTools command strips naabu placeholders', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(orch).toContain("naabu");
      expect(orch).toContain(".replace(/\\{[^}]*naabu[^}]*\\}/gi, '')");
    });
  });

  describe('Nmap port specification sanitization', () => {
    it('strips -p80,443 format (no space) from discovery flags', () => {
      const flags = '-Pn -sV -p80,443 -sC';
      const result = flags
        .replace(/(?<=\s|^)-p[\s]*[\d,\-]+(?=\s|$)|-p-/g, '')
        .replace(/\s+/g, ' ').trim();
      expect(result).toBe('-Pn -sV -sC');
    });

    it('strips -p 80,443 format (with space) from discovery flags', () => {
      const flags = '-Pn -sV -p 80,443 -sC';
      const result = flags
        .replace(/(?<=\s|^)-p[\s]*[\d,\-]+(?=\s|$)|-p-/g, '')
        .replace(/\s+/g, ' ').trim();
      expect(result).toBe('-Pn -sV -sC');
    });

    it('strips -p- (all ports) from discovery flags', () => {
      const flags = '-Pn -sV -p- -sC';
      const result = flags
        .replace(/(?<=\s|^)-p[\s]*[\d,\-]+(?=\s|$)|-p-/g, '')
        .replace(/\s+/g, ' ').trim();
      expect(result).toBe('-Pn -sV -sC');
    });

    it('strips -p1-65535 range format from discovery flags', () => {
      const flags = '-Pn -sV -p1-65535 -sC';
      const result = flags
        .replace(/(?<=\s|^)-p[\s]*[\d,\-]+(?=\s|$)|-p-/g, '')
        .replace(/\s+/g, ' ').trim();
      expect(result).toBe('-Pn -sV -sC');
    });

    it('does NOT strip -Pn (uppercase P) from discovery flags', () => {
      const flags = '-Pn -sV -sC';
      const result = flags
        .replace(/(?<=\s|^)-p[\s]*[\d,\-]+(?=\s|$)|-p-/g, '')
        .replace(/\s+/g, ' ').trim();
      expect(result).toBe('-Pn -sV -sC');
    });

    it('does NOT strip --top-ports from discovery flags', () => {
      const flags = '-Pn -sV --top-ports 1000 -sC';
      const result = flags
        .replace(/(?<=\s|^)-p[\s]*[\d,\-]+(?=\s|$)|-p-/g, '')
        .replace(/\s+/g, ' ').trim();
      expect(result).toBe('-Pn -sV --top-ports 1000 -sC');
    });

    it('orchestrator uses the improved port spec regex', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      // Should use the improved regex that catches -p with numeric or placeholder values
      expect(orch).toContain('\\{[^}]+\\}|[\\d,\\-]+');
      // Should NOT use the old broken regex
      expect(orch).not.toContain("/-p[- ]\\S*/g");
    });
  });

  describe('UI: httpx findings display', () => {
    it('EngagementOps shows httpx findings count in Discovery tab', () => {
      const opsPage = fs.readFileSync(
        path.resolve(__dirname, '../client/src/pages/EngagementOps.tsx'), 'utf-8'
      );
      // Should calculate httpx findings count using reduce
      expect(opsPage).toContain('httpxResults.reduce');
      expect(opsPage).toContain('findings?.length || tr.findingCount || 0');
    });

    it('EngagementOps shows Nuclei card instead of Naabu', () => {
      const opsPage = fs.readFileSync(
        path.resolve(__dirname, '../client/src/pages/EngagementOps.tsx'), 'utf-8'
      );
      // Should have nuclei card, not naabu
      expect(opsPage).toContain('nucleiResults');
      expect(opsPage).not.toContain('naabuResults');
    });

    it('findings rendering handles object findings (not just strings)', () => {
      const opsPage = fs.readFileSync(
        path.resolve(__dirname, '../client/src/pages/EngagementOps.tsx'), 'utf-8'
      );
      // Should use typeof check for findings
      expect(opsPage).toContain("typeof f === 'string'");
      expect(opsPage).toContain("f?.title");
    });
  });

  describe('Auto-retry: nmap retries without evasion flags when all ports filtered', () => {
    it('orchestrator detects all-filtered output and retries with simple flags', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      // Should detect filtered output
      expect(orch).toContain('allFiltered');
      expect(orch).toContain('hasEvasionFlags');
      // Should retry with simple flags
      expect(orch).toContain("'-Pn -sV -sC -T3 --top-ports 1000'");
      expect(orch).toContain('nmap Retry:');
    });

    it('retry only triggers when evasion flags are present', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      // Should check for evasion flags before retrying
      expect(orch).toContain('if (allFiltered && hasEvasionFlags)');
    });

    it('retry persists results with discovery_retry phase', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(orch).toContain("phase: 'discovery_retry'");
    });
  });

  describe('httpx port backfill when nmap finds 0 ports', () => {
    it('orchestrator backfills ports from httpx when nmap finds nothing', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(orch).toContain('httpx Port Backfill');
      expect(orch).toContain('asset.ports.length === 0 && webPorts.length > 0');
    });

    it('backfill parses httpx JSON output for confirmed ports', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(orch).toContain('obj.status_code && obj.port');
      expect(orch).toContain('confirmedPorts');
    });

    it('backfill falls back to standard web ports (80, 443) when httpx has findings', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(orch).toContain("{ port: 80, service: 'http' }");
      expect(orch).toContain("{ port: 443, service: 'https' }");
    });
  });

  describe('Cloud target evasion guidance in LLM prompt', () => {
    it('LLM prompt warns against evasion flags on cloud targets', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(orch).toContain('EVASION FLAGS vs CLOUD TARGETS');
      expect(orch).toContain('cloud firewalls DROP fragmented packets');
    });

    it('LLM prompt provides simple flag example for cloud targets', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(orch).toContain("Example for cloud targets: '-Pn -sV -sC'");
    });

    it('LLM prompt prioritizes finding ports over evasion', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(orch).toContain('Finding open ports is ALWAYS more important than evasion');
    });
  });

  describe('Nuclei tech-targeted template selection', () => {
    it('nuclei uses httpx-detected technologies for template tags', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(orch).toContain('techTags');
      expect(orch).toContain('passiveRecon?.technologies');
      expect(orch).toContain('-tags');
    });

    it('maps common technologies to nuclei template tags', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(orch).toContain("techTags.push('wordpress')");
      expect(orch).toContain("techTags.push('nginx')");
      expect(orch).toContain("techTags.push('apache')");
      expect(orch).toContain("techTags.push('php')");
    });

    it('falls back to broad severity scan when no tech detected', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(orch).toContain("techTags.length > 0 ? `-tags ${techTags.join(',')}`");
    });
  });

  describe('Result parsing', () => {
    it('nmap output is parsed for open ports', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      // TCP port regex
      expect(orch).toContain("/(\\d+)\\/tcp\\s+open\\s+(\\S+)");
      // UDP port regex
      expect(orch).toContain("/(\\d+)\\/udp\\s+open\\s+(\\S+)");
    });

    it('nuclei output is parsed for vulnerability findings', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      // Nuclei JSONL parsing
      expect(orch).toContain('obj.info?.severity && obj.info?.name');
      expect(orch).toContain('[Nuclei]');
    });

    it('scan results are persisted to database', () => {
      const orch = fs.readFileSync(orchestratorPath, 'utf-8');
      expect(orch).toContain('persistScanResult');
    });
  });
});
