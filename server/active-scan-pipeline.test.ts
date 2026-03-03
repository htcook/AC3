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
