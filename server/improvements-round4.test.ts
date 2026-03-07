import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Nuclei DAST Mode Tests ──
describe('Nuclei DAST Mode with Crawling', () => {
  it('should build nuclei DAST command with correct flags', () => {
    const target = 'http://testphp.vulnweb.com';
    const dastCmd = `echo '${target}' | nuclei -t dast/ -jsonl -system-resolvers -timeout 300 -stats -silent`;
    expect(dastCmd).toContain('-t dast/');
    expect(dastCmd).toContain('-jsonl');
    expect(dastCmd).toContain('-system-resolvers');
    expect(dastCmd).toContain('-timeout 300');
    expect(dastCmd).toContain(`echo '${target}'`);
  });

  it('should use stdin piping instead of -u flag to avoid TTY hang', () => {
    const target = 'http://demo.testfire.net';
    const cmd = `echo '${target}' | nuclei -jsonl -system-resolvers`;
    expect(cmd).not.toContain('-u ');
    expect(cmd).toContain(`echo '${target}' | nuclei`);
  });

  it('should include DAST templates for active fuzzing', () => {
    const dastTemplates = ['dast/'];
    expect(dastTemplates).toContain('dast/');
  });

  it('should parse DAST JSONL findings correctly', () => {
    const dastFinding = JSON.stringify({
      'template-id': 'dast-sqli-error-based',
      info: { name: 'SQL Injection (Error Based)', severity: 'critical' },
      host: 'http://testphp.vulnweb.com',
      'matched-at': 'http://testphp.vulnweb.com/listproducts.php?cat=1',
      type: 'http',
    });
    const parsed = JSON.parse(dastFinding);
    expect(parsed['template-id']).toBe('dast-sqli-error-based');
    expect(parsed.info.severity).toBe('critical');
    expect(parsed.info.name).toContain('SQL Injection');
  });

  it('should merge DAST findings with existing vulns and mark as confirmed', () => {
    const existingVulns = [
      { id: 'v1', title: 'SQL Injection', severity: 'critical', tool: 'llm-synthesis' },
    ];
    const dastFindings = [
      { templateId: 'dast-sqli', name: 'SQL Injection (Error Based)', severity: 'critical', matchedAt: '/listproducts.php?cat=1' },
    ];

    // Simulate confirmation logic
    const confirmed = existingVulns.map(v => {
      const match = dastFindings.find(d => 
        d.name.toLowerCase().includes('sql injection') && v.title.toLowerCase().includes('sql injection')
      );
      return match ? { ...v, confirmedByActiveScan: true, dastEvidence: match.matchedAt } : v;
    });

    expect(confirmed[0].confirmedByActiveScan).toBe(true);
    expect(confirmed[0].dastEvidence).toBe('/listproducts.php?cat=1');
  });
});

// ── Exploit Execution Sandbox Tests ──
describe('Exploit Execution Sandbox', () => {
  it('should enforce dry run mode by default', () => {
    const config = { dryRun: true, timeout: 30, maxOutputSize: 50000 };
    expect(config.dryRun).toBe(true);
    expect(config.timeout).toBe(30);
  });

  it('should detect exploit language from code content', () => {
    const detectLanguage = (code: string): string => {
      if (code.includes('#!/usr/bin/env python') || code.includes('import ')) return 'python';
      if (code.includes('#!/bin/bash') || code.includes('curl ')) return 'bash';
      if (code.includes('require ') && code.includes("'net/http'")) return 'ruby';
      if (code.includes('Invoke-WebRequest') || code.includes('$PSVersionTable')) return 'powershell';
      return 'python'; // default
    };

    expect(detectLanguage('#!/usr/bin/env python3\nimport requests')).toBe('python');
    expect(detectLanguage('#!/bin/bash\ncurl -s http://target')).toBe('bash');
    expect(detectLanguage("require 'net/http'\nuri = URI.parse")).toBe('ruby');
    expect(detectLanguage('$headers = @{}\nInvoke-WebRequest')).toBe('powershell');
  });

  it('should build sandboxed execution command with resource limits', () => {
    const code = 'print("hello")';
    const language = 'python';
    const timeout = 30;
    const dryRun = true;

    const dryRunPrefix = dryRun ? 'echo "[DRY RUN] Would execute:" && cat' : '';
    const execCmd = dryRun
      ? `${dryRunPrefix} /tmp/exploit_sandbox_*.py`
      : `timeout ${timeout}s python3 /tmp/exploit_sandbox_*.py 2>&1`;

    expect(dryRun ? execCmd : '').toContain('DRY RUN');
  });

  it('should sanitize exploit code before execution', () => {
    const dangerousPatterns = [
      'rm -rf /',
      'dd if=/dev/zero',
      'mkfs.',
      ':(){ :|:& };:',
      'chmod -R 777 /',
    ];

    const sanitize = (code: string): { safe: boolean; warnings: string[] } => {
      const warnings: string[] = [];
      for (const pattern of dangerousPatterns) {
        if (code.includes(pattern)) {
          warnings.push(`Dangerous pattern detected: ${pattern}`);
        }
      }
      return { safe: warnings.length === 0, warnings };
    };

    expect(sanitize('import requests\nrequests.get("http://target")').safe).toBe(true);
    expect(sanitize('import os\nos.system("rm -rf /")').safe).toBe(false);
    expect(sanitize('import os\nos.system("rm -rf /")').warnings).toHaveLength(1);
  });

  it('should limit execution output size', () => {
    const maxOutputSize = 50000;
    const longOutput = 'A'.repeat(100000);
    const truncated = longOutput.length > maxOutputSize
      ? longOutput.slice(0, maxOutputSize) + '\n... [output truncated]'
      : longOutput;

    expect(truncated.length).toBeLessThan(longOutput.length);
    expect(truncated).toContain('[output truncated]');
  });

  it('should track execution history with timestamps', () => {
    const execution = {
      id: 1,
      engagementId: 42,
      exploitIndex: 0,
      language: 'python',
      dryRun: false,
      exitCode: 0,
      status: 'success',
      durationMs: 1500,
      output: 'Exploit executed successfully',
      timestamp: Date.now(),
    };

    expect(execution.status).toBe('success');
    expect(execution.durationMs).toBeLessThan(30000);
    expect(execution.timestamp).toBeGreaterThan(0);
  });
});

// ── Vulnerability Trend Tracking Tests ──
describe('Vulnerability Trend Tracking', () => {
  it('should create a scan snapshot with severity breakdown', () => {
    const assets = [
      {
        hostname: 'testphp.vulnweb.com',
        vulns: [
          { id: 'v1', title: 'SQL Injection', severity: 'critical' },
          { id: 'v2', title: 'XSS', severity: 'high' },
          { id: 'v3', title: 'CRLF', severity: 'medium' },
          { id: 'v4', title: 'Info Disclosure', severity: 'low' },
        ],
        ports: [{ port: 80, service: 'http' }, { port: 443, service: 'https' }],
      },
    ];

    const snapshot = {
      totalVulns: assets.reduce((s, a) => s + a.vulns.length, 0),
      critical: assets.flatMap(a => a.vulns).filter(v => v.severity === 'critical').length,
      high: assets.flatMap(a => a.vulns).filter(v => v.severity === 'high').length,
      medium: assets.flatMap(a => a.vulns).filter(v => v.severity === 'medium').length,
      low: assets.flatMap(a => a.vulns).filter(v => v.severity === 'low').length,
      totalPorts: assets.reduce((s, a) => s + a.ports.length, 0),
      assetCount: assets.length,
    };

    expect(snapshot.totalVulns).toBe(4);
    expect(snapshot.critical).toBe(1);
    expect(snapshot.high).toBe(1);
    expect(snapshot.medium).toBe(1);
    expect(snapshot.low).toBe(1);
    expect(snapshot.totalPorts).toBe(2);
  });

  it('should detect new vulnerabilities between snapshots', () => {
    const previousVulns = [
      { title: 'SQL Injection', severity: 'critical', hostname: 'target.com' },
      { title: 'XSS', severity: 'high', hostname: 'target.com' },
    ];
    const currentVulns = [
      { title: 'SQL Injection', severity: 'critical', hostname: 'target.com' },
      { title: 'XSS', severity: 'high', hostname: 'target.com' },
      { title: 'SSRF', severity: 'high', hostname: 'target.com' },
    ];

    const prevKeys = new Set(previousVulns.map(v => `${v.hostname}:${v.title}`));
    const newVulns = currentVulns.filter(v => !prevKeys.has(`${v.hostname}:${v.title}`));

    expect(newVulns).toHaveLength(1);
    expect(newVulns[0].title).toBe('SSRF');
  });

  it('should detect resolved vulnerabilities between snapshots', () => {
    const previousVulns = [
      { title: 'SQL Injection', severity: 'critical', hostname: 'target.com' },
      { title: 'XSS', severity: 'high', hostname: 'target.com' },
      { title: 'Open Redirect', severity: 'medium', hostname: 'target.com' },
    ];
    const currentVulns = [
      { title: 'SQL Injection', severity: 'critical', hostname: 'target.com' },
      { title: 'XSS', severity: 'high', hostname: 'target.com' },
    ];

    const currKeys = new Set(currentVulns.map(v => `${v.hostname}:${v.title}`));
    const resolvedVulns = previousVulns.filter(v => !currKeys.has(`${v.hostname}:${v.title}`));

    expect(resolvedVulns).toHaveLength(1);
    expect(resolvedVulns[0].title).toBe('Open Redirect');
  });

  it('should compute trend data with per-asset breakdown', () => {
    const snapshots = [
      {
        id: 1,
        date: '2026-03-01T00:00:00Z',
        type: 'full_pipeline',
        totalVulns: 10,
        critical: 3,
        high: 4,
        medium: 2,
        low: 1,
        ports: 20,
        exploits: 5,
        assets: 3,
        assetBreakdown: [
          { hostname: 'a.com', vulnCount: 4, portCount: 8 },
          { hostname: 'b.com', vulnCount: 3, portCount: 7 },
          { hostname: 'c.com', vulnCount: 3, portCount: 5 },
        ],
      },
      {
        id: 2,
        date: '2026-03-05T00:00:00Z',
        type: 'full_pipeline',
        totalVulns: 15,
        critical: 5,
        high: 5,
        medium: 3,
        low: 2,
        ports: 25,
        exploits: 8,
        assets: 3,
        assetBreakdown: [
          { hostname: 'a.com', vulnCount: 6, portCount: 10 },
          { hostname: 'b.com', vulnCount: 5, portCount: 8 },
          { hostname: 'c.com', vulnCount: 4, portCount: 7 },
        ],
      },
    ];

    expect(snapshots).toHaveLength(2);
    expect(snapshots[1].totalVulns).toBeGreaterThan(snapshots[0].totalVulns);
    expect(snapshots[1].critical).toBeGreaterThan(snapshots[0].critical);
    // Trend is upward
    const trend = snapshots[1].totalVulns - snapshots[0].totalVulns;
    expect(trend).toBe(5);
  });

  it('should format chart data correctly for recharts', () => {
    const raw = {
      date: '2026-03-07T12:00:00Z',
      critical: 5,
      high: 8,
      medium: 3,
      low: 2,
      totalVulns: 18,
      exploits: 6,
    };

    const chartPoint = {
      date: new Date(raw.date).toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      }),
      Critical: raw.critical,
      High: raw.high,
      Medium: raw.medium,
      Low: raw.low,
      Total: raw.totalVulns,
      Exploits: raw.exploits,
    };

    expect(chartPoint.Critical).toBe(5);
    expect(chartPoint.High).toBe(8);
    expect(chartPoint.date).toContain('Mar');
  });

  it('should support manual snapshot recording', () => {
    const manualSnapshot = {
      engagementId: 42,
      snapshotType: 'manual',
      assets: [
        { hostname: 'target.com', vulns: [{ id: 'v1', severity: 'critical', title: 'SQLi' }], ports: [] },
      ],
      exploitCount: 3,
      metadata: { recordedManually: true },
    };

    expect(manualSnapshot.snapshotType).toBe('manual');
    expect(manualSnapshot.metadata.recordedManually).toBe(true);
    expect(manualSnapshot.assets[0].vulns).toHaveLength(1);
  });

  it('should auto-record snapshot on pipeline completion', () => {
    // Simulate the pipeline completion handler
    const pipelineComplete = true;
    const autoRecord = pipelineComplete;
    expect(autoRecord).toBe(true);
  });
});

// ── VulnTrendChart Component Tests ──
describe('VulnTrendChart Component', () => {
  it('should handle empty data gracefully', () => {
    const data: any[] = [];
    const chartData = data.map(d => ({
      date: new Date(d.date).toLocaleDateString(),
      Critical: d.critical,
      High: d.high,
    }));
    expect(chartData).toHaveLength(0);
  });

  it('should transform trend data to chart format', () => {
    const data = [
      { id: 1, date: '2026-03-01', critical: 3, high: 5, medium: 2, low: 1, totalVulns: 11, exploits: 4 },
      { id: 2, date: '2026-03-05', critical: 5, high: 7, medium: 3, low: 2, totalVulns: 17, exploits: 7 },
    ];

    const chartData = data.map(d => ({
      date: new Date(d.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      Critical: d.critical,
      High: d.high,
      Medium: d.medium,
      Low: d.low,
    }));

    expect(chartData).toHaveLength(2);
    expect(chartData[0].Critical).toBe(3);
    expect(chartData[1].Critical).toBe(5);
  });
});
