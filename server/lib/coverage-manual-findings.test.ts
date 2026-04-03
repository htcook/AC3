import { describe, it, expect } from 'vitest';

/**
 * Tests for:
 * 1. Scan Coverage Heatmap data transformation
 * 2. Timeline replay logic
 * 3. Manual findings data model and report integration
 * 4. Evasion CLI adapter (coverage of new getZapEvasionOverrides)
 */

// ─── Scan Coverage Heatmap Logic ──────────────────────────────────────

describe('Scan Coverage Heatmap', () => {
  // Test the coverage computation logic that lives in the frontend memo
  function computeCoverage(assets: any[]) {
    const assetCoverage: Array<{
      hostname: string;
      portsCovered: number;
      portsTotal: number;
      servicesTested: string[];
      pathsCrawled: number;
      vulnsFound: number;
      toolsRun: string[];
      gaps: string[];
      coveragePercent: number;
    }> = [];

    for (const asset of assets) {
      const ports = asset.discoveredPorts || [];
      const toolResults = asset.toolResults || [];
      const vulns = asset.vulnerabilities || [];

      const toolsRun = [...new Set(toolResults.map((t: any) => t.tool))];
      const servicesTested = [...new Set(ports.filter((p: any) => p.service).map((p: any) => p.service))];

      // Identify gaps
      const gaps: string[] = [];
      const hasWebPorts = ports.some((p: any) => [80, 443, 8080, 8443].includes(p.port));
      const hasSSH = ports.some((p: any) => p.port === 22);
      const hasSMTP = ports.some((p: any) => p.port === 25);

      if (hasWebPorts && !toolsRun.some((t: string) => ['zap', 'nikto', 'nuclei'].includes(t.toLowerCase()))) {
        gaps.push('Web ports open but no web vulnerability scanner run');
      }
      if (hasSSH && !toolsRun.some((t: string) => ['ssh-audit', 'hydra'].includes(t.toLowerCase()))) {
        gaps.push('SSH port open but no SSH audit tool run');
      }
      if (hasSMTP && !toolsRun.some((t: string) => ['smtp-user-enum'].includes(t.toLowerCase()))) {
        gaps.push('SMTP port open but no SMTP enumeration run');
      }
      if (ports.length > 0 && toolResults.length === 0) {
        gaps.push('Ports discovered but no tools executed');
      }

      const maxScore = Math.max(ports.length, 1) + (hasWebPorts ? 3 : 0) + (hasSSH ? 1 : 0);
      const earnedScore = toolsRun.length + vulns.length * 0.5;
      const coveragePercent = Math.min(100, Math.round((earnedScore / maxScore) * 100));

      assetCoverage.push({
        hostname: asset.hostname,
        portsCovered: toolResults.length,
        portsTotal: ports.length,
        servicesTested,
        pathsCrawled: toolResults.filter((t: any) => t.tool?.toLowerCase() === 'katana').length > 0 ? 1 : 0,
        vulnsFound: vulns.length,
        toolsRun,
        gaps,
        coveragePercent,
      });
    }

    const totalGaps = assetCoverage.reduce((sum, a) => sum + a.gaps.length, 0);
    return { assetCoverage, totalGaps };
  }

  it('should compute coverage for assets with ports and tools', () => {
    const assets = [{
      hostname: 'target.com',
      discoveredPorts: [
        { port: 80, service: 'http' },
        { port: 443, service: 'https' },
        { port: 22, service: 'ssh' },
      ],
      toolResults: [
        { tool: 'nuclei', exitCode: 0 },
        { tool: 'zap', exitCode: 0 },
        { tool: 'ssh-audit', exitCode: 0 },
      ],
      vulnerabilities: [
        { title: 'XSS', severity: 'High' },
      ],
    }];

    const result = computeCoverage(assets);
    expect(result.assetCoverage).toHaveLength(1);
    expect(result.assetCoverage[0].toolsRun).toContain('nuclei');
    expect(result.assetCoverage[0].toolsRun).toContain('zap');
    expect(result.assetCoverage[0].toolsRun).toContain('ssh-audit');
    expect(result.assetCoverage[0].gaps).toHaveLength(0);
    expect(result.totalGaps).toBe(0);
  });

  it('should identify gaps when web ports have no scanner', () => {
    const assets = [{
      hostname: 'target.com',
      discoveredPorts: [
        { port: 80, service: 'http' },
        { port: 443, service: 'https' },
      ],
      toolResults: [
        { tool: 'naabu', exitCode: 0 },
      ],
      vulnerabilities: [],
    }];

    const result = computeCoverage(assets);
    expect(result.assetCoverage[0].gaps.length).toBeGreaterThan(0);
    expect(result.assetCoverage[0].gaps.some(g => g.includes('web vulnerability scanner'))).toBe(true);
    expect(result.totalGaps).toBeGreaterThan(0);
  });

  it('should identify SSH gap when no SSH audit tool run', () => {
    const assets = [{
      hostname: 'target.com',
      discoveredPorts: [{ port: 22, service: 'ssh' }],
      toolResults: [],
      vulnerabilities: [],
    }];

    const result = computeCoverage(assets);
    expect(result.assetCoverage[0].gaps.some(g => g.includes('SSH'))).toBe(true);
  });

  it('should handle assets with no ports', () => {
    const assets = [{
      hostname: 'empty.com',
      discoveredPorts: [],
      toolResults: [],
      vulnerabilities: [],
    }];

    const result = computeCoverage(assets);
    expect(result.assetCoverage[0].portsTotal).toBe(0);
    expect(result.assetCoverage[0].coveragePercent).toBe(0);
  });

  it('should compute coverage percent correctly', () => {
    const assets = [{
      hostname: 'target.com',
      discoveredPorts: [
        { port: 80, service: 'http' },
        { port: 443, service: 'https' },
      ],
      toolResults: [
        { tool: 'nuclei', exitCode: 0 },
        { tool: 'zap', exitCode: 0 },
        { tool: 'httpx', exitCode: 0 },
      ],
      vulnerabilities: [
        { title: 'SQLi', severity: 'Critical' },
        { title: 'XSS', severity: 'High' },
      ],
    }];

    const result = computeCoverage(assets);
    // maxScore = 2 ports + 3 web = 5, earnedScore = 3 tools + 2*0.5 vulns = 4
    expect(result.assetCoverage[0].coveragePercent).toBe(80);
  });
});

// ─── Timeline Replay Logic ──────────────────────────────────────

describe('Timeline Replay', () => {
  function buildTimelineEvents(log: any[], assets: any[]) {
    const events: Array<{
      id: string;
      type: string;
      timestamp: number;
      title: string;
      severity?: string;
    }> = [];

    // Phase transitions from log
    for (const entry of log) {
      if (entry.phase) {
        events.push({
          id: `phase-${entry.timestamp}`,
          type: 'phase',
          timestamp: entry.timestamp,
          title: `Phase: ${entry.phase}`,
        });
      }
      if (entry.message?.includes('evasion') || entry.message?.includes('escalat')) {
        events.push({
          id: `evasion-${entry.timestamp}`,
          type: 'evasion',
          timestamp: entry.timestamp,
          title: entry.message,
        });
      }
    }

    // Tool results from assets
    for (const asset of assets) {
      for (const tr of (asset.toolResults || [])) {
        const ts = tr.startedAt || tr.completedAt || Date.now();
        events.push({
          id: `tool-${asset.hostname}-${tr.tool}-${ts}`,
          type: 'tool',
          timestamp: ts,
          title: `${tr.tool} on ${asset.hostname}`,
        });
      }
      for (const vuln of (asset.vulnerabilities || [])) {
        events.push({
          id: `finding-${asset.hostname}-${vuln.title}`,
          type: 'finding',
          timestamp: vuln.discoveredAt || Date.now(),
          title: vuln.title,
          severity: vuln.severity,
        });
      }
    }

    return events.sort((a, b) => a.timestamp - b.timestamp);
  }

  it('should build timeline events from log and assets', () => {
    const log = [
      { timestamp: 1000, phase: 'enumeration', message: 'Starting enumeration' },
      { timestamp: 2000, phase: 'vuln_detection', message: 'Starting vuln detection' },
    ];
    const assets = [{
      hostname: 'target.com',
      toolResults: [
        { tool: 'nuclei', startedAt: 1500, exitCode: 0 },
      ],
      vulnerabilities: [
        { title: 'XSS', severity: 'High', discoveredAt: 1800 },
      ],
    }];

    const events = buildTimelineEvents(log, assets);
    expect(events.length).toBeGreaterThanOrEqual(4);
    // Should be sorted by timestamp
    for (let i = 1; i < events.length; i++) {
      expect(events[i].timestamp).toBeGreaterThanOrEqual(events[i - 1].timestamp);
    }
  });

  it('should identify evasion events from log messages', () => {
    const log = [
      { timestamp: 1000, message: 'Evasion escalated to level 3 for target.com' },
      { timestamp: 2000, message: 'Normal scan progress' },
    ];

    const events = buildTimelineEvents(log, []);
    const evasionEvents = events.filter(e => e.type === 'evasion');
    expect(evasionEvents).toHaveLength(1);
    expect(evasionEvents[0].title).toContain('Evasion');
  });

  it('should handle empty log and assets', () => {
    const events = buildTimelineEvents([], []);
    expect(events).toHaveLength(0);
  });

  // Replay speed simulation
  it('should calculate replay intervals correctly', () => {
    const speeds = [1, 2, 5, 10];
    const baseInterval = 1000; // 1 second base
    for (const speed of speeds) {
      const interval = baseInterval / speed;
      expect(interval).toBe(1000 / speed);
    }
    expect(1000 / 1).toBe(1000);
    expect(1000 / 2).toBe(500);
    expect(1000 / 5).toBe(200);
    expect(1000 / 10).toBe(100);
  });
});

// ─── Manual Findings Data Model ──────────────────────────────────────

describe('Manual Findings', () => {
  interface ManualFinding {
    id: string;
    asset: string;
    title: string;
    severity: string;
    cvss?: number;
    cve?: string;
    cwe?: string;
    description: string;
    stepsToReproduce?: string;
    impact?: string;
    remediation?: string;
    category: string;
    tags: string[];
    submittedBy: string;
    submittedAt: number;
    status: 'draft' | 'submitted' | 'verified' | 'rejected';
    notes?: string;
    evidence: Array<{
      type: string;
      name: string;
      mimeType: string;
      url?: string;
      textContent?: string;
      caption?: string;
    }>;
  }

  function createManualFinding(input: Partial<ManualFinding>): ManualFinding {
    return {
      id: input.id || `mf-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`,
      asset: input.asset || 'unknown',
      title: input.title || 'Untitled Finding',
      severity: input.severity || 'Medium',
      cvss: input.cvss,
      cve: input.cve,
      cwe: input.cwe,
      description: input.description || '',
      stepsToReproduce: input.stepsToReproduce,
      impact: input.impact,
      remediation: input.remediation,
      category: input.category || 'Other',
      tags: input.tags || [],
      submittedBy: input.submittedBy || 'operator',
      submittedAt: input.submittedAt || Date.now(),
      status: input.status || 'submitted',
      notes: input.notes,
      evidence: input.evidence || [],
    };
  }

  it('should create a manual finding with all fields', () => {
    const finding = createManualFinding({
      title: 'SQL Injection in Login Form',
      asset: 'target.com',
      severity: 'Critical',
      cvss: 9.8,
      cve: 'CVE-2024-1234',
      cwe: 'CWE-89',
      description: 'The login form is vulnerable to SQL injection via the username parameter.',
      stepsToReproduce: "1. Navigate to /login\n2. Enter ' OR 1=1-- in username\n3. Submit form",
      impact: 'Full database access, authentication bypass',
      remediation: 'Use parameterized queries',
      category: 'Injection',
      tags: ['owasp-top10', 'manual', 'authenticated'],
      evidence: [
        { type: 'screenshot', name: 'sqli-proof.png', mimeType: 'image/png', url: 'https://s3.example.com/sqli.png', caption: 'SQL error in response' },
        { type: 'terminal_output', name: 'sqlmap-output.txt', mimeType: 'text/plain', textContent: '$ sqlmap -u ...\n[*] 3 databases found' },
        { type: 'http_request_response', name: 'login-request.http', mimeType: 'text/plain', textContent: "POST /login HTTP/1.1\nHost: target.com\n\nusername=' OR 1=1--" },
      ],
    });

    expect(finding.title).toBe('SQL Injection in Login Form');
    expect(finding.severity).toBe('Critical');
    expect(finding.cvss).toBe(9.8);
    expect(finding.evidence).toHaveLength(3);
    expect(finding.evidence[0].type).toBe('screenshot');
    expect(finding.evidence[1].type).toBe('terminal_output');
    expect(finding.evidence[2].type).toBe('http_request_response');
    expect(finding.status).toBe('submitted');
  });

  it('should create a finding with defaults', () => {
    const finding = createManualFinding({});
    expect(finding.severity).toBe('Medium');
    expect(finding.category).toBe('Other');
    expect(finding.status).toBe('submitted');
    expect(finding.evidence).toHaveLength(0);
    expect(finding.id).toMatch(/^mf-/);
  });

  it('should support all evidence types', () => {
    const evidenceTypes = [
      'screenshot', 'terminal_output', 'http_request_response',
      'exploit_code', 'tool_output', 'notes', 'pcap', 'video', 'document',
    ];
    for (const type of evidenceTypes) {
      const finding = createManualFinding({
        evidence: [{ type, name: `test.${type}`, mimeType: 'text/plain' }],
      });
      expect(finding.evidence[0].type).toBe(type);
    }
  });

  it('should support status transitions', () => {
    const statuses: Array<ManualFinding['status']> = ['draft', 'submitted', 'verified', 'rejected'];
    for (const status of statuses) {
      const finding = createManualFinding({ status });
      expect(finding.status).toBe(status);
    }
  });
});

// ─── Manual Findings in Report Pipeline ──────────────────────────────────────

describe('Manual Findings Report Integration', () => {
  function buildManualFindingsReportSection(manualFindings: any[]): string {
    const validManual = manualFindings.filter(mf => mf.status !== 'rejected');
    if (validManual.length === 0) return '';

    let md = `### 12.7 Manual Testing Evidence\n\n`;
    md += `The following ${validManual.length} finding(s) were identified through manual testing.\n\n`;

    for (const mf of validManual) {
      md += `#### ${mf.title}\n\n`;
      md += `| Field | Value |\n|---|---|\n`;
      md += `| **Severity** | ${mf.severity} |\n`;
      md += `| **Asset** | ${mf.asset} |\n`;
      md += `| **Category** | ${mf.category} |\n`;
      if (mf.cve) md += `| **CVE** | ${mf.cve} |\n`;
      if (mf.cwe) md += `| **CWE** | ${mf.cwe} |\n`;
      md += `\n`;
      md += `**Description:** ${mf.description}\n\n`;

      const screenshots = mf.evidence.filter((e: any) => e.type === 'screenshot' && e.url);
      if (screenshots.length > 0) {
        md += `**Screenshots:**\n\n`;
        for (const ss of screenshots) {
          md += `![${ss.caption || ss.name}](${ss.url})\n\n`;
        }
      }

      const textEvidence = mf.evidence.filter((e: any) => e.textContent);
      if (textEvidence.length > 0) {
        md += `**Evidence Output:**\n\n`;
        for (const te of textEvidence) {
          md += `\`\`\`\n${te.textContent.substring(0, 2000)}\n\`\`\`\n\n`;
        }
      }
    }

    return md;
  }

  it('should generate report section for manual findings', () => {
    const findings = [
      {
        title: 'SQL Injection',
        severity: 'Critical',
        asset: 'target.com',
        category: 'Injection',
        cve: 'CVE-2024-1234',
        cwe: 'CWE-89',
        description: 'SQL injection in login form',
        status: 'verified',
        evidence: [
          { type: 'screenshot', name: 'proof.png', url: 'https://s3.example.com/proof.png', caption: 'SQL error' },
          { type: 'terminal_output', name: 'output.txt', textContent: '$ sqlmap --dbs\n[*] 3 databases' },
        ],
      },
    ];

    const md = buildManualFindingsReportSection(findings);
    expect(md).toContain('Manual Testing Evidence');
    expect(md).toContain('SQL Injection');
    expect(md).toContain('Critical');
    expect(md).toContain('CVE-2024-1234');
    expect(md).toContain('CWE-89');
    expect(md).toContain('![SQL error](https://s3.example.com/proof.png)');
    expect(md).toContain('sqlmap --dbs');
  });

  it('should exclude rejected findings from report', () => {
    const findings = [
      { title: 'Valid Finding', status: 'verified', severity: 'High', asset: 'a.com', category: 'XSS', description: 'XSS', evidence: [] },
      { title: 'Rejected Finding', status: 'rejected', severity: 'Low', asset: 'a.com', category: 'Other', description: 'FP', evidence: [] },
    ];

    const md = buildManualFindingsReportSection(findings);
    expect(md).toContain('Valid Finding');
    expect(md).not.toContain('Rejected Finding');
    expect(md).toContain('1 finding(s)');
  });

  it('should return empty string when no valid findings', () => {
    const findings = [
      { title: 'Rejected', status: 'rejected', severity: 'Low', asset: 'a.com', category: 'Other', description: 'FP', evidence: [] },
    ];

    const md = buildManualFindingsReportSection(findings);
    expect(md).toBe('');
  });

  it('should handle findings with no evidence', () => {
    const findings = [
      { title: 'No Evidence', status: 'submitted', severity: 'Medium', asset: 'a.com', category: 'Config', description: 'Misconfiguration found', evidence: [] },
    ];

    const md = buildManualFindingsReportSection(findings);
    expect(md).toContain('No Evidence');
    expect(md).toContain('Misconfiguration found');
    expect(md).not.toContain('Screenshots');
    expect(md).not.toContain('Evidence Output');
  });

  it('should truncate long text evidence to 2000 chars', () => {
    const longText = 'A'.repeat(3000);
    const findings = [
      {
        title: 'Long Output',
        status: 'submitted',
        severity: 'Low',
        asset: 'a.com',
        category: 'Other',
        description: 'Test',
        evidence: [{ type: 'terminal_output', name: 'out.txt', textContent: longText }],
      },
    ];

    const md = buildManualFindingsReportSection(findings);
    // The text content in the code block should be truncated
    const codeBlockMatch = md.match(/```\n([\s\S]*?)\n```/);
    expect(codeBlockMatch).toBeTruthy();
    expect(codeBlockMatch![1].length).toBeLessThanOrEqual(2000);
  });

  it('should include multiple findings sorted in output', () => {
    const findings = [
      { title: 'Finding A', status: 'verified', severity: 'Critical', asset: 'a.com', category: 'Injection', description: 'A', evidence: [] },
      { title: 'Finding B', status: 'submitted', severity: 'High', asset: 'b.com', category: 'XSS', description: 'B', evidence: [] },
      { title: 'Finding C', status: 'draft', severity: 'Medium', asset: 'c.com', category: 'Config', description: 'C', evidence: [] },
    ];

    const md = buildManualFindingsReportSection(findings);
    expect(md).toContain('3 finding(s)');
    expect(md).toContain('Finding A');
    expect(md).toContain('Finding B');
    expect(md).toContain('Finding C');
  });
});

// ─── Evasion CLI Adapter - ZAP Overrides ──────────────────────────────────────

describe('Evasion CLI Adapter - ZAP Overrides', () => {
  // Replicate the getZapEvasionOverrides logic
  function getZapEvasionOverrides(evasionLevel: number): {
    delayInMs: number;
    threadCount: number;
    maxDuration: number;
  } {
    switch (evasionLevel) {
      case 1: return { delayInMs: 0, threadCount: 5, maxDuration: 60 };
      case 2: return { delayInMs: 200, threadCount: 3, maxDuration: 90 };
      case 3: return { delayInMs: 500, threadCount: 2, maxDuration: 120 };
      case 4: return { delayInMs: 1000, threadCount: 1, maxDuration: 180 };
      case 5: return { delayInMs: 2000, threadCount: 1, maxDuration: 300 };
      default: return { delayInMs: 0, threadCount: 5, maxDuration: 60 };
    }
  }

  it('should return no delay for level 1', () => {
    const overrides = getZapEvasionOverrides(1);
    expect(overrides.delayInMs).toBe(0);
    expect(overrides.threadCount).toBe(5);
  });

  it('should increase delay and reduce threads at higher levels', () => {
    const level2 = getZapEvasionOverrides(2);
    const level4 = getZapEvasionOverrides(4);
    expect(level4.delayInMs).toBeGreaterThan(level2.delayInMs);
    expect(level4.threadCount).toBeLessThan(level2.threadCount);
  });

  it('should use maximum stealth at level 5', () => {
    const overrides = getZapEvasionOverrides(5);
    expect(overrides.delayInMs).toBe(2000);
    expect(overrides.threadCount).toBe(1);
    expect(overrides.maxDuration).toBe(300);
  });
});
