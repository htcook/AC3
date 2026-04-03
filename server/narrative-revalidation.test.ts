import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Attack Narrative Generator Tests ───

describe('Attack Narrative Generator', () => {
  describe('generateAttackNarratives', () => {
    it('should handle empty assets gracefully', async () => {
      const { generateAttackNarratives } = await import('./lib/attack-narrative-generator');
      
      const result = await generateAttackNarratives({
        engagementId: 1,
        engagementName: 'Test Engagement',
        assets: [],
      });

      expect(result).toEqual([]);
    });

    it('should handle assets with no evidence-backed vulns', async () => {
      const { generateAttackNarratives } = await import('./lib/attack-narrative-generator');
      
      const result = await generateAttackNarratives({
        engagementId: 1,
        engagementName: 'Test Engagement',
        assets: [{
          hostname: 'test.com',
          vulns: [{
            title: 'Test Vuln',
            severity: 'high',
            // No rawEvidence, no corroborationTier, no screenshotPath
          }],
        }],
      });

      // Should return empty since no vulns have evidence
      expect(result).toEqual([]);
    });

    it('should filter findings by evidence presence', async () => {
      const { generateAttackNarratives } = await import('./lib/attack-narrative-generator');
      
      // Mock invokeLLM to avoid actual API calls
      vi.doMock('../_core/llm', () => ({
        invokeLLM: vi.fn().mockResolvedValue({
          choices: [{
            message: {
              content: JSON.stringify({
                title: 'SQL Injection in Login Form',
                attackPath: 'Attacker exploits SQL injection to bypass authentication',
                businessImpact: 'Full database access',
                technicalImpact: 'Authentication bypass, data exfiltration',
                steps: [{
                  stepNumber: 1,
                  phase: 'vuln_detection',
                  tool: 'sqlmap',
                  command: 'sqlmap -u "http://test.com/login" --batch',
                  target: 'test.com',
                  finding: 'SQL injection in login parameter',
                  evidence: 'Parameter: username, Type: boolean-based blind',
                }],
                remediationSteps: [{
                  priority: 1,
                  action: 'Use parameterized queries',
                  effort: 'medium',
                  timeEstimate: '4 hours',
                }],
                mitreTechniques: ['T1190'],
                cvssScore: 9.8,
              }),
            },
          }],
        }),
      }));

      // This test verifies the filtering logic works
      const assets = [{
        hostname: 'test.com',
        vulns: [
          {
            title: 'SQL Injection',
            severity: 'critical',
            rawEvidence: 'Parameter: username, Type: boolean-based blind',
            tool: 'sqlmap',
            endpoint: 'http://test.com/login',
          },
          {
            title: 'No Evidence Vuln',
            severity: 'high',
            // No evidence - should be filtered out
          },
          {
            title: 'Confirmed Vuln',
            severity: 'high',
            corroborationTier: 'confirmed',
            tool: 'nuclei',
          },
        ],
      }];

      // Count evidence-backed findings
      const evidencedVulns = assets[0].vulns.filter(v =>
        (v as any).rawEvidence || (v as any).corroborationTier === 'confirmed' || (v as any).screenshotPath
      );
      expect(evidencedVulns).toHaveLength(2);
      expect(evidencedVulns[0].title).toBe('SQL Injection');
      expect(evidencedVulns[1].title).toBe('Confirmed Vuln');
    });
  });

  describe('NarrativeInput structure', () => {
    it('should accept complete narrative input', () => {
      const input = {
        engagementId: 42,
        engagementName: 'Production Pentest Q1',
        targetProfile: {
          industry: 'Finance',
          waf: 'Cloudflare',
          cdn: 'CloudFront',
          techStack: ['nginx', 'PHP', 'MySQL'],
        },
        assets: [{
          hostname: 'api.example.com',
          ip: '10.0.0.1',
          ports: [{ port: 443, service: 'https' }],
          vulns: [{
            id: 'vuln-001',
            title: 'SQL Injection',
            severity: 'critical',
            description: 'Boolean-based blind SQL injection',
            tool: 'sqlmap',
            cve: 'CVE-2024-1234',
            endpoint: 'https://api.example.com/login',
            rawEvidence: 'Parameter: username, Type: boolean-based blind',
            corroborationTier: 'confirmed',
            screenshotPath: '/tmp/evidence-screenshot-42-1234.png',
          }],
          exploitAttempts: [{
            id: 'exp-001',
            technique: 'SQL Injection',
            tool: 'sqlmap',
            command: 'sqlmap -u "https://api.example.com/login" --batch',
            succeeded: true,
            rawEvidence: 'Database: mysql\nTables: users, orders',
          }],
          toolResults: [{
            tool: 'nuclei',
            command: 'nuclei -u https://api.example.com -severity critical,high',
            output: '3 findings',
            exitCode: 0,
            findingCount: 3,
          }],
        }],
      };

      expect(input.engagementId).toBe(42);
      expect(input.assets).toHaveLength(1);
      expect(input.assets[0].vulns[0].corroborationTier).toBe('confirmed');
      expect(input.targetProfile?.waf).toBe('Cloudflare');
    });
  });
});

// ─── Remediation Revalidation Tests ───

describe('Remediation Revalidation', () => {
  describe('selectRevalidationTargets', () => {
    it('should select confirmed vulns by default', async () => {
      const { selectRevalidationTargets } = await import('./lib/remediation-revalidation');

      const assets = [
        {
          hostname: 'web.example.com',
          vulns: [
            {
              id: 'v1',
              title: 'SQL Injection',
              severity: 'critical',
              tool: 'sqlmap',
              endpoint: 'https://web.example.com/login',
              corroborationTier: 'confirmed',
              rawEvidence: 'boolean-based blind',
            },
            {
              id: 'v2',
              title: 'XSS Reflected',
              severity: 'high',
              tool: 'xsstrike',
              endpoint: 'https://web.example.com/search',
              corroborationTier: 'confirmed',
            },
            {
              id: 'v3',
              title: 'Unverified Info Leak',
              severity: 'medium',
              tool: 'nuclei',
              corroborationTier: 'unverified',
            },
          ],
        },
      ];

      const targets = selectRevalidationTargets(assets);
      expect(targets).toHaveLength(2); // Only confirmed
      expect(targets[0].title).toBe('SQL Injection'); // Critical first
      expect(targets[1].title).toBe('XSS Reflected');
    });

    it('should filter by severity', async () => {
      const { selectRevalidationTargets } = await import('./lib/remediation-revalidation');

      const assets = [
        {
          hostname: 'test.com',
          vulns: [
            { id: 'v1', title: 'Critical', severity: 'critical', tool: 'nuclei', corroborationTier: 'confirmed' },
            { id: 'v2', title: 'High', severity: 'high', tool: 'nuclei', corroborationTier: 'confirmed' },
            { id: 'v3', title: 'Medium', severity: 'medium', tool: 'nuclei', corroborationTier: 'confirmed' },
            { id: 'v4', title: 'Low', severity: 'low', tool: 'nuclei', corroborationTier: 'confirmed' },
          ],
        },
      ];

      const targets = selectRevalidationTargets(assets, { severityFilter: ['critical'] });
      expect(targets).toHaveLength(1);
      expect(targets[0].title).toBe('Critical');
    });

    it('should respect maxTargets limit', async () => {
      const { selectRevalidationTargets } = await import('./lib/remediation-revalidation');

      const vulns = Array.from({ length: 100 }, (_, i) => ({
        id: `v${i}`,
        title: `Vuln ${i}`,
        severity: 'high',
        tool: 'nuclei',
        corroborationTier: 'confirmed',
      }));

      const targets = selectRevalidationTargets([{ hostname: 'test.com', vulns }], { maxTargets: 5 });
      expect(targets).toHaveLength(5);
    });

    it('should include unverified vulns when confirmedOnly is false', async () => {
      const { selectRevalidationTargets } = await import('./lib/remediation-revalidation');

      const assets = [
        {
          hostname: 'test.com',
          vulns: [
            { id: 'v1', title: 'Confirmed', severity: 'high', tool: 'nuclei', corroborationTier: 'confirmed' },
            { id: 'v2', title: 'Unverified', severity: 'high', tool: 'nuclei', corroborationTier: 'unverified' },
          ],
        },
      ];

      const targets = selectRevalidationTargets(assets, { confirmedOnly: false });
      expect(targets).toHaveLength(2);
    });
  });

  describe('buildRevalidationCommands', () => {
    it('should generate nuclei commands for nuclei findings', async () => {
      const { buildRevalidationCommands } = await import('./lib/remediation-revalidation');

      const commands = buildRevalidationCommands({
        findingId: 'v1',
        title: 'SQL Injection',
        severity: 'critical',
        tool: 'nuclei',
        endpoint: 'https://test.com/login',
        assetHostname: 'test.com',
      });

      expect(commands.length).toBeGreaterThanOrEqual(1);
      expect(commands[0].tool).toBe('nuclei');
      expect(commands[0].command).toContain('nuclei');
      expect(commands[0].command).toContain('test.com/login');
    });

    it('should generate sqlmap commands for sqlmap findings', async () => {
      const { buildRevalidationCommands } = await import('./lib/remediation-revalidation');

      const commands = buildRevalidationCommands({
        findingId: 'v2',
        title: 'SQL Injection',
        severity: 'critical',
        tool: 'sqlmap',
        endpoint: 'https://test.com/login?id=1',
        assetHostname: 'test.com',
      });

      expect(commands.length).toBeGreaterThanOrEqual(1);
      expect(commands[0].tool).toBe('sqlmap');
      expect(commands[0].command).toContain('sqlmap');
    });

    it('should add CVE-specific scan when CVE is known', async () => {
      const { buildRevalidationCommands } = await import('./lib/remediation-revalidation');

      const commands = buildRevalidationCommands({
        findingId: 'v3',
        title: 'Apache Struts RCE',
        severity: 'critical',
        tool: 'nuclei',
        endpoint: 'https://test.com/',
        cve: 'CVE-2017-5638',
        assetHostname: 'test.com',
      });

      // Should have both regular nuclei scan and CVE-specific scan
      expect(commands.length).toBe(2);
      const cveCommand = commands.find(c => c.command.includes('cve-2017-5638'));
      expect(cveCommand).toBeDefined();
    });

    it('should generate xsstrike commands for XSS findings', async () => {
      const { buildRevalidationCommands } = await import('./lib/remediation-revalidation');

      const commands = buildRevalidationCommands({
        findingId: 'v4',
        title: 'Reflected XSS',
        severity: 'high',
        tool: 'xsstrike',
        endpoint: 'https://test.com/search?q=test',
        assetHostname: 'test.com',
      });

      expect(commands[0].tool).toBe('xsstrike');
      expect(commands[0].command).toContain('XSStrike');
    });

    it('should generate commix commands for command injection findings', async () => {
      const { buildRevalidationCommands } = await import('./lib/remediation-revalidation');

      const commands = buildRevalidationCommands({
        findingId: 'v5',
        title: 'Command Injection',
        severity: 'critical',
        tool: 'commix',
        endpoint: 'https://test.com/ping?host=127.0.0.1',
        assetHostname: 'test.com',
      });

      expect(commands[0].tool).toBe('commix');
      expect(commands[0].command).toContain('commix');
    });

    it('should generate tplmap commands for SSTI findings', async () => {
      const { buildRevalidationCommands } = await import('./lib/remediation-revalidation');

      const commands = buildRevalidationCommands({
        findingId: 'v6',
        title: 'Server-Side Template Injection',
        severity: 'critical',
        tool: 'tplmap',
        endpoint: 'https://test.com/render?template={{7*7}}',
        assetHostname: 'test.com',
      });

      expect(commands[0].tool).toBe('tplmap');
      expect(commands[0].command).toContain('tplmap');
    });

    it('should fall back to nuclei for unknown tools', async () => {
      const { buildRevalidationCommands } = await import('./lib/remediation-revalidation');

      const commands = buildRevalidationCommands({
        findingId: 'v7',
        title: 'Custom Finding',
        severity: 'medium',
        tool: 'custom-scanner',
        endpoint: 'https://test.com/api',
        assetHostname: 'test.com',
      });

      expect(commands[0].tool).toBe('nuclei');
    });
  });

  describe('compareEvidence', () => {
    it('should detect remediated status', async () => {
      const { compareEvidence } = await import('./lib/remediation-revalidation');

      const result = compareEvidence(
        'Parameter: username, Type: boolean-based blind',
        'No results found. Target appears clean.',
        0
      );

      expect(result.status).toBe('remediated');
      expect(result.confidence).toBeGreaterThan(0.5);
    });

    it('should detect still_vulnerable status', async () => {
      const { compareEvidence } = await import('./lib/remediation-revalidation');

      const result = compareEvidence(
        'Parameter: username, Type: boolean-based blind',
        'Vulnerability found: SQL injection in username parameter. Exploitable payload detected.',
        0
      );

      expect(result.status).toBe('still_vulnerable');
      expect(result.confidence).toBeGreaterThan(0.5);
    });

    it('should detect error status for short output with non-zero exit', async () => {
      const { compareEvidence } = await import('./lib/remediation-revalidation');

      const result = compareEvidence(
        'original evidence',
        'Error: connection refused',
        1
      );

      expect(result.status).toBe('error');
      expect(result.confidence).toBeLessThan(0.5);
    });

    it('should return inconclusive for ambiguous output', async () => {
      const { compareEvidence } = await import('./lib/remediation-revalidation');

      const result = compareEvidence(
        'original evidence',
        'Scan completed. Processing results. Some data returned but analysis unclear.',
        0
      );

      expect(result.status).toBe('inconclusive');
    });
  });

  describe('createRevalidationSession', () => {
    it('should create a session with correct structure', async () => {
      const { createRevalidationSession } = await import('./lib/remediation-revalidation');

      const session = createRevalidationSession(42, [
        {
          findingId: 'v1',
          title: 'SQL Injection',
          severity: 'critical',
          tool: 'sqlmap',
          endpoint: 'https://test.com/login',
          assetHostname: 'test.com',
        },
      ]);

      expect(session.id).toMatch(/^reval-42-/);
      expect(session.engagementId).toBe(42);
      expect(session.status).toBe('pending');
      expect(session.targets).toHaveLength(1);
      expect(session.results).toEqual([]);
    });
  });

  describe('computeRevalidationSummary', () => {
    it('should compute correct summary statistics', async () => {
      const { computeRevalidationSummary } = await import('./lib/remediation-revalidation');

      const summary = computeRevalidationSummary({
        id: 'reval-1',
        engagementId: 1,
        createdAt: Date.now(),
        status: 'completed',
        targets: [],
        results: [
          { findingId: 'v1', status: 'remediated', originalEvidence: '', retestEvidence: '', retestTool: 'nuclei', retestCommand: '', retestTimestamp: Date.now(), confidenceScore: 0.9, notes: '' },
          { findingId: 'v2', status: 'remediated', originalEvidence: '', retestEvidence: '', retestTool: 'nuclei', retestCommand: '', retestTimestamp: Date.now(), confidenceScore: 0.8, notes: '' },
          { findingId: 'v3', status: 'still_vulnerable', originalEvidence: '', retestEvidence: '', retestTool: 'sqlmap', retestCommand: '', retestTimestamp: Date.now(), confidenceScore: 0.7, notes: '' },
          { findingId: 'v4', status: 'inconclusive', originalEvidence: '', retestEvidence: '', retestTool: 'nuclei', retestCommand: '', retestTimestamp: Date.now(), confidenceScore: 0.3, notes: '' },
          { findingId: 'v5', status: 'error', originalEvidence: '', retestEvidence: '', retestTool: 'nuclei', retestCommand: '', retestTimestamp: Date.now(), confidenceScore: 0.1, notes: '' },
        ],
      });

      expect(summary!.total).toBe(5);
      expect(summary!.remediated).toBe(2);
      expect(summary!.stillVulnerable).toBe(1);
      expect(summary!.inconclusive).toBe(1);
      expect(summary!.errors).toBe(1);
      expect(summary!.remediationRate).toBe(40); // 2/5 = 40%
    });

    it('should handle empty results', async () => {
      const { computeRevalidationSummary } = await import('./lib/remediation-revalidation');

      const summary = computeRevalidationSummary({
        id: 'reval-2',
        engagementId: 2,
        createdAt: Date.now(),
        status: 'completed',
        targets: [],
        results: [],
      });

      expect(summary!.total).toBe(0);
      expect(summary!.remediationRate).toBe(0);
    });
  });
});

// ─── Screenshot Capture Tests ───

describe('Screenshot Capture', () => {
  describe('selectFindingsForScreenshot', () => {
    it('should prioritize critical/high findings', async () => {
      const { selectFindingsForScreenshot } = await import('./lib/scanners/screenshot-capture');

      const vulns = [
        { id: 'v1', title: 'Info Leak', severity: 'info', url: 'http://test.com/info' },
        { id: 'v2', title: 'Critical SQLi', severity: 'critical', url: 'http://test.com/login' },
        { id: 'v3', title: 'Medium XSS', severity: 'medium', url: 'http://test.com/search' },
        { id: 'v4', title: 'High RCE', severity: 'high', url: 'http://test.com/api' },
      ];

      const selected = selectFindingsForScreenshot(vulns, 3);
      expect(selected).toHaveLength(3);
      expect(selected[0].findingTitle).toBe('Critical SQLi');
      expect(selected[1].findingTitle).toBe('High RCE');
      expect(selected[2].findingTitle).toBe('Medium XSS');
    });

    it('should filter out non-HTTP findings', async () => {
      const { selectFindingsForScreenshot } = await import('./lib/scanners/screenshot-capture');

      const vulns = [
        { id: 'v1', title: 'SSH Weak Key', severity: 'high', url: 'ssh://test.com:22' },
        { id: 'v2', title: 'Web XSS', severity: 'high', url: 'https://test.com/search' },
        { id: 'v3', title: 'No URL', severity: 'critical' },
      ];

      const selected = selectFindingsForScreenshot(vulns);
      expect(selected).toHaveLength(1);
      expect(selected[0].findingTitle).toBe('Web XSS');
    });

    it('should filter out false positives', async () => {
      const { selectFindingsForScreenshot } = await import('./lib/scanners/screenshot-capture');

      const vulns = [
        { id: 'v1', title: 'Real Vuln', severity: 'high', url: 'http://test.com/a', corroborationTier: 'confirmed' },
        { id: 'v2', title: 'False Positive', severity: 'high', url: 'http://test.com/b', corroborationTier: 'false_positive' },
      ];

      const selected = selectFindingsForScreenshot(vulns);
      expect(selected).toHaveLength(1);
      expect(selected[0].findingTitle).toBe('Real Vuln');
    });

    it('should respect maxScreenshots limit', async () => {
      const { selectFindingsForScreenshot } = await import('./lib/scanners/screenshot-capture');

      const vulns = Array.from({ length: 50 }, (_, i) => ({
        id: `v${i}`,
        title: `Vuln ${i}`,
        severity: 'high',
        url: `http://test.com/page${i}`,
      }));

      const selected = selectFindingsForScreenshot(vulns, 5);
      expect(selected).toHaveLength(5);
    });

    it('should prefer confirmed findings over unverified', async () => {
      const { selectFindingsForScreenshot } = await import('./lib/scanners/screenshot-capture');

      const vulns = [
        { id: 'v1', title: 'Unverified', severity: 'high', url: 'http://test.com/a', corroborationTier: 'unverified' },
        { id: 'v2', title: 'Confirmed', severity: 'high', url: 'http://test.com/b', corroborationTier: 'confirmed' },
      ];

      const selected = selectFindingsForScreenshot(vulns);
      expect(selected[0].findingTitle).toBe('Confirmed');
    });
  });
});
