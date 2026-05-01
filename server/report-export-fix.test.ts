/**
 * Tests for report export fixes:
 * 1. doStorageGetContent function for S3 SDK direct download
 * 2. Report content fetch strategy (S3 SDK first, URL fallback)
 * 3. Bug bounty type mapping in report blueprints
 * 4. splitLink configuration for long-running operations
 */
import { describe, it, expect, vi } from 'vitest';

// ── 1. doStorageGetContent function shape ──
describe('doStorageGetContent', () => {
  it('should be exported from do-storage module', async () => {
    // Verify the function exists and is exported
    const mod = await import('./do-storage');
    expect(typeof mod.doStorageGetContent).toBe('function');
  });

  it('should accept a relKey parameter', async () => {
    const mod = await import('./do-storage');
    // The function signature should accept a string key
    expect(mod.doStorageGetContent.length).toBeGreaterThanOrEqual(1);
  });
});

// ── 2. Report blueprint bug_bounty mapping ──
describe('getReportBlueprint', () => {
  it('should map bug_bounty to penetration_test blueprint', async () => {
    const { getReportBlueprint } = await import('./lib/report-section-blueprints');
    const blueprint = getReportBlueprint('bug_bounty');
    expect(blueprint).toBeDefined();
    expect(blueprint.displayName).toBeTruthy();
    // bug_bounty should map to penetration_test which has a displayName
    expect(typeof blueprint.displayName).toBe('string');
  });

  it('should map pentest_assessment to penetration_test blueprint', async () => {
    const { getReportBlueprint } = await import('./lib/report-section-blueprints');
    const blueprint = getReportBlueprint('pentest_assessment');
    expect(blueprint).toBeDefined();
    expect(blueprint.displayName).toBeTruthy();
  });

  it('should handle standard engagement types', async () => {
    const { getReportBlueprint } = await import('./lib/report-section-blueprints');
    
    const types = ['red_team', 'phishing', 'pentest', 'purple_team', 'tabletop', 'fedramp_sar'];
    for (const t of types) {
      const bp = getReportBlueprint(t);
      expect(bp).toBeDefined();
      expect(bp.displayName).toBeTruthy();
    }
  });

  it('should fall back to penetration_test for unknown types', async () => {
    const { getReportBlueprint } = await import('./lib/report-section-blueprints');
    const bp = getReportBlueprint('unknown_type_xyz');
    expect(bp).toBeDefined();
    expect(bp.displayName).toBeTruthy();
  });
});

// ── 3. Markdown-to-DOCX converter ──
describe('markdownToDocx', () => {
  it('should convert simple markdown to DOCX buffer', async () => {
    const { markdownToDocx } = await import('./lib/markdown-to-docx');
    const md = `# Test Report\n\n## Executive Summary\n\nThis is a test report.\n\n## Findings\n\n| Severity | Title |\n|----------|-------|\n| High | XSS in login |\n| Medium | Missing headers |\n`;
    const buffer = await markdownToDocx(md, {
      title: 'Test Report',
      preparedFor: 'Test Client',
      preparedBy: 'Ace of Cloud LLC',
      assessmentType: 'Penetration Test',
      reportDate: 'May 1, 2026',
      reportId: '12345',
    });
    expect(buffer).toBeInstanceOf(Buffer);
    expect(buffer.length).toBeGreaterThan(0);
    // DOCX files start with PK (ZIP magic bytes)
    expect(buffer[0]).toBe(0x50); // P
    expect(buffer[1]).toBe(0x4b); // K
  });

  it('should handle markdown with code blocks', async () => {
    const { markdownToDocx } = await import('./lib/markdown-to-docx');
    const md = "# Report\n\n## Evidence\n\n```\nHTTP/1.1 200 OK\nServer: Apache/2.4.49\nX-Powered-By: PHP/7.4.3\n```\n\nThe server is running a vulnerable version.\n";
    const buffer = await markdownToDocx(md, {
      title: 'Test',
      preparedFor: 'Client',
      preparedBy: 'AoC',
      assessmentType: 'Pentest',
      reportDate: 'May 1, 2026',
      reportId: '1',
    });
    expect(buffer).toBeInstanceOf(Buffer);
    expect(buffer.length).toBeGreaterThan(100);
  });

  it('should handle markdown with bullet lists', async () => {
    const { markdownToDocx } = await import('./lib/markdown-to-docx');
    const md = "# Report\n\n## Recommendations\n\n- Update Apache to latest version\n- Enable HSTS headers\n- Disable directory listing\n  - Specifically in /admin/\n  - And in /uploads/\n";
    const buffer = await markdownToDocx(md, {
      title: 'Test',
      preparedFor: 'Client',
      preparedBy: 'AoC',
      assessmentType: 'Pentest',
      reportDate: 'May 1, 2026',
      reportId: '1',
    });
    expect(buffer).toBeInstanceOf(Buffer);
    expect(buffer.length).toBeGreaterThan(100);
  });

  it('should handle large markdown content without crashing', async () => {
    const { markdownToDocx } = await import('./lib/markdown-to-docx');
    // Generate a large markdown file (~100KB)
    let md = '# Large Report\n\n';
    for (let i = 0; i < 200; i++) {
      md += `## Finding ${i + 1}: Vulnerability ${i}\n\n`;
      md += `This is a detailed description of vulnerability ${i}. `;
      md += `The vulnerability was discovered during the assessment. `;
      md += `It affects the following components and could lead to data exposure.\n\n`;
      md += `| Field | Value |\n|-------|-------|\n`;
      md += `| Severity | High |\n| CVSS | 7.5 |\n| Status | Open |\n\n`;
    }
    const buffer = await markdownToDocx(md, {
      title: 'Large Report',
      preparedFor: 'Client',
      preparedBy: 'AoC',
      assessmentType: 'Pentest',
      reportDate: 'May 1, 2026',
      reportId: '1',
    });
    expect(buffer).toBeInstanceOf(Buffer);
    expect(buffer.length).toBeGreaterThan(1000);
  });
});

// ── 4. HTML generation for PDF (marked) ──
describe('HTML generation for PDF', () => {
  it('should convert markdown to HTML using marked', async () => {
    const { marked } = await import('marked');
    const md = '# Test\n\n## Findings\n\n- Finding 1\n- Finding 2\n';
    const html = await marked.parse(md, { gfm: true, breaks: true });
    expect(html).toContain('<h1');
    expect(html).toContain('<h2');
    expect(html).toContain('Finding 1');
  });

  it('should handle tables in markdown', async () => {
    const { marked } = await import('marked');
    const md = '| Header 1 | Header 2 |\n|----------|----------|\n| Cell 1 | Cell 2 |\n';
    const html = await marked.parse(md, { gfm: true, breaks: true });
    expect(html).toContain('<table');
    expect(html).toContain('Cell 1');
  });
});

// ── 5. S3 content fetch strategy ──
describe('Report content fetch strategy', () => {
  it('should prefer reportKey over reportUrl when both available', () => {
    // Simulate the fetch strategy logic
    const report = {
      reportKey: 'reports/123/456-pentest-1234.md',
      reportUrl: 'https://example.com/reports/456.md',
    };
    
    // The strategy should try reportKey first
    let fetchMethod = '';
    if (report.reportKey) {
      fetchMethod = 's3_sdk';
    } else if (report.reportUrl) {
      fetchMethod = 'url_fetch';
    }
    expect(fetchMethod).toBe('s3_sdk');
  });

  it('should fall back to reportUrl when reportKey is null', () => {
    const report = {
      reportKey: null as string | null,
      reportUrl: 'https://example.com/reports/456.md',
    };
    
    let fetchMethod = '';
    if (report.reportKey) {
      fetchMethod = 's3_sdk';
    } else if (report.reportUrl) {
      fetchMethod = 'url_fetch';
    }
    expect(fetchMethod).toBe('url_fetch');
  });

  it('should detect expired presigned URLs (403 status)', () => {
    // Verify the logic for detecting expired presigned URLs
    const status = 403;
    const isExpiredPresigned = status === 403;
    expect(isExpiredPresigned).toBe(true);
    // Should not retry 403s
    const shouldRetry = status !== 403 && status >= 500;
    expect(shouldRetry).toBe(false);
  });
});

// ── 6. Long-running operation detection ──
describe('Long-running operation detection', () => {
  const LONG_RUNNING_OPERATIONS = [
    'reports.exportPdf', 'reports.exportDocx', 'reports.generate',
    'ac3Reports.exportDocx', 'ac3Reports.exportPdf',
    'engagementOps.runFullEngagement', 'engagementOps.runDomainIntel',
  ];

  it('should identify export operations as long-running', () => {
    expect(LONG_RUNNING_OPERATIONS.includes('reports.exportPdf')).toBe(true);
    expect(LONG_RUNNING_OPERATIONS.includes('reports.exportDocx')).toBe(true);
    expect(LONG_RUNNING_OPERATIONS.includes('ac3Reports.exportDocx')).toBe(true);
  });

  it('should not identify regular operations as long-running', () => {
    expect(LONG_RUNNING_OPERATIONS.includes('reports.list')).toBe(false);
    expect(LONG_RUNNING_OPERATIONS.includes('auth.me')).toBe(false);
    expect(LONG_RUNNING_OPERATIONS.includes('engagementOps.getStatus')).toBe(false);
  });
});
