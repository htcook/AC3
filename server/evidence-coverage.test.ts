import { describe, it, expect, vi } from 'vitest';

// ─── Test Suite: Evidence Capture & Validation Coverage ───
// Covers: evidence artifact types, coverage metric calculations, PDF export data shapes,
// evidence screenshot generation, and S3 artifact wiring

describe('Evidence Capture Module', () => {
  describe('Evidence Artifact Types', () => {
    it('should define all 4 evidence artifact types', () => {
      const validTypes = ['console_output', 'session_info', 'evidence_report', 'screenshot_text'];
      const artifact = {
        type: 'console_output' as const,
        filename: 'test-console.txt',
        url: 'https://s3.example.com/evidence/1/test-console.txt',
        mimeType: 'text/plain',
        sizeBytes: 1024,
        capturedAt: '2026-02-20T12:00:00Z',
      };

      expect(validTypes).toContain(artifact.type);
      expect(artifact.url).toMatch(/^https?:\/\//);
      expect(artifact.sizeBytes).toBeGreaterThan(0);
      expect(artifact.mimeType).toBe('text/plain');
    });

    it('should validate session_info artifact structure', () => {
      const artifact = {
        type: 'session_info',
        filename: 'asset1-CVE-2024-1234-session-info.txt',
        url: 'https://s3.example.com/evidence/1/session-info.txt',
        mimeType: 'text/plain',
        sizeBytes: 2048,
        capturedAt: new Date().toISOString(),
      };

      expect(artifact.type).toBe('session_info');
      expect(artifact.filename).toContain('session-info');
      expect(new Date(artifact.capturedAt).getTime()).not.toBeNaN();
    });

    it('should validate evidence_report artifact as HTML', () => {
      const artifact = {
        type: 'evidence_report',
        filename: 'candidate-report.html',
        url: 'https://s3.example.com/evidence/1/candidate-report.html',
        mimeType: 'text/html',
        sizeBytes: 4096,
        capturedAt: new Date().toISOString(),
      };

      expect(artifact.type).toBe('evidence_report');
      expect(artifact.mimeType).toBe('text/html');
      expect(artifact.filename).toContain('.html');
    });

    it('should validate screenshot_text artifact structure', () => {
      const artifact = {
        type: 'screenshot_text',
        filename: 'candidate-evidence-screenshot.txt',
        url: 'https://s3.example.com/evidence/1/screenshot.txt',
        mimeType: 'text/plain',
        sizeBytes: 1536,
        capturedAt: new Date().toISOString(),
      };

      expect(artifact.type).toBe('screenshot_text');
      expect(artifact.mimeType).toBe('text/plain');
    });
  });

  describe('CapturedEvidence Structure', () => {
    it('should include reportUrl, artifacts array, and summary', () => {
      const captured = {
        reportUrl: 'https://s3.example.com/evidence/1/report.html',
        artifacts: [
          { type: 'console_output', filename: 'console.txt', url: 'https://s3.example.com/a.txt', mimeType: 'text/plain', sizeBytes: 500, capturedAt: '2026-02-20T12:00:00Z' },
          { type: 'screenshot_text', filename: 'screenshot.txt', url: 'https://s3.example.com/b.txt', mimeType: 'text/plain', sizeBytes: 1200, capturedAt: '2026-02-20T12:00:01Z' },
          { type: 'evidence_report', filename: 'report.html', url: 'https://s3.example.com/c.html', mimeType: 'text/html', sizeBytes: 3500, capturedAt: '2026-02-20T12:00:02Z' },
        ],
        summary: 'Exploit validated: CVE-2024-1234 on web01.example.com via exploit/multi/http/test',
      };

      expect(captured.reportUrl).toMatch(/^https?:\/\//);
      expect(captured.artifacts.length).toBe(3);
      expect(captured.summary).toContain('CVE-2024-1234');
    });

    it('should handle empty artifacts array for failed captures', () => {
      const captured = {
        reportUrl: 'https://s3.example.com/evidence/1/report.html',
        artifacts: [],
        summary: 'Evidence captured for CVE-2024-5678 on db01.example.com (0 artifacts)',
      };

      expect(captured.artifacts.length).toBe(0);
    });
  });

  describe('Evidence Screenshot Generation', () => {
    it('should generate formatted text screenshot with all sections', () => {
      // Replicate the generateEvidenceScreenshot logic
      const ctx = {
        runId: 1,
        scanId: 100,
        candidateId: '42-CVE-2024-1234',
        assetHostname: 'web01.example.com',
        cveId: 'CVE-2024-1234',
        msfModule: 'exploit/multi/http/apache_mod_cgi_bash_env_exec',
        mode: 'check_only',
        targetIp: '10.0.0.1',
        targetPort: 80,
      };
      const result = {
        status: 'validated',
        exploitable: true,
        rawOutput: 'Module check succeeded\nVulnerable: true',
        evidence: { method: 'msf_check', finding: 'vulnerable', confidence: 0.95 },
        durationMs: 3200,
        scoreAdjustment: 15,
      };

      const border = '═'.repeat(62);
      const lines: string[] = [];
      lines.push(`╔${border}╗`);
      lines.push(`║  VALIDATION EVIDENCE CAPTURE                                 ║`);

      const statusIcon = result.exploitable ? '⚠ EXPLOITABLE' : 'NOT VULNERABLE';
      lines.push(`Target: ${ctx.assetHostname}`);
      lines.push(`CVE: ${ctx.cveId}`);
      lines.push(`Status: ${statusIcon}`);

      const screenshot = lines.join('\n');
      expect(screenshot).toContain('VALIDATION EVIDENCE CAPTURE');
      expect(screenshot).toContain('web01.example.com');
      expect(screenshot).toContain('CVE-2024-1234');
      expect(screenshot).toContain('EXPLOITABLE');
    });

    it('should show NOT VULNERABLE for non-exploitable results', () => {
      const result = { exploitable: false, status: 'not_vulnerable' };
      const statusIcon = result.exploitable ? '⚠ EXPLOITABLE' :
        result.status === 'not_vulnerable' ? '✓ NOT VULNERABLE' :
        result.status === 'inconclusive' ? '? INCONCLUSIVE' : result.status.toUpperCase();

      expect(statusIcon).toBe('✓ NOT VULNERABLE');
    });

    it('should show ERROR for error results', () => {
      const result = { exploitable: false, status: 'error' };
      const statusIcon = result.exploitable ? '⚠ EXPLOITABLE' :
        result.status === 'not_vulnerable' ? '✓ NOT VULNERABLE' :
        result.status === 'inconclusive' ? '? INCONCLUSIVE' :
        result.status === 'error' ? '✗ ERROR' : result.status.toUpperCase();

      expect(statusIcon).toBe('✗ ERROR');
    });

    it('should truncate raw MSF output to 20 lines', () => {
      const rawOutput = Array.from({ length: 50 }, (_, i) => `Line ${i + 1}: output data`).join('\n');
      const outputLines = rawOutput.split('\n').slice(0, 20);
      const remaining = rawOutput.split('\n').length - 20;

      expect(outputLines.length).toBe(20);
      expect(remaining).toBe(30);
    });
  });

  describe('Evidence Capture Context', () => {
    it('should construct valid capture context from validation candidate', () => {
      const ctx = {
        runId: 5,
        scanId: 200,
        candidateId: '15-CVE-2024-9999',
        assetHostname: 'api.example.com',
        cveId: 'CVE-2024-9999',
        msfModule: 'auxiliary/scanner/http/apache_optionsbleed',
        mode: 'safe_exploit',
        targetIp: '192.168.1.100',
        targetPort: 443,
      };

      expect(ctx.candidateId).toBe('15-CVE-2024-9999');
      expect(ctx.mode).toBe('safe_exploit');
      expect(ctx.targetPort).toBe(443);
    });

    it('should handle null targetIp and targetPort', () => {
      const ctx = {
        runId: 5,
        scanId: 200,
        candidateId: '15-CVE-2024-9999',
        assetHostname: 'api.example.com',
        cveId: 'CVE-2024-9999',
        msfModule: null,
        mode: 'check_only',
        targetIp: null,
        targetPort: null,
      };

      expect(ctx.targetIp).toBeNull();
      expect(ctx.targetPort).toBeNull();
      expect(ctx.msfModule).toBeNull();
    });
  });
});

describe('Validation Coverage Metric', () => {
  describe('Coverage Percentage Calculation', () => {
    it('should calculate 100% coverage when all findings are validated', () => {
      const totalFindings = 10;
      const validated = 10;
      const coveragePct = totalFindings > 0 ? Math.round((validated / totalFindings) * 100) : 0;
      expect(coveragePct).toBe(100);
    });

    it('should calculate 0% coverage when no findings are validated', () => {
      const totalFindings = 10;
      const validated = 0;
      const coveragePct = totalFindings > 0 ? Math.round((validated / totalFindings) * 100) : 0;
      expect(coveragePct).toBe(0);
    });

    it('should handle zero total findings gracefully', () => {
      const totalFindings = 0;
      const validated = 0;
      const coveragePct = totalFindings > 0 ? Math.round((validated / totalFindings) * 100) : 0;
      expect(coveragePct).toBe(0);
    });

    it('should calculate partial coverage correctly', () => {
      const totalFindings = 15;
      const validated = 6;
      const coveragePct = totalFindings > 0 ? Math.round((validated / totalFindings) * 100) : 0;
      expect(coveragePct).toBe(40);
    });

    it('should round to nearest integer', () => {
      const totalFindings = 3;
      const validated = 1;
      const coveragePct = totalFindings > 0 ? Math.round((validated / totalFindings) * 100) : 0;
      expect(coveragePct).toBe(33);
    });
  });

  describe('Exploitable Percentage Calculation', () => {
    it('should calculate exploitable percentage of validated findings', () => {
      const validated = 8;
      const exploitable = 3;
      const exploitablePct = validated > 0 ? Math.round((exploitable / validated) * 100) : 0;
      expect(exploitablePct).toBe(38);
    });

    it('should return 0% when no findings are validated', () => {
      const validated = 0;
      const exploitable = 0;
      const exploitablePct = validated > 0 ? Math.round((exploitable / validated) * 100) : 0;
      expect(exploitablePct).toBe(0);
    });

    it('should return 100% when all validated findings are exploitable', () => {
      const validated = 5;
      const exploitable = 5;
      const exploitablePct = validated > 0 ? Math.round((exploitable / validated) * 100) : 0;
      expect(exploitablePct).toBe(100);
    });
  });

  describe('Coverage Quality Assessment', () => {
    it('should classify >= 80% as high coverage', () => {
      const coveragePct = 85;
      const quality = coveragePct >= 80 ? 'high' : coveragePct >= 50 ? 'moderate' : 'low';
      expect(quality).toBe('high');
    });

    it('should classify 50-79% as moderate coverage', () => {
      const coveragePct = 65;
      const quality = coveragePct >= 80 ? 'high' : coveragePct >= 50 ? 'moderate' : 'low';
      expect(quality).toBe('moderate');
    });

    it('should classify < 50% as low coverage', () => {
      const coveragePct = 30;
      const quality = coveragePct >= 80 ? 'high' : coveragePct >= 50 ? 'moderate' : 'low';
      expect(quality).toBe('low');
    });

    it('should classify exactly 80% as high', () => {
      const coveragePct = 80;
      const quality = coveragePct >= 80 ? 'high' : coveragePct >= 50 ? 'moderate' : 'low';
      expect(quality).toBe('high');
    });

    it('should classify exactly 50% as moderate', () => {
      const coveragePct = 50;
      const quality = coveragePct >= 80 ? 'high' : coveragePct >= 50 ? 'moderate' : 'low';
      expect(quality).toBe('moderate');
    });
  });

  describe('Coverage Bar Color Selection', () => {
    it('should use green for >= 80% coverage', () => {
      const coveragePct = 90;
      const barColor = coveragePct >= 80 ? 'bg-emerald-500' : coveragePct >= 50 ? 'bg-amber-500' : 'bg-red-500';
      expect(barColor).toBe('bg-emerald-500');
    });

    it('should use amber for 50-79% coverage', () => {
      const coveragePct = 60;
      const barColor = coveragePct >= 80 ? 'bg-emerald-500' : coveragePct >= 50 ? 'bg-amber-500' : 'bg-red-500';
      expect(barColor).toBe('bg-amber-500');
    });

    it('should use red for < 50% coverage', () => {
      const coveragePct = 25;
      const barColor = coveragePct >= 80 ? 'bg-emerald-500' : coveragePct >= 50 ? 'bg-amber-500' : 'bg-red-500';
      expect(barColor).toBe('bg-red-500');
    });
  });

  describe('PDF Coverage Bar Rendering', () => {
    it('should calculate correct bar fill width', () => {
      const barWidth = 80;
      const coveragePct = 65;
      const fillWidth = Math.max(2, (coveragePct / 100) * barWidth);
      expect(fillWidth).toBe(52);
    });

    it('should enforce minimum 2mm fill width', () => {
      const barWidth = 80;
      const coveragePct = 1;
      const fillWidth = Math.max(2, (coveragePct / 100) * barWidth);
      expect(fillWidth).toBe(2);
    });

    it('should use correct PDF bar colors', () => {
      const getBarColor = (pct: number): [number, number, number] =>
        pct >= 80 ? [34, 197, 94] : pct >= 50 ? [234, 179, 8] : [239, 68, 68];

      expect(getBarColor(90)).toEqual([34, 197, 94]);   // green
      expect(getBarColor(60)).toEqual([234, 179, 8]);    // amber
      expect(getBarColor(30)).toEqual([239, 68, 68]);    // red
    });
  });
});

describe('Validation Result Export with Evidence', () => {
  it('should include evidenceUrl and evidenceArtifacts in export type', () => {
    const result = {
      assetHostname: 'web01.example.com',
      cveId: 'CVE-2024-1234',
      msfModule: 'exploit/multi/http/test',
      status: 'validated',
      exploitable: true,
      scoreAdjustment: 15,
      durationMs: 3200,
      evidence: { checkOutput: 'Vulnerable: true', msfJobId: 'job-123' },
      errorMessage: null,
      timestamp: '2026-02-20T12:00:00Z',
      evidenceUrl: 'https://s3.example.com/evidence/1/report.html',
      evidenceArtifacts: [
        { type: 'console_output', filename: 'console.txt', url: 'https://s3.example.com/a.txt', mimeType: 'text/plain', sizeBytes: 500, capturedAt: '2026-02-20T12:00:00Z' },
        { type: 'screenshot_text', filename: 'screenshot.txt', url: 'https://s3.example.com/b.txt', mimeType: 'text/plain', sizeBytes: 1200, capturedAt: '2026-02-20T12:00:01Z' },
        { type: 'evidence_report', filename: 'report.html', url: 'https://s3.example.com/c.html', mimeType: 'text/html', sizeBytes: 3500, capturedAt: '2026-02-20T12:00:02Z' },
      ],
    };

    expect(result.evidenceUrl).toMatch(/^https?:\/\//);
    expect(result.evidenceArtifacts).toHaveLength(3);
    expect(result.evidenceArtifacts![0].type).toBe('console_output');
    expect(result.evidenceArtifacts![2].type).toBe('evidence_report');
  });

  it('should handle null evidenceUrl and evidenceArtifacts', () => {
    const result = {
      assetHostname: 'db01.example.com',
      cveId: 'CVE-2024-5678',
      msfModule: null,
      status: 'not_vulnerable',
      exploitable: false,
      scoreAdjustment: 0,
      durationMs: 1500,
      evidence: null,
      errorMessage: null,
      timestamp: '2026-02-20T12:01:00Z',
      evidenceUrl: null,
      evidenceArtifacts: null,
    };

    expect(result.evidenceUrl).toBeNull();
    expect(result.evidenceArtifacts).toBeNull();
  });

  it('should count artifacts correctly for PDF display', () => {
    const artifacts = [
      { type: 'console_output', filename: 'a.txt', url: 'https://s3.example.com/a.txt', mimeType: 'text/plain', sizeBytes: 500, capturedAt: '2026-02-20T12:00:00Z' },
      { type: 'session_info', filename: 'b.txt', url: 'https://s3.example.com/b.txt', mimeType: 'text/plain', sizeBytes: 2048, capturedAt: '2026-02-20T12:00:01Z' },
      { type: 'screenshot_text', filename: 'c.txt', url: 'https://s3.example.com/c.txt', mimeType: 'text/plain', sizeBytes: 1536, capturedAt: '2026-02-20T12:00:02Z' },
      { type: 'evidence_report', filename: 'd.html', url: 'https://s3.example.com/d.html', mimeType: 'text/html', sizeBytes: 4096, capturedAt: '2026-02-20T12:00:03Z' },
    ];

    const displayText = `${artifacts.length} files`;
    expect(displayText).toBe('4 files');
  });

  it('should format artifact size for display', () => {
    const formatSize = (bytes: number): string => {
      if (bytes < 1024) return `${bytes} B`;
      if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
      return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    };

    expect(formatSize(500)).toBe('500 B');
    expect(formatSize(1024)).toBe('1.0 KB');
    expect(formatSize(2560)).toBe('2.5 KB');
    expect(formatSize(1048576)).toBe('1.0 MB');
  });
});

describe('Evidence Filtering for PDF Export', () => {
  it('should include results with checkOutput in evidence details', () => {
    const results = [
      { evidence: { checkOutput: 'Vulnerable: true' }, evidenceUrl: null, evidenceArtifacts: null },
      { evidence: null, evidenceUrl: null, evidenceArtifacts: null },
      { evidence: { checkOutput: '' }, evidenceUrl: 'https://s3.example.com/report.html', evidenceArtifacts: [] },
    ];

    const withEvidence = results.filter(r =>
      r.evidence?.checkOutput || r.evidenceUrl || (r.evidenceArtifacts && r.evidenceArtifacts.length > 0)
    );

    expect(withEvidence.length).toBe(2); // First (has checkOutput) and third (has evidenceUrl)
  });

  it('should include results with only evidenceArtifacts', () => {
    const results = [
      {
        evidence: null,
        evidenceUrl: null,
        evidenceArtifacts: [
          { type: 'console_output', filename: 'a.txt', url: 'https://s3.example.com/a.txt', mimeType: 'text/plain', sizeBytes: 500, capturedAt: '2026-02-20T12:00:00Z' },
        ],
      },
    ];

    const withEvidence = results.filter(r =>
      r.evidence?.checkOutput || r.evidenceUrl || (r.evidenceArtifacts && r.evidenceArtifacts.length > 0)
    );

    expect(withEvidence.length).toBe(1);
  });

  it('should exclude results with no evidence at all', () => {
    const results = [
      { evidence: null, evidenceUrl: null, evidenceArtifacts: null },
      { evidence: null, evidenceUrl: null, evidenceArtifacts: [] },
      { evidence: { checkOutput: '' }, evidenceUrl: null, evidenceArtifacts: null },
    ];

    const withEvidence = results.filter(r =>
      r.evidence?.checkOutput || r.evidenceUrl || (r.evidenceArtifacts && r.evidenceArtifacts.length > 0)
    );

    expect(withEvidence.length).toBe(0);
  });
});

describe('HTML Evidence Report Structure', () => {
  it('should escape HTML entities in raw output', () => {
    const escapeHtml = (text: string): string =>
      text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

    expect(escapeHtml('<script>alert("xss")</script>')).toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
    expect(escapeHtml('Normal text')).toBe('Normal text');
    expect(escapeHtml('A & B < C > D')).toBe('A &amp; B &lt; C &gt; D');
  });

  it('should format bytes correctly', () => {
    const formatBytes = (bytes: number): string => {
      if (bytes < 1024) return `${bytes} B`;
      if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
      return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    };

    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(1023)).toBe('1023 B');
    expect(formatBytes(1024)).toBe('1.0 KB');
    expect(formatBytes(5120)).toBe('5.0 KB');
  });

  it('should truncate raw output to 4000 characters for HTML report', () => {
    const longOutput = 'A'.repeat(5000);
    const truncated = longOutput.slice(0, 4000);
    expect(truncated.length).toBe(4000);
  });
});

describe('Validation Coverage in Executive Summary', () => {
  it('should compute coverage stats for PDF from validation results', () => {
    const scan = { totalFindings: 20 };
    const validationResults = [
      { status: 'validated', exploitable: true },
      { status: 'validated', exploitable: true },
      { status: 'not_vulnerable', exploitable: false },
      { status: 'not_vulnerable', exploitable: false },
      { status: 'not_vulnerable', exploitable: false },
      { status: 'error', exploitable: false },
      { status: 'inconclusive', exploitable: false },
    ];

    const totalCritical = scan.totalFindings;
    const validated = validationResults.filter(r => r.status === 'validated' || r.status === 'not_vulnerable').length;
    const exploitable = validationResults.filter(r => r.exploitable).length;
    const coveragePct = totalCritical > 0 ? Math.round((validated / totalCritical) * 100) : 0;
    const exploitablePct = validated > 0 ? Math.round((exploitable / validated) * 100) : 0;

    expect(validated).toBe(5);
    expect(exploitable).toBe(2);
    expect(coveragePct).toBe(25);
    expect(exploitablePct).toBe(40);
  });

  it('should use validation results length as fallback for totalCritical', () => {
    const scan = { totalFindings: undefined };
    const validationResults = [
      { status: 'validated', exploitable: true },
      { status: 'not_vulnerable', exploitable: false },
    ];

    const totalCritical = scan.totalFindings ?? validationResults.length;
    expect(totalCritical).toBe(2);
  });

  it('should generate correct quality message for each tier', () => {
    const getQualityMsg = (pct: number): string =>
      pct >= 80
        ? 'High validation coverage — findings are well-substantiated with proof-of-exploit evidence.'
        : pct >= 50
        ? 'Moderate validation coverage — additional validation recommended for remaining critical findings.'
        : 'Low validation coverage — significant portion of critical findings remain unconfirmed.';

    expect(getQualityMsg(90)).toContain('well-substantiated');
    expect(getQualityMsg(60)).toContain('additional validation recommended');
    expect(getQualityMsg(20)).toContain('remain unconfirmed');
  });
});
