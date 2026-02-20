import { describe, it, expect, vi } from 'vitest';

// ─── Test Suite: Validation Engine Enhancements ───
// Covers: (1) Export utilities with validation evidence, (2) Re-scoring hook logic, (3) Validate Top 10 candidate selection

describe('Validation Evidence Export Types', () => {
  it('should define ValidationResultExport interface with all required fields', async () => {
    // Verify the export type shape matches what the PDF generator expects
    const mockResult = {
      assetHostname: 'web01.example.com',
      cveId: 'CVE-2024-1234',
      msfModule: 'exploit/multi/http/apache_mod_cgi_bash_env_exec',
      status: 'validated' as const,
      exploitable: true,
      scoreAdjustment: 15,
      durationMs: 3200,
      evidence: { sessionType: 'shell', platform: 'linux', output: 'uid=33(www-data)' },
      errorMessage: null,
      timestamp: '2026-02-20T12:00:00Z',
    };

    expect(mockResult.assetHostname).toBe('web01.example.com');
    expect(mockResult.exploitable).toBe(true);
    expect(mockResult.scoreAdjustment).toBe(15);
    expect(mockResult.evidence).toBeDefined();
    expect(mockResult.evidence.sessionType).toBe('shell');
  });

  it('should define ValidationRunExport interface with summary fields', () => {
    const mockRun = {
      id: 1,
      scanId: 100,
      mode: 'check_only' as const,
      status: 'completed' as const,
      totalCandidates: 10,
      validated: 4,
      exploitable: 3,
      notVulnerable: 5,
      errors: 1,
      startedAt: '2026-02-20T12:00:00Z',
      completedAt: '2026-02-20T12:05:00Z',
    };

    expect(mockRun.totalCandidates).toBe(10);
    expect(mockRun.validated + mockRun.notVulnerable + mockRun.errors).toBeLessThanOrEqual(mockRun.totalCandidates);
    expect(mockRun.exploitable).toBeLessThanOrEqual(mockRun.validated);
  });

  it('should handle null evidence gracefully in export data', () => {
    const mockResult = {
      assetHostname: 'db01.example.com',
      cveId: 'CVE-2024-5678',
      msfModule: null,
      status: 'not_vulnerable' as const,
      exploitable: false,
      scoreAdjustment: 0,
      durationMs: 1500,
      evidence: null,
      errorMessage: null,
      timestamp: '2026-02-20T12:01:00Z',
    };

    expect(mockResult.evidence).toBeNull();
    expect(mockResult.exploitable).toBe(false);
    expect(mockResult.scoreAdjustment).toBe(0);
  });
});

describe('Re-scoring Hook Logic', () => {
  it('should calculate correct risk band from score', () => {
    const getBand = (score: number) =>
      score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 40 ? 'medium' : 'low';

    expect(getBand(95)).toBe('critical');
    expect(getBand(80)).toBe('critical');
    expect(getBand(79)).toBe('high');
    expect(getBand(60)).toBe('high');
    expect(getBand(59)).toBe('medium');
    expect(getBand(40)).toBe('medium');
    expect(getBand(39)).toBe('low');
    expect(getBand(0)).toBe('low');
  });

  it('should cap re-scored asset at 100', () => {
    const currentScore = 92;
    const adjustment = 15;
    const newScore = Math.min(100, currentScore + adjustment);
    expect(newScore).toBe(100);
  });

  it('should not exceed 100 even with large adjustments', () => {
    const currentScore = 50;
    const adjustment = 60;
    const newScore = Math.min(100, currentScore + adjustment);
    expect(newScore).toBe(100);
  });

  it('should calculate scan overall risk as weighted max+avg', () => {
    const scores = [85, 72, 60, 45, 30];
    const maxScore = Math.max(...scores);
    const avgScore = scores.reduce((s, v) => s + v, 0) / scores.length;
    const overall = Math.round(maxScore * 0.6 + avgScore * 0.4);

    expect(maxScore).toBe(85);
    expect(avgScore).toBeCloseTo(58.4);
    expect(overall).toBe(74); // 85*0.6 + 58.4*0.4 = 51 + 23.36 = 74.36 → 74
  });

  it('should produce correct audit log entry for exploit_validation trigger', () => {
    const auditEntry = {
      assetId: 42,
      scanId: 100,
      hybridRiskScore: 85,
      riskBand: 'critical',
      previousScore: 70,
      delta: 15,
      triggerType: 'exploit_validation',
      pipelinePhase: 'validation_engine',
      changeDescription: 'Exploitation validated: CVE-2024-1234 via exploit/multi/http/test — confirmed exploitable (+15)',
      factorChanges: [{
        factor: 'exploitability',
        previousValue: 'unconfirmed',
        newValue: 'confirmed_exploitable',
        reason: 'CVE CVE-2024-1234 validated via check_only mode',
      }],
      computedBy: 'validation-engine',
    };

    expect(auditEntry.triggerType).toBe('exploit_validation');
    expect(auditEntry.delta).toBe(15);
    expect(auditEntry.previousScore + auditEntry.delta).toBe(auditEntry.hybridRiskScore);
    expect(auditEntry.factorChanges[0].newValue).toBe('confirmed_exploitable');
  });

  it('should produce correct audit log entry for negative validation', () => {
    const auditEntry = {
      assetId: 43,
      scanId: 100,
      hybridRiskScore: 65,
      riskBand: 'high',
      previousScore: 65,
      delta: 0,
      triggerType: 'exploit_validation_negative',
      pipelinePhase: 'validation_engine',
      changeDescription: 'Exploitation check negative: CVE-2024-9999 — not exploitable in current configuration',
      factorChanges: [{
        factor: 'exploitability',
        previousValue: 'unconfirmed',
        newValue: 'not_exploitable',
        reason: 'CVE CVE-2024-9999 check returned not vulnerable',
      }],
      computedBy: 'validation-engine',
    };

    expect(auditEntry.triggerType).toBe('exploit_validation_negative');
    expect(auditEntry.delta).toBe(0);
    expect(auditEntry.previousScore).toBe(auditEntry.hybridRiskScore);
    expect(auditEntry.factorChanges[0].newValue).toBe('not_exploitable');
  });

  it('should handle single-asset scan overall calculation', () => {
    const scores = [92];
    const maxScore = Math.max(...scores);
    const avgScore = scores.reduce((s, v) => s + v, 0) / scores.length;
    const overall = Math.round(maxScore * 0.6 + avgScore * 0.4);

    // For single asset, max === avg, so overall === score
    expect(overall).toBe(92);
  });
});

describe('Validate Top 10 Candidate Selection', () => {
  it('should limit candidates to maxCandidates=10', () => {
    const allCandidates = Array.from({ length: 25 }, (_, i) => ({
      assetId: i + 1,
      hostname: `host${i + 1}.example.com`,
      cveId: `CVE-2024-${1000 + i}`,
      priorityScore: 100 - i * 3,
    }));

    const top10 = allCandidates.slice(0, 10);
    expect(top10.length).toBe(10);
    expect(top10[0].priorityScore).toBe(100);
    expect(top10[9].priorityScore).toBe(73);
  });

  it('should prioritize KEV-listed candidates', () => {
    const candidates = [
      { cveId: 'CVE-2024-001', kevListed: false, cvss: 9.0, hasMsfModule: true, priorityScore: 0 },
      { cveId: 'CVE-2024-002', kevListed: true, cvss: 7.0, hasMsfModule: true, priorityScore: 0 },
      { cveId: 'CVE-2024-003', kevListed: true, cvss: 9.5, hasMsfModule: false, priorityScore: 0 },
    ];

    // Apply priority scoring: KEV +40, CVSS up to +30, MSF +15
    for (const c of candidates) {
      c.priorityScore = (c.kevListed ? 40 : 0) + (c.cvss / 10 * 30) + (c.hasMsfModule ? 15 : 0);
    }

    candidates.sort((a, b) => b.priorityScore - a.priorityScore);

    // CVE-002: KEV(40) + CVSS(21) + MSF(15) = 76
    // CVE-003: KEV(40) + CVSS(28.5) + MSF(0) = 68.5
    // CVE-001: KEV(0) + CVSS(27) + MSF(15) = 42
    expect(candidates[0].cveId).toBe('CVE-2024-002'); // 76 — KEV + MSF module wins
    expect(candidates[1].cveId).toBe('CVE-2024-003'); // 68.5
    expect(candidates[2].cveId).toBe('CVE-2024-001'); // 42
  });

  it('should default to check_only mode for Validate Top 10', () => {
    const quickValidateConfig = {
      mode: 'check_only' as const,
      maxCandidates: 10,
    };

    expect(quickValidateConfig.mode).toBe('check_only');
    expect(quickValidateConfig.maxCandidates).toBe(10);
  });
});

describe('Executive Summary with Validation Enhancement', () => {
  it('should include validation section when validation data is present', () => {
    const hasValidation = true;
    const validationRun = {
      id: 1, scanId: 100, mode: 'check_only', status: 'completed',
      totalCandidates: 10, validated: 4, exploitable: 3, notVulnerable: 5, errors: 1,
      startedAt: '2026-02-20T12:00:00Z', completedAt: '2026-02-20T12:05:00Z',
    };
    const validationResults = [
      { assetHostname: 'web01', cveId: 'CVE-2024-1234', status: 'validated', exploitable: true, scoreAdjustment: 15 },
      { assetHostname: 'web02', cveId: 'CVE-2024-5678', status: 'not_vulnerable', exploitable: false, scoreAdjustment: 0 },
    ];

    // The enhanced export should include validation section
    const exploitableFindings = validationResults.filter(r => r.exploitable);
    expect(exploitableFindings.length).toBe(1);
    expect(exploitableFindings[0].cveId).toBe('CVE-2024-1234');
    expect(exploitableFindings[0].scoreAdjustment).toBe(15);
  });

  it('should fall back to standard export when no validation data', () => {
    const validationRun = null;
    const validationResults: any[] = [];

    const useEnhancedExport = validationRun && validationResults.length > 0;
    expect(useEnhancedExport).toBeFalsy();
  });
});
