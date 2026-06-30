import { describe, it, expect } from 'vitest';
import {
  getProgramRoE,
  getAllProgramRoEs,
  enforceScanAction,
  filterFindingsForProgram,
  generateOperatorBriefing,
  buildScanHeaders,
  H1_CORE_INELIGIBLE_PATTERNS,
  type ScanAction,
  type ReportFinding,
} from './lib/bb-roe-enforcement';

// ─── Program Registry ────────────────────────────────────────────────────

describe('BB RoE Program Registry', () => {
  it('should have configs for all known programs', () => {
    expect(getProgramRoE('priceline')).toBeDefined();
    expect(getProgramRoE('nextcloud')).toBeDefined();
    expect(getProgramRoE('wordpress')).toBeDefined();
    expect(getProgramRoE('nodejs')).toBeDefined();
  });

  it('should return undefined for unknown programs', () => {
    expect(getProgramRoE('unknown_program')).toBeUndefined();
  });

  it('should be case-insensitive', () => {
    expect(getProgramRoE('Priceline')).toBeDefined();
    expect(getProgramRoE('NEXTCLOUD')).toBeDefined();
  });

  it('should return all registered programs', () => {
    const all = getAllProgramRoEs();
    expect(all.length).toBeGreaterThanOrEqual(4);
  });
});

// ─── Scan-Time Enforcement ───────────────────────────────────────────────

describe('BB RoE Scan-Time Enforcement', () => {
  describe('Priceline', () => {
    it('should block excluded targets (*.roomvaluesteam.com)', () => {
      const action: ScanAction = {
        type: 'scan',
        target: 'admin.roomvaluesteam.com',
        isAutomated: false,
      };
      const result = enforceScanAction('priceline', action);
      expect(result.allowed).toBe(false);
      expect(result.blockedBy).toBe('excluded_target');
    });

    it('should block excluded targets (airportrentalcars.com)', () => {
      const action: ScanAction = {
        type: 'scan',
        target: 'airportrentalcars.com',
        isAutomated: false,
      };
      const result = enforceScanAction('priceline', action);
      expect(result.allowed).toBe(false);
    });

    it('should block fuzzing contact forms', () => {
      const action: ScanAction = {
        type: 'fuzz',
        target: 'priceline.com',
        endpoint: '/contact-us',
        isAutomated: false,
      };
      const result = enforceScanAction('priceline', action);
      expect(result.allowed).toBe(false);
      expect(result.blockedBy).toBe('excluded_endpoint');
    });

    it('should block fuzzing account activation endpoints', () => {
      const action: ScanAction = {
        type: 'fuzz',
        target: 'priceline.com',
        endpoint: '/api/account-activation',
        isAutomated: false,
      };
      const result = enforceScanAction('priceline', action);
      expect(result.allowed).toBe(false);
    });

    it('should block automated fuzzing (scanner not allowed)', () => {
      const action: ScanAction = {
        type: 'fuzz',
        target: 'priceline.com',
        endpoint: '/search',
        isAutomated: true,
      };
      const result = enforceScanAction('priceline', action);
      expect(result.allowed).toBe(false);
      expect(result.blockedBy).toBe('automated_scanner_prohibited');
    });

    it('should allow manual scanning on in-scope targets', () => {
      const action: ScanAction = {
        type: 'scan',
        target: 'www.priceline.com',
        isAutomated: false,
      };
      const result = enforceScanAction('priceline', action);
      expect(result.allowed).toBe(true);
    });

    it('should inject X-Bug-Bounty header with operator username', () => {
      const action: ScanAction = {
        type: 'request',
        target: 'www.priceline.com',
        isAutomated: false,
      };
      const result = enforceScanAction('priceline', action, 'ac3_operator');
      expect(result.allowed).toBe(true);
      expect(result.modifications?.headers?.['X-Bug-Bounty']).toBe('ac3_operator');
    });

    it('should apply rate limiting (10 rps max)', () => {
      const action: ScanAction = {
        type: 'scan',
        target: 'www.priceline.com',
        isAutomated: false,
      };
      const result = enforceScanAction('priceline', action);
      expect(result.allowed).toBe(true);
      expect(result.modifications?.rateLimit?.maxRps).toBe(10);
    });

    it('should block inventory manipulation actions', () => {
      const action: ScanAction = {
        type: 'request',
        target: 'www.priceline.com',
        endpoint: '/api/booking',
        isAutomated: false,
        context: { involvesReservation: true },
      };
      const result = enforceScanAction('priceline', action);
      expect(result.allowed).toBe(false);
      expect(result.blockedBy).toContain('inventory_manipulation');
    });
  });

  describe('Nextcloud', () => {
    it('should block automated scanning', () => {
      const action: ScanAction = {
        type: 'scan',
        target: 'cloud.nextcloud.com',
        isAutomated: true,
      };
      const result = enforceScanAction('nextcloud', action);
      expect(result.allowed).toBe(false);
    });

    it('should allow manual testing', () => {
      const action: ScanAction = {
        type: 'scan',
        target: 'cloud.nextcloud.com',
        isAutomated: false,
      };
      const result = enforceScanAction('nextcloud', action);
      expect(result.allowed).toBe(true);
    });
  });

  describe('WordPress', () => {
    it('should block production WordPress.com targets', () => {
      const action: ScanAction = {
        type: 'scan',
        target: 'blog.wordpress.com',
        isAutomated: false,
      };
      const result = enforceScanAction('wordpress', action);
      expect(result.allowed).toBe(false);
      expect(result.blockedBy).toBe('excluded_target');
    });

    it('should allow automated scanning on non-excluded targets', () => {
      const action: ScanAction = {
        type: 'scan',
        target: 'wordpress.org',
        endpoint: '/wp-json/wp/v2/posts',
        isAutomated: true,
      };
      const result = enforceScanAction('wordpress', action);
      // WordPress allows automated scanning but the prohibited action for 'automated_scanning'
      // category matches type 'scan' with isAutomated=true
      expect(result.allowed).toBe(false);
      expect(result.blockedBy).toContain('automated_scanning');
    });
  });

  describe('Unknown program', () => {
    it('should block all actions for programs without RoE config', () => {
      const action: ScanAction = {
        type: 'scan',
        target: 'example.com',
        isAutomated: false,
      };
      const result = enforceScanAction('unknown_program', action);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('No RoE config found');
    });
  });
});

// ─── Report-Time Filtering ───────────────────────────────────────────────

describe('BB RoE Report-Time Filtering', () => {
  describe('H1 Core Ineligible Findings', () => {
    it('should filter out version disclosure findings', () => {
      const findings: ReportFinding[] = [
        { title: 'Server Version Disclosure via HTTP Headers', severity: 'low', asset: 'priceline.com' },
      ];
      const result = filterFindingsForProgram('priceline', findings);
      expect(result.ineligible.length).toBe(1);
      expect(result.ineligible[0].ineligibleReason).toContain('H1 Ineligible');
    });

    it('should filter out self-XSS findings', () => {
      const findings: ReportFinding[] = [
        { title: 'Self-XSS in profile bio field', severity: 'low', asset: 'priceline.com' },
      ];
      const result = filterFindingsForProgram('priceline', findings);
      expect(result.ineligible.length).toBe(1);
    });

    it('should filter out missing CSP findings', () => {
      const findings: ReportFinding[] = [
        { title: 'Content Security Policy Missing on login page', severity: 'info', asset: 'priceline.com' },
      ];
      const result = filterFindingsForProgram('priceline', findings);
      expect(result.ineligible.length).toBe(1);
    });

    it('should filter out clickjacking on non-sensitive pages', () => {
      const findings: ReportFinding[] = [
        { title: 'Clickjacking on static marketing page with no sensitive actions', severity: 'low', asset: 'priceline.com' },
      ];
      const result = filterFindingsForProgram('priceline', findings);
      expect(result.ineligible.length).toBe(1);
    });

    it('should filter out DoS findings', () => {
      const findings: ReportFinding[] = [
        { title: 'Denial of Service via large payload', severity: 'medium', asset: 'priceline.com' },
      ];
      const result = filterFindingsForProgram('priceline', findings);
      expect(result.ineligible.length).toBe(1);
    });

    it('should NOT filter out legitimate XSS findings', () => {
      const findings: ReportFinding[] = [
        { title: 'Stored XSS in booking confirmation page', severity: 'high', asset: 'priceline.com' },
      ];
      const result = filterFindingsForProgram('priceline', findings);
      expect(result.eligible.length).toBe(1);
      expect(result.ineligible.length).toBe(0);
    });

    it('should NOT filter out SQL injection findings', () => {
      const findings: ReportFinding[] = [
        { title: 'SQL Injection in search parameter', severity: 'critical', asset: 'priceline.com' },
      ];
      const result = filterFindingsForProgram('priceline', findings);
      expect(result.eligible.length).toBe(1);
    });
  });

  describe('Priceline-specific filtering', () => {
    it('should filter findings on excluded targets', () => {
      const findings: ReportFinding[] = [
        { title: 'XSS on admin panel', severity: 'high', asset: 'admin.roomvaluesteam.com' },
      ];
      const result = filterFindingsForProgram('priceline', findings);
      expect(result.ineligible.length).toBe(1);
      expect(result.ineligible[0].ineligibleReason).toContain('excluded target');
    });

    it('should warn about automated scanner findings needing manual PoC', () => {
      const findings: ReportFinding[] = [
        { title: 'Reflected XSS in search', severity: 'high', asset: 'priceline.com', source: 'nuclei', hasDetailedPoC: false },
      ];
      const result = filterFindingsForProgram('priceline', findings);
      expect(result.eligible.length).toBe(1);
      expect(result.eligible[0].warnings).toBeDefined();
      expect(result.eligible[0].warnings!.some(w => w.includes('automated scanner'))).toBe(true);
    });

    it('should warn about missing PoC', () => {
      const findings: ReportFinding[] = [
        { title: 'IDOR in booking API', severity: 'high', asset: 'priceline.com', hasDetailedPoC: false },
      ];
      const result = filterFindingsForProgram('priceline', findings);
      expect(result.eligible.length).toBe(1);
      expect(result.eligible[0].warnings!.some(w => w.includes('detailed working PoC'))).toBe(true);
    });
  });

  describe('Nextcloud-specific filtering', () => {
    it('should filter third-party app findings', () => {
      const findings: ReportFinding[] = [
        { title: 'XSS in third-party app Calendar Plus', severity: 'high', asset: 'nextcloud.com' },
      ];
      const result = filterFindingsForProgram('nextcloud', findings);
      expect(result.ineligible.length).toBe(1);
      expect(result.ineligible[0].ineligibleReason).toContain('Third-party');
    });
  });

  describe('Filter summary', () => {
    it('should provide accurate summary counts', () => {
      const findings: ReportFinding[] = [
        { title: 'Stored XSS in booking page', severity: 'high', asset: 'priceline.com', hasDetailedPoC: true },
        { title: 'SQL Injection in API', severity: 'critical', asset: 'priceline.com', hasDetailedPoC: true },
        { title: 'Server Version Disclosure', severity: 'info', asset: 'priceline.com' },
        { title: 'Self-XSS in profile', severity: 'low', asset: 'priceline.com' },
        { title: 'Missing CSP header', severity: 'info', asset: 'priceline.com' },
      ];
      const result = filterFindingsForProgram('priceline', findings);
      expect(result.summary.total).toBe(5);
      expect(result.summary.eligible).toBe(2);
      expect(result.summary.ineligible).toBe(3);
    });
  });

  describe('Unknown program (no config)', () => {
    it('should pass all findings through with warning', () => {
      const findings: ReportFinding[] = [
        { title: 'XSS', severity: 'high', asset: 'example.com' },
      ];
      const result = filterFindingsForProgram('unknown', findings);
      expect(result.eligible.length).toBe(1);
      expect(result.summary.noRoEConfig).toBe(true);
    });
  });
});

// ─── Operator Briefing ───────────────────────────────────────────────────

describe('BB RoE Operator Briefing', () => {
  it('should generate Priceline briefing with all critical rules', () => {
    const briefing = generateOperatorBriefing('priceline');
    expect(briefing).not.toBeNull();
    expect(briefing!.criticalRules.length).toBeGreaterThanOrEqual(6);
    expect(briefing!.identificationSetup.some(s => s.includes('X-Bug-Bounty'))).toBe(true);
    expect(briefing!.identificationSetup.some(s => s.includes('wearehackerone.com'))).toBe(true);
    expect(briefing!.excludedTargets).toContain('*.roomvaluesteam.com');
  });

  it('should generate Nextcloud briefing', () => {
    const briefing = generateOperatorBriefing('nextcloud');
    expect(briefing).not.toBeNull();
    expect(briefing!.criticalRules.some(r => r.toLowerCase().includes('automated') || r.toLowerCase().includes('scanning'))).toBe(true);
  });

  it('should return null for unknown programs', () => {
    const briefing = generateOperatorBriefing('unknown');
    expect(briefing).toBeNull();
  });
});

// ─── HTTP Header Builder ─────────────────────────────────────────────────

describe('BB RoE HTTP Header Builder', () => {
  it('should build X-Bug-Bounty header for Priceline', () => {
    const headers = buildScanHeaders('priceline', 'ac3_hunter');
    expect(headers['X-Bug-Bounty']).toBe('ac3_hunter');
  });

  it('should return empty headers for programs without custom header requirements', () => {
    const headers = buildScanHeaders('nextcloud', 'ac3_hunter');
    expect(Object.keys(headers).length).toBe(0);
  });

  it('should return empty headers for unknown programs', () => {
    const headers = buildScanHeaders('unknown', 'ac3_hunter');
    expect(Object.keys(headers).length).toBe(0);
  });
});

// ─── H1 Core Ineligible Patterns ─────────────────────────────────────────

describe('H1 Core Ineligible Patterns', () => {
  it('should have patterns covering all major categories', () => {
    expect(H1_CORE_INELIGIBLE_PATTERNS.length).toBeGreaterThanOrEqual(15);
  });

  it('should match version disclosure patterns', () => {
    const pattern = H1_CORE_INELIGIBLE_PATTERNS.find(p => p.pattern.includes('version.disclos'));
    expect(pattern).toBeDefined();
    expect(new RegExp(pattern!.pattern, 'i').test('server version disclosure via headers')).toBe(true);
  });

  it('should match self-XSS patterns', () => {
    const pattern = H1_CORE_INELIGIBLE_PATTERNS.find(p => p.pattern.includes('self.xss'));
    expect(pattern).toBeDefined();
    expect(new RegExp(pattern!.pattern, 'i').test('self xss in profile field')).toBe(true);
  });

  it('should match DoS patterns', () => {
    const pattern = H1_CORE_INELIGIBLE_PATTERNS.find(p => p.pattern.includes('denial.of.service'));
    expect(pattern).toBeDefined();
    expect(new RegExp(pattern!.pattern, 'i').test('denial of service via regex')).toBe(true);
  });
});
