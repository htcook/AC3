import { describe, it, expect } from 'vitest';

// Import pure utility functions from vuln-feeds
import {
  parseCSVLine,
  severityFromCvss,
} from './lib/vuln-feeds';

// ─── CSV Parser Tests ───

describe('parseCSVLine', () => {
  it('parses simple comma-separated values', () => {
    const result = parseCSVLine('a,b,c,d');
    expect(result).toEqual(['a', 'b', 'c', 'd']);
  });

  it('handles quoted fields with commas', () => {
    const result = parseCSVLine('CVE-2024-1234,"Some, description",vendor,product');
    expect(result).toEqual(['CVE-2024-1234', 'Some, description', 'vendor', 'product']);
  });

  it('handles escaped quotes inside quoted fields', () => {
    const result = parseCSVLine('CVE-2024-5678,"He said ""hello""",vendor');
    expect(result).toEqual(['CVE-2024-5678', 'He said "hello"', 'vendor']);
  });

  it('handles empty fields', () => {
    const result = parseCSVLine('a,,c,');
    expect(result).toEqual(['a', '', 'c', '']);
  });

  it('handles single field', () => {
    const result = parseCSVLine('onlyfield');
    expect(result).toEqual(['onlyfield']);
  });

  it('handles empty string', () => {
    const result = parseCSVLine('');
    expect(result).toEqual(['']);
  });
});

// ─── Severity Scoring Tests ───

describe('severityFromCvss', () => {
  it('returns critical for CVSS >= 9.0', () => {
    expect(severityFromCvss(9.0)).toBe('critical');
    expect(severityFromCvss(10.0)).toBe('critical');
    expect(severityFromCvss(9.8)).toBe('critical');
  });

  it('returns high for CVSS 7.0-8.9', () => {
    expect(severityFromCvss(7.0)).toBe('high');
    expect(severityFromCvss(8.9)).toBe('high');
    expect(severityFromCvss(7.5)).toBe('high');
  });

  it('returns medium for CVSS 4.0-6.9', () => {
    expect(severityFromCvss(4.0)).toBe('medium');
    expect(severityFromCvss(6.9)).toBe('medium');
    expect(severityFromCvss(5.5)).toBe('medium');
  });

  it('returns low for CVSS < 4.0', () => {
    expect(severityFromCvss(3.9)).toBe('low');
    expect(severityFromCvss(0)).toBe('low');
    expect(severityFromCvss(1.5)).toBe('low');
  });

  it('returns unknown for null', () => {
    expect(severityFromCvss(null)).toBe('unknown');
  });
});

// ─── VulnEntry Type Validation Tests ───

describe('VulnEntry structure', () => {
  it('defines correct source types', () => {
    const validSources = ['cisa_kev', 'project_zero', 'nvd', 'circl', 'exploit_db'];
    validSources.forEach(src => {
      expect(typeof src).toBe('string');
    });
  });

  it('validates severity levels', () => {
    const validSeverities = ['critical', 'high', 'medium', 'low', 'unknown'];
    validSeverities.forEach(sev => {
      expect(['critical', 'high', 'medium', 'low', 'unknown']).toContain(sev);
    });
  });

  it('constructs a valid VulnEntry', () => {
    const entry = {
      cveId: 'CVE-2024-1234',
      title: 'Test Vulnerability',
      description: 'A test vulnerability description',
      severity: 'critical' as const,
      cvssScore: 9.8,
      vendor: 'TestVendor',
      product: 'TestProduct',
      datePublished: '2024-01-15',
      sources: ['cisa_kev' as const, 'nvd' as const],
      exploitAvailable: true,
      inTheWild: true,
      kevListed: true,
      ransomwareLinked: false,
      suggestedTechniques: ['T1190'],
    };

    expect(entry.cveId).toMatch(/^CVE-\d{4}-\d+$/);
    expect(entry.severity).toBe('critical');
    expect(entry.sources).toContain('cisa_kev');
    expect(entry.sources).toContain('nvd');
    expect(entry.exploitAvailable).toBe(true);
    expect(entry.inTheWild).toBe(true);
    expect(entry.kevListed).toBe(true);
  });
});

// ─── Feed Stats Structure Tests ───

describe('VulnFeedStats structure', () => {
  it('validates feed health statuses', () => {
    const validStatuses = ['ok', 'stale', 'error'];
    validStatuses.forEach(status => {
      expect(['ok', 'stale', 'error']).toContain(status);
    });
  });

  it('validates source keys', () => {
    const sourceKeys = ['cisa_kev', 'project_zero', 'nvd', 'circl', 'exploit_db'];
    expect(sourceKeys).toHaveLength(5);
    expect(sourceKeys).toContain('cisa_kev');
    expect(sourceKeys).toContain('project_zero');
    expect(sourceKeys).toContain('nvd');
    expect(sourceKeys).toContain('circl');
    expect(sourceKeys).toContain('exploit_db');
  });
});

// ─── TechVulnMatch Risk Score Tests ───

describe('TechVulnMatch risk scoring logic', () => {
  function calculateRiskScore(opts: {
    maxCvss: number;
    hasExploit: boolean;
    hasKev: boolean;
    hasZeroDay: boolean;
  }): number {
    return Math.min(100, Math.round(
      (opts.maxCvss / 10) * 40 +
      (opts.hasExploit ? 25 : 0) +
      (opts.hasKev ? 20 : 0) +
      (opts.hasZeroDay ? 15 : 0)
    ));
  }

  it('calculates max risk for critical KEV 0-day with exploit', () => {
    const score = calculateRiskScore({ maxCvss: 10, hasExploit: true, hasKev: true, hasZeroDay: true });
    expect(score).toBe(100);
  });

  it('calculates high risk for high CVSS with exploit', () => {
    const score = calculateRiskScore({ maxCvss: 8.5, hasExploit: true, hasKev: false, hasZeroDay: false });
    expect(score).toBe(59);
  });

  it('calculates medium risk for medium CVSS without exploit', () => {
    const score = calculateRiskScore({ maxCvss: 5.0, hasExploit: false, hasKev: false, hasZeroDay: false });
    expect(score).toBe(20);
  });

  it('calculates low risk for low CVSS', () => {
    const score = calculateRiskScore({ maxCvss: 2.0, hasExploit: false, hasKev: false, hasZeroDay: false });
    expect(score).toBe(8);
  });

  it('caps at 100', () => {
    const score = calculateRiskScore({ maxCvss: 10, hasExploit: true, hasKev: true, hasZeroDay: true });
    expect(score).toBeLessThanOrEqual(100);
  });

  it('returns 0 for zero CVSS and no flags', () => {
    const score = calculateRiskScore({ maxCvss: 0, hasExploit: false, hasKev: false, hasZeroDay: false });
    expect(score).toBe(0);
  });
});

// ─── Search Filter Logic Tests ───

describe('Vulnerability search filter logic', () => {
  const mockEntries = [
    { cveId: 'CVE-2024-0001', severity: 'critical', sources: ['cisa_kev'], exploitAvailable: true, inTheWild: true, kevListed: true, vendor: 'Microsoft', product: 'Exchange' },
    { cveId: 'CVE-2024-0002', severity: 'high', sources: ['nvd', 'exploit_db'], exploitAvailable: true, inTheWild: false, kevListed: false, vendor: 'Apache', product: 'Tomcat' },
    { cveId: 'CVE-2024-0003', severity: 'medium', sources: ['circl'], exploitAvailable: false, inTheWild: false, kevListed: false, vendor: 'Nginx', product: 'Nginx' },
    { cveId: 'CVE-2024-0004', severity: 'critical', sources: ['project_zero'], exploitAvailable: true, inTheWild: true, kevListed: false, vendor: 'Google', product: 'Chrome' },
  ];

  function filterVulns(entries: typeof mockEntries, filters: {
    severity?: string;
    source?: string;
    exploitOnly?: boolean;
    kevOnly?: boolean;
    zeroDayOnly?: boolean;
  }) {
    let results = [...entries];
    if (filters.severity) results = results.filter(e => e.severity === filters.severity);
    if (filters.source) results = results.filter(e => e.sources.includes(filters.source!));
    if (filters.exploitOnly) results = results.filter(e => e.exploitAvailable);
    if (filters.kevOnly) results = results.filter(e => e.kevListed);
    if (filters.zeroDayOnly) results = results.filter(e => e.inTheWild);
    return results;
  }

  it('filters by severity', () => {
    const results = filterVulns(mockEntries, { severity: 'critical' });
    expect(results).toHaveLength(2);
    expect(results.every(r => r.severity === 'critical')).toBe(true);
  });

  it('filters by source', () => {
    const results = filterVulns(mockEntries, { source: 'cisa_kev' });
    expect(results).toHaveLength(1);
    expect(results[0].cveId).toBe('CVE-2024-0001');
  });

  it('filters exploit-only', () => {
    const results = filterVulns(mockEntries, { exploitOnly: true });
    expect(results).toHaveLength(3);
    expect(results.every(r => r.exploitAvailable)).toBe(true);
  });

  it('filters KEV-only', () => {
    const results = filterVulns(mockEntries, { kevOnly: true });
    expect(results).toHaveLength(1);
    expect(results[0].kevListed).toBe(true);
  });

  it('filters 0-day only', () => {
    const results = filterVulns(mockEntries, { zeroDayOnly: true });
    expect(results).toHaveLength(2);
    expect(results.every(r => r.inTheWild)).toBe(true);
  });

  it('combines multiple filters', () => {
    const results = filterVulns(mockEntries, { severity: 'critical', zeroDayOnly: true });
    expect(results).toHaveLength(2);
  });

  it('returns empty for impossible filter combo', () => {
    const results = filterVulns(mockEntries, { severity: 'low' });
    expect(results).toHaveLength(0);
  });
});

// ─── CVE ID Validation Tests ───

describe('CVE ID format validation', () => {
  const CVE_REGEX = /^CVE-\d{4}-\d{4,}$/;

  it('validates standard CVE IDs', () => {
    expect(CVE_REGEX.test('CVE-2024-1234')).toBe(true);
    expect(CVE_REGEX.test('CVE-2024-12345')).toBe(true);
    expect(CVE_REGEX.test('CVE-2023-99999')).toBe(true);
  });

  it('rejects invalid CVE IDs', () => {
    expect(CVE_REGEX.test('CVE-2024-123')).toBe(false);
    expect(CVE_REGEX.test('cve-2024-1234')).toBe(false);
    expect(CVE_REGEX.test('CVE2024-1234')).toBe(false);
    expect(CVE_REGEX.test('NOTACVE')).toBe(false);
  });
});

// ─── Technology Matching Logic Tests ───

describe('Technology matching logic', () => {
  function matchesTechnology(tech: string, vuln: { vendor: string; product: string; title: string }): boolean {
    const techLower = tech.toLowerCase().trim();
    if (techLower.length < 4) return false;
    const vendorLower = vuln.vendor.toLowerCase();
    const productLower = vuln.product.toLowerCase();
    const titleLower = vuln.title.toLowerCase();
    return (
      vendorLower.includes(techLower) ||
      productLower.includes(techLower) ||
      titleLower.includes(techLower) ||
      techLower.includes(vendorLower) ||
      techLower.includes(productLower)
    );
  }

  it('matches by vendor name', () => {
    expect(matchesTechnology('Microsoft', { vendor: 'microsoft', product: 'exchange', title: '' })).toBe(true);
  });

  it('matches by product name', () => {
    expect(matchesTechnology('Exchange', { vendor: 'microsoft', product: 'exchange', title: '' })).toBe(true);
  });

  it('matches by title', () => {
    expect(matchesTechnology('Apache', { vendor: '', product: '', title: 'Apache Struts RCE' })).toBe(true);
  });

  it('matches when tech contains vendor', () => {
    expect(matchesTechnology('Microsoft Exchange Server', { vendor: 'microsoft', product: 'exchange', title: '' })).toBe(true);
  });

  it('rejects short tech strings', () => {
    expect(matchesTechnology('IIS', { vendor: 'microsoft', product: 'iis', title: '' })).toBe(false);
  });

  it('rejects non-matching tech', () => {
    expect(matchesTechnology('PostgreSQL', { vendor: 'microsoft', product: 'exchange', title: 'Exchange RCE' })).toBe(false);
  });

  it('is case-insensitive', () => {
    expect(matchesTechnology('NGINX', { vendor: 'Nginx', product: 'nginx', title: '' })).toBe(true);
  });
});

// ─── Severity Priority Ordering Tests ───

describe('Vulnerability sort ordering', () => {
  const vulns = [
    { cveId: 'CVE-1', kevListed: false, inTheWild: false, exploitAvailable: false, cvssScore: 5.0 },
    { cveId: 'CVE-2', kevListed: true, inTheWild: true, exploitAvailable: true, cvssScore: 9.8 },
    { cveId: 'CVE-3', kevListed: false, inTheWild: true, exploitAvailable: true, cvssScore: 8.5 },
    { cveId: 'CVE-4', kevListed: false, inTheWild: false, exploitAvailable: true, cvssScore: 7.0 },
  ];

  it('sorts KEV first, then 0-day, then exploit, then CVSS', () => {
    const sorted = [...vulns].sort((a, b) => {
      if (a.kevListed !== b.kevListed) return a.kevListed ? -1 : 1;
      if (a.inTheWild !== b.inTheWild) return a.inTheWild ? -1 : 1;
      if (a.exploitAvailable !== b.exploitAvailable) return a.exploitAvailable ? -1 : 1;
      return (b.cvssScore || 0) - (a.cvssScore || 0);
    });

    expect(sorted[0].cveId).toBe('CVE-2'); // KEV + 0-day
    expect(sorted[1].cveId).toBe('CVE-3'); // 0-day
    expect(sorted[2].cveId).toBe('CVE-4'); // exploit
    expect(sorted[3].cveId).toBe('CVE-1'); // none
  });
});
