import { describe, it, expect } from 'vitest';

/**
 * Unit tests for FedRAMP Risk Exposure Table (RET) appendix logic.
 * Tests the helper functions and data mapping used in the RET generation.
 */

// Replicate the helper functions from ac3-reports.ts for unit testing
const mapSeverityToFedRAMP = (sev: string, cvss?: string | null): string => {
  if (cvss) {
    const score = parseFloat(cvss);
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Moderate';
    if (score > 0) return 'Low';
  }
  switch (sev) {
    case 'critical': return 'Critical';
    case 'high': return 'High';
    case 'moderate': return 'Moderate';
    case 'low': return 'Low';
    case 'informational': return 'Warning';
    default: return 'Moderate';
  }
};

const classifyWeaknessType = (f: any): string => {
  const title = (f.rfTitle || '').toLowerCase();
  const techniques = (f.rfAttackTechniques as any[] || []);
  if (title.includes('config') || title.includes('header') || title.includes('tls') || title.includes('ssl')) return 'Misconfiguration';
  if (title.includes('patch') || title.includes('outdated') || title.includes('version')) return 'Software Flaw';
  if (title.includes('injection') || title.includes('xss') || title.includes('sqli')) return 'Vulnerability';
  if (title.includes('credential') || title.includes('password') || title.includes('auth')) return 'Vulnerability';
  if (techniques.length > 0) return 'Vulnerability';
  return 'Vulnerability';
};

const getSourceOfDiscovery = (f: any): string => {
  const module = f.rfSourceModule || '';
  if (module.includes('nuclei')) return 'Nuclei (Automated Scanner)';
  if (module.includes('zap')) return 'OWASP ZAP (DAST)';
  if (module.includes('sqlmap')) return 'SQLMap (Injection Testing)';
  if (module.includes('nmap') || module.includes('rustscan')) return 'Port Scanner (Nmap/RustScan)';
  if (module.includes('nikto')) return 'Nikto (Web Scanner)';
  if (module.includes('testssl')) return 'testssl.sh (TLS Analysis)';
  if (module.includes('caldera')) return 'CALDERA (Adversary Emulation)';
  if (module.includes('manual') || module.includes('operator')) return 'Manual Penetration Testing';
  if (module.includes('full-report')) return 'AC3 Automated Assessment';
  return 'Penetration Testing (AC3)';
};

describe('FedRAMP RET - Severity to Risk Rating Mapping', () => {
  it('maps CVSS 9.0+ to Critical', () => {
    expect(mapSeverityToFedRAMP('high', '9.5')).toBe('Critical');
    expect(mapSeverityToFedRAMP('moderate', '10.0')).toBe('Critical');
    expect(mapSeverityToFedRAMP('low', '9.0')).toBe('Critical');
  });

  it('maps CVSS 7.0-8.9 to High', () => {
    expect(mapSeverityToFedRAMP('moderate', '7.0')).toBe('High');
    expect(mapSeverityToFedRAMP('low', '8.9')).toBe('High');
    expect(mapSeverityToFedRAMP('critical', '7.5')).toBe('High');
  });

  it('maps CVSS 4.0-6.9 to Moderate', () => {
    expect(mapSeverityToFedRAMP('low', '4.0')).toBe('Moderate');
    expect(mapSeverityToFedRAMP('high', '6.9')).toBe('Moderate');
    expect(mapSeverityToFedRAMP('critical', '5.0')).toBe('Moderate');
  });

  it('maps CVSS 0.1-3.9 to Low', () => {
    expect(mapSeverityToFedRAMP('high', '3.9')).toBe('Low');
    expect(mapSeverityToFedRAMP('critical', '0.1')).toBe('Low');
    expect(mapSeverityToFedRAMP('moderate', '2.5')).toBe('Low');
  });

  it('falls back to severity string when no CVSS', () => {
    expect(mapSeverityToFedRAMP('critical')).toBe('Critical');
    expect(mapSeverityToFedRAMP('high')).toBe('High');
    expect(mapSeverityToFedRAMP('moderate')).toBe('Moderate');
    expect(mapSeverityToFedRAMP('low')).toBe('Low');
    expect(mapSeverityToFedRAMP('informational')).toBe('Warning');
  });

  it('defaults to Moderate for unknown severity', () => {
    expect(mapSeverityToFedRAMP('unknown')).toBe('Moderate');
    expect(mapSeverityToFedRAMP('')).toBe('Moderate');
  });

  it('handles null/undefined CVSS gracefully', () => {
    expect(mapSeverityToFedRAMP('high', null)).toBe('High');
    expect(mapSeverityToFedRAMP('critical', undefined)).toBe('Critical');
  });
});

describe('FedRAMP RET - Weakness Type Classification', () => {
  it('classifies configuration issues as Misconfiguration', () => {
    expect(classifyWeaknessType({ rfTitle: 'Missing Security Headers' })).toBe('Misconfiguration');
    expect(classifyWeaknessType({ rfTitle: 'Weak TLS Configuration' })).toBe('Misconfiguration');
    expect(classifyWeaknessType({ rfTitle: 'SSL Certificate Expired' })).toBe('Misconfiguration');
    expect(classifyWeaknessType({ rfTitle: 'Server Config Disclosure' })).toBe('Misconfiguration');
  });

  it('classifies patch issues as Software Flaw', () => {
    expect(classifyWeaknessType({ rfTitle: 'Missing Patch KB12345' })).toBe('Software Flaw');
    expect(classifyWeaknessType({ rfTitle: 'Outdated Apache Version' })).toBe('Software Flaw');
    expect(classifyWeaknessType({ rfTitle: 'PHP Version 5.6 End of Life' })).toBe('Software Flaw');
  });

  it('classifies injection/XSS as Vulnerability', () => {
    expect(classifyWeaknessType({ rfTitle: 'SQL Injection in Login Form' })).toBe('Vulnerability');
    expect(classifyWeaknessType({ rfTitle: 'Reflected XSS in Search' })).toBe('Vulnerability');
    expect(classifyWeaknessType({ rfTitle: 'Command Injection via File Upload' })).toBe('Vulnerability');
  });

  it('classifies auth issues as Vulnerability', () => {
    expect(classifyWeaknessType({ rfTitle: 'Default Credentials on Admin Panel' })).toBe('Vulnerability');
    expect(classifyWeaknessType({ rfTitle: 'Weak Password Policy' })).toBe('Vulnerability');
    expect(classifyWeaknessType({ rfTitle: 'Authentication Bypass via Token' })).toBe('Vulnerability');
  });

  it('classifies findings with ATT&CK techniques as Vulnerability', () => {
    expect(classifyWeaknessType({ rfTitle: 'Unknown Issue', rfAttackTechniques: ['T1059'] })).toBe('Vulnerability');
  });

  it('defaults to Vulnerability for unclassified findings', () => {
    expect(classifyWeaknessType({ rfTitle: 'Some Other Finding' })).toBe('Vulnerability');
    expect(classifyWeaknessType({})).toBe('Vulnerability');
  });
});

describe('FedRAMP RET - Source of Discovery', () => {
  it('identifies nuclei scanner', () => {
    expect(getSourceOfDiscovery({ rfSourceModule: 'nuclei-scan' })).toBe('Nuclei (Automated Scanner)');
  });

  it('identifies ZAP DAST', () => {
    expect(getSourceOfDiscovery({ rfSourceModule: 'zap-active-scan' })).toBe('OWASP ZAP (DAST)');
  });

  it('identifies SQLMap', () => {
    expect(getSourceOfDiscovery({ rfSourceModule: 'sqlmap-injection' })).toBe('SQLMap (Injection Testing)');
  });

  it('identifies port scanners', () => {
    expect(getSourceOfDiscovery({ rfSourceModule: 'nmap-service-scan' })).toBe('Port Scanner (Nmap/RustScan)');
    expect(getSourceOfDiscovery({ rfSourceModule: 'rustscan-fast' })).toBe('Port Scanner (Nmap/RustScan)');
  });

  it('identifies Nikto', () => {
    expect(getSourceOfDiscovery({ rfSourceModule: 'nikto-web-scan' })).toBe('Nikto (Web Scanner)');
  });

  it('identifies testssl', () => {
    expect(getSourceOfDiscovery({ rfSourceModule: 'testssl-analysis' })).toBe('testssl.sh (TLS Analysis)');
  });

  it('identifies CALDERA', () => {
    expect(getSourceOfDiscovery({ rfSourceModule: 'caldera-emulation' })).toBe('CALDERA (Adversary Emulation)');
  });

  it('identifies manual testing', () => {
    expect(getSourceOfDiscovery({ rfSourceModule: 'manual-exploit' })).toBe('Manual Penetration Testing');
    expect(getSourceOfDiscovery({ rfSourceModule: 'operator-verified' })).toBe('Manual Penetration Testing');
  });

  it('identifies full-report', () => {
    expect(getSourceOfDiscovery({ rfSourceModule: 'full-report-gen' })).toBe('AC3 Automated Assessment');
  });

  it('defaults to Penetration Testing (AC3)', () => {
    expect(getSourceOfDiscovery({ rfSourceModule: '' })).toBe('Penetration Testing (AC3)');
    expect(getSourceOfDiscovery({})).toBe('Penetration Testing (AC3)');
  });
});

describe('FedRAMP RET - PT-XXX Identifier Format', () => {
  it('generates correct PT-XXX identifiers', () => {
    // Simulate the identifier generation logic
    const generatePtId = (idx: number) => `PT-${String(idx + 1).padStart(3, '0')}`;
    
    expect(generatePtId(0)).toBe('PT-001');
    expect(generatePtId(1)).toBe('PT-002');
    expect(generatePtId(9)).toBe('PT-010');
    expect(generatePtId(99)).toBe('PT-100');
    expect(generatePtId(998)).toBe('PT-999');
  });
});

describe('FedRAMP RET - Control String Formatting', () => {
  it('formats multiple controls as comma-separated', () => {
    const controls = [{ id: 'SI-10' }, { id: 'AC-3' }, { id: 'RA-5' }];
    const controlStr = controls.map((c: any) => c.id).join(', ');
    expect(controlStr).toBe('SI-10, AC-3, RA-5');
  });

  it('defaults to RA-5 when no controls mapped', () => {
    const controls: any[] = [];
    const controlStr = controls.length > 0 ? controls.map((c: any) => c.id).join(', ') : 'RA-5';
    expect(controlStr).toBe('RA-5');
  });
});

describe('FedRAMP RET - Summary Statistics', () => {
  it('correctly counts findings by risk rating', () => {
    const findings = [
      { rfSeverity: 'critical', rfCvssScore: '9.5' },
      { rfSeverity: 'high', rfCvssScore: '7.2' },
      { rfSeverity: 'high', rfCvssScore: '8.1' },
      { rfSeverity: 'moderate', rfCvssScore: '5.0' },
      { rfSeverity: 'low', rfCvssScore: '2.0' },
      { rfSeverity: 'informational', rfCvssScore: null },
    ];

    const retStats = findings.reduce((acc, f) => {
      const rating = mapSeverityToFedRAMP(f.rfSeverity, f.rfCvssScore);
      acc[rating] = (acc[rating] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    expect(retStats['Critical']).toBe(1);
    expect(retStats['High']).toBe(2);
    expect(retStats['Moderate']).toBe(1);
    expect(retStats['Low']).toBe(1);
    expect(retStats['Warning']).toBe(1);
  });
});
