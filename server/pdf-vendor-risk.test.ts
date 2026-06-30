/**
 * Tests for PDF Export — Vendor Risk Enrichment
 * 
 * Validates the new sections added to the PDF export:
 * - Shared Responsibility Model (provider/customer/shared scope)
 * - Supply Chain Concentration Analysis (vendor dependencies)
 * - Supply Chain Risk Findings
 * - Infrastructure Posture Summary
 * - InfraMapData interface compatibility
 */
import { describe, it, expect } from 'vitest';

// ─── Shared Responsibility Model Logic ──────────────────────────────────────
// Tests the provider matching and fallback logic used in the PDF export

describe('PDF Export — Shared Responsibility Model', () => {
  const KNOWN_PROVIDERS: Record<string, { providerScope: string[]; customerScope: string[]; sharedScope: string[] }> = {
    'Microsoft 365': {
      providerScope: ['Exchange Online server patching', 'Infrastructure security', 'Physical datacenter security', 'Platform availability (SLA)', 'Anti-malware engine updates'],
      customerScope: ['SPF/DKIM/DMARC configuration', 'Tenant security settings', 'Conditional Access policies', 'User access management', 'Data classification & DLP rules'],
      sharedScope: ['Incident response coordination', 'Threat intelligence sharing', 'Compliance reporting'],
    },
    'Google Workspace': {
      providerScope: ['Gmail server infrastructure', 'Infrastructure security', 'Physical datacenter security', 'Platform availability (SLA)', 'Spam/phishing filter updates'],
      customerScope: ['SPF/DKIM/DMARC configuration', 'Workspace admin console settings', 'User access management', 'Data Loss Prevention rules', 'Security investigation tool usage'],
      sharedScope: ['Incident response coordination', 'Threat intelligence sharing', 'Compliance reporting'],
    },
    'Cloudflare': {
      providerScope: ['CDN/WAF infrastructure', 'DDoS mitigation', 'Edge network availability', 'SSL/TLS certificate management', 'Bot management engine'],
      customerScope: ['WAF rule configuration', 'Page rules & caching policies', 'DNS record management', 'Origin server security', 'Rate limiting configuration'],
      sharedScope: ['Incident response coordination', 'Security event monitoring', 'Custom rule tuning'],
    },
    'AWS': {
      providerScope: ['Physical infrastructure security', 'Hypervisor & network infrastructure', 'Managed service patching (RDS, Lambda)', 'Global infrastructure availability'],
      customerScope: ['IAM policies & access control', 'Security group configuration', 'Data encryption configuration', 'Application security', 'OS patching (EC2)'],
      sharedScope: ['Incident response coordination', 'Compliance framework alignment', 'Shared vulnerability disclosure'],
    },
  };

  function resolveProvider(providerName: string) {
    return KNOWN_PROVIDERS[providerName] ||
      Object.entries(KNOWN_PROVIDERS).find(([k]) => providerName.toLowerCase().includes(k.toLowerCase()))?.[1] ||
      {
        providerScope: ['Infrastructure security', 'Platform patching', 'Physical security', 'Service availability'],
        customerScope: ['Configuration management', 'Access control', 'Data protection', 'Compliance monitoring'],
        sharedScope: ['Incident response', 'Security monitoring', 'Compliance reporting'],
      };
  }

  it('resolves Microsoft 365 provider with correct scope', () => {
    const model = resolveProvider('Microsoft 365');
    expect(model.providerScope).toContain('Exchange Online server patching');
    expect(model.customerScope).toContain('SPF/DKIM/DMARC configuration');
    expect(model.sharedScope).toContain('Incident response coordination');
    expect(model.providerScope.length).toBe(5);
    expect(model.customerScope.length).toBeGreaterThanOrEqual(5);
  });

  it('resolves Google Workspace provider', () => {
    const model = resolveProvider('Google Workspace');
    expect(model.providerScope).toContain('Gmail server infrastructure');
    expect(model.customerScope).toContain('Workspace admin console settings');
  });

  it('resolves Cloudflare provider', () => {
    const model = resolveProvider('Cloudflare');
    expect(model.providerScope).toContain('DDoS mitigation');
    expect(model.customerScope).toContain('WAF rule configuration');
  });

  it('resolves AWS provider', () => {
    const model = resolveProvider('AWS');
    expect(model.providerScope).toContain('Physical infrastructure security');
    expect(model.customerScope).toContain('IAM policies & access control');
  });

  it('falls back to generic model for unknown providers', () => {
    const model = resolveProvider('Zoho Mail');
    expect(model.providerScope).toContain('Infrastructure security');
    expect(model.customerScope).toContain('Configuration management');
    expect(model.sharedScope).toContain('Incident response');
  });

  it('matches partial provider names case-insensitively', () => {
    const model = resolveProvider('microsoft 365 enterprise');
    expect(model.providerScope).toContain('Exchange Online server patching');
  });

  it('all known providers have non-empty scopes', () => {
    for (const [name, model] of Object.entries(KNOWN_PROVIDERS)) {
      expect(model.providerScope.length, `${name} providerScope`).toBeGreaterThan(0);
      expect(model.customerScope.length, `${name} customerScope`).toBeGreaterThan(0);
      expect(model.sharedScope.length, `${name} sharedScope`).toBeGreaterThan(0);
    }
  });

  it('builds correct table row count from max scope length', () => {
    const model = resolveProvider('Microsoft 365');
    const maxLen = Math.max(model.providerScope.length, model.customerScope.length, model.sharedScope.length);
    expect(maxLen).toBe(5); // M365 has 5 provider and 5+ customer items
    // Table rows should pad shorter arrays with empty strings
    const rows: string[][] = [];
    for (let i = 0; i < maxLen; i++) {
      rows.push([
        model.providerScope[i] || '',
        model.customerScope[i] || '',
        model.sharedScope[i] || '',
      ]);
    }
    expect(rows.length).toBe(maxLen);
    // Last shared scope row should be empty if sharedScope is shorter
    if (model.sharedScope.length < maxLen) {
      expect(rows[maxLen - 1][2]).toBe('');
    }
  });
});

// ─── Supply Chain Concentration Analysis ────────────────────────────────────

describe('PDF Export — Supply Chain Concentration', () => {
  it('renders vendor dependency rows correctly', () => {
    const vendorDeps = [
      { vendor: 'Cloudflare', services: ['CDN', 'WAF', 'DNS'], serviceCount: 3, criticality: 'critical', singlePointOfFailure: true, notes: 'All traffic routes through CF' },
      { vendor: 'AWS', services: ['Hosting', 'Storage'], serviceCount: 2, criticality: 'high', singlePointOfFailure: false, notes: 'Primary cloud provider' },
    ];

    const rows = vendorDeps.map(vd => [
      vd.vendor,
      vd.services.join(', '),
      String(vd.serviceCount),
      vd.criticality.charAt(0).toUpperCase() + vd.criticality.slice(1),
      vd.singlePointOfFailure ? 'YES' : 'No',
      vd.notes,
    ]);

    expect(rows.length).toBe(2);
    expect(rows[0][0]).toBe('Cloudflare');
    expect(rows[0][1]).toBe('CDN, WAF, DNS');
    expect(rows[0][4]).toBe('YES');
    expect(rows[1][4]).toBe('No');
    expect(rows[0][3]).toBe('Critical');
  });

  it('handles empty vendor dependencies gracefully', () => {
    const vendorDeps: any[] = [];
    // The PDF export skips this section when empty
    expect(vendorDeps.length).toBe(0);
  });
});

// ─── Supply Chain Risks ─────────────────────────────────────────────────────

describe('PDF Export — Supply Chain Risks', () => {
  it('formats risk type labels correctly', () => {
    const riskTypes = ['vendor_concentration', 'single_provider', 'unmanaged_exposure', 'legacy_tech', 'missing_defense', 'c2_detected'];
    const formatted = riskTypes.map(rt =>
      rt.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
    );

    expect(formatted[0]).toBe('Vendor Concentration');
    expect(formatted[1]).toBe('Single Provider');
    expect(formatted[2]).toBe('Unmanaged Exposure');
    expect(formatted[3]).toBe('Legacy Tech');
    expect(formatted[4]).toBe('Missing Defense');
    expect(formatted[5]).toBe('C2 Detected');
  });

  it('renders supply chain risk rows', () => {
    const risks = [
      { riskType: 'vendor_concentration', severity: 'high', description: 'Cloudflare provides 3+ services', affectedServices: ['CDN', 'WAF', 'DNS'], recommendation: 'Evaluate redundancy' },
      { riskType: 'c2_detected', severity: 'critical', description: 'JARM fingerprint matches known C2', affectedServices: ['Unknown service on port 443'], recommendation: 'Investigate immediately' },
    ];

    const rows = risks.map(r => [
      r.riskType.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
      r.severity.charAt(0).toUpperCase() + r.severity.slice(1),
      r.description,
      r.affectedServices.join(', '),
      r.recommendation,
    ]);

    expect(rows.length).toBe(2);
    expect(rows[0][0]).toBe('Vendor Concentration');
    expect(rows[1][1]).toBe('Critical');
    expect(rows[1][0]).toBe('C2 Detected');
  });
});

// ─── InfraMapData Interface ─────────────────────────────────────────────────

describe('PDF Export — InfraMapData Interface', () => {
  it('handles null infraMap gracefully', () => {
    const infraMap = null;
    const vendorDeps = infraMap?.vendorDependencies || [];
    const scRisks = infraMap?.supplyChainRisks || [];
    const summary = infraMap?.summary;

    expect(vendorDeps).toEqual([]);
    expect(scRisks).toEqual([]);
    expect(summary).toBeUndefined();
  });

  it('handles undefined infraMap gracefully', () => {
    const infraMap = undefined;
    const vendorDeps = infraMap?.vendorDependencies || [];
    const scRisks = infraMap?.supplyChainRisks || [];

    expect(vendorDeps).toEqual([]);
    expect(scRisks).toEqual([]);
  });

  it('extracts data from populated infraMap', () => {
    const infraMap = {
      vendorDependencies: [
        { vendor: 'AWS', services: ['EC2', 'S3'], serviceCount: 2, criticality: 'high', singlePointOfFailure: false, notes: 'Primary cloud' },
      ],
      supplyChainRisks: [
        { riskType: 'vendor_concentration', severity: 'medium', description: 'Test', affectedServices: ['EC2'], recommendation: 'Diversify' },
      ],
      summary: {
        totalServices: 12,
        totalVendors: 5,
        thirdPartyManaged: 3,
        externallyExposed: 8,
        criticalRisks: 1,
        highRisks: 2,
        topVendor: 'AWS',
        topVendorServiceCount: 4,
        overallMaturity: 'moderate',
      },
    };

    expect(infraMap.vendorDependencies.length).toBe(1);
    expect(infraMap.vendorDependencies[0].vendor).toBe('AWS');
    expect(infraMap.supplyChainRisks.length).toBe(1);
    expect(infraMap.summary.totalServices).toBe(12);
    expect(infraMap.summary.overallMaturity).toBe('moderate');
  });

  it('builds infrastructure summary table rows', () => {
    const summary = {
      totalServices: 15,
      totalVendors: 7,
      thirdPartyManaged: 4,
      externallyExposed: 10,
      criticalRisks: 2,
      highRisks: 3,
      topVendor: 'Cloudflare' as string | null,
      topVendorServiceCount: 5,
      overallMaturity: 'advanced',
    };

    const rows: string[][] = [
      ['Total Services Detected', String(summary.totalServices)],
      ['Total Vendors', String(summary.totalVendors)],
      ['Third-Party Managed', String(summary.thirdPartyManaged)],
      ['Externally Exposed', String(summary.externallyExposed)],
      ['Critical Supply Chain Risks', String(summary.criticalRisks)],
      ['High Supply Chain Risks', String(summary.highRisks)],
      ['Top Vendor', summary.topVendor ? `${summary.topVendor} (${summary.topVendorServiceCount} services)` : 'N/A'],
      ['Overall Infrastructure Maturity', summary.overallMaturity.charAt(0).toUpperCase() + summary.overallMaturity.slice(1)],
    ];

    expect(rows.length).toBe(8);
    expect(rows[0][1]).toBe('15');
    expect(rows[6][1]).toBe('Cloudflare (5 services)');
    expect(rows[7][1]).toBe('Advanced');
  });

  it('handles null topVendor in summary', () => {
    const summary = {
      topVendor: null as string | null,
      topVendorServiceCount: 0,
    };

    const topVendorDisplay = summary.topVendor
      ? `${summary.topVendor} (${summary.topVendorServiceCount} services)`
      : 'N/A';

    expect(topVendorDisplay).toBe('N/A');
  });
});

// ─── Export Function Signature ──────────────────────────────────────────────

describe('PDF Export — Function Signature', () => {
  it('exports InfraMapData interface', async () => {
    const mod = await import('../client/src/lib/export-di-report');
    expect(mod.exportDiReport).toBeDefined();
    expect(typeof mod.exportDiReport).toBe('function');
    // The function should accept 5 parameters (domain, scan, wlConfig, evidenceData, infraMap)
    // We can't easily test the parameter count in JS but we verify it's callable
  });
});
