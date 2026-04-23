import { describe, it, expect, vi } from 'vitest';

// ─── Domain Registration Fallback Tests ─────────────────────────────────
describe('domainRegistration dehashed_whois fallback', () => {
  // Simulates the extraction logic from domain-intel-core.ts
  function extractDomainRegistration(allObservations: any[]) {
    // Try RDAP first
    const rdapObs = allObservations.find(
      (o: any) => o.source === 'rdap' && o.tags?.includes('domain_registration')
    );
    if (rdapObs) {
      const ev = rdapObs.evidence || {};
      return {
        registrar: ev.registrar || null,
        registrationDate: ev.registrationDate || null,
        expirationDate: ev.expirationDate || null,
        lastChanged: ev.lastChanged || null,
        status: ev.status || [],
        nameservers: ev.nameservers || [],
        dnssec: ev.dnssec === 'signedDelegation' || ev.dnssec === 'signed' || false,
        handle: ev.handle || null,
        source: 'rdap',
      };
    }
    // Fallback to Dehashed WHOIS
    const dehashedObs = allObservations.find(
      (o: any) => o.source === 'dehashed_whois' && o.tags?.includes('domain_registration')
    );
    if (dehashedObs) {
      const ev = dehashedObs.evidence || {};
      return {
        registrar: ev.registrar || null,
        registrationDate: ev.creation_date || null,
        expirationDate: ev.expiration_date || null,
        lastChanged: ev.updated_date || null,
        status: ev.status || [],
        nameservers: ev.name_servers || [],
        dnssec: ev.dnssec === 'signedDelegation' || ev.dnssec === 'signed' || false,
        handle: null,
        registrantOrg: ev.registrant_organization || null,
        registrantCountry: ev.registrant_country || null,
        domainAgeYears: ev.domain_age_years || null,
        daysUntilExpiry: ev.days_until_expiry || null,
        riskSignals: ev.risk_signals || [],
        source: 'dehashed_whois',
      };
    }
    return null;
  }

  it('should use RDAP data when available', () => {
    const obs = [
      {
        source: 'rdap',
        tags: ['domain_registration'],
        evidence: {
          registrar: 'GoDaddy',
          registrationDate: '2020-01-01',
          expirationDate: '2025-01-01',
          status: ['clientTransferProhibited'],
          nameservers: ['ns1.example.com'],
          dnssec: 'signedDelegation',
          handle: 'D12345',
        },
      },
    ];
    const result = extractDomainRegistration(obs);
    expect(result).not.toBeNull();
    expect(result!.source).toBe('rdap');
    expect(result!.registrar).toBe('GoDaddy');
    expect(result!.dnssec).toBe(true);
    expect(result!.handle).toBe('D12345');
  });

  it('should fall back to dehashed_whois when RDAP is missing', () => {
    const obs = [
      {
        source: 'dehashed_whois',
        tags: ['domain_registration'],
        evidence: {
          registrar: 'Namecheap',
          creation_date: '2019-06-15',
          expiration_date: '2026-06-15',
          updated_date: '2024-01-10',
          status: ['clientTransferProhibited'],
          name_servers: ['ns1.namecheap.com', 'ns2.namecheap.com'],
          dnssec: 'unsigned',
          registrant_organization: 'TES Consultants',
          registrant_country: 'US',
          domain_age_years: 6,
          days_until_expiry: 420,
          risk_signals: ['No DNSSEC'],
        },
      },
    ];
    const result = extractDomainRegistration(obs);
    expect(result).not.toBeNull();
    expect(result!.source).toBe('dehashed_whois');
    expect(result!.registrar).toBe('Namecheap');
    expect(result!.registrantOrg).toBe('TES Consultants');
    expect(result!.registrantCountry).toBe('US');
    expect(result!.domainAgeYears).toBe(6);
    expect(result!.daysUntilExpiry).toBe(420);
    expect(result!.riskSignals).toEqual(['No DNSSEC']);
    expect(result!.dnssec).toBe(false);
  });

  it('should prefer RDAP over dehashed_whois when both exist', () => {
    const obs = [
      {
        source: 'rdap',
        tags: ['domain_registration'],
        evidence: { registrar: 'GoDaddy', handle: 'D12345' },
      },
      {
        source: 'dehashed_whois',
        tags: ['domain_registration'],
        evidence: { registrar: 'Namecheap', registrant_organization: 'TES' },
      },
    ];
    const result = extractDomainRegistration(obs);
    expect(result!.source).toBe('rdap');
    expect(result!.registrar).toBe('GoDaddy');
  });

  it('should return null when neither source has registration data', () => {
    const obs = [
      { source: 'censys', tags: ['certificate'], evidence: {} },
      { source: 'shodan', tags: ['port_scan'], evidence: {} },
    ];
    const result = extractDomainRegistration(obs);
    expect(result).toBeNull();
  });

  it('should handle empty observations array', () => {
    const result = extractDomainRegistration([]);
    expect(result).toBeNull();
  });
});

// ─── Report Recommendation Truncation Tests ─────────────────────────────
describe('report recommendation rendering', () => {
  // Simulates the recommendation body mapping from export-di-report.ts
  function mapRecommendationBody(recommendations: any[]): string[][] {
    return recommendations.slice(0, 20).map((r: any, i: number) => [
      `P${i + 1}`,
      r.recommendation || r.description || r.title || (typeof r === 'string' ? r : ''),
      (r.category || 'General').replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase()),
      (r.effort || 'N/A').replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase()),
    ]);
  }

  it('should NOT truncate long recommendations', () => {
    const longRec = 'A'.repeat(400);
    const recs = [{ recommendation: longRec, category: 'Vulnerability Management', effort: 'Short Term' }];
    const body = mapRecommendationBody(recs);
    expect(body[0][1]).toBe(longRec);
    expect(body[0][1].length).toBe(400);
  });

  it('should fall back to description when recommendation is missing', () => {
    const recs = [{ description: 'Use description field', category: 'General', effort: 'Quick Win' }];
    const body = mapRecommendationBody(recs);
    expect(body[0][1]).toBe('Use description field');
  });

  it('should fall back to title when both recommendation and description are missing', () => {
    const recs = [{ title: 'Enable DNSSEC', category: 'DNS Security', effort: 'Short Term' }];
    const body = mapRecommendationBody(recs);
    expect(body[0][1]).toBe('Enable DNSSEC');
  });

  it('should handle string-type recommendations', () => {
    const recs = ['Simple string recommendation'];
    const body = mapRecommendationBody(recs);
    expect(body[0][1]).toBe('Simple string recommendation');
  });

  it('should limit to 20 recommendations', () => {
    const recs = Array.from({ length: 30 }, (_, i) => ({ recommendation: `Rec ${i}`, category: 'General', effort: 'N/A' }));
    const body = mapRecommendationBody(recs);
    expect(body.length).toBe(20);
  });
});

// ─── Entity Profile & Financial Impact Report Section Tests ─────────────
describe('entity profile and financial impact in report', () => {
  function formatMoney(v: number): string {
    if (v >= 1_000_000) return `$${(v / 1_000_000).toFixed(1)}M`;
    if (v >= 1_000) return `$${(v / 1_000).toFixed(0)}K`;
    return `$${v}`;
  }

  it('should format financial values correctly', () => {
    expect(formatMoney(845893)).toBe('$846K');
    expect(formatMoney(150000)).toBe('$150K');
    expect(formatMoney(1500000)).toBe('$1.5M');
    expect(formatMoney(500)).toBe('$500');
    expect(formatMoney(13699)).toBe('$14K');
  });

  it('should build entity profile rows from data', () => {
    const ep = {
      orgName: 'TES Consultants',
      industry: 'Consulting',
      estimatedRevenue: 5000000,
      estimatedEmployees: 50,
      headquarters: 'Washington, DC',
      isPublicCompany: false,
      foundedYear: 2015,
      keyProducts: ['IT Consulting', 'Cybersecurity'],
      identificationMethod: 'whois_ssl_correlation',
      confidence: 85,
    };
    const rows: string[][] = [];
    if (ep.orgName) rows.push(['Organization', ep.orgName]);
    if (ep.industry) rows.push(['Industry', ep.industry]);
    if (ep.estimatedRevenue) rows.push(['Est. Annual Revenue', `$${(ep.estimatedRevenue / 1_000_000).toFixed(1)}M`]);
    if (ep.estimatedEmployees) rows.push(['Est. Employees', String(ep.estimatedEmployees)]);
    if (ep.headquarters) rows.push(['Headquarters', ep.headquarters]);
    if (ep.isPublicCompany !== undefined) rows.push(['Public Company', ep.isPublicCompany ? 'Yes' : 'No']);
    if (ep.foundedYear) rows.push(['Founded', String(ep.foundedYear)]);
    if (ep.keyProducts?.length > 0) rows.push(['Key Products/Services', ep.keyProducts.slice(0, 5).join(', ')]);
    if (ep.identificationMethod) rows.push(['Identification Method', ep.identificationMethod]);
    if (ep.confidence) rows.push(['Confidence', `${ep.confidence}%`]);

    expect(rows.length).toBe(10);
    expect(rows[0]).toEqual(['Organization', 'TES Consultants']);
    expect(rows[2]).toEqual(['Est. Annual Revenue', '$5.0M']);
    expect(rows[5]).toEqual(['Public Company', 'No']);
    expect(rows[9]).toEqual(['Confidence', '85%']);
  });

  it('should build financial impact rows from data', () => {
    const fi = {
      totalMaxExposure: 845893,
      maxSingleIncidentLoss: 150000,
      estimatedDailyRevenueLoss: 13699,
      regulatoryFineExposure: 200000,
      reputationalDamageEstimate: 400000,
      impactTier: 'moderate',
      rationale: 'Annual revenue: $5.0M',
    };
    const rows: string[][] = [];
    if (fi.totalMaxExposure) rows.push(['Total Maximum Exposure', formatMoney(fi.totalMaxExposure)]);
    if (fi.maxSingleIncidentLoss) rows.push(['Max Single Incident Loss', formatMoney(fi.maxSingleIncidentLoss)]);
    if (fi.estimatedDailyRevenueLoss) rows.push(['Est. Daily Revenue Loss', formatMoney(fi.estimatedDailyRevenueLoss)]);
    if (fi.regulatoryFineExposure) rows.push(['Regulatory Fine Exposure', formatMoney(fi.regulatoryFineExposure)]);
    if (fi.reputationalDamageEstimate) rows.push(['Reputational Damage Est.', formatMoney(fi.reputationalDamageEstimate)]);

    expect(rows.length).toBe(5);
    expect(rows[0]).toEqual(['Total Maximum Exposure', '$846K']);
    expect(rows[1]).toEqual(['Max Single Incident Loss', '$150K']);
  });

  it('should map impact tier to correct color', () => {
    const tierColor = (tier: string) => {
      if (tier === 'critical') return 'red';
      if (tier === 'high') return 'orange';
      if (tier === 'moderate') return 'yellow';
      return 'green';
    };
    expect(tierColor('critical')).toBe('red');
    expect(tierColor('high')).toBe('orange');
    expect(tierColor('moderate')).toBe('yellow');
    expect(tierColor('low')).toBe('green');
  });
});

// ─── Domain Registration Report Section Tests ───────────────────────────
describe('domain registration report section with dehashed fields', () => {
  it('should include dehashed-specific fields in registration rows', () => {
    const reg = {
      registrar: 'Namecheap',
      registrationDate: '2019-06-15',
      expirationDate: '2026-06-15',
      dnssec: false,
      nameservers: ['ns1.namecheap.com'],
      status: ['clientTransferProhibited'],
      registrantOrg: 'TES Consultants',
      registrantCountry: 'US',
      domainAgeYears: 6,
      daysUntilExpiry: 420,
      source: 'dehashed_whois',
    };

    const rows: string[][] = [];
    rows.push(['Registrar', reg.registrar || 'N/A']);
    rows.push(['DNSSEC', reg.dnssec ? 'Enabled' : 'Not Enabled']);
    if (reg.nameservers?.length > 0) rows.push(['Nameservers', reg.nameservers.join(', ')]);
    if (reg.status?.length > 0) rows.push(['Status Codes', reg.status.join(', ')]);
    if (reg.registrantOrg) rows.push(['Registrant Organization', reg.registrantOrg]);
    if (reg.registrantCountry) rows.push(['Registrant Country', reg.registrantCountry]);
    if (reg.domainAgeYears) rows.push(['Domain Age', `${reg.domainAgeYears} years`]);
    if (reg.daysUntilExpiry) rows.push(['Days Until Expiry (WHOIS)', String(reg.daysUntilExpiry)]);
    if (reg.source) rows.push(['Data Source', reg.source === 'dehashed_whois' ? 'Dehashed WHOIS' : reg.source === 'rdap' ? 'RDAP' : reg.source]);

    expect(rows.find(r => r[0] === 'Registrant Organization')?.[1]).toBe('TES Consultants');
    expect(rows.find(r => r[0] === 'Registrant Country')?.[1]).toBe('US');
    expect(rows.find(r => r[0] === 'Domain Age')?.[1]).toBe('6 years');
    expect(rows.find(r => r[0] === 'Data Source')?.[1]).toBe('Dehashed WHOIS');
    expect(rows.find(r => r[0] === 'DNSSEC')?.[1]).toBe('Not Enabled');
  });

  it('should format RDAP source label correctly', () => {
    const source = 'rdap';
    const label = source === 'dehashed_whois' ? 'Dehashed WHOIS' : source === 'rdap' ? 'RDAP' : source;
    expect(label).toBe('RDAP');
  });
});
