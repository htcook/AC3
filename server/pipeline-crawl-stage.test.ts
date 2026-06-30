import { describe, it, expect, vi } from 'vitest';

// Mock the web-crawler module
vi.mock('./lib/web-crawler', () => ({
  quickScan: vi.fn().mockResolvedValue({
    url: 'https://example.com',
    finalUrl: 'https://example.com',
    httpStatus: 200,
    responseTimeMs: 450,
    contentType: 'text/html',
    contentLength: 12000,
    depth: 0,
    securityHeaders: {},
    securityHeaderGrade: 'B',
    detectedTechnologies: [
      { name: 'React', version: '18.2.0', confidence: 100, categories: ['JavaScript frameworks'] },
      { name: 'Next.js', version: '14.0', confidence: 90, categories: ['Web frameworks'] },
    ],
    serverHeader: 'nginx',
    poweredBy: null,
    pageTitle: 'Example Corp - Cloud Solutions',
    metaDescription: 'Enterprise cloud solutions for healthcare and finance',
    internalLinks: ['/about', '/services', '/products', '/contact'],
    externalLinks: ['https://aws.amazon.com', 'https://partner.com'],
    resourceUrls: [],
    forms: [{ action: '/contact', method: 'POST', fields: ['name', 'email'] }],
    exposedPaths: [],
    robotsTxt: 'User-agent: *\nDisallow: /admin',
    securityTxt: null,
    sitemapUrls: [],
    cookies: [{ name: 'session', secure: false, httpOnly: true, sameSite: 'lax' }],
    tlsInfo: { protocol: 'TLSv1.3' },
    findings: [
      { severity: 'medium', title: 'Missing X-Frame-Options', description: 'X-Frame-Options header not set' },
    ],
    findingCounts: { critical: 0, high: 0, medium: 1, low: 0, info: 0 },
    rawHeaders: {},
  }),
}));

// Mock the crawl-carver-integration module
vi.mock('./lib/crawl-carver-integration', () => ({
  computeCrawlCarverAdjustments: vi.fn().mockReturnValue({
    carver: { criticality: 0.1, accessibility: 0.2, recuperability: 0, vulnerability: 0.15, effect: 0, recognizability: 0.1 },
    shock: { scope: 0, handling: 0.1, operationalImpact: 0, cascadingEffects: 0, knowledge: 0.05 },
    likelihoodBoost: 0.05,
    contextAdjustment: { exposureBoost: 0.1, recognizabilityBoost: 0.05, confidenceBoost: 0.1 },
    breakdown: {
      headerScore: { grade: 'B', missingCritical: [], missingMedium: ['X-Frame-Options'], misconfigured: [], vulnerabilityImpact: 0.15, handlingImpact: 0.1 },
      exposedPathScore: { criticalPaths: [], highPaths: [], mediumPaths: [], accessibilityImpact: 0, effectImpact: 0 },
      cookieScore: { insecureCookies: ['session'], totalCookies: 1, vulnerabilityImpact: 0.1 },
      technologyScore: { detectedTech: ['React', 'Next.js'], outdatedVersions: [], recognizabilityImpact: 0.1, knowledgeImpact: 0.05 },
      tlsScore: { issues: [], vulnerabilityImpact: 0 },
    },
    postureFindings: [
      {
        id: 'crawl-1',
        category: 'web_security',
        title: 'Missing X-Frame-Options Header',
        severity: 5,
        confidence: 100,
        description: 'X-Frame-Options header not set',
        evidenceDetail: 'Header missing from response',
        corroborationTier: 'confirmed' as const,
        remediation: 'Add X-Frame-Options: DENY header',
        source: 'web_crawler' as const,
      },
    ],
  }),
}));

// Mock the LLM
vi.mock('./_core/llm', () => ({
  invokeLLM: vi.fn().mockResolvedValue({
    choices: [{
      message: {
        content: JSON.stringify({
          services: ['Cloud Migration', 'Managed Security'],
          products: ['CloudShield', 'SecureConnect'],
          industryIndicators: ['Healthcare IT', 'Financial Services'],
          partnerships: ['AWS Partner', 'Microsoft Gold'],
          targetMarket: ['Enterprise', 'Mid-Market'],
          complianceMentions: ['HIPAA', 'SOC 2'],
          geographicPresence: ['United States', 'Europe'],
          pricingModel: 'Subscription-based SaaS',
          businessSummary: 'Example Corp provides cloud migration and managed security services for healthcare and financial enterprises.',
          confidence: 0.85,
        }),
      },
    }],
  }),
}));

describe('Pipeline Crawl Stage', () => {
  it('should export the main functions', async () => {
    const mod = await import('./lib/pipeline-crawl-stage');
    expect(mod.runPipelineCrawlStage).toBeDefined();
    expect(typeof mod.runPipelineCrawlStage).toBe('function');
    expect(mod.enrichOrgWithBusinessIntel).toBeDefined();
    expect(typeof mod.enrichOrgWithBusinessIntel).toBe('function');
    expect(mod.applyBusinessIntelCarverBoosts).toBeDefined();
    expect(typeof mod.applyBusinessIntelCarverBoosts).toBe('function');
  });

  it('enrichOrgWithBusinessIntel should add services, industry, and compliance to org profile', async () => {
    const { enrichOrgWithBusinessIntel } = await import('./lib/pipeline-crawl-stage');
    const org: any = {
      customerName: 'Test Corp',
      primaryDomain: 'test.com',
      sector: 'Technology',
      clientType: 'enterprise',
      criticalFunctions: [],
      complianceFlags: [],
    };
    const bizIntel = {
      services: ['Cloud Migration', 'Managed Security'],
      products: ['CloudShield'],
      industryIndicators: ['Healthcare IT'],
      partnerships: ['AWS Partner'],
      targetMarket: ['Enterprise'],
      complianceMentions: ['HIPAA', 'SOC 2'],
      geographicPresence: ['US'],
      pricingModel: 'SaaS',
      businessSummary: 'Test summary',
      confidence: 0.85,
    };

    enrichOrgWithBusinessIntel(org, bizIntel);

    expect(org.keyProducts).toEqual(['Cloud Migration', 'Managed Security', 'CloudShield']);
    expect(org.industry).toBe('Healthcare IT');
    expect(org.complianceFlags).toContain('HIPAA');
    expect(org.complianceFlags).toContain('SOC 2');
  });

  it('applyBusinessIntelCarverBoosts should boost CARVER scores for compliance-heavy orgs', async () => {
    const { applyBusinessIntelCarverBoosts } = await import('./lib/pipeline-crawl-stage');
    const analyses: any[] = [
      {
        asset: { hostname: 'app.test.com', assetType: 'web' },
        carverScores: { criticality: 5, accessibility: 5, recuperability: 5, vulnerability: 5, effect: 5, recognizability: 5 },
        shockScores: { scope: 5, handling: 5, operationalImpact: 5, cascadingEffects: 5, knowledge: 5 },
      },
    ];
    const bizIntel = {
      services: ['Cloud Migration'],
      products: [],
      industryIndicators: ['Healthcare IT'],
      partnerships: [],
      targetMarket: ['Enterprise'],
      complianceMentions: ['HIPAA', 'PCI-DSS', 'SOC 2'],
      geographicPresence: [],
      pricingModel: '',
      businessSummary: '',
      confidence: 0.8,
    };

    const count = applyBusinessIntelCarverBoosts(analyses, bizIntel);

    expect(count).toBe(1);
    // Compliance mentions should boost criticality and effect
    expect(analyses[0].carverScores.criticality).toBeGreaterThan(5);
    expect(analyses[0].carverScores.effect).toBeGreaterThan(5);
  });

  it('applyBusinessIntelCarverBoosts should not exceed max score of 10', async () => {
    const { applyBusinessIntelCarverBoosts } = await import('./lib/pipeline-crawl-stage');
    const analyses: any[] = [
      {
        asset: { hostname: 'app.test.com', assetType: 'web' },
        carverScores: { criticality: 9.5, accessibility: 9, recuperability: 9, vulnerability: 9, effect: 9.5, recognizability: 9 },
        shockScores: { scope: 9, handling: 9, operationalImpact: 9, cascadingEffects: 9, knowledge: 9 },
      },
    ];
    const bizIntel = {
      services: ['Cloud Migration', 'Managed Security', 'Compliance Consulting'],
      products: ['Product1', 'Product2'],
      industryIndicators: ['Healthcare IT', 'Financial Services'],
      partnerships: ['AWS', 'Microsoft', 'Google'],
      targetMarket: ['Enterprise', 'Government'],
      complianceMentions: ['HIPAA', 'PCI-DSS', 'SOC 2', 'FedRAMP', 'GDPR'],
      geographicPresence: ['US', 'EU'],
      pricingModel: 'Enterprise',
      businessSummary: 'Major enterprise provider',
      confidence: 0.95,
    };

    applyBusinessIntelCarverBoosts(analyses, bizIntel);

    // All scores should be capped at 10
    expect(analyses[0].carverScores.criticality).toBeLessThanOrEqual(10);
    expect(analyses[0].carverScores.effect).toBeLessThanOrEqual(10);
    expect(analyses[0].shockScores.scope).toBeLessThanOrEqual(10);
  });

  it('enrichOrgWithBusinessIntel should not duplicate existing compliance flags', async () => {
    const { enrichOrgWithBusinessIntel } = await import('./lib/pipeline-crawl-stage');
    const org: any = {
      customerName: 'Test Corp',
      primaryDomain: 'test.com',
      sector: 'Technology',
      clientType: 'enterprise',
      criticalFunctions: [],
      complianceFlags: ['HIPAA'], // Already has HIPAA
    };
    const bizIntel = {
      services: [],
      products: [],
      industryIndicators: [],
      partnerships: [],
      targetMarket: [],
      complianceMentions: ['HIPAA', 'SOC 2'], // HIPAA again + new SOC 2
      geographicPresence: [],
      pricingModel: '',
      businessSummary: '',
      confidence: 0.8,
    };

    enrichOrgWithBusinessIntel(org, bizIntel);

    // Should not duplicate HIPAA
    const hipaaCount = org.complianceFlags.filter((f: string) => f === 'HIPAA').length;
    expect(hipaaCount).toBe(1);
    expect(org.complianceFlags).toContain('SOC 2');
  });
});
