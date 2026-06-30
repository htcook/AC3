import { describe, it, expect, vi } from "vitest";

/**
 * Tests for managed provider asset filtering in LLM summary prompts.
 * Verifies that managed provider and third-party assets are excluded
 * from the findings lists sent to the LLM, preventing inaccurate
 * attribution of provider CVEs to the client.
 */

// Mock the LLM to capture the prompt
let capturedPrompt = '';
vi.mock('../server/_core/llm', () => ({
  invokeLLM: vi.fn(async (params: any) => {
    capturedPrompt = params.messages?.[1]?.content || '';
    return {
      choices: [{
        message: {
          content: JSON.stringify({
            executiveSummary: 'Test summary',
            threatModelSummary: 'Test threat model',
          }),
        },
      }],
    };
  }),
}));

// Import after mock
import { generateScanOnlySummary } from "./domainIntel";

// Helper to create a mock AssetAnalysis
function mockAnalysis(hostname: string, tags: string[], findings: any[]): any {
  return {
    asset: {
      assetId: `asset-${hostname}`,
      hostname,
      assetType: 'web_server',
      technologies: ['nginx'],
      tags,
    },
    hybridRiskScore: 40,
    riskBand: 'moderate',
    assetCriticalityBand: 'medium',
    missionFunction: 'public_facing_services',
    essentialService: 'web_server',
    postureFindings: findings,
    carverScores: {},
    shockScores: {},
  };
}

function mockFinding(id: string, title: string, tier: string, kev: boolean, hostname: string): any {
  return {
    id,
    title,
    severity: 8,
    corroborationTier: tier,
    versionMatchConfirmed: tier === 'confirmed',
    kevListed: kev,
    cvssScore: 9.0,
    detectedVersion: tier === 'confirmed' ? '15.0.1' : undefined,
    category: 'Vulnerability',
    assetHostname: hostname,
    evidenceDetail: `Test finding on ${hostname}`,
  };
}

describe("Managed Provider Filtering in LLM Prompts", () => {
  it("should exclude managed provider asset findings from scan-only summary", async () => {
    const analyses = [
      // Client-owned asset
      mockAnalysis('api.aceofcloud.com', ['subdomain'], [
        mockFinding('f1', 'Next.js CVE', 'probable', false, 'api.aceofcloud.com'),
      ]),
      // Managed provider asset (outlook.com)
      mockAnalysis('outlook.com', ['reverse_whois', 'related_domain'], [
        mockFinding('f2', 'CVE-2021-42321: Exchange RCE', 'confirmed', true, 'outlook.com'),
        mockFinding('f3', 'CVE-2026-20963: SharePoint Vuln', 'confirmed', true, 'outlook.com'),
      ]),
    ];

    const org = {
      customerName: 'AceofCloud',
      primaryDomain: 'aceofcloud.com',
      sector: 'technology',
      clientType: 'enterprise',
    };

    await generateScanOnlySummary(analyses as any, org as any, {
      managedProviderName: 'Microsoft 365',
    });

    // The prompt should NOT contain Exchange or SharePoint CVEs as findings
    expect(capturedPrompt).not.toContain('CVE-2021-42321');
    expect(capturedPrompt).not.toContain('Exchange RCE');
    expect(capturedPrompt).not.toContain('CVE-2026-20963');
    // Note: 'SharePoint' appears in the exclusion context message ("Mail server CVEs (e.g., Exchange, SharePoint)")
    // which is correct — it's telling the LLM NOT to attribute them. The CVE itself should not appear.
    expect(capturedPrompt).not.toContain('SharePoint Vuln');

    // The prompt SHOULD contain the client-owned finding
    expect(capturedPrompt).toContain('Next.js CVE');

    // The prompt should mention exclusion
    expect(capturedPrompt).toContain('excluded');
    expect(capturedPrompt).toContain('outlook.com');
  });

  it("should show correct asset counts (client-owned vs excluded)", async () => {
    const analyses = [
      mockAnalysis('api.aceofcloud.com', ['subdomain'], [
        mockFinding('f1', 'Client Finding', 'probable', false, 'api.aceofcloud.com'),
      ]),
      mockAnalysis('outlook.com', ['reverse_whois', 'related_domain'], [
        mockFinding('f2', 'Exchange CVE', 'confirmed', true, 'outlook.com'),
      ]),
      mockAnalysis('nsone.net', ['reverse_whois', 'related_domain'], [
        mockFinding('f3', 'NS1 Finding', 'probable', false, 'nsone.net'),
      ]),
    ];

    const org = {
      customerName: 'AceofCloud',
      primaryDomain: 'aceofcloud.com',
      sector: 'technology',
      clientType: 'enterprise',
    };

    await generateScanOnlySummary(analyses as any, org as any, {
      managedProviderName: 'Microsoft 365',
    });

    // Should show 1 client-owned, 2 excluded
    expect(capturedPrompt).toContain('Digital Assets Discovered: 1');
    expect(capturedPrompt).toContain('2 third-party managed assets excluded');
  });

  it("should exclude reverse WHOIS third-party assets even without managed provider", async () => {
    const analyses = [
      mockAnalysis('app.aceofcloud.com', ['subdomain'], [
        mockFinding('f1', 'Client Finding', 'confirmed', false, 'app.aceofcloud.com'),
      ]),
      mockAnalysis('nsone.net', ['reverse_whois', 'related_domain'], [
        mockFinding('f2', 'NS1 CVE', 'confirmed', true, 'nsone.net'),
      ]),
    ];

    const org = {
      customerName: 'AceofCloud',
      primaryDomain: 'aceofcloud.com',
      sector: 'technology',
      clientType: 'enterprise',
    };

    // No managed provider name
    await generateScanOnlySummary(analyses as any, org as any);

    // nsone.net should still be excluded (reverse WHOIS third-party)
    expect(capturedPrompt).not.toContain('NS1 CVE');
    expect(capturedPrompt).toContain('Client Finding');
  });

  it("should include all findings when no managed provider or third-party assets exist", async () => {
    const analyses = [
      mockAnalysis('api.aceofcloud.com', ['subdomain'], [
        mockFinding('f1', 'API Finding', 'confirmed', true, 'api.aceofcloud.com'),
      ]),
      mockAnalysis('app.aceofcloud.com', ['subdomain'], [
        mockFinding('f2', 'App Finding', 'probable', false, 'app.aceofcloud.com'),
      ]),
    ];

    const org = {
      customerName: 'AceofCloud',
      primaryDomain: 'aceofcloud.com',
      sector: 'technology',
      clientType: 'enterprise',
    };

    await generateScanOnlySummary(analyses as any, org as any);

    // Both findings should be present
    expect(capturedPrompt).toContain('API Finding');
    expect(capturedPrompt).toContain('App Finding');
    // No exclusion context
    expect(capturedPrompt).not.toContain('MANAGED/THIRD-PARTY ASSET EXCLUSION');
  });

  it("should correctly count KEV findings from client-owned assets only", async () => {
    const analyses = [
      mockAnalysis('api.aceofcloud.com', ['subdomain'], [
        mockFinding('f1', 'Client KEV', 'confirmed', true, 'api.aceofcloud.com'),
      ]),
      mockAnalysis('outlook.com', ['reverse_whois', 'related_domain'], [
        mockFinding('f2', 'Exchange KEV 1', 'confirmed', true, 'outlook.com'),
        mockFinding('f3', 'Exchange KEV 2', 'confirmed', true, 'outlook.com'),
        mockFinding('f4', 'Exchange KEV 3', 'confirmed', true, 'outlook.com'),
      ]),
    ];

    const org = {
      customerName: 'AceofCloud',
      primaryDomain: 'aceofcloud.com',
      sector: 'technology',
      clientType: 'enterprise',
    };

    await generateScanOnlySummary(analyses as any, org as any, {
      managedProviderName: 'Microsoft 365',
    });

    // Should show only 1 KEV finding (client-owned), not 4
    expect(capturedPrompt).toContain('Actively Exploited Vulnerabilities (per government alerts): 1');
  });
});
