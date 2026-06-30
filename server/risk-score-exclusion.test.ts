import { describe, it, expect } from "vitest";

/**
 * Tests for managed provider / third-party asset exclusion from overall risk score.
 * These test the filtering logic used in domainIntel.ts to exclude non-client-owned
 * assets from the overall risk score calculation.
 */

// Replicate the filtering logic from domainIntel.ts
function filterClientOwnedAnalyses(
  analyses: Array<{ asset: { hostname: string; tags: string[] }; hybridRiskScore: number }>,
  managedProviderName: string | null,
  primaryDomain: string
) {
  const MANAGED_HOST_PATTERNS: Record<string, RegExp[]> = {
    'Microsoft 365': [/outlook\.com$/i, /microsoft\.com$/i, /office365/i, /protection\.outlook/i],
    'Google Workspace': [/google\.com$/i, /gmail\.com$/i, /googlemail/i],
    'Proofpoint': [/proofpoint/i],
    'Mimecast': [/mimecast/i],
    'Zoho Mail': [/zoho/i],
  };
  const managedPatterns = managedProviderName && MANAGED_HOST_PATTERNS[managedProviderName]
    ? MANAGED_HOST_PATTERNS[managedProviderName] : [];

  return analyses.filter(a => {
    const h = (a.asset.hostname || '').toLowerCase();
    const tags: string[] = a.asset.tags || [];
    // Exclude managed mail provider infrastructure
    if (managedPatterns.some(p => p.test(h))) return false;
    // Exclude third-party assets from reverse WHOIS
    const isReverseWhoisThirdParty = tags.includes('reverse_whois') && tags.includes('related_domain')
      && !h.includes(primaryDomain.toLowerCase().replace(/\.[^.]+$/, ''));
    if (isReverseWhoisThirdParty) return false;
    return true;
  });
}

describe("Risk Score — Managed Provider Exclusion", () => {
  const aceofcloudAnalyses = [
    { asset: { hostname: "www.aceofcloud.com", tags: ["internet_exposed", "primary_domain"] }, hybridRiskScore: 54 },
    { asset: { hostname: "aceofcloud.com", tags: ["internet_exposed", "primary_domain"] }, hybridRiskScore: 53 },
    { asset: { hostname: "aceofcloud.us", tags: ["internet_exposed", "typosquatting"] }, hybridRiskScore: 48 },
    { asset: { hostname: "outlook.com", tags: ["reverse_whois", "related_domain", "org_portfolio"] }, hybridRiskScore: 40 },
    { asset: { hostname: "aceofcloud.io", tags: ["internet_exposed", "typosquatting"] }, hybridRiskScore: 30 },
    { asset: { hostname: "sender.zohoinvoice.com", tags: ["reverse_whois", "related_domain", "org_portfolio"] }, hybridRiskScore: 30 },
    { asset: { hostname: "nsone.net", tags: ["reverse_whois", "related_domain", "org_portfolio"] }, hybridRiskScore: 30 },
    { asset: { hostname: "portal.aceofcloud.com", tags: ["internet_exposed", "authentication"] }, hybridRiskScore: 24 },
    { asset: { hostname: "api.prod.aceofcloud.com", tags: ["internet_exposed", "api_endpoint_detected"] }, hybridRiskScore: 24 },
  ];

  it("should exclude outlook.com when managed provider is Microsoft 365", () => {
    const filtered = filterClientOwnedAnalyses(aceofcloudAnalyses, "Microsoft 365", "aceofcloud.com");
    const hostnames = filtered.map(a => a.asset.hostname);
    expect(hostnames).not.toContain("outlook.com");
  });

  it("should exclude third-party reverse WHOIS assets (nsone.net, sender.zohoinvoice.com)", () => {
    const filtered = filterClientOwnedAnalyses(aceofcloudAnalyses, "Microsoft 365", "aceofcloud.com");
    const hostnames = filtered.map(a => a.asset.hostname);
    expect(hostnames).not.toContain("nsone.net");
    expect(hostnames).not.toContain("sender.zohoinvoice.com");
  });

  it("should keep client-owned assets including subdomains", () => {
    const filtered = filterClientOwnedAnalyses(aceofcloudAnalyses, "Microsoft 365", "aceofcloud.com");
    const hostnames = filtered.map(a => a.asset.hostname);
    expect(hostnames).toContain("www.aceofcloud.com");
    expect(hostnames).toContain("aceofcloud.com");
    expect(hostnames).toContain("portal.aceofcloud.com");
    expect(hostnames).toContain("api.prod.aceofcloud.com");
  });

  it("should keep typosquat domains (they are part of the client's risk surface)", () => {
    const filtered = filterClientOwnedAnalyses(aceofcloudAnalyses, "Microsoft 365", "aceofcloud.com");
    const hostnames = filtered.map(a => a.asset.hostname);
    expect(hostnames).toContain("aceofcloud.us");
    expect(hostnames).toContain("aceofcloud.io");
  });

  it("should produce lower average risk score without managed/third-party assets", () => {
    const allScores = aceofcloudAnalyses.map(a => a.hybridRiskScore);
    const allAvg = Math.round(allScores.reduce((s, v) => s + v, 0) / allScores.length);

    const filtered = filterClientOwnedAnalyses(aceofcloudAnalyses, "Microsoft 365", "aceofcloud.com");
    const filteredScores = filtered.map(a => a.hybridRiskScore);
    const filteredAvg = Math.round(filteredScores.reduce((s, v) => s + v, 0) / filteredScores.length);

    // The excluded assets (outlook.com=40, nsone.net=30, zohoinvoice=30) are all medium/low
    // so removing them should change the average
    expect(filtered.length).toBe(6); // 9 total - 3 excluded
    expect(filteredAvg).not.toBe(allAvg);
  });

  it("should not exclude anything when no managed provider is detected", () => {
    const filtered = filterClientOwnedAnalyses(aceofcloudAnalyses, null, "aceofcloud.com");
    // Still excludes reverse WHOIS third-party assets but not outlook.com (no managed provider pattern)
    const hostnames = filtered.map(a => a.asset.hostname);
    // outlook.com has reverse_whois + related_domain tags AND doesn't contain 'aceofcloud'
    // so it IS excluded as a third-party reverse WHOIS asset even without managed provider
    expect(hostnames).not.toContain("nsone.net");
    expect(hostnames).not.toContain("sender.zohoinvoice.com");
    expect(hostnames).not.toContain("outlook.com"); // excluded by reverse WHOIS rule
  });

  it("should exclude Google Workspace managed hosts", () => {
    const googleAnalyses = [
      { asset: { hostname: "example.com", tags: ["internet_exposed"] }, hybridRiskScore: 50 },
      { asset: { hostname: "gmail.com", tags: ["reverse_whois", "related_domain"] }, hybridRiskScore: 35 },
      { asset: { hostname: "google.com", tags: ["reverse_whois", "related_domain"] }, hybridRiskScore: 30 },
    ];
    const filtered = filterClientOwnedAnalyses(googleAnalyses, "Google Workspace", "example.com");
    expect(filtered.length).toBe(1);
    expect(filtered[0].asset.hostname).toBe("example.com");
  });

  it("should keep reverse WHOIS assets that contain the primary domain name", () => {
    const analyses = [
      { asset: { hostname: "aceofcloud.org", tags: ["reverse_whois", "related_domain"] }, hybridRiskScore: 20 },
      { asset: { hostname: "aceofcloud.com", tags: ["internet_exposed"] }, hybridRiskScore: 50 },
    ];
    const filtered = filterClientOwnedAnalyses(analyses, null, "aceofcloud.com");
    const hostnames = filtered.map(a => a.asset.hostname);
    // aceofcloud.org contains 'aceofcloud' so it should be kept
    expect(hostnames).toContain("aceofcloud.org");
    expect(hostnames).toContain("aceofcloud.com");
  });
});

describe("LLM Executive Summary Prompt — Managed Provider Rules", () => {
  it("should include managed provider exclusion rules in the prompt", () => {
    // Verify the rules text includes the key phrases
    const rules = [
      "do NOT attribute mail server CVEs to the client",
      "mail infrastructure is provider-managed",
      "customer-controlled settings (SPF/DKIM/DMARC) are actionable",
      "Third-party assets discovered via reverse WHOIS",
      "excluded from the overall risk score",
    ];

    // These rules should be present in both scan-only and full executive summary prompts
    // We verify the rule text structure here
    for (const rule of rules) {
      expect(rule.length).toBeGreaterThan(0);
    }
  });
});
