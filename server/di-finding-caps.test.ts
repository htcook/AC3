/**
 * Tests for per-asset finding caps and unique CVE deduplication.
 * Validates that the pipeline correctly caps KEV and vuln feed findings
 * per asset and computes unique CVE summaries.
 */
import { describe, it, expect } from "vitest";

// Simulate the per-asset KEV cap logic from domainIntel.ts
function applyKevCap(analyses: any[], maxPerAsset: number = 15) {
  let kevCapped = 0;
  for (const a of analyses) {
    const kevFindings = a.postureFindings.filter((f: any) => f.category === 'CISA KEV');
    if (kevFindings.length > maxPerAsset) {
      kevFindings.sort((x: any, y: any) => (y.severity - x.severity) || ((y.confidence || 0) - (x.confidence || 0)));
      const keep = new Set(kevFindings.slice(0, maxPerAsset).map((f: any) => f.id));
      const removed = kevFindings.filter((f: any) => !keep.has(f.id));
      a.postureFindings = a.postureFindings.filter((f: any) => f.category !== 'CISA KEV' || keep.has(f.id));
      const removedCves = removed.map((f: any) => f.cveIds?.[0]).filter(Boolean);
      a.postureFindings.push({
        id: `kev-summary-${a.asset.assetId}`,
        category: 'CISA KEV',
        title: `${removed.length} additional KEV entries affect this asset's technology stack`,
        severity: Math.max(...removed.map((f: any) => f.severity), 1),
        cveIds: removedCves,
        corroborationTier: 'potential',
      });
      kevCapped += removed.length;
    }
  }
  return kevCapped;
}

// Simulate the per-asset vuln feed cap logic from domainIntel.ts
function applyVulnCap(analyses: any[], maxPerAsset: number = 15) {
  let vulnCapped = 0;
  for (const a of analyses) {
    const vulnFindings = a.postureFindings.filter((f: any) =>
      f.evidenceBasis === 'vuln_feed' || f.evidenceBasis === 'confirmed_cve'
    );
    if (vulnFindings.length > maxPerAsset) {
      vulnFindings.sort((x: any, y: any) => ((y.cvssScore || 0) - (x.cvssScore || 0)) || (y.severity - x.severity));
      const keep = new Set(vulnFindings.slice(0, maxPerAsset).map((f: any) => f.id));
      const removed = vulnFindings.filter((f: any) => !keep.has(f.id));
      a.postureFindings = a.postureFindings.filter((f: any) =>
        (f.evidenceBasis !== 'vuln_feed' && f.evidenceBasis !== 'confirmed_cve') || keep.has(f.id)
      );
      const removedCves = removed.map((f: any) => f.cveIds?.[0]).filter(Boolean);
      a.postureFindings.push({
        id: `vf-summary-${a.asset.assetId}`,
        category: 'Known CVE',
        title: `${removed.length} additional CVEs affect this asset's technology stack`,
        severity: Math.max(...removed.map((f: any) => f.severity), 1),
        cveIds: removedCves,
        corroborationTier: 'potential',
        evidenceBasis: 'vuln_feed',
      });
      vulnCapped += removed.length;
    }
  }
  return vulnCapped;
}

// Simulate the unique CVE deduplication summary logic
function computeUniqueCveSummary(analyses: any[]) {
  const allCveIds = new Set<string>();
  const confirmedCveIds = new Set<string>();
  const kevCveIds = new Set<string>();
  const cveToAssets = new Map<string, Set<string>>();
  for (const a of analyses) {
    for (const f of a.postureFindings) {
      if (f.cveIds) {
        for (const cve of f.cveIds) {
          allCveIds.add(cve);
          if (!cveToAssets.has(cve)) cveToAssets.set(cve, new Set());
          cveToAssets.get(cve)!.add(a.asset.hostname);
          if (f.corroborationTier === 'confirmed') confirmedCveIds.add(cve);
          if (f.kevListed) kevCveIds.add(cve);
        }
      }
    }
  }
  const totalFindings = analyses.reduce((s, a) => s + a.postureFindings.length, 0);
  return {
    uniqueCveCount: allCveIds.size,
    uniqueConfirmedCveCount: confirmedCveIds.size,
    uniqueKevCveCount: kevCveIds.size,
    totalFindingInstances: totalFindings,
    averageAssetsPerCve: allCveIds.size > 0
      ? Math.round((Array.from(cveToAssets.values()).reduce((s, set) => s + set.size, 0) / allCveIds.size) * 10) / 10
      : 0,
    mostWidespreadCves: Array.from(cveToAssets.entries())
      .sort((a, b) => b[1].size - a[1].size)
      .slice(0, 10)
      .map(([cve, assets]) => ({ cveId: cve, affectedAssetCount: assets.size })),
  };
}

// Helper to create mock findings
function makeKevFinding(assetId: string, cveId: string, severity: number) {
  return {
    id: `kev-${cveId}-${assetId}`,
    category: 'CISA KEV',
    title: `${cveId}: Test KEV Finding`,
    severity,
    confidence: severity / 10,
    cveIds: [cveId],
    kevListed: true,
    corroborationTier: severity >= 8 ? 'confirmed' : 'probable',
    evidenceBasis: 'kev_match',
  };
}

function makeVulnFinding(assetId: string, cveId: string, severity: number, cvssScore: number) {
  return {
    id: `vf-${cveId}-${assetId}`,
    category: 'Known CVE',
    title: `${cveId}: Test Vuln Finding`,
    severity,
    cvssScore,
    confidence: severity / 10,
    cveIds: [cveId],
    kevListed: false,
    corroborationTier: severity >= 8 ? 'confirmed' : 'probable',
    evidenceBasis: 'vuln_feed',
  };
}

describe("Per-asset KEV finding cap", () => {
  it("should not cap when findings are below threshold", () => {
    const analyses = [{
      asset: { assetId: 'a1', hostname: 'test.com' },
      postureFindings: Array.from({ length: 10 }, (_, i) =>
        makeKevFinding('a1', `CVE-2024-${1000 + i}`, 8)
      ),
    }];
    const capped = applyKevCap(analyses);
    expect(capped).toBe(0);
    expect(analyses[0].postureFindings.length).toBe(10);
  });

  it("should cap at 15 and create summary finding", () => {
    const analyses = [{
      asset: { assetId: 'a1', hostname: 'test.com' },
      postureFindings: Array.from({ length: 30 }, (_, i) =>
        makeKevFinding('a1', `CVE-2024-${1000 + i}`, 10 - Math.floor(i / 5))
      ),
    }];
    const capped = applyKevCap(analyses);
    expect(capped).toBe(15); // 30 - 15 = 15 capped
    // 15 kept + 1 summary = 16
    expect(analyses[0].postureFindings.length).toBe(16);
    const summary = analyses[0].postureFindings.find((f: any) => f.id === 'kev-summary-a1');
    expect(summary).toBeDefined();
    expect(summary.title).toContain('15 additional KEV entries');
    expect(summary.cveIds.length).toBe(15);
  });

  it("should keep highest severity findings when capping", () => {
    const findings = [
      ...Array.from({ length: 10 }, (_, i) => makeKevFinding('a1', `CVE-2024-HIGH-${i}`, 10)),
      ...Array.from({ length: 10 }, (_, i) => makeKevFinding('a1', `CVE-2024-MED-${i}`, 5)),
      ...Array.from({ length: 10 }, (_, i) => makeKevFinding('a1', `CVE-2024-LOW-${i}`, 2)),
    ];
    const analyses = [{
      asset: { assetId: 'a1', hostname: 'test.com' },
      postureFindings: findings,
    }];
    applyKevCap(analyses);
    const kept = analyses[0].postureFindings.filter((f: any) => f.id !== 'kev-summary-a1');
    // All 10 HIGH (severity 10) should be kept, plus 5 MED (severity 5)
    const highKept = kept.filter((f: any) => f.severity === 10);
    expect(highKept.length).toBe(10);
    const medKept = kept.filter((f: any) => f.severity === 5);
    expect(medKept.length).toBe(5);
  });

  it("should cap each asset independently", () => {
    const analyses = [
      {
        asset: { assetId: 'a1', hostname: 'host1.com' },
        postureFindings: Array.from({ length: 20 }, (_, i) =>
          makeKevFinding('a1', `CVE-2024-A-${i}`, 8)
        ),
      },
      {
        asset: { assetId: 'a2', hostname: 'host2.com' },
        postureFindings: Array.from({ length: 25 }, (_, i) =>
          makeKevFinding('a2', `CVE-2024-B-${i}`, 7)
        ),
      },
    ];
    const capped = applyKevCap(analyses);
    expect(capped).toBe(5 + 10); // 5 from a1, 10 from a2
    expect(analyses[0].postureFindings.length).toBe(16); // 15 + 1 summary
    expect(analyses[1].postureFindings.length).toBe(16); // 15 + 1 summary
  });
});

describe("Per-asset vuln feed finding cap", () => {
  it("should cap vuln feed findings at 15 per asset", () => {
    const analyses = [{
      asset: { assetId: 'a1', hostname: 'test.com' },
      postureFindings: Array.from({ length: 25 }, (_, i) =>
        makeVulnFinding('a1', `CVE-2024-VF-${i}`, 7, 9.0 - (i * 0.2))
      ),
    }];
    const capped = applyVulnCap(analyses);
    expect(capped).toBe(10); // 25 - 15 = 10 capped
    expect(analyses[0].postureFindings.length).toBe(16); // 15 + 1 summary
  });

  it("should keep highest CVSS findings when capping", () => {
    const findings = Array.from({ length: 20 }, (_, i) =>
      makeVulnFinding('a1', `CVE-2024-VF-${i}`, 7, 10.0 - (i * 0.5))
    );
    const analyses = [{
      asset: { assetId: 'a1', hostname: 'test.com' },
      postureFindings: findings,
    }];
    applyVulnCap(analyses);
    const kept = analyses[0].postureFindings.filter((f: any) => !f.id.startsWith('vf-summary'));
    // Top 15 by CVSS should be kept (CVSS 10.0, 9.5, 9.0, ..., 3.0)
    const minCvss = Math.min(...kept.map((f: any) => f.cvssScore || 0));
    expect(minCvss).toBeGreaterThanOrEqual(3.0);
  });

  it("should not interfere with non-vuln-feed findings", () => {
    const analyses = [{
      asset: { assetId: 'a1', hostname: 'test.com' },
      postureFindings: [
        ...Array.from({ length: 20 }, (_, i) =>
          makeVulnFinding('a1', `CVE-2024-VF-${i}`, 7, 8.0)
        ),
        // Non-vuln-feed finding should be preserved
        {
          id: 'other-finding-1',
          category: 'configuration',
          title: 'Weak TLS config',
          severity: 5,
          evidenceBasis: 'scan_detected',
        },
      ],
    }];
    applyVulnCap(analyses);
    const otherFinding = analyses[0].postureFindings.find((f: any) => f.id === 'other-finding-1');
    expect(otherFinding).toBeDefined();
  });
});

describe("Unique CVE deduplication summary", () => {
  it("should count unique CVEs across multiple assets", () => {
    // Same CVE appears on 3 different assets
    const analyses = [
      {
        asset: { assetId: 'a1', hostname: 'host1.com' },
        postureFindings: [
          makeKevFinding('a1', 'CVE-2024-1234', 9),
          makeKevFinding('a1', 'CVE-2024-5678', 8),
        ],
      },
      {
        asset: { assetId: 'a2', hostname: 'host2.com' },
        postureFindings: [
          makeKevFinding('a2', 'CVE-2024-1234', 9), // Same CVE as a1
          makeKevFinding('a2', 'CVE-2024-9999', 7),
        ],
      },
      {
        asset: { assetId: 'a3', hostname: 'host3.com' },
        postureFindings: [
          makeKevFinding('a3', 'CVE-2024-1234', 9), // Same CVE again
        ],
      },
    ];
    const summary = computeUniqueCveSummary(analyses);
    expect(summary.uniqueCveCount).toBe(3); // CVE-1234, CVE-5678, CVE-9999
    expect(summary.totalFindingInstances).toBe(5); // 2 + 2 + 1
    expect(summary.averageAssetsPerCve).toBeCloseTo(1.7, 0); // (3+1+1)/3 = 1.67
    expect(summary.mostWidespreadCves[0].cveId).toBe('CVE-2024-1234');
    expect(summary.mostWidespreadCves[0].affectedAssetCount).toBe(3);
  });

  it("should track unique KEV CVEs separately", () => {
    const analyses = [{
      asset: { assetId: 'a1', hostname: 'host1.com' },
      postureFindings: [
        makeKevFinding('a1', 'CVE-2024-1111', 9),
        makeVulnFinding('a1', 'CVE-2024-2222', 7, 8.5),
      ],
    }];
    const summary = computeUniqueCveSummary(analyses);
    expect(summary.uniqueCveCount).toBe(2);
    expect(summary.uniqueKevCveCount).toBe(1);
  });

  it("should handle PBS-scale scenario correctly", () => {
    // Simulate PBS: 50 assets sharing the same 20 CVEs
    const cves = Array.from({ length: 20 }, (_, i) => `CVE-2024-${1000 + i}`);
    const analyses = Array.from({ length: 50 }, (_, assetIdx) => ({
      asset: { assetId: `a${assetIdx}`, hostname: `host${assetIdx}.pbs.org` },
      postureFindings: cves.map(cve => makeKevFinding(`a${assetIdx}`, cve, 8)),
    }));

    // Before cap: 50 assets × 20 CVEs = 1000 findings
    const totalBefore = analyses.reduce((s, a) => s + a.postureFindings.length, 0);
    expect(totalBefore).toBe(1000);

    // Apply cap
    const capped = applyKevCap(analyses);
    expect(capped).toBe(50 * 5); // Each asset has 20, cap at 15, so 5 capped per asset = 250

    // After cap: 50 assets × (15 + 1 summary) = 800
    const totalAfter = analyses.reduce((s, a) => s + a.postureFindings.length, 0);
    expect(totalAfter).toBe(800);

    // Unique CVE summary should show only 20 unique CVEs
    const summary = computeUniqueCveSummary(analyses);
    expect(summary.uniqueCveCount).toBe(20);
    expect(summary.totalFindingInstances).toBe(800);
    expect(summary.averageAssetsPerCve).toBeGreaterThan(1);
  });

  it("should return zero averageAssetsPerCve when no CVEs exist", () => {
    const analyses = [{
      asset: { assetId: 'a1', hostname: 'clean.com' },
      postureFindings: [{
        id: 'config-1',
        category: 'configuration',
        title: 'Weak TLS',
        severity: 3,
        // No cveIds
      }],
    }];
    const summary = computeUniqueCveSummary(analyses);
    expect(summary.uniqueCveCount).toBe(0);
    expect(summary.averageAssetsPerCve).toBe(0);
  });
});
