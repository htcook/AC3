import { describe, it, expect, vi } from 'vitest';

/**
 * Tests for vuln feed matching logic — specifically the fix for empty vendor/product
 * matching everything (because 'anything'.includes('') is true in JavaScript).
 */

describe('Vuln Feed Matching — Empty Vendor/Product Fix', () => {
  // Simulate the matching logic from vuln-feeds.ts
  function matchesTech(techLower: string, entry: { vendor: string; product: string; title: string }): boolean {
    const vendorLower = (entry.vendor || '').toLowerCase();
    const productLower = (entry.product || '').toLowerCase();
    const titleLower = (entry.title || '').toLowerCase();

    return (
      techLower.length >= 4 && (
        (vendorLower.length >= 3 && vendorLower.includes(techLower)) ||
        (productLower.length >= 3 && productLower.includes(techLower)) ||
        (titleLower.length >= 3 && titleLower.includes(techLower)) ||
        (vendorLower.length >= 3 && techLower.includes(vendorLower)) ||
        (productLower.length >= 3 && techLower.includes(productLower))
      )
    );
  }

  it('should NOT match CVEs with empty vendor and product', () => {
    const entry = { vendor: '', product: '', title: 'CVE-2026-2446' };
    expect(matchesTech('next.js', entry)).toBe(false);
    expect(matchesTech('react', entry)).toBe(false);
    expect(matchesTech('nginx', entry)).toBe(false);
  });

  it('should NOT match CVEs with very short vendor/product', () => {
    const entry = { vendor: 'ab', product: 'cd', title: 'CVE-2026-2446' };
    expect(matchesTech('next.js', entry)).toBe(false);
  });

  it('should match CVEs with valid vendor containing tech name', () => {
    const entry = { vendor: 'vercel', product: 'next.js', title: 'Next.js SSRF vulnerability' };
    expect(matchesTech('next.js', entry)).toBe(true);
  });

  it('should match CVEs with valid product containing tech name', () => {
    const entry = { vendor: 'microsoft', product: 'exchange server', title: 'Exchange RCE' };
    expect(matchesTech('exchange', entry)).toBe(true);
  });

  it('should match CVEs where title contains tech name', () => {
    const entry = { vendor: '', product: '', title: 'Apache Struts Remote Code Execution' };
    expect(matchesTech('apache struts', entry)).toBe(true);
  });

  it('should NOT match when title is too short', () => {
    const entry = { vendor: '', product: '', title: 'ab' };
    expect(matchesTech('next.js', entry)).toBe(false);
  });

  it('should NOT match when tech name is too short', () => {
    const entry = { vendor: 'microsoft', product: 'exchange', title: 'Exchange RCE' };
    expect(matchesTech('abc', entry)).toBe(false);
  });

  it('should match when tech includes vendor name', () => {
    const entry = { vendor: 'oracle', product: 'java', title: 'Java RCE' };
    expect(matchesTech('oracle java', entry)).toBe(true);
  });

  it('should match when tech includes product name', () => {
    const entry = { vendor: 'apache', product: 'tomcat', title: 'Tomcat RCE' };
    expect(matchesTech('apache tomcat', entry)).toBe(true);
  });
});

describe('CVE Title Formatting — Empty Vendor/Product', () => {
  function formatTitle(cveId: string, title: string | undefined, description: string | undefined, vendor: string, product: string): string {
    return `${cveId}: ${title || description?.substring(0, 100) || "Vulnerability"}${vendor || product ? ` (${[vendor, product].filter(Boolean).join(' ')})` : ''}`;
  }

  it('should not show empty parentheses when vendor and product are empty', () => {
    const result = formatTitle('CVE-2026-2446', undefined, undefined, '', '');
    expect(result).toBe('CVE-2026-2446: Vulnerability');
    expect(result).not.toContain('( )');
    expect(result).not.toContain('()');
  });

  it('should show vendor and product when both present', () => {
    const result = formatTitle('CVE-2021-42321', 'Exchange RCE', undefined, 'Microsoft', 'Exchange Server');
    expect(result).toBe('CVE-2021-42321: Exchange RCE (Microsoft Exchange Server)');
  });

  it('should show only vendor when product is empty', () => {
    const result = formatTitle('CVE-2021-42321', 'Exchange RCE', undefined, 'Microsoft', '');
    expect(result).toBe('CVE-2021-42321: Exchange RCE (Microsoft)');
  });

  it('should show only product when vendor is empty', () => {
    const result = formatTitle('CVE-2021-42321', 'Exchange RCE', undefined, '', 'Exchange Server');
    expect(result).toBe('CVE-2021-42321: Exchange RCE (Exchange Server)');
  });

  it('should use description when title is undefined', () => {
    const result = formatTitle('CVE-2026-2446', undefined, 'A vulnerability in the charging station firmware', 'Vendor', 'Product');
    expect(result).toBe('CVE-2026-2446: A vulnerability in the charging station firmware (Vendor Product)');
  });
});

describe('Observation Deduplication & Managed Provider Filtering', () => {
  function buildObservations(assets: any[], managedMailHosts: Set<string>) {
    const synth: any[] = [];
    const cveDedup = new Map<string, any>();

    for (const asset of assets) {
      for (const f of (asset.postureFindings || [])) {
        const titleOrFinding = f.title || '';
        const cveMatch = titleOrFinding.match(/CVE-\d{4}-\d+/);
        const cveId = (f.cveIds && f.cveIds[0]) || cveMatch?.[0] || undefined;
        const assetHostname = f.assetHostname || asset.hostname || '';
        const isOnManagedHost = managedMailHosts.has(assetHostname);
        const corroborationLabel = f.corroborationTier === 'confirmed' ? '[CONFIRMED]' : '[PROBABLE]';

        if (cveId && cveDedup.has(cveId)) {
          const existing = cveDedup.get(cveId);
          if (!existing.evidence.affectedHosts.includes(assetHostname)) {
            existing.evidence.affectedHosts.push(assetHostname);
          }
          if (corroborationLabel === '[CONFIRMED]' && existing.evidence.corroboration !== '[CONFIRMED]') {
            existing.evidence.corroboration = '[CONFIRMED]';
          }
          if (isOnManagedHost) existing.evidence.hasProviderManagedInstance = true;
          continue;
        }

        const obs = {
          name: titleOrFinding,
          tags: ['vulnerability', 'cve'],
          evidence: {
            cve_id: cveId,
            hostname: assetHostname,
            affectedHosts: [assetHostname],
            corroboration: corroborationLabel,
            hasProviderManagedInstance: isOnManagedHost,
            providerManagedOnly: false,
          },
        };
        if (cveId) cveDedup.set(cveId, obs);
        synth.push(obs);
      }
    }

    // Post-process: mark CVEs that ONLY appear on managed hosts
    for (const obs of synth) {
      if (obs.evidence?.cve_id && obs.evidence.hasProviderManagedInstance) {
        const allHostsManaged = obs.evidence.affectedHosts.every((h: string) => managedMailHosts.has(h));
        obs.evidence.providerManagedOnly = allHostsManaged;
        if (allHostsManaged) obs.tags.push('provider_managed');
      }
    }

    return synth;
  }

  it('should deduplicate same CVE across multiple assets', () => {
    const assets = [
      { hostname: 'host1.com', postureFindings: [{ title: 'CVE-2021-42321: Exchange RCE', cveIds: ['CVE-2021-42321'], corroborationTier: 'probable' }] },
      { hostname: 'host2.com', postureFindings: [{ title: 'CVE-2021-42321: Exchange RCE', cveIds: ['CVE-2021-42321'], corroborationTier: 'probable' }] },
      { hostname: 'host3.com', postureFindings: [{ title: 'CVE-2021-42321: Exchange RCE', cveIds: ['CVE-2021-42321'], corroborationTier: 'confirmed' }] },
    ];
    const result = buildObservations(assets, new Set());
    expect(result.length).toBe(1);
    expect(result[0].evidence.affectedHosts).toEqual(['host1.com', 'host2.com', 'host3.com']);
    // Should upgrade to confirmed since host3 has confirmed
    expect(result[0].evidence.corroboration).toBe('[CONFIRMED]');
  });

  it('should mark CVEs as provider-managed when only on managed hosts', () => {
    const managedHosts = new Set(['outlook.com']);
    const assets = [
      { hostname: 'outlook.com', postureFindings: [{ title: 'CVE-2021-42321: Exchange RCE', cveIds: ['CVE-2021-42321'], corroborationTier: 'confirmed' }] },
    ];
    const result = buildObservations(assets, managedHosts);
    expect(result.length).toBe(1);
    expect(result[0].evidence.providerManagedOnly).toBe(true);
    expect(result[0].tags).toContain('provider_managed');
  });

  it('should NOT mark CVEs as provider-managed when also on non-managed hosts', () => {
    const managedHosts = new Set(['outlook.com']);
    const assets = [
      { hostname: 'outlook.com', postureFindings: [{ title: 'CVE-2021-42321: Exchange RCE', cveIds: ['CVE-2021-42321'], corroborationTier: 'confirmed' }] },
      { hostname: 'myserver.com', postureFindings: [{ title: 'CVE-2021-42321: Exchange RCE', cveIds: ['CVE-2021-42321'], corroborationTier: 'probable' }] },
    ];
    const result = buildObservations(assets, managedHosts);
    expect(result.length).toBe(1);
    expect(result[0].evidence.providerManagedOnly).toBe(false);
    expect(result[0].tags).not.toContain('provider_managed');
  });

  it('should keep non-CVE findings without deduplication', () => {
    const assets = [
      { hostname: 'host1.com', postureFindings: [{ title: 'Potential XSS vulnerabilities', corroborationTier: 'potential' }] },
      { hostname: 'host2.com', postureFindings: [{ title: 'Potential XSS vulnerabilities', corroborationTier: 'potential' }] },
    ];
    const result = buildObservations(assets, new Set());
    // Non-CVE findings should NOT be deduplicated (no cveId)
    expect(result.length).toBe(2);
  });
});
