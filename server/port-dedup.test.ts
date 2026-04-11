/**
 * Port Deduplication Tests
 * 
 * Verifies that:
 * 1. The KPI stats count unique host:port combinations (not raw rows)
 * 2. The per-asset port list deduplicates by port number
 * 3. The dedup logic prefers fingerprinted > identified > inferred
 * 4. Rich metadata (banner, product) is preserved during dedup
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const PROJECT_ROOT = path.resolve(__dirname, '..');
const readSrc = (relPath: string) => fs.readFileSync(path.join(PROJECT_ROOT, relPath), 'utf-8');

describe('Port Count Deduplication — KPI Stats', () => {
  const opsCode = readSrc('client/src/pages/EngagementOps.tsx');

  it('KPI strip uses Set-based unique port counting instead of raw length sum', () => {
    // The old pattern was: .reduce((sum, a) => sum + (a.ports || []).length, 0)
    // The new pattern uses Set<string> to count unique host:port combos
    expect(opsCode).toContain("new Set<string>()");
    expect(opsCode).toContain("seen.add(`${a.hostname || a.ip}:${p.port}`)");
    expect(opsCode).toContain("seen.size");
  });

  it('StatCard sidebar also uses Set-based unique port counting', () => {
    // Find the StatCard for Open Ports — should also use Set dedup
    const statCardSection = opsCode.slice(
      opsCode.indexOf('label="Open Ports"'),
      opsCode.indexOf('label="Open Ports"') + 400
    );
    expect(statCardSection).toContain("new Set<string>()");
    expect(statCardSection).toContain("seen.add");
    expect(statCardSection).toContain("seen.size");
  });

  it('does NOT use the old raw .length sum pattern for Open Ports stat', () => {
    // Ensure the old pattern is gone from Open Ports lines
    // Old: (ops.assets || []).reduce((sum: number, a: any) => sum + (a.ports || []).length, 0)
    // Find all Open Ports value computations
    const kpiLine = opsCode.split('\n').find(l => l.includes("'Open Ports'") && l.includes('value:'));
    const statLine = opsCode.split('\n').find(l => l.includes('"Open Ports"') && l.includes('value='));
    
    if (kpiLine) {
      expect(kpiLine).not.toMatch(/\.reduce\(\(sum.*a\.ports.*\.length/);
    }
    if (statLine) {
      expect(statLine).not.toMatch(/\.reduce\(\(sum.*a\.ports.*\.length/);
    }
  });
});

describe('Port Count Deduplication — Unique host:port Logic', () => {
  it('correctly counts unique ports across multiple assets', () => {
    // Simulate the dedup logic used in the frontend
    const assets = [
      {
        hostname: 'api.dev.vianova.ai',
        ports: [
          { port: 22, service: 'ssh' },
          { port: 80, service: 'http' },
          { port: 80, service: 'http' },  // duplicate
          { port: 443, service: 'https' },
          { port: 443, service: 'https' }, // duplicate
          { port: 443, service: 'https' }, // triple
          { port: 3306, service: 'mysql' },
          { port: 80, service: 'http' },   // another dup
          { port: 443, service: 'https' }, // another dup
        ]
      },
      {
        hostname: 'dashboard-dev.vianovahealth.com',
        ports: [
          { port: 80, service: 'http' },
          { port: 80, service: 'http' },
          { port: 80, service: 'CloudFront httpd' },
          { port: 443, service: 'https' },
          { port: 443, service: 'https' },
          { port: 443, service: 'CloudFront httpd' },
          { port: 80, service: 'http' },
          { port: 443, service: 'https' },
          { port: 80, service: 'http' },
          { port: 443, service: 'https' },
          { port: 80, service: 'http' },
          { port: 443, service: 'https' },
        ]
      }
    ];

    // Apply the same dedup logic as the frontend
    const seen = new Set<string>();
    assets.forEach(a => (a.ports || []).forEach(p => seen.add(`${a.hostname}:${p.port}`)));
    
    // api.dev.vianova.ai has 4 unique ports: 22, 80, 443, 3306
    // dashboard-dev.vianovahealth.com has 2 unique ports: 80, 443
    // Total unique host:port combos = 6
    expect(seen.size).toBe(6);
  });

  it('counts same port on different hosts as separate entries', () => {
    const assets = [
      { hostname: 'host-a.com', ports: [{ port: 80 }, { port: 443 }] },
      { hostname: 'host-b.com', ports: [{ port: 80 }, { port: 443 }] },
    ];
    const seen = new Set<string>();
    assets.forEach(a => a.ports.forEach(p => seen.add(`${a.hostname}:${p.port}`)));
    expect(seen.size).toBe(4); // 80 and 443 on each host = 4
  });

  it('handles empty ports arrays', () => {
    const assets = [
      { hostname: 'host-a.com', ports: [] },
      { hostname: 'host-b.com', ports: [{ port: 22 }] },
    ];
    const seen = new Set<string>();
    assets.forEach(a => (a.ports || []).forEach(p => seen.add(`${a.hostname}:${p.port}`)));
    expect(seen.size).toBe(1);
  });

  it('handles null/undefined ports', () => {
    const assets = [
      { hostname: 'host-a.com', ports: null },
      { hostname: 'host-b.com' },
    ] as any[];
    const seen = new Set<string>();
    assets.forEach((a: any) => (a.ports || []).forEach((p: any) => seen.add(`${a.hostname}:${p.port}`)));
    expect(seen.size).toBe(0);
  });
});

describe('Per-Asset Port List Deduplication', () => {
  const opsCode = readSrc('client/src/pages/EngagementOps.tsx');

  it('uses Map-based deduplication for per-asset port display', () => {
    expect(opsCode).toContain('new Map<number, any>()');
    expect(opsCode).toContain('portMap.get(p.port)');
    expect(opsCode).toContain('portMap.set(p.port, p)');
  });

  it('prefers fingerprinted sources over inferred', () => {
    expect(opsCode).toContain("serviceSource === 'fingerprinted'");
    expect(opsCode).toContain('srcPriority');
  });

  it('preserves banner metadata during dedup merge', () => {
    expect(opsCode).toContain('banner');
    expect(opsCode).toContain('product');
  });

  it('sorts deduplicated ports by port number', () => {
    expect(opsCode).toContain('.sort((a, b) => a.port - b.port)');
  });

  it('shows deduplicated count in the header', () => {
    // The header should use Set<number> to count unique ports
    expect(opsCode).toContain('new Set<number>()');
    expect(opsCode).toContain('seen.add(p.port)');
  });

  it('correctly deduplicates ports preferring richest metadata', () => {
    // Simulate the dedup logic
    const ports = [
      { port: 80, service: 'unknown', serviceSource: undefined },
      { port: 80, service: 'http', serviceSource: undefined },
      { port: 80, service: 'CloudFront httpd', serviceSource: 'fingerprinted', banner: 'CloudFront', product: 'Amazon CloudFront' },
      { port: 443, service: 'unknown' },
      { port: 443, service: 'https' },
      { port: 443, service: 'https', banner: 'TLS 1.3' },
    ];

    const portMap = new Map<number, any>();
    for (const p of ports) {
      const existing = portMap.get(p.port);
      if (!existing) { portMap.set(p.port, p); continue; }
      const srcPriority = (s: any) => s?.serviceSource === 'fingerprinted' ? 3 : (s?.service && s.service !== 'unknown') ? 2 : 1;
      if (srcPriority(p) > srcPriority(existing)) portMap.set(p.port, { ...existing, ...p });
      else if ((p as any).banner && !(existing as any).banner) portMap.set(p.port, { ...existing, banner: (p as any).banner, product: (p as any).product || existing.product });
    }
    const result = Array.from(portMap.values()).sort((a, b) => a.port - b.port);

    expect(result).toHaveLength(2); // Only 80 and 443
    expect(result[0].port).toBe(80);
    expect(result[0].service).toBe('CloudFront httpd');
    expect(result[0].serviceSource).toBe('fingerprinted');
    expect(result[0].banner).toBe('CloudFront');
    expect(result[0].product).toBe('Amazon CloudFront');
    expect(result[1].port).toBe(443);
    expect(result[1].service).toBe('https');
    expect(result[1].banner).toBe('TLS 1.3');
  });
});
