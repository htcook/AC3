import { describe, it, expect } from "vitest";

/**
 * Tests for Domain Scan Display Enhancement
 * Validates that scan results correctly display:
 * - All subdomains and assets
 * - Domain names and IP addresses
 * - Discovered technologies/apps
 * - Open ports and services
 */

// Simulate the inventory building logic from the frontend
function buildAssetInventory(
  assets: any[],
  discoveredSubdomains: any[],
  discoveredPorts: any[]
) {
  const commonPorts: Record<number, string> = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
    110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Alt',
  };

  const inventoryMap = new Map<string, any>();

  // 1. Add all DB assets
  for (const a of assets) {
    const hostname = (a.hostname || '').toLowerCase();
    const techArr = Array.isArray(a.technologies) ? a.technologies : [];
    const techVersions = a.technologyVersions || {};
    let ip = '';
    const dns = a.dnsRecords || {};
    if (dns.A && Array.isArray(dns.A) && dns.A.length > 0) {
      ip = typeof dns.A[0] === 'string' ? dns.A[0] : dns.A[0]?.address || '';
    }
    const assetPorts = discoveredPorts
      .filter(p => p.hostname?.toLowerCase() === hostname || (ip && p.ip === ip))
      .map(p => ({
        port: p.port,
        transport: p.transport || 'tcp',
        service: p.product || commonPorts[p.port] || '',
        version: p.version || '',
        vulns: p.vulns || [],
      }));

    inventoryMap.set(hostname, {
      hostname: a.hostname,
      ip,
      assetType: a.assetType || 'unknown',
      technologies: techArr,
      technologyVersions: techVersions,
      ports: assetPorts,
      riskScore: a.hybridRiskScore || 0,
      riskBand: a.riskBand || 'low',
      discoveryMethod: a.discoveryMethod || 'inferred',
    });
  }

  // 2. Add subdomains not already in assets
  for (const s of discoveredSubdomains) {
    const key = (s.name || '').toLowerCase();
    if (!key || inventoryMap.has(key)) continue;
    const subPorts = discoveredPorts
      .filter(p => p.hostname?.toLowerCase() === key || (s.ip && p.ip === s.ip))
      .map(p => ({
        port: p.port,
        transport: p.transport || 'tcp',
        service: p.product || commonPorts[p.port] || '',
        version: p.version || '',
        vulns: p.vulns || [],
      }));
    const techFromTags = (s.tags || []).filter((t: string) => t.startsWith('product:')).map((t: string) => t.replace('product:', ''));
    inventoryMap.set(key, {
      hostname: s.name,
      ip: s.ip || '',
      assetType: 'subdomain',
      technologies: techFromTags,
      technologyVersions: {},
      ports: subPorts,
      riskScore: 0,
      riskBand: 'low',
      discoveryMethod: 'passive_recon',
    });
  }

  return Array.from(inventoryMap.values());
}

// Simulate the enriched subdomain building logic
function buildEnrichedSubdomains(
  assets: any[],
  discoveredSubdomains: any[],
  discoveredPorts: any[]
) {
  const assetMap = new Map<string, any>();
  for (const a of assets) {
    assetMap.set((a.hostname || '').toLowerCase(), a);
  }

  const allSubdomainMap = new Map<string, any>();
  for (const s of discoveredSubdomains) {
    allSubdomainMap.set(s.name.toLowerCase(), { ...s });
  }
  for (const a of assets) {
    const key = (a.hostname || '').toLowerCase();
    if (key && !allSubdomainMap.has(key)) {
      allSubdomainMap.set(key, {
        name: a.hostname,
        ip: null,
        source: 'asset_discovery',
        tags: [],
      });
    }
  }

  return Array.from(allSubdomainMap.values()).map(s => {
    const key = (s.name || '').toLowerCase();
    const matchedAsset = assetMap.get(key);
    let ip = s.ip || '';
    if (!ip && matchedAsset) {
      const dns = matchedAsset.dnsRecords || {};
      if (dns.A && Array.isArray(dns.A) && dns.A.length > 0) {
        ip = typeof dns.A[0] === 'string' ? dns.A[0] : dns.A[0]?.address || '';
      }
    }
    if (!ip) {
      const portMatch = discoveredPorts.find(p => p.hostname?.toLowerCase() === key);
      if (portMatch) ip = portMatch.ip || '';
    }
    const technologies = matchedAsset ? (Array.isArray(matchedAsset.technologies) ? matchedAsset.technologies : []) : [];
    const tagTech = (s.tags || []).filter((t: string) => t.startsWith('product:')).map((t: string) => t.replace('product:', ''));
    const allTech = [...new Set([...technologies, ...tagTech])];
    const subPorts = discoveredPorts
      .filter(p => p.hostname?.toLowerCase() === key || (ip && p.ip === ip))
      .map(p => ({
        port: p.port,
        transport: p.transport || 'tcp',
        service: p.product || '',
        version: p.version || '',
        vulns: p.vulns || [],
      }));

    return {
      ...s,
      ip,
      technologies: allTech,
      ports: subPorts,
      riskScore: matchedAsset?.hybridRiskScore || 0,
      riskBand: matchedAsset?.riskBand || '',
      assetType: matchedAsset?.assetType || 'subdomain',
    };
  });
}

// Test fixtures
const mockAssets = [
  {
    hostname: 'sso.example.com',
    assetType: 'sso',
    technologies: ['Okta', 'React', 'Nginx'],
    technologyVersions: { 'Okta': '2023.1', 'Nginx': '1.24.0' },
    dnsRecords: { A: ['10.0.1.1'], MX: [] },
    hybridRiskScore: 78,
    riskBand: 'high',
    discoveryMethod: 'dns_verified',
  },
  {
    hostname: 'api.example.com',
    assetType: 'api',
    technologies: ['Express', 'Node.js'],
    technologyVersions: { 'Node.js': '18.17.0' },
    dnsRecords: { A: ['10.0.1.2'] },
    hybridRiskScore: 65,
    riskBand: 'medium',
    discoveryMethod: 'dns_verified',
  },
  {
    hostname: 'mail.example.com',
    assetType: 'mail_gateway',
    technologies: ['Exchange'],
    technologyVersions: { 'Exchange': '2019' },
    dnsRecords: { A: ['10.0.1.3'], MX: ['mail.example.com'] },
    hybridRiskScore: 82,
    riskBand: 'critical',
    discoveryMethod: 'dns_verified',
  },
];

const mockSubdomains = [
  { name: 'sso.example.com', ip: '10.0.1.1', source: 'crt.sh', tags: [] },
  { name: 'api.example.com', ip: '10.0.1.2', source: 'SecurityTrails', tags: [] },
  { name: 'dev.example.com', ip: '10.0.2.50', source: 'Censys', tags: ['product:Apache', 'port:8080'] },
  { name: 'staging.example.com', ip: null, source: 'crt.sh', tags: ['product:Nginx'] },
  { name: 'old.example.com', ip: null, source: 'Wayback', tags: [] },
];

const mockPorts = [
  { hostname: 'sso.example.com', ip: '10.0.1.1', port: 443, transport: 'tcp', product: 'Nginx', version: '1.24.0', vulns: [] },
  { hostname: 'sso.example.com', ip: '10.0.1.1', port: 80, transport: 'tcp', product: 'Nginx', version: '1.24.0', vulns: [] },
  { hostname: 'api.example.com', ip: '10.0.1.2', port: 443, transport: 'tcp', product: 'Node.js', version: '18.17.0', vulns: [] },
  { hostname: 'api.example.com', ip: '10.0.1.2', port: 8080, transport: 'tcp', product: 'Express', version: '', vulns: [] },
  { hostname: 'mail.example.com', ip: '10.0.1.3', port: 25, transport: 'tcp', product: 'Exchange', version: '2019', vulns: ['CVE-2023-21529'] },
  { hostname: 'mail.example.com', ip: '10.0.1.3', port: 443, transport: 'tcp', product: 'OWA', version: '', vulns: [] },
  { hostname: 'dev.example.com', ip: '10.0.2.50', port: 8080, transport: 'tcp', product: 'Apache', version: '2.4.57', vulns: [] },
  { hostname: 'dev.example.com', ip: '10.0.2.50', port: 22, transport: 'tcp', product: 'OpenSSH', version: '8.9', vulns: [] },
];

describe("Asset Inventory Builder", () => {
  it("should include all DB assets in the inventory", () => {
    const inventory = buildAssetInventory(mockAssets, mockSubdomains, mockPorts);
    const hostnames = inventory.map(i => i.hostname);
    expect(hostnames).toContain('sso.example.com');
    expect(hostnames).toContain('api.example.com');
    expect(hostnames).toContain('mail.example.com');
  });

  it("should include subdomains not in DB assets", () => {
    const inventory = buildAssetInventory(mockAssets, mockSubdomains, mockPorts);
    const hostnames = inventory.map(i => i.hostname);
    expect(hostnames).toContain('dev.example.com');
    expect(hostnames).toContain('staging.example.com');
    expect(hostnames).toContain('old.example.com');
  });

  it("should not duplicate assets that appear in both DB and subdomains", () => {
    const inventory = buildAssetInventory(mockAssets, mockSubdomains, mockPorts);
    const ssoEntries = inventory.filter(i => i.hostname === 'sso.example.com');
    expect(ssoEntries).toHaveLength(1);
  });

  it("should resolve IPs from DNS records for DB assets", () => {
    const inventory = buildAssetInventory(mockAssets, mockSubdomains, mockPorts);
    const sso = inventory.find(i => i.hostname === 'sso.example.com');
    expect(sso?.ip).toBe('10.0.1.1');
    const api = inventory.find(i => i.hostname === 'api.example.com');
    expect(api?.ip).toBe('10.0.1.2');
  });

  it("should resolve IPs from subdomain data for non-asset subdomains", () => {
    const inventory = buildAssetInventory(mockAssets, mockSubdomains, mockPorts);
    const dev = inventory.find(i => i.hostname === 'dev.example.com');
    expect(dev?.ip).toBe('10.0.2.50');
  });

  it("should include technologies from DB assets", () => {
    const inventory = buildAssetInventory(mockAssets, mockSubdomains, mockPorts);
    const sso = inventory.find(i => i.hostname === 'sso.example.com');
    expect(sso?.technologies).toContain('Okta');
    expect(sso?.technologies).toContain('React');
    expect(sso?.technologies).toContain('Nginx');
  });

  it("should extract technologies from subdomain tags for non-asset subdomains", () => {
    const inventory = buildAssetInventory(mockAssets, mockSubdomains, mockPorts);
    const dev = inventory.find(i => i.hostname === 'dev.example.com');
    expect(dev?.technologies).toContain('Apache');
  });

  it("should include technology versions for DB assets", () => {
    const inventory = buildAssetInventory(mockAssets, mockSubdomains, mockPorts);
    const sso = inventory.find(i => i.hostname === 'sso.example.com');
    expect(sso?.technologyVersions['Okta']).toBe('2023.1');
    expect(sso?.technologyVersions['Nginx']).toBe('1.24.0');
  });

  it("should match ports to assets by hostname", () => {
    const inventory = buildAssetInventory(mockAssets, mockSubdomains, mockPorts);
    const sso = inventory.find(i => i.hostname === 'sso.example.com');
    expect(sso?.ports).toHaveLength(2);
    expect(sso?.ports.map((p: any) => p.port).sort((a: number, b: number) => a - b)).toEqual([80, 443]);
  });

  it("should match ports to assets by IP when hostname doesn't match", () => {
    // Create a port entry that matches by IP only
    const portsWithIpOnly = [
      ...mockPorts,
      { hostname: 'unknown.example.com', ip: '10.0.1.1', port: 8443, transport: 'tcp', product: 'HTTPS-Alt', version: '', vulns: [] },
    ];
    const inventory = buildAssetInventory(mockAssets, mockSubdomains, portsWithIpOnly);
    const sso = inventory.find(i => i.hostname === 'sso.example.com');
    expect(sso?.ports.map((p: any) => p.port)).toContain(8443);
  });

  it("should include port service names", () => {
    const inventory = buildAssetInventory(mockAssets, mockSubdomains, mockPorts);
    const mail = inventory.find(i => i.hostname === 'mail.example.com');
    const smtpPort = mail?.ports.find((p: any) => p.port === 25);
    expect(smtpPort?.service).toBe('Exchange');
  });

  it("should include port vulnerabilities", () => {
    const inventory = buildAssetInventory(mockAssets, mockSubdomains, mockPorts);
    const mail = inventory.find(i => i.hostname === 'mail.example.com');
    const smtpPort = mail?.ports.find((p: any) => p.port === 25);
    expect(smtpPort?.vulns).toContain('CVE-2023-21529');
  });

  it("should preserve risk scores from DB assets", () => {
    const inventory = buildAssetInventory(mockAssets, mockSubdomains, mockPorts);
    const sso = inventory.find(i => i.hostname === 'sso.example.com');
    expect(sso?.riskScore).toBe(78);
    expect(sso?.riskBand).toBe('high');
  });

  it("should set risk score to 0 for subdomain-only entries", () => {
    const inventory = buildAssetInventory(mockAssets, mockSubdomains, mockPorts);
    const old = inventory.find(i => i.hostname === 'old.example.com');
    expect(old?.riskScore).toBe(0);
    expect(old?.riskBand).toBe('low');
  });

  it("should have correct total count (assets + unique subdomains)", () => {
    const inventory = buildAssetInventory(mockAssets, mockSubdomains, mockPorts);
    // 3 DB assets + 3 unique subdomains (dev, staging, old) = 6
    expect(inventory).toHaveLength(6);
  });
});

describe("Enriched Subdomains Builder", () => {
  it("should include all subdomains plus assets as subdomains", () => {
    const enriched = buildEnrichedSubdomains(mockAssets, mockSubdomains, mockPorts);
    // 5 subdomains + 1 asset not in subdomains (mail.example.com) = 6
    expect(enriched.length).toBe(6);
  });

  it("should resolve IPs from asset DNS records for matching subdomains", () => {
    const enriched = buildEnrichedSubdomains(mockAssets, mockSubdomains, mockPorts);
    const sso = enriched.find(s => s.name === 'sso.example.com');
    expect(sso?.ip).toBe('10.0.1.1');
  });

  it("should resolve IPs from port data when no other source available", () => {
    const subdomainsNoIp = mockSubdomains.map(s => 
      s.name === 'dev.example.com' ? { ...s, ip: null } : s
    );
    const enriched = buildEnrichedSubdomains(mockAssets, subdomainsNoIp, mockPorts);
    const dev = enriched.find(s => s.name === 'dev.example.com');
    expect(dev?.ip).toBe('10.0.2.50');
  });

  it("should enrich subdomains with technologies from matching assets", () => {
    const enriched = buildEnrichedSubdomains(mockAssets, mockSubdomains, mockPorts);
    const sso = enriched.find(s => s.name === 'sso.example.com');
    expect(sso?.technologies).toContain('Okta');
    expect(sso?.technologies).toContain('React');
  });

  it("should extract technologies from tags for non-asset subdomains", () => {
    const enriched = buildEnrichedSubdomains(mockAssets, mockSubdomains, mockPorts);
    const dev = enriched.find(s => s.name === 'dev.example.com');
    expect(dev?.technologies).toContain('Apache');
  });

  it("should enrich subdomains with port data", () => {
    const enriched = buildEnrichedSubdomains(mockAssets, mockSubdomains, mockPorts);
    const api = enriched.find(s => s.name === 'api.example.com');
    expect(api?.ports).toHaveLength(2);
    expect(api?.ports.map((p: any) => p.port).sort()).toEqual([443, 8080]);
  });

  it("should include risk scores from matching assets", () => {
    const enriched = buildEnrichedSubdomains(mockAssets, mockSubdomains, mockPorts);
    const sso = enriched.find(s => s.name === 'sso.example.com');
    expect(sso?.riskScore).toBe(78);
    expect(sso?.riskBand).toBe('high');
  });

  it("should set risk to 0 for subdomains without matching assets", () => {
    const enriched = buildEnrichedSubdomains(mockAssets, mockSubdomains, mockPorts);
    const old = enriched.find(s => s.name === 'old.example.com');
    expect(old?.riskScore).toBe(0);
  });

  it("should include asset type from matching assets", () => {
    const enriched = buildEnrichedSubdomains(mockAssets, mockSubdomains, mockPorts);
    const sso = enriched.find(s => s.name === 'sso.example.com');
    expect(sso?.assetType).toBe('sso');
    const dev = enriched.find(s => s.name === 'dev.example.com');
    expect(dev?.assetType).toBe('subdomain');
  });
});

describe("Edge Cases", () => {
  it("should handle empty inputs gracefully", () => {
    const inventory = buildAssetInventory([], [], []);
    expect(inventory).toHaveLength(0);
    const enriched = buildEnrichedSubdomains([], [], []);
    expect(enriched).toHaveLength(0);
  });

  it("should handle assets with no DNS records", () => {
    const assetsNoDns = [{ hostname: 'nodns.example.com', assetType: 'web', technologies: ['React'], dnsRecords: null }];
    const inventory = buildAssetInventory(assetsNoDns, [], []);
    expect(inventory[0].ip).toBe('');
    expect(inventory[0].technologies).toContain('React');
  });

  it("should handle DNS records with object format (address field)", () => {
    const assetsObjDns = [{
      hostname: 'obj.example.com',
      assetType: 'web',
      technologies: [],
      dnsRecords: { A: [{ address: '192.168.1.1', ttl: 300 }] },
    }];
    const inventory = buildAssetInventory(assetsObjDns, [], []);
    expect(inventory[0].ip).toBe('192.168.1.1');
  });

  it("should deduplicate technologies from tags and asset data", () => {
    const assetsWithNginx = [{
      hostname: 'dup.example.com',
      assetType: 'web',
      technologies: ['Nginx'],
      technologyVersions: {},
      dnsRecords: {},
    }];
    const subsWithNginxTag = [{ name: 'dup.example.com', ip: '1.2.3.4', source: 'crt.sh', tags: ['product:Nginx'] }];
    const enriched = buildEnrichedSubdomains(assetsWithNginx, subsWithNginxTag, []);
    const dup = enriched.find(s => s.name === 'dup.example.com');
    // Should deduplicate — only one 'Nginx'
    const nginxCount = dup?.technologies.filter((t: string) => t === 'Nginx').length;
    expect(nginxCount).toBe(1);
  });

  it("should handle case-insensitive hostname matching", () => {
    const assetsUpper = [{ hostname: 'SSO.Example.COM', assetType: 'sso', technologies: ['Okta'], dnsRecords: { A: ['10.0.1.1'] } }];
    const subsLower = [{ name: 'sso.example.com', ip: '10.0.1.1', source: 'crt.sh', tags: [] }];
    const inventory = buildAssetInventory(assetsUpper, subsLower, []);
    // Should not duplicate — case-insensitive match
    expect(inventory).toHaveLength(1);
  });
});
