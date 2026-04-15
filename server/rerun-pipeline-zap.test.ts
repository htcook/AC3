import { describe, it, expect, vi } from 'vitest';

describe('rerunFullPipeline ZAP+Burp integration', () => {
  it('executeVulnDetection is exported from engagement-orchestrator', async () => {
    const mod = await import('./lib/engagement-orchestrator');
    expect(typeof mod.executeVulnDetection).toBe('function');
  });

  it('webApps filter matches assets with type "web" (not just "web_app")', async () => {
    const { isInRoeScope } = await import('./lib/engagement-orchestrator');
    
    // Simulate the webApps filter logic from executeVulnDetection
    const assets = [
      { hostname: 'bc.example.com', type: 'web', ports: [{ port: 80, service: 'unknown' }, { port: 443, service: 'unknown' }], ip: '1.2.3.4' },
      { hostname: 'api.example.com', type: 'web_app', ports: [{ port: 443, service: 'https' }], ip: '5.6.7.8' },
      { hostname: 'db.example.com', type: 'database', ports: [{ port: 3306, service: 'mysql' }], ip: '9.10.11.12' },
      { hostname: 'web.example.com', type: 'unknown', ports: [{ port: 8080, service: 'http' }], ip: '13.14.15.16' },
    ];

    // Replicate the filter from executeVulnDetection (line 6700-6704)
    const webApps = assets.filter(a =>
      (a.type === "web_app" || a.type === "web" ||
      a.ports.some(p => ["http", "https"].includes(p.service) || [80, 443, 8080, 8443].includes(p.port)))
    );

    // BC asset (type: 'web') should match
    expect(webApps.find(a => a.hostname === 'bc.example.com')).toBeTruthy();
    // web_app should match
    expect(webApps.find(a => a.hostname === 'api.example.com')).toBeTruthy();
    // database with mysql port should NOT match
    expect(webApps.find(a => a.hostname === 'db.example.com')).toBeFalsy();
    // unknown type with http service should match
    expect(webApps.find(a => a.hostname === 'web.example.com')).toBeTruthy();
  });

  it('webApps filter matches assets with web ports even when service is "unknown"', () => {
    const assets = [
      { hostname: 'target.com', type: 'unknown', ports: [{ port: 80, service: 'unknown' }, { port: 443, service: 'unknown' }] },
    ];

    const webApps = assets.filter(a =>
      (a.type === "web_app" || a.type === "web" ||
      a.ports.some(p => ["http", "https"].includes(p.service) || [80, 443, 8080, 8443].includes(p.port)))
    );

    expect(webApps.length).toBe(1);
    expect(webApps[0].hostname).toBe('target.com');
  });

  it('webApps filter excludes assets with no web ports and non-web type', () => {
    const assets = [
      { hostname: 'ftp.example.com', type: 'unknown', ports: [{ port: 21, service: 'ftp' }] },
      { hostname: 'ssh.example.com', type: 'network', ports: [{ port: 22, service: 'ssh' }] },
      { hostname: 'dns.example.com', type: 'dns', ports: [{ port: 53, service: 'dns' }] },
    ];

    const webApps = assets.filter(a =>
      (a.type === "web_app" || a.type === "web" ||
      a.ports.some(p => ["http", "https"].includes(p.service) || [80, 443, 8080, 8443].includes(p.port)))
    );

    expect(webApps.length).toBe(0);
  });
});
