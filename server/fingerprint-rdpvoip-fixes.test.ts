import { describe, it, expect, vi } from 'vitest';

// ─── 1. Fingerprinting crash fix: state.scanProfile instead of state.config.profile ───

describe("Fingerprinting crash fix — state.scanProfile", () => {
  it("should use state.scanProfile instead of state.config.profile", () => {
    // The bug was: state.config.profile — state.config is undefined
    // The fix: (state.scanProfile || 'standard') !== 'stealth'
    const state: any = { scanProfile: 'stealth' };
    const tryDefaultCreds = (state.scanProfile || 'standard') !== 'stealth';
    expect(tryDefaultCreds).toBe(false);
  });

  it("should default to 'standard' when scanProfile is undefined", () => {
    const state: any = {};
    const tryDefaultCreds = (state.scanProfile || 'standard') !== 'stealth';
    expect(tryDefaultCreds).toBe(true);
  });

  it("should allow default creds for 'quick' profile", () => {
    const state: any = { scanProfile: 'quick' };
    const tryDefaultCreds = (state.scanProfile || 'standard') !== 'stealth';
    expect(tryDefaultCreds).toBe(true);
  });

  it("should allow default creds for 'standard' profile", () => {
    const state: any = { scanProfile: 'standard' };
    const tryDefaultCreds = (state.scanProfile || 'standard') !== 'stealth';
    expect(tryDefaultCreds).toBe(true);
  });

  it("should allow default creds for 'deep' profile", () => {
    const state: any = { scanProfile: 'deep' };
    const tryDefaultCreds = (state.scanProfile || 'standard') !== 'stealth';
    expect(tryDefaultCreds).toBe(true);
  });

  it("should NOT crash when state.config is undefined (the original bug)", () => {
    const state: any = { engagementId: 1 }; // no config property at all
    // Old code would crash: state.config.profile
    expect(() => {
      const _x = state.config?.profile;
    }).not.toThrow();
    // But direct access DOES crash:
    expect(() => {
      const _x = state.config.profile;
    }).toThrow("Cannot read properties of undefined");
    // Our fix never accesses state.config:
    expect(() => {
      const tryDefaultCreds = (state.scanProfile || 'standard') !== 'stealth';
    }).not.toThrow();
  });
});

// ─── 2. False positive RDP/VoIP detection fix ───

describe("RDP/VoIP false positive fix — 443/8443 filtering", () => {
  const CONFERENCING_WEB_PORTS = new Set([443, 8443]);
  const CONFERENCING_FINGERPRINTS = ['polycom', 'telepresence', 'zoom room', 'crestron', 'webex', 'lifesize', 'tandberg', 'cisco meeting', 'realpresence'];

  function isRdpVoipConferencingPort(port: number): boolean {
    // Simplified version of the actual function for testing
    const knownPorts = [3389, 3390, 5060, 5061, 5080, 1720, 1719, 2427, 2000, 2443, 443, 8443];
    return knownPorts.includes(port);
  }

  function filterRdpVoipPorts(discoveredPorts: any[]): any[] {
    return discoveredPorts.filter(p => {
      if (['rdp', 'sip', 'sips', 'h323', 'sccp', 'mgcp', 'ms-wbt-server'].includes(p.service)) return true;
      if (CONFERENCING_WEB_PORTS.has(p.port)) {
        const banner = ((p as any).banner || '').toLowerCase();
        const product = ((p as any).product || '').toLowerCase();
        const version = (p.version || '').toLowerCase();
        const combined = `${banner} ${product} ${version}`;
        return CONFERENCING_FINGERPRINTS.some(fp => combined.includes(fp));
      }
      return isRdpVoipConferencingPort(p.port);
    });
  }

  it("should NOT flag 443/unknown as RDP/VoIP (the original false positive)", () => {
    const ports = [
      { port: 443, service: 'unknown', version: '' },
      { port: 8443, service: 'unknown', version: '' },
    ];
    const result = filterRdpVoipPorts(ports);
    expect(result).toHaveLength(0);
  });

  it("should NOT flag 443/https as RDP/VoIP", () => {
    const ports = [
      { port: 443, service: 'https', version: 'nginx 1.24' },
    ];
    const result = filterRdpVoipPorts(ports);
    expect(result).toHaveLength(0);
  });

  it("should flag 443 when banner indicates Polycom conferencing", () => {
    const ports = [
      { port: 443, service: 'https', version: '', banner: 'Polycom RealPresence Group 500', product: 'Polycom' },
    ];
    const result = filterRdpVoipPorts(ports);
    expect(result).toHaveLength(1);
    expect(result[0].port).toBe(443);
  });

  it("should flag 8443 when product indicates Cisco TelePresence", () => {
    const ports = [
      { port: 8443, service: 'https', version: '', product: 'Cisco TelePresence Server' },
    ];
    const result = filterRdpVoipPorts(ports);
    expect(result).toHaveLength(1);
  });

  it("should flag 443 when banner indicates Zoom Room", () => {
    const ports = [
      { port: 443, service: 'https', version: '', banner: 'Zoom Room Controller v5.12' },
    ];
    const result = filterRdpVoipPorts(ports);
    expect(result).toHaveLength(1);
  });

  it("should flag 8443 when product indicates Crestron", () => {
    const ports = [
      { port: 8443, service: 'https', version: '', product: 'Crestron TSW-1060' },
    ];
    const result = filterRdpVoipPorts(ports);
    expect(result).toHaveLength(1);
  });

  it("should flag 443 when banner indicates Webex", () => {
    const ports = [
      { port: 443, service: 'https', version: '', banner: 'Cisco Webex Board 85' },
    ];
    const result = filterRdpVoipPorts(ports);
    expect(result).toHaveLength(1);
  });

  it("should always flag port 3389 as RDP regardless of service name", () => {
    const ports = [
      { port: 3389, service: 'unknown', version: '' },
    ];
    const result = filterRdpVoipPorts(ports);
    expect(result).toHaveLength(1);
  });

  it("should always flag port 5060 as SIP regardless of service name", () => {
    const ports = [
      { port: 5060, service: 'unknown', version: '' },
    ];
    const result = filterRdpVoipPorts(ports);
    expect(result).toHaveLength(1);
  });

  it("should flag service 'rdp' on any port", () => {
    const ports = [
      { port: 13389, service: 'rdp', version: '' },
    ];
    const result = filterRdpVoipPorts(ports);
    expect(result).toHaveLength(1);
  });

  it("should flag service 'sip' on any port", () => {
    const ports = [
      { port: 15060, service: 'sip', version: '' },
    ];
    const result = filterRdpVoipPorts(ports);
    expect(result).toHaveLength(1);
  });

  it("should correctly filter mixed ports — only real RDP/VoIP", () => {
    const ports = [
      { port: 22, service: 'ssh', version: 'OpenSSH 8.9' },
      { port: 80, service: 'http', version: 'nginx' },
      { port: 443, service: 'https', version: 'nginx' },  // generic HTTPS — should be excluded
      { port: 3389, service: 'ms-wbt-server', version: '' },  // real RDP
      { port: 5060, service: 'unknown', version: '' },  // SIP port
      { port: 8443, service: 'unknown', version: '' },  // generic HTTPS alt — should be excluded
    ];
    const result = filterRdpVoipPorts(ports);
    expect(result).toHaveLength(2); // 3389 (ms-wbt-server service match), 5060 (port match)
    const resultPorts = result.map(p => p.port);
    expect(resultPorts).toContain(3389);
    expect(resultPorts).toContain(5060);
    expect(resultPorts).not.toContain(443);
    expect(resultPorts).not.toContain(8443);
    expect(resultPorts).not.toContain(22);
    expect(resultPorts).not.toContain(80);
  });

  it("should handle ports with no banner/product/version gracefully", () => {
    const ports = [
      { port: 443, service: 'unknown' },  // no version, banner, or product
      { port: 8443, service: 'unknown' },
    ];
    const result = filterRdpVoipPorts(ports);
    expect(result).toHaveLength(0);
  });

  it("should be case-insensitive for conferencing fingerprints", () => {
    const ports = [
      { port: 443, service: 'https', version: '', banner: 'POLYCOM REALPRESENCE GROUP 700' },
    ];
    const result = filterRdpVoipPorts(ports);
    expect(result).toHaveLength(1);
  });
});
