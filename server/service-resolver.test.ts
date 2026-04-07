import { describe, it, expect } from 'vitest';
import {
  resolvePortService,
  resolveAssetServices,
  inferServiceName,
  enrichPortServices,
  getSourceLabel,
  getConfidenceColor,
  WELL_KNOWN_PORTS,
} from './lib/service-resolver';

describe('service-resolver', () => {
  // ─── resolvePortService ───────────────────────────────────────────────

  describe('resolvePortService', () => {
    it('returns active fingerprint as tier-1 (highest confidence)', () => {
      const result = resolvePortService(8080, 'nginx', '1.25.3', []);
      expect(result.service).toBe('nginx');
      expect(result.source).toBe('fingerprinted');
      expect(result.confidence).toBe(0.95);
      expect(result.version).toBe('1.25.3');
    });

    it('falls back to passive recon as tier-2 when active is unknown', () => {
      const passive = [{ port: 22, service: 'openssh', version: '8.9p1', source: 'shodan' }];
      const result = resolvePortService(22, 'unknown', undefined, passive);
      expect(result.service).toBe('openssh');
      expect(result.source).toBe('passive');
      expect(result.confidence).toBe(0.75);
      expect(result.version).toBe('8.9p1');
    });

    it('falls back to well-known port map as tier-3 when both active and passive are unknown', () => {
      const result = resolvePortService(443, 'unknown', undefined, []);
      expect(result.service).toBe('https');
      expect(result.source).toBe('inferred');
      expect(result.confidence).toBe(0.5);
    });

    it('returns unknown with low confidence for unmapped ports', () => {
      const result = resolvePortService(31337, 'unknown', undefined, []);
      expect(result.service).toBe('unknown');
      expect(result.source).toBe('inferred');
      expect(result.confidence).toBe(0.1);
    });

    it('treats empty string service as unknown', () => {
      const result = resolvePortService(80, '', undefined, []);
      expect(result.service).toBe('http');
      expect(result.source).toBe('inferred');
    });

    it('prefers active fingerprint over passive even when passive has data', () => {
      const passive = [{ port: 80, service: 'apache', version: '2.4.52' }];
      const result = resolvePortService(80, 'nginx', '1.25', passive);
      expect(result.service).toBe('nginx');
      expect(result.source).toBe('fingerprinted');
    });

    it('passive match preserves active version if passive has none', () => {
      const passive = [{ port: 3306, service: 'mysql' }];
      const result = resolvePortService(3306, 'unknown', '8.0.35', passive);
      expect(result.service).toBe('mysql');
      expect(result.version).toBe('8.0.35');
      expect(result.source).toBe('passive');
    });

    it('passive match ignores entries with unknown service', () => {
      const passive = [{ port: 9999, service: 'unknown' }];
      const result = resolvePortService(9999, 'unknown', undefined, passive);
      // Should fall through to tier-3 (well-known) or unknown
      expect(result.service).toBe('unknown');
      expect(result.confidence).toBe(0.1);
    });
  });

  // ─── resolveAssetServices ─────────────────────────────────────────────

  describe('resolveAssetServices', () => {
    it('resolves all ports for an asset combining active + passive', () => {
      const active = [
        { port: 22, service: 'unknown', version: undefined },
        { port: 80, service: 'nginx', version: '1.25' },
        { port: 443, service: 'unknown', version: undefined },
      ];
      const passive = [
        { port: 22, service: 'openssh', version: '8.9p1' },
        { port: 8080, service: 'tomcat', version: '9.0' },
      ];
      const result = resolveAssetServices(active, passive);

      // Port 22: passive wins over unknown
      expect(result.find(r => r.port === 22)?.service).toBe('openssh');
      expect(result.find(r => r.port === 22)?.source).toBe('passive');

      // Port 80: active fingerprint wins
      expect(result.find(r => r.port === 80)?.service).toBe('nginx');
      expect(result.find(r => r.port === 80)?.source).toBe('fingerprinted');

      // Port 443: well-known fallback
      expect(result.find(r => r.port === 443)?.service).toBe('https');
      expect(result.find(r => r.port === 443)?.source).toBe('inferred');

      // Port 8080: passive-only port added
      expect(result.find(r => r.port === 8080)?.service).toBe('tomcat');
      expect(result.find(r => r.port === 8080)?.source).toBe('passive');

      // Sorted by port number
      expect(result.map(r => r.port)).toEqual([22, 80, 443, 8080]);
    });

    it('deduplicates ports between active and passive', () => {
      const active = [{ port: 22, service: 'ssh' }];
      const passive = [{ port: 22, service: 'openssh', version: '8.9' }];
      const result = resolveAssetServices(active, passive);
      expect(result.length).toBe(1);
      expect(result[0].service).toBe('ssh'); // active wins
    });

    it('handles empty inputs', () => {
      expect(resolveAssetServices([], []).length).toBe(0);
      expect(resolveAssetServices([], [{ port: 80, service: 'http' }]).length).toBe(1);
    });
  });

  // ─── inferServiceName ─────────────────────────────────────────────────

  describe('inferServiceName', () => {
    it('returns service name for well-known ports', () => {
      expect(inferServiceName(22)).toBe('ssh');
      expect(inferServiceName(80)).toBe('http');
      expect(inferServiceName(443)).toBe('https');
      expect(inferServiceName(3306)).toBe('mysql');
      expect(inferServiceName(5432)).toBe('postgresql');
      expect(inferServiceName(6379)).toBe('redis');
      expect(inferServiceName(27017)).toBe('mongodb');
    });

    it('returns unknown for unmapped ports', () => {
      expect(inferServiceName(31337)).toBe('unknown');
      expect(inferServiceName(12345)).toBe('unknown');
    });
  });

  // ─── enrichPortServices ───────────────────────────────────────────────

  describe('enrichPortServices', () => {
    it('mutates ports in-place, replacing unknown with resolved names', () => {
      const ports = [
        { port: 22, service: 'unknown' },
        { port: 80, service: 'nginx' },
        { port: 443, service: 'unknown' },
        { port: 8090, service: 'unknown' },
      ];
      enrichPortServices(ports, []);

      expect(ports[0].service).toBe('ssh');
      expect(ports[1].service).toBe('nginx'); // unchanged — already identified
      expect(ports[2].service).toBe('https');
      expect(ports[3].service).toBe('http-alt');
    });

    it('prefers passive recon over well-known fallback', () => {
      const ports = [{ port: 8080, service: 'unknown' }];
      const passive = [{ port: 8080, service: 'tomcat', version: '9.0.80' }];
      enrichPortServices(ports, passive);

      expect(ports[0].service).toBe('tomcat');
      expect(ports[0].version).toBe('9.0.80');
    });

    it('does not overwrite already-identified services', () => {
      const ports = [{ port: 22, service: 'dropbear' }];
      enrichPortServices(ports, [{ port: 22, service: 'openssh' }]);
      expect(ports[0].service).toBe('dropbear');
    });

    it('fills in version from passive when active has none', () => {
      const ports = [{ port: 3306, service: 'unknown' }];
      const passive = [{ port: 3306, service: 'mysql', version: '8.0.35' }];
      enrichPortServices(ports, passive);
      expect(ports[0].service).toBe('mysql');
      expect(ports[0].version).toBe('8.0.35');
    });

    it('handles empty string service same as unknown', () => {
      const ports = [{ port: 445, service: '' }];
      enrichPortServices(ports, []);
      expect(ports[0].service).toBe('smb');
    });
  });

  // ─── WELL_KNOWN_PORTS coverage ────────────────────────────────────────

  describe('WELL_KNOWN_PORTS', () => {
    it('covers the 5 ports from the screenshot (22, 80, 443, 4000, 8090)', () => {
      expect(WELL_KNOWN_PORTS[22]?.service).toBe('ssh');
      expect(WELL_KNOWN_PORTS[80]?.service).toBe('http');
      expect(WELL_KNOWN_PORTS[443]?.service).toBe('https');
      expect(WELL_KNOWN_PORTS[4000]?.service).toBe('http-alt');
      expect(WELL_KNOWN_PORTS[8090]?.service).toBe('http-alt');
    });

    it('covers common database ports', () => {
      expect(WELL_KNOWN_PORTS[3306]?.service).toBe('mysql');
      expect(WELL_KNOWN_PORTS[5432]?.service).toBe('postgresql');
      expect(WELL_KNOWN_PORTS[6379]?.service).toBe('redis');
      expect(WELL_KNOWN_PORTS[27017]?.service).toBe('mongodb');
      expect(WELL_KNOWN_PORTS[1433]?.service).toBe('mssql');
    });

    it('covers container/orchestration ports', () => {
      expect(WELL_KNOWN_PORTS[2375]?.service).toBe('docker');
      expect(WELL_KNOWN_PORTS[6443]?.service).toBe('kubernetes');
      expect(WELL_KNOWN_PORTS[10250]?.service).toBe('kubelet');
    });
  });

  // ─── Helper functions ─────────────────────────────────────────────────

  describe('getSourceLabel', () => {
    it('returns human-friendly labels', () => {
      expect(getSourceLabel('fingerprinted')).toBe('Banner Grab');
      expect(getSourceLabel('passive')).toBe('Passive Recon');
      expect(getSourceLabel('inferred')).toBe('Port Mapping');
    });
  });

  describe('getConfidenceColor', () => {
    it('returns appropriate color classes for confidence levels', () => {
      expect(getConfidenceColor(0.95)).toBe('text-emerald-400');
      expect(getConfidenceColor(0.75)).toBe('text-cyan-400');
      expect(getConfidenceColor(0.5)).toBe('text-cyan-400');
      expect(getConfidenceColor(0.3)).toBe('text-yellow-400');
      expect(getConfidenceColor(0.1)).toBe('text-muted-foreground');
    });
  });
});
