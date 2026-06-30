import { describe, it, expect, vi } from 'vitest';
import { selectFindingsForScreenshot } from './lib/scanners/screenshot-capture';

describe('Screenshot Capture - DI Report Integration', () => {
  describe('selectFindingsForScreenshot', () => {
    it('should prioritize critical/high severity findings', () => {
      const vulns = [
        { id: '1', title: 'Info disclosure', severity: 'info', url: 'https://example.com/info' },
        { id: '2', title: 'XSS in login', severity: 'high', url: 'https://example.com/login' },
        { id: '3', title: 'RCE via deserialization', severity: 'critical', url: 'https://example.com/api' },
        { id: '4', title: 'Missing headers', severity: 'low', url: 'https://example.com/headers' },
        { id: '5', title: 'SQLi in search', severity: 'high', url: 'https://example.com/search' },
      ];
      const result = selectFindingsForScreenshot(vulns, 3);
      expect(result).toHaveLength(3);
      expect(result[0].severity).toBe('critical');
      expect(result[1].severity).toBe('high');
      expect(result[2].severity).toBe('high');
    });

    it('should filter out non-HTTP URLs', () => {
      const vulns = [
        { id: '1', title: 'SSH vuln', severity: 'high', url: 'ssh://example.com:22' },
        { id: '2', title: 'FTP vuln', severity: 'high', url: 'ftp://example.com' },
        { id: '3', title: 'Web vuln', severity: 'high', url: 'https://example.com/vuln' },
        { id: '4', title: 'No URL', severity: 'critical' },
      ];
      const result = selectFindingsForScreenshot(vulns, 10);
      expect(result).toHaveLength(1);
      expect(result[0].findingTitle).toBe('Web vuln');
    });

    it('should filter out false positives', () => {
      const vulns = [
        { id: '1', title: 'Real vuln', severity: 'high', url: 'https://example.com/real', corroborationTier: 'confirmed' },
        { id: '2', title: 'FP vuln', severity: 'critical', url: 'https://example.com/fp', corroborationTier: 'false_positive' },
      ];
      const result = selectFindingsForScreenshot(vulns, 10);
      expect(result).toHaveLength(1);
      expect(result[0].findingTitle).toBe('Real vuln');
    });

    it('should prefer confirmed findings over unverified at same severity', () => {
      const vulns = [
        { id: '1', title: 'Unverified', severity: 'high', url: 'https://example.com/a', corroborationTier: 'unverified' },
        { id: '2', title: 'Confirmed', severity: 'high', url: 'https://example.com/b', corroborationTier: 'confirmed' },
      ];
      const result = selectFindingsForScreenshot(vulns, 2);
      expect(result[0].findingTitle).toBe('Confirmed');
      expect(result[1].findingTitle).toBe('Unverified');
    });

    it('should respect maxScreenshots limit', () => {
      const vulns = Array.from({ length: 50 }, (_, i) => ({
        id: String(i),
        title: `Vuln ${i}`,
        severity: 'high',
        url: `https://example.com/vuln${i}`,
      }));
      const result = selectFindingsForScreenshot(vulns, 10);
      expect(result).toHaveLength(10);
    });

    it('should use endpoint field as fallback for url', () => {
      const vulns = [
        { id: '1', title: 'Endpoint vuln', severity: 'high', endpoint: 'https://example.com/endpoint' },
      ];
      const result = selectFindingsForScreenshot(vulns, 10);
      expect(result).toHaveLength(1);
      expect(result[0].url).toBe('https://example.com/endpoint');
    });

    it('should return empty array for no web-accessible findings', () => {
      const vulns = [
        { id: '1', title: 'No URL', severity: 'critical' },
        { id: '2', title: 'Internal', severity: 'high', url: 'internal://scan' },
      ];
      const result = selectFindingsForScreenshot(vulns, 10);
      expect(result).toHaveLength(0);
    });
  });

  describe('DI Report Evidence Data - Screenshot Integration', () => {
    it('should match screenshots to findings by title', () => {
      // Simulates the matching logic used in export-di-report.ts
      const screenshotEvidence = [
        { id: 1, title: 'Missing critical security headers', severity: 'high', screenshotPath: 'https://s3.example.com/ss1.png', hostname: 'example.com', endpoint: '/headers', corroborationTier: 'confirmed' },
        { id: 2, title: 'SQL Injection in search', severity: 'critical', screenshotPath: 'https://s3.example.com/ss2.png', hostname: 'example.com', endpoint: '/search', corroborationTier: 'confirmed' },
      ];

      const findingTitle = 'Missing critical security headers';
      const titleNorm = findingTitle.toLowerCase().trim();
      const matchingScreenshot = screenshotEvidence.find((ss) => {
        const ssTitle = (ss.title || '').toLowerCase().trim();
        return ssTitle === titleNorm || ssTitle.includes(titleNorm) || titleNorm.includes(ssTitle);
      });

      expect(matchingScreenshot).toBeDefined();
      expect(matchingScreenshot!.screenshotPath).toBe('https://s3.example.com/ss1.png');
    });

    it('should match screenshots by hostname when title does not match', () => {
      const screenshotEvidence = [
        { id: 1, title: 'Different title', severity: 'high', screenshotPath: 'https://s3.example.com/ss1.png', hostname: 'target.com', endpoint: '/vuln', corroborationTier: 'confirmed' },
      ];

      const hosts = ['target.com'];
      const titleNorm = 'some other finding title';
      const matchingScreenshot = screenshotEvidence.find((ss) => {
        const ssTitle = (ss.title || '').toLowerCase().trim();
        return ssTitle === titleNorm || ssTitle.includes(titleNorm) || titleNorm.includes(ssTitle) || (hosts[0] && ss.hostname === hosts[0]);
      });

      expect(matchingScreenshot).toBeDefined();
      expect(matchingScreenshot!.hostname).toBe('target.com');
    });

    it('should match screenshots by CVE ID', () => {
      const screenshotEvidence = [
        { id: 1, title: 'CVE-2024-1234 - Buffer overflow', severity: 'critical', screenshotPath: 'https://s3.example.com/ss1.png', hostname: 'other.com', endpoint: '/api', corroborationTier: 'confirmed' },
      ];

      const cveId = 'CVE-2024-1234';
      const titleNorm = 'buffer overflow in api endpoint';
      const matchingScreenshot = screenshotEvidence.find((ss) => {
        const ssTitle = (ss.title || '').toLowerCase().trim();
        return ssTitle === titleNorm ||
          ssTitle.includes(titleNorm) ||
          titleNorm.includes(ssTitle) ||
          (cveId !== 'N/A' && ssTitle.includes(cveId.toLowerCase()));
      });

      expect(matchingScreenshot).toBeDefined();
      expect(matchingScreenshot!.title).toContain('CVE-2024-1234');
    });
  });
});
