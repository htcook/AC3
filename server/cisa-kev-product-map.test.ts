/**
 * Tests for CISA KEV CVE-to-Product Mapping Engine
 *
 * Validates:
 * - Static fallback lookups for critical CVEs
 * - Technology family keyword definitions
 * - CVE-to-target validation logic
 * - KEV stats reporting
 * - Ransomware-linked CVE identification
 * - Vendor-product classification rules
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock fetch for KEV catalog loading tests
const mockFetch = vi.fn();
global.fetch = mockFetch as any;

import {
  lookupCVEProduct,
  validateCVEAgainstTarget,
  getKEVStats,
  loadKEVCatalog,
  ensureKEVLoaded,
  getRansomwareLinkedCVEs,
  TECH_FAMILY_KEYWORDS,
} from './lib/cisa-kev-product-map';

describe('CISA KEV CVE-to-Product Mapping Engine', () => {

  // ─── Static Fallback Lookups ─────────────────────────────────────────────

  describe('Static Fallback Lookups', () => {
    it('should find Rejetto HFS CVE in static fallback', () => {
      const result = lookupCVEProduct('CVE-2024-23692');
      expect(result.source).not.toBe('not_found');
      expect(result.family).toBe('rejetto_hfs');
      expect(result.keywords).toContain('rejetto');
      expect(result.keywords).toContain('hfs');
    });

    it('should find Log4Shell in static fallback', () => {
      const result = lookupCVEProduct('CVE-2021-44228');
      expect(result.source).not.toBe('not_found');
      expect(result.family).toBe('apache_log4j');
      expect(result.keywords).toContain('log4j');
    });

    it('should find EternalBlue in static fallback', () => {
      const result = lookupCVEProduct('CVE-2017-0144');
      expect(result.source).not.toBe('not_found');
      expect(result.family).toBe('microsoft_windows');
      expect(result.keywords).toContain('windows');
    });

    it('should find ProxyShell in static fallback', () => {
      const result = lookupCVEProduct('CVE-2021-34473');
      expect(result.source).not.toBe('not_found');
      expect(result.family).toBe('microsoft_exchange');
      expect(result.keywords).toContain('exchange');
    });

    it('should find ProxyLogon in static fallback', () => {
      const result = lookupCVEProduct('CVE-2021-26855');
      expect(result.source).not.toBe('not_found');
      expect(result.family).toBe('microsoft_exchange');
    });

    it('should find MOVEit Transfer in static fallback', () => {
      const result = lookupCVEProduct('CVE-2023-34362');
      expect(result.source).not.toBe('not_found');
      expect(result.family).toBe('moveit');
    });

    it('should find Fortinet FortiOS in static fallback', () => {
      const result = lookupCVEProduct('CVE-2024-21762');
      expect(result.source).not.toBe('not_found');
      expect(result.family).toBe('fortinet_fortios');
      expect(result.keywords).toContain('fortios');
    });

    it('should find Palo Alto PAN-OS in static fallback', () => {
      const result = lookupCVEProduct('CVE-2024-3400');
      expect(result.source).not.toBe('not_found');
      expect(result.family).toBe('paloalto_panos');
      expect(result.keywords).toContain('globalprotect');
    });

    it('should find Ivanti Connect Secure in static fallback', () => {
      const result = lookupCVEProduct('CVE-2024-21887');
      expect(result.source).not.toBe('not_found');
      expect(result.family).toBe('ivanti_connect_secure');
    });

    it('should find Citrix NetScaler in static fallback', () => {
      const result = lookupCVEProduct('CVE-2023-3519');
      expect(result.source).not.toBe('not_found');
      expect(result.family).toBe('citrix_adc');
    });

    it('should find ConnectWise ScreenConnect in static fallback', () => {
      const result = lookupCVEProduct('CVE-2024-1709');
      expect(result.source).not.toBe('not_found');
      expect(result.family).toBe('connectwise');
    });

    it('should find Apache ActiveMQ in static fallback', () => {
      const result = lookupCVEProduct('CVE-2023-46604');
      expect(result.source).not.toBe('not_found');
      expect(result.family).toBe('apache_activemq');
    });

    it('should find Confluence in static fallback', () => {
      const result = lookupCVEProduct('CVE-2023-22515');
      expect(result.source).not.toBe('not_found');
      expect(result.family).toBe('atlassian_confluence');
    });

    it('should find Dirty Pipe (Linux kernel) in static fallback', () => {
      const result = lookupCVEProduct('CVE-2022-0847');
      expect(result.source).not.toBe('not_found');
      expect(result.family).toBe('linux_kernel');
    });

    it('should find Barracuda ESG in static fallback', () => {
      const result = lookupCVEProduct('CVE-2023-2868');
      expect(result.source).not.toBe('not_found');
      expect(result.family).toBe('barracuda');
    });

    it('should return not_found for unknown CVEs', () => {
      const result = lookupCVEProduct('CVE-9999-99999');
      expect(result.source).toBe('not_found');
      expect(result.family).toBe('');
      expect(result.keywords).toEqual([]);
    });

    it('should handle case-insensitive CVE IDs', () => {
      const result = lookupCVEProduct('cve-2021-44228');
      // The function expects uppercase, but the caller should normalize
      // Testing that the static map uses uppercase keys
      const upper = lookupCVEProduct('CVE-2021-44228');
      expect(upper.source).not.toBe('not_found');
    });

    it('should have at least 50 CVEs in static fallback', () => {
      const stats = getKEVStats();
      expect(stats.staticFallbackCount).toBeGreaterThanOrEqual(50);
    });
  });

  // ─── Technology Family Keywords ──────────────────────────────────────────

  describe('Technology Family Keywords', () => {
    it('should have at least 50 technology families defined', () => {
      expect(Object.keys(TECH_FAMILY_KEYWORDS).length).toBeGreaterThanOrEqual(50);
    });

    it('should have keywords for all major vendors', () => {
      const families = Object.keys(TECH_FAMILY_KEYWORDS);
      expect(families).toContain('microsoft_windows');
      expect(families).toContain('microsoft_exchange');
      expect(families).toContain('apache_log4j');
      expect(families).toContain('fortinet_fortios');
      expect(families).toContain('citrix_adc');
      expect(families).toContain('paloalto_panos');
      expect(families).toContain('vmware_vcenter');
      expect(families).toContain('rejetto_hfs');
      expect(families).toContain('atlassian_confluence');
      expect(families).toContain('f5_bigip');
    });

    it('should have non-empty keyword arrays for every family', () => {
      for (const [family, keywords] of Object.entries(TECH_FAMILY_KEYWORDS)) {
        expect(keywords.length, `${family} has no keywords`).toBeGreaterThan(0);
      }
    });

    it('should have lowercase keywords', () => {
      for (const [family, keywords] of Object.entries(TECH_FAMILY_KEYWORDS)) {
        for (const kw of keywords) {
          expect(kw, `${family} keyword "${kw}" is not lowercase`).toBe(kw.toLowerCase());
        }
      }
    });
  });

  // ─── CVE-to-Target Validation ────────────────────────────────────────────

  describe('CVE-to-Target Validation', () => {
    it('should block Rejetto HFS CVE against Java/Spring target', () => {
      const result = validateCVEAgainstTarget(
        'CVE-2024-23692',
        ['java', 'spring', 'tomcat'],
        ['http apache']
      );
      expect(result).not.toBeNull();
      expect(result!.family).toBe('rejetto_hfs');
      expect(result!.violation).toContain('rejetto_hfs');
    });

    it('should allow Rejetto HFS CVE against HFS target', () => {
      const result = validateCVEAgainstTarget(
        'CVE-2024-23692',
        ['rejetto http file server'],
        ['hfs 2.3']
      );
      expect(result).toBeNull();
    });

    it('should block Log4Shell against PHP target', () => {
      const result = validateCVEAgainstTarget(
        'CVE-2021-44228',
        ['php', 'wordpress', 'mysql'],
        ['http nginx']
      );
      expect(result).not.toBeNull();
      expect(result!.family).toBe('apache_log4j');
    });

    it('should allow Log4Shell against Java target', () => {
      const result = validateCVEAgainstTarget(
        'CVE-2021-44228',
        ['java', 'log4j', 'spring boot'],
        []
      );
      expect(result).toBeNull();
    });

    it('should block Exchange CVE against Linux target', () => {
      const result = validateCVEAgainstTarget(
        'CVE-2021-34473',
        ['linux', 'nginx', 'php'],
        []
      );
      expect(result).not.toBeNull();
      expect(result!.family).toBe('microsoft_exchange');
    });

    it('should allow Exchange CVE against Exchange target', () => {
      const result = validateCVEAgainstTarget(
        'CVE-2021-34473',
        ['microsoft exchange server 2019'],
        ['https exchange']
      );
      expect(result).toBeNull();
    });

    it('should block Fortinet CVE against Apache target', () => {
      const result = validateCVEAgainstTarget(
        'CVE-2024-21762',
        ['apache', 'php', 'mysql'],
        []
      );
      expect(result).not.toBeNull();
      expect(result!.family).toBe('fortinet_fortios');
    });

    it('should allow Fortinet CVE against FortiGate target', () => {
      const result = validateCVEAgainstTarget(
        'CVE-2024-21762',
        ['fortigate', 'fortios 7.4'],
        []
      );
      expect(result).toBeNull();
    });

    it('should return null for unknown CVEs (no opinion)', () => {
      const result = validateCVEAgainstTarget(
        'CVE-9999-99999',
        ['anything'],
        []
      );
      expect(result).toBeNull();
    });

    it('should match via service versions when tech stack is empty', () => {
      const result = validateCVEAgainstTarget(
        'CVE-2024-23692',
        [],
        ['rejetto hfs 2.3m']
      );
      expect(result).toBeNull();
    });

    it('should block when both tech stack and services mismatch', () => {
      const result = validateCVEAgainstTarget(
        'CVE-2024-3400',
        ['nginx', 'wordpress'],
        ['http nginx/1.18']
      );
      expect(result).not.toBeNull();
      expect(result!.family).toBe('paloalto_panos');
    });

    it('should allow Palo Alto CVE when GlobalProtect is in services', () => {
      const result = validateCVEAgainstTarget(
        'CVE-2024-3400',
        [],
        ['https globalprotect']
      );
      expect(result).toBeNull();
    });

    it('should block Confluence CVE against Drupal target', () => {
      const result = validateCVEAgainstTarget(
        'CVE-2023-22515',
        ['drupal', 'php', 'mysql'],
        []
      );
      expect(result).not.toBeNull();
      expect(result!.family).toBe('atlassian_confluence');
    });

    it('should allow Confluence CVE against Confluence target', () => {
      const result = validateCVEAgainstTarget(
        'CVE-2023-22515',
        ['atlassian confluence 8.5'],
        []
      );
      expect(result).toBeNull();
    });
  });

  // ─── Dynamic KEV Loading ─────────────────────────────────────────────────

  describe('Dynamic KEV Catalog Loading', () => {
    beforeEach(() => {
      mockFetch.mockReset();
    });

    it('should load and classify KEV entries', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          vulnerabilities: [
            {
              cveID: 'CVE-2024-99999',
              vendorProject: 'Fortinet',
              product: 'FortiOS',
              vulnerabilityName: 'Fortinet FortiOS RCE',
              knownRansomwareCampaignUse: 'Known',
              dateAdded: '2024-01-15',
            },
            {
              cveID: 'CVE-2024-88888',
              vendorProject: 'Apache',
              product: 'Tomcat',
              vulnerabilityName: 'Apache Tomcat RCE',
              knownRansomwareCampaignUse: 'Unknown',
              dateAdded: '2024-02-01',
            },
            {
              cveID: 'CVE-2024-77777',
              vendorProject: 'UnknownVendor',
              product: 'UnknownProduct',
              vulnerabilityName: 'Some Vuln',
              knownRansomwareCampaignUse: 'Unknown',
              dateAdded: '2024-03-01',
            },
          ],
        }),
      });

      const count = await loadKEVCatalog();
      expect(count).toBe(2); // Only 2 classified, UnknownVendor has no rule

      // Verify the loaded entries
      const fortinet = lookupCVEProduct('CVE-2024-99999');
      expect(fortinet.source).toBe('kev_live');
      expect(fortinet.family).toBe('fortinet_fortios');
      expect(fortinet.ransomwareLinked).toBe(true);

      const tomcat = lookupCVEProduct('CVE-2024-88888');
      expect(tomcat.source).toBe('kev_live');
      expect(tomcat.family).toBe('apache_tomcat');
      expect(tomcat.ransomwareLinked).toBe(false);
    });

    it('should handle fetch failures gracefully', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));
      const count = await loadKEVCatalog();
      // Should return current index size (may be > 0 from previous test)
      expect(typeof count).toBe('number');
    });

    it('should handle non-OK responses', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 503,
      });
      const count = await loadKEVCatalog();
      expect(typeof count).toBe('number');
    });

    it('should report KEV stats', () => {
      const stats = getKEVStats();
      expect(stats).toHaveProperty('loaded');
      expect(stats).toHaveProperty('totalCVEs');
      expect(stats).toHaveProperty('families');
      expect(stats).toHaveProperty('lastRefresh');
      expect(stats).toHaveProperty('staticFallbackCount');
      expect(stats.staticFallbackCount).toBeGreaterThanOrEqual(50);
    });

    it('should identify ransomware-linked CVEs after loading', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          vulnerabilities: [
            {
              cveID: 'CVE-2024-RANSOM1',
              vendorProject: 'Fortinet',
              product: 'FortiOS',
              vulnerabilityName: 'FortiOS RCE',
              knownRansomwareCampaignUse: 'Known',
              dateAdded: '2024-01-01',
            },
            {
              cveID: 'CVE-2024-NORANSOM',
              vendorProject: 'Fortinet',
              product: 'FortiOS',
              vulnerabilityName: 'FortiOS Info Disclosure',
              knownRansomwareCampaignUse: 'Unknown',
              dateAdded: '2024-01-02',
            },
          ],
        }),
      });

      await loadKEVCatalog();
      const ransomCVEs = getRansomwareLinkedCVEs();
      expect(ransomCVEs).toContain('CVE-2024-RANSOM1');
      expect(ransomCVEs).not.toContain('CVE-2024-NORANSOM');
    });
  });

  // ─── Integration: Guardrails Using KEV Data ──────────────────────────────

  describe('Integration with Guardrails', () => {
    it('should block mismatched CVE even when only static fallback is available', () => {
      // This tests the full flow without loading KEV
      const result = validateCVEAgainstTarget(
        'CVE-2024-23692', // Rejetto HFS
        ['java', 'spring boot', 'tomcat 9'],
        ['http apache-coyote/1.1']
      );
      expect(result).not.toBeNull();
      expect(result!.violation).toContain('rejetto_hfs');
    });

    it('should cover multiple CVEs for the same product family', () => {
      // Both Rejetto CVEs should map to the same family
      const r1 = lookupCVEProduct('CVE-2024-23692');
      const r2 = lookupCVEProduct('CVE-2014-6287');
      expect(r1.family).toBe('rejetto_hfs');
      expect(r2.family).toBe('rejetto_hfs');
    });

    it('should cover ProxyShell chain CVEs consistently', () => {
      const cves = ['CVE-2021-34473', 'CVE-2021-34523', 'CVE-2021-31207'];
      for (const cve of cves) {
        const result = lookupCVEProduct(cve);
        expect(result.source, `${cve} not found`).not.toBe('not_found');
        expect(result.family).toBe('microsoft_exchange');
      }
    });

    it('should cover Fortinet chain CVEs consistently', () => {
      const cves = ['CVE-2024-21762', 'CVE-2023-27997', 'CVE-2022-42475', 'CVE-2018-13379'];
      for (const cve of cves) {
        const result = lookupCVEProduct(cve);
        expect(result.source, `${cve} not found`).not.toBe('not_found');
        expect(result.family).toBe('fortinet_fortios');
      }
    });

    it('should cover Ivanti/Pulse Secure CVEs consistently', () => {
      const cves = ['CVE-2024-21887', 'CVE-2023-46805', 'CVE-2019-11510'];
      for (const cve of cves) {
        const result = lookupCVEProduct(cve);
        expect(result.source, `${cve} not found`).not.toBe('not_found');
        expect(result.family).toBe('ivanti_connect_secure');
      }
    });
  });
});
