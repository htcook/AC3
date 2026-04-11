/**
 * Tests for Nuclei Enhancements:
 *   1. JSON Output Parser (nuclei-output-parser.ts)
 *   2. Verification Engine (nuclei-verification-engine.ts)
 *   3. Authenticated Scan Cookie Injection
 */
import { describe, it, expect, vi } from 'vitest';
import {
  parseNucleiJsonOutput,
  assessNucleiAccessLevel,
  formatNucleiExploitOutput,
  addJsonFlag,
  type NucleiParseResult,
  type NucleiJsonFinding,
} from './lib/nuclei-output-parser';
import {
  extractSessionCookie,
  adjustVerificationWithNuclei,
  buildCookieHeader,
  type NucleiVerificationResult,
} from './lib/nuclei-verification-engine';
import type { VerificationResult, AccessLevel } from './lib/exploit-verification-engine';

// ═══════════════════════════════════════════════════════════════════════
// §1 — NUCLEI JSON OUTPUT PARSER TESTS
// ═══════════════════════════════════════════════════════════════════════

describe('Nuclei JSON Output Parser', () => {
  describe('parseNucleiJsonOutput', () => {
    it('parses a single JSONL finding (CVE with extracted data)', () => {
      const jsonLine = JSON.stringify({
        'template-id': 'CVE-2021-41773',
        'template-path': '/root/nuclei-templates/cves/2021/CVE-2021-41773.yaml',
        info: {
          name: 'Apache HTTP Server Path Traversal',
          author: ['dhiyaneshdk'],
          tags: ['cve', 'cve2021', 'apache', 'rce', 'lfi', 'kev'],
          severity: 'critical',
          description: 'A flaw was found in a change made to path normalization...',
          reference: ['https://nvd.nist.gov/vuln/detail/CVE-2021-41773'],
          classification: {
            'cve-id': 'CVE-2021-41773',
            'cwe-id': ['CWE-22'],
            'cvss-metrics': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'cvss-score': 9.8,
          },
        },
        type: 'http',
        host: 'http://10.0.0.1:80',
        'matched-at': 'http://10.0.0.1:80/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd',
        'extracted-results': ['root:x:0:0:root:/root:/bin/bash'],
        ip: '10.0.0.1',
        timestamp: '2024-01-15T10:30:00.000Z',
        'curl-command': "curl -X GET 'http://10.0.0.1/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'",
        'matcher-status': true,
      });

      const result = parseNucleiJsonOutput(jsonLine);

      expect(result.findings).toHaveLength(1);
      expect(result.stats.total).toBe(1);
      expect(result.stats.critical).toBe(1);
      expect(result.cves).toContain('CVE-2021-41773');
      expect(result.cwes).toContain('CWE-22');
      expect(result.matchedTemplates).toContain('CVE-2021-41773');
      expect(result.hasExploitableFindings).toBe(true);
      expect(result.highestSeverity).toBe('critical');
      expect(result.allExtractedData).toContain('root:x:0:0:root:/root:/bin/bash');
      expect(result.curlCommands).toHaveLength(1);
      expect(result.parseErrors).toHaveLength(0);

      const finding = result.findings[0];
      expect(finding.templateId).toBe('CVE-2021-41773');
      expect(finding.info.name).toBe('Apache HTTP Server Path Traversal');
      expect(finding.info.severity).toBe('critical');
      expect(finding.info.classification?.cveId).toBe('CVE-2021-41773');
      expect(finding.info.classification?.cvssScore).toBe(9.8);
      expect(finding.matchedAt).toBe('http://10.0.0.1:80/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd');
      expect(finding.extractedResults).toContain('root:x:0:0:root:/root:/bin/bash');
      expect(finding.matcherStatus).toBe(true);
    });

    it('parses multiple JSONL findings (multi-line output)', () => {
      const lines = [
        JSON.stringify({
          'template-id': 'CVE-2021-44228',
          info: { name: 'Log4Shell', author: ['pdteam'], tags: ['cve', 'rce', 'log4j'], severity: 'critical', classification: { 'cve-id': 'CVE-2021-44228' } },
          type: 'http', host: 'http://10.0.0.2:8080', 'matched-at': 'http://10.0.0.2:8080/api', 'extracted-results': [], 'matcher-status': true,
        }),
        JSON.stringify({
          'template-id': 'CVE-2021-45046',
          info: { name: 'Log4Shell Bypass', author: ['pdteam'], tags: ['cve', 'rce', 'log4j'], severity: 'high', classification: { 'cve-id': 'CVE-2021-45046' } },
          type: 'http', host: 'http://10.0.0.2:8080', 'matched-at': 'http://10.0.0.2:8080/api', 'extracted-results': [], 'matcher-status': true,
        }),
        JSON.stringify({
          'template-id': 'apache-detect',
          info: { name: 'Apache Detection', author: ['pdteam'], tags: ['tech', 'apache'], severity: 'info' },
          type: 'http', host: 'http://10.0.0.2:8080', 'matched-at': 'http://10.0.0.2:8080', 'extracted-results': ['Apache/2.4.49'], 'matcher-status': true,
        }),
      ].join('\n');

      const result = parseNucleiJsonOutput(lines);

      expect(result.findings).toHaveLength(3);
      expect(result.stats.total).toBe(3);
      expect(result.stats.critical).toBe(1);
      expect(result.stats.high).toBe(1);
      expect(result.stats.info).toBe(1);
      expect(result.cves).toContain('CVE-2021-44228');
      expect(result.cves).toContain('CVE-2021-45046');
      expect(result.matchedTemplates).toHaveLength(3);
      expect(result.hasExploitableFindings).toBe(true);
      expect(result.highestSeverity).toBe('critical');
    });

    it('handles mixed output (JSON lines + progress/stats text)', () => {
      const mixed = [
        '[INF] Running nuclei with 50 templates...',
        '[INF] Templates loaded: 50',
        JSON.stringify({
          'template-id': 'xss-reflected',
          info: { name: 'Reflected XSS', author: ['test'], tags: ['xss', 'reflected'], severity: 'medium' },
          type: 'http', host: 'http://target:80', 'matched-at': 'http://target:80/search?q=test', 'extracted-results': [], 'matcher-status': true,
        }),
        '[INF] Scan completed in 5.2s',
        '[INF] Found 1 results',
      ].join('\n');

      const result = parseNucleiJsonOutput(mixed);

      expect(result.findings).toHaveLength(1);
      expect(result.stats.total).toBe(1);
      expect(result.stats.medium).toBe(1);
      expect(result.parseErrors).toHaveLength(0); // Non-JSON lines should not generate errors
    });

    it('returns empty result for empty input', () => {
      const result = parseNucleiJsonOutput('');
      expect(result.findings).toHaveLength(0);
      expect(result.stats.total).toBe(0);
      expect(result.hasExploitableFindings).toBe(false);
      expect(result.highestSeverity).toBe('unknown');
    });

    it('returns empty result for all non-JSON lines', () => {
      const result = parseNucleiJsonOutput('[INF] No results found\n[INF] Scan complete');
      expect(result.findings).toHaveLength(0);
      expect(result.stats.total).toBe(0);
    });

    it('handles camelCase field names (Nuclei v3 format)', () => {
      const jsonLine = JSON.stringify({
        templateId: 'CVE-2023-1234',
        info: { name: 'Test Vuln', author: 'single-author', tags: 'cve,rce', severity: 'HIGH', classification: { cveId: 'CVE-2023-1234', cweId: 'CWE-79' } },
        type: 'http', host: 'http://target:80', matchedAt: 'http://target:80/vuln', extractedResults: ['data'], matcherStatus: true,
        curlCommand: "curl http://target:80/vuln",
      });

      const result = parseNucleiJsonOutput(jsonLine);

      expect(result.findings).toHaveLength(1);
      const f = result.findings[0];
      expect(f.templateId).toBe('CVE-2023-1234');
      expect(f.info.severity).toBe('high'); // Normalized to lowercase
      expect(f.info.author).toEqual(['single-author']); // String → array
      expect(f.info.tags).toEqual(['cve', 'rce']); // Comma-separated → array
      expect(f.info.classification?.cveId).toBe('CVE-2023-1234');
      expect(f.info.classification?.cweId).toEqual(['CWE-79']); // String → array
      expect(f.matchedAt).toBe('http://target:80/vuln');
      expect(f.extractedResults).toEqual(['data']);
      expect(f.curlCommand).toBe('curl http://target:80/vuln');
    });

    it('skips JSON objects without template-id', () => {
      const lines = [
        JSON.stringify({ 'template-id': 'valid-template', info: { name: 'Valid', severity: 'high', tags: ['test'] }, type: 'http', host: 'http://t', 'matched-at': 'http://t', 'extracted-results': [], 'matcher-status': true }),
        JSON.stringify({ info: { name: 'No Template ID' }, type: 'http' }), // Missing template-id
        JSON.stringify({ random: 'data' }), // Not a Nuclei finding at all
      ].join('\n');

      const result = parseNucleiJsonOutput(lines);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].templateId).toBe('valid-template');
    });

    it('collects CVEs from both classification and template-id', () => {
      const lines = [
        JSON.stringify({
          'template-id': 'CVE-2022-1111',
          info: { name: 'Test 1', severity: 'high', tags: ['cve'], classification: { 'cve-id': 'CVE-2022-1111' } },
          type: 'http', host: 'http://t', 'matched-at': 'http://t', 'extracted-results': [], 'matcher-status': true,
        }),
        JSON.stringify({
          'template-id': 'CVE-2022-2222',
          info: { name: 'Test 2', severity: 'high', tags: ['cve'] },
          type: 'http', host: 'http://t', 'matched-at': 'http://t', 'extracted-results': [], 'matcher-status': true,
        }),
      ].join('\n');

      const result = parseNucleiJsonOutput(lines);
      expect(result.cves).toContain('CVE-2022-1111');
      expect(result.cves).toContain('CVE-2022-2222');
    });

    it('identifies exploitable findings (critical + rce tag)', () => {
      const jsonLine = JSON.stringify({
        'template-id': 'rce-test',
        info: { name: 'RCE Test', severity: 'critical', tags: ['rce', 'critical'], author: ['test'] },
        type: 'http', host: 'http://t', 'matched-at': 'http://t/rce', 'extracted-results': ['uid=0(root)'], 'matcher-status': true,
      });

      const result = parseNucleiJsonOutput(jsonLine);
      expect(result.hasExploitableFindings).toBe(true);
    });

    it('does NOT mark info-only findings as exploitable', () => {
      const jsonLine = JSON.stringify({
        'template-id': 'tech-detect',
        info: { name: 'Tech Detection', severity: 'info', tags: ['tech'], author: ['test'] },
        type: 'http', host: 'http://t', 'matched-at': 'http://t', 'extracted-results': [], 'matcher-status': true,
      });

      const result = parseNucleiJsonOutput(jsonLine);
      expect(result.hasExploitableFindings).toBe(false);
    });
  });

  describe('assessNucleiAccessLevel', () => {
    function makeResult(overrides: Partial<NucleiParseResult> = {}): NucleiParseResult {
      return {
        findings: [], stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        cves: [], cwes: [], matchedTemplates: [], hasExploitableFindings: false,
        highestSeverity: 'unknown', allExtractedData: [], curlCommands: [], parseErrors: [],
        ...overrides,
      };
    }

    it('returns none for empty findings', () => {
      const result = assessNucleiAccessLevel(makeResult());
      expect(result.accessLevel).toBe('none');
      expect(result.confidence).toBeGreaterThanOrEqual(80);
    });

    it('detects root_shell from /etc/passwd root entry', () => {
      const result = assessNucleiAccessLevel(makeResult({
        findings: [{ templateId: 'lfi', info: { name: 'LFI', severity: 'critical', tags: ['lfi'], author: [] }, type: 'http', host: '', matchedAt: '', extractedResults: ['root:x:0:0:root:/root:/bin/bash'], matcherStatus: true, timestamp: '' }],
        stats: { total: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 },
        allExtractedData: ['root:x:0:0:root:/root:/bin/bash'],
        hasExploitableFindings: true,
        highestSeverity: 'critical',
      }));
      expect(result.accessLevel).toBe('root_shell');
      expect(result.confidence).toBeGreaterThanOrEqual(80);
    });

    it('detects command_execution from uid output', () => {
      const result = assessNucleiAccessLevel(makeResult({
        findings: [{ templateId: 'rce', info: { name: 'RCE', severity: 'critical', tags: ['rce'], author: [] }, type: 'http', host: '', matchedAt: '', extractedResults: ['uid=1000(www-data)'], matcherStatus: true, timestamp: '' }],
        stats: { total: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 },
        allExtractedData: ['uid=1000(www-data)'],
        hasExploitableFindings: true,
        highestSeverity: 'critical',
      }));
      expect(result.accessLevel).toBe('command_execution');
    });

    it('detects file_read from file system content', () => {
      const result = assessNucleiAccessLevel(makeResult({
        findings: [{ templateId: 'lfi', info: { name: 'LFI', severity: 'high', tags: ['lfi'], author: [] }, type: 'http', host: '', matchedAt: '', extractedResults: ['www-data:x:33:33::/var/www:/bin/bash'], matcherStatus: true, timestamp: '' }],
        stats: { total: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        allExtractedData: ['www-data:x:33:33::/var/www:/bin/bash'],
        hasExploitableFindings: true,
        highestSeverity: 'high',
      }));
      expect(result.accessLevel).toBe('file_read');
    });

    it('detects credential_access from password extraction', () => {
      const result = assessNucleiAccessLevel(makeResult({
        findings: [{ templateId: 'config-leak', info: { name: 'Config Leak', severity: 'high', tags: ['exposure'], author: [] }, type: 'http', host: '', matchedAt: '', extractedResults: ['password=s3cret123'], matcherStatus: true, timestamp: '' }],
        stats: { total: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        allExtractedData: ['password=s3cret123'],
        hasExploitableFindings: true,
        highestSeverity: 'high',
      }));
      expect(result.accessLevel).toBe('credential_access');
    });

    it('detects database_access from SQL output', () => {
      const result = assessNucleiAccessLevel(makeResult({
        findings: [{ templateId: 'sqli', info: { name: 'SQLi', severity: 'critical', tags: ['sqli'], author: [] }, type: 'http', host: '', matchedAt: '', extractedResults: ['SELECT * FROM information_schema.tables'], matcherStatus: true, timestamp: '' }],
        stats: { total: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 },
        allExtractedData: ['SELECT * FROM information_schema.tables'],
        hasExploitableFindings: true,
        highestSeverity: 'critical',
      }));
      expect(result.accessLevel).toBe('database_access');
    });

    it('infers command_execution from rce tag even without extracted data', () => {
      const result = assessNucleiAccessLevel(makeResult({
        findings: [{ templateId: 'rce-test', info: { name: 'RCE', severity: 'high', tags: ['rce'], author: [] }, type: 'http', host: '', matchedAt: '', extractedResults: [], matcherStatus: true, timestamp: '' }],
        stats: { total: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        allExtractedData: [],
        hasExploitableFindings: true,
        highestSeverity: 'high',
      }));
      expect(result.accessLevel).toBe('command_execution');
    });

    it('infers database_access from sqli tag', () => {
      const result = assessNucleiAccessLevel(makeResult({
        findings: [{ templateId: 'sqli-test', info: { name: 'SQLi', severity: 'high', tags: ['sqli'], author: [] }, type: 'http', host: '', matchedAt: '', extractedResults: [], matcherStatus: true, timestamp: '' }],
        stats: { total: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        allExtractedData: [],
        hasExploitableFindings: true,
        highestSeverity: 'high',
      }));
      expect(result.accessLevel).toBe('database_access');
    });

    it('stays at info_disclosure for info-severity findings with no data', () => {
      const result = assessNucleiAccessLevel(makeResult({
        findings: [{ templateId: 'tech-detect', info: { name: 'Tech', severity: 'info', tags: ['tech'], author: [] }, type: 'http', host: '', matchedAt: '', extractedResults: [], matcherStatus: true, timestamp: '' }],
        stats: { total: 1, critical: 0, high: 0, medium: 0, low: 0, info: 1 },
        allExtractedData: [],
        hasExploitableFindings: false,
        highestSeverity: 'info',
      }));
      expect(result.accessLevel).toBe('info_disclosure');
    });

    it('boosts confidence for critical severity with extracted data', () => {
      const withData = assessNucleiAccessLevel(makeResult({
        findings: [{ templateId: 'crit', info: { name: 'Crit', severity: 'critical', tags: ['rce'], author: [] }, type: 'http', host: '', matchedAt: '', extractedResults: ['uid=0(root)'], matcherStatus: true, timestamp: '' }],
        stats: { total: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 },
        allExtractedData: ['uid=0(root)'],
        hasExploitableFindings: true,
        highestSeverity: 'critical',
      }));

      const withoutData = assessNucleiAccessLevel(makeResult({
        findings: [{ templateId: 'crit', info: { name: 'Crit', severity: 'high', tags: ['rce'], author: [] }, type: 'http', host: '', matchedAt: '', extractedResults: [], matcherStatus: true, timestamp: '' }],
        stats: { total: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        allExtractedData: [],
        hasExploitableFindings: true,
        highestSeverity: 'high',
      }));

      expect(withData.confidence).toBeGreaterThan(withoutData.confidence);
    });
  });

  describe('formatNucleiExploitOutput', () => {
    it('returns empty string for no findings', () => {
      const result: NucleiParseResult = {
        findings: [], stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        cves: [], cwes: [], matchedTemplates: [], hasExploitableFindings: false,
        highestSeverity: 'unknown', allExtractedData: [], curlCommands: [], parseErrors: [],
      };
      expect(formatNucleiExploitOutput(result)).toBe('');
    });

    it('formats findings sorted by severity', () => {
      const result: NucleiParseResult = {
        findings: [
          { templateId: 'low-test', info: { name: 'Low', severity: 'low', tags: [], author: [] }, type: 'http', host: '', matchedAt: 'http://t/low', extractedResults: [], matcherStatus: true, timestamp: '' },
          { templateId: 'crit-test', info: { name: 'Critical', severity: 'critical', tags: [], author: [], classification: { cveId: 'CVE-2021-1234', cvssScore: 9.8 } }, type: 'http', host: '', matchedAt: 'http://t/crit', extractedResults: ['root:x:0:0'], matcherStatus: true, timestamp: '', curlCommand: 'curl http://t/crit' },
        ],
        stats: { total: 2, critical: 1, high: 0, medium: 0, low: 1, info: 0 },
        cves: ['CVE-2021-1234'], cwes: [], matchedTemplates: ['crit-test', 'low-test'],
        hasExploitableFindings: true, highestSeverity: 'critical',
        allExtractedData: ['root:x:0:0'], curlCommands: ['curl http://t/crit'], parseErrors: [],
      };

      const output = formatNucleiExploitOutput(result);
      expect(output).toContain('Nuclei Scan Results');
      expect(output).toContain('Total: 2 findings');
      expect(output).toContain('CVEs: CVE-2021-1234');
      expect(output).toContain('[CRITICAL] Critical');
      expect(output).toContain('CVE: CVE-2021-1234');
      expect(output).toContain('CVSS: 9.8');
      expect(output).toContain('Extracted: root:x:0:0');
      expect(output).toContain('Reproduce: curl http://t/crit');
      // Critical finding should appear before Low finding in the output
      // Use the finding format "[SEVERITY] Name (template-id)" to avoid matching the stats header
      const critIdx = output.indexOf('[CRITICAL] Critical (crit-test)');
      const lowIdx = output.indexOf('[LOW] Low (low-test)');
      expect(critIdx).toBeGreaterThan(-1);
      expect(lowIdx).toBeGreaterThan(-1);
      expect(critIdx).toBeLessThan(lowIdx);
    });
  });

  describe('addJsonFlag', () => {
    it('adds -json flag to a basic Nuclei command', () => {
      const cmd = 'nuclei -u http://target:80 -t template.yaml -severity critical,high -timeout 45 -no-color 2>&1 | head -100';
      const result = addJsonFlag(cmd);
      expect(result).toContain('-json');
      expect(result).not.toContain('head -100'); // Should remove head pipe
    });

    it('does not double-add -json if already present', () => {
      const cmd = 'nuclei -u http://target:80 -json -t template.yaml';
      const result = addJsonFlag(cmd);
      expect(result).toBe(cmd);
      const jsonCount = (result.match(/-json/g) || []).length;
      expect(jsonCount).toBe(1);
    });

    it('does not double-add -jsonl if already present', () => {
      const cmd = 'nuclei -u http://target:80 -jsonl -t template.yaml';
      const result = addJsonFlag(cmd);
      expect(result).toBe(cmd);
    });

    it('removes 2>&1 | head -N pipe', () => {
      const cmd = 'nuclei -u http://target:80 -tags sqli -severity critical,high,medium -timeout 45 -no-color 2>&1 | head -100';
      const result = addJsonFlag(cmd);
      expect(result).not.toContain('2>&1');
      expect(result).not.toContain('head');
      expect(result).toContain('-json');
    });

    it('handles command without pipe', () => {
      const cmd = 'nuclei -u http://target:80 -tags sqli -severity critical';
      const result = addJsonFlag(cmd);
      expect(result).toContain('-json');
      expect(result).toContain('-tags sqli');
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §2 — NUCLEI VERIFICATION ENGINE TESTS
// ═══════════════════════════════════════════════════════════════════════

describe('Nuclei Verification Engine', () => {
  describe('adjustVerificationWithNuclei', () => {
    function makeVerification(overrides: Partial<VerificationResult> = {}): VerificationResult {
      return {
        exploitId: 'test-exploit-1',
        status: 'probable_success' as any,
        accessLevel: 'info_disclosure' as AccessLevel,
        confidence: 60,
        explanation: 'LLM exploit output suggests success',
        verificationCommands: [],
        durationMs: 100,
        verifiedAt: Date.now(),
        ...overrides,
      };
    }

    function makeNucleiResult(overrides: Partial<NucleiVerificationResult> = {}): NucleiVerificationResult {
      return {
        confirmed: false,
        confidenceAdjustment: 0,
        nucleiAccessLevel: 'none' as any,
        parseResult: { findings: [], stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, cves: [], cwes: [], matchedTemplates: [], hasExploitableFindings: false, highestSeverity: 'unknown', allExtractedData: [], curlCommands: [], parseErrors: [] },
        summary: 'Test summary',
        durationMs: 500,
        command: 'nuclei -u http://target -json',
        ...overrides,
      };
    }

    it('boosts confidence when Nuclei confirms (+20)', () => {
      const existing = makeVerification({ confidence: 60, status: 'probable_success' as any });
      const nuclei = makeNucleiResult({ confirmed: true, confidenceAdjustment: 20 });

      const adjusted = adjustVerificationWithNuclei(existing, nuclei);
      expect(adjusted.confidence).toBe(80);
      expect(adjusted.status).toBe('confirmed_success');
    });

    it('upgrades status from unverified to confirmed_success', () => {
      const existing = makeVerification({ confidence: 40, status: 'unverified' as any });
      const nuclei = makeNucleiResult({ confirmed: true, confidenceAdjustment: 20 });

      const adjusted = adjustVerificationWithNuclei(existing, nuclei);
      expect(adjusted.status).toBe('confirmed_success');
      expect(adjusted.confidence).toBe(60);
    });

    it('reduces confidence when Nuclei finds nothing (-10)', () => {
      const existing = makeVerification({ confidence: 60, status: 'probable_success' as any });
      const nuclei = makeNucleiResult({ confirmed: false, confidenceAdjustment: -10 });

      const adjusted = adjustVerificationWithNuclei(existing, nuclei);
      expect(adjusted.confidence).toBe(50);
    });

    it('downgrades probable_success to unverified when confidence drops below 40', () => {
      const existing = makeVerification({ confidence: 35, status: 'probable_success' as any });
      const nuclei = makeNucleiResult({ confirmed: false, confidenceAdjustment: -10 });

      const adjusted = adjustVerificationWithNuclei(existing, nuclei);
      expect(adjusted.confidence).toBe(25);
      expect(adjusted.status).toBe('unverified');
    });

    it('upgrades access level when Nuclei finds higher access', () => {
      const existing = makeVerification({ accessLevel: 'info_disclosure' as AccessLevel });
      const nuclei = makeNucleiResult({ confirmed: true, confidenceAdjustment: 20, nucleiAccessLevel: 'command_execution' as any });

      const adjusted = adjustVerificationWithNuclei(existing, nuclei);
      expect(adjusted.accessLevel).toBe('command_execution');
    });

    it('does NOT downgrade access level', () => {
      const existing = makeVerification({ accessLevel: 'user_shell' as AccessLevel });
      const nuclei = makeNucleiResult({ confirmed: true, confidenceAdjustment: 15, nucleiAccessLevel: 'info_disclosure' as any });

      const adjusted = adjustVerificationWithNuclei(existing, nuclei);
      expect(adjusted.accessLevel).toBe('user_shell');
    });

    it('clamps confidence to 0-100 range', () => {
      const highConf = makeVerification({ confidence: 95 });
      const boost = makeNucleiResult({ confirmed: true, confidenceAdjustment: 20 });
      const adjusted1 = adjustVerificationWithNuclei(highConf, boost);
      expect(adjusted1.confidence).toBeLessThanOrEqual(100);

      const lowConf = makeVerification({ confidence: 5, status: 'probable_success' as any });
      const reduce = makeNucleiResult({ confirmed: false, confidenceAdjustment: -10 });
      const adjusted2 = adjustVerificationWithNuclei(lowConf, reduce);
      expect(adjusted2.confidence).toBeGreaterThanOrEqual(0);
    });

    it('appends Nuclei summary to explanation', () => {
      const existing = makeVerification({ explanation: 'Original explanation' });
      const nuclei = makeNucleiResult({ confirmed: true, confidenceAdjustment: 15, summary: 'Nuclei confirmed 3 critical findings' });

      const adjusted = adjustVerificationWithNuclei(existing, nuclei);
      expect(adjusted.explanation).toContain('Original explanation');
      expect(adjusted.explanation).toContain('Nuclei');
    });

    it('handles zero confidence adjustment (no change)', () => {
      const existing = makeVerification({ confidence: 60, status: 'probable_success' as any });
      const nuclei = makeNucleiResult({ confirmed: false, confidenceAdjustment: 0 });

      const adjusted = adjustVerificationWithNuclei(existing, nuclei);
      expect(adjusted.confidence).toBe(60);
      expect(adjusted.status).toBe('probable_success');
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §3 — COOKIE INJECTION TESTS
// ═══════════════════════════════════════════════════════════════════════

describe('Authenticated Scan Cookie Injection', () => {
  describe('extractSessionCookie', () => {
    it('extracts session cookie from confirmedCredentials', () => {
      const asset = {
        confirmedCredentials: [
          { username: 'admin', password: 'pass', service: 'http', port: 80, protocol: 'tcp', source: 'hydra', sessionCookie: 'PHPSESSID=abc123' },
        ],
      };
      const cookie = extractSessionCookie(asset as any);
      expect(cookie).toBe('PHPSESSID=abc123');
    });

    it('extracts session cookie from trainingLabCreds', () => {
      const asset = {
        confirmedCredentials: [
          { username: 'admin', password: 'pass', service: 'http', port: 80, protocol: 'tcp', source: 'hydra' }, // No sessionCookie
        ],
        trainingLabCreds: {
          username: 'admin',
          password: 'password',
          sessionCookie: 'security=low; PHPSESSID=dvwa123',
          loginPath: '/login.php',
        },
      };
      const cookie = extractSessionCookie(asset as any);
      expect(cookie).toBe('security=low; PHPSESSID=dvwa123');
    });

    it('prefers confirmedCredentials over trainingLabCreds', () => {
      const asset = {
        confirmedCredentials: [
          { username: 'admin', password: 'pass', service: 'http', port: 80, protocol: 'tcp', source: 'hydra', sessionCookie: 'CONFIRMED=yes' },
        ],
        trainingLabCreds: {
          username: 'admin',
          password: 'password',
          sessionCookie: 'TRAINING=yes',
        },
      };
      const cookie = extractSessionCookie(asset as any);
      expect(cookie).toBe('CONFIRMED=yes');
    });

    it('returns undefined when no session cookies exist', () => {
      const asset = {
        confirmedCredentials: [
          { username: 'admin', password: 'pass', service: 'ssh', port: 22, protocol: 'tcp', source: 'hydra' },
        ],
      };
      const cookie = extractSessionCookie(asset as any);
      expect(cookie).toBeUndefined();
    });

    it('returns undefined for empty asset', () => {
      expect(extractSessionCookie(undefined)).toBeUndefined();
      expect(extractSessionCookie({})).toBeUndefined();
    });

    it('returns undefined for HTTP credentials without session cookie', () => {
      const asset = {
        confirmedCredentials: [
          { username: 'admin', password: 'pass', service: 'http', port: 80, protocol: 'tcp', source: 'http_form' },
        ],
      };
      const cookie = extractSessionCookie(asset as any);
      expect(cookie).toBeUndefined();
    });

    it('finds session cookie in second credential entry', () => {
      const asset = {
        confirmedCredentials: [
          { username: 'user1', password: 'pass1', service: 'ssh', port: 22, protocol: 'tcp', source: 'hydra' },
          { username: 'admin', password: 'admin', service: 'http', port: 80, protocol: 'tcp', source: 'http_form', sessionCookie: 'sid=second_entry' },
        ],
      };
      const cookie = extractSessionCookie(asset as any);
      expect(cookie).toBe('sid=second_entry');
    });
  });

  describe('buildCookieHeader', () => {
    it('returns raw string as-is', () => {
      expect(buildCookieHeader('PHPSESSID=abc123; security=low')).toBe('PHPSESSID=abc123; security=low');
    });

    it('builds cookie header from structured array', () => {
      const cookies = [
        { name: 'PHPSESSID', value: 'abc123' },
        { name: 'security', value: 'low' },
      ];
      expect(buildCookieHeader(cookies)).toBe('PHPSESSID=abc123; security=low');
    });

    it('handles single cookie', () => {
      expect(buildCookieHeader([{ name: 'sid', value: 'xyz' }])).toBe('sid=xyz');
    });

    it('handles empty array', () => {
      expect(buildCookieHeader([])).toBe('');
    });
  });

  describe('Cookie injection into buildNucleiCommand', () => {
    it('injects cookie into CVE-specific template command', async () => {
      const { buildNucleiCommand } = await import('./lib/exploit-selection-intelligence');
      const result = buildNucleiCommand({
        target: 'http://dvwa.local',
        port: 80,
        cve: 'CVE-2021-41773',
        vulnClass: 'lfi',
        cookie: 'PHPSESSID=abc123; security=low',
      });

      expect(result).not.toBeNull();
      expect(result!.command).toContain('-H "Cookie: PHPSESSID=abc123; security=low"');
    });

    it('injects cookie into vuln-class tag command', async () => {
      const { buildNucleiCommand } = await import('./lib/exploit-selection-intelligence');
      const result = buildNucleiCommand({
        target: 'http://dvwa.local',
        port: 80,
        vulnClass: 'sqli',
        cookie: 'security=low; PHPSESSID=dvwa123',
      });

      expect(result).not.toBeNull();
      expect(result!.command).toContain('-H "Cookie: security=low; PHPSESSID=dvwa123"');
    });

    it('does NOT include Cookie header when cookie is undefined', async () => {
      const { buildNucleiCommand } = await import('./lib/exploit-selection-intelligence');
      const result = buildNucleiCommand({
        target: 'http://target.local',
        port: 80,
        vulnClass: 'xss',
      });

      expect(result).not.toBeNull();
      expect(result!.command).not.toContain('Cookie');
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §4 — INTEGRATION TESTS (orchestration wiring)
// ═══════════════════════════════════════════════════════════════════════

describe('Orchestration Integration', () => {
  it('enhanced-exploit-orchestration imports nuclei-output-parser correctly', async () => {
    const mod = await import('./lib/nuclei-output-parser');
    expect(mod.parseNucleiJsonOutput).toBeDefined();
    expect(mod.assessNucleiAccessLevel).toBeDefined();
    expect(mod.formatNucleiExploitOutput).toBeDefined();
    expect(mod.addJsonFlag).toBeDefined();
  });

  it('enhanced-exploit-orchestration imports nuclei-verification-engine correctly', async () => {
    const mod = await import('./lib/nuclei-verification-engine');
    expect(mod.runNucleiVerification).toBeDefined();
    expect(mod.adjustVerificationWithNuclei).toBeDefined();
    expect(mod.extractSessionCookie).toBeDefined();
    expect(mod.buildCookieHeader).toBeDefined();
  });

  it('parseNucleiJsonOutput handles real-world multi-finding output', () => {
    // Simulate a real Nuclei scan against DVWA with multiple findings
    const realOutput = [
      '[INF] nuclei-engine v3.1.0 (latest)',
      '[INF] Using 50 templates, 0 workflows',
      JSON.stringify({
        'template-id': 'CVE-2021-41773',
        info: { name: 'Apache Path Traversal', author: ['dhiyaneshdk'], tags: ['cve', 'lfi', 'rce'], severity: 'critical', classification: { 'cve-id': 'CVE-2021-41773', 'cvss-score': 9.8 } },
        type: 'http', host: 'http://dvwa:80', 'matched-at': 'http://dvwa:80/cgi-bin/.%2e/etc/passwd',
        'extracted-results': ['root:x:0:0:root:/root:/bin/bash', 'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin'],
        ip: '192.168.1.100', timestamp: '2024-06-15T10:00:00Z', 'matcher-status': true,
        'curl-command': "curl 'http://dvwa:80/cgi-bin/.%2e/etc/passwd'",
      }),
      JSON.stringify({
        'template-id': 'xss-reflected-generic',
        info: { name: 'Reflected XSS', author: ['test'], tags: ['xss', 'reflected'], severity: 'medium' },
        type: 'http', host: 'http://dvwa:80', 'matched-at': 'http://dvwa:80/vulnerabilities/xss_r/?name=<script>alert(1)</script>',
        'extracted-results': [], ip: '192.168.1.100', timestamp: '2024-06-15T10:00:01Z', 'matcher-status': true,
      }),
      JSON.stringify({
        'template-id': 'sqli-error-based',
        info: { name: 'Error-Based SQL Injection', author: ['test'], tags: ['sqli', 'error-based'], severity: 'high' },
        type: 'http', host: 'http://dvwa:80', 'matched-at': "http://dvwa:80/vulnerabilities/sqli/?id=1'",
        'extracted-results': ['You have an error in your SQL syntax'], ip: '192.168.1.100', timestamp: '2024-06-15T10:00:02Z', 'matcher-status': true,
      }),
      '[INF] Found 3 results in 5.2s',
    ].join('\n');

    const result = parseNucleiJsonOutput(realOutput);

    expect(result.findings).toHaveLength(3);
    expect(result.stats.critical).toBe(1);
    expect(result.stats.high).toBe(1);
    expect(result.stats.medium).toBe(1);
    expect(result.cves).toContain('CVE-2021-41773');
    expect(result.hasExploitableFindings).toBe(true);
    expect(result.highestSeverity).toBe('critical');
    expect(result.allExtractedData).toContain('root:x:0:0:root:/root:/bin/bash');

    // Access assessment should detect root shell from passwd extraction
    const access = assessNucleiAccessLevel(result);
    expect(access.accessLevel).toBe('root_shell');
    expect(access.confidence).toBeGreaterThanOrEqual(80);

    // Formatted output should be rich and readable
    const formatted = formatNucleiExploitOutput(result);
    expect(formatted).toContain('Nuclei Scan Results');
    expect(formatted).toContain('[CRITICAL]');
    expect(formatted).toContain('[HIGH]');
    expect(formatted).toContain('[MEDIUM]');
  });
});
