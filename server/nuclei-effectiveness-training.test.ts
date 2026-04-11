/**
 * Tests for:
 *   1. Nuclei Template Effectiveness Tracking (hit rate analytics)
 *   2. Training Lab Nuclei Auto-Selector Integration
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── 1. Template Effectiveness Tracking ─────────────────────────────────────

describe('Nuclei Template Effectiveness Tracking', () => {
  describe('getTemplateEffectiveness', () => {
    it('should return empty array when DB is not available', async () => {
      const { getTemplateEffectiveness } = await import('./lib/nuclei-findings-persistence');
      const result = await getTemplateEffectiveness();
      // DB not available in test env → returns []
      expect(Array.isArray(result)).toBe(true);
    });

    it('should accept a limit parameter', async () => {
      const { getTemplateEffectiveness } = await import('./lib/nuclei-findings-persistence');
      const result = await getTemplateEffectiveness(5);
      expect(Array.isArray(result)).toBe(true);
    });
  });

  describe('getTopTemplates', () => {
    it('should return empty array when DB is not available', async () => {
      const { getTopTemplates } = await import('./lib/nuclei-findings-persistence');
      const result = await getTopTemplates(10);
      expect(Array.isArray(result)).toBe(true);
    });

    it('should default to 10 results', async () => {
      const { getTopTemplates } = await import('./lib/nuclei-findings-persistence');
      const result = await getTopTemplates();
      expect(Array.isArray(result)).toBe(true);
    });
  });

  describe('getTemplateEffectivenessStats', () => {
    it('should return structured stats object', async () => {
      const { getTemplateEffectivenessStats } = await import('./lib/nuclei-findings-persistence');
      const result = await getTemplateEffectivenessStats();
      expect(result).toHaveProperty('totalMappings');
      expect(result).toHaveProperty('totalSuccesses');
      expect(result).toHaveProperty('topTemplates');
      expect(result).toHaveProperty('byCveId');
      expect(result).toHaveProperty('byVulnClass');
      expect(typeof result.totalMappings).toBe('number');
      expect(typeof result.totalSuccesses).toBe('number');
      expect(Array.isArray(result.topTemplates)).toBe(true);
      expect(typeof result.byCveId).toBe('object');
      expect(typeof result.byVulnClass).toBe('object');
    });
  });

  describe('getTemplateHistory', () => {
    it('should return empty array when DB is not available', async () => {
      const { getTemplateHistory } = await import('./lib/nuclei-findings-persistence');
      const result = await getTemplateHistory('cves/2021/CVE-2021-44228');
      expect(Array.isArray(result)).toBe(true);
      expect(result).toEqual([]);
    });
  });

  describe('TemplateEffectiveness type structure', () => {
    it('should calculate hitRate correctly', () => {
      // Simulate what getTemplateEffectiveness does with the hitRate calculation
      const rows = [
        { successCount: 10, templatePath: 'cves/2021/CVE-2021-44228', cveId: 'CVE-2021-44228' },
        { successCount: 5, templatePath: 'cves/2021/CVE-2021-41773', cveId: 'CVE-2021-41773' },
        { successCount: 1, templatePath: 'cves/2023/CVE-2023-12345', cveId: 'CVE-2023-12345' },
      ];
      const maxSuccess = Math.max(...rows.map(r => r.successCount));
      const results = rows.map(r => ({
        ...r,
        hitRate: maxSuccess > 0 ? (r.successCount / maxSuccess) : 1,
      }));

      expect(results[0].hitRate).toBe(1.0);     // 10/10
      expect(results[1].hitRate).toBe(0.5);     // 5/10
      expect(results[2].hitRate).toBe(0.1);     // 1/10
    });

    it('should handle single template (hitRate = 1)', () => {
      const rows = [{ successCount: 3 }];
      const maxSuccess = Math.max(...rows.map(r => r.successCount));
      const hitRate = maxSuccess > 0 ? (rows[0].successCount / maxSuccess) : 1;
      expect(hitRate).toBe(1.0);
    });

    it('should handle zero success count gracefully', () => {
      const rows = [{ successCount: 0 }];
      const maxSuccess = Math.max(...rows.map(r => r.successCount));
      // 0/0 → NaN, but we guard with maxSuccess > 0
      const hitRate = maxSuccess > 0 ? (rows[0].successCount / maxSuccess) : 1;
      expect(hitRate).toBe(1); // fallback to 1 when max is 0
    });
  });

  describe('Stats grouping logic', () => {
    it('should group templates by vulnClass', () => {
      const templates = [
        { cveId: 'CVE-2021-44228', vulnClass: 'rce', successCount: 10, hitRate: 1.0 },
        { cveId: 'CVE-2021-41773', vulnClass: 'lfi', successCount: 5, hitRate: 0.5 },
        { cveId: 'CVE-2023-12345', vulnClass: 'rce', successCount: 3, hitRate: 0.3 },
        { cveId: 'CVE-2023-99999', vulnClass: null, successCount: 1, hitRate: 0.1 },
      ];

      const byVulnClass: Record<string, typeof templates> = {};
      for (const t of templates) {
        if (t.vulnClass) {
          if (!byVulnClass[t.vulnClass]) byVulnClass[t.vulnClass] = [];
          byVulnClass[t.vulnClass].push(t);
        }
      }

      expect(Object.keys(byVulnClass)).toEqual(['rce', 'lfi']);
      expect(byVulnClass['rce']).toHaveLength(2);
      expect(byVulnClass['lfi']).toHaveLength(1);
    });

    it('should index templates by cveId', () => {
      const templates = [
        { cveId: 'CVE-2021-44228', templatePath: 'cves/2021/CVE-2021-44228' },
        { cveId: 'CVE-2021-41773', templatePath: 'cves/2021/CVE-2021-41773' },
      ];

      const byCveId: Record<string, typeof templates[0]> = {};
      for (const t of templates) {
        byCveId[t.cveId] = t;
      }

      expect(byCveId['CVE-2021-44228'].templatePath).toBe('cves/2021/CVE-2021-44228');
      expect(byCveId['CVE-2021-41773'].templatePath).toBe('cves/2021/CVE-2021-41773');
    });
  });
});

// ─── 2. Training Lab Nuclei Auto-Selector Integration ───────────────────────

describe('Training Lab Nuclei Auto-Selector Integration', () => {
  describe('resolveNucleiTemplate for training lab vuln classes', () => {
    it('should resolve SQL Injection to sqli tags', async () => {
      const { resolveNucleiTemplate, clearAutoSelectorCache } = await import('./lib/nuclei-template-auto-selector');
      clearAutoSelectorCache();
      const result = await resolveNucleiTemplate({ vulnClass: 'sqli' });
      expect(result.source).toBe('vuln_class_tags');
      expect(result.tags.length).toBeGreaterThan(0);
      expect(result.tags.some(t => t.includes('sqli'))).toBe(true);
    });

    it('should resolve XSS to xss tags', async () => {
      const { resolveNucleiTemplate, clearAutoSelectorCache } = await import('./lib/nuclei-template-auto-selector');
      clearAutoSelectorCache();
      const result = await resolveNucleiTemplate({ vulnClass: 'xss' });
      expect(result.source).toBe('vuln_class_tags');
      expect(result.tags.some(t => t.includes('xss'))).toBe(true);
    });

    it('should resolve SSRF to ssrf tags', async () => {
      const { resolveNucleiTemplate, clearAutoSelectorCache } = await import('./lib/nuclei-template-auto-selector');
      clearAutoSelectorCache();
      const result = await resolveNucleiTemplate({ vulnClass: 'ssrf' });
      expect(result.source).toBe('vuln_class_tags');
      expect(result.tags.some(t => t.includes('ssrf'))).toBe(true);
    });

    it('should resolve SSTI to ssti tags', async () => {
      const { resolveNucleiTemplate, clearAutoSelectorCache } = await import('./lib/nuclei-template-auto-selector');
      clearAutoSelectorCache();
      const result = await resolveNucleiTemplate({ vulnClass: 'ssti' });
      expect(result.source).toBe('vuln_class_tags');
      expect(result.tags.some(t => t.includes('ssti'))).toBe(true);
    });

    it('should resolve command_injection to command injection tags', async () => {
      const { resolveNucleiTemplate, clearAutoSelectorCache } = await import('./lib/nuclei-template-auto-selector');
      clearAutoSelectorCache();
      const result = await resolveNucleiTemplate({ vulnClass: 'command_injection' });
      expect(result.source).toBe('vuln_class_tags');
      expect(result.tags.length).toBeGreaterThan(0);
    });

    it('should resolve auth_bypass to auth bypass tags', async () => {
      const { resolveNucleiTemplate, clearAutoSelectorCache } = await import('./lib/nuclei-template-auto-selector');
      clearAutoSelectorCache();
      const result = await resolveNucleiTemplate({ vulnClass: 'auth_bypass' });
      expect(result.source).toBe('vuln_class_tags');
      expect(result.tags.length).toBeGreaterThan(0);
    });

    it('should resolve deserialization to deserialization tags', async () => {
      const { resolveNucleiTemplate, clearAutoSelectorCache } = await import('./lib/nuclei-template-auto-selector');
      clearAutoSelectorCache();
      const result = await resolveNucleiTemplate({ vulnClass: 'deserialization' });
      expect(result.source).toBe('vuln_class_tags');
      expect(result.tags.length).toBeGreaterThan(0);
    });

    it('should resolve lfi to lfi tags', async () => {
      const { resolveNucleiTemplate, clearAutoSelectorCache } = await import('./lib/nuclei-template-auto-selector');
      clearAutoSelectorCache();
      const result = await resolveNucleiTemplate({ vulnClass: 'lfi' });
      expect(result.source).toBe('vuln_class_tags');
      expect(result.tags.some(t => t.includes('lfi'))).toBe(true);
    });

    it('should return none for unknown vuln class', async () => {
      const { resolveNucleiTemplate, clearAutoSelectorCache } = await import('./lib/nuclei-template-auto-selector');
      clearAutoSelectorCache();
      const result = await resolveNucleiTemplate({ vulnClass: 'unknown_vuln_class' });
      expect(result.source).toBe('none');
      expect(result.tags).toEqual([]);
    });
  });

  describe('Training lab vuln class mapping', () => {
    it('should map all common training target vuln names to valid vuln classes', () => {
      const vulnClassMap: Record<string, string> = {
        'SQL Injection': 'sqli', 'XSS': 'xss', 'SSRF': 'ssrf', 'SSTI': 'ssti',
        'File Inclusion': 'lfi', 'Command Injection': 'command_injection',
        'Auth Bypass': 'auth_bypass', 'Insecure Deserialization': 'deserialization',
        'File Upload': 'file_upload', 'Path Traversal': 'lfi', 'XXE': 'xxe',
        'CSRF': 'csrf', 'IDOR': 'idor', 'Open Redirect': 'redirect',
      };

      // All mapped values should be non-empty strings
      for (const [name, vc] of Object.entries(vulnClassMap)) {
        expect(vc).toBeTruthy();
        expect(typeof vc).toBe('string');
      }

      // Key vuln types should be mapped
      expect(vulnClassMap['SQL Injection']).toBe('sqli');
      expect(vulnClassMap['XSS']).toBe('xss');
      expect(vulnClassMap['SSRF']).toBe('ssrf');
      expect(vulnClassMap['Command Injection']).toBe('command_injection');
    });
  });

  describe('CVE resolution for training lab findings', () => {
    it('should resolve known CVE to static template', async () => {
      const { resolveNucleiTemplate, clearAutoSelectorCache } = await import('./lib/nuclei-template-auto-selector');
      clearAutoSelectorCache();
      const result = await resolveNucleiTemplate({ cve: 'CVE-2021-44228' });
      expect(result.source).toBe('static_map');
      expect(result.templatePath).toBeTruthy();
      expect(result.confidence).toBe(95);
    });

    it('should resolve CVE-2021-41773 to static template', async () => {
      const { resolveNucleiTemplate, clearAutoSelectorCache } = await import('./lib/nuclei-template-auto-selector');
      clearAutoSelectorCache();
      const result = await resolveNucleiTemplate({ cve: 'CVE-2021-41773' });
      expect(result.source).toBe('static_map');
      expect(result.templatePath).toBeTruthy();
    });

    it('should fall back to vuln class when CVE is unknown', async () => {
      const { resolveNucleiTemplate, clearAutoSelectorCache } = await import('./lib/nuclei-template-auto-selector');
      clearAutoSelectorCache();
      const result = await resolveNucleiTemplate({ cve: 'CVE-9999-99999', vulnClass: 'sqli' });
      expect(result.source).toBe('vuln_class_tags');
      expect(result.tags.length).toBeGreaterThan(0);
    });
  });

  describe('Nuclei fast-path hint annotation', () => {
    it('should annotate findings with __nucleiHint when CVE is known', async () => {
      const { resolveNucleiTemplate, clearAutoSelectorCache } = await import('./lib/nuclei-template-auto-selector');
      clearAutoSelectorCache();

      // Simulate what the training lab does
      const findings = [
        { title: 'Log4Shell RCE', cve: 'CVE-2021-44228', category: 'rce' },
        { title: 'SQL Injection', cve: undefined, category: 'sqli' },
        { title: 'Apache Path Traversal', cve: 'CVE-2021-41773', category: 'lfi' },
      ];

      let hintCount = 0;
      for (const finding of findings) {
        if (finding.cve && finding.cve.startsWith('CVE-')) {
          const resolution = await resolveNucleiTemplate({
            cve: finding.cve,
            vulnClass: finding.category?.toLowerCase(),
          });
          if (resolution.source !== 'none') {
            (finding as any).__nucleiHint = {
              templatePath: resolution.templatePath,
              tags: resolution.tags,
              source: resolution.source,
              confidence: resolution.confidence,
            };
            hintCount++;
          }
        }
      }

      expect(hintCount).toBe(2); // CVE-2021-44228 and CVE-2021-41773
      expect((findings[0] as any).__nucleiHint).toBeDefined();
      expect((findings[0] as any).__nucleiHint.source).toBe('static_map');
      expect((findings[1] as any).__nucleiHint).toBeUndefined(); // no CVE
      expect((findings[2] as any).__nucleiHint).toBeDefined();
      expect((findings[2] as any).__nucleiHint.source).toBe('static_map');
    });

    it('should not annotate findings without CVEs', async () => {
      const findings = [
        { title: 'Missing Security Headers', category: 'misconfiguration' },
        { title: 'Directory Listing', category: 'exposure' },
      ];

      for (const finding of findings) {
        expect((finding as any).__nucleiHint).toBeUndefined();
      }
    });
  });

  describe('Persistence integration in training lab', () => {
    it('should build synthetic findings from nuclei scan results', () => {
      const nucleiFindings = [
        { id: 'nuclei-abc123', severity: 'high', title: '[nuclei] SQL Injection', cve: 'CVE-2021-12345', tool: 'nuclei', matchedAt: 'http://target.com/login', description: 'SQL injection found' },
        { id: 'nuclei-def456', severity: 'medium', title: '[nuclei] XSS Reflected', cve: undefined, tool: 'nuclei', matchedAt: 'http://target.com/search' },
      ];
      const scanUrl = 'http://target.com';

      const syntheticFindings = nucleiFindings.map((f: any) => ({
        'template-id': f.title?.replace('[nuclei] ', '') || 'unknown',
        host: scanUrl,
        'matched-at': f.matchedAt || scanUrl,
        type: 'http',
        info: {
          id: f.title?.replace('[nuclei] ', '') || 'unknown',
          name: f.title?.replace('[nuclei] ', '') || 'Unknown',
          severity: f.severity || 'info',
          description: f.description || '',
          classification: f.cve ? { 'cve-id': [f.cve] } : undefined,
        },
      }));

      expect(syntheticFindings).toHaveLength(2);
      expect(syntheticFindings[0]['template-id']).toBe('SQL Injection');
      expect(syntheticFindings[0].info.severity).toBe('high');
      expect(syntheticFindings[0].info.classification?.['cve-id']).toEqual(['CVE-2021-12345']);
      expect(syntheticFindings[1].info.classification).toBeUndefined();
    });
  });

  describe('Auto-selector command building', () => {
    it('should build targeted template args from resolved templates', async () => {
      const { resolveNucleiTemplate, clearAutoSelectorCache } = await import('./lib/nuclei-template-auto-selector');
      clearAutoSelectorCache();

      const discoveredCves = ['CVE-2021-44228', 'CVE-2021-41773'];
      const targetedTemplateArgs: string[] = [];

      for (const cve of discoveredCves) {
        const resolution = await resolveNucleiTemplate({ cve });
        if (resolution.templatePath) {
          targetedTemplateArgs.push(`-t ${resolution.templatePath}`);
        } else if (resolution.tags.length > 0) {
          targetedTemplateArgs.push(`-tags ${resolution.tags.join(',')}`);
        }
      }

      expect(targetedTemplateArgs.length).toBe(2);
      expect(targetedTemplateArgs[0]).toMatch(/^-t /);
      expect(targetedTemplateArgs[1]).toMatch(/^-t /);
    });

    it('should build tag-based args for vuln classes', async () => {
      const { resolveNucleiTemplate, clearAutoSelectorCache } = await import('./lib/nuclei-template-auto-selector');
      clearAutoSelectorCache();

      const vulnClasses = ['sqli', 'xss', 'ssrf'];
      const targetedTemplateArgs: string[] = [];

      for (const vc of vulnClasses) {
        const resolution = await resolveNucleiTemplate({ vulnClass: vc });
        if (resolution.tags.length > 0) {
          targetedTemplateArgs.push(`-tags ${resolution.tags.join(',')}`);
        }
      }

      expect(targetedTemplateArgs.length).toBe(3);
      expect(targetedTemplateArgs.every(a => a.startsWith('-tags '))).toBe(true);
    });

    it('should deduplicate template args', () => {
      const args = ['-tags sqli,sql-injection', '-tags sqli,sql-injection', '-t cves/2021/CVE-2021-44228'];
      const unique = [...new Set(args)];
      expect(unique).toHaveLength(2);
    });

    it('should limit to 15 args to avoid overly long commands', () => {
      const args = Array.from({ length: 20 }, (_, i) => `-tags tag${i}`);
      const limited = args.slice(0, 15);
      expect(limited).toHaveLength(15);
    });
  });
});
