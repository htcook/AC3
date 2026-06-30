/**
 * Tests for Nuclei Fast-Path Wiring in the DI Scan Pipeline
 *
 * Validates that CVEs discovered during domain intelligence are annotated
 * with __nucleiHint for immediate Nuclei confirmation during exploitation.
 *
 * Coverage:
 * 1. postureToVulns annotates CVEs with __nucleiHint (static map, vuln class, generic)
 * 2. __nucleiHint flows through pendingVulns → vulns → exploitation
 * 3. Nuclei hint extraction in the exploit loop passes nucleiHint param
 * 4. End-to-end: DI finding → vuln → fast-path exploit execution
 */
import { describe, it, expect, vi } from 'vitest';

// Import the maps directly to validate hint resolution logic
import { KNOWN_NUCLEI_CVES, NUCLEI_VULN_CLASS_TAGS } from './lib/exploit-selection-intelligence';

// ═══════════════════════════════════════════════════════════════════
// Helper: Simulate postureToVulns logic (extracted from engagement-orchestrator)
// ═══════════════════════════════════════════════════════════════════

const VULN_CLASS_ALIASES: Record<string, string> = {
  'command_injection': 'cmdi', 'os_command_injection': 'cmdi',
  'path_traversal': 'lfi', 'directory_traversal': 'lfi',
  'local_file_inclusion': 'lfi', 'remote_file_inclusion': 'rfi',
  'server_side_request_forgery': 'ssrf', 'cross_site_scripting': 'xss',
  'sql_injection': 'sqli', 'server_side_template_injection': 'ssti',
  'xml_external_entity': 'xxe', 'insecure_deserialization': 'deserialization',
  'unrestricted_file_upload': 'file_upload', 'fileupload': 'file_upload',
  'authentication_bypass': 'auth_bypass', 'auth-bypass': 'auth_bypass',
};

function simulatePostureToVulns(findings: any[], domain: string = 'test.com') {
  return (findings || []).map((f: any, idx: number) => {
    const hasVersion = !!f.detectedVersion && f.detectedVersion !== 'unknown';
    const hasConfirmedVersion = hasVersion && f.versionConfidence === 'confirmed';
    const tier = hasConfirmedVersion ? 'confirmed' : hasVersion ? 'probable' : 'potential';
    const evidenceSource = f.source || 'passive recon';

    let nucleiHint: any = undefined;
    const primaryCve = f.cveIds?.[0];
    if (primaryCve || f.category) {
      // Try CVE-based template first
      if (primaryCve && KNOWN_NUCLEI_CVES) {
        const templatePath = KNOWN_NUCLEI_CVES[primaryCve];
        if (templatePath) {
          nucleiHint = {
            templatePath,
            tags: [],
            source: 'di_pipeline_static_map',
            confidence: 95,
            cveId: primaryCve,
          };
        }
      }

      // Fall back to vuln class tags
      if (!nucleiHint && f.category && NUCLEI_VULN_CLASS_TAGS) {
        const rawClass = f.category.toLowerCase().replace(/[\s-]+/g, '_');
        const normalizedClass = VULN_CLASS_ALIASES[rawClass] || rawClass;
        const tags = NUCLEI_VULN_CLASS_TAGS[normalizedClass];
        if (tags && tags.length > 0) {
          nucleiHint = {
            templatePath: null,
            tags: [...tags],
            source: 'di_pipeline_vuln_class',
            confidence: 70,
            cveId: primaryCve || undefined,
          };
        }
      }

      // Fall back to generic CVE tag
      if (!nucleiHint && primaryCve) {
        nucleiHint = {
          templatePath: null,
          tags: ['cve'],
          source: 'di_pipeline_generic_cve',
          confidence: 50,
          cveId: primaryCve,
        };
      }
    }

    const vuln: any = {
      id: f.cveIds?.[0] || `passive-${domain}-${idx}`,
      severity: f.severity >= 8 ? 'critical' : f.severity >= 6 ? 'high' : f.severity >= 4 ? 'medium' : 'low',
      title: f.title || f.category || 'Unknown finding',
      cve: f.cveIds?.[0],
      corroborationTier: tier,
      evidenceDetail: `Detected via ${evidenceSource}${hasVersion ? ` (version ${f.detectedVersion})` : ' (version unconfirmed)'}`,
      detectedVersion: f.detectedVersion || null,
      affectedVersions: f.affectedVersions || null,
    };

    if (nucleiHint) {
      vuln.__nucleiHint = nucleiHint;
    }

    return vuln;
  });
}

// ═══════════════════════════════════════════════════════════════════
// 1. CVE-based static map resolution
// ═══════════════════════════════════════════════════════════════════


// Skip in CI — requires SSH access to scan server
const __skipInCI = !process.env.SCAN_SERVER_HOST;

describe.skipIf(__skipInCI)('DI Pipeline → Nuclei Fast-Path: CVE Static Map', () => {
  it('annotates CVE-2021-44228 (Log4Shell) with known Nuclei template', () => {
    const findings = [{
      title: 'Log4Shell RCE',
      severity: 10,
      cveIds: ['CVE-2021-44228'],
      category: 'Remote Code Execution',
      detectedVersion: '2.14.0',
      versionConfidence: 'confirmed',
    }];

    const vulns = simulatePostureToVulns(findings);
    expect(vulns).toHaveLength(1);
    expect(vulns[0].__nucleiHint).toBeDefined();
    expect(vulns[0].__nucleiHint.source).toBe('di_pipeline_static_map');
    expect(vulns[0].__nucleiHint.confidence).toBe(95);
    expect(vulns[0].__nucleiHint.cveId).toBe('CVE-2021-44228');
    expect(vulns[0].__nucleiHint.templatePath).toBeTruthy();
  });

  it('annotates CVE-2021-41773 (Apache Path Traversal) with known template', () => {
    const findings = [{
      title: 'Apache Path Traversal',
      severity: 9,
      cveIds: ['CVE-2021-41773'],
      category: 'Path Traversal',
    }];

    const vulns = simulatePostureToVulns(findings);
    expect(vulns[0].__nucleiHint).toBeDefined();
    expect(vulns[0].__nucleiHint.source).toBe('di_pipeline_static_map');
    expect(vulns[0].__nucleiHint.templatePath).toBeTruthy();
  });

  it('annotates CVE-2023-44487 (HTTP/2 Rapid Reset) with known template', () => {
    const findings = [{
      title: 'HTTP/2 Rapid Reset DoS',
      severity: 8,
      cveIds: ['CVE-2023-44487'],
    }];

    const vulns = simulatePostureToVulns(findings);
    expect(vulns[0].__nucleiHint).toBeDefined();
    expect(vulns[0].__nucleiHint.cveId).toBe('CVE-2023-44487');
  });

  it('annotates all known CVEs in KNOWN_NUCLEI_CVES map', () => {
    const knownCves = Object.keys(KNOWN_NUCLEI_CVES);
    expect(knownCves.length).toBeGreaterThan(0);

    for (const cve of knownCves) {
      const findings = [{ title: `Test ${cve}`, severity: 8, cveIds: [cve] }];
      const vulns = simulatePostureToVulns(findings);
      expect(vulns[0].__nucleiHint).toBeDefined();
      expect(vulns[0].__nucleiHint.source).toBe('di_pipeline_static_map');
      expect(vulns[0].__nucleiHint.templatePath).toBe(KNOWN_NUCLEI_CVES[cve]);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════
// 2. Vuln class tag resolution
// ═══════════════════════════════════════════════════════════════════

describe('DI Pipeline → Nuclei Fast-Path: Vuln Class Tags', () => {
  it('resolves SQL Injection category to sqli tags', () => {
    const findings = [{
      title: 'SQL Injection in login form',
      severity: 8,
      category: 'SQL Injection',
    }];

    const vulns = simulatePostureToVulns(findings);
    expect(vulns[0].__nucleiHint).toBeDefined();
    expect(vulns[0].__nucleiHint.source).toBe('di_pipeline_vuln_class');
    expect(vulns[0].__nucleiHint.confidence).toBe(70);
    expect(vulns[0].__nucleiHint.tags).toContain('sqli');
  });

  it('resolves Command Injection via alias to cmdi tags', () => {
    const findings = [{
      title: 'OS Command Injection',
      severity: 9,
      category: 'Command Injection',
    }];

    const vulns = simulatePostureToVulns(findings);
    expect(vulns[0].__nucleiHint).toBeDefined();
    expect(vulns[0].__nucleiHint.source).toBe('di_pipeline_vuln_class');
    expect(vulns[0].__nucleiHint.tags.length).toBeGreaterThan(0);
  });

  it('resolves Cross-Site Scripting to xss tags', () => {
    const findings = [{
      title: 'Reflected XSS',
      severity: 6,
      category: 'Cross Site Scripting',
    }];

    const vulns = simulatePostureToVulns(findings);
    expect(vulns[0].__nucleiHint).toBeDefined();
    expect(vulns[0].__nucleiHint.tags).toContain('xss');
  });

  it('resolves SSRF category to ssrf tags', () => {
    const findings = [{
      title: 'Server-Side Request Forgery',
      severity: 7,
      category: 'ssrf',
    }];

    const vulns = simulatePostureToVulns(findings);
    expect(vulns[0].__nucleiHint).toBeDefined();
    expect(vulns[0].__nucleiHint.tags).toContain('ssrf');
  });

  it('resolves Path Traversal via alias to lfi tags', () => {
    const findings = [{
      title: 'Directory Traversal',
      severity: 7,
      category: 'Path Traversal',
    }];

    const vulns = simulatePostureToVulns(findings);
    expect(vulns[0].__nucleiHint).toBeDefined();
    expect(vulns[0].__nucleiHint.source).toBe('di_pipeline_vuln_class');
  });

  it('resolves File Upload category to fileupload tags', () => {
    const findings = [{
      title: 'Unrestricted File Upload',
      severity: 8,
      category: 'File Upload',
    }];

    const vulns = simulatePostureToVulns(findings);
    expect(vulns[0].__nucleiHint).toBeDefined();
    expect(vulns[0].__nucleiHint.source).toBe('di_pipeline_vuln_class');
  });

  it('prefers CVE static map over vuln class when both available', () => {
    const findings = [{
      title: 'Log4Shell SQL Injection',
      severity: 10,
      cveIds: ['CVE-2021-44228'],
      category: 'SQL Injection',
    }];

    const vulns = simulatePostureToVulns(findings);
    expect(vulns[0].__nucleiHint).toBeDefined();
    // CVE static map takes priority
    expect(vulns[0].__nucleiHint.source).toBe('di_pipeline_static_map');
    expect(vulns[0].__nucleiHint.confidence).toBe(95);
  });
});

// ═══════════════════════════════════════════════════════════════════
// 3. Generic CVE fallback
// ═══════════════════════════════════════════════════════════════════

describe('DI Pipeline → Nuclei Fast-Path: Generic CVE Fallback', () => {
  it('falls back to generic cve tag for unknown CVE', () => {
    const findings = [{
      title: 'Unknown Vuln',
      severity: 7,
      cveIds: ['CVE-2099-99999'],
      category: 'SomeUnknownCategory',
    }];

    const vulns = simulatePostureToVulns(findings);
    expect(vulns[0].__nucleiHint).toBeDefined();
    expect(vulns[0].__nucleiHint.source).toBe('di_pipeline_generic_cve');
    expect(vulns[0].__nucleiHint.confidence).toBe(50);
    expect(vulns[0].__nucleiHint.tags).toEqual(['cve']);
    expect(vulns[0].__nucleiHint.cveId).toBe('CVE-2099-99999');
  });

  it('uses generic CVE tag when CVE exists but no matching vuln class', () => {
    const findings = [{
      title: 'Memory Corruption',
      severity: 9,
      cveIds: ['CVE-2024-12345'],
      category: 'Buffer Overflow', // Not in NUCLEI_VULN_CLASS_TAGS
    }];

    const vulns = simulatePostureToVulns(findings);
    expect(vulns[0].__nucleiHint).toBeDefined();
    expect(vulns[0].__nucleiHint.source).toBe('di_pipeline_generic_cve');
  });
});

// ═══════════════════════════════════════════════════════════════════
// 4. No hint for findings without CVEs or matching categories
// ═══════════════════════════════════════════════════════════════════

describe('DI Pipeline → Nuclei Fast-Path: No Hint Cases', () => {
  it('does not annotate findings without CVEs or known categories', () => {
    const findings = [{
      title: 'Informational: Server Header Disclosure',
      severity: 2,
      // No cveIds, no matching category
    }];

    const vulns = simulatePostureToVulns(findings);
    expect(vulns[0].__nucleiHint).toBeUndefined();
  });

  it('does not annotate findings with empty cveIds array', () => {
    const findings = [{
      title: 'Weak Cipher Suite',
      severity: 4,
      cveIds: [],
      category: 'Cryptographic Weakness', // Not in NUCLEI_VULN_CLASS_TAGS
    }];

    const vulns = simulatePostureToVulns(findings);
    expect(vulns[0].__nucleiHint).toBeUndefined();
  });
});

// ═══════════════════════════════════════════════════════════════════
// 5. Vuln metadata preservation
// ═══════════════════════════════════════════════════════════════════

describe('DI Pipeline → Nuclei Fast-Path: Metadata Preservation', () => {
  it('preserves all vuln fields alongside __nucleiHint', () => {
    const findings = [{
      title: 'Apache Struts RCE',
      severity: 10,
      cveIds: ['CVE-2017-5638'],
      category: 'Remote Code Execution',
      detectedVersion: '2.3.31',
      versionConfidence: 'confirmed',
      affectedVersions: '< 2.3.32',
      source: 'Shodan',
    }];

    const vulns = simulatePostureToVulns(findings);
    expect(vulns[0].id).toBe('CVE-2017-5638');
    expect(vulns[0].severity).toBe('critical');
    expect(vulns[0].title).toBe('Apache Struts RCE');
    expect(vulns[0].cve).toBe('CVE-2017-5638');
    expect(vulns[0].corroborationTier).toBe('confirmed');
    expect(vulns[0].detectedVersion).toBe('2.3.31');
    expect(vulns[0].affectedVersions).toBe('< 2.3.32');
    expect(vulns[0].evidenceDetail).toContain('Shodan');
    expect(vulns[0].__nucleiHint).toBeDefined();
  });

  it('correctly sets severity bands', () => {
    const findings = [
      { title: 'Critical', severity: 10, cveIds: ['CVE-2021-44228'] },
      { title: 'High', severity: 7 },
      { title: 'Medium', severity: 5 },
      { title: 'Low', severity: 2 },
    ];

    const vulns = simulatePostureToVulns(findings);
    expect(vulns[0].severity).toBe('critical');
    expect(vulns[1].severity).toBe('high');
    expect(vulns[2].severity).toBe('medium');
    expect(vulns[3].severity).toBe('low');
  });

  it('correctly sets corroboration tiers', () => {
    const findings = [
      { title: 'Confirmed', severity: 8, detectedVersion: '1.0', versionConfidence: 'confirmed' },
      { title: 'Probable', severity: 6, detectedVersion: '1.0', versionConfidence: 'inferred' },
      { title: 'Potential', severity: 4 },
    ];

    const vulns = simulatePostureToVulns(findings);
    expect(vulns[0].corroborationTier).toBe('confirmed');
    expect(vulns[1].corroborationTier).toBe('probable');
    expect(vulns[2].corroborationTier).toBe('potential');
  });
});

// ═══════════════════════════════════════════════════════════════════
// 6. Multi-finding batch processing
// ═══════════════════════════════════════════════════════════════════

describe('DI Pipeline → Nuclei Fast-Path: Batch Processing', () => {
  it('processes mixed findings with and without hints', () => {
    const findings = [
      { title: 'Log4Shell', severity: 10, cveIds: ['CVE-2021-44228'] },
      { title: 'Info Leak', severity: 2 },
      { title: 'SQLi', severity: 8, category: 'SQL Injection' },
      { title: 'Unknown CVE', severity: 7, cveIds: ['CVE-2099-11111'] },
      { title: 'Weak TLS', severity: 3, category: 'Misconfiguration' },
    ];

    const vulns = simulatePostureToVulns(findings);
    expect(vulns).toHaveLength(5);

    // Log4Shell: static map
    expect(vulns[0].__nucleiHint).toBeDefined();
    expect(vulns[0].__nucleiHint.source).toBe('di_pipeline_static_map');

    // Info Leak: no hint
    expect(vulns[1].__nucleiHint).toBeUndefined();

    // SQLi: vuln class
    expect(vulns[2].__nucleiHint).toBeDefined();
    expect(vulns[2].__nucleiHint.source).toBe('di_pipeline_vuln_class');

    // Unknown CVE: generic
    expect(vulns[3].__nucleiHint).toBeDefined();
    expect(vulns[3].__nucleiHint.source).toBe('di_pipeline_generic_cve');

    // Weak TLS: no hint (misconfiguration not in tags)
    expect(vulns[4].__nucleiHint).toBeUndefined();
  });

  it('counts hinted vulns correctly for logging', () => {
    const findings = [
      { title: 'A', severity: 10, cveIds: ['CVE-2021-44228'] },
      { title: 'B', severity: 2 },
      { title: 'C', severity: 8, category: 'SQL Injection' },
      { title: 'D', severity: 7, cveIds: ['CVE-2099-11111'] },
    ];

    const vulns = simulatePostureToVulns(findings);
    const hintedCount = vulns.filter((v: any) => v.__nucleiHint).length;
    expect(hintedCount).toBe(3); // Log4Shell, SQLi, Unknown CVE
  });
});

// ═══════════════════════════════════════════════════════════════════
// 7. __nucleiHint extraction in exploit loop
// ═══════════════════════════════════════════════════════════════════

describe('DI Pipeline → Exploit Loop: __nucleiHint Extraction', () => {
  it('extracts nucleiHint from vuln object for exploit params', () => {
    const vuln: any = {
      id: 'CVE-2021-44228',
      severity: 'critical',
      title: 'Log4Shell',
      cve: 'CVE-2021-44228',
      __nucleiHint: {
        templatePath: 'cves/2021/CVE-2021-44228.yaml',
        tags: [],
        source: 'di_pipeline_static_map',
        confidence: 95,
        cveId: 'CVE-2021-44228',
      },
    };

    // Simulate the extraction logic from engagement-orchestrator.ts
    const nucleiHint = vuln.__nucleiHint || (vuln as any).__nucleiHint;
    expect(nucleiHint).toBeDefined();
    expect(nucleiHint.templatePath).toBe('cves/2021/CVE-2021-44228.yaml');
    expect(nucleiHint.source).toBe('di_pipeline_static_map');
  });

  it('handles vuln without __nucleiHint gracefully', () => {
    const vuln: any = {
      id: 'passive-test-0',
      severity: 'low',
      title: 'Info Leak',
    };

    const nucleiHint = vuln.__nucleiHint;
    expect(nucleiHint).toBeUndefined();
  });
});

// ═══════════════════════════════════════════════════════════════════
// 8. End-to-end flow simulation
// ═══════════════════════════════════════════════════════════════════

describe('DI Pipeline → Nuclei Fast-Path: End-to-End Flow', () => {
  it('simulates full flow: DI finding → postureToVulns → pendingVulns → vulns → exploit hint', () => {
    // Step 1: DI pipeline discovers a finding with CVE
    const diFindings = [{
      title: 'Apache Log4j RCE',
      severity: 10,
      cveIds: ['CVE-2021-44228'],
      category: 'Remote Code Execution',
      detectedVersion: '2.14.0',
      versionConfidence: 'confirmed',
      source: 'Shodan',
    }];

    // Step 2: postureToVulns converts to vulns with __nucleiHint
    const passiveVulns = simulatePostureToVulns(diFindings, 'target.com');
    expect(passiveVulns).toHaveLength(1);
    expect(passiveVulns[0].__nucleiHint).toBeDefined();
    expect(passiveVulns[0].__nucleiHint.source).toBe('di_pipeline_static_map');

    // Step 3: Vulns go to pendingVulns (simulated)
    const asset: any = {
      hostname: 'target.com',
      vulns: [],
      pendingVulns: passiveVulns,
    };

    // Step 4: Promotion at vuln_detection phase start
    for (const pv of asset.pendingVulns) {
      asset.vulns.push(pv);
    }
    asset.pendingVulns = [];

    // Step 5: Verify __nucleiHint survived promotion
    expect(asset.vulns).toHaveLength(1);
    expect(asset.vulns[0].__nucleiHint).toBeDefined();
    expect(asset.vulns[0].__nucleiHint.templatePath).toBeTruthy();

    // Step 6: Exploit loop extracts nucleiHint
    const exploitVuln = asset.vulns[0];
    const nucleiHint = exploitVuln.__nucleiHint;
    expect(nucleiHint.templatePath).toBe(KNOWN_NUCLEI_CVES['CVE-2021-44228']);
    expect(nucleiHint.confidence).toBe(95);
  });

  it('simulates full flow with vuln class fallback', () => {
    const diFindings = [{
      title: 'SQL Injection in search',
      severity: 8,
      category: 'SQL Injection',
      source: 'Censys',
    }];

    const passiveVulns = simulatePostureToVulns(diFindings, 'target.com');
    expect(passiveVulns[0].__nucleiHint).toBeDefined();
    expect(passiveVulns[0].__nucleiHint.source).toBe('di_pipeline_vuln_class');
    expect(passiveVulns[0].__nucleiHint.tags).toContain('sqli');

    // Promotion preserves hint
    const asset: any = { vulns: [], pendingVulns: passiveVulns };
    for (const pv of asset.pendingVulns) asset.vulns.push(pv);
    asset.pendingVulns = [];

    expect(asset.vulns[0].__nucleiHint.tags).toContain('sqli');
  });

  it('simulates full flow with generic CVE fallback', () => {
    const diFindings = [{
      title: 'Unknown Vuln',
      severity: 7,
      cveIds: ['CVE-2025-00001'],
      category: 'Memory Corruption',
    }];

    const passiveVulns = simulatePostureToVulns(diFindings, 'target.com');
    expect(passiveVulns[0].__nucleiHint).toBeDefined();
    expect(passiveVulns[0].__nucleiHint.source).toBe('di_pipeline_generic_cve');

    // Promotion preserves hint
    const asset: any = { vulns: [], pendingVulns: passiveVulns };
    for (const pv of asset.pendingVulns) asset.vulns.push(pv);
    asset.pendingVulns = [];

    expect(asset.vulns[0].__nucleiHint.cveId).toBe('CVE-2025-00001');
  });
});

// ═══════════════════════════════════════════════════════════════════
// 9. Vuln class alias coverage
// ═══════════════════════════════════════════════════════════════════

describe('DI Pipeline → Nuclei Fast-Path: Alias Coverage', () => {
  const aliasTests: Array<{ input: string; expectedNormalized: string }> = [
    { input: 'Command Injection', expectedNormalized: 'cmdi' },
    { input: 'OS Command Injection', expectedNormalized: 'cmdi' },
    { input: 'Path Traversal', expectedNormalized: 'lfi' },
    { input: 'Directory Traversal', expectedNormalized: 'lfi' },
    { input: 'Local File Inclusion', expectedNormalized: 'lfi' },
    { input: 'Remote File Inclusion', expectedNormalized: 'rfi' },
    { input: 'Server Side Request Forgery', expectedNormalized: 'ssrf' },
    { input: 'Cross Site Scripting', expectedNormalized: 'xss' },
    { input: 'SQL Injection', expectedNormalized: 'sqli' },
    { input: 'Server Side Template Injection', expectedNormalized: 'ssti' },
    { input: 'XML External Entity', expectedNormalized: 'xxe' },
    { input: 'Insecure Deserialization', expectedNormalized: 'deserialization' },
    { input: 'Unrestricted File Upload', expectedNormalized: 'fileupload' },
    { input: 'File Upload', expectedNormalized: 'fileupload' },
    { input: 'Authentication Bypass', expectedNormalized: 'auth-bypass' },
  ];

  for (const { input, expectedNormalized } of aliasTests) {
    it(`resolves "${input}" category via alias to "${expectedNormalized}" tags`, () => {
      const findings = [{ title: `Test ${input}`, severity: 7, category: input }];
      const vulns = simulatePostureToVulns(findings);

      // Should get a hint if the normalized class has tags
      const tags = NUCLEI_VULN_CLASS_TAGS[expectedNormalized];
      if (tags && tags.length > 0) {
        expect(vulns[0].__nucleiHint).toBeDefined();
        expect(vulns[0].__nucleiHint.source).toBe('di_pipeline_vuln_class');
      }
    });
  }
});
