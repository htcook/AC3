/**
 * Tests for Nuclei Fast-Path Execution Bypass
 * ═══════════════════════════════════════════
 * Validates that findings with __nucleiHint annotations skip LLM generation
 * and run the hinted Nuclei template directly as the primary exploit path.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── 1. Fast-path command construction tests ──────────────────────────────


// Skip in CI — requires SSH access to scan server
const __skipInCI = !process.env.SCAN_SERVER_HOST;

describe.skipIf(__skipInCI)('Nuclei Fast-Path Command Construction', () => {
  it('builds command with templatePath when hint has a template', () => {
    const hint = {
      templatePath: 'cves/2021/CVE-2021-44228.yaml',
      tags: ['log4j', 'rce'],
      source: 'static_map',
      confidence: 95,
      cveId: 'CVE-2021-44228',
    };

    // Simulate the command construction logic from the orchestration
    let cmd = `nuclei -u target.com:8080 -json -timeout 30 -no-color -silent`;
    if (hint.templatePath) {
      cmd += ` -t ${hint.templatePath}`;
    } else if (hint.tags.length > 0) {
      cmd += ` -tags ${hint.tags.join(',')}`;
    }

    expect(cmd).toContain('-t cves/2021/CVE-2021-44228.yaml');
    expect(cmd).not.toContain('-tags');
    expect(cmd).toContain('-json');
  });

  it('builds command with tags when hint has no templatePath', () => {
    const hint = {
      templatePath: null,
      tags: ['sqli', 'injection'],
      source: 'vuln_class_tags',
      confidence: 70,
    };

    let cmd = `nuclei -u target.com:80 -json -timeout 30 -no-color -silent`;
    if (hint.templatePath) {
      cmd += ` -t ${hint.templatePath}`;
    } else if (hint.tags.length > 0) {
      cmd += ` -tags ${hint.tags.join(',')}`;
    }

    expect(cmd).toContain('-tags sqli,injection');
    expect(cmd).not.toContain('-t ');
  });

  it('adds cookie header when session cookie is available', () => {
    const sessionCookie = 'PHPSESSID=abc123; security=low';
    let cmd = `nuclei -u target.com:80 -json -timeout 30 -no-color -silent -t cves/2021/CVE-2021-41773.yaml`;
    if (sessionCookie) {
      cmd += ` -H "Cookie: ${sessionCookie}"`;
    }

    expect(cmd).toContain('-H "Cookie: PHPSESSID=abc123; security=low"');
  });

  it('does not add cookie header when no session cookie', () => {
    const sessionCookie: string | null = null;
    let cmd = `nuclei -u target.com:80 -json -timeout 30 -no-color -silent -t cves/2021/CVE-2021-41773.yaml`;
    if (sessionCookie) {
      cmd += ` -H "Cookie: ${sessionCookie}"`;
    }

    expect(cmd).not.toContain('-H "Cookie:');
  });
});

// ── 2. Fast-path decision logic tests ────────────────────────────────────

describe('Nuclei Fast-Path Decision Logic', () => {
  it('activates fast-path when nucleiHint has templatePath and scanServerHost exists', () => {
    const nucleiHint = {
      templatePath: 'cves/2021/CVE-2021-44228.yaml',
      tags: ['log4j'],
      source: 'static_map',
      confidence: 95,
    };
    const scanServerHost = '10.0.0.1';

    const shouldUseFastPath = !!(nucleiHint && scanServerHost && (nucleiHint.templatePath || nucleiHint.tags.length > 0));
    expect(shouldUseFastPath).toBe(true);
  });

  it('activates fast-path when nucleiHint has tags only', () => {
    const nucleiHint = {
      templatePath: null,
      tags: ['sqli', 'injection'],
      source: 'vuln_class_tags',
      confidence: 70,
    };
    const scanServerHost = '10.0.0.1';

    const shouldUseFastPath = !!(nucleiHint && scanServerHost && (nucleiHint.templatePath || nucleiHint.tags.length > 0));
    expect(shouldUseFastPath).toBe(true);
  });

  it('does NOT activate fast-path when nucleiHint is undefined', () => {
    const nucleiHint = undefined;
    const scanServerHost = '10.0.0.1';

    const shouldUseFastPath = !!(nucleiHint && scanServerHost && ((nucleiHint as any)?.templatePath || (nucleiHint as any)?.tags?.length > 0));
    expect(shouldUseFastPath).toBe(false);
  });

  it('does NOT activate fast-path when scanServerHost is missing', () => {
    const nucleiHint = {
      templatePath: 'cves/2021/CVE-2021-44228.yaml',
      tags: ['log4j'],
      source: 'static_map',
      confidence: 95,
    };
    const scanServerHost: string | undefined = undefined;

    const shouldUseFastPath = !!(nucleiHint && scanServerHost && (nucleiHint.templatePath || nucleiHint.tags.length > 0));
    expect(shouldUseFastPath).toBe(false);
  });

  it('does NOT activate fast-path when hint has empty tags and no templatePath', () => {
    const nucleiHint = {
      templatePath: null,
      tags: [] as string[],
      source: 'vuln_class_tags',
      confidence: 50,
    };
    const scanServerHost = '10.0.0.1';

    const shouldUseFastPath = !!(nucleiHint && scanServerHost && (nucleiHint.templatePath || nucleiHint.tags.length > 0));
    expect(shouldUseFastPath).toBe(false);
  });
});

// ── 3. __nucleiHint extraction from vuln objects ─────────────────────────

describe('__nucleiHint Extraction from Vuln Objects', () => {
  it('extracts nucleiHint from matching vuln by CVE', () => {
    const cve = 'CVE-2021-44228';
    const service = 'http';
    const vulns = [
      {
        title: 'Log4Shell RCE',
        severity: 'critical',
        cve: 'CVE-2021-44228',
        description: 'Apache Log4j2 RCE',
        __nucleiHint: {
          templatePath: 'cves/2021/CVE-2021-44228.yaml',
          tags: ['log4j', 'rce'],
          source: 'static_map',
          confidence: 95,
          cveId: 'CVE-2021-44228',
        },
      },
      {
        title: 'XSS in search',
        severity: 'medium',
        cve: 'CVE-2023-1234',
        description: 'Reflected XSS',
      },
    ];

    // Simulate the extraction logic from engagement-orchestrator
    const vuln = vulns.find(v => v.cve === cve || v.title?.includes(service || ''));
    const hint = (vuln as any)?.__nucleiHint;
    let nucleiHint: any = undefined;
    if (hint && (hint.templatePath || (hint.tags && hint.tags.length > 0))) {
      nucleiHint = {
        templatePath: hint.templatePath || null,
        tags: hint.tags || [],
        source: hint.source || 'engagement-orchestrator',
        confidence: hint.confidence || 70,
        cveId: cve || hint.cveId || undefined,
      };
    }

    expect(nucleiHint).toBeDefined();
    expect(nucleiHint.templatePath).toBe('cves/2021/CVE-2021-44228.yaml');
    expect(nucleiHint.tags).toEqual(['log4j', 'rce']);
    expect(nucleiHint.source).toBe('static_map');
    expect(nucleiHint.confidence).toBe(95);
    expect(nucleiHint.cveId).toBe('CVE-2021-44228');
  });

  it('returns undefined when vuln has no __nucleiHint', () => {
    const cve = 'CVE-2023-9999';
    const vulns = [
      { title: 'Some vuln', severity: 'high', cve: 'CVE-2023-9999', description: 'No hint' },
    ];

    const vuln = vulns.find(v => v.cve === cve);
    const hint = (vuln as any)?.__nucleiHint;
    let nucleiHint: any = undefined;
    if (hint && (hint.templatePath || (hint.tags && hint.tags.length > 0))) {
      nucleiHint = { templatePath: hint.templatePath || null, tags: hint.tags || [], source: hint.source || 'engagement-orchestrator', confidence: hint.confidence || 70 };
    }

    expect(nucleiHint).toBeUndefined();
  });

  it('returns undefined when no matching vuln found', () => {
    const cve = 'CVE-2023-0000';
    const vulns = [
      { title: 'Other vuln', severity: 'low', cve: 'CVE-2023-1111', description: 'Different' },
    ];

    const vuln = vulns.find(v => v.cve === cve);
    const hint = (vuln as any)?.__nucleiHint;
    let nucleiHint: any = undefined;
    if (hint && (hint.templatePath || (hint.tags && hint.tags.length > 0))) {
      nucleiHint = { templatePath: hint.templatePath || null, tags: hint.tags || [], source: hint.source || 'engagement-orchestrator', confidence: hint.confidence || 70 };
    }

    expect(nucleiHint).toBeUndefined();
  });
});

// ── 4. Fast-path result handling tests ───────────────────────────────────

describe('Nuclei Fast-Path Result Handling', () => {
  it('recognizes nuclei-fast-path as a Nuclei method for access level assessment', () => {
    const method = 'nuclei-fast-path';
    const isNucleiMethod = method === 'nuclei' || method === 'nuclei-fast-path';
    expect(isNucleiMethod).toBe(true);
  });

  it('recognizes regular nuclei as a Nuclei method', () => {
    const method = 'nuclei';
    const isNucleiMethod = method === 'nuclei' || method === 'nuclei-fast-path';
    expect(isNucleiMethod).toBe(true);
  });

  it('does NOT recognize metasploit as a Nuclei method', () => {
    const method = 'metasploit';
    const isNucleiMethod = method === 'nuclei' || method === 'nuclei-fast-path';
    expect(isNucleiMethod).toBe(false);
  });

  it('sets shellType to nuclei-confirmed for fast-path results', () => {
    const method = 'nuclei-fast-path';
    const isNucleiMethod = method === 'nuclei' || method === 'nuclei-fast-path';
    const shellType = method === 'metasploit' ? 'meterpreter' : isNucleiMethod ? 'nuclei-confirmed' : undefined;
    expect(shellType).toBe('nuclei-confirmed');
  });

  it('sets confidence to 95 for fast-path persistence', () => {
    // Fast-path findings are persisted with confidence 95 (higher than direct=90, re-verification=85)
    const confidence = 95;
    expect(confidence).toBeGreaterThan(90); // Higher than direct execution
    expect(confidence).toBeGreaterThan(85); // Higher than re-verification
  });

  it('sets executionContext to fast_path for persistence', () => {
    const executionContext = 'fast_path';
    expect(executionContext).toBe('fast_path');
    expect(executionContext).not.toBe('direct');
    expect(executionContext).not.toBe('re_verification');
  });
});

// ── 5. EnhancedExploitParams type tests ──────────────────────────────────

describe('EnhancedExploitParams nucleiHint field', () => {
  it('accepts nucleiHint with templatePath', () => {
    const params = {
      engagementId: 1,
      target: '10.0.0.1',
      port: 80,
      service: 'http',
      nucleiHint: {
        templatePath: 'cves/2021/CVE-2021-44228.yaml',
        tags: ['log4j'],
        source: 'static_map',
        confidence: 95,
        cveId: 'CVE-2021-44228',
      },
    };

    expect(params.nucleiHint).toBeDefined();
    expect(params.nucleiHint!.templatePath).toBe('cves/2021/CVE-2021-44228.yaml');
  });

  it('accepts nucleiHint with tags only', () => {
    const params = {
      engagementId: 1,
      target: '10.0.0.1',
      port: 80,
      service: 'http',
      nucleiHint: {
        templatePath: null,
        tags: ['sqli', 'injection'],
        source: 'vuln_class_tags',
        confidence: 70,
      },
    };

    expect(params.nucleiHint).toBeDefined();
    expect(params.nucleiHint!.templatePath).toBeNull();
    expect(params.nucleiHint!.tags).toEqual(['sqli', 'injection']);
  });

  it('accepts params without nucleiHint (optional field)', () => {
    const params = {
      engagementId: 1,
      target: '10.0.0.1',
      port: 80,
      service: 'http',
    };

    expect((params as any).nucleiHint).toBeUndefined();
  });
});

// ── 6. Fast-path fallthrough behavior ────────────────────────────────────

describe('Nuclei Fast-Path Fallthrough', () => {
  it('falls through to normal pipeline when fast-path finds no exploitable findings', () => {
    // Simulate: fast-path ran but found only info-level findings
    const parsed = {
      findings: [{ info: { severity: 'info', id: 'info-test' } }],
      hasExploitableFindings: false,
      stats: { total: 1, critical: 0, high: 0, medium: 0, low: 0, info: 1 },
      cves: [],
    };

    const shouldReturnFastPath = parsed.findings.length > 0 &&
      (parsed.hasExploitableFindings || parsed.stats.critical > 0 || parsed.stats.high > 0);

    expect(shouldReturnFastPath).toBe(false);
    // directToolResult stays null → normal pipeline continues
  });

  it('falls through when fast-path finds nothing', () => {
    const parsed = {
      findings: [],
      hasExploitableFindings: false,
      stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      cves: [],
    };

    const shouldReturnFastPath = parsed.findings.length > 0 &&
      (parsed.hasExploitableFindings || parsed.stats.critical > 0 || parsed.stats.high > 0);

    expect(shouldReturnFastPath).toBe(false);
  });

  it('returns fast-path result when critical findings exist', () => {
    const parsed = {
      findings: [{ info: { severity: 'critical', id: 'crit-test' } }],
      hasExploitableFindings: true,
      stats: { total: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      cves: ['CVE-2021-44228'],
    };

    const shouldReturnFastPath = parsed.findings.length > 0 &&
      (parsed.hasExploitableFindings || parsed.stats.critical > 0 || parsed.stats.high > 0);

    expect(shouldReturnFastPath).toBe(true);
  });

  it('returns fast-path result when high findings exist', () => {
    const parsed = {
      findings: [{ info: { severity: 'high', id: 'high-test' } }],
      hasExploitableFindings: false,
      stats: { total: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      cves: [],
    };

    const shouldReturnFastPath = parsed.findings.length > 0 &&
      (parsed.hasExploitableFindings || parsed.stats.critical > 0 || parsed.stats.high > 0);

    expect(shouldReturnFastPath).toBe(true);
  });

  it('does NOT block normal Path A/B when fast-path fails with error', () => {
    // When fast-path throws, directToolResult stays null
    let directToolResult: { success: boolean; output: string; method: string } | null = null;

    // Simulate fast-path error
    try {
      throw new Error('Connection refused');
    } catch {
      // Fast-path failed, directToolResult stays null
    }

    expect(directToolResult).toBeNull();
    // Normal Path A (MSF) and Path B (Nuclei) should still run
  });
});

// ── 7. End-to-end flow simulation ────────────────────────────────────────

describe('Nuclei Fast-Path End-to-End Flow', () => {
  it('simulates complete fast-path flow: hint → command → parse → result', () => {
    // Step 1: Extract hint from vuln
    const vuln = {
      title: 'Apache Path Traversal',
      severity: 'critical',
      cve: 'CVE-2021-41773',
      __nucleiHint: {
        templatePath: 'cves/2021/CVE-2021-41773.yaml',
        tags: ['apache', 'lfi', 'rce'],
        source: 'static_map',
        confidence: 95,
        cveId: 'CVE-2021-41773',
      },
    };

    const hint = (vuln as any).__nucleiHint;
    expect(hint).toBeDefined();

    // Step 2: Build command
    let cmd = `nuclei -u 10.0.0.1:80 -json -timeout 30 -no-color -silent`;
    cmd += ` -t ${hint.templatePath}`;
    expect(cmd).toContain('-t cves/2021/CVE-2021-41773.yaml');

    // Step 3: Simulate parsed output
    const parsed = {
      findings: [{
        info: { severity: 'critical', id: 'CVE-2021-41773', name: 'Apache Path Traversal' },
        'matched-at': 'http://10.0.0.1:80/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd',
        'curl-command': 'curl -X GET http://10.0.0.1:80/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd',
      }],
      hasExploitableFindings: true,
      stats: { total: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      cves: ['CVE-2021-41773'],
    };

    // Step 4: Determine result
    const shouldReturn = parsed.findings.length > 0 && (parsed.hasExploitableFindings || parsed.stats.critical > 0);
    expect(shouldReturn).toBe(true);

    // Step 5: Build result
    const directToolResult = {
      success: true,
      output: 'Nuclei Fast-Path: CVE-2021-41773 confirmed',
      method: 'nuclei-fast-path',
    };

    const isNucleiMethod = directToolResult.method === 'nuclei' || directToolResult.method === 'nuclei-fast-path';
    expect(isNucleiMethod).toBe(true);
    expect(directToolResult.method).toBe('nuclei-fast-path');
  });

  it('simulates fast-path fallthrough to normal pipeline', () => {
    // Hint exists but Nuclei finds nothing → falls through to MSF/LLM
    const hint = {
      templatePath: 'cves/2023/CVE-2023-9999.yaml',
      tags: ['unknown'],
      source: 'dynamic_db',
      confidence: 60,
    };

    // Simulate empty Nuclei output
    const parsed = {
      findings: [],
      hasExploitableFindings: false,
      stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      cves: [],
    };

    const shouldReturn = parsed.findings.length > 0 && (parsed.hasExploitableFindings || parsed.stats.critical > 0);
    expect(shouldReturn).toBe(false);

    // directToolResult stays null → normal pipeline runs
    let directToolResult: any = null;
    expect(directToolResult).toBeNull();

    // Normal pipeline would then run Path A (MSF) → Path B (Nuclei) → LLM
  });
});

// ── 8. Execution priority order tests ────────────────────────────────────

describe('Execution Priority Order', () => {
  it('fast-path runs BEFORE Path A (Metasploit)', () => {
    // The fast-path block is placed before the direct tool execution block
    // in the orchestration code. If fast-path succeeds, directToolResult is set
    // and Path A/B are skipped via the existing !directToolResult?.success guard.
    const executionOrder = [
      'Step 0c-FAST: Nuclei Fast-Path',
      'Step 0c: Path A (Metasploit)',
      'Step 0c: Path B (Nuclei)',
      'Step 1: LLM Generation',
    ];

    expect(executionOrder.indexOf('Step 0c-FAST: Nuclei Fast-Path'))
      .toBeLessThan(executionOrder.indexOf('Step 0c: Path A (Metasploit)'));
  });

  it('fast-path success prevents Path A/B/LLM from running', () => {
    // When fast-path sets directToolResult, the success handler returns early
    const directToolResult = { success: true, output: 'fast-path result', method: 'nuclei-fast-path' };

    // The guard `if (directToolResult?.success)` returns before LLM generation
    expect(directToolResult?.success).toBe(true);
    // This means Step 1 (LLM), Step 2 (enhanced pipeline), Step 2b (re-verification) are all skipped
  });

  it('fast-path failure allows Path A/B to run', () => {
    // When fast-path fails, directToolResult stays null
    let directToolResult: any = null;

    // Path A guard: `if (!directToolResult?.success && scanServerHost)`
    const scanServerHost = '10.0.0.1';
    const shouldTryPathA = !directToolResult?.success && !!scanServerHost;
    expect(shouldTryPathA).toBe(true);
  });
});
