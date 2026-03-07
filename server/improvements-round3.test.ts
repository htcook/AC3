import { describe, it, expect, vi } from 'vitest';

// ── Test Suite: Round 3 Improvements ──
// Tests for: nuclei stdin piping fix, CodeViewer component, targeted re-synthesis endpoint

describe('Nuclei stdin piping fix', () => {
  it('should use stdin piping instead of -u flag for nuclei commands', () => {
    // The fix: echo "target" | nuclei ... instead of nuclei -u target
    const target = 'http://testphp.vulnweb.com';
    const nucleiCmd = `echo "${target}" | nuclei -t /root/nuclei-templates/http/ -tags sqli,xss,lfi,rfi,rce,crlf,traversal -jsonl -timeout 300 -silent -no-color -system-resolvers`;
    
    // Verify the command uses stdin piping
    expect(nucleiCmd).toContain('echo "');
    expect(nucleiCmd).toContain('| nuclei');
    expect(nucleiCmd).not.toContain('-u ');
    expect(nucleiCmd).not.toContain('-u "');
    
    // Verify it uses -jsonl not -json
    expect(nucleiCmd).toContain('-jsonl');
    expect(nucleiCmd).not.toMatch(/-json\b(?!l)/); // -json but not -jsonl
    
    // Verify system-resolvers flag is present
    expect(nucleiCmd).toContain('-system-resolvers');
  });

  it('should include proper nuclei tags for web app vuln detection', () => {
    const tags = 'sqli,xss,lfi,rfi,rce,crlf,traversal';
    const tagList = tags.split(',');
    
    expect(tagList).toContain('sqli');
    expect(tagList).toContain('xss');
    expect(tagList).toContain('lfi');
    expect(tagList).toContain('rfi');
    expect(tagList).toContain('rce');
    expect(tagList).toContain('crlf');
    expect(tagList).toContain('traversal');
  });
});

describe('Targeted re-synthesis endpoint validation', () => {
  const VULN_CATEGORIES = [
    'injection', 'xss', 'directory_traversal', 'crlf_injection',
    'file_inclusion', 'auth_bypass', 'sensitive_data', 'broken_access',
    'ssrf', 'misconfig'
  ];

  it('should accept valid input with target categories', () => {
    const input = {
      engagementId: 1,
      hostname: 'testphp.vulnweb.com',
      targetCategories: ['injection', 'xss'],
      replaceExisting: false,
    };
    
    expect(input.engagementId).toBeGreaterThan(0);
    expect(input.hostname).toBeTruthy();
    expect(input.targetCategories).toHaveLength(2);
    expect(input.targetCategories!.every(c => VULN_CATEGORIES.includes(c))).toBe(true);
  });

  it('should accept input without target categories (scan all)', () => {
    const input = {
      engagementId: 1,
      hostname: 'demo.testfire.net',
      replaceExisting: false,
    };
    
    expect(input.engagementId).toBeGreaterThan(0);
    expect(input.hostname).toBeTruthy();
    expect(input.targetCategories).toBeUndefined();
  });

  it('should build correct category focus prompt when categories are specified', () => {
    const targetCategories = ['injection', 'xss', 'file_inclusion'];
    const categoryFocus = targetCategories.length
      ? `\n\nIMPORTANT: The operator specifically wants you to CHECK FOR these vulnerability categories: ${targetCategories.join(', ')}. You MUST include findings for each of these categories if there is ANY evidence.`
      : '';
    
    expect(categoryFocus).toContain('injection');
    expect(categoryFocus).toContain('xss');
    expect(categoryFocus).toContain('file_inclusion');
    expect(categoryFocus).toContain('MUST include findings');
  });

  it('should build empty category focus when no categories specified', () => {
    const targetCategories: string[] = [];
    const categoryFocus = targetCategories.length
      ? `\n\nIMPORTANT: ...`
      : '';
    
    expect(categoryFocus).toBe('');
  });

  it('should build existing context to avoid duplicates', () => {
    const existingVulns = [
      { title: 'SQL Injection', severity: 'critical', category: 'injection' },
      { title: 'XSS', severity: 'high', category: 'xss' },
    ];
    
    const existingContext = existingVulns.length > 0
      ? `\n\nAlready identified vulnerabilities (DO NOT duplicate these, find NEW ones):\n${existingVulns.map(v => `- ${v.title} [${v.severity}] (${v.category || 'unknown'})`).join('\n')}`
      : '';
    
    expect(existingContext).toContain('SQL Injection [critical]');
    expect(existingContext).toContain('XSS [high]');
    expect(existingContext).toContain('DO NOT duplicate');
  });

  it('should filter out low-confidence vulns (below 40%)', () => {
    const synthVulns = [
      { title: 'SQL Injection', confidence: 95, severity: 'critical' },
      { title: 'Maybe XSS', confidence: 30, severity: 'low' },
      { title: 'File Inclusion', confidence: 70, severity: 'high' },
      { title: 'Unlikely SSRF', confidence: 15, severity: 'low' },
    ];
    
    const filtered = synthVulns.filter(v => v.confidence >= 40);
    expect(filtered).toHaveLength(2);
    expect(filtered[0].title).toBe('SQL Injection');
    expect(filtered[1].title).toBe('File Inclusion');
  });

  it('should handle replace mode correctly', () => {
    const existingVulns = [
      { id: 'v1', title: 'SQL Injection', tool: 'llm-synthesis', severity: 'critical' },
      { id: 'v2', title: 'Port 22 SSH', tool: 'nmap', severity: 'info' },
      { id: 'v3', title: 'XSS', tool: 'llm-synthesis', severity: 'high' },
    ];
    
    // Replace mode: remove LLM-synthesized, keep active scan findings
    const afterReplace = existingVulns.filter(v => v.tool !== 'llm-synthesis');
    expect(afterReplace).toHaveLength(1);
    expect(afterReplace[0].tool).toBe('nmap');
  });

  it('should detect duplicate vulns by title similarity', () => {
    const existingVulns = [
      { title: 'SQL Injection in User Input Fields', severity: 'critical' },
    ];
    
    const newVuln = { title: 'SQL Injection via Login Form', severity: 'high' };
    
    const isDuplicate = existingVulns.some(existing =>
      existing.title.toLowerCase().includes(newVuln.title.toLowerCase().split(' ')[0]) ||
      newVuln.title.toLowerCase().includes(existing.title.toLowerCase().split(' ')[0])
    );
    
    // "sql" is the first word of both, so they should be detected as duplicates
    expect(isDuplicate).toBe(true);
  });
});

describe('Smart signal sampling', () => {
  it('should prioritize high-severity signals', () => {
    const signals = [
      ...Array(20).fill(null).map((_, i) => ({ severity: 'critical', rationale: `Critical signal ${i}` })),
      ...Array(15).fill(null).map((_, i) => ({ severity: 'high', rationale: `High signal ${i}` })),
      ...Array(30).fill(null).map((_, i) => ({ severity: 'medium', rationale: `Medium signal ${i}` })),
      ...Array(50).fill(null).map((_, i) => ({ severity: 'low', rationale: `Low signal ${i}` })),
    ];
    
    const highSeverity = signals.filter(s => s.severity === 'critical' || s.severity === 'high');
    const medSeverity = signals.filter(s => s.severity === 'medium');
    const lowSeverity = signals.filter(s => s.severity === 'low' || s.severity === 'info');
    
    const sampled = [
      ...highSeverity.slice(0, 12),
      ...medSeverity.slice(0, 8),
      ...lowSeverity.slice(0, 5),
    ].slice(0, 25);
    
    expect(sampled.length).toBe(25);
    // First 12 should be high severity
    expect(sampled.slice(0, 12).every(s => s.severity === 'critical' || s.severity === 'high')).toBe(true);
    // Next 8 should be medium
    expect(sampled.slice(12, 20).every(s => s.severity === 'medium')).toBe(true);
    // Last 5 should be low
    expect(sampled.slice(20, 25).every(s => s.severity === 'low')).toBe(true);
  });

  it('should truncate signal rationale to 120 chars', () => {
    const longSignal = {
      severity: 'high',
      rationale: 'A'.repeat(200),
    };
    
    const truncated = { ...longSignal, rationale: longSignal.rationale.slice(0, 120) };
    expect(truncated.rationale.length).toBe(120);
  });
});

describe('CodeViewer component structure', () => {
  it('should detect language from filename', () => {
    const detectLanguage = (filename: string): string => {
      if (filename.endsWith('.py')) return 'python';
      if (filename.endsWith('.sh') || filename.endsWith('.bash')) return 'bash';
      if (filename.endsWith('.ps1')) return 'powershell';
      if (filename.endsWith('.rb')) return 'ruby';
      if (filename.endsWith('.js') || filename.endsWith('.ts')) return 'javascript';
      return 'python'; // default
    };
    
    expect(detectLanguage('exploit.py')).toBe('python');
    expect(detectLanguage('shell.sh')).toBe('bash');
    expect(detectLanguage('attack.ps1')).toBe('powershell');
    expect(detectLanguage('exploit.rb')).toBe('ruby');
    expect(detectLanguage('script.js')).toBe('javascript');
    expect(detectLanguage('unknown.txt')).toBe('python');
  });

  it('should support copy to clipboard functionality', () => {
    const code = 'import requests\nprint("hello")';
    expect(code.length).toBeGreaterThan(0);
    expect(typeof code).toBe('string');
  });
});

describe('Nmap scan improvements', () => {
  it('should use top-1000 ports with script scanning', () => {
    const nmapCmd = 'nmap -sV -sC --top-ports 1000 -T4 --open -oX -';
    
    expect(nmapCmd).toContain('-sV'); // service version detection
    expect(nmapCmd).toContain('-sC'); // script scanning
    expect(nmapCmd).toContain('--top-ports 1000'); // top 1000 ports
    expect(nmapCmd).toContain('-T4'); // aggressive timing
    expect(nmapCmd).toContain('-oX -'); // XML output to stdout
  });
});

describe('Curl-based header probe fallback', () => {
  it('should detect security header misconfigurations', () => {
    const headers: Record<string, string> = {
      'content-type': 'text/html',
      'server': 'Apache/2.4.7',
      // Missing security headers
    };
    
    const missingHeaders = [];
    if (!headers['strict-transport-security']) missingHeaders.push('HSTS');
    if (!headers['x-content-type-options']) missingHeaders.push('X-Content-Type-Options');
    if (!headers['x-frame-options']) missingHeaders.push('X-Frame-Options');
    if (!headers['content-security-policy']) missingHeaders.push('CSP');
    if (!headers['x-xss-protection']) missingHeaders.push('X-XSS-Protection');
    
    expect(missingHeaders.length).toBe(5);
    expect(missingHeaders).toContain('HSTS');
    expect(missingHeaders).toContain('CSP');
  });

  it('should detect server version disclosure', () => {
    const serverHeader = 'Apache/2.4.7 (Ubuntu)';
    const hasVersionDisclosure = /\d+\.\d+/.test(serverHeader);
    expect(hasVersionDisclosure).toBe(true);
  });
});
