/**
 * Tests for Bug Fixes:
 *   1. Hydra hostname usage for HTTPS/ALB targets
 *   2. Dependency resolution type mismatch (manifest vs array)
 *   3. CVE-product-to-technology guardrail cross-validation
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// ═══════════════════════════════════════════════════════════════════════
// §1 — HYDRA HOSTNAME FIX
// ═══════════════════════════════════════════════════════════════════════


// Skip in CI — requires SSH access to scan server
const __skipInCI = !process.env.SCAN_SERVER_HOST;

describe.skipIf(__skipInCI)('Hydra Hostname Fix for HTTPS/ALB Targets', () => {
  it('should use hostname instead of raw IP for HTTPS (port 443) targets', async () => {
    const { suggestToolCommands } = await import('./lib/scan-server-executor');
    const commands = await suggestToolCommands({
      ip: '34.246.169.176',
      hostname: 'ginandjuice.shop',
      ports: [{ port: 443, service: 'https' }],
    });

    // Find any command that contains 'hydra'
    const hydraCmd = commands.find(c => c.tool === 'hydra' || c.args?.includes('hydra'));
    if (hydraCmd) {
      const fullCmd = `${hydraCmd.tool} ${hydraCmd.args}`;
      // Should use hostname for HTTPS targets (SNI/ALB compatibility)
      expect(fullCmd).toContain('ginandjuice.shop');
    }
  });

  it('should prefer hostname over raw IP for all Hydra targets (consistent DNS resolution)', async () => {
    const { suggestToolCommands } = await import('./lib/scan-server-executor');
    const commands = await suggestToolCommands({
      ip: '192.168.1.100',
      hostname: 'internal.lab',
      ports: [{ port: 22, service: 'ssh' }],
    });

    const hydraCmd = commands.find(c => c.tool === 'hydra' || c.args?.includes('hydra'));
    if (hydraCmd) {
      const fullCmd = `${hydraCmd.tool} ${hydraCmd.args}`;
      // Hydra prefers hostname when available for consistent DNS resolution
      expect(fullCmd).toContain('internal.lab');
    }
  });

  it('should use hostname for port 8443 (alternate HTTPS)', async () => {
    const { suggestToolCommands } = await import('./lib/scan-server-executor');
    const commands = await suggestToolCommands({
      ip: '10.0.0.5',
      hostname: 'secure.example.com',
      ports: [{ port: 8443, service: 'https-alt' }],
    });

    const hydraCmd = commands.find(c => c.tool === 'hydra' || c.args?.includes('hydra'));
    if (hydraCmd) {
      const fullCmd = `${hydraCmd.tool} ${hydraCmd.args}`;
      expect(fullCmd).toContain('secure.example.com');
    }
  });

  it('should fall back to IP when no hostname is provided', async () => {
    const { suggestToolCommands } = await import('./lib/scan-server-executor');
    const commands = await suggestToolCommands({
      ip: '10.0.0.5',
      ports: [{ port: 443, service: 'https' }],
    });

    const hydraCmd = commands.find(c => c.tool === 'hydra' || c.args?.includes('hydra'));
    if (hydraCmd) {
      const fullCmd = `${hydraCmd.tool} ${hydraCmd.args}`;
      expect(fullCmd).toContain('10.0.0.5');
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §2 — DEPENDENCY RESOLUTION TYPE MISMATCH FIX
// ═══════════════════════════════════════════════════════════════════════

describe('Dependency Resolution Type Mismatch Fix', () => {
  it('resolveDependencies should pass array (not manifest object) to installDependencies', async () => {
    // Mock executeRawCommand to avoid actual SSH calls
    vi.doMock('./lib/scan-server-executor', () => ({
      executeRawCommand: vi.fn().mockResolvedValue({ exitCode: 0, stdout: 'ok', stderr: '' }),
    }));

    const { resolveDependencies } = await import('./lib/exploit-dependency-manager');

    // This should NOT throw "deps is not iterable"
    const result = await resolveDependencies(
      ['requests', 'beautifulsoup4'],
      'python',
    );

    expect(result).toBeDefined();
    expect(result).toHaveProperty('success');
    expect(result).toHaveProperty('installed');
    expect(result).toHaveProperty('failed');
    expect(Array.isArray(result.installed)).toBe(true);
    expect(Array.isArray(result.failed)).toBe(true);
  });

  it('installDependencies should handle non-array input gracefully', async () => {
    const { installDependencies } = await import('./lib/exploit-dependency-manager');

    // Pass a non-array (simulating the old bug where manifest was passed)
    const result = await installDependencies({} as any);

    expect(result).toBeDefined();
    expect(result.success).toBe(true);
    expect(result.installed).toEqual([]);
    expect(result.failed).toEqual([]);
    expect(result.durationMs).toBe(0);
  });

  it('installDependencies should handle null input gracefully', async () => {
    const { installDependencies } = await import('./lib/exploit-dependency-manager');

    const result = await installDependencies(null as any);

    expect(result).toBeDefined();
    expect(result.success).toBe(true);
    expect(result.installed).toEqual([]);
  });

  it('installDependencies should handle undefined input gracefully', async () => {
    const { installDependencies } = await import('./lib/exploit-dependency-manager');

    const result = await installDependencies(undefined as any);

    expect(result).toBeDefined();
    expect(result.success).toBe(true);
  });

  it('checkDependencies should handle manifest with undefined dependencies', async () => {
    const { checkDependencies } = await import('./lib/exploit-dependency-manager');

    const result = await checkDependencies({
      exploitId: 'test',
      language: 'python',
      dependencies: undefined as any,
    });

    expect(result).toBeDefined();
    expect(result.ready).toBe(true);
    expect(result.checks).toEqual([]);
    expect(result.missingRequired).toEqual([]);
    expect(result.missingOptional).toEqual([]);
  });

  it('buildManifest should always return an array for dependencies', async () => {
    const { buildManifest } = await import('./lib/exploit-dependency-manager');

    const manifest = buildManifest('test-exploit', 'echo hello', 'bash');

    expect(manifest).toBeDefined();
    expect(Array.isArray(manifest.dependencies)).toBe(true);
  });

  it('buildManifest should return dependencies for Python code with imports', async () => {
    const { buildManifest } = await import('./lib/exploit-dependency-manager');

    const manifest = buildManifest(
      'test-exploit',
      'import requests\nfrom bs4 import BeautifulSoup\nimport json',
      'python',
    );

    expect(manifest.dependencies.length).toBeGreaterThan(0);
    const depNames = manifest.dependencies.map(d => d.name);
    expect(depNames).toContain('requests');
    expect(depNames).toContain('beautifulsoup4');
    // json is stdlib, should not be included
    expect(depNames).not.toContain('json');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §3 — CVE-PRODUCT-TO-TECHNOLOGY GUARDRAIL
// ═══════════════════════════════════════════════════════════════════════

describe('CVE Product-to-Technology Guardrail', () => {
  it('should block CVE-2024-23692 (Rejetto HFS) against a Java/Spring target', async () => {
    const { runGuardrails } = await import('./lib/exploit-guardrails');

    const result = runGuardrails(
      {
        cveId: 'CVE-2024-23692',
        targetHostname: 'ginandjuice.shop',
        targetPort: 80,
        code: 'exploit code here',
        confidence: 70,
        assumedTechnologies: [],
      },
      {
        confirmedPorts: [{ port: 80, service: 'http', version: 'Apache' }, { port: 443, service: 'https' }],
        confirmedTechnologies: ['Java', 'Spring Framework'],
        confirmedCVEs: ['CVE-2024-23692'],
        scopeTargets: ['ginandjuice.shop'],
        targetHostname: 'ginandjuice.shop',
        reconEvidence: 'Java/Spring web application',
      },
    );

    // Should have a cve_product_mismatch check that failed
    const productCheck = result.checks.find(c => c.name === 'cve_product_mismatch');
    expect(productCheck).toBeDefined();
    expect(productCheck!.passed).toBe(false);
    expect(productCheck!.severity).toBe('critical');
    expect(productCheck!.message).toContain('rejetto_hfs');
    expect(productCheck!.message).toContain('no matching technology');
  });

  it('should allow CVE-2024-23692 against a target running Rejetto HFS', async () => {
    const { runGuardrails } = await import('./lib/exploit-guardrails');

    const result = runGuardrails(
      {
        cveId: 'CVE-2024-23692',
        targetHostname: 'target.lab',
        targetPort: 80,
        code: 'exploit code here',
        confidence: 80,
        assumedTechnologies: [],
      },
      {
        confirmedPorts: [{ port: 80, service: 'http', version: 'Rejetto HFS 2.3m' }],
        confirmedTechnologies: ['Rejetto HTTP File Server'],
        confirmedCVEs: ['CVE-2024-23692'],
        scopeTargets: ['target.lab'],
        targetHostname: 'target.lab',
        reconEvidence: 'Rejetto HTTP File Server 2.3m',
      },
    );

    const productCheck = result.checks.find(c => c.name === 'cve_product_mismatch');
    expect(productCheck).toBeDefined();
    expect(productCheck!.passed).toBe(true);
  });

  it('should allow CVE-2024-23692 when HFS is detected in service version', async () => {
    const { runGuardrails } = await import('./lib/exploit-guardrails');

    const result = runGuardrails(
      {
        cveId: 'CVE-2024-23692',
        targetHostname: 'target.lab',
        targetPort: 80,
        code: 'exploit code here',
        confidence: 80,
        assumedTechnologies: [],
      },
      {
        confirmedPorts: [{ port: 80, service: 'http file server', version: '2.3m' }],
        confirmedTechnologies: [],
        confirmedCVEs: ['CVE-2024-23692'],
        scopeTargets: ['target.lab'],
        targetHostname: 'target.lab',
        reconEvidence: 'HTTP File Server detected',
      },
    );

    const productCheck = result.checks.find(c => c.name === 'cve_product_mismatch');
    expect(productCheck).toBeDefined();
    expect(productCheck!.passed).toBe(true);
  });

  it('should block CVE-2021-44228 (Log4j) against a PHP target', async () => {
    const { runGuardrails } = await import('./lib/exploit-guardrails');

    const result = runGuardrails(
      {
        cveId: 'CVE-2021-44228',
        targetHostname: 'wordpress.example.com',
        targetPort: 80,
        code: 'log4shell exploit',
        confidence: 60,
        assumedTechnologies: [],
      },
      {
        confirmedPorts: [{ port: 80, service: 'http', version: 'Apache/PHP' }],
        confirmedTechnologies: ['PHP', 'WordPress'],
        confirmedCVEs: ['CVE-2021-44228'],
        scopeTargets: ['wordpress.example.com'],
        targetHostname: 'wordpress.example.com',
        reconEvidence: 'WordPress 6.4 on PHP 8.1',
      },
    );

    const productCheck = result.checks.find(c => c.name === 'cve_product_mismatch');
    expect(productCheck).toBeDefined();
    expect(productCheck!.passed).toBe(false);
    expect(productCheck!.message).toContain('apache_log4j');
  });

  it('should allow CVE-2021-44228 against a Java target', async () => {
    const { runGuardrails } = await import('./lib/exploit-guardrails');

    const result = runGuardrails(
      {
        cveId: 'CVE-2021-44228',
        targetHostname: 'java-app.example.com',
        targetPort: 8080,
        code: 'log4shell exploit',
        confidence: 85,
        assumedTechnologies: ['Java'],
      },
      {
        confirmedPorts: [{ port: 8080, service: 'http', version: 'Apache Tomcat' }],
        confirmedTechnologies: ['Java', 'Apache Tomcat', 'Log4j'],
        confirmedCVEs: ['CVE-2021-44228'],
        scopeTargets: ['java-app.example.com'],
        targetHostname: 'java-app.example.com',
        reconEvidence: 'Java web application with Log4j',
      },
    );

    const productCheck = result.checks.find(c => c.name === 'cve_product_mismatch');
    expect(productCheck).toBeDefined();
    expect(productCheck!.passed).toBe(true);
  });

  it('should not add cve_product_mismatch check for unknown CVEs', async () => {
    const { runGuardrails } = await import('./lib/exploit-guardrails');

    const result = runGuardrails(
      {
        cveId: 'CVE-2024-99999',
        targetHostname: 'target.lab',
        targetPort: 80,
        code: 'exploit code',
        confidence: 70,
        assumedTechnologies: [],
      },
      {
        confirmedPorts: [{ port: 80, service: 'http' }],
        confirmedTechnologies: ['nginx'],
        confirmedCVEs: ['CVE-2024-99999'],
        scopeTargets: ['target.lab'],
        targetHostname: 'target.lab',
        reconEvidence: 'nginx web server',
      },
    );

    const productCheck = result.checks.find(c => c.name === 'cve_product_mismatch');
    // No mapping exists for CVE-2024-99999, so no check should be added
    expect(productCheck).toBeUndefined();
  });

  it('should not add cve_product_mismatch check when no CVE is specified', async () => {
    const { runGuardrails } = await import('./lib/exploit-guardrails');

    const result = runGuardrails(
      {
        targetHostname: 'target.lab',
        targetPort: 80,
        code: 'generic exploit',
        confidence: 70,
        assumedTechnologies: [],
      },
      {
        confirmedPorts: [{ port: 80, service: 'http' }],
        confirmedTechnologies: ['nginx'],
        confirmedCVEs: [],
        scopeTargets: ['target.lab'],
        targetHostname: 'target.lab',
        reconEvidence: 'nginx web server',
      },
    );

    const productCheck = result.checks.find(c => c.name === 'cve_product_mismatch');
    expect(productCheck).toBeUndefined();
  });

  it('should block CVE-2017-0144 (EternalBlue) against a Linux target', async () => {
    const { runGuardrails } = await import('./lib/exploit-guardrails');

    const result = runGuardrails(
      {
        cveId: 'CVE-2017-0144',
        targetHostname: 'linux.lab',
        targetPort: 445,
        code: 'eternalblue exploit',
        confidence: 75,
        assumedTechnologies: [],
      },
      {
        confirmedPorts: [{ port: 445, service: 'samba', version: '4.15.0' }],
        confirmedTechnologies: ['Linux', 'Samba'],
        confirmedCVEs: ['CVE-2017-0144'],
        scopeTargets: ['linux.lab'],
        targetHostname: 'linux.lab',
        reconEvidence: 'Linux server running Samba',
      },
    );

    const productCheck = result.checks.find(c => c.name === 'cve_product_mismatch');
    expect(productCheck).toBeDefined();
    expect(productCheck!.passed).toBe(false);
    expect(productCheck!.message).toContain('microsoft_windows');
  });

  it('should allow CVE-2017-0144 against a Windows SMB target', async () => {
    const { runGuardrails } = await import('./lib/exploit-guardrails');

    const result = runGuardrails(
      {
        cveId: 'CVE-2017-0144',
        targetHostname: 'windows.lab',
        targetPort: 445,
        code: 'eternalblue exploit',
        confidence: 90,
        assumedTechnologies: ['Windows'],
      },
      {
        confirmedPorts: [{ port: 445, service: 'smb', version: 'Windows Server 2008' }],
        confirmedTechnologies: ['Windows Server 2008', 'SMB'],
        confirmedCVEs: ['CVE-2017-0144'],
        scopeTargets: ['windows.lab'],
        targetHostname: 'windows.lab',
        reconEvidence: 'Windows Server 2008 R2 with SMBv1',
      },
    );

    const productCheck = result.checks.find(c => c.name === 'cve_product_mismatch');
    expect(productCheck).toBeDefined();
    expect(productCheck!.passed).toBe(true);
  });

  it('CVE product mismatch should increase risk score and block execution', async () => {
    const { runGuardrails } = await import('./lib/exploit-guardrails');

    const result = runGuardrails(
      {
        cveId: 'CVE-2024-23692',
        targetHostname: 'ginandjuice.shop',
        targetPort: 80,
        code: 'rejetto exploit against spring app',
        confidence: 80,
        assumedTechnologies: [],
      },
      {
        confirmedPorts: [{ port: 80, service: 'http' }],
        confirmedTechnologies: ['Java', 'Spring'],
        confirmedCVEs: ['CVE-2024-23692'],
        scopeTargets: ['ginandjuice.shop'],
        targetHostname: 'ginandjuice.shop',
        reconEvidence: 'Java Spring application',
      },
    );

    // Critical failure should block execution
    expect(result.passed).toBe(false);
    expect(result.riskScore).toBeGreaterThanOrEqual(40); // Critical = 40 points
    expect(result.blockedReasons.length).toBeGreaterThan(0);
    expect(result.blockedReasons.some(r => r.includes('rejetto_hfs') || r.includes('Rejetto'))).toBe(true);
  });
});
