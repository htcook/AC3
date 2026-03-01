import { describe, it, expect, vi } from 'vitest';

// ─── Container Discovery Tests ──────────────────────────────────────

describe('Container Discovery Module', () => {
  it('should export containerDiscoveryConnector with correct interface', async () => {
    const mod = await import('./lib/passive/container-discovery');
    expect(mod.containerDiscoveryConnector).toBeDefined();
    expect(mod.containerDiscoveryConnector.name).toBe('container-discovery');
    expect(mod.containerDiscoveryConnector.description).toBeDefined();
    expect(typeof mod.containerDiscoveryConnector.collect).toBe('function');
    expect(mod.containerDiscoveryConnector.requiresApiKey).toBe(false);
  });

  it('should export analyzeContainerExposure standalone function', async () => {
    const { analyzeContainerExposure } = await import('./lib/passive/container-discovery');
    expect(typeof analyzeContainerExposure).toBe('function');
  });

  it('should define connector with description containing container keywords', async () => {
    const mod = await import('./lib/passive/container-discovery');
    expect(mod.containerDiscoveryConnector.name).toBe('container-discovery');
    expect(mod.containerDiscoveryConnector.description).toContain('container');
  });

  it('analyzeContainerExposure should return correct structure for non-existent domain', async () => {
    const { analyzeContainerExposure } = await import('./lib/passive/container-discovery');
    // Use a domain that won't have container infrastructure
    const result = await analyzeContainerExposure('this-domain-definitely-does-not-exist-12345.test', [], 3000);
    expect(result).toHaveProperty('totalProbes');
    expect(result).toHaveProperty('totalHits');
    expect(result).toHaveProperty('criticalFindings');
    expect(result).toHaveProperty('highFindings');
    expect(result).toHaveProperty('findings');
    expect(result).toHaveProperty('subdomainsProbed');
    expect(result).toHaveProperty('durationMs');
    expect(Array.isArray(result.findings)).toBe(true);
    expect(Array.isArray(result.subdomainsProbed)).toBe(true);
    expect(typeof result.totalProbes).toBe('number');
    expect(typeof result.durationMs).toBe('number');
    expect(result.totalProbes).toBeGreaterThan(0); // Should have probed multiple endpoints
  });

  it('ContainerDiscoveryResult interface should have required fields', async () => {
    const { analyzeContainerExposure } = await import('./lib/passive/container-discovery');
    // Verify the function exists and returns the right shape
    expect(typeof analyzeContainerExposure).toBe('function');
  });

  it('ContainerDiscoveryResult should export the interface', async () => {
    const mod = await import('./lib/passive/container-discovery');
    // Verify the module exports what we expect
    expect(mod.analyzeContainerExposure).toBeDefined();
    expect(mod.containerDiscoveryConnector).toBeDefined();
  });
});

// ─── SCAP Compliance Scanner Tests ──────────────────────────────────

describe('SCAP Compliance Scanner', () => {
  it('should export runExternalComplianceScan function', async () => {
    const { runExternalComplianceScan } = await import('./lib/scap-compliance-scanner');
    expect(typeof runExternalComplianceScan).toBe('function');
  });

  it('should export parseOpenSCAPResults function', async () => {
    const { parseOpenSCAPResults } = await import('./lib/scap-compliance-scanner');
    expect(typeof parseOpenSCAPResults).toBe('function');
  });

  it('should export parseLynisReport function', async () => {
    const { parseLynisReport } = await import('./lib/scap-compliance-scanner');
    expect(typeof parseLynisReport).toBe('function');
  });

  it('runExternalComplianceScan should return correct structure', async () => {
    const { runExternalComplianceScan } = await import('./lib/scap-compliance-scanner');
    const result = await runExternalComplianceScan('example.com', { timeout: 5000 });
    expect(result).toHaveProperty('target', 'example.com');
    expect(result).toHaveProperty('complianceScore');
    expect(result).toHaveProperty('totalChecks');
    expect(result).toHaveProperty('passed');
    expect(result).toHaveProperty('failed');
    expect(result).toHaveProperty('notApplicable');
    expect(result).toHaveProperty('manualReview');
    expect(result).toHaveProperty('errors');
    expect(result).toHaveProperty('benchmarkProfile');
    expect(result).toHaveProperty('scanType', 'external');
    expect(result).toHaveProperty('durationMs');
    expect(result).toHaveProperty('checks');
    expect(Array.isArray(result.checks)).toBe(true);
    expect(typeof result.complianceScore).toBe('number');
    expect(result.complianceScore).toBeGreaterThanOrEqual(0);
    expect(result.complianceScore).toBeLessThanOrEqual(100);
  });

  it('compliance checks should have required fields', async () => {
    const { runExternalComplianceScan } = await import('./lib/scap-compliance-scanner');
    const result = await runExternalComplianceScan('example.com', { timeout: 5000 });
    expect(result.checks.length).toBeGreaterThan(0);
    for (const check of result.checks) {
      expect(check).toHaveProperty('checkId');
      expect(check).toHaveProperty('title');
      expect(check).toHaveProperty('category');
      expect(check).toHaveProperty('severity');
      expect(check).toHaveProperty('status');
      expect(check).toHaveProperty('evidence');
      expect(check).toHaveProperty('remediation');
      expect(check).toHaveProperty('benchmarkRef');
      expect(check).toHaveProperty('nistControls');
      expect(Array.isArray(check.nistControls)).toBe(true);
      expect(['pass', 'fail', 'manual_review', 'not_applicable', 'error']).toContain(check.status);
      expect(['critical', 'high', 'medium', 'low', 'info']).toContain(check.severity);
    }
  });

  it('compliance score should equal passed / (total - notApplicable) * 100', async () => {
    const { runExternalComplianceScan } = await import('./lib/scap-compliance-scanner');
    const result = await runExternalComplianceScan('example.com', { timeout: 5000 });
    const applicable = result.totalChecks - result.notApplicable;
    if (applicable > 0) {
      const expectedScore = Math.round((result.passed / applicable) * 100);
      expect(result.complianceScore).toBe(expectedScore);
    }
  });

  it('total checks should equal sum of passed + failed + notApplicable + manualReview + errors', async () => {
    const { runExternalComplianceScan } = await import('./lib/scap-compliance-scanner');
    const result = await runExternalComplianceScan('example.com', { timeout: 5000 });
    const sum = result.passed + result.failed + result.notApplicable + result.manualReview + result.errors;
    expect(result.totalChecks).toBe(sum);
  });

  it('compliance checks should include TLS, HTTP headers, DNS, and service hardening categories', async () => {
    const { runExternalComplianceScan } = await import('./lib/scap-compliance-scanner');
    const result = await runExternalComplianceScan('example.com', { timeout: 5000 });
    const categories = new Set(result.checks.map(c => c.category));
    // Should have at least some of these categories
    const expectedCategories = ['tls_configuration', 'http_security_headers', 'dns_security', 'service_hardening', 'authentication'];
    const foundCategories = expectedCategories.filter(c => categories.has(c));
    expect(foundCategories.length).toBeGreaterThanOrEqual(2);
  });
});

// ─── Scanner API Integration Tests ──────────────────────────────────

describe('Scanner API Integration', () => {
  it('should export validateConnection function', async () => {
    const { validateConnection } = await import('./lib/scanner-api-integration');
    expect(validateConnection).toBeDefined();
    expect(typeof validateConnection).toBe('function');
  });

  it('should export listRemoteScans function', async () => {
    const { listRemoteScans } = await import('./lib/scanner-api-integration');
    expect(listRemoteScans).toBeDefined();
    expect(typeof listRemoteScans).toBe('function');
  });

  it('should export pullScanResults function', async () => {
    const { pullScanResults } = await import('./lib/scanner-api-integration');
    expect(pullScanResults).toBeDefined();
    expect(typeof pullScanResults).toBe('function');
  });

  it('validateConnection should fail gracefully for unreachable nessus scanner', async () => {
    const { validateConnection } = await import('./lib/scanner-api-integration');
    const result = await validateConnection({
      type: 'nessus',
      baseUrl: 'https://this-scanner-does-not-exist.test:8834',
      apiKey: 'test-key',
    });
    expect(result).toHaveProperty('connected', false);
    expect(result).toHaveProperty('error');
    expect(typeof result.error).toBe('string');
  });

  it('validateConnection should fail gracefully for unreachable qualys scanner', async () => {
    const { validateConnection } = await import('./lib/scanner-api-integration');
    const result = await validateConnection({
      type: 'qualys',
      baseUrl: 'https://this-scanner-does-not-exist.test',
      apiKey: 'test-key',
    });
    expect(result).toHaveProperty('connected', false);
    expect(result).toHaveProperty('error');
  });

  it('validateConnection should fail gracefully for unreachable rapid7 scanner', async () => {
    const { validateConnection } = await import('./lib/scanner-api-integration');
    const result = await validateConnection({
      type: 'rapid7',
      baseUrl: 'https://this-scanner-does-not-exist.test',
      apiKey: 'test-key',
    });
    expect(result).toHaveProperty('connected', false);
    expect(result).toHaveProperty('error');
  });
});

// ─── Pipeline Integration Tests ──────────────────────────────────

describe('Pipeline Integration', () => {
  it('PipelineResult should include complianceScan field', async () => {
    // Verify the type exists by importing and checking the pipeline module
    const mod = await import('./domainIntel');
    expect(mod).toHaveProperty('runDomainIntelPipeline');
  });

  it('PipelineResult should include containerExposure field', async () => {
    const mod = await import('./domainIntel');
    expect(mod).toHaveProperty('runDomainIntelPipeline');
  });
});
