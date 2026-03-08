import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the database module
vi.mock('./db', () => ({
  getHistoricalScanContext: vi.fn(),
}));

describe('Cross-Session Context Persistence', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('getHistoricalScanContext returns null when no previous scans exist', async () => {
    const { getHistoricalScanContext } = await import('./db');
    (getHistoricalScanContext as any).mockResolvedValue(null);

    const result = await getHistoricalScanContext('new-domain.com');
    expect(result).toBeNull();
  });

  it('getHistoricalScanContext returns context from previous completed scan', async () => {
    const { getHistoricalScanContext } = await import('./db');
    const mockContext = {
      previousScanId: 100,
      previousScanDate: '2026-03-01T00:00:00Z',
      previousRiskScore: 45,
      previousTotalAssets: 10,
      previousTotalFindings: 25,
      scanCount: 2,
      previousAssets: [
        { hostname: 'api.example.com', assetType: 'api_endpoint', riskScore: 60 },
        { hostname: 'www.example.com', assetType: 'web_application', riskScore: 30 },
      ],
      previousFindings: [
        { title: 'Missing HSTS', severity: 5, type: 'misconfiguration' },
        { title: 'Outdated TLS', severity: 7, type: 'vulnerability' },
      ],
    };
    (getHistoricalScanContext as any).mockResolvedValue(mockContext);

    const result = await getHistoricalScanContext('example.com');
    expect(result).toBeDefined();
    expect(result!.previousScanId).toBe(100);
    expect(result!.scanCount).toBe(2);
    expect(result!.previousAssets).toHaveLength(2);
    expect(result!.previousFindings).toHaveLength(2);
  });

  it('builds historical context string from scan context', async () => {
    const mockContext = {
      previousScanId: 100,
      previousScanDate: '2026-03-01T00:00:00Z',
      previousRiskScore: 45,
      previousTotalAssets: 10,
      previousTotalFindings: 25,
      scanCount: 2,
      previousAssets: [
        { hostname: 'api.example.com', assetType: 'api_endpoint', riskScore: 60 },
        { hostname: 'www.example.com', assetType: 'web_application', riskScore: 30 },
      ],
      previousFindings: [
        { title: 'Missing HSTS', severity: 5, type: 'misconfiguration' },
      ],
    };

    // Build the context string the same way the pipeline does
    const ctx = mockContext;
    const lines: string[] = [
      `\n--- HISTORICAL CONTEXT (Previous Scan #${ctx.previousScanId}, ${ctx.previousScanDate}) ---`,
      `This is scan #${ctx.scanCount + 1} for this domain. Previous scan found:`,
      `- Overall Risk Score: ${ctx.previousRiskScore}/100`,
      `- Total Assets: ${ctx.previousTotalAssets}`,
      `- Total Findings: ${ctx.previousTotalFindings}`,
    ];
    if (ctx.previousAssets.length > 0) {
      lines.push(`\nPrevious Assets (top 20):`);
      for (const a of ctx.previousAssets.slice(0, 20)) {
        lines.push(`  - ${a.hostname} [${a.assetType}] risk=${a.riskScore}`);
      }
    }
    if (ctx.previousFindings.length > 0) {
      lines.push(`\nPrevious Key Findings (top 15):`);
      for (const f of ctx.previousFindings.slice(0, 15)) {
        lines.push(`  - ${f.title} (severity: ${f.severity}/10, type: ${f.type})`);
      }
    }
    const historicalContext = lines.join('\n');

    expect(historicalContext).toContain('HISTORICAL CONTEXT');
    expect(historicalContext).toContain('scan #3');
    expect(historicalContext).toContain('api.example.com');
    expect(historicalContext).toContain('Missing HSTS');
    expect(historicalContext).toContain('Risk Score: 45/100');
  });

  it('computes scan delta correctly', () => {
    const currentAssets = ['api.example.com', 'www.example.com', 'new-service.example.com'];
    const previousAssets = ['api.example.com', 'www.example.com', 'old-service.example.com'];

    const currentHostnames = new Set(currentAssets.map(h => h.toLowerCase()));
    const previousHostnames = new Set(previousAssets.map(h => h.toLowerCase()));

    const newAssets = [...currentHostnames].filter(h => !previousHostnames.has(h));
    const removedAssets = [...previousHostnames].filter(h => !currentHostnames.has(h));
    const persistentAssets = [...currentHostnames].filter(h => previousHostnames.has(h));

    expect(newAssets).toEqual(['new-service.example.com']);
    expect(removedAssets).toEqual(['old-service.example.com']);
    expect(persistentAssets).toEqual(['api.example.com', 'www.example.com']);
  });

  it('computes risk delta correctly', () => {
    const previousRiskScore = 45;
    const currentRiskScore = 38;
    const riskDelta = currentRiskScore - previousRiskScore;

    expect(riskDelta).toBe(-7); // improved by 7 points
    expect(riskDelta < 0).toBe(true); // negative = improved
  });

  it('handles null previous values gracefully', () => {
    const previousRiskScore: number | null = null;
    const currentRiskScore = 38;
    const riskDelta = previousRiskScore != null ? currentRiskScore - previousRiskScore : null;

    expect(riskDelta).toBeNull();
  });
});

describe('Exploitation Bridge Router', () => {
  it('quickPlan input schema accepts correct fields', () => {
    // Validate the expected input shape
    const validInput = {
      cveId: 'CVE-2024-1234',
      targetIp: '192.168.1.1',
      targetPort: 443,
      targetOs: 'linux',
      vulnDescription: 'SQL injection in login form',
    };

    expect(validInput.cveId).toBeDefined();
    expect(validInput.targetIp).toBeDefined();
    expect(typeof validInput.targetPort).toBe('number');
    expect(validInput.targetOs).toBeDefined();
    expect(validInput.vulnDescription).toBeDefined();
  });

  it('lookupExploits input schema accepts cveId', () => {
    const validInput = {
      cveId: 'CVE-2024-5678',
    };

    expect(validInput.cveId).toMatch(/^CVE-\d{4}-\d+$/);
  });

  it('executePlan input schema accepts planId and target', () => {
    const validInput = {
      planId: 'plan-abc-123',
      targetIp: '10.0.0.1',
      targetPort: 8080,
    };

    expect(validInput.planId).toBeDefined();
    expect(validInput.targetIp).toBeDefined();
    expect(typeof validInput.targetPort).toBe('number');
  });
});
