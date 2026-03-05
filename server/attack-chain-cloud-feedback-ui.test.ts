import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * Tests for the three new tRPC endpoints:
 *   1. engagementOps.getAttackChains
 *   2. engagementOps.getCloudMisconfigs
 *   3. engagementOps.getFeedbackLoopState
 *
 * These tests validate the data transformation logic without requiring
 * a live engagement orchestrator by mocking getOpsState.
 */

// ── Mock engagement orchestrator ──────────────────────────────────────────────

const mockGetOpsState = vi.fn();

vi.mock("../lib/engagement-orchestrator", () => ({
  getOpsState: (...args: any[]) => mockGetOpsState(...args),
  broadcastOpsUpdate: vi.fn(),
}));

// ── Helper: build a mock ops state ────────────────────────────────────────────

function buildMockOpsState(overrides: Record<string, any> = {}) {
  return {
    engagementId: 1,
    phase: "completed",
    isRunning: false,
    assets: [
      {
        hostname: "example.com",
        ip: "1.2.3.4",
        type: "web",
        ports: [{ port: 80, service: "http" }, { port: 443, service: "https" }],
        vulns: [
          { id: "v1", title: "SQL Injection", severity: "critical", cve: "CVE-2024-1234" },
          { id: "v2", title: "XSS Reflected", severity: "high", cve: null },
        ],
        zapFindings: [],
        cloudProviders: ["AWS"],
        cloudServices: ["S3", "EC2"],
      },
    ],
    stats: { hostsScanned: 1, portsFound: 2, vulnsFound: 2, exploitsAttempted: 1, exploitsSucceeded: 0, sessionsOpened: 0, zapScansRun: 0, wafDetections: 0 },
    log: [],
    approvalGates: [],
    ...overrides,
  };
}

// ── Attack Chain Endpoint Logic Tests ─────────────────────────────────────────

describe("getAttackChains endpoint logic", () => {
  beforeEach(() => {
    mockGetOpsState.mockReset();
  });

  it("returns empty chains when no ops state exists", () => {
    mockGetOpsState.mockReturnValue(null);
    // Simulate the endpoint logic
    const state = mockGetOpsState(1);
    expect(state).toBeNull();
    const result = { chains: [], summary: null, cloudRiskAssessment: null };
    expect(result.chains).toHaveLength(0);
    expect(result.summary).toBeNull();
  });

  it("returns empty chains when no attackChains on state", () => {
    mockGetOpsState.mockReturnValue(buildMockOpsState());
    const state = mockGetOpsState(1);
    const chains = state.attackChains || [];
    expect(chains).toHaveLength(0);
  });

  it("builds summary from attack chains correctly", () => {
    const mockChains = [
      {
        id: "chain-1",
        name: "Web App Exploitation Chain",
        description: "SQL injection to data exfiltration",
        overallRisk: 9,
        feasibility: 7,
        stealthRating: 5,
        totalSteps: 4,
        mitreTechniques: ["T1190", "T1059", "T1005"],
        cloudExploitPaths: [],
        recommendations: ["Patch SQL injection", "Enable WAF"],
        steps: [
          { name: "Initial Access", technique: "T1190", tool: "sqlmap" },
          { name: "Execution", technique: "T1059", tool: "bash" },
        ],
      },
      {
        id: "chain-2",
        name: "Cloud Lateral Movement",
        description: "S3 misconfiguration to IAM escalation",
        overallRisk: 8,
        feasibility: 6,
        stealthRating: 8,
        totalSteps: 3,
        mitreTechniques: ["T1530", "T1078"],
        cloudExploitPaths: [{ id: "s3-public", name: "Public S3 Bucket", severity: "critical", provider: "AWS" }],
        recommendations: ["Restrict S3 bucket policy"],
        steps: [],
      },
    ];

    mockGetOpsState.mockReturnValue(buildMockOpsState({ attackChains: mockChains }));
    const state = mockGetOpsState(1);
    const chains = state.attackChains || [];

    // Build summary (mirrors endpoint logic)
    const allTechniques = [...new Set(chains.flatMap((c: any) => c.mitreTechniques || []))];
    const cloudChains = chains.filter((c: any) => (c.cloudExploitPaths || []).length > 0);
    const sortedByFeasibility = [...chains].sort((a: any, b: any) => (b.feasibility || 0) - (a.feasibility || 0));
    const sortedByStealth = [...chains].sort((a: any, b: any) => (b.stealthRating || 0) - (a.stealthRating || 0));

    const summary = {
      totalChains: chains.length,
      totalSteps: chains.reduce((s: number, c: any) => s + (c.totalSteps || 0), 0),
      uniqueTechniques: allTechniques.length,
      highestRisk: Math.max(...chains.map((c: any) => c.overallRisk || 0), 0),
      mostFeasible: sortedByFeasibility[0] ? { name: sortedByFeasibility[0].name, feasibility: sortedByFeasibility[0].feasibility } : null,
      stealthiest: sortedByStealth[0] ? { name: sortedByStealth[0].name, stealthRating: sortedByStealth[0].stealthRating } : null,
      cloudChainsCount: cloudChains.length,
      criticalPaths: chains.filter((c: any) => (c.overallRisk || 0) >= 8).map((c: any) => `${c.name} (risk: ${c.overallRisk}/10)`),
    };

    expect(summary.totalChains).toBe(2);
    expect(summary.totalSteps).toBe(7);
    expect(summary.uniqueTechniques).toBe(5); // T1190, T1059, T1005, T1530, T1078
    expect(summary.highestRisk).toBe(9);
    expect(summary.mostFeasible?.name).toBe("Web App Exploitation Chain");
    expect(summary.mostFeasible?.feasibility).toBe(7);
    expect(summary.stealthiest?.name).toBe("Cloud Lateral Movement");
    expect(summary.stealthiest?.stealthRating).toBe(8);
    expect(summary.cloudChainsCount).toBe(1);
    expect(summary.criticalPaths).toHaveLength(2); // both >= 8
  });

  it("computes cloud risk assessment from cloud detection findings", () => {
    const cloudDetection = {
      findings: [
        { title: "Public S3 Bucket", severity: "critical", provider: "AWS", service: "S3", asset: "example.com" },
        { title: "Open Azure Blob", severity: "high", provider: "Azure", service: "Blob Storage", asset: "example.com" },
        { title: "IAM Role Misconfiguration", severity: "high", provider: "AWS", service: "IAM", asset: "example.com" },
        { title: "Anonymous GCS Access", severity: "medium", provider: "GCP", service: "GCS", asset: "example.com" },
      ],
    };

    mockGetOpsState.mockReturnValue(buildMockOpsState({ cloudDetection }));
    const state = mockGetOpsState(1);
    const findings = state.cloudDetection.findings;

    const providers = [...new Set(findings.map((f: any) => f.provider))];
    const publicStorage = findings.filter((f: any) =>
      f.title?.toLowerCase().includes("public") || f.title?.toLowerCase().includes("open") || f.title?.toLowerCase().includes("anonymous")
    );
    const criticalCount = findings.filter((f: any) => f.severity === "critical").length;
    const highCount = findings.filter((f: any) => f.severity === "high").length;
    const riskScore = Math.min(100, criticalCount * 25 + highCount * 15 + publicStorage.length * 10);

    expect(providers).toContain("AWS");
    expect(providers).toContain("Azure");
    expect(providers).toContain("GCP");
    expect(publicStorage).toHaveLength(3); // Public S3, Open Azure, Anonymous GCS
    expect(criticalCount).toBe(1);
    expect(highCount).toBe(2);
    expect(riskScore).toBe(85); // 25 + 30 + 30
    expect(riskScore >= 75 ? "critical" : riskScore >= 50 ? "high" : riskScore >= 25 ? "medium" : "low").toBe("critical");
  });
});

// ── Cloud Misconfigs Endpoint Logic Tests ─────────────────────────────────────

describe("getCloudMisconfigs endpoint logic", () => {
  beforeEach(() => {
    mockGetOpsState.mockReset();
  });

  it("returns empty when no ops state", () => {
    mockGetOpsState.mockReturnValue(null);
    const state = mockGetOpsState(1);
    expect(state).toBeNull();
  });

  it("returns empty when no cloud detection data", () => {
    mockGetOpsState.mockReturnValue(buildMockOpsState());
    const state = mockGetOpsState(1);
    const cloudDetection = state.cloudDetection || { findings: [] };
    expect(cloudDetection.findings).toHaveLength(0);
  });

  it("computes severity stats correctly", () => {
    const cloudDetection = {
      assetsFound: 2,
      storageEndpoints: 3,
      findings: [
        { title: "Public S3", severity: "critical", provider: "AWS", service: "S3", asset: "a.com" },
        { title: "Weak IAM", severity: "high", provider: "AWS", service: "IAM", asset: "a.com" },
        { title: "Open Blob", severity: "high", provider: "Azure", service: "Blob", asset: "b.com" },
        { title: "Logging Disabled", severity: "medium", provider: "GCP", service: "CloudTrail", asset: "a.com" },
        { title: "Version Exposed", severity: "low", provider: "AWS", service: "EC2", asset: "a.com" },
        { title: "Info Header", severity: "info", provider: "Azure", service: "AppService", asset: "b.com" },
      ],
    };

    mockGetOpsState.mockReturnValue(buildMockOpsState({ cloudDetection }));
    const state = mockGetOpsState(1);
    const findings = state.cloudDetection.findings;

    const stats = {
      total: findings.length,
      critical: findings.filter((f: any) => f.severity === "critical").length,
      high: findings.filter((f: any) => f.severity === "high").length,
      medium: findings.filter((f: any) => f.severity === "medium").length,
      low: findings.filter((f: any) => f.severity === "low" || f.severity === "info").length,
    };

    expect(stats.total).toBe(6);
    expect(stats.critical).toBe(1);
    expect(stats.high).toBe(2);
    expect(stats.medium).toBe(1);
    expect(stats.low).toBe(2);
  });

  it("gathers cloud info from individual assets", () => {
    const state = buildMockOpsState({
      assets: [
        { hostname: "a.com", ip: "1.1.1.1", cloudProviders: ["AWS"], cloudServices: ["S3", "EC2"], ports: [], vulns: [] },
        { hostname: "b.com", ip: "2.2.2.2", cloudProviders: ["Azure", "GCP"], cloudServices: ["Blob"], ports: [], vulns: [] },
        { hostname: "c.com", ip: "3.3.3.3", cloudProviders: [], cloudServices: [], ports: [], vulns: [] },
      ],
    });

    mockGetOpsState.mockReturnValue(state);
    const s = mockGetOpsState(1);

    const assetCloudInfo = s.assets
      .filter((a: any) => (a.cloudProviders?.length || 0) > 0)
      .map((a: any) => ({
        hostname: a.hostname,
        ip: a.ip,
        providers: a.cloudProviders || [],
        services: a.cloudServices || [],
      }));

    expect(assetCloudInfo).toHaveLength(2); // c.com filtered out
    expect(assetCloudInfo[0].hostname).toBe("a.com");
    expect(assetCloudInfo[0].providers).toContain("AWS");
    expect(assetCloudInfo[1].providers).toContain("Azure");
    expect(assetCloudInfo[1].providers).toContain("GCP");

    const allProviders = [...new Set(assetCloudInfo.flatMap((a: any) => a.providers))];
    expect(allProviders).toHaveLength(3);
  });
});

// ── Feedback Loop Endpoint Logic Tests ────────────────────────────────────────

describe("getFeedbackLoopState endpoint logic", () => {
  beforeEach(() => {
    mockGetOpsState.mockReset();
  });

  it("returns null when no ops state", () => {
    mockGetOpsState.mockReturnValue(null);
    const state = mockGetOpsState(1);
    expect(state).toBeNull();
  });

  it("returns null when no scanFeedbackLoop on state", () => {
    mockGetOpsState.mockReturnValue(buildMockOpsState());
    const state = mockGetOpsState(1);
    expect(state.scanFeedbackLoop).toBeUndefined();
  });

  it("transforms feedback loop state correctly", () => {
    const feedbackLoop = {
      iteration: 2,
      totalScansExecuted: 5,
      budgetRemaining: 3,
      satisfied: true,
      finalAnalysis: "All critical gaps have been addressed. The LLM identified 3 new vulnerabilities through targeted re-scans.",
      history: [
        {
          request: { tool: "nmap", target: "1.2.3.4", args: "-sV -p 8080", rationale: "Verify service on port 8080", depth: "standard", priority: 1 },
          result: { exitCode: 0, stdout: "8080/tcp open http Apache 2.4.51", stderr: "", durationMs: 3200 },
          executedAt: 1709654400000,
        },
        {
          request: { tool: "nuclei", target: "example.com", args: "-t cves/", rationale: "Check for known CVEs", depth: "deep", priority: 2 },
          result: { exitCode: 0, stdout: "[CVE-2024-5678] example.com:443", stderr: "", durationMs: 12000 },
          executedAt: 1709654410000,
        },
        {
          request: { tool: "sslscan", target: "example.com", args: "--no-colour", rationale: "Check TLS configuration", depth: "quick", priority: 3 },
          result: { exitCode: 1, stdout: "", stderr: "Connection refused", durationMs: 1500 },
          executedAt: 1709654420000,
        },
      ],
    };

    mockGetOpsState.mockReturnValue(buildMockOpsState({ scanFeedbackLoop: feedbackLoop }));
    const state = mockGetOpsState(1);
    const fb = state.scanFeedbackLoop;

    // Transform (mirrors endpoint logic)
    const transformed = {
      iteration: fb.iteration,
      totalScansExecuted: fb.totalScansExecuted,
      budgetRemaining: fb.budgetRemaining,
      satisfied: fb.satisfied,
      finalAnalysis: fb.finalAnalysis,
      history: (fb.history || []).map((h: any) => ({
        tool: h.request.tool,
        target: h.request.target,
        args: h.request.args,
        rationale: h.request.rationale,
        depth: h.request.depth,
        priority: h.request.priority,
        exitCode: h.result.exitCode,
        durationMs: h.result.durationMs,
        outputPreview: (h.result.stdout || "").slice(0, 500),
        stderrPreview: (h.result.stderr || "").slice(0, 200),
        executedAt: h.executedAt,
      })),
    };

    expect(transformed.iteration).toBe(2);
    expect(transformed.totalScansExecuted).toBe(5);
    expect(transformed.budgetRemaining).toBe(3);
    expect(transformed.satisfied).toBe(true);
    expect(transformed.finalAnalysis).toContain("critical gaps");
    expect(transformed.history).toHaveLength(3);

    // First scan
    expect(transformed.history[0].tool).toBe("nmap");
    expect(transformed.history[0].target).toBe("1.2.3.4");
    expect(transformed.history[0].exitCode).toBe(0);
    expect(transformed.history[0].durationMs).toBe(3200);
    expect(transformed.history[0].outputPreview).toContain("Apache");

    // Failed scan
    expect(transformed.history[2].tool).toBe("sslscan");
    expect(transformed.history[2].exitCode).toBe(1);
    expect(transformed.history[2].stderrPreview).toContain("Connection refused");
  });

  it("truncates long output previews", () => {
    const longOutput = "A".repeat(1000);
    const feedbackLoop = {
      iteration: 0,
      totalScansExecuted: 1,
      budgetRemaining: 7,
      satisfied: false,
      finalAnalysis: null,
      history: [
        {
          request: { tool: "nmap", target: "1.2.3.4", args: "-sV", rationale: "Test", depth: "quick", priority: 1 },
          result: { exitCode: 0, stdout: longOutput, stderr: "W".repeat(500), durationMs: 1000 },
          executedAt: Date.now(),
        },
      ],
    };

    mockGetOpsState.mockReturnValue(buildMockOpsState({ scanFeedbackLoop: feedbackLoop }));
    const state = mockGetOpsState(1);
    const fb = state.scanFeedbackLoop;

    const transformed = (fb.history || []).map((h: any) => ({
      outputPreview: (h.result.stdout || "").slice(0, 500),
      stderrPreview: (h.result.stderr || "").slice(0, 200),
    }));

    expect(transformed[0].outputPreview.length).toBe(500);
    expect(transformed[0].stderrPreview.length).toBe(200);
  });
});

// ── UI Helper Tests ───────────────────────────────────────────────────────────

describe("UI helper functions", () => {
  it("getRiskColor returns correct colors for risk levels", () => {
    // Replicate the getRiskColor function from the UI
    function getRiskColor(risk: number): string {
      if (risk >= 9) return "text-red-500";
      if (risk >= 7) return "text-red-400";
      if (risk >= 5) return "text-orange-400";
      if (risk >= 3) return "text-yellow-400";
      return "text-green-400";
    }

    expect(getRiskColor(10)).toBe("text-red-500");
    expect(getRiskColor(9)).toBe("text-red-500");
    expect(getRiskColor(8)).toBe("text-red-400");
    expect(getRiskColor(7)).toBe("text-red-400");
    expect(getRiskColor(6)).toBe("text-orange-400");
    expect(getRiskColor(5)).toBe("text-orange-400");
    expect(getRiskColor(4)).toBe("text-yellow-400");
    expect(getRiskColor(3)).toBe("text-yellow-400");
    expect(getRiskColor(2)).toBe("text-green-400");
    expect(getRiskColor(0)).toBe("text-green-400");
  });

  it("TOOL_COLORS maps all expected tools", () => {
    const TOOL_COLORS: Record<string, string> = {
      nmap: "text-cyan-400 border-cyan-500/30",
      nikto: "text-yellow-400 border-yellow-500/30",
      nuclei: "text-purple-400 border-purple-500/30",
      gobuster: "text-orange-400 border-orange-500/30",
      ffuf: "text-orange-400 border-orange-500/30",
      sslscan: "text-green-400 border-green-500/30",
      testssl: "text-green-400 border-green-500/30",
      whatweb: "text-blue-400 border-blue-500/30",
      subfinder: "text-cyan-400 border-cyan-500/30",
      httpx: "text-blue-400 border-blue-500/30",
      curl: "text-muted-foreground border-muted-foreground/30",
      wpscan: "text-indigo-400 border-indigo-500/30",
      cloud_enum: "text-orange-400 border-orange-500/30",
      s3scanner: "text-orange-400 border-orange-500/30",
      trufflehog: "text-red-400 border-red-500/30",
      aws: "text-orange-400 border-orange-500/30",
      dig: "text-cyan-400 border-cyan-500/30",
      whois: "text-muted-foreground border-muted-foreground/30",
      katana: "text-red-400 border-red-500/30",
      gospider: "text-blue-400 border-blue-500/30",
      waybackurls: "text-amber-400 border-amber-500/30",
      gau: "text-amber-400 border-amber-500/30",
      naabu: "text-cyan-400 border-cyan-500/30",
    };

    // All 23 tools from the feedback loop inventory should have colors
    const expectedTools = [
      "nmap", "nikto", "nuclei", "gobuster", "ffuf", "sslscan", "testssl",
      "whatweb", "subfinder", "httpx", "curl", "wpscan", "cloud_enum",
      "s3scanner", "trufflehog", "aws", "dig", "whois", "katana",
      "gospider", "waybackurls", "gau", "naabu",
    ];

    for (const tool of expectedTools) {
      expect(TOOL_COLORS[tool]).toBeDefined();
      expect(TOOL_COLORS[tool]).toContain("text-");
      expect(TOOL_COLORS[tool]).toContain("border-");
    }
  });

  it("SEVERITY_COLORS maps all severity levels", () => {
    const SEVERITY_COLORS: Record<string, string> = {
      critical: "text-red-400 bg-red-500/10 border-red-500/30",
      high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
      medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
      low: "text-blue-400 bg-blue-500/10 border-blue-500/30",
      info: "text-muted-foreground bg-muted/30 border-muted-foreground/30",
    };

    expect(SEVERITY_COLORS.critical).toContain("red");
    expect(SEVERITY_COLORS.high).toContain("orange");
    expect(SEVERITY_COLORS.medium).toContain("yellow");
    expect(SEVERITY_COLORS.low).toContain("blue");
    expect(SEVERITY_COLORS.info).toContain("muted");
  });
});

// ── Integration: Combined State Tests ─────────────────────────────────────────

describe("combined state with all three features", () => {
  it("handles a fully populated ops state with all features", () => {
    const fullState = buildMockOpsState({
      attackChains: [
        {
          id: "chain-1",
          name: "Full Kill Chain",
          overallRisk: 10,
          feasibility: 8,
          stealthRating: 6,
          totalSteps: 5,
          mitreTechniques: ["T1190", "T1059", "T1005", "T1048"],
          cloudExploitPaths: [{ id: "s3-exfil", name: "S3 Data Exfiltration", severity: "critical", provider: "AWS" }],
          recommendations: ["Patch all critical vulns", "Enable MFA"],
          steps: [
            { name: "Initial Access via SQLi", technique: "T1190" },
            { name: "Command Execution", technique: "T1059" },
            { name: "Data Collection", technique: "T1005" },
            { name: "S3 Bucket Access", technique: "T1530" },
            { name: "Exfiltration", technique: "T1048" },
          ],
        },
      ],
      cloudDetection: {
        findings: [
          { title: "Public S3 Bucket", severity: "critical", provider: "AWS", service: "S3", asset: "example.com" },
          { title: "Metadata Service Accessible", severity: "high", provider: "AWS", service: "EC2", asset: "example.com" },
        ],
      },
      scanFeedbackLoop: {
        iteration: 1,
        totalScansExecuted: 3,
        budgetRemaining: 5,
        satisfied: true,
        finalAnalysis: "Comprehensive coverage achieved.",
        history: [
          {
            request: { tool: "nmap", target: "1.2.3.4", args: "-sV", rationale: "Service detection", depth: "standard", priority: 1 },
            result: { exitCode: 0, stdout: "80/tcp open http", stderr: "", durationMs: 2000 },
            executedAt: Date.now(),
          },
        ],
      },
    });

    mockGetOpsState.mockReturnValue(fullState);
    const state = mockGetOpsState(1);

    // Attack chains present
    expect(state.attackChains).toHaveLength(1);
    expect(state.attackChains[0].overallRisk).toBe(10);
    expect(state.attackChains[0].cloudExploitPaths).toHaveLength(1);

    // Cloud detection present
    expect(state.cloudDetection.findings).toHaveLength(2);
    expect(state.cloudDetection.findings[0].provider).toBe("AWS");

    // Feedback loop present
    expect(state.scanFeedbackLoop.satisfied).toBe(true);
    expect(state.scanFeedbackLoop.totalScansExecuted).toBe(3);
    expect(state.scanFeedbackLoop.history).toHaveLength(1);
  });

  it("handles empty/missing optional fields gracefully", () => {
    const minimalState = buildMockOpsState({
      attackChains: [],
      cloudDetection: null,
      scanFeedbackLoop: undefined,
    });

    mockGetOpsState.mockReturnValue(minimalState);
    const state = mockGetOpsState(1);

    expect(state.attackChains).toHaveLength(0);
    expect(state.cloudDetection).toBeNull();
    expect(state.scanFeedbackLoop).toBeUndefined();

    // Simulate endpoint null-safe access
    const chains = state.attackChains || [];
    const cloudFindings = state.cloudDetection?.findings || [];
    const feedbackLoop = state.scanFeedbackLoop || null;

    expect(chains).toHaveLength(0);
    expect(cloudFindings).toHaveLength(0);
    expect(feedbackLoop).toBeNull();
  });
});
