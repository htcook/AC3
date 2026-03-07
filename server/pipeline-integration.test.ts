import { describe, it, expect, vi } from "vitest";

// ── Functional Exploit Generator Tests ──────────────────────────────────────

describe("Functional Exploit Generator", () => {
  it("exports all required functions", async () => {
    const mod = await import("./lib/functional-exploit-generator");
    expect(typeof mod.generateFunctionalExploit).toBe("function");
    expect(typeof mod.validateExploitCode).toBe("function");
    expect(typeof mod.improveExploit).toBe("function");
    expect(typeof mod.generateExploitsForAsset).toBe("function");
  });

  it("ExploitContext interface has all required fields", async () => {
    const mod = await import("./lib/functional-exploit-generator");
    // Verify we can construct a valid ExploitContext
    const ctx: import("./lib/functional-exploit-generator").ExploitContext = {
      vulnerability: {
        title: "SQL Injection",
        severity: "critical",
        cve: "CVE-2024-1234",
        description: "SQL injection in login form",
        service: "http",
        port: 80,
        rawOutput: "sqlmap found injectable param",
        tool: "sqlmap",
      },
      target: {
        hostname: "test.example.com",
        ip: "192.168.1.1",
        os: "Linux",
        technologies: ["Apache", "PHP", "MySQL"],
        wafDetected: "none",
        ports: [
          { port: 80, service: "http", version: "Apache 2.4.41" },
          { port: 443, service: "https" },
          { port: 3306, service: "mysql", version: "5.7.32" },
        ],
      },
      exploitPlan: {
        selectedModule: "exploit/multi/http/sqli_injection",
        preflightChecks: [{ name: "port_open", command: "nc -zv test.example.com 80" }],
        executionSteps: [
          { action: "enumerate", command: "sqlmap -u ...", description: "Enumerate databases" },
        ],
        payloadConfig: { RHOSTS: "test.example.com", RPORT: 80 },
        evasionRecommendations: ["Use time-based blind injection"],
        reasoning: "SQL injection is the most direct attack vector",
      },
      scanResults: [
        { tool: "nmap", output: "80/tcp open http Apache 2.4.41", exitCode: 0 },
        { tool: "sqlmap", output: "Parameter 'id' is vulnerable", exitCode: 0 },
      ],
      otherVulns: [
        { title: "XSS in search", severity: "medium", port: 80 },
      ],
      preferredLanguage: "python",
      includeEvasion: true,
      includeCleanup: false,
    };
    expect(ctx.vulnerability.title).toBe("SQL Injection");
    expect(ctx.target.hostname).toBe("test.example.com");
    expect(ctx.preferredLanguage).toBe("python");
  });

  it("GeneratedExploit interface has all required fields", async () => {
    const exploit: import("./lib/functional-exploit-generator").GeneratedExploit = {
      code: "#!/usr/bin/env python3\nimport requests\n...",
      language: "python",
      filename: "sqli_exploit_test_example_com.py",
      description: "SQL injection exploit targeting login form",
      explanation: ["Step 1: Send crafted payload", "Step 2: Extract data"],
      prerequisites: ["Python 3", "requests library"],
      usage: "python3 sqli_exploit.py --target test.example.com",
      expectedOutcome: "Database contents extracted",
      riskAssessment: {
        opsecRisk: 5,
        detectionLikelihood: "medium",
        iocSignatures: ["SQL error in response"],
        mitigations: ["Use parameterized queries"],
      },
      verificationSteps: ["Check if data was extracted"],
      confidence: 85,
      reasoning: "Direct SQL injection with known vulnerable parameter",
      isChained: false,
      mitreTechniques: ["T1190", "T1059"],
    };
    expect(exploit.language).toBe("python");
    expect(exploit.confidence).toBeGreaterThanOrEqual(0);
    expect(exploit.confidence).toBeLessThanOrEqual(100);
    expect(exploit.riskAssessment.opsecRisk).toBeGreaterThanOrEqual(1);
    expect(exploit.mitreTechniques.length).toBeGreaterThan(0);
  });

  it("ExploitValidation interface has all required fields", async () => {
    const validation: import("./lib/functional-exploit-generator").ExploitValidation = {
      isValid: true,
      isSafe: true,
      issues: [],
      suggestions: ["Add timeout handling"],
      codeQuality: "high",
      wouldWork: "likely",
      reasoning: "Code is well-structured and targets known vulnerability",
    };
    expect(validation.isValid).toBe(true);
    expect(["high", "medium", "low"]).toContain(validation.codeQuality);
    expect(["likely", "possible", "unlikely"]).toContain(validation.wouldWork);
  });
});

// ── Unified Pipeline Tests ──────────────────────────────────────────────────

describe("Unified Pipeline", () => {
  it("exports all required functions and constants", async () => {
    const mod = await import("./lib/unified-pipeline");
    expect(typeof mod.correlateFindings).toBe("function");
    expect(typeof mod.getPhaseTools).toBe("function");
    expect(typeof mod.generatePipelineSummary).toBe("function");
    expect(typeof mod.generateTimelineEvents).toBe("function");
    expect(Array.isArray(mod.PIPELINE_STAGES)).toBe(true);
  });

  it("PIPELINE_STAGES has stages with required fields", async () => {
    const { PIPELINE_STAGES } = await import("./lib/unified-pipeline");
    expect(PIPELINE_STAGES.length).toBeGreaterThan(0);
    for (const stage of PIPELINE_STAGES) {
      expect(stage).toHaveProperty("phase");
      expect(stage).toHaveProperty("description");
      expect(stage).toHaveProperty("tools");
    }
  });

  it("getPhaseTools returns tools for a given phase", async () => {
    const { getPhaseTools, PIPELINE_STAGES } = await import("./lib/unified-pipeline");
    const firstPhase = PIPELINE_STAGES[0].phase;
    const tools = getPhaseTools(firstPhase);
    expect(Array.isArray(tools)).toBe(true);
  });
});

// ── LLM Scan Feedback Loop Tests ────────────────────────────────────────────

describe("LLM Scan Feedback Loop", () => {
  it("exports all required functions", async () => {
    const mod = await import("./lib/llm-scan-feedback");
    expect(typeof mod.analyzeFindingsAndRequestScans).toBe("function");
    expect(typeof mod.runFeedbackLoop).toBe("function");
  });
});

// ── Exploitation Bridge Tests ───────────────────────────────────────────────

describe("Exploitation Bridge", () => {
  it("exports all required functions", async () => {
    const mod = await import("./lib/exploitation-bridge");
    expect(typeof mod.generateExploitPlan).toBe("function");
    expect(typeof mod.deterministicGenerateExploitPlan).toBe("function");
  });

  it("buildDeterministicPlan generates a plan from vulnerability data", async () => {
    const { deterministicGenerateExploitPlan } = await import("./lib/exploitation-bridge");
    const plan = deterministicGenerateExploitPlan({
      cve: "CVE-2021-44228",
      title: "Log4Shell RCE",
      cvss: 10.0,
      service: "http",
      port: 8080,
      targetIp: "192.168.1.100",
      targetOs: "Linux",
    });
    expect(plan).toBeDefined();
    expect(plan).toHaveProperty("selectedExploit");
    expect(plan).toHaveProperty("preflightChecks");
    expect(plan).toHaveProperty("executionSteps");
  });
});

// ── LLM Post-Enrichment Analysis Tests ──────────────────────────────────────

describe("LLM Post-Enrichment Analysis", () => {
  it("exports all required functions", async () => {
    const mod = await import("./lib/llm-post-enrichment-analysis");
    expect(typeof mod.runPostEnrichmentAnalysis).toBe("function");
  });
});

// ── Vulnerability Analysis Agents Tests ─────────────────────────────────────

describe("Vulnerability Analysis Agents", () => {
  it("exports all required functions", async () => {
    const mod = await import("./lib/vuln-analysis-agents");
    expect(typeof mod.analyzeVulnerability).toBe("function");
    expect(typeof mod.batchAnalyzeFindings).toBe("function");
    expect(typeof mod.classifyVulnerability).toBe("function");
    expect(typeof mod.generateAnalysisSummary).toBe("function");
  });
});

// ── Engagement Orchestrator Tests ───────────────────────────────────────────

describe("Engagement Orchestrator", () => {
  it("exports all required functions", async () => {
    const mod = await import("./lib/engagement-orchestrator");
    expect(typeof mod.executeEngagement).toBe("function");
  });
});

// ── Exploitation Bridge Engine Tests ────────────────────────────────────────

describe("Exploitation Bridge Engine", () => {
  it("exports all required functions", async () => {
    const mod = await import("./lib/exploitation-bridge-engine");
    expect(typeof mod.generateExploitPlan).toBe("function");
    expect(typeof mod.deterministicGenerateExploitPlan).toBe("function");
    expect(typeof mod.lookupExploitsForCve).toBe("function");
    expect(typeof mod.getKnownExploitableCves).toBe("function");
  });
});
