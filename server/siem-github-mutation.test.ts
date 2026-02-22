/**
 * Tests for:
 *   1. SIEM Connectors — connection config, alert normalization, detection correlation
 *   2. Mutation Test — Sigma rule mutation testing (Tier 1 evasion engine)
 *   3. GitHub Code Leak Connector — observation builder, leak pattern coverage
 */
import { describe, expect, it } from "vitest";

// ═══════════════════════════════════════════════════════════════════════
// §1 — SIEM CONNECTORS
// ═══════════════════════════════════════════════════════════════════════

import {
  testSiemConnection,
  correlateDetections,
  computeDetectionStats,
  summarizeAlerts,
  type SiemConnectionConfig,
  type NormalizedSiemAlert,
} from "./lib/siem-connectors";

describe("SIEM Connectors", () => {
  describe("testSiemConnection", () => {
    it("returns error for unreachable Wazuh endpoint", async () => {
      const config: SiemConnectionConfig = {
        backend: "wazuh",
        baseUrl: "https://127.0.0.1:55000",
        username: "admin",
        password: "admin",
        insecure: true,
        timeout: 3000,
      };

      const result = await testSiemConnection(config);
      expect(result.connected).toBe(false);
      expect(result.error).toBeDefined();
      expect(typeof result.error).toBe("string");
    });

    it("returns error for unreachable Elastic endpoint", async () => {
      const config: SiemConnectionConfig = {
        backend: "elastic",
        baseUrl: "https://127.0.0.1:9200",
        apiKey: "test-key",
        insecure: true,
        timeout: 3000,
      };

      const result = await testSiemConnection(config);
      expect(result.connected).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe("correlateDetections", () => {
    const mockAlerts: NormalizedSiemAlert[] = [
      {
        alertId: "alert-1",
        backend: "wazuh",
        timestamp: Date.now() - 60000,
        severity: "high",
        severityScore: 70,
        title: "Suspicious PowerShell Execution",
        description: "Encoded PowerShell command detected",
        mitreTechniques: ["T1059.001"],
        mitreTactics: ["execution"],
        ruleId: "rule-001",
        ruleName: "win_susp_powershell_enc_cmd",
        agentName: "WIN-DC01",
        rawData: {},
      },
      {
        alertId: "alert-2",
        backend: "elastic",
        timestamp: Date.now() - 30000,
        severity: "critical",
        severityScore: 90,
        title: "Credential Dumping via LSASS",
        description: "LSASS memory access detected",
        mitreTechniques: ["T1003.001"],
        mitreTactics: ["credential-access"],
        ruleId: "rule-002",
        ruleName: "credential_access_lsass",
        agentName: "WIN-DC01",
        rawData: {},
      },
      {
        alertId: "alert-3",
        backend: "wazuh",
        timestamp: Date.now() - 10000,
        severity: "medium",
        severityScore: 50,
        title: "Lateral Movement via WMI",
        description: "WMI process creation on remote host",
        mitreTechniques: ["T1047"],
        mitreTactics: ["execution"],
        ruleId: "rule-003",
        ruleName: "win_wmi_lateral",
        agentName: "WIN-SRV02",
        rawData: {},
      },
    ];

    it("correlates techniques with matching alerts", () => {
      const techniques = ["T1059.001", "T1003.001", "T1047", "T1021.002"];
      const correlations = correlateDetections(techniques, mockAlerts);

      expect(correlations).toHaveLength(4);

      const psCorrelation = correlations.find((c) => c.techniqueId === "T1059.001");
      expect(psCorrelation?.detected).toBe(true);
      expect(psCorrelation?.alertCount).toBe(1);
      expect(psCorrelation?.maxSeverity).toBe("high");

      const lsassCorrelation = correlations.find((c) => c.techniqueId === "T1003.001");
      expect(lsassCorrelation?.detected).toBe(true);
      expect(lsassCorrelation?.maxSeverity).toBe("critical");

      // T1021.002 has no matching alerts
      const smbCorrelation = correlations.find((c) => c.techniqueId === "T1021.002");
      expect(smbCorrelation?.detected).toBe(false);
      expect(smbCorrelation?.alertCount).toBe(0);
    });

    it("handles empty alerts gracefully", () => {
      const correlations = correlateDetections(["T1059.001", "T1003.001"], []);
      expect(correlations).toHaveLength(2);
      expect(correlations.every((c) => !c.detected)).toBe(true);
    });

    it("handles empty techniques gracefully", () => {
      const correlations = correlateDetections([], mockAlerts);
      expect(correlations).toHaveLength(0);
    });
  });

  describe("computeDetectionStats", () => {
    it("computes correct coverage statistics", () => {
      const correlations = [
        { techniqueId: "T1059.001", detected: true, alertCount: 2, maxSeverity: "high" as const, detectionRules: ["rule-1"], sampleAlertIds: ["a1"], timeToDetection: undefined },
        { techniqueId: "T1003.001", detected: true, alertCount: 1, maxSeverity: "critical" as const, detectionRules: ["rule-2"], sampleAlertIds: ["a2"], timeToDetection: undefined },
        { techniqueId: "T1021.002", detected: false, alertCount: 0, maxSeverity: "none" as const, detectionRules: [], sampleAlertIds: [], timeToDetection: undefined },
        { techniqueId: "T1047", detected: false, alertCount: 0, maxSeverity: "none" as const, detectionRules: [], sampleAlertIds: [], timeToDetection: undefined },
      ];

      const stats = computeDetectionStats(correlations);
      expect(stats.totalTechniques).toBe(4);
      expect(stats.detectedTechniques).toBe(2);
      expect(stats.undetectedTechniques).toBe(2);
      expect(stats.coveragePercent).toBe(50);
      expect(stats.detectionGaps).toContain("T1021.002");
      expect(stats.detectionGaps).toContain("T1047");
    });

    it("handles 100% coverage", () => {
      const correlations = [
        { techniqueId: "T1059.001", detected: true, alertCount: 1, maxSeverity: "high" as const, detectionRules: ["r1"], sampleAlertIds: ["a1"], timeToDetection: undefined },
      ];
      const stats = computeDetectionStats(correlations);
      expect(stats.coveragePercent).toBe(100);
      expect(stats.detectionGaps).toHaveLength(0);
    });

    it("handles 0% coverage", () => {
      const correlations = [
        { techniqueId: "T1059.001", detected: false, alertCount: 0, maxSeverity: "none" as const, detectionRules: [], sampleAlertIds: [], timeToDetection: undefined },
      ];
      const stats = computeDetectionStats(correlations);
      expect(stats.coveragePercent).toBe(0);
      expect(stats.detectionGaps).toContain("T1059.001");
    });
  });

  describe("summarizeAlerts", () => {
    it("summarizes alerts by severity and backend", () => {
      const alerts: NormalizedSiemAlert[] = [
        { alertId: "1", backend: "wazuh", timestamp: Date.now(), severity: "high", severityScore: 70, title: "A", description: "", mitreTechniques: [], mitreTactics: [], ruleId: "1", ruleName: "r1", agentName: "a1", rawData: {} },
        { alertId: "2", backend: "elastic", timestamp: Date.now(), severity: "critical", severityScore: 90, title: "B", description: "", mitreTechniques: [], mitreTactics: [], ruleId: "2", ruleName: "r2", agentName: "a1", rawData: {} },
        { alertId: "3", backend: "wazuh", timestamp: Date.now(), severity: "high", severityScore: 70, title: "C", description: "", mitreTechniques: ["T1059"], mitreTactics: ["execution"], ruleId: "3", ruleName: "r3", agentName: "a2", rawData: {} },
      ];

      const summary = summarizeAlerts(alerts);
      expect(summary.totalAlerts).toBe(3);
      expect(summary.bySeverity.high).toBe(2);
      expect(summary.bySeverity.critical).toBe(1);
      expect(summary.byBackend.wazuh).toBe(2);
      expect(summary.byBackend.elastic).toBe(1);
    });

    it("handles empty alerts", () => {
      const summary = summarizeAlerts([]);
      expect(summary.totalAlerts).toBe(0);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §2 — MUTATION TEST (Tier 1 Evasion Engine)
// ═══════════════════════════════════════════════════════════════════════

import {
  testRawPatternMutations,
  parseSigmaRule,
  testRuleMutations,
  generateMutations,
} from "./lib/siem-mutation-engine";

describe("Mutation Test Engine", () => {
  describe("testRawPatternMutations", () => {
    it("generates mutation variants and tests against a pattern", () => {
      const result = testRawPatternMutations(
        "powershell.exe -enc SQBFAFgA",
        "powershell.*-enc"
      );

      expect(result.originalCommand).toBe("powershell.exe -enc SQBFAFgA");
      expect(result.detectionPattern).toBe("powershell.*-enc");
      expect(result.totalVariants).toBeGreaterThan(0);
      expect(result.robustnessScore).toBeGreaterThanOrEqual(0);
      expect(result.robustnessScore).toBeLessThanOrEqual(100);
      expect(["robust", "moderate", "fragile", "bypassed"]).toContain(result.robustnessClass);
      expect(result.detectedCount + result.evadedCount).toBe(result.totalVariants);
    });

    it("handles simple string pattern", () => {
      const result = testRawPatternMutations("whoami", "whoami");
      expect(result.totalVariants).toBeGreaterThan(0);
    });
  });

  describe("parseSigmaRule", () => {
    it("parses a valid Sigma rule YAML", () => {
      const yaml = `title: Suspicious PowerShell Execution
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection`;
      const rule = parseSigmaRule(yaml);
      expect(rule.title).toBe("Suspicious PowerShell Execution");
      expect(rule.detectionPatterns.length).toBeGreaterThan(0);
    });
  });

  describe("testRuleMutations", () => {
    it("tests a command against a parsed Sigma rule", () => {
      const yaml = `title: Test Rule
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'mimikatz'
  condition: selection`;
      const rule = parseSigmaRule(yaml);
      const result = testRuleMutations("mimikatz.exe sekurlsa::logonpasswords", rule);

      expect(result.originalCommand).toBe("mimikatz.exe sekurlsa::logonpasswords");
      expect(result.totalVariants).toBeGreaterThan(0);
      expect(result.robustnessScore).toBeGreaterThanOrEqual(0);
    });
  });

  describe("generateMutations", () => {
    it("generates mutation variants for a command", () => {
      const variants = generateMutations("net user /domain");
      expect(variants.length).toBeGreaterThan(0);
      expect(variants[0]).toHaveProperty("category");
      expect(variants[0]).toHaveProperty("command");
    });

    it("respects maxPerCategory limit", () => {
      const variants = generateMutations("whoami", { maxPerCategory: 2 });
      const categoryCounts: Record<string, number> = {};
      for (const v of variants) {
        categoryCounts[v.category] = (categoryCounts[v.category] || 0) + 1;
      }
      for (const count of Object.values(categoryCounts)) {
        expect(count).toBeLessThanOrEqual(2);
      }
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §3 — GITHUB CODE LEAK CONNECTOR
// ═══════════════════════════════════════════════════════════════════════

import {
  githubLeaksConnector,
  summarizeGitHubLeaks,
  getLeakPatterns,
} from "./lib/passive/github-leaks";

describe("GitHub Code Leak Connector", () => {
  describe("connector metadata", () => {
    it("has correct name and description", () => {
      expect(githubLeaksConnector.name).toBe("github_leaks");
      expect(githubLeaksConnector.description).toContain("GitHub");
      expect(githubLeaksConnector.description).toContain("Priority #10");
    });

    it("has a collect function", () => {
      expect(typeof githubLeaksConnector.collect).toBe("function");
    });
  });

  describe("getLeakPatterns", () => {
    it("returns all leak search patterns", () => {
      const patterns = getLeakPatterns();
      expect(patterns.length).toBeGreaterThanOrEqual(10);

      // Check structure
      for (const p of patterns) {
        expect(p).toHaveProperty("id");
        expect(p).toHaveProperty("name");
        expect(p).toHaveProperty("description");
        expect(p).toHaveProperty("severity");
        expect(p).toHaveProperty("tags");
        expect(["critical", "high", "medium", "low"]).toContain(p.severity);
      }
    });

    it("covers critical leak categories", () => {
      const patterns = getLeakPatterns();
      const ids = patterns.map((p) => p.id);
      expect(ids).toContain("env_files");
      expect(ids).toContain("api_keys");
      expect(ids).toContain("passwords");
      expect(ids).toContain("ssh_keys");
      expect(ids).toContain("database_strings");
    });
  });

  describe("summarizeGitHubLeaks", () => {
    it("summarizes observations by severity and category", () => {
      const mockObservations = [
        {
          assetId: "obs-1",
          domain: "example.com",
          assetType: "url" as const,
          name: "[Environment Files (.env)] user/repo/path",
          source: "github_leaks",
          observedAt: new Date(),
          lastSeen: new Date(),
          tags: ["github", "code_leak", "env_file", "severity:critical"],
          evidence: {
            patternId: "env_files",
            patternName: "Environment Files (.env)",
            severity: "critical",
            repository: "user/repo",
            repoUrl: "https://github.com/user/repo",
            repoOwner: "user",
          },
          attribution: {
            provider: "GitHub Code Search API",
            method: "test",
            url: "https://github.com/user/repo/blob/main/.env",
          },
        },
        {
          assetId: "obs-2",
          domain: "example.com",
          assetType: "url" as const,
          name: "[API Keys & Tokens] other/project/config.js",
          source: "github_leaks",
          observedAt: new Date(),
          lastSeen: new Date(),
          tags: ["github", "code_leak", "api_key_leak", "severity:critical"],
          evidence: {
            patternId: "api_keys",
            patternName: "API Keys & Tokens",
            severity: "critical",
            repository: "other/project",
            repoUrl: "https://github.com/other/project",
            repoOwner: "other",
          },
          attribution: {
            provider: "GitHub Code Search API",
            method: "test",
            url: "https://github.com/other/project/blob/main/config.js",
          },
        },
        {
          assetId: "obs-3",
          domain: "example.com",
          assetType: "url" as const,
          name: "[Internal IP Addresses] team/infra/network.conf",
          source: "github_leaks",
          observedAt: new Date(),
          lastSeen: new Date(),
          tags: ["github", "code_leak", "internal_ip", "severity:medium"],
          evidence: {
            patternId: "internal_ips",
            patternName: "Internal IP Addresses",
            severity: "medium",
            repository: "team/infra",
            repoUrl: "https://github.com/team/infra",
            repoOwner: "team",
          },
          attribution: {
            provider: "GitHub Code Search API",
            method: "test",
            url: "https://github.com/team/infra/blob/main/network.conf",
          },
        },
      ];

      const summary = summarizeGitHubLeaks(mockObservations as any);
      expect(summary.totalFindings).toBe(3);
      expect(summary.bySeverity.critical).toBe(2);
      expect(summary.bySeverity.medium).toBe(1);
      expect(summary.uniqueRepos).toBe(3);
      expect(summary.uniqueOwners).toBe(3);
      expect(summary.riskScore).toBeGreaterThan(0);
      expect(["critical", "high", "medium", "low"]).toContain(summary.riskBand);
    });

    it("handles empty observations", () => {
      const summary = summarizeGitHubLeaks([]);
      expect(summary.totalFindings).toBe(0);
      expect(summary.riskScore).toBe(0);
      expect(summary.riskBand).toBe("low");
    });
  });

  describe("collect (rate-limited, uses real API)", () => {
    it("returns a valid ConnectorResult structure for a non-existent domain", async () => {
      // Use a domain unlikely to have results to avoid rate limits
      const result = await githubLeaksConnector.collect(
        "zzz-nonexistent-test-domain-12345.invalid",
        { timeout: 8000, maxResults: 5 }
      );

      expect(result.connector).toBe("github_leaks");
      expect(result.domain).toBe("zzz-nonexistent-test-domain-12345.invalid");
      expect(Array.isArray(result.observations)).toBe(true);
      expect(Array.isArray(result.errors)).toBe(true);
      expect(typeof result.durationMs).toBe("number");
    }, 30000); // 30s timeout for network test
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §4 — RED TEAM PRIORITY #10 REGISTRATION
// ═══════════════════════════════════════════════════════════════════════

import { RED_TEAM_PRIORITIES } from "./lib/redteam-discovery-coverage";

describe("Red Team Priority #10 Registration", () => {
  it("priority #10 now has github_leaks connector registered", () => {
    const priority10 = RED_TEAM_PRIORITIES.find((p) => p.id === 10);
    expect(priority10).toBeDefined();
    expect(priority10!.name).toContain("Code Repositories");
    expect(priority10!.connectors).toContain("github_leaks");
  });

  it("no more structural gaps for priority #10", () => {
    const priority10 = RED_TEAM_PRIORITIES.find((p) => p.id === 10);
    expect(priority10!.connectors.length).toBeGreaterThan(0);
  });
});
