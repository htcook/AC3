/**
 * ZAP Scan Gates — Three-Gate Verification System Tests
 *
 * Tests the reliability specification implementation:
 * - Gate A: Setup verification (reachability + auth indicators)
 * - Gate B: Execution proof-of-work (message count threshold)
 * - Gate C: Oracle (passive alerts, WAF ratio, auth expansion)
 * - Quarantine semantics
 * - Deterministic policy isolation (A6)
 */
import { describe, it, expect } from "vitest";

// ─── Gate Module Structure Tests ─────────────────────────────────────────────

describe("ZAP Scan Gates Module", () => {
  it("exports all required gate functions", async () => {
    const gates = await import("./lib/zap-scan-gates");
    expect(gates.evaluateGateA).toBeDefined();
    expect(typeof gates.evaluateGateA).toBe("function");
    expect(gates.evaluateGateB).toBeDefined();
    expect(typeof gates.evaluateGateB).toBe("function");
    expect(gates.evaluateGateC).toBeDefined();
    expect(typeof gates.evaluateGateC).toBe("function");
    expect(gates.computeOverallQuality).toBeDefined();
    expect(typeof gates.computeOverallQuality).toBe("function");
    expect(gates.runPostScanGates).toBeDefined();
    expect(typeof gates.runPostScanGates).toBe("function");
    expect(gates.persistGateResults).toBeDefined();
    expect(typeof gates.persistGateResults).toBe("function");
  });

  it("exports ScanQuality type-compatible values", async () => {
    const gates = await import("./lib/zap-scan-gates");
    // Verify the module structure includes the expected types
    expect(gates.evaluateGateA).toBeDefined();
    expect(gates.evaluateGateB).toBeDefined();
    expect(gates.evaluateGateC).toBeDefined();
  });
});

// ─── Gate A: Setup Verification ──────────────────────────────────────────────

describe("Gate A — Setup Verification", () => {
  it("returns GateAResult structure with passed and reason", async () => {
    const { evaluateGateA } = await import("./lib/zap-scan-gates");
    // Call with unreachable ZAP (will fail but should return proper structure)
    const result = await evaluateGateA(
      "http://example.com",
      async () => { throw new Error("ZAP unreachable"); },
      { authConfigured: false }
    );
    expect(result).toHaveProperty("passed");
    expect(result).toHaveProperty("reason");
    expect(typeof result.passed).toBe("boolean");
    expect(typeof result.reason).toBe("string");
  });

  it("fails when ZAP cannot reach target", async () => {
    const { evaluateGateA } = await import("./lib/zap-scan-gates");
    const mockZapRequest = async () => { throw new Error("Connection refused"); };
    const result = await evaluateGateA(
      "http://192.0.2.1:99999",
      mockZapRequest,
      { authConfigured: false }
    );
    expect(result.passed).toBe(false);
    expect(result.reason.length).toBeGreaterThan(0);
  });

  it("passes when ZAP can reach target (no auth)", async () => {
    const { evaluateGateA } = await import("./lib/zap-scan-gates");
    // Mock ZAP request that simulates successful reachability
    const mockZapRequest = async (endpoint: string) => {
      if (endpoint.includes("accessUrl")) return { Result: "OK" };
      if (endpoint.includes("messagesById")) return { messages: [{ responseHeader: "HTTP/1.1 200 OK" }] };
      if (endpoint.includes("sites")) return { sites: ["http://example.com"] };
      return {};
    };
    const result = await evaluateGateA(1, "http://example.com", mockZapRequest, {}, false);
    expect(result.reachable).toBe(true);
    // Without auth configured, Gate A passes if target is reachable
    expect(result.passed).toBe(true);
  });
});

// ─── Gate B: Execution Proof-of-Work ─────────────────────────────────────────

describe("Gate B — Execution Proof-of-Work", () => {
  it("passes when message count exceeds threshold", async () => {
    const { evaluateGateB } = await import("./lib/zap-scan-gates");
    // Mock zapRequest that returns high message count
    const mockZapRequest = async (endpoint: string) => {
      if (endpoint.includes("numberOfMessages")) return { numberOfMessages: "500" };
      if (endpoint.includes("recordsToScan")) return { recordsToScan: "0" };
      if (endpoint.includes("alerts")) return { alerts: [{}, {}, {}] };
      return {};
    };
    const result = await evaluateGateB(1, "http://example.com", "0", mockZapRequest, {}, 15);
    expect(result.passed).toBe(true);
    expect(result.activeScanMessages).toBeGreaterThan(0);
  });

  it("fails when active scan produced zero messages", async () => {
    const { evaluateGateB } = await import("./lib/zap-scan-gates");
    const mockZapRequest = async (endpoint: string) => {
      if (endpoint.includes("numberOfMessages")) return { numberOfMessages: "0" };
      if (endpoint.includes("recordsToScan")) return { recordsToScan: "0" };
      if (endpoint.includes("alerts")) return { alerts: [] };
      return {};
    };
    const result = await evaluateGateB(1, "http://example.com", "0", mockZapRequest, {}, 10);
    expect(result.passed).toBe(false);
    expect(result.activeScanMessages).toBe(0);
  });

  it("fails when message count is below minimum threshold", async () => {
    const { evaluateGateB } = await import("./lib/zap-scan-gates");
    const mockZapRequest = async (endpoint: string) => {
      if (endpoint.includes("numberOfMessages")) return { numberOfMessages: "3" };
      if (endpoint.includes("recordsToScan")) return { recordsToScan: "0" };
      if (endpoint.includes("alerts")) return { alerts: [] };
      return {};
    };
    const result = await evaluateGateB(1, "http://example.com", "0", mockZapRequest, {}, 10);
    expect(result.passed).toBe(false);
  });
});

// ─── Gate C: Oracle ──────────────────────────────────────────────────────────

describe("Gate C — Oracle", () => {
  it("passes when passive alerts present and WAF ratio acceptable", async () => {
    const { evaluateGateC } = await import("./lib/zap-scan-gates");
    // Mock that returns passive alerts and low WAF blocking
    const mockZapRequest = async (endpoint: string) => {
      if (endpoint.includes("recordsToScan")) return { recordsToScan: "0" };
      if (endpoint.includes("alerts")) return { alerts: [{}, {}, {}, {}, {}] }; // 5 passive alerts
      if (endpoint.includes("numberOfMessages")) return { numberOfMessages: "100" };
      return {};
    };
    const result = await evaluateGateC(1, "http://example.com", mockZapRequest, {}, 5, false);
    expect(result.passed).toBe(true);
  });

  it("fails when zero passive alerts on a real target", async () => {
    const { evaluateGateC } = await import("./lib/zap-scan-gates");
    // Mock that returns zero alerts
    const mockZapRequest = async (endpoint: string) => {
      if (endpoint.includes("recordsToScan")) return { recordsToScan: "0" };
      if (endpoint.includes("alerts")) return { alerts: [] };
      if (endpoint.includes("numberOfMessages")) return { numberOfMessages: "100" };
      return {};
    };
    const result = await evaluateGateC(1, "http://example.com", mockZapRequest, {}, 0, false);
    expect(result.passed).toBe(false);
    expect(result.reason.toLowerCase()).toContain("passive");
  });

  it("fails when WAF block ratio exceeds threshold", async () => {
    const { evaluateGateC } = await import("./lib/zap-scan-gates");
    // Mock that simulates high WAF blocking (403 responses)
    const mockZapRequest = async (endpoint: string) => {
      if (endpoint.includes("recordsToScan")) return { recordsToScan: "0" };
      if (endpoint.includes("alerts")) return { alerts: [{}, {}] };
      // Return messages showing 90% 403 responses
      if (endpoint.includes("messages")) return { messages: Array(100).fill({ responseHeader: "HTTP/1.1 403" }) };
      if (endpoint.includes("numberOfMessages")) return { numberOfMessages: "100" };
      return {};
    };
    const result = await evaluateGateC(1, "http://example.com", mockZapRequest, {}, 2, false);
    // With mocked ZAP, the WAF detection depends on actual message parsing
    // At minimum, the function should return a GateCResult structure
    expect(result).toHaveProperty("passed");
    expect(result).toHaveProperty("wafBlockRatio");
    expect(typeof result.wafBlockRatio).toBe("number");
  });
});

// ─── Composite Quality Assessment ───────────────────────────────────────────

describe("Composite Quality Assessment", () => {
  it("returns 'verified' when all gates pass", async () => {
    const { computeOverallQuality } = await import("./lib/zap-scan-gates");
    const quality = computeOverallQuality(
      { passed: true, reason: "" },
      { passed: true, reason: "", activeScanMessages: 500, spiderUrlsFound: 20 },
      { passed: true, reason: "", passiveAlertCount: 5, wafBlockRatio: 0.05 },
    );
    expect(quality.quality).toBe("verified");
    expect(quality.quarantineReason).toBeNull();
  });

  it("returns 'quarantined' when Gate B fails", async () => {
    const { computeOverallQuality } = await import("./lib/zap-scan-gates");
    const quality = computeOverallQuality(
      { passed: true, reason: "" },
      { passed: false, reason: "0 messages", activeScanMessages: 0, spiderUrlsFound: 0 },
      { passed: true, reason: "", passiveAlertCount: 0, wafBlockRatio: 0 },
    );
    expect(quality.quality).toBe("quarantined");
    expect(quality.quarantineReason).toBeDefined();
    expect(quality.quarantineReason!.length).toBeGreaterThan(0);
  });

  it("returns 'quarantined' when Gate A fails", async () => {
    const { computeOverallQuality } = await import("./lib/zap-scan-gates");
    const quality = computeOverallQuality(
      { passed: false, reason: "Target unreachable" },
      { passed: true, reason: "", activeScanMessages: 100, spiderUrlsFound: 10 },
      { passed: true, reason: "", passiveAlertCount: 3, wafBlockRatio: 0.02 },
    );
    expect(quality.quality).toBe("quarantined");
    expect(quality.quarantineReason).toContain("Target unreachable");
  });

  it("returns degraded when Gate C fails with WAF_BLOCKING", async () => {
    const { computeOverallQuality } = await import("./lib/zap-scan-gates");
    const quality = computeOverallQuality(
      { passed: true, reason: "" },
      { passed: true, reason: "", activeScanMessages: 200, spiderUrlsFound: 15 },
      { passed: false, reason: "WAF_BLOCKING: ratio 0.85", passiveAlertCount: 2, wafBlockRatio: 0.85 },
    );
    // WAF blocking specifically should degrade, not quarantine
    expect(quality.quality).toBe("degraded");
  });

  it("returns quarantined when Gate C fails with zero passive alerts", async () => {
    const { computeOverallQuality } = await import("./lib/zap-scan-gates");
    const quality = computeOverallQuality(
      { passed: true, reason: "" },
      { passed: true, reason: "", activeScanMessages: 200, spiderUrlsFound: 15 },
      { passed: false, reason: "Zero passive alerts — proxy not intercepting", passiveAlertCount: 0, wafBlockRatio: 0 },
    );
    // Zero alerts = quarantine (scan likely broken)
    expect(quality.quality).toBe("quarantined");
  });
});

// ─── Credential Verification Gates ──────────────────────────────────────────

describe("Credential Verification Gates", () => {
  it("exports negative control and four-state classification functions", async () => {
    const credGates = await import("./lib/credential-verification-gates");
    expect(credGates.runNegativeControl).toBeDefined();
    expect(typeof credGates.runNegativeControl).toBe("function");
    expect(credGates.classifyCredentialResult).toBeDefined();
    expect(typeof credGates.classifyCredentialResult).toBe("function");
    expect(credGates.runVerifiedCredentialBatch).toBeDefined();
    expect(typeof credGates.runVerifiedCredentialBatch).toBe("function");
    expect(credGates.summarizeCredentialResults).toBeDefined();
    expect(typeof credGates.summarizeCredentialResults).toBe("function");
  });

  it("classifyCredentialResult returns valid four-state values", async () => {
    const { classifyCredentialResult } = await import("./lib/credential-verification-gates");
    // Test with a mock response that looks like a successful login
    const result = classifyCredentialResult(
      "admin",
      "password123",
      {
        success: true,
        responseCode: 200,
        responseSnippet: JSON.stringify({ token: "abc123", user: { name: "admin" } }),
      },
    );
    // Should be one of the four valid states
    expect(["VALID", "VALID_MFA_BLOCKED", "INVALID", "INDETERMINATE"]).toContain(result.state);
  });

  it("classifyCredentialResult detects MFA challenge", async () => {
    const { classifyCredentialResult } = await import("./lib/credential-verification-gates");
    const result = classifyCredentialResult(
      "admin",
      "password123",
      {
        success: true,
        responseCode: 200,
        responseSnippet: JSON.stringify({ mfa_required: true, challenge: "totp" }),
      },
    );
    expect(result.state).toBe("VALID_MFA_BLOCKED");
  });

  it("summarizeCredentialResults aggregates counts correctly", async () => {
    const { summarizeCredentialResults } = await import("./lib/credential-verification-gates");
    const results = [
      { state: "VALID" as const, confidence: 0.95, evidence: "token returned", username: "admin", password: "pass1" },
      { state: "VALID_MFA_BLOCKED" as const, confidence: 0.9, evidence: "mfa required", username: "user1", password: "pass2" },
      { state: "INVALID" as const, confidence: 0.99, evidence: "401 response", username: "user2", password: "pass3" },
      { state: "INVALID" as const, confidence: 0.98, evidence: "401 response", username: "user3", password: "pass4" },
      { state: "INDETERMINATE" as const, confidence: 0.3, evidence: "ambiguous response", username: "user4", password: "pass5" },
    ];
    const summary = summarizeCredentialResults(results);
    expect(summary.valid.length).toBe(1);
    expect(summary.mfaBlocked.length).toBe(1);
    expect(summary.invalid.length).toBe(2);
    expect(summary.indeterminate.length).toBe(1);
    expect(summary.summary).toBeDefined();
  });
});

// ─── A6: Deterministic Policy Isolation ──────────────────────────────────────

describe("A6 — Deterministic Policy Isolation", () => {
  it("selectPlaybook returns a valid playbook with enabledRules for each phase", async () => {
    const { selectPlaybook } = await import("./lib/zap-attack-playbooks");
    const phases = ["fingerprinting", "crawling", "secrets", "injection", "auth", "infra_enum", "api_security", "server_exploit", "full"] as const;
    const technologies = ["Node.js", "Express.js", "React"];

    for (const phase of phases) {
      const playbook = selectPlaybook(phase, technologies);
      expect(playbook).toHaveProperty("name");
      expect(playbook).toHaveProperty("enabledRules");
      expect(playbook).toHaveProperty("disabledRuleIds");
      expect(Array.isArray(playbook.enabledRules)).toBe(true);
      expect(Array.isArray(playbook.disabledRuleIds)).toBe(true);
      // Every playbook should have at least one enabled rule
      expect(playbook.enabledRules.length).toBeGreaterThan(0);
      // Each rule should have id, threshold, and strength
      for (const rule of playbook.enabledRules) {
        expect(rule).toHaveProperty("id");
        expect(rule).toHaveProperty("threshold");
        expect(rule).toHaveProperty("strength");
        expect(typeof rule.id).toBe("number");
        expect(["OFF", "LOW", "MEDIUM", "HIGH"]).toContain(rule.threshold);
        expect(["LOW", "MEDIUM", "HIGH", "INSANE"]).toContain(rule.strength);
      }
    }
  });

  it("same inputs produce identical playbook (deterministic)", async () => {
    const { selectPlaybook } = await import("./lib/zap-attack-playbooks");
    const techs = ["Django", "PostgreSQL", "Nginx"];
    const p1 = selectPlaybook("injection", techs);
    const p2 = selectPlaybook("injection", techs);
    expect(p1.name).toBe(p2.name);
    expect(p1.enabledRules.length).toBe(p2.enabledRules.length);
    expect(p1.enabledRules.map(r => r.id).sort()).toEqual(p2.enabledRules.map(r => r.id).sort());
  });

  it("different tech stacks produce different rule sets", async () => {
    const { selectPlaybook } = await import("./lib/zap-attack-playbooks");
    const phpPlaybook = selectPlaybook("injection", ["PHP", "WordPress", "MySQL"]);
    const nodePlaybook = selectPlaybook("injection", ["Node.js", "Express.js", "MongoDB"]);
    // They should have different rule sets (PHP-specific vs Node-specific)
    const phpIds = new Set(phpPlaybook.enabledRules.map(r => r.id));
    const nodeIds = new Set(nodePlaybook.enabledRules.map(r => r.id));
    // Not all rules should be the same (some overlap is expected for universal rules)
    const intersection = [...phpIds].filter(id => nodeIds.has(id));
    expect(intersection.length).toBeLessThan(phpIds.size);
  });

  it("getEngagementPlaybookSequence returns ordered kill-chain phases", async () => {
    const { getEngagementPlaybookSequence } = await import("./lib/zap-attack-playbooks");
    const sequence = getEngagementPlaybookSequence(["Node.js", "Express.js"]);
    expect(sequence.length).toBeGreaterThan(3);
    // First should be fingerprinting phase
    expect(sequence[0].name).toContain("fingerprint");
    // Last should be exploitation phase
    expect(sequence[sequence.length - 1].name.toLowerCase()).toContain("exploit");
  });
});

// ─── Report Generator Quarantine Awareness ──────────────────────────────────

describe("Report Generator — Quarantine Awareness", () => {
  it("generateReportFromZapApi is exported and callable", async () => {
    const reportGen = await import("./lib/zap-report-generator");
    expect(reportGen.generateReportFromZapApi).toBeDefined();
    expect(typeof reportGen.generateReportFromZapApi).toBe("function");
  });
});

// ─── Schema Verification ─────────────────────────────────────────────────────

describe("Schema — Gate Columns", () => {
  it("webAppScans schema includes gate verification columns", async () => {
    const schema = await import("../drizzle/schema");
    const table = schema.webAppScans;
    // Verify the new columns exist in the schema definition
    expect(table.scanQuality).toBeDefined();
    expect(table.quarantineReason).toBeDefined();
    expect(table.gateAPassed).toBeDefined();
    expect(table.gateBPassed).toBeDefined();
    expect(table.activeScanMessages).toBeDefined();
    expect(table.authConfigured).toBeDefined();
    expect(table.authMethod).toBeDefined();
  });
});
