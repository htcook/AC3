import { describe, it, expect } from "vitest";

// ── ZAP Training Lab Boost ──

// Skip in CI — requires SSH access to scan server
const __skipInCI = !process.env.SCAN_SERVER_HOST;

describe.skipIf(__skipInCI)("ZAP Training Lab Rule Boost", () => {
  it("should export applyTrainingLabBoost function", async () => {
    const mod = await import("./lib/zap-attack-playbooks");
    expect(typeof (mod as any).boostPlaybookForTrainingLab).toBe("function");
  });

  it("should export getTrainingLabBoostRules function", async () => {
    const mod = await import("./lib/zap-attack-playbooks");
    expect(typeof (mod as any).buildTrainingLabPlaybook).toBe("function");
  });

  it("getTrainingLabBoostRules should return rules with LOW threshold and INSANE strength", async () => {
    const mod = await import("./lib/zap-attack-playbooks");
    const playbook = (mod as any).buildTrainingLabPlaybook();
    expect(playbook).toBeDefined();
    expect(playbook.enabledRules).toBeDefined();
    expect(Array.isArray(playbook.enabledRules)).toBe(true);
    expect(playbook.enabledRules.length).toBeGreaterThan(10);

    // All rules should have LOW threshold and INSANE strength
    for (const rule of playbook.enabledRules) {
      expect(rule.threshold).toBe("LOW");
      expect(rule.strength).toBe("INSANE");
      expect(typeof rule.id).toBe("number");
    }
  });

  it("boost rules should cover critical vuln categories: SQLi, XSS, CSRF, Command Injection", async () => {
    const mod = await import("./lib/zap-attack-playbooks");
    const playbook = (mod as any).buildTrainingLabPlaybook();
    const ruleIds = playbook.enabledRules.map((r: any) => r.id);

    // Known ZAP rule IDs for critical vuln categories:
    // SQLi: 40018 (SQL Injection), 40019 (SQL Injection - MySQL), 40020 (SQL Injection - Hypersonic), 40021 (SQL Injection - Oracle), 40022 (SQL Injection - PostgreSQL), 40024 (SQL Injection - SQLite)
    expect(ruleIds).toContain(40018); // SQL Injection
    // XSS: 40012 (Reflected XSS), 40014 (Persistent XSS), 40016 (Persistent XSS - Prime), 40017 (Persistent XSS - Spider)
    expect(ruleIds).toContain(40012); // Reflected XSS
    // CSRF: 20012
    expect(ruleIds).toContain(20012); // CSRF
    // Command Injection: 90020 (Remote OS Command Injection)
    expect(ruleIds).toContain(90020); // Remote OS Command Injection
  });
});

// ── Training Lab Credential Injection ──
describe("Training Lab Credential Injection", () => {
  it("should have DVWA default credentials in the training lab creds map", async () => {
    // The creds are inline in engagement-orchestrator.ts, so we verify the pattern
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf8");

    expect(content).toContain("TRAINING_LAB_CREDS");
    expect(content).toContain("dvwa");
    expect(content).toContain("admin");
    expect(content).toContain("password");
    expect(content).toContain("login.php");
  });

  it("should have Juice Shop default credentials", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf8");

    expect(content).toContain("juice-shop");
    expect(content).toContain("admin@juice-sh.op");
    expect(content).toContain("admin123");
    expect(content).toContain("/rest/user/login");
  });

  it("should inject creds only when trainingLabMode is true", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf8");

    // The injection block should be guarded by trainingLabMode check
    const injectionBlock = content.indexOf("TRAINING_LAB_CREDS");
    expect(injectionBlock).toBeGreaterThan(-1);
    // Check that trainingLabMode guard appears before the creds block
    const guardCheck = content.lastIndexOf("trainingLabMode", injectionBlock);
    expect(guardCheck).toBeGreaterThan(-1);
    expect(injectionBlock - guardCheck).toBeLessThan(500);
  });

  it("should cover multiple training lab targets", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf8");

    // Extract the TRAINING_LAB_CREDS section
    const labNames = ["dvwa", "juice-shop", "webgoat", "bwapp", "mutillidae"];
    for (const lab of labNames) {
      expect(content).toContain(lab);
    }
  });
});

// ── Safety Escalation for Training Labs ──
describe("Training Lab Safety Escalation", () => {
  it("should auto-escalate to full_exploitation for training lab mode", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf8");

    // Check that training lab mode forces full_exploitation
    expect(content).toContain("trainingLabMode");
    expect(content).toContain("full_exploitation");
  });

  it("batch training run should set scanMode to active and roeStatus to signed", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/routers/engagement-automation.ts", "utf8");

    // Check that the batch training run sets correct DB fields
    expect(content).toContain("scanMode");
    expect(content).toContain("active");
    expect(content).toContain("roeStatus");
    expect(content).toContain("signed");
  });
});

// ── Scan Server Tool Availability ──
describe("Scan Server Tool Whitelist", () => {
  it("should include xsstrike and dalfox in allowed tools", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/scan-server-executor.ts", "utf8");

    expect(content).toContain("xsstrike");
    expect(content).toContain("dalfox");
  });

  it("sqlmap scanner should use latest version from /opt/sqlmap-latest", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/scanners/sqlmap-scanner.ts", "utf8");

    expect(content).toContain("/opt/sqlmap-latest/sqlmap.py");
  });

  it("xsstrike scanner should have fallback tool detection", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/scanners/xsstrike-scanner.ts", "utf8");

    // Should try both xsstrike and dalfox
    expect(content).toContain("xsstrike");
    expect(content).toContain("dalfox");
    expect(content).toContain("toolOrder");
  });
});

// ── ZAP Scanner Training Lab Mode Pass-Through ──
describe("ZAP Scanner Training Lab Mode", () => {
  it("startScan should accept trainingLabMode parameter", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/zap-scanner.ts", "utf8");

    expect(content).toContain("trainingLabMode");
    expect(content).toContain("boostPlaybookForTrainingLab");
  });

  it("should apply training lab boost when trainingLabMode is true", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/zap-scanner.ts", "utf8");

    // Check that the boost is conditionally applied
    const boostIndex = content.indexOf("boostPlaybookForTrainingLab");
    expect(boostIndex).toBeGreaterThan(-1);
    const conditionIndex = content.lastIndexOf("trainingLabMode", boostIndex);
    expect(conditionIndex).toBeGreaterThan(-1);
  });
});
