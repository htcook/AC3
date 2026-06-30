/**
 * Tests for:
 * 1. Evasion CLI Adapter — translating evasion profiles into tool CLI flags
 * 2. Engagement Timeline — building timeline events from ops log + asset data
 */

import { describe, it, expect } from "vitest";
import {
  buildToolEvasionFlags,
  augmentCommandWithEvasion,
  getZapEvasionOverrides,
  getEffectiveEvasionProfile,
} from "./evasion-cli-adapter";
import { buildTimelineEvents } from "../../client/src/components/EngagementTimeline";

// ─── Evasion CLI Adapter Tests ─────────────────────────────────────────────

describe("Evasion CLI Adapter", () => {
  describe("buildToolEvasionFlags", () => {
    it("should build nuclei flags with rate limit at level 1", () => {
      const profile = {
        name: "normal",
        rateLimit: 100,
        delayMs: 0,
        userAgentStrategy: "default" as const,
        headerManipulation: {},
      };
      const flags = buildToolEvasionFlags(profile);
      expect(flags.nuclei).toContain("-rate-limit 100");
      expect(flags.nuclei.length).toBeGreaterThanOrEqual(1);
    });

    it("should add bulk-size at level 2", () => {
      const profile = {
        name: "cautious",
        rateLimit: 50,
        delayMs: 200,
        userAgentStrategy: "default" as const,
        headerManipulation: {},
      };
      const flags = buildToolEvasionFlags(profile, { currentLevel: 2, history: [], lastEscalatedAt: 0, cooldownUntil: 0 });
      expect(flags.nuclei).toContain("-rate-limit 50");
      expect(flags.nuclei).toContain("-bulk-size 10");
    });

    it("should add concurrency and timeout at level 3+", () => {
      const profile = {
        name: "moderate",
        rateLimit: 30,
        delayMs: 500,
        userAgentStrategy: "browser_mimic" as const,
        headerManipulation: { "X-Forwarded-For": "127.0.0.1" },
      };
      const flags = buildToolEvasionFlags(profile, { currentLevel: 3, history: [], lastEscalatedAt: 0, cooldownUntil: 0 });
      expect(flags.nuclei).toContain("-rate-limit 30");
      expect(flags.nuclei).toContain("-bulk-size 10");
      expect(flags.nuclei).toContain("-concurrency 5");
      // Should have header flags
      const headerFlags = flags.nuclei.filter(f => f.startsWith('-H'));
      expect(headerFlags.length).toBeGreaterThanOrEqual(1);
      expect(headerFlags.some(f => f.includes("X-Forwarded-For"))).toBe(true);
    });

    it("should set ZAP config with reduced threads at level 3", () => {
      const profile = {
        name: "moderate",
        rateLimit: 30,
        delayMs: 500,
        userAgentStrategy: "default" as const,
        headerManipulation: {},
      };
      const flags = buildToolEvasionFlags(profile, { currentLevel: 3, history: [], lastEscalatedAt: 0, cooldownUntil: 0 });
      expect(flags.zap.threadPerHost).toBe(2);
      expect(flags.zap.delayInMs).toBe(1500);
    });

    it("should set maximum stealth at level 5", () => {
      const profile = {
        name: "stealth",
        rateLimit: 5,
        delayMs: 5000,
        userAgentStrategy: "browser_mimic" as const,
        headerManipulation: { "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1" },
      };
      const flags = buildToolEvasionFlags(profile, { currentLevel: 5, history: [], lastEscalatedAt: 0, cooldownUntil: 0 });
      expect(flags.nuclei).toContain("-timeout 30");
      expect(flags.zap.threadPerHost).toBe(1);
      expect(flags.zap.delayInMs).toBe(3000);
    });

    it("should set httpx rate limit capped at 50", () => {
      const profile = {
        name: "normal",
        rateLimit: 200,
        delayMs: 0,
        userAgentStrategy: "default" as const,
        headerManipulation: {},
      };
      const flags = buildToolEvasionFlags(profile);
      expect(flags.httpx).toContain("-rate-limit 50");
    });

    it("should set naabu rate at 10x rate limit capped at 1000", () => {
      const profile = {
        name: "normal",
        rateLimit: 200,
        delayMs: 0,
        userAgentStrategy: "default" as const,
        headerManipulation: {},
      };
      const flags = buildToolEvasionFlags(profile);
      expect(flags.naabu).toContain("-rate 1000");
    });

    it("should add gobuster thread reduction at level 2", () => {
      const profile = {
        name: "cautious",
        rateLimit: 50,
        delayMs: 200,
        userAgentStrategy: "default" as const,
        headerManipulation: {},
      };
      const flags = buildToolEvasionFlags(profile, { currentLevel: 2, history: [], lastEscalatedAt: 0, cooldownUntil: 0 });
      expect(flags.gobuster).toContain("-t 10");
    });
  });

  describe("augmentCommandWithEvasion", () => {
    const makeProfile = (level: number) => ({
      fingerprint: { webServer: "nginx", os: null, appFramework: null, language: null, cms: null, databases: [], jsFrameworks: [], additionalTech: [] },
      waf: { detected: false },
      cdn: { detected: false },
      firewall: { detected: false },
      topology: { role: "web_server" as const, confidence: 0.8, children: [] },
      recommendedStrategy: {
        evasionProfile: {
          name: "test",
          rateLimit: 30,
          delayMs: 500,
          userAgentStrategy: "browser_mimic" as const,
          headerManipulation: { "X-Forwarded-For": "127.0.0.1" },
        },
        phases: [],
      },
      evasionEscalation: level > 1 ? {
        currentLevel: level,
        history: [],
        lastEscalatedAt: 0,
        cooldownUntil: 0,
      } : undefined,
    });

    it("should not modify command at level 1", () => {
      const profile = makeProfile(1);
      const result = augmentCommandWithEvasion("nuclei", "nuclei -u target.com", profile as any);
      expect(result.augmentedCommand).toBe("nuclei -u target.com");
      expect(result.flagsAdded.length).toBe(0);
      expect(result.evasionLevel).toBe(1);
    });

    it("should add rate-limit to nuclei at level 2+", () => {
      const profile = makeProfile(3);
      const result = augmentCommandWithEvasion("nuclei", "nuclei -u target.com", profile as any);
      expect(result.augmentedCommand).toContain("-rate-limit 30");
      expect(result.flagsAdded.length).toBeGreaterThan(0);
      expect(result.evasionLevel).toBe(3);
    });

    it("should replace existing rate-limit in nuclei command", () => {
      const profile = makeProfile(3);
      const result = augmentCommandWithEvasion("nuclei", "nuclei -u target.com -rate-limit 150", profile as any);
      expect(result.augmentedCommand).toContain("-rate-limit 30");
      expect(result.augmentedCommand).not.toContain("-rate-limit 150");
    });

    it("should add rate-limit to httpx capped at 50", () => {
      const profile = makeProfile(2);
      const result = augmentCommandWithEvasion("httpx", "httpx -u target.com", profile as any);
      expect(result.augmentedCommand).toContain("-rate-limit 30");
    });

    it("should reduce gobuster threads at level 3", () => {
      const profile = makeProfile(3);
      const result = augmentCommandWithEvasion("gobuster", "gobuster dir -u http://target.com -w wordlist.txt", profile as any);
      expect(result.augmentedCommand).toContain("-t ");
      expect(result.augmentedCommand).toContain("--delay");
    });

    it("should add header flags to nuclei", () => {
      const profile = makeProfile(3);
      const result = augmentCommandWithEvasion("nuclei", "nuclei -u target.com", profile as any);
      expect(result.augmentedCommand).toContain("X-Forwarded-For");
    });
  });

  describe("getZapEvasionOverrides", () => {
    it("should return null at level 1", () => {
      const profile = {
        recommendedStrategy: {
          evasionProfile: { name: "normal", rateLimit: 100, delayMs: 0, userAgentStrategy: "default" as const, headerManipulation: {} },
          phases: [],
        },
      };
      const result = getZapEvasionOverrides(profile as any);
      expect(result).toBeNull();
    });

    it("should return overrides at level 3", () => {
      const profile = {
        recommendedStrategy: {
          evasionProfile: { name: "moderate", rateLimit: 30, delayMs: 500, userAgentStrategy: "default" as const, headerManipulation: {} },
          phases: [],
        },
        evasionEscalation: { currentLevel: 3, history: [], lastEscalatedAt: 0, cooldownUntil: 0 },
      };
      const result = getZapEvasionOverrides(profile as any);
      expect(result).not.toBeNull();
      expect(result!.threadPerHost).toBe(2);
      expect(result!.delayInMs).toBe(1500);
    });
  });

  describe("getEffectiveEvasionProfile", () => {
    it("should return base profile when no escalation", () => {
      const profile = {
        recommendedStrategy: {
          evasionProfile: { name: "normal", rateLimit: 100, delayMs: 0, userAgentStrategy: "default" as const, headerManipulation: {} },
          phases: [],
        },
      };
      const result = getEffectiveEvasionProfile(profile as any);
      expect(result).not.toBeNull();
      expect(result!.name).toBe("normal");
    });

    it("should return null when no strategy", () => {
      const profile = {};
      const result = getEffectiveEvasionProfile(profile as any);
      expect(result).toBeNull();
    });
  });
});

// ─── Engagement Timeline Tests ─────────────────────────────────────────────

describe("Engagement Timeline - buildTimelineEvents", () => {
  it("should create phase transition events from log entries", () => {
    const log = [
      { id: "1", timestamp: 1000, phase: "recon", type: "info", title: "Starting recon", detail: "" },
      { id: "2", timestamp: 2000, phase: "enumeration", type: "info", title: "Starting enum", detail: "" },
    ];
    const events = buildTimelineEvents(log, []);
    const phaseStarts = events.filter(e => e.type === "phase_start");
    expect(phaseStarts.length).toBe(2);
    expect(phaseStarts[0].phase).toBe("recon");
    expect(phaseStarts[1].phase).toBe("enumeration");
  });

  it("should create phase_end events on phase transitions", () => {
    const log = [
      { id: "1", timestamp: 1000, phase: "recon", type: "info", title: "Recon", detail: "" },
      { id: "2", timestamp: 2000, phase: "enumeration", type: "info", title: "Enum", detail: "" },
    ];
    const events = buildTimelineEvents(log, []);
    const phaseEnds = events.filter(e => e.type === "phase_end");
    expect(phaseEnds.length).toBe(1);
    expect(phaseEnds[0].phase).toBe("recon");
  });

  it("should detect evasion escalation events", () => {
    const log = [
      { id: "1", timestamp: 1000, phase: "enumeration", type: "warning", title: "Evasion escalated to level 3", detail: "WAF blocking detected", riskTier: "yellow" as const },
    ];
    const events = buildTimelineEvents(log, []);
    const evasionEvents = events.filter(e => e.type === "evasion");
    expect(evasionEvents.length).toBe(1);
    expect(evasionEvents[0].title).toContain("Evasion");
    expect(evasionEvents[0].riskTier).toBe("yellow");
  });

  it("should detect tool execution events from log data", () => {
    const log = [
      {
        id: "1", timestamp: 1000, phase: "enumeration", type: "tool_result",
        title: "nuclei completed", detail: "Found 3 vulns",
        data: { tool: "nuclei", durationMs: 5000, exitCode: 0, target: "example.com" },
      },
    ];
    const events = buildTimelineEvents(log, []);
    const toolEvents = events.filter(e => e.type === "tool_exec");
    expect(toolEvents.length).toBe(1);
    expect(toolEvents[0].tool).toBe("nuclei");
    expect(toolEvents[0].durationMs).toBe(5000);
    expect(toolEvents[0].success).toBe(true);
  });

  it("should detect finding events from log data", () => {
    const log = [
      {
        id: "1", timestamp: 1000, phase: "vuln_detection", type: "finding",
        title: "SQL Injection found", detail: "In login form",
        data: { severity: "critical", cve: "CVE-2024-1234", target: "example.com" },
      },
    ];
    const events = buildTimelineEvents(log, []);
    const findingEvents = events.filter(e => e.type === "finding");
    expect(findingEvents.length).toBe(1);
    expect(findingEvents[0].severity).toBe("critical");
  });

  it("should add tool results from assets as supplementary events", () => {
    const assets = [
      {
        hostname: "example.com",
        vulns: [],
        zapFindings: [],
        exploitAttempts: [],
        toolResults: [
          {
            tool: "naabu", command: "naabu -host example.com", exitCode: 0,
            durationMs: 3000, timedOut: false, findingCount: 5,
            findings: [], outputPreview: "", executedAt: 5000, phase: "enumeration",
          },
        ],
        status: "scanned",
      },
    ];
    const events = buildTimelineEvents([], assets as any);
    const toolEvents = events.filter(e => e.type === "tool_exec");
    expect(toolEvents.length).toBe(1);
    expect(toolEvents[0].tool).toBe("naabu");
    expect(toolEvents[0].asset).toBe("example.com");
  });

  it("should add exploit attempts from assets", () => {
    const assets = [
      {
        hostname: "example.com",
        vulns: [],
        zapFindings: [],
        exploitAttempts: [
          { module: "ssh_brute", success: true, timestamp: 8000 },
          { module: "sqli_exploit", success: false, timestamp: 20000 },
        ],
        toolResults: [],
        status: "compromised",
      },
    ];
    const events = buildTimelineEvents([], assets as any);
    const exploitEvents = events.filter(e => e.type === "exploit");
    expect(exploitEvents.length).toBe(2);
    expect(exploitEvents[0].success).toBe(true);
    expect(exploitEvents[1].success).toBe(false);
  });

  it("should sort all events by timestamp", () => {
    const log = [
      { id: "1", timestamp: 3000, phase: "enumeration", type: "info", title: "Enum", detail: "" },
      { id: "2", timestamp: 1000, phase: "recon", type: "info", title: "Recon", detail: "" },
    ];
    const events = buildTimelineEvents(log, []);
    for (let i = 1; i < events.length; i++) {
      expect(events[i].timestamp).toBeGreaterThanOrEqual(events[i - 1].timestamp);
    }
  });

  it("should not duplicate tool events that exist in both log and assets", () => {
    const log = [
      {
        id: "1", timestamp: 5000, phase: "enumeration", type: "tool_result",
        title: "naabu completed", detail: "",
        data: { tool: "naabu", durationMs: 3000, exitCode: 0, target: "example.com" },
      },
    ];
    const assets = [
      {
        hostname: "example.com",
        vulns: [],
        zapFindings: [],
        exploitAttempts: [],
        toolResults: [
          {
            tool: "naabu", command: "naabu", exitCode: 0,
            durationMs: 3000, timedOut: false, findingCount: 5,
            findings: [], outputPreview: "", executedAt: 5000, phase: "enumeration",
          },
        ],
        status: "scanned",
      },
    ];
    const events = buildTimelineEvents(log, assets as any);
    const naabuEvents = events.filter(e => e.type === "tool_exec" && e.tool === "naabu");
    // Should deduplicate — only 1 naabu event, not 2
    expect(naabuEvents.length).toBe(1);
  });

  it("should handle empty log and assets gracefully", () => {
    const events = buildTimelineEvents([], []);
    expect(events).toEqual([]);
  });

  it("should detect approval gate events", () => {
    const log = [
      {
        id: "1", timestamp: 1000, phase: "exploitation", type: "approval_required",
        title: "Exploit approval needed", detail: "SSH brute force on production server",
        riskTier: "red" as const,
      },
    ];
    const events = buildTimelineEvents(log, []);
    const approvalEvents = events.filter(e => e.type === "approval");
    expect(approvalEvents.length).toBe(1);
    expect(approvalEvents[0].riskTier).toBe("red");
  });
});
