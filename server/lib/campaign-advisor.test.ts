/**
 * Tests for Campaign Advisor and Auto-Persistence modules
 */
import { describe, it, expect, vi } from "vitest";
import {
  getDeterministicAdvice,
  CAMPAIGN_ADVISOR_SYSTEM_PROMPT,
  buildContextSummary,
  type AdvisorContext,
} from "./campaign-advisor";
import {
  recordAction,
  CATEGORY_TO_PHASE,
  CATEGORY_TO_OPSEC_ACTION,
  type ActionCategory,
} from "./auto-persistence";

// ─── Campaign Advisor: Deterministic Advice ──────────────────────────────────

describe("Campaign Advisor - getDeterministicAdvice", () => {
  it("returns advice for recon phase", () => {
    const ctx: AdvisorContext = { currentPhase: "recon" };
    const advice = getDeterministicAdvice(ctx);
    expect(advice).toBeDefined();
    expect(advice.nextAction).toBeTruthy();
    expect(advice.reasoning).toBeTruthy();
    expect(advice.steps).toBeInstanceOf(Array);
    expect(advice.steps.length).toBeGreaterThan(0);
    expect(advice.opsecRisk).toBeGreaterThanOrEqual(0);
    expect(advice.opsecRisk).toBeLessThanOrEqual(100);
    expect(advice.engine).toBeTruthy();
  });

  it("returns advice for scanning phase", () => {
    const ctx: AdvisorContext = { currentPhase: "scanning" };
    const advice = getDeterministicAdvice(ctx);
    expect(advice.nextAction).toBeTruthy();
    expect(advice.steps.length).toBeGreaterThan(0);
  });

  it("returns advice for gaining_access phase", () => {
    const ctx: AdvisorContext = { currentPhase: "gaining_access" };
    const advice = getDeterministicAdvice(ctx);
    expect(advice.nextAction).toBeTruthy();
    expect(advice.opsecRisk).toBeGreaterThan(0);
  });

  it("returns advice for escalation phase", () => {
    const ctx: AdvisorContext = { currentPhase: "escalation" };
    const advice = getDeterministicAdvice(ctx);
    expect(advice.nextAction).toBeTruthy();
  });

  it("returns advice for lateral_movement phase", () => {
    const ctx: AdvisorContext = { currentPhase: "lateral_movement" };
    const advice = getDeterministicAdvice(ctx);
    expect(advice.nextAction).toBeTruthy();
  });

  it("returns advice for exfiltration phase", () => {
    const ctx: AdvisorContext = { currentPhase: "exfiltration" };
    const advice = getDeterministicAdvice(ctx);
    expect(advice.nextAction).toBeTruthy();
    expect(advice.opsecRisk).toBeGreaterThan(30); // exfil is high risk
  });

  it("returns advice for reporting phase", () => {
    const ctx: AdvisorContext = { currentPhase: "reporting" };
    const advice = getDeterministicAdvice(ctx);
    expect(advice.nextAction).toBeTruthy();
    expect(advice.opsecRisk).toBeLessThan(30); // reporting is low risk
  });

  it("returns default advice for unknown phase", () => {
    const ctx: AdvisorContext = { currentPhase: "unknown_phase" };
    const advice = getDeterministicAdvice(ctx);
    expect(advice.nextAction).toBeTruthy();
    expect(advice.engine).toBeTruthy();
  });

  it("returns advice with no context at all", () => {
    const ctx: AdvisorContext = {};
    const advice = getDeterministicAdvice(ctx);
    expect(advice).toBeDefined();
    expect(advice.nextAction).toBeTruthy();
    expect(advice.engine).toBeTruthy();
  });

  it("includes warnings for high OPSEC score", () => {
    const ctx: AdvisorContext = {
      currentPhase: "gaining_access",
      opsecScore: 85,
    };
    const advice = getDeterministicAdvice(ctx);
    expect(advice.warnings.length).toBeGreaterThan(0);
  });

  it("includes warnings when no context provided", () => {
    const ctx: AdvisorContext = {};
    const advice = getDeterministicAdvice(ctx);
    // Should still return valid advice
    expect(advice.warnings).toBeInstanceOf(Array);
  });
});

// ─── Campaign Advisor: System Prompt ─────────────────────────────────────────

describe("Campaign Advisor - System Prompt", () => {
  it("has a comprehensive system prompt", () => {
    expect(CAMPAIGN_ADVISOR_SYSTEM_PROMPT).toBeTruthy();
    expect(CAMPAIGN_ADVISOR_SYSTEM_PROMPT.length).toBeGreaterThan(500);
    expect(CAMPAIGN_ADVISOR_SYSTEM_PROMPT).toContain("OPSEC");
    expect(CAMPAIGN_ADVISOR_SYSTEM_PROMPT).toContain("engagement");
  });
});

// ─── Campaign Advisor: Context Summary ───────────────────────────────────────

describe("Campaign Advisor - buildContextSummary", () => {
  it("builds summary from empty context", () => {
    const summary = buildContextSummary({});
    expect(summary).toBeTruthy();
    expect(typeof summary).toBe("string");
  });

  it("builds summary with full context", () => {
    const ctx: AdvisorContext = {
      currentPhase: "scanning",
      engagementId: "eng_001",
      opsecScore: 42,
      compromisedHosts: ["10.0.0.5", "10.0.0.12"],
      availableCredentials: ["admin:password123", "root:toor"],
      knownVulnerabilities: [
        { cve: "CVE-2021-44228", host: "10.0.0.5", cvss: 10.0 },
        { cve: "CVE-2023-1234", host: "10.0.0.12", cvss: 7.5 },
      ],
      objectives: ["Domain admin", "Exfiltrate PII"],
      recentActions: [
        { action: "nmap scan", timestamp: Date.now(), success: true },
      ],
    };
    const summary = buildContextSummary(ctx);
    expect(summary).toContain("scanning");
    expect(summary).toContain("eng_001");
    expect(summary).toContain("42");
    expect(summary).toContain("10.0.0.5");
    expect(summary).toContain("CVE-2021-44228");
  });

  it("handles context with only phase", () => {
    const summary = buildContextSummary({ currentPhase: "recon" });
    expect(summary).toContain("recon");
  });
});

// ─── Auto-Persistence: Category Mappings ─────────────────────────────────────

describe("Auto-Persistence - Category Mappings", () => {
  it("maps all categories to kill chain phases", () => {
    const categories: ActionCategory[] = [
      "scanning", "credential_attack", "exploitation", "lateral_movement",
      "privilege_escalation", "recon", "c2", "exfiltration",
    ];
    for (const cat of categories) {
      expect(CATEGORY_TO_PHASE[cat]).toBeTruthy();
      expect(typeof CATEGORY_TO_PHASE[cat]).toBe("string");
    }
  });

  it("maps all categories to OPSEC action types", () => {
    const categories: ActionCategory[] = [
      "scanning", "credential_attack", "exploitation", "lateral_movement",
      "privilege_escalation", "recon", "c2", "exfiltration",
    ];
    for (const cat of categories) {
      expect(CATEGORY_TO_OPSEC_ACTION[cat]).toBeTruthy();
      expect(typeof CATEGORY_TO_OPSEC_ACTION[cat]).toBe("string");
    }
  });

  it("scanning maps to scanning phase", () => {
    expect(CATEGORY_TO_PHASE["scanning"]).toBe("scanning");
  });

  it("credential_attack maps to gaining_access phase", () => {
    expect(CATEGORY_TO_PHASE["credential_attack"]).toBe("gaining_access");
  });

  it("lateral_movement maps to lateral_movement phase", () => {
    expect(CATEGORY_TO_PHASE["lateral_movement"]).toBe("lateral_movement");
  });

  it("exfiltration maps to exfiltration phase", () => {
    expect(CATEGORY_TO_PHASE["exfiltration"]).toBe("exfiltration");
  });
});

// ─── Auto-Persistence: Event Emission ────────────────────────────────────────

describe("Auto-Persistence - emitAutoPersistenceEvent", () => {
  it("emits event without throwing (DB may not be available in tests)", async () => {
    // This should not throw even if DB is unavailable
    await expect(
      recordAction({
        category: "scanning",
        action: "nmap_scan",
        description: "Port scan of 10.0.0.0/24",
        source: "nmap",
        target: "10.0.0.0/24",
        success: true,
      })
    ).resolves.not.toThrow();
  });

  it("handles failed events gracefully", async () => {
    await expect(
      recordAction({
        category: "exploitation",
        action: "metasploit_exploit",
        description: "EternalBlue exploit attempt",
        source: "metasploit",
        target: "10.0.0.5",
        success: false,
      })
    ).resolves.not.toThrow();
  });

  it("handles events with engagement ID", async () => {
    await expect(
      recordAction({
        category: "credential_attack",
        action: "hydra_brute_force",
        description: "SSH brute force on 10.0.0.5",
        source: "hydra",
        target: "10.0.0.5",
        success: true,
        engagementId: "eng_001",
      })
    ).resolves.not.toThrow();
  });

  it("handles events with metadata", async () => {
    await expect(
      recordAction({
        category: "privilege_escalation",
        action: "linpeas_scan",
        description: "LinPEAS enumeration on target",
        source: "linpeas",
        target: "10.0.0.5",
        success: true,
        metadata: { foundSuid: true, kernelVersion: "5.4.0" },
      })
    ).resolves.not.toThrow();
  });
});
