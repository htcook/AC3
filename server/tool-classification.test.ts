import { describe, it, expect } from "vitest";
import {
  TOOL_TIER_CLASSIFICATION,
  getToolsByTier,
  getToolClassification,
  isToolAllowedInMode,
} from "./lib/scan-policy-engine";

describe("Tool-to-Tier Classification (Claude Passive/Active Taxonomy)", () => {
  describe("TOOL_TIER_CLASSIFICATION completeness", () => {
    it("should have at least 40 passive tools classified", () => {
      const passive = TOOL_TIER_CLASSIFICATION.filter(t => t.tier === "passive");
      expect(passive.length).toBeGreaterThanOrEqual(40);
    });

    it("should have active-low tools (boundary cases)", () => {
      const activeLow = TOOL_TIER_CLASSIFICATION.filter(t => t.tier === "active-low");
      expect(activeLow.length).toBeGreaterThanOrEqual(5);
    });

    it("should have active-standard tools", () => {
      const activeStandard = TOOL_TIER_CLASSIFICATION.filter(t => t.tier === "active-standard");
      expect(activeStandard.length).toBeGreaterThanOrEqual(5);
    });

    it("should have active-aggressive tools", () => {
      const activeAggressive = TOOL_TIER_CLASSIFICATION.filter(t => t.tier === "active-aggressive");
      expect(activeAggressive.length).toBeGreaterThanOrEqual(3);
    });

    it("should have unique tool names", () => {
      const names = TOOL_TIER_CLASSIFICATION.map(t => t.name);
      const unique = new Set(names);
      expect(unique.size).toBe(names.length);
    });
  });

  describe("Passive tool classification correctness", () => {
    const passiveTools = [
      "crt.sh", "certspotter", "subfinder", "shodan", "censys",
      "alienvault-otx", "hibp", "phishtank", "nvd", "cisa-kev",
      "epss", "osv-dev", "github-advisories", "sec-edgar",
      "companies-house", "opencorporates",
    ];

    for (const tool of passiveTools) {
      it(`${tool} should be classified as passive`, () => {
        const classification = getToolClassification(tool);
        expect(classification).toBeDefined();
        expect(classification!.tier).toBe("passive");
        expect(classification!.targetContact).toBe(false);
        expect(classification!.stateChange).toBe(false);
        expect(classification!.detectionRisk).toBe("none");
        expect(classification!.roeRequired).toBe(false);
      });
    }
  });

  describe("Boundary case classification (httpx, dnsx)", () => {
    it("httpx should be active-low, not passive", () => {
      const httpx = getToolClassification("httpx");
      expect(httpx).toBeDefined();
      expect(httpx!.tier).toBe("active-low");
      expect(httpx!.targetContact).toBe(true);
      expect(httpx!.roeRequired).toBe(true);
      expect(httpx!.detectionRisk).toBe("minimal");
    });

    it("dnsx should be active-low, not passive", () => {
      const dnsx = getToolClassification("dnsx");
      expect(dnsx).toBeDefined();
      expect(dnsx!.tier).toBe("active-low");
      expect(dnsx!.targetContact).toBe(true);
      expect(dnsx!.roeRequired).toBe(true);
    });
  });

  describe("Active-low classification", () => {
    const activeLowTools = ["naabu", "gowitness", "aquatone", "eyewitness"];

    for (const tool of activeLowTools) {
      it(`${tool} should be active-low`, () => {
        const classification = getToolClassification(tool);
        expect(classification).toBeDefined();
        expect(classification!.tier).toBe("active-low");
        expect(classification!.targetContact).toBe(true);
        expect(classification!.stateChange).toBe(false);
        expect(classification!.roeRequired).toBe(true);
      });
    }
  });

  describe("Active-standard classification", () => {
    const activeStdTools = ["nmap-sv", "ffuf", "gobuster", "katana", "nikto"];

    for (const tool of activeStdTools) {
      it(`${tool} should be active-standard`, () => {
        const classification = getToolClassification(tool);
        expect(classification).toBeDefined();
        expect(classification!.tier).toBe("active-standard");
        expect(classification!.targetContact).toBe(true);
        expect(classification!.roeRequired).toBe(true);
        expect(classification!.detectionRisk).toBe("medium");
      });
    }
  });

  describe("Active-aggressive classification", () => {
    const aggressiveTools = ["nuclei", "masscan", "nmap-vuln"];

    for (const tool of aggressiveTools) {
      it(`${tool} should be active-aggressive`, () => {
        const classification = getToolClassification(tool);
        expect(classification).toBeDefined();
        expect(classification!.tier).toBe("active-aggressive");
        expect(classification!.targetContact).toBe(true);
        expect(classification!.roeRequired).toBe(true);
        expect(classification!.detectionRisk).toBe("high");
      });
    }
  });

  describe("getToolsByTier", () => {
    it("should return only passive tools for passive tier", () => {
      const tools = getToolsByTier("passive");
      expect(tools.length).toBeGreaterThan(0);
      expect(tools.every(t => t.tier === "passive")).toBe(true);
    });

    it("should return only active-aggressive tools for that tier", () => {
      const tools = getToolsByTier("active-aggressive");
      expect(tools.length).toBeGreaterThan(0);
      expect(tools.every(t => t.tier === "active-aggressive")).toBe(true);
    });
  });

  describe("isToolAllowedInMode", () => {
    it("passive tool should be allowed in all modes", () => {
      expect(isToolAllowedInMode("shodan", "passive")).toBe(true);
      expect(isToolAllowedInMode("shodan", "active-low")).toBe(true);
      expect(isToolAllowedInMode("shodan", "active-standard")).toBe(true);
      expect(isToolAllowedInMode("shodan", "active-aggressive")).toBe(true);
    });

    it("active-low tool should NOT be allowed in passive mode", () => {
      expect(isToolAllowedInMode("httpx", "passive")).toBe(false);
      expect(isToolAllowedInMode("httpx", "active-low")).toBe(true);
      expect(isToolAllowedInMode("httpx", "active-standard")).toBe(true);
    });

    it("active-standard tool should NOT be allowed in passive or active-low", () => {
      expect(isToolAllowedInMode("ffuf", "passive")).toBe(false);
      expect(isToolAllowedInMode("ffuf", "active-low")).toBe(false);
      expect(isToolAllowedInMode("ffuf", "active-standard")).toBe(true);
      expect(isToolAllowedInMode("ffuf", "active-aggressive")).toBe(true);
    });

    it("active-aggressive tool should only be allowed in aggressive mode", () => {
      expect(isToolAllowedInMode("nuclei", "passive")).toBe(false);
      expect(isToolAllowedInMode("nuclei", "active-low")).toBe(false);
      expect(isToolAllowedInMode("nuclei", "active-standard")).toBe(false);
      expect(isToolAllowedInMode("nuclei", "active-aggressive")).toBe(true);
    });

    it("unknown tool should return false for all modes", () => {
      expect(isToolAllowedInMode("nonexistent-tool", "passive")).toBe(false);
      expect(isToolAllowedInMode("nonexistent-tool", "active-aggressive")).toBe(false);
    });
  });

  describe("ROE requirements", () => {
    it("no passive tool should require ROE", () => {
      const passive = TOOL_TIER_CLASSIFICATION.filter(t => t.tier === "passive");
      expect(passive.every(t => t.roeRequired === false)).toBe(true);
    });

    it("all active tools should require ROE", () => {
      const active = TOOL_TIER_CLASSIFICATION.filter(t => t.tier !== "passive");
      expect(active.every(t => t.roeRequired === true)).toBe(true);
    });

    it("no passive tool should contact target", () => {
      const passive = TOOL_TIER_CLASSIFICATION.filter(t => t.tier === "passive");
      expect(passive.every(t => t.targetContact === false)).toBe(true);
    });

    it("all active tools should contact target", () => {
      const active = TOOL_TIER_CLASSIFICATION.filter(t => t.tier !== "passive");
      expect(active.every(t => t.targetContact === true)).toBe(true);
    });
  });
});

describe("Passive Guard — Connector Classification", () => {
  // Import dynamically to avoid module resolution issues
  it("should have JARM in active contact set (sends TLS probes to target)", async () => {
    const mod = await import("./lib/passive/passive-guard");
    const result = mod.filterConnectors(
      [{ name: "jarm_fingerprint", run: async () => ({ assets: [], signals: [], rawData: {} }) }] as any,
      "strict_passive" as any
    );
    expect(result.blocked.length).toBe(1);
    expect(result.blocked[0].name).toBe("jarm_fingerprint");
    expect(result.blocked[0].reason).toContain("direct HTTP contact");
  });

  it("should have favicon_hash in active contact set (fetches from target)", async () => {
    const mod = await import("./lib/passive/passive-guard");
    const result = mod.filterConnectors(
      [{ name: "favicon_hash", run: async () => ({ assets: [], signals: [], rawData: {} }) }] as any,
      "strict_passive" as any
    );
    expect(result.blocked.length).toBe(1);
    expect(result.blocked[0].name).toBe("favicon_hash");
  });

  it("should have dns_zone_transfer in active contact set (AXFR to target NS)", async () => {
    const mod = await import("./lib/passive/passive-guard");
    const result = mod.filterConnectors(
      [{ name: "dns_zone_transfer", run: async () => ({ assets: [], signals: [], rawData: {} }) }] as any,
      "strict_passive" as any
    );
    expect(result.blocked.length).toBe(1);
    expect(result.blocked[0].name).toBe("dns_zone_transfer");
  });

  it("should allow anubis in strict passive (queries third-party DB)", async () => {
    const mod = await import("./lib/passive/passive-guard");
    const result = mod.filterConnectors(
      [{ name: "anubis", run: async () => ({ assets: [], signals: [], rawData: {} }) }] as any,
      "strict_passive" as any
    );
    expect(result.allowed.length).toBe(1);
    expect(result.blocked.length).toBe(0);
  });

  it("should allow wayback_diff in strict passive", async () => {
    const mod = await import("./lib/passive/passive-guard");
    const result = mod.filterConnectors(
      [{ name: "wayback_diff", run: async () => ({ assets: [], signals: [], rawData: {} }) }] as any,
      "strict_passive" as any
    );
    expect(result.allowed.length).toBe(1);
    expect(result.blocked.length).toBe(0);
  });

  it("should have domain_health in DNS resolution set (DNS + SMTP)", async () => {
    const mod = await import("./lib/passive/passive-guard");
    const result = mod.filterConnectors(
      [{ name: "domain_health", run: async () => ({ assets: [], signals: [], rawData: {} }) }] as any,
      "strict_passive" as any
    );
    expect(result.blocked.length).toBe(1);
    expect(result.blocked[0].reason).toContain("DNS resolution");
  });

  it("should allow domain_health in standard mode", async () => {
    const mod = await import("./lib/passive/passive-guard");
    const result = mod.filterConnectors(
      [{ name: "domain_health", run: async () => ({ assets: [], signals: [], rawData: {} }) }] as any,
      "standard" as any
    );
    expect(result.allowed.length).toBe(1);
    expect(result.blocked.length).toBe(0);
  });

  it("should allow JARM in active mode", async () => {
    const mod = await import("./lib/passive/passive-guard");
    const result = mod.filterConnectors(
      [{ name: "jarm_fingerprint", run: async () => ({ assets: [], signals: [], rawData: {} }) }] as any,
      "active" as any
    );
    expect(result.allowed.length).toBe(1);
    expect(result.blocked.length).toBe(0);
  });
});
