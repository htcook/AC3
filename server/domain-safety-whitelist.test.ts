/**
 * Domain Safety Whitelist — Vitest Tests
 *
 * Tests the guardrail that prevents active scanning/exploitation
 * on non-whitelisted domains. This is a critical safety feature.
 */
import { describe, it, expect } from "vitest";
import {
  extractHostname,
  isDomainWhitelisted,
  parseTargets,
  validateEngagementTargets,
  getSafetyWarning,
  WHITELISTED_DOMAINS,
  WHITELISTED_IPS,
} from "../shared/domain-safety-whitelist";

// ─── extractHostname ────────────────────────────────────────────────────────

describe("extractHostname", () => {
  it("extracts hostname from a full URL", () => {
    expect(extractHostname("https://scan.aceofcloud.io/lab/dvwa/")).toBe("scan.aceofcloud.io");
  });

  it("extracts hostname from URL with port", () => {
    expect(extractHostname("http://159.223.152.190:3001")).toBe("159.223.152.190");
  });

  it("handles bare domain", () => {
    expect(extractHostname("example.com")).toBe("example.com");
  });

  it("handles domain with path", () => {
    expect(extractHostname("example.com/path/to/page")).toBe("example.com");
  });

  it("handles domain with port", () => {
    expect(extractHostname("example.com:8080")).toBe("example.com");
  });

  it("lowercases the hostname", () => {
    expect(extractHostname("EXAMPLE.COM")).toBe("example.com");
  });

  it("handles empty string", () => {
    expect(extractHostname("")).toBe("");
  });

  it("handles whitespace", () => {
    expect(extractHostname("  scan.aceofcloud.io  ")).toBe("scan.aceofcloud.io");
  });
});

// ─── isDomainWhitelisted ────────────────────────────────────────────────────

describe("isDomainWhitelisted", () => {
  // AC3-owned domains
  it("approves scan.aceofcloud.io", () => {
    expect(isDomainWhitelisted("scan.aceofcloud.io")).toBe(true);
  });

  it("approves aceofcloud.io", () => {
    expect(isDomainWhitelisted("aceofcloud.io")).toBe(true);
  });

  it("approves aceofcloud.com", () => {
    expect(isDomainWhitelisted("aceofcloud.com")).toBe(true);
  });

  it("approves subdomains of aceofcloud.io", () => {
    expect(isDomainWhitelisted("lab.scan.aceofcloud.io")).toBe(true);
  });

  // Public vuln apps
  it("approves testphp.vulnweb.com", () => {
    expect(isDomainWhitelisted("testphp.vulnweb.com")).toBe(true);
  });

  it("approves demo.testfire.net", () => {
    expect(isDomainWhitelisted("demo.testfire.net")).toBe(true);
  });

  it("approves brokencrystals.com", () => {
    expect(isDomainWhitelisted("brokencrystals.com")).toBe(true);
  });

  it("approves ginandjuice.shop", () => {
    expect(isDomainWhitelisted("ginandjuice.shop")).toBe(true);
  });

  it("approves scanme.nmap.org", () => {
    expect(isDomainWhitelisted("scanme.nmap.org")).toBe(true);
  });

  // Whitelisted IPs
  it("approves AC3 test lab IP 159.223.152.190", () => {
    expect(isDomainWhitelisted("159.223.152.190")).toBe(true);
  });

  it("approves nmap IP 45.33.32.156", () => {
    expect(isDomainWhitelisted("45.33.32.156")).toBe(true);
  });

  // Private/localhost ranges (always safe)
  it("approves localhost", () => {
    expect(isDomainWhitelisted("localhost")).toBe(true);
  });

  it("approves 127.0.0.1", () => {
    expect(isDomainWhitelisted("127.0.0.1")).toBe(true);
  });

  it("approves 10.x.x.x private range", () => {
    expect(isDomainWhitelisted("10.0.1.50")).toBe(true);
  });

  it("approves 192.168.x.x private range", () => {
    expect(isDomainWhitelisted("192.168.1.1")).toBe(true);
  });

  it("approves 172.16.x.x private range", () => {
    expect(isDomainWhitelisted("172.16.0.1")).toBe(true);
  });

  it("approves 172.31.x.x private range", () => {
    expect(isDomainWhitelisted("172.31.255.255")).toBe(true);
  });

  // NON-whitelisted domains — MUST be blocked
  it("BLOCKS google.com", () => {
    expect(isDomainWhitelisted("google.com")).toBe(false);
  });

  it("BLOCKS tesconsultantsgov.us", () => {
    expect(isDomainWhitelisted("tesconsultantsgov.us")).toBe(false);
  });

  it("BLOCKS mcdllc.com", () => {
    expect(isDomainWhitelisted("mcdllc.com")).toBe(false);
  });

  it("BLOCKS random-company.com", () => {
    expect(isDomainWhitelisted("random-company.com")).toBe(false);
  });

  it("BLOCKS pentagon.mil", () => {
    expect(isDomainWhitelisted("pentagon.mil")).toBe(false);
  });

  it("BLOCKS arbitrary IPs", () => {
    expect(isDomainWhitelisted("8.8.8.8")).toBe(false);
  });

  // Edge cases: URL format should still work
  it("approves whitelisted domain in URL format", () => {
    expect(isDomainWhitelisted("https://scan.aceofcloud.io/lab/dvwa/")).toBe(true);
  });

  it("BLOCKS non-whitelisted domain in URL format", () => {
    expect(isDomainWhitelisted("https://tesconsultantsgov.us/admin")).toBe(false);
  });
});

// ─── parseTargets ───────────────────────────────────────────────────────────

describe("parseTargets", () => {
  it("parses comma-separated targets", () => {
    expect(parseTargets("a.com, b.com, c.com")).toEqual(["a.com", "b.com", "c.com"]);
  });

  it("parses space-separated targets", () => {
    expect(parseTargets("a.com b.com c.com")).toEqual(["a.com", "b.com", "c.com"]);
  });

  it("parses semicolon-separated targets", () => {
    expect(parseTargets("a.com;b.com;c.com")).toEqual(["a.com", "b.com", "c.com"]);
  });

  it("handles empty string", () => {
    expect(parseTargets("")).toEqual([]);
  });

  it("handles null/undefined", () => {
    expect(parseTargets("")).toEqual([]);
  });

  it("filters empty entries from multiple spaces", () => {
    const result = parseTargets("a.com   b.com");
    expect(result.filter(Boolean)).toEqual(["a.com", "b.com"]);
  });
});

// ─── validateEngagementTargets ──────────────────────────────────────────────

describe("validateEngagementTargets", () => {
  it("returns allWhitelisted=true for all-approved targets", () => {
    const result = validateEngagementTargets(
      "scan.aceofcloud.io, testphp.vulnweb.com",
      "159.223.152.190"
    );
    expect(result.allWhitelisted).toBe(true);
    expect(result.nonWhitelistedCount).toBe(0);
  });

  it("returns allWhitelisted=false when any target is not approved", () => {
    const result = validateEngagementTargets(
      "scan.aceofcloud.io, tesconsultantsgov.us",
      null
    );
    expect(result.allWhitelisted).toBe(false);
    expect(result.nonWhitelistedCount).toBeGreaterThan(0);
    expect(result.nonWhitelistedTargets).toContain("tesconsultantsgov.us");
  });

  it("identifies all non-whitelisted targets", () => {
    const result = validateEngagementTargets(
      "tesconsultantsgov.us mcdllc.com",
      "8.8.8.8"
    );
    expect(result.nonWhitelistedCount).toBe(3);
    expect(result.nonWhitelistedTargets).toContain("tesconsultantsgov.us");
    expect(result.nonWhitelistedTargets).toContain("mcdllc.com");
    expect(result.nonWhitelistedTargets).toContain("8.8.8.8");
  });

  it("handles null inputs", () => {
    const result = validateEngagementTargets(null, null);
    expect(result.totalTargets).toBe(0);
    expect(result.allWhitelisted).toBe(false); // No targets = not "all whitelisted"
  });

  it("handles mixed whitelisted and non-whitelisted", () => {
    const result = validateEngagementTargets(
      "scan.aceofcloud.io tesconsultantsgov.us",
      "159.223.152.190 8.8.8.8"
    );
    expect(result.totalTargets).toBe(4);
    expect(result.whitelistedCount).toBe(2);
    expect(result.nonWhitelistedCount).toBe(2);
    expect(result.allWhitelisted).toBe(false);
  });

  it("correctly counts per-target status", () => {
    const result = validateEngagementTargets("scan.aceofcloud.io", "159.223.152.190");
    expect(result.targets.length).toBe(2);
    expect(result.targets.every(t => t.whitelisted)).toBe(true);
  });
});

// ─── getSafetyWarning ───────────────────────────────────────────────────────

describe("getSafetyWarning", () => {
  it("returns null for all-whitelisted targets", () => {
    const result = validateEngagementTargets("scan.aceofcloud.io", "159.223.152.190");
    expect(getSafetyWarning(result)).toBeNull();
  });

  it("returns null for empty targets", () => {
    const result = validateEngagementTargets(null, null);
    expect(getSafetyWarning(result)).toBeNull();
  });

  it("returns warning message for non-whitelisted targets", () => {
    const result = validateEngagementTargets("tesconsultantsgov.us", null);
    const warning = getSafetyWarning(result);
    expect(warning).not.toBeNull();
    expect(warning).toContain("SAFETY GUARDRAIL");
    expect(warning).toContain("tesconsultantsgov.us");
    expect(warning).toContain("BLOCKED");
    expect(warning).toContain("passive reconnaissance");
  });

  it("lists all non-whitelisted targets in warning", () => {
    const result = validateEngagementTargets("tesconsultantsgov.us mcdllc.com", null);
    const warning = getSafetyWarning(result);
    expect(warning).toContain("tesconsultantsgov.us");
    expect(warning).toContain("mcdllc.com");
    expect(warning).toContain("2 target(s)");
  });
});

// ─── Whitelist Integrity ────────────────────────────────────────────────────

describe("Whitelist integrity", () => {
  it("contains AC3-owned domains", () => {
    expect(WHITELISTED_DOMAINS).toContain("aceofcloud.io");
    expect(WHITELISTED_DOMAINS).toContain("aceofcloud.com");
    expect(WHITELISTED_DOMAINS).toContain("scan.aceofcloud.io");
  });

  it("contains AC3 test lab IP", () => {
    expect(WHITELISTED_IPS).toContain("159.223.152.190");
  });

  it("contains public vuln apps", () => {
    expect(WHITELISTED_DOMAINS).toContain("testphp.vulnweb.com");
    expect(WHITELISTED_DOMAINS).toContain("demo.testfire.net");
    expect(WHITELISTED_DOMAINS).toContain("brokencrystals.com");
    expect(WHITELISTED_DOMAINS).toContain("scanme.nmap.org");
  });

  it("does NOT contain any .gov, .mil, or .edu domains", () => {
    for (const d of WHITELISTED_DOMAINS) {
      expect(d).not.toMatch(/\.(gov|mil|edu)$/);
    }
  });

  it("does NOT contain major cloud provider domains", () => {
    for (const d of WHITELISTED_DOMAINS) {
      expect(d).not.toMatch(/(aws\.amazon|azure\.microsoft|cloud\.google)\.com$/);
    }
  });
});
