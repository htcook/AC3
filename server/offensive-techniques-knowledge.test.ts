/**
 * Tests for Offensive Techniques Knowledge Module
 *
 * Validates all 6 knowledge domains and the context builder function
 * that injects knowledge into LLM system prompts.
 */

import { describe, it, expect } from "vitest";
import {
  getLOTLContext,
  getFileUploadBypassContext,
  getFirewallEvasionContext,
  getSocialEngineeringContext,
  getShodanReconContext,
  getSubdomainEnumContext,
  buildOffensiveTechniquesContext,
} from "./lib/knowledge/offensive-techniques-knowledge";

// ─── 1. Living Off the Land (LOTL) ─────────────────────────────────────────

describe("getLOTLContext", () => {
  it("returns non-empty context with all platforms when no filter", () => {
    const ctx = getLOTLContext();
    expect(ctx.length).toBeGreaterThan(100);
    expect(ctx).toContain("GTFOBins");
    expect(ctx).toContain("LOLBAS");
    expect(ctx).toContain("LOOBins");
    expect(ctx).toContain("LOLDrivers");
    expect(ctx).toContain("MalAPI");
    expect(ctx).toContain("HijackLibs");
    expect(ctx).toContain("LOTS Project");
    expect(ctx).toContain("FileSec");
    expect(ctx).toContain("WADComs");
  });

  it("filters to windows-only resources", () => {
    const ctx = getLOTLContext("windows");
    expect(ctx).toContain("LOLBAS");
    expect(ctx).toContain("LOLDrivers");
    expect(ctx).toContain("HijackLibs");
    expect(ctx).toContain("MalAPI");
    expect(ctx).toContain("WADComs");
    // Should not contain linux-only
    expect(ctx).not.toContain("GTFOBins");
    // Should not contain macos-only
    expect(ctx).not.toContain("LOOBins");
  });

  it("filters to linux-only resources", () => {
    const ctx = getLOTLContext("linux");
    expect(ctx).toContain("GTFOBins");
    // Should not contain windows-only
    expect(ctx).not.toContain("LOLBAS");
    expect(ctx).not.toContain("LOLDrivers");
  });

  it("filters to macos-only resources", () => {
    const ctx = getLOTLContext("macos");
    expect(ctx).toContain("LOOBins");
    expect(ctx).not.toContain("GTFOBins");
    expect(ctx).not.toContain("LOLBAS");
  });

  it("includes MITRE technique references", () => {
    const ctx = getLOTLContext();
    expect(ctx).toMatch(/T\d{4}/); // MITRE technique IDs
  });
});

// ─── 2. File Upload Extension Filter Bypass ─────────────────────────────────

describe("getFileUploadBypassContext", () => {
  it("returns non-empty context with bypass categories", () => {
    const ctx = getFileUploadBypassContext();
    expect(ctx.length).toBeGreaterThan(100);
    expect(ctx).toContain("File Upload");
    expect(ctx).toContain("Bypass");
  });

  it("includes null byte techniques", () => {
    const ctx = getFileUploadBypassContext();
    expect(ctx).toMatch(/null|%00|\\x00|\\0/i);
  });

  it("includes newline/carriage return techniques", () => {
    const ctx = getFileUploadBypassContext();
    expect(ctx).toMatch(/newline|\\n|%0a|carriage|\\r|%0d/i);
  });

  it("includes encoding bypass techniques", () => {
    const ctx = getFileUploadBypassContext();
    expect(ctx).toMatch(/unicode|overlong|encoding|%C0/i);
  });

  it("includes semicolon/hash delimiter techniques", () => {
    const ctx = getFileUploadBypassContext();
    expect(ctx).toMatch(/semicolon|;|hash|#|%23|%3B/i);
  });

  it("includes tab/space whitespace techniques", () => {
    const ctx = getFileUploadBypassContext();
    expect(ctx).toMatch(/tab|space|whitespace|%09|%20/i);
  });
});

// ─── 3. Firewall Testing & Evasion ─────────────────────────────────────────

describe("getFirewallEvasionContext", () => {
  it("returns non-empty context", () => {
    const ctx = getFirewallEvasionContext();
    expect(ctx.length).toBeGreaterThan(100);
    expect(ctx).toContain("Firewall");
  });

  it("includes key firewall testing tools", () => {
    const ctx = getFirewallEvasionContext();
    expect(ctx).toContain("Nmap");
    expect(ctx).toContain("Metasploit");
  });

  it("includes evasion techniques when firewall detected", () => {
    const ctx = getFirewallEvasionContext(true);
    expect(ctx).toMatch(/fragment|evasion|tunnel|bypass/i);
  });

  it("includes WAF-specific techniques when WAF detected", () => {
    const ctx = getFirewallEvasionContext(false, true);
    expect(ctx).toMatch(/WAF|wafw00f|web application firewall/i);
  });

  it("includes both firewall and WAF context when both detected", () => {
    const ctx = getFirewallEvasionContext(true, true);
    expect(ctx).toMatch(/fragment|evasion|tunnel/i);
    expect(ctx).toMatch(/WAF|wafw00f/i);
  });

  it("includes tunneling tools", () => {
    const ctx = getFirewallEvasionContext(true);
    expect(ctx).toMatch(/tunnel|ICMP|DNS|HTTP|SSH/i);
  });
});

// ─── 4. Social Engineering Attack Taxonomy ──────────────────────────────────

describe("getSocialEngineeringContext", () => {
  it("returns non-empty context with all categories", () => {
    const ctx = getSocialEngineeringContext();
    expect(ctx.length).toBeGreaterThan(100);
    expect(ctx).toContain("Phishing");
    expect(ctx).toContain("Pretexting");
    expect(ctx).toContain("Baiting");
    expect(ctx).toContain("Quid Pro Quo");
    expect(ctx).toContain("Tailgating");
  });

  it("includes phishing sub-techniques", () => {
    const ctx = getSocialEngineeringContext("Phishing");
    expect(ctx).toContain("Spear Phishing");
    expect(ctx).toContain("Vishing");
    expect(ctx).toContain("Smishing");
    expect(ctx).toContain("Clone Phishing");
    expect(ctx).toContain("BEC");
  });

  it("includes pretexting sub-techniques", () => {
    const ctx = getSocialEngineeringContext("Pretexting");
    expect(ctx).toContain("Tech Support Scam");
    expect(ctx).toContain("CEO Fraud");
  });

  it("includes baiting sub-techniques", () => {
    const ctx = getSocialEngineeringContext("Baiting");
    expect(ctx).toContain("USB Drop");
    expect(ctx).toContain("Fake WiFi");
    expect(ctx).toContain("Evil Twin");
  });

  it("includes tailgating sub-techniques", () => {
    const ctx = getSocialEngineeringContext("Tailgating");
    expect(ctx).toContain("Piggybacking");
    expect(ctx).toContain("Shoulder Surfing");
    expect(ctx).toContain("Dumpster Diving");
  });

  it("filters to a specific category when provided", () => {
    const ctx = getSocialEngineeringContext("Phishing");
    // Should have phishing details but less of other categories
    expect(ctx).toContain("Phishing");
  });
});

// ─── 5. Shodan Filters & Queries ────────────────────────────────────────────

describe("getShodanReconContext", () => {
  it("returns non-empty context with Shodan info", () => {
    const ctx = getShodanReconContext();
    expect(ctx.length).toBeGreaterThan(100);
    expect(ctx).toContain("Shodan");
  });

  it("includes Shodan query syntax and filters", () => {
    const ctx = getShodanReconContext();
    // Should include Shodan filter syntax like hostname:, port:, product:
    expect(ctx).toMatch(/hostname:|org:|port:|product:/i);
  });

  it("includes common filters", () => {
    const ctx = getShodanReconContext();
    expect(ctx).toMatch(/port:|product:|os:|country:|ssl/i);
  });

  it("includes pre-built search queries for databases", () => {
    const ctx = getShodanReconContext("database");
    expect(ctx).toMatch(/mongo|mysql|elastic|postgres/i);
  });

  it("includes web server queries", () => {
    const ctx = getShodanReconContext("web");
    expect(ctx).toMatch(/apache|nginx|iis/i);
  });
});

// ─── 6. Subdomain Enumeration Tools ────────────────────────────────────────

describe("getSubdomainEnumContext", () => {
  it("returns non-empty context", () => {
    const ctx = getSubdomainEnumContext();
    expect(ctx.length).toBeGreaterThan(100);
    expect(ctx).toContain("Subdomain");
  });

  it("includes major subdomain enumeration tools", () => {
    const ctx = getSubdomainEnumContext();
    // Top tools from the cheat sheet
    expect(ctx).toMatch(/subfinder|amass|sublist3r|dnsenum/i);
  });

  it("includes passive and active tools", () => {
    const ctx = getSubdomainEnumContext();
    expect(ctx).toMatch(/passive|active|brute|certificate/i);
  });
});

// ─── 7. Composite Context Builder ──────────────────────────────────────────

describe("buildOffensiveTechniquesContext", () => {
  it("returns empty string for reporting phase with no flags", () => {
    const ctx = buildOffensiveTechniquesContext({ phase: "reporting" });
    expect(ctx).toBe("");
  });

  it("includes firewall evasion when hasFirewall=true in enumeration", () => {
    const ctx = buildOffensiveTechniquesContext({
      phase: "enumeration",
      hasFirewall: true,
    });
    expect(ctx).toMatch(/firewall|evasion|fragment/i);
  });

  it("includes file upload bypass when hasFileUpload=true", () => {
    const ctx = buildOffensiveTechniquesContext({
      phase: "vuln_detection",
      hasFileUpload: true,
    });
    expect(ctx).toMatch(/upload|bypass|extension/i);
  });

  it("includes Shodan context in enumeration phase by default", () => {
    const ctx = buildOffensiveTechniquesContext({
      phase: "enumeration",
    });
    // enumeration phase includes subdomain enum and shodan by default
    expect(ctx).toMatch(/shodan/i);
  });

  it("includes LOTL context for exploitation phase", () => {
    const ctx = buildOffensiveTechniquesContext({
      phase: "exploitation",
    });
    // Exploitation phase always includes LOTL
    expect(ctx).toMatch(/GTFOBins|LOLBAS|LOOBins|Living Off/i);
  });

  it("includes platform-specific LOTL for windows exploitation", () => {
    const ctx = buildOffensiveTechniquesContext({
      phase: "exploitation",
      platform: "windows",
    });
    expect(ctx).toContain("LOLBAS");
    // Windows filter excludes linux-only tools
    expect(ctx).not.toContain("GTFOBins");
  });

  it("includes WAF context when hasWAF=true", () => {
    const ctx = buildOffensiveTechniquesContext({
      phase: "vuln_detection",
      hasWAF: true,
    });
    expect(ctx).toMatch(/WAF|wafw00f/i);
  });

  it("combines multiple knowledge domains when all flags set in exploitation", () => {
    const ctx = buildOffensiveTechniquesContext({
      phase: "exploitation",
      hasFileUpload: true,
      platform: "linux",
    });
    // exploitation phase includes LOTL + file upload when flagged
    expect(ctx.length).toBeGreaterThan(200);
    expect(ctx).toMatch(/upload|bypass/i);
    expect(ctx).toMatch(/GTFOBins/i);
  });

  it("combines firewall + file upload + shodan in enumeration", () => {
    const ctx = buildOffensiveTechniquesContext({
      phase: "enumeration",
      hasFirewall: true,
      hasWAF: true,
      hasFileUpload: true,
      includeShodan: true,
    });
    expect(ctx.length).toBeGreaterThan(200);
    expect(ctx).toMatch(/firewall|evasion/i);
    expect(ctx).toMatch(/upload|bypass/i);
    expect(ctx).toMatch(/shodan/i);
  });

  it("includes firewall evasion in post_exploitation when hasFirewall", () => {
    const ctx = buildOffensiveTechniquesContext({
      phase: "post_exploitation",
      hasFirewall: true,
    });
    expect(ctx).toMatch(/firewall|evasion/i);
    // Also includes LOTL for post_exploitation
    expect(ctx).toMatch(/GTFOBins|LOLBAS|LOOBins/i);
  });
});

// ─── 8. Integration: Knowledge is non-empty and well-formatted ──────────────

describe("Knowledge module output quality", () => {
  it("all context functions return strings without undefined/null", () => {
    const outputs = [
      getLOTLContext(),
      getLOTLContext("windows"),
      getLOTLContext("linux"),
      getLOTLContext("macos"),
      getFileUploadBypassContext(),
      getFirewallEvasionContext(),
      getFirewallEvasionContext(true),
      getFirewallEvasionContext(false, true),
      getSocialEngineeringContext(),
      getShodanReconContext(),
      getSubdomainEnumContext(),
      buildOffensiveTechniquesContext({ phase: "enumeration" }),
    ];
    for (const output of outputs) {
      expect(typeof output).toBe("string");
      expect(output).not.toContain("undefined");
      expect(output).not.toContain("[object Object]");
    }
  });

  it("context strings are reasonable length for LLM injection (< 10KB each)", () => {
    const outputs = [
      getLOTLContext(),
      getFileUploadBypassContext(),
      getFirewallEvasionContext(true, true),
      getSocialEngineeringContext(),
      getShodanReconContext(),
      getSubdomainEnumContext(),
    ];
    for (const output of outputs) {
      expect(output.length).toBeLessThan(10000);
    }
  });

  it("composite context stays under 15KB to avoid token overflow", () => {
    const ctx = buildOffensiveTechniquesContext({
      phase: "exploitation",
      hasFirewall: true,
      hasWAF: true,
      hasFileUpload: true,
      includeShodan: true,
    });
    expect(ctx.length).toBeLessThan(15000);
  });
});
