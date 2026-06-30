/**
 * Nuclei Direct Execution Tests
 * Tests the Nuclei integration as a first-class exploit method:
 *   1. ExploitMethod type includes 'nuclei'
 *   2. selectExploitMethod routes to 'nuclei' for web app vulns
 *   3. buildNucleiCommand generates correct commands
 *   4. KNOWN_NUCLEI_CVES and NUCLEI_VULN_CLASS_TAGS are properly populated
 *   5. NUCLEI_CLI_TEMPLATES generate valid commands
 */

import { describe, it, expect } from "vitest";

// ── Import from exploit-selection-intelligence ──
import {
  selectExploitMethod,
  buildNucleiCommand,
  KNOWN_NUCLEI_CVES,
  NUCLEI_VULN_CLASS_TAGS,
  NUCLEI_CLI_TEMPLATES,
  type ExploitMethod,
  type RuntimeExploitCriteria,
} from "./lib/exploit-selection-intelligence";

// ═══════════════════════════════════════════════════════════════════════
// §1 — ExploitMethod Type & Routing
// ═══════════════════════════════════════════════════════════════════════

describe("Nuclei ExploitMethod Routing", () => {
  it("should route to 'nuclei' for CVEs with known Nuclei templates (no MSF module)", () => {
    // CVE-2023-22515 is in KNOWN_NUCLEI_CVES but NOT in KNOWN_MSF_CVES
    const result = selectExploitMethod({
      cve: "CVE-2023-22515",
      service: "http",
      port: 8090,
      vulnClass: "auth_bypass",
      hasKnownModule: false,
      technologies: ["confluence"],
      os: "linux",
    });
    expect(result).toBe("nuclei");
  });

  it("should route to 'nuclei' for web app vuln classes without CVE", () => {
    const result = selectExploitMethod({
      cve: undefined,
      service: "http",
      port: 80,
      vulnClass: "sqli",
      hasKnownModule: false,
      technologies: ["php", "mysql"],
    });
    expect(result).toBe("nuclei");
  });

  it("should route to 'nuclei' for XSS vuln class", () => {
    const result = selectExploitMethod({
      cve: undefined,
      service: "http",
      port: 443,
      vulnClass: "xss",
      hasKnownModule: false,
      technologies: ["javascript"],
    });
    expect(result).toBe("nuclei");
  });

  it("should route to 'nuclei' for SSTI vuln class", () => {
    const result = selectExploitMethod({
      cve: undefined,
      service: "http",
      port: 8080,
      vulnClass: "ssti",
      hasKnownModule: false,
      technologies: ["python", "flask"],
    });
    expect(result).toBe("nuclei");
  });

  it("should route to 'nuclei' for SSRF vuln class", () => {
    const result = selectExploitMethod({
      cve: undefined,
      service: "http",
      port: 3000,
      vulnClass: "ssrf",
      hasKnownModule: false,
      technologies: ["node"],
    });
    expect(result).toBe("nuclei");
  });

  it("should route to 'nuclei' for command injection vuln class", () => {
    const result = selectExploitMethod({
      cve: undefined,
      service: "http",
      port: 80,
      vulnClass: "cmdi",
      hasKnownModule: false,
      technologies: ["php"],
    });
    expect(result).toBe("nuclei");
  });

  it("should route to 'nuclei' for LFI vuln class", () => {
    const result = selectExploitMethod({
      cve: undefined,
      service: "http",
      port: 80,
      vulnClass: "lfi",
      hasKnownModule: false,
      technologies: ["php"],
    });
    expect(result).toBe("nuclei");
  });

  it("should route to 'nuclei' for auth_bypass vuln class", () => {
    const result = selectExploitMethod({
      cve: undefined,
      service: "http",
      port: 80,
      vulnClass: "auth_bypass",
      hasKnownModule: false,
      technologies: [],
    });
    expect(result).toBe("nuclei");
  });

  it("should still route to 'metasploit' when MSF module is known", () => {
    const result = selectExploitMethod({
      cve: "CVE-2017-5638",
      service: "http",
      port: 8080,
      vulnClass: "cmdi",
      hasKnownModule: true,
      technologies: ["struts"],
    });
    expect(result).toBe("metasploit");
  });

  it("should route CVE-2021-44228 to metasploit (in KNOWN_MSF_CVES), but Nuclei is fallback", () => {
    // CVE-2021-44228 is in BOTH KNOWN_MSF_CVES and KNOWN_NUCLEI_CVES
    // MSF takes priority when hasKnownMSFModule is inferred from KNOWN_MSF_CVES
    const result = selectExploitMethod({
      cve: "CVE-2021-44228",
      service: "http",
      port: 8080,
      vulnClass: "cmdi",
      hasKnownModule: false,
      technologies: ["java"],
    });
    expect(result).toBe("metasploit");
  });

  it("should route to 'nuclei' for CVE-2024-21887 (Nuclei-only, no MSF)", () => {
    const result = selectExploitMethod({
      cve: "CVE-2024-21887",
      service: "http",
      port: 443,
      vulnClass: "cmdi",
      hasKnownModule: false,
      technologies: ["ivanti"],
    });
    expect(result).toBe("nuclei");
  });

  it("should route to 'nuclei' for CVE-2014-0160 (Heartbleed) when no MSF module", () => {
    const result = selectExploitMethod({
      cve: "CVE-2014-0160",
      service: "https",
      port: 443,
      vulnClass: "generic",
      hasKnownModule: false,
      technologies: ["openssl"],
    });
    expect(result).toBe("nuclei");
  });

  it("should route to 'exploitdb' for unknown CVE without Nuclei template on non-web service", () => {
    const result = selectExploitMethod({
      cve: "CVE-2099-99999",
      service: "ssh",
      port: 22,
      vulnClass: "generic",
      hasKnownModule: false,
      technologies: [],
    });
    expect(result).toBe("exploitdb");
  });

  it("should route to 'manual_verification' for Security Misconfiguration", () => {
    const result = selectExploitMethod({
      cve: undefined,
      service: "http",
      port: 80,
      vulnClass: "Security Misconfiguration",
      hasKnownModule: false,
      technologies: [],
    });
    expect(result).toBe("manual_verification");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §2 — KNOWN_NUCLEI_CVES Coverage
// ═══════════════════════════════════════════════════════════════════════

describe("KNOWN_NUCLEI_CVES", () => {
  it("should contain at least 15 CVE entries", () => {
    expect(Object.keys(KNOWN_NUCLEI_CVES).length).toBeGreaterThanOrEqual(15);
  });

  it("should have template paths for all entries", () => {
    for (const [cve, template] of Object.entries(KNOWN_NUCLEI_CVES)) {
      expect(template).toMatch(/^cves\/\d{4}\/CVE-\d{4}-\d+$/);
    }
  });

  const criticalCVEs = [
    "CVE-2021-44228", // Log4Shell
    "CVE-2021-41773", // Apache path traversal
    "CVE-2022-22965", // Spring4Shell
    "CVE-2014-0160",  // Heartbleed
    "CVE-2014-6271",  // Shellshock
    "CVE-2017-5638",  // Struts2
  ];

  for (const cve of criticalCVEs) {
    it(`should include ${cve}`, () => {
      expect(KNOWN_NUCLEI_CVES[cve]).toBeDefined();
    });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// §3 — NUCLEI_VULN_CLASS_TAGS Coverage
// ═══════════════════════════════════════════════════════════════════════

describe("NUCLEI_VULN_CLASS_TAGS", () => {
  const expectedClasses = ["sqli", "xss", "ssrf", "cmdi", "ssti", "lfi", "file_upload", "auth_bypass", "deserialization"];

  for (const cls of expectedClasses) {
    it(`should have tags for vuln class: ${cls}`, () => {
      expect(NUCLEI_VULN_CLASS_TAGS[cls]).toBeDefined();
      expect(NUCLEI_VULN_CLASS_TAGS[cls].length).toBeGreaterThan(0);
    });
  }

  it("should have at least 2 tags for sqli", () => {
    expect(NUCLEI_VULN_CLASS_TAGS.sqli.length).toBeGreaterThanOrEqual(2);
  });

  it("should include 'rce' tag for command injection", () => {
    expect(NUCLEI_VULN_CLASS_TAGS.cmdi).toContain("rce");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §4 — buildNucleiCommand
// ═══════════════════════════════════════════════════════════════════════

describe("buildNucleiCommand", () => {
  it("should generate CVE-specific template command", () => {
    const result = buildNucleiCommand({
      target: "dvwa.lab.aceofcloud.io",
      port: 80,
      cve: "CVE-2021-44228",
      vulnClass: "cmdi",
    });
    expect(result).not.toBeNull();
    expect(result!.command).toContain("nuclei");
    expect(result!.command).toContain("cves/2021/CVE-2021-44228");
    expect(result!.command).toContain("dvwa.lab.aceofcloud.io:80");
    expect(result!.templateInfo).toContain("CVE template");
  });

  it("should generate vuln-class tag command when no CVE template", () => {
    const result = buildNucleiCommand({
      target: "target.example.com",
      port: 443,
      vulnClass: "sqli",
    });
    expect(result).not.toBeNull();
    expect(result!.command).toContain("nuclei");
    expect(result!.command).toContain("-tags sqli,sql-injection");
    expect(result!.templateInfo).toContain("Vuln class tags");
  });

  it("should generate generic vuln class tag command for generic class with CVE", () => {
    // 'generic' vuln class has tags ['cve', 'rce', 'critical'] in NUCLEI_VULN_CLASS_TAGS
    const result = buildNucleiCommand({
      target: "target.example.com",
      port: 8080,
      cve: "CVE-2024-12345",
      vulnClass: "generic",
    });
    expect(result).not.toBeNull();
    expect(result!.command).toContain("nuclei");
    // CVE-2024-12345 is not in KNOWN_NUCLEI_CVES, but 'generic' has vuln class tags
    expect(result!.command).toContain("-tags cve,rce,critical");
    expect(result!.templateInfo).toContain("Vuln class tags");
  });

  it("should generate generic CVE tag for unknown CVE with unknown vuln class", () => {
    const result = buildNucleiCommand({
      target: "target.example.com",
      port: 8080,
      cve: "CVE-2024-12345",
      vulnClass: "unknown_class",
    });
    expect(result).not.toBeNull();
    expect(result!.command).toContain("-tags cve202412345");
    expect(result!.templateInfo).toContain("Generic CVE tag");
  });

  it("should include cookie header for authenticated scanning", () => {
    const result = buildNucleiCommand({
      target: "dvwa.lab.aceofcloud.io",
      port: 80,
      vulnClass: "sqli",
      cookie: "PHPSESSID=abc123; security=low",
    });
    expect(result).not.toBeNull();
    expect(result!.command).toContain("Cookie: PHPSESSID=abc123; security=low");
  });

  it("should return null for generic vuln class without CVE", () => {
    const result = buildNucleiCommand({
      target: "target.example.com",
      port: 22,
      vulnClass: "unknown_class",
    });
    expect(result).toBeNull();
  });

  it("should prefer CVE template over vuln class tags", () => {
    const result = buildNucleiCommand({
      target: "target.example.com",
      port: 80,
      cve: "CVE-2021-41773",
      vulnClass: "lfi",
    });
    expect(result).not.toBeNull();
    expect(result!.command).toContain("-t cves/2021/CVE-2021-41773");
    expect(result!.templateInfo).toContain("CVE template");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §5 — NUCLEI_CLI_TEMPLATES
// ═══════════════════════════════════════════════════════════════════════

describe("NUCLEI_CLI_TEMPLATES", () => {
  it("scanByCVE should generate valid nuclei command", () => {
    const cmds = NUCLEI_CLI_TEMPLATES.scanByCVE("target.com", 80, "cves/2021/CVE-2021-44228");
    expect(cmds).toHaveLength(1);
    expect(cmds[0].tool).toBe("nuclei");
    expect(cmds[0].command).toContain("nuclei -u target.com:80");
    expect(cmds[0].command).toContain("-t cves/2021/CVE-2021-44228");
    expect(cmds[0].timeout).toBe(60);
  });

  it("scanByTags should join tags with commas", () => {
    const cmds = NUCLEI_CLI_TEMPLATES.scanByTags("target.com", 443, ["sqli", "sql-injection"]);
    expect(cmds).toHaveLength(1);
    expect(cmds[0].command).toContain("-tags sqli,sql-injection");
  });

  it("fullWebScan should use http type filter", () => {
    const cmds = NUCLEI_CLI_TEMPLATES.fullWebScan("target.com", 80);
    expect(cmds).toHaveLength(1);
    expect(cmds[0].command).toContain("-type http");
    expect(cmds[0].timeout).toBe(180);
  });

  it("authenticatedScan should include Cookie header", () => {
    const cmds = NUCLEI_CLI_TEMPLATES.authenticatedScan("target.com", 80, ["xss"], "PHPSESSID=test123");
    expect(cmds).toHaveLength(1);
    expect(cmds[0].command).toContain('Cookie: PHPSESSID=test123');
    expect(cmds[0].command).toContain("-tags xss");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §6 — Integration: Nuclei in Exploit Pipeline
// ═══════════════════════════════════════════════════════════════════════

describe("Nuclei Pipeline Integration", () => {
  it("should route DVWA SQLi to nuclei (web app, sqli class, no MSF module)", () => {
    const method = selectExploitMethod({
      cve: undefined,
      service: "http",
      port: 80,
      vulnClass: "sqli",
      hasKnownModule: false,
      technologies: ["php", "mysql", "apache"],
    });
    expect(method).toBe("nuclei");

    const cmd = buildNucleiCommand({
      target: "dvwa.lab.aceofcloud.io",
      port: 80,
      vulnClass: "sqli",
      cookie: "PHPSESSID=abc; security=low",
    });
    expect(cmd).not.toBeNull();
    expect(cmd!.command).toContain("-tags sqli,sql-injection");
    expect(cmd!.command).toContain("Cookie:");
  });

  it("should route Juice Shop XSS to nuclei", () => {
    const method = selectExploitMethod({
      cve: undefined,
      service: "http",
      port: 3000,
      vulnClass: "xss",
      hasKnownModule: false,
      technologies: ["node", "angular"],
    });
    expect(method).toBe("nuclei");
  });

  it("should route bWAPP command injection to nuclei", () => {
    const method = selectExploitMethod({
      cve: undefined,
      service: "http",
      port: 80,
      vulnClass: "cmdi",
      hasKnownModule: false,
      technologies: ["php"],
    });
    expect(method).toBe("nuclei");
  });

  it("should route Heartbleed to nuclei when no MSF module available", () => {
    const method = selectExploitMethod({
      cve: "CVE-2014-0160",
      service: "https",
      port: 443,
      vulnClass: "generic",
      hasKnownModule: false,
      technologies: ["openssl"],
    });
    expect(method).toBe("nuclei");

    const cmd = buildNucleiCommand({
      target: "target.example.com",
      port: 443,
      cve: "CVE-2014-0160",
      vulnClass: "generic",
    });
    expect(cmd).not.toBeNull();
    expect(cmd!.command).toContain("cves/2014/CVE-2014-0160");
  });

  it("should route file_upload to nuclei", () => {
    const method = selectExploitMethod({
      cve: undefined,
      service: "http",
      port: 80,
      vulnClass: "file_upload",
      hasKnownModule: false,
      technologies: ["php"],
    });
    expect(method).toBe("nuclei");
  });

  it("should route deserialization to nuclei (web app)", () => {
    const method = selectExploitMethod({
      cve: undefined,
      service: "http",
      port: 8080,
      vulnClass: "deserialization",
      hasKnownModule: false,
      technologies: ["java"],
    });
    // deserialization has requiresCustomPayload=true AND complexity=high,
    // but Nuclei vuln class tags exist, so it should route to nuclei
    expect(method).toBe("nuclei");
  });
});
