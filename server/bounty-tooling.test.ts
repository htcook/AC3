/**
 * Tests for Bug Bounty Tooling Enhancements
 *
 * Covers: Vulnerability Class Specialists, Tool Adapter Architecture,
 * Wordlist Intelligence, Tool Version Tracker, and License Compliance
 */
import { describe, it, expect } from "vitest";

// ─── Vulnerability Class Specialists ────────────────────────────────────────

import {
  getVulnSpecialist,
  getSpecialistsByPriority,
  getToolsForVulnClass,
  buildVulnClassContext,
  VULN_CLASS_SPECIALISTS,
} from "./lib/vuln-class-specialists";

describe("Vulnerability Class Specialists", () => {
  it("should return specialist for known vuln classes", () => {
    const xss = getVulnSpecialist("xss");
    expect(xss).toBeDefined();
    expect(xss!.vulnClass).toContain("XSS");
    expect(xss!.cweIds).toContain("CWE-79");
    expect(xss!.tools.length).toBeGreaterThan(0);
  });

  it("should return undefined for unknown vuln class", () => {
    const unknown = getVulnSpecialist("nonexistent_vuln");
    expect(unknown).toBeUndefined();
  });

  it("should list all vuln classes", () => {
    const classes = Object.keys(VULN_CLASS_SPECIALISTS);
    expect(classes.length).toBeGreaterThanOrEqual(8);
    expect(classes).toContain("xss");
    expect(classes).toContain("ssrf");
  });

  it("should get specialists sorted by priority", () => {
    const sorted = getSpecialistsByPriority();
    expect(sorted.length).toBeGreaterThanOrEqual(8);
    // Lower testingPriority = test first, so first item should have lowest number
    expect(sorted[0].testingPriority).toBeLessThanOrEqual(sorted[sorted.length - 1].testingPriority);
  });

  it("should build LLM context for vuln classes", () => {
    const context = buildVulnClassContext(["xss", "ssrf"]);
    expect(context).toContain("XSS");
    expect(context).toContain("SSRF");
    expect(context.length).toBeGreaterThan(100);
  });

  it("should get tools for a vuln class", () => {
    const tools = getToolsForVulnClass("xss");
    expect(tools.length).toBeGreaterThan(0);
    expect(tools[0].name).toBeTruthy();
  });
});

// ─── Tool Adapter Architecture ──────────────────────────────────────────────

import {
  GobusterAdapter,
  FfufAdapter,
  KatanaAdapter,
  DalfoxAdapter,
  getAdapter,
  getAdaptersForCategory,
  selectBestAdapter,
  selectWordlists,
  buildWordlistStrategy,
  WORDLIST_PROFILES,
} from "./lib/tool-adapter-architecture";

describe("Tool Adapter Architecture", () => {
  it("should build gobuster command with config", () => {
    const adapter = new GobusterAdapter();
    const result = adapter.buildCommand({
      target: "http://example.com",
      threads: 50,
      authCookie: "session=abc123",
      extensions: ["php", "html"],
      intensity: "standard",
    });

    expect(result.command).toContain("gobuster dir");
    expect(result.command).toContain("-u http://example.com");
    expect(result.command).toContain("-t 50");
    expect(result.command).toContain("-c session=abc123");
    expect(result.command).toContain("-x php,html");
    expect(result.estimatedDuration).toBe("5-15 min");
  });

  it("should build ffuf command with auto-calibrate", () => {
    const adapter = new FfufAdapter();
    const result = adapter.buildCommand({
      target: "http://example.com",
      threads: 100,
      recursive: true,
      intensity: "deep",
    });

    expect(result.command).toContain("ffuf");
    expect(result.command).toContain("-u http://example.com/FUZZ");
    expect(result.command).toContain("-t 100");
    expect(result.command).toContain("-recursion");
    expect(result.command).toContain("-ac");
    expect(result.command).toContain("-of json");
  });

  it("should build katana command with JS crawling", () => {
    const adapter = new KatanaAdapter();
    const result = adapter.buildCommand({
      target: "http://example.com",
      intensity: "deep",
    });

    expect(result.command).toContain("katana");
    expect(result.command).toContain("-jc");
    expect(result.command).toContain("-d 5"); // Deep = depth 5
  });

  it("should build dalfox command for XSS scanning", () => {
    const adapter = new DalfoxAdapter();
    const result = adapter.buildCommand({
      target: "http://example.com/search?q=test",
      intensity: "deep",
      authCookie: "session=abc",
    });

    expect(result.command).toContain("dalfox url");
    expect(result.command).toContain("-C session=abc");
    expect(result.command).toContain("--deep-domxss");
  });

  it("should parse gobuster output into normalized findings", () => {
    const adapter = new GobusterAdapter();
    const output = `/admin (Status: 200) [Size: 1234]
/backup.sql (Status: 200) [Size: 5678]
/api/v1 (Status: 301) [Size: 100]
/.git (Status: 403) [Size: 0]`;

    const findings = adapter.parseOutput(output);
    expect(findings.length).toBe(4);
    expect(findings[0].value).toBe("/admin");
    expect(findings[0].severity).toBe("high");
    expect(findings[1].value).toBe("/backup.sql");
    expect(findings[1].severity).toBe("critical");
  });

  it("should parse ffuf JSON output", () => {
    const adapter = new FfufAdapter();
    const output = JSON.stringify({
      results: [
        { input: { FUZZ: "admin" }, status: 200, length: 1234, words: 50, lines: 20 },
        { input: { FUZZ: "api" }, status: 301, length: 100, words: 5, lines: 1 },
      ],
    });

    const findings = adapter.parseOutput(output);
    expect(findings.length).toBe(2);
    expect(findings[0].value).toBe("admin");
    expect(findings[0].status).toBe(200);
  });

  it("should retrieve registered adapters by name", () => {
    const gobuster = getAdapter("gobuster");
    expect(gobuster).toBeDefined();
    expect(gobuster!.name).toBe("gobuster");

    const ffuf = getAdapter("ffuf");
    expect(ffuf).toBeDefined();
    expect(ffuf!.name).toBe("ffuf");
  });

  it("should find adapters by category", () => {
    const dirBruteforce = getAdaptersForCategory("directory_bruteforce");
    expect(dirBruteforce.length).toBeGreaterThanOrEqual(2);
    expect(dirBruteforce.map((a) => a.name)).toContain("gobuster");
    expect(dirBruteforce.map((a) => a.name)).toContain("ffuf");
  });

  it("should select best adapter based on requirements", () => {
    // When speed is priority, ffuf should win (speedRating 9 vs gobuster 7)
    const speedAdapter = selectBestAdapter("directory_bruteforce", { needsSpeed: true });
    expect(speedAdapter).toBeDefined();
    expect(speedAdapter!.name).toBe("ffuf");

    // When JSON output is required, ffuf should win (gobuster doesn't support JSON)
    const jsonAdapter = selectBestAdapter("directory_bruteforce", { needsJson: true });
    expect(jsonAdapter).toBeDefined();
    expect(jsonAdapter!.name).toBe("ffuf");
  });
});

// ─── Wordlist Intelligence ──────────────────────────────────────────────────

describe("Wordlist Intelligence", () => {
  it("should have comprehensive wordlist profiles", () => {
    expect(Object.keys(WORDLIST_PROFILES).length).toBeGreaterThanOrEqual(15);
    expect(WORDLIST_PROFILES["common"]).toBeDefined();
    expect(WORDLIST_PROFILES["api_endpoints"]).toBeDefined();
    expect(WORDLIST_PROFILES["wordpress"]).toBeDefined();
  });

  it("should select baseline wordlist for quick directory scan", () => {
    const wordlists = selectWordlists({
      technologies: [],
      scanType: "directory",
      intensity: "quick",
    });

    expect(wordlists.length).toBeGreaterThanOrEqual(1);
    expect(wordlists[0].name).toBe("Common");
  });

  it("should select tech-specific wordlists for PHP targets", () => {
    const wordlists = selectWordlists({
      technologies: ["PHP", "WordPress"],
      scanType: "directory",
      intensity: "standard",
    });

    const names = wordlists.map((w) => w.name);
    expect(names).toContain("Big"); // baseline for standard
    expect(names.some((n) => n.includes("PHP") || n.includes("WordPress"))).toBe(true);
  });

  it("should select subdomain wordlists for DNS scan", () => {
    const wordlists = selectWordlists({
      technologies: [],
      scanType: "subdomain",
      intensity: "quick",
    });

    expect(wordlists.length).toBeGreaterThanOrEqual(1);
    expect(wordlists[0].techTargets).toContain("dns");
  });

  it("should add specialized wordlists for deep scans", () => {
    const wordlists = selectWordlists({
      technologies: [],
      scanType: "directory",
      intensity: "deep",
    });

    const names = wordlists.map((w) => w.name);
    expect(names.some((n) => n.includes("Git") || n.includes("RAFT") || n.includes("Backup"))).toBe(true);
  });

  it("should respect time budget when selecting wordlists", () => {
    const wordlists = selectWordlists({
      technologies: ["PHP", "WordPress", "Java", "Spring"],
      scanType: "directory",
      intensity: "deep",
      maxTimeMinutes: 10,
    });

    // Should not include the massive directory-list-medium (47.8x multiplier = ~239 min)
    const names = wordlists.map((w) => w.name);
    expect(names).not.toContain("Directory List Medium");
  });

  it("should build wordlist strategy summary", () => {
    const strategy = buildWordlistStrategy({
      technologies: ["PHP", "WordPress"],
      intensity: "standard",
      targetType: "cms",
    });

    expect(strategy).toContain("Wordlist Strategy");
    expect(strategy).toContain("cms");
    expect(strategy).toContain("standard");
  });
});

// ─── Tool Version Tracker ───────────────────────────────────────────────────

import {
  checkToolVersion,
  checkAllToolVersions,
  checkLicenseCompliance,
  checkAllLicenseCompliance,
  getDeprecationWarnings,
  TOOL_VERSION_DB,
} from "./lib/tool-version-tracker";

describe("Tool Version Tracker", () => {
  it("should check version for a specific tool", () => {
    const result = checkToolVersion("nuclei");
    expect(result).toBeDefined();
    expect(result!.tool).toBe("Nuclei");
    expect(result!.isOutdated).toBe(true);
    expect(result!.updateUrgency).not.toBe("current");
  });

  it("should report current tools as not outdated", () => {
    const result = checkToolVersion("gobuster");
    expect(result).toBeDefined();
    expect(result!.isOutdated).toBe(false);
    expect(result!.updateUrgency).toBe("current");
  });

  it("should return undefined for unknown tools", () => {
    const result = checkToolVersion("nonexistent_tool");
    expect(result).toBeUndefined();
  });

  it("should check all tool versions", () => {
    const summary = checkAllToolVersions();
    expect(summary.results.length).toBeGreaterThanOrEqual(10);
    expect(summary.outdatedCount).toBeGreaterThanOrEqual(0);
    expect(summary.deprecatedTools.length).toBeGreaterThanOrEqual(2);
    expect(summary.deprecatedTools).toContain("Wfuzz");
    expect(summary.deprecatedTools).toContain("enum4linux");
  });

  it("should have version info for all tracked tools", () => {
    expect(Object.keys(TOOL_VERSION_DB).length).toBeGreaterThanOrEqual(15);
    for (const info of Object.values(TOOL_VERSION_DB)) {
      expect(info.name).toBeTruthy();
      expect(info.currentVersion).toBeTruthy();
      expect(info.license).toBeTruthy();
      expect(info.source).toBeTruthy();
    }
  });
});

describe("License Compliance Checker", () => {
  it("should report GPL tools as compliant for internal use", () => {
    const result = checkLicenseCompliance("nikto", "internal");
    expect(result).toBeDefined();
    expect(result!.compliant).toBe(true);
  });

  it("should flag AGPL tools for SaaS usage", () => {
    const result = checkLicenseCompliance("hydra", "saas");
    expect(result).toBeDefined();
    expect(result!.compliant).toBe(false);
    expect(result!.issues.length).toBeGreaterThan(0);
    expect(result!.issues[0]).toContain("AGPL");
  });

  it("should flag GPL tools for distribution", () => {
    const result = checkLicenseCompliance("sqlmap", "distribution");
    expect(result).toBeDefined();
    expect(result!.compliant).toBe(false);
    expect(result!.issues[0]).toContain("source code disclosure");
  });

  it("should report MIT tools as compliant for all uses", () => {
    const result = checkLicenseCompliance("ffuf", "commercial");
    expect(result).toBeDefined();
    expect(result!.compliant).toBe(true);
  });

  it("should flag Nmap NPSL for commercial use", () => {
    const result = checkLicenseCompliance("nmap", "commercial");
    expect(result).toBeDefined();
    expect(result!.issues.length).toBeGreaterThan(0);
    expect(result!.issues[0]).toContain("Nmap");
  });

  it("should check all licenses at once", () => {
    const summary = checkAllLicenseCompliance("internal");
    expect(summary.results.length).toBeGreaterThanOrEqual(10);
    expect(summary.compliantCount).toBeGreaterThan(0);
  });

  it("should get deprecation warnings for tools in use", () => {
    const warnings = getDeprecationWarnings(["wfuzz", "gobuster", "enum4linux"]);
    expect(warnings.length).toBe(2); // wfuzz and enum4linux are deprecated
    expect(warnings.map((w) => w.tool)).toContain("Wfuzz");
    expect(warnings.map((w) => w.tool)).toContain("enum4linux");
    expect(warnings.find((w) => w.tool === "Wfuzz")!.replacement).toBe("ffuf");
  });
});
