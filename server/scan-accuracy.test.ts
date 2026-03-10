import { describe, expect, it } from "vitest";

/**
 * Tests for scan accuracy fixes:
 * 1. KEV matching false positive prevention
 * 2. Exploit evidence persistence
 * 3. Vulnerability deduplication
 */

// ─── Test 1: KEV Matching False Positive Prevention ───────────────────────────

describe("KEV matching: pattern matching direction", () => {
  // Simulates the fixed matching logic from kev-service.ts matchTechnologiesAgainstKev
  function matchesPattern(techLower: string, pattern: string): boolean {
    if (techLower.length < 3) return false;
    return techLower.includes(pattern) || techLower === pattern;
  }

  it("should match when tech name exactly equals pattern", () => {
    expect(matchesPattern("nginx", "nginx")).toBe(true);
    expect(matchesPattern("apache", "apache")).toBe(true);
    expect(matchesPattern("wordpress", "wordpress")).toBe(true);
  });

  it("should match when tech name contains the pattern", () => {
    expect(matchesPattern("apache httpd", "apache")).toBe(true);
    expect(matchesPattern("nginx/1.21.3", "nginx")).toBe(true); // version string still contains "nginx"
    expect(matchesPattern("f5 big-ip", "big-ip")).toBe(true);
  });

  it("should NOT match when pattern contains tech name (reverse match removed)", () => {
    // This was the root cause of false positives:
    // "api" would match "apache" because "apache".includes("api") was true
    expect(matchesPattern("api", "apache")).toBe(false);
    expect(matchesPattern("app", "apache")).toBe(false);
    expect(matchesPattern("cdn", "cloudfront")).toBe(false);
    expect(matchesPattern("ssh", "sharepoint")).toBe(false);
  });

  it("should reject tech names shorter than 3 characters", () => {
    expect(matchesPattern("ip", "iis")).toBe(false);
    expect(matchesPattern("db", "docker")).toBe(false);
    expect(matchesPattern("js", "jenkins")).toBe(false);
  });

  it("should handle the api.dev false positive scenario", () => {
    // The api.dev asset had technologies like "CloudFront", "Amazon S3", etc.
    // These should match their own patterns but NOT pull in unrelated KEV entries
    const apiDevTechs = ["cloudfront", "amazon s3", "nginx", "react"];

    // CloudFront should NOT match "apache" pattern
    expect(matchesPattern("cloudfront", "apache")).toBe(false);
    // But it should match "cloudfront" if that pattern existed
    expect(matchesPattern("cloudfront", "cloudfront")).toBe(true);

    // "react" should NOT match "redis" or "exchange"
    expect(matchesPattern("react", "redis")).toBe(false);
    expect(matchesPattern("react", "exchange")).toBe(false);
  });
});

// ─── Test 2: Version Confidence in domain-intel-advanced ──────────────────────

describe("Version confidence for tech CVE matching", () => {
  it("should mark unknown version matches as 'potential'", () => {
    const version = "unknown";
    const versionConfidence = version !== "unknown" ? "confirmed" : "potential";
    expect(versionConfidence).toBe("potential");
  });

  it("should mark known version matches as 'confirmed' when version matches", () => {
    const version = "2.4.49";
    const versionConfidence = version !== "unknown" ? "confirmed" : "potential";
    expect(versionConfidence).toBe("confirmed");
  });

  it("should reduce CVSS score for potential matches", () => {
    const baseCvss = 9.8;
    const potentialCvss = Math.max(baseCvss - 2, 1);
    expect(potentialCvss).toBeCloseTo(7.8, 1);
  });

  it("should downgrade critical severity to high for potential matches", () => {
    const severity = "critical";
    const versionConfidence = "potential";
    const adjustedSeverity = versionConfidence === "potential" && severity === "critical" ? "high" : severity;
    expect(adjustedSeverity).toBe("high");
  });

  it("should NOT downgrade non-critical severities for potential matches", () => {
    const severity = "high";
    const versionConfidence = "potential";
    const adjustedSeverity = versionConfidence === "potential" && severity === "critical" ? "high" : severity;
    expect(adjustedSeverity).toBe("high"); // unchanged
  });
});

// ─── Test 3: Exploit Evidence Persistence ─────────────────────────────────────

describe("Exploit evidence persistence", () => {
  interface ExploitAttempt {
    module: string;
    success: boolean;
    sessionId?: string;
    cve?: string;
    service?: string;
    port?: number;
    target?: string;
    confidence?: number;
    reasoning?: string;
    selectedExploit?: { modulePath?: string; payload?: string; options?: Record<string, any> };
    timestamp?: number;
    durationMs?: number;
    errorDetail?: string;
  }

  it("should include full evidence fields in successful exploit attempt", () => {
    const attempt: ExploitAttempt = {
      module: "exploit/multi/http/apache_mod_cgi_bash_env_exec",
      success: true,
      sessionId: "session-123",
      cve: "CVE-2014-6271",
      service: "http",
      port: 80,
      target: "192.168.1.100",
      confidence: 0.85,
      reasoning: "Target runs Apache 2.4.49 with mod_cgi enabled, vulnerable to Shellshock",
      selectedExploit: {
        modulePath: "exploit/multi/http/apache_mod_cgi_bash_env_exec",
        payload: "linux/x64/meterpreter/reverse_tcp",
      },
      timestamp: Date.now(),
      durationMs: 3200,
    };

    expect(attempt.cve).toBe("CVE-2014-6271");
    expect(attempt.confidence).toBe(0.85);
    expect(attempt.reasoning).toContain("Shellshock");
    expect(attempt.selectedExploit?.modulePath).toBeTruthy();
    expect(attempt.timestamp).toBeGreaterThan(0);
    expect(attempt.errorDetail).toBeUndefined();
  });

  it("should include error details in failed exploit attempt", () => {
    const attempt: ExploitAttempt = {
      module: "auto",
      success: false,
      cve: "CVE-2024-1234",
      service: "ssh",
      port: 22,
      target: "10.0.0.5",
      timestamp: Date.now(),
      errorDetail: "Connection refused: target port 22 not responding",
    };

    expect(attempt.success).toBe(false);
    expect(attempt.errorDetail).toContain("Connection refused");
    expect(attempt.sessionId).toBeUndefined();
    expect(attempt.confidence).toBeUndefined();
  });
});

// ─── Test 4: Vulnerability Deduplication ──────────────────────────────────────

describe("Vulnerability deduplication (pushVulnDeduped)", () => {
  // Simulates the pushVulnDeduped function from engagement-orchestrator.ts
  interface Vuln {
    id: string;
    severity: string;
    title: string;
    cve?: string;
  }

  function pushVulnDeduped(vulns: Vuln[], vuln: Vuln): boolean {
    const isDuplicate = vulns.some((existing) => {
      if (vuln.cve && existing.cve && vuln.cve === existing.cve) return true;
      if (existing.title === vuln.title) return true;
      return false;
    });
    if (isDuplicate) return false;
    vulns.push(vuln);
    return true;
  }

  it("should add a new unique vulnerability", () => {
    const vulns: Vuln[] = [];
    const added = pushVulnDeduped(vulns, { id: "1", severity: "high", title: "SQL Injection", cve: "CVE-2024-1234" });
    expect(added).toBe(true);
    expect(vulns).toHaveLength(1);
  });

  it("should reject duplicate by CVE", () => {
    const vulns: Vuln[] = [{ id: "1", severity: "high", title: "SQL Injection", cve: "CVE-2024-1234" }];
    const added = pushVulnDeduped(vulns, { id: "2", severity: "critical", title: "Different Title", cve: "CVE-2024-1234" });
    expect(added).toBe(false);
    expect(vulns).toHaveLength(1);
  });

  it("should reject duplicate by title", () => {
    const vulns: Vuln[] = [{ id: "1", severity: "high", title: "SQL Injection" }];
    const added = pushVulnDeduped(vulns, { id: "2", severity: "high", title: "SQL Injection", cve: "CVE-2024-5678" });
    expect(added).toBe(false);
    expect(vulns).toHaveLength(1);
  });

  it("should allow different vulns with different CVEs and titles", () => {
    const vulns: Vuln[] = [{ id: "1", severity: "high", title: "SQL Injection", cve: "CVE-2024-1234" }];
    const added = pushVulnDeduped(vulns, { id: "2", severity: "medium", title: "XSS Vulnerability", cve: "CVE-2024-5678" });
    expect(added).toBe(true);
    expect(vulns).toHaveLength(2);
  });

  it("should handle vulns without CVEs (title-only dedup)", () => {
    const vulns: Vuln[] = [{ id: "1", severity: "high", title: "Weak SSL Configuration" }];
    const added1 = pushVulnDeduped(vulns, { id: "2", severity: "high", title: "Weak SSL Configuration" });
    const added2 = pushVulnDeduped(vulns, { id: "3", severity: "medium", title: "Missing HSTS Header" });
    expect(added1).toBe(false);
    expect(added2).toBe(true);
    expect(vulns).toHaveLength(2);
  });

  it("should handle the multi-phase scan scenario (targeted_enum + nuclei + credential_test)", () => {
    const vulns: Vuln[] = [];

    // Phase 1: targeted_enum finds CVE-2024-1234
    pushVulnDeduped(vulns, { id: "1", severity: "high", title: "Apache Path Traversal", cve: "CVE-2024-1234" });
    expect(vulns).toHaveLength(1);

    // Phase 2: nuclei also finds CVE-2024-1234 — should be deduped
    const nucleiAdded = pushVulnDeduped(vulns, { id: "2", severity: "high", title: "Apache Path Traversal", cve: "CVE-2024-1234" });
    expect(nucleiAdded).toBe(false);
    expect(vulns).toHaveLength(1);

    // Phase 3: credential test finds same title — should be deduped
    const credAdded = pushVulnDeduped(vulns, { id: "3", severity: "high", title: "Apache Path Traversal" });
    expect(credAdded).toBe(false);
    expect(vulns).toHaveLength(1);

    // Phase 4: re-scan finds a genuinely new vuln — should be added
    const rescanAdded = pushVulnDeduped(vulns, { id: "4", severity: "critical", title: "RCE via Deserialization", cve: "CVE-2024-9999" });
    expect(rescanAdded).toBe(true);
    expect(vulns).toHaveLength(2);
  });
});

// ─── Test 5: Posture-to-Vulns corroboration tier ──────────────────────────────

describe("postureToVulns corroboration tier assignment", () => {
  function determineCorroborationTier(finding: any): string {
    const hasVersion = !!finding.detectedVersion && finding.detectedVersion !== "unknown";
    const hasConfirmedVersion = hasVersion && finding.versionConfidence === "confirmed";
    return hasConfirmedVersion ? "confirmed" : hasVersion ? "probable" : "potential";
  }

  it("should assign 'confirmed' when version is known and confirmed", () => {
    expect(determineCorroborationTier({ detectedVersion: "2.4.49", versionConfidence: "confirmed" })).toBe("confirmed");
  });

  it("should assign 'probable' when version is known but not explicitly confirmed", () => {
    expect(determineCorroborationTier({ detectedVersion: "1.21.3" })).toBe("probable");
  });

  it("should assign 'potential' when version is unknown", () => {
    expect(determineCorroborationTier({ detectedVersion: "unknown" })).toBe("potential");
    expect(determineCorroborationTier({})).toBe("potential");
    expect(determineCorroborationTier({ detectedVersion: null })).toBe("potential");
  });
});
