/**
 * Gobuster Enhancements Tests
 *
 * Tests for the 6 Gobuster scan enhancements:
 * 1. Authenticated scanning (cookie injection)
 * 2. Extension enumeration on Standard/Deep profiles
 * 3. Follow redirects
 * 4. Random user-agent
 * 5. Status code filtering (WAF-adaptive)
 * 6. Custom HTTP methods (API targets)
 */
import { describe, it, expect } from "vitest";
import { buildGobusterCommand, getScanProfile, SCAN_PROFILES } from "./lib/scan-profiles";

describe("buildGobusterCommand", () => {
  describe("Basic command generation", () => {
    it("generates a valid gobuster dir command with target URL", () => {
      const profile = getScanProfile("standard");
      const cmd = buildGobusterCommand(profile, "https://example.com");
      expect(cmd).toContain("gobuster dir -u https://example.com");
      expect(cmd).toContain("-w /opt/SecLists/Discovery/Web-Content/common.txt");
    });

    it("includes thread count from profile", () => {
      const profile = getScanProfile("standard");
      const cmd = buildGobusterCommand(profile, "https://example.com");
      expect(cmd).toContain("-t 30");
    });

    it("includes quiet and no-error flags from profile extraFlags", () => {
      const profile = getScanProfile("standard");
      const cmd = buildGobusterCommand(profile, "https://example.com");
      expect(cmd).toContain("-q");
      expect(cmd).toContain("--no-error");
    });

    it("uses correct wordlist for deep profile", () => {
      const profile = getScanProfile("deep");
      const cmd = buildGobusterCommand(profile, "https://example.com");
      expect(cmd).toContain("-w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt");
    });
  });

  describe("Enhancement 1: Authenticated scanning", () => {
    it("injects auth cookie when profile allows and cookie is provided", () => {
      const profile = getScanProfile("standard");
      const cmd = buildGobusterCommand(profile, "https://example.com", {
        authCookie: "PHPSESSID=abc123; security=low",
      });
      expect(cmd).toContain("-c PHPSESSID=abc123; security=low");
    });

    it("does NOT inject cookie when profile disallows (quick profile)", () => {
      const profile = getScanProfile("quick");
      const cmd = buildGobusterCommand(profile, "https://example.com", {
        authCookie: "PHPSESSID=abc123",
      });
      expect(cmd).not.toContain("-c");
    });

    it("does NOT inject cookie when no cookie is provided", () => {
      const profile = getScanProfile("standard");
      const cmd = buildGobusterCommand(profile, "https://example.com", {});
      expect(cmd).not.toContain("-c");
    });

    it("injects cookie for deep profile", () => {
      const profile = getScanProfile("deep");
      const cmd = buildGobusterCommand(profile, "https://target.com", {
        authCookie: "token=eyJhbGciOiJIUzI1NiJ9",
      });
      expect(cmd).toContain("-c token=eyJhbGciOiJIUzI1NiJ9");
    });
  });

  describe("Enhancement 2: Extension enumeration", () => {
    it("includes profile-defined extensions for standard profile", () => {
      const profile = getScanProfile("standard");
      const cmd = buildGobusterCommand(profile, "https://example.com");
      expect(cmd).toContain("-x php,html,js,txt,bak,env,conf");
    });

    it("includes extensive extensions for deep profile", () => {
      const profile = getScanProfile("deep");
      const cmd = buildGobusterCommand(profile, "https://example.com");
      expect(cmd).toContain("-x php,html,js,txt,bak,old,conf,env,swp,zip,tar.gz,sql,xml,json,yml,yaml,log");
    });

    it("does NOT include extensions for quick profile (no extensions defined)", () => {
      const profile = getScanProfile("quick");
      const cmd = buildGobusterCommand(profile, "https://example.com");
      expect(cmd).not.toContain("-x");
    });

    it("auto-detects PHP extensions from technology stack", () => {
      const profile = getScanProfile("quick"); // No profile extensions
      const cmd = buildGobusterCommand(profile, "https://example.com", {
        detectedTech: ["PHP 7.4", "Laravel"],
      });
      expect(cmd).toContain("-x");
      expect(cmd).toContain("php");
      expect(cmd).toContain("phtml");
    });

    it("auto-detects ASP.NET extensions from technology stack", () => {
      const profile = getScanProfile("quick");
      const cmd = buildGobusterCommand(profile, "https://example.com", {
        detectedTech: ["ASP.NET 4.8", "IIS 10"],
      });
      expect(cmd).toContain("-x");
      expect(cmd).toContain("asp");
      expect(cmd).toContain("aspx");
    });

    it("auto-detects Java extensions from technology stack", () => {
      const profile = getScanProfile("quick");
      const cmd = buildGobusterCommand(profile, "https://example.com", {
        detectedTech: ["Java", "Apache Tomcat"],
      });
      expect(cmd).toContain("-x");
      expect(cmd).toContain("jsp");
      expect(cmd).toContain("do");
    });

    it("auto-detects Node.js extensions from technology stack", () => {
      const profile = getScanProfile("quick");
      const cmd = buildGobusterCommand(profile, "https://example.com", {
        detectedTech: ["Node.js", "Express"],
      });
      expect(cmd).toContain("-x");
      expect(cmd).toContain("js");
      expect(cmd).toContain("json");
    });

    it("deduplicates extensions from multiple tech detections", () => {
      const profile = getScanProfile("quick");
      const cmd = buildGobusterCommand(profile, "https://example.com", {
        detectedTech: ["Node.js", "Express", "Node 18"],
      });
      // Should not have duplicate 'js' entries
      const extMatch = cmd.match(/-x\s+(\S+)/);
      expect(extMatch).toBeTruthy();
      const exts = extMatch![1].split(",");
      const unique = [...new Set(exts)];
      expect(exts.length).toBe(unique.length);
    });

    it("profile-defined extensions take precedence over tech detection", () => {
      const profile = getScanProfile("standard");
      const cmd = buildGobusterCommand(profile, "https://example.com", {
        detectedTech: ["Java", "Tomcat"],
      });
      // Standard profile has its own extensions, should use those not Java ones
      expect(cmd).toContain("-x php,html,js,txt,bak,env,conf");
      expect(cmd).not.toContain("jsp");
    });
  });

  describe("Enhancement 3: Follow redirects", () => {
    it("includes -r flag for standard profile", () => {
      const profile = getScanProfile("standard");
      const cmd = buildGobusterCommand(profile, "https://example.com");
      expect(cmd).toContain("-r");
    });

    it("includes -r flag for deep profile", () => {
      const profile = getScanProfile("deep");
      const cmd = buildGobusterCommand(profile, "https://example.com");
      expect(cmd).toContain("-r");
    });

    it("does NOT include -r flag for quick profile", () => {
      const profile = getScanProfile("quick");
      const cmd = buildGobusterCommand(profile, "https://example.com");
      expect(cmd).not.toContain(" -r");
    });

    it("does NOT include -r flag for stealth profile", () => {
      const profile = getScanProfile("stealth");
      const cmd = buildGobusterCommand(profile, "https://example.com");
      expect(cmd).not.toContain(" -r");
    });
  });

  describe("Enhancement 4: Random user-agent", () => {
    it("includes --random-agent for standard profile", () => {
      const profile = getScanProfile("standard");
      const cmd = buildGobusterCommand(profile, "https://example.com");
      expect(cmd).toContain("--random-agent");
    });

    it("includes --random-agent for deep profile", () => {
      const profile = getScanProfile("deep");
      const cmd = buildGobusterCommand(profile, "https://example.com");
      expect(cmd).toContain("--random-agent");
    });

    it("includes --random-agent for stealth profile", () => {
      const profile = getScanProfile("stealth");
      const cmd = buildGobusterCommand(profile, "https://example.com");
      expect(cmd).toContain("--random-agent");
    });

    it("does NOT include --random-agent for quick profile", () => {
      const profile = getScanProfile("quick");
      const cmd = buildGobusterCommand(profile, "https://example.com");
      expect(cmd).not.toContain("--random-agent");
    });
  });

  describe("Enhancement 5: Status code filtering (WAF-adaptive)", () => {
    it("adds -b 403 when WAF is detected and no profile excludeCodes set", () => {
      const profile = getScanProfile("standard");
      const cmd = buildGobusterCommand(profile, "https://example.com", {
        wafDetected: true,
      });
      expect(cmd).toContain("-b 403");
    });

    it("does NOT add -b flag when no WAF detected and no profile excludeCodes", () => {
      const profile = getScanProfile("standard");
      const cmd = buildGobusterCommand(profile, "https://example.com", {
        wafDetected: false,
      });
      expect(cmd).not.toContain("-b");
    });

    it("uses profile-defined excludeStatusCodes when set", () => {
      const profile = { ...getScanProfile("standard") };
      profile.gobuster = { ...profile.gobuster, excludeStatusCodes: "403,429" };
      const cmd = buildGobusterCommand(profile, "https://example.com");
      expect(cmd).toContain("-b 403,429");
    });
  });

  describe("Enhancement 6: Custom HTTP methods (API targets)", () => {
    it("adds -m GET,POST for API targets", () => {
      const profile = getScanProfile("standard");
      const cmd = buildGobusterCommand(profile, "https://api.example.com/v1/", {
        isApiTarget: true,
      });
      expect(cmd).toContain("-m GET,POST");
    });

    it("does NOT add -m for non-API targets", () => {
      const profile = getScanProfile("standard");
      const cmd = buildGobusterCommand(profile, "https://example.com", {
        isApiTarget: false,
      });
      expect(cmd).not.toContain("-m");
    });

    it("uses profile-defined httpMethod when set for API targets", () => {
      const profile = { ...getScanProfile("standard") };
      profile.gobuster = { ...profile.gobuster, httpMethod: "GET,POST,PUT,DELETE" };
      const cmd = buildGobusterCommand(profile, "https://api.example.com", {
        isApiTarget: true,
      });
      expect(cmd).toContain("-m GET,POST,PUT,DELETE");
    });
  });

  describe("WAF-adaptive thread reduction", () => {
    it("reduces threads to max 10 when WAF is detected", () => {
      const profile = getScanProfile("standard"); // normally 30 threads
      const cmd = buildGobusterCommand(profile, "https://example.com", {
        wafDetected: true,
      });
      expect(cmd).toContain("-t 10");
      expect(cmd).not.toContain("-t 30");
    });

    it("keeps threads unchanged when no WAF detected", () => {
      const profile = getScanProfile("standard");
      const cmd = buildGobusterCommand(profile, "https://example.com", {
        wafDetected: false,
      });
      expect(cmd).toContain("-t 30");
    });

    it("keeps threads at profile value if already <= 10", () => {
      const profile = getScanProfile("stealth"); // 5 threads
      const cmd = buildGobusterCommand(profile, "https://example.com", {
        wafDetected: true,
      });
      expect(cmd).toContain("-t 5");
    });

    it("adds --delay 200ms when WAF detected and no delay in extraFlags", () => {
      const profile = getScanProfile("standard");
      const cmd = buildGobusterCommand(profile, "https://example.com", {
        wafDetected: true,
      });
      expect(cmd).toContain("--delay 200ms");
    });

    it("does NOT add extra --delay when profile already has delay in extraFlags", () => {
      const profile = getScanProfile("stealth"); // already has --delay 500ms
      const cmd = buildGobusterCommand(profile, "https://example.com", {
        wafDetected: true,
      });
      // Should have the profile's 500ms delay but not an additional 200ms
      expect(cmd).toContain("--delay 500ms");
      expect(cmd).not.toContain("--delay 200ms");
    });
  });

  describe("Combined scenarios", () => {
    it("handles full WAF + auth + API target scenario", () => {
      const profile = getScanProfile("deep");
      const cmd = buildGobusterCommand(profile, "https://api.target.com/v2/", {
        wafDetected: true,
        authCookie: "session=xyz789",
        detectedTech: ["Node.js", "Express"],
        isApiTarget: true,
      });
      // WAF: reduced threads, -b 403, --delay
      expect(cmd).toContain("-t 10");
      expect(cmd).toContain("-b 403");
      expect(cmd).toContain("--delay 200ms");
      // Auth: cookie injected
      expect(cmd).toContain("-c session=xyz789");
      // API: method enumeration
      expect(cmd).toContain("-m GET,POST");
      // Deep profile: extensions from profile (not tech-detected)
      expect(cmd).toContain("-x php,html,js,txt,bak,old,conf,env,swp,zip,tar.gz,sql,xml,json,yml,yaml,log");
      // Deep profile: follow redirects + random agent
      expect(cmd).toContain("-r");
      expect(cmd).toContain("--random-agent");
    });

    it("handles stealth profile with WAF (no gobuster enabled but command still works)", () => {
      const profile = getScanProfile("stealth");
      const cmd = buildGobusterCommand(profile, "https://example.com", {
        wafDetected: true,
      });
      // Stealth: 5 threads (already <= 10, stays at 5)
      expect(cmd).toContain("-t 5");
      // Stealth: random agent enabled
      expect(cmd).toContain("--random-agent");
      // Stealth: has delay in extraFlags, no extra delay added
      expect(cmd).toContain("--delay 500ms");
    });
  });
});

describe("Scan Profile Gobuster Configuration", () => {
  it("quick profile has gobuster disabled in tools", () => {
    expect(SCAN_PROFILES.quick.tools.gobuster).toBe(false);
  });

  it("standard profile has gobuster enabled in tools", () => {
    expect(SCAN_PROFILES.standard.tools.gobuster).toBe(true);
  });

  it("deep profile has gobuster enabled in tools", () => {
    expect(SCAN_PROFILES.deep.tools.gobuster).toBe(true);
  });

  it("stealth profile has gobuster disabled in tools", () => {
    expect(SCAN_PROFILES.stealth.tools.gobuster).toBe(false);
  });

  it("standard profile has useAuthCookies enabled", () => {
    expect(SCAN_PROFILES.standard.gobuster.useAuthCookies).toBe(true);
  });

  it("quick profile has useAuthCookies disabled", () => {
    expect(SCAN_PROFILES.quick.gobuster.useAuthCookies).toBe(false);
  });

  it("standard profile has followRedirects enabled", () => {
    expect(SCAN_PROFILES.standard.gobuster.followRedirects).toBe(true);
  });

  it("standard profile has randomAgent enabled", () => {
    expect(SCAN_PROFILES.standard.gobuster.randomAgent).toBe(true);
  });

  it("all profiles have valid wordlist paths", () => {
    for (const [name, profile] of Object.entries(SCAN_PROFILES)) {
      expect(profile.gobuster.wordlist).toMatch(/^\/opt\/SecLists\//);
    }
  });

  it("all profiles have positive thread counts", () => {
    for (const [name, profile] of Object.entries(SCAN_PROFILES)) {
      expect(profile.gobuster.threads).toBeGreaterThan(0);
    }
  });
});

describe("Gobuster Output Parser (severity classification)", () => {
  // Test the regex pattern used in the output parser
  const parseGobusterLine = (line: string) => {
    const match = line.match(/\/(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?/);
    if (!match) return null;
    const [, path, status, sizeStr] = match;
    const size = sizeStr ? parseInt(sizeStr, 10) : undefined;
    return { path, status, size };
  };

  it("parses standard gobuster output with size", () => {
    const result = parseGobusterLine("/admin (Status: 200) [Size: 4523]");
    expect(result).toEqual({ path: "admin", status: "200", size: 4523 });
  });

  it("parses gobuster output without size", () => {
    const result = parseGobusterLine("/login (Status: 302)");
    expect(result).toEqual({ path: "login", status: "302", size: undefined });
  });

  it("parses 403 with size for severity classification", () => {
    const result = parseGobusterLine("/secret (Status: 403) [Size: 1024]");
    expect(result).toEqual({ path: "secret", status: "403", size: 1024 });
    // Size > 500 → medium severity
    expect(result!.size! > 500).toBe(true);
  });

  it("parses sensitive file extensions", () => {
    const result = parseGobusterLine("/.env (Status: 200) [Size: 256]");
    expect(result).toEqual({ path: ".env", status: "200", size: 256 });
  });

  it("returns null for non-matching lines", () => {
    expect(parseGobusterLine("Progress: 4614 / 4615 (99.98%)")).toBeNull();
    expect(parseGobusterLine("===============================================================")).toBeNull();
    expect(parseGobusterLine("")).toBeNull();
  });
});
