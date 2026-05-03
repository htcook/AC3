import { describe, it, expect } from "vitest";

describe("Nuclei Template Selection by Tech Stack", () => {
  it("should export getNucleiTagsForTech function", async () => {
    const { getNucleiTagsForTech } = await import("./lib/tool-knowledge-base");
    expect(typeof getNucleiTagsForTech).toBe("function");
  });

  it("should return wordpress tags for WordPress detection", async () => {
    const { getNucleiTagsForTech } = await import("./lib/tool-knowledge-base");
    const tags = getNucleiTagsForTech(["WordPress"]);
    expect(tags).toContain("wordpress");
    expect(tags).toContain("wp-plugin");
    expect(tags).toContain("wp-theme");
  });

  it("should return apache tags for Apache detection", async () => {
    const { getNucleiTagsForTech } = await import("./lib/tool-knowledge-base");
    const tags = getNucleiTagsForTech(["Apache/2.4.51"]);
    expect(tags).toContain("apache");
    expect(tags).toContain("httpd");
  });

  it("should return java tags for Tomcat detection", async () => {
    const { getNucleiTagsForTech } = await import("./lib/tool-knowledge-base");
    const tags = getNucleiTagsForTech(["Apache Tomcat/9.0.50"]);
    expect(tags).toContain("tomcat");
    expect(tags).toContain("java");
  });

  it("should return spring tags for Spring Boot detection", async () => {
    const { getNucleiTagsForTech } = await import("./lib/tool-knowledge-base");
    const tags = getNucleiTagsForTech(["Spring Boot"]);
    expect(tags).toContain("spring");
    expect(tags).toContain("java");
    expect(tags).toContain("springboot");
  });

  it("should return nginx tags for Nginx detection", async () => {
    const { getNucleiTagsForTech } = await import("./lib/tool-knowledge-base");
    const tags = getNucleiTagsForTech(["nginx/1.21.0"]);
    expect(tags).toContain("nginx");
  });

  it("should return jenkins tags for Jenkins detection", async () => {
    const { getNucleiTagsForTech } = await import("./lib/tool-knowledge-base");
    const tags = getNucleiTagsForTech(["Jenkins"]);
    expect(tags).toContain("jenkins");
  });

  it("should combine tags for multiple technologies", async () => {
    const { getNucleiTagsForTech } = await import("./lib/tool-knowledge-base");
    const tags = getNucleiTagsForTech(["WordPress", "Apache/2.4", "PHP/7.4"]);
    expect(tags).toContain("wordpress");
    expect(tags).toContain("apache");
    expect(tags).toContain("php");
  });

  it("should return empty array for unknown technologies", async () => {
    const { getNucleiTagsForTech } = await import("./lib/tool-knowledge-base");
    const tags = getNucleiTagsForTech(["SomeUnknownTech123"]);
    expect(tags).toEqual([]);
  });

  it("should handle case-insensitive matching", async () => {
    const { getNucleiTagsForTech } = await import("./lib/tool-knowledge-base");
    const tags = getNucleiTagsForTech(["WORDPRESS", "NGINX"]);
    expect(tags).toContain("wordpress");
    expect(tags).toContain("nginx");
  });

  it("should export NUCLEI_TECH_TAG_MAP with expected keys", async () => {
    const { NUCLEI_TECH_TAG_MAP } = await import("./lib/tool-knowledge-base");
    expect(NUCLEI_TECH_TAG_MAP).toBeDefined();
    expect(NUCLEI_TECH_TAG_MAP.wordpress).toBeDefined();
    expect(NUCLEI_TECH_TAG_MAP.apache).toBeDefined();
    expect(NUCLEI_TECH_TAG_MAP.nginx).toBeDefined();
    expect(NUCLEI_TECH_TAG_MAP.jenkins).toBeDefined();
    expect(NUCLEI_TECH_TAG_MAP.spring).toBeDefined();
  });
});

describe("buildNucleiCommand", () => {
  it("should export buildNucleiCommand function", async () => {
    const { buildNucleiCommand } = await import("./lib/tool-knowledge-base");
    expect(typeof buildNucleiCommand).toBe("function");
  });

  it("should use -as flag when no technologies provided", async () => {
    const { buildNucleiCommand } = await import("./lib/tool-knowledge-base");
    const cmd = buildNucleiCommand({ target: "http://example.com" });
    expect(cmd).toContain("-as");
    expect(cmd).toContain("-nc");
    expect(cmd).toContain("-duc");
    expect(cmd).toContain("-ni");
    expect(cmd).toContain("-jsonl");
  });

  it("should use -tags when technologies are provided", async () => {
    const { buildNucleiCommand } = await import("./lib/tool-knowledge-base");
    const cmd = buildNucleiCommand({
      target: "http://example.com",
      technologies: ["WordPress", "PHP"],
    });
    expect(cmd).toContain("-tags");
    expect(cmd).toContain("wordpress");
    expect(cmd).not.toContain("-as");
  });

  it("should add severity filter for quick scan depth", async () => {
    const { buildNucleiCommand } = await import("./lib/tool-knowledge-base");
    const cmd = buildNucleiCommand({
      target: "http://example.com",
      scanDepth: "quick",
    });
    expect(cmd).toContain("-severity");
    expect(cmd).toContain("critical,high");
  });

  it("should add Cookie header when authenticated", async () => {
    const { buildNucleiCommand } = await import("./lib/tool-knowledge-base");
    const cmd = buildNucleiCommand({
      target: "http://example.com",
      authenticated: true,
      cookie: "PHPSESSID=abc123; security=low",
    });
    expect(cmd).toContain("-H");
    expect(cmd).toContain("Cookie:");
    expect(cmd).toContain("PHPSESSID=abc123");
  });

  it("should reduce rate limit for WAF targets", async () => {
    const { buildNucleiCommand } = await import("./lib/tool-knowledge-base");
    const cmd = buildNucleiCommand({
      target: "http://example.com",
      wafDetected: true,
    });
    expect(cmd).toContain("-rl 15");
    expect(cmd).toContain("-c 5");
    expect(cmd).toContain("-timeout 15");
  });

  it("should use higher rate limits for deep scan", async () => {
    const { buildNucleiCommand } = await import("./lib/tool-knowledge-base");
    const cmd = buildNucleiCommand({
      target: "http://example.com",
      scanDepth: "deep",
    });
    expect(cmd).toContain("-rl 50");
    expect(cmd).toContain("-c 25");
  });
});

describe("Nikto Knowledge Base", () => {
  it("should have nikto entry in TOOL_KNOWLEDGE_BASE", async () => {
    const { TOOL_KNOWLEDGE_BASE } = await import("./lib/tool-knowledge-base");
    expect(TOOL_KNOWLEDGE_BASE.nikto).toBeDefined();
    expect(TOOL_KNOWLEDGE_BASE.nikto.tool).toBe("nikto");
  });

  it("should have nikto techniques covering key scan types", async () => {
    const { TOOL_KNOWLEDGE_BASE } = await import("./lib/tool-knowledge-base");
    const nikto = TOOL_KNOWLEDGE_BASE.nikto;
    const techniqueNames = nikto.techniques.map(t => t.name);
    expect(techniqueNames).toContain("Targeted Misconfiguration Scan");
    expect(techniqueNames).toContain("Injection Vulnerability Scan");
    expect(techniqueNames).toContain("Evasive Scan (IDS Bypass)");
    expect(techniqueNames).toContain("Authenticated Scan with Cookie");
  });

  it("should have nikto evasion strategies", async () => {
    const { TOOL_KNOWLEDGE_BASE } = await import("./lib/tool-knowledge-base");
    const nikto = TOOL_KNOWLEDGE_BASE.nikto;
    expect(nikto.evasionStrategies.length).toBeGreaterThan(5);
    expect(nikto.evasionStrategies.some(s => s.includes("evasion 1"))).toBe(true);
  });

  it("should export NIKTO_TUNING_PROFILES", async () => {
    const { NIKTO_TUNING_PROFILES } = await import("./lib/tool-knowledge-base");
    expect(NIKTO_TUNING_PROFILES).toBeDefined();
    expect(NIKTO_TUNING_PROFILES.quick).toBeDefined();
    expect(NIKTO_TUNING_PROFILES.comprehensive).toBeDefined();
    expect(NIKTO_TUNING_PROFILES.stealth).toBeDefined();
    expect(NIKTO_TUNING_PROFILES.injection).toBeDefined();
  });

  it("should have correct tuning values in profiles", async () => {
    const { NIKTO_TUNING_PROFILES } = await import("./lib/tool-knowledge-base");
    expect(NIKTO_TUNING_PROFILES.quick.tuning).toBe("12b");
    expect(NIKTO_TUNING_PROFILES.injection.tuning).toBe("489");
    expect(NIKTO_TUNING_PROFILES.comprehensive.tuning).toBe("123456789abc");
    expect(NIKTO_TUNING_PROFILES.stealth.evasion).toBe("1247");
  });
});

describe("buildNiktoCommand", () => {
  it("should export buildNiktoCommand function", async () => {
    const { buildNiktoCommand } = await import("./lib/tool-knowledge-base");
    expect(typeof buildNiktoCommand).toBe("function");
  });

  it("should build basic nikto command with quick profile", async () => {
    const { buildNiktoCommand } = await import("./lib/tool-knowledge-base");
    const cmd = buildNiktoCommand({ target: "http://example.com" });
    expect(cmd).toContain("nikto");
    expect(cmd).toContain("-h http://example.com");
    expect(cmd).toContain("-Tuning 12b");
    expect(cmd).toContain("-Format xml");
    expect(cmd).toContain("-nointeractive");
  });

  it("should add -ssl for HTTPS targets", async () => {
    const { buildNiktoCommand } = await import("./lib/tool-knowledge-base");
    const cmd = buildNiktoCommand({ target: "https://example.com" });
    expect(cmd).toContain("-ssl");
  });

  it("should add -id for basic auth credentials", async () => {
    const { buildNiktoCommand } = await import("./lib/tool-knowledge-base");
    const cmd = buildNiktoCommand({
      target: "http://example.com",
      authenticated: true,
      credentials: { user: "admin", pass: "password" },
    });
    expect(cmd).toContain("-id admin:password");
  });

  it("should add Cookie header when cookie provided", async () => {
    const { buildNiktoCommand } = await import("./lib/tool-knowledge-base");
    const cmd = buildNiktoCommand({
      target: "http://example.com",
      cookie: "PHPSESSID=abc123",
    });
    expect(cmd).toContain("-H");
    expect(cmd).toContain("Cookie: PHPSESSID=abc123");
  });

  it("should add evasion for WAF targets", async () => {
    const { buildNiktoCommand } = await import("./lib/tool-knowledge-base");
    const cmd = buildNiktoCommand({
      target: "http://example.com",
      wafDetected: true,
    });
    expect(cmd).toContain("-evasion 1247");
    expect(cmd).toContain("-Pause 3");
  });

  it("should use stealth profile evasion", async () => {
    const { buildNiktoCommand } = await import("./lib/tool-knowledge-base");
    const cmd = buildNiktoCommand({
      target: "http://example.com",
      tuningProfile: "stealth",
    });
    expect(cmd).toContain("-evasion 1247");
    expect(cmd).toContain("-Tuning 12b");
  });

  it("should add maxtime when specified", async () => {
    const { buildNiktoCommand } = await import("./lib/tool-knowledge-base");
    const cmd = buildNiktoCommand({
      target: "http://example.com",
      maxTime: 600,
    });
    expect(cmd).toContain("-maxtime 600");
  });

  it("should use comprehensive tuning profile", async () => {
    const { buildNiktoCommand } = await import("./lib/tool-knowledge-base");
    const cmd = buildNiktoCommand({
      target: "http://example.com",
      tuningProfile: "comprehensive",
    });
    expect(cmd).toContain("-Tuning 123456789abc");
  });
});

describe("Shared Auto-Auth: Nikto Cookie Injection", () => {
  it("should inject training lab cookie into nikto command when available", () => {
    // Simulate the logic from the orchestrator
    const asset = {
      hostname: "dvwa.lab.local",
      ip: "10.0.0.5",
      trainingLabCreds: { sessionCookie: "PHPSESSID=test123; security=low" },
      confirmedCredentials: [],
      ports: [],
    };

    let niktoCommand = "nikto -h http://dvwa.lab.local -Tuning 12b -Format xml -o nikto.xml -nointeractive";

    // Replicate the nikto auth injection logic
    if (!niktoCommand.includes('Cookie:') && !niktoCommand.includes('-id ')) {
      let niktoCookie = '';
      if ((asset as any).trainingLabCreds?.sessionCookie) {
        niktoCookie = (asset as any).trainingLabCreds.sessionCookie;
      }
      if (niktoCookie) {
        niktoCommand += ` -H "Cookie: ${niktoCookie}"`;
      }
    }

    expect(niktoCommand).toContain('-H "Cookie: PHPSESSID=test123; security=low"');
  });

  it("should NOT inject cookie when nikto already has Cookie header", () => {
    const asset = {
      hostname: "dvwa.lab.local",
      trainingLabCreds: { sessionCookie: "PHPSESSID=test123" },
      confirmedCredentials: [],
    };

    let niktoCommand = 'nikto -h http://dvwa.lab.local -H "Cookie: existing=cookie" -nointeractive';

    if (!niktoCommand.includes('Cookie:') && !niktoCommand.includes('-id ')) {
      niktoCommand += ` -H "Cookie: ${(asset as any).trainingLabCreds.sessionCookie}"`;
    }

    // Should NOT have double cookie injection
    expect(niktoCommand.match(/Cookie:/g)?.length).toBe(1);
  });

  it("should NOT inject cookie when nikto uses -id auth", () => {
    const asset = {
      hostname: "target.lab.local",
      trainingLabCreds: { sessionCookie: "token=abc" },
      confirmedCredentials: [],
    };

    let niktoCommand = "nikto -h http://target.lab.local -id admin:password -nointeractive";

    if (!niktoCommand.includes('Cookie:') && !niktoCommand.includes('-id ')) {
      niktoCommand += ` -H "Cookie: ${(asset as any).trainingLabCreds.sessionCookie}"`;
    }

    expect(niktoCommand).not.toContain("Cookie:");
  });
});

describe("Shared Auto-Auth: SQLMap Cookie Reuse", () => {
  it("should reuse Gobuster session cookie for SQLMap when available", () => {
    // Simulate the shared auth logic
    const webApp = {
      hostname: "dvwa.lab.local",
      trainingLabCreds: { sessionCookie: "PHPSESSID=gobuster_session; security=low" },
      confirmedCredentials: [],
    };

    const webCreds = (webApp as any).confirmedCredentials || [];
    let cookieStr = webCreds.length > 0 ? webCreds[0]?.sessionCookie || "" : "";

    // Shared auto-auth: reuse from Gobuster
    if (!cookieStr && (webApp as any).trainingLabCreds?.sessionCookie) {
      cookieStr = (webApp as any).trainingLabCreds.sessionCookie;
    }

    expect(cookieStr).toBe("PHPSESSID=gobuster_session; security=low");
  });

  it("should prefer confirmed credentials over training lab creds", () => {
    const webApp = {
      hostname: "dvwa.lab.local",
      trainingLabCreds: { sessionCookie: "PHPSESSID=gobuster_old" },
      confirmedCredentials: [{ sessionCookie: "PHPSESSID=confirmed_session" }],
    };

    const webCreds = (webApp as any).confirmedCredentials || [];
    let cookieStr = webCreds.length > 0 ? webCreds[0]?.sessionCookie || "" : "";

    if (!cookieStr && (webApp as any).trainingLabCreds?.sessionCookie) {
      cookieStr = (webApp as any).trainingLabCreds.sessionCookie;
    }

    expect(cookieStr).toBe("PHPSESSID=confirmed_session");
  });

  it("should fall back to empty string when no auth available", () => {
    const webApp = {
      hostname: "unknown.target.com",
      confirmedCredentials: [],
    };

    const webCreds = (webApp as any).confirmedCredentials || [];
    let cookieStr = webCreds.length > 0 ? webCreds[0]?.sessionCookie || "" : "";

    if (!cookieStr && (webApp as any).trainingLabCreds?.sessionCookie) {
      cookieStr = (webApp as any).trainingLabCreds.sessionCookie;
    }

    expect(cookieStr).toBe("");
  });
});

describe("Nuclei Knowledge Base Expansion", () => {
  it("should have expanded nuclei techniques including tech-specific scans", async () => {
    const { TOOL_KNOWLEDGE_BASE } = await import("./lib/tool-knowledge-base");
    const nuclei = TOOL_KNOWLEDGE_BASE.nuclei;
    const techniqueNames = nuclei.techniques.map(t => t.name);
    expect(techniqueNames).toContain("Automatic Tech-Stack Scan");
    expect(techniqueNames).toContain("WordPress Targeted Scan");
    expect(techniqueNames).toContain("Apache/Nginx Server Scan");
    expect(techniqueNames).toContain("Java/Tomcat Stack Scan");
    expect(techniqueNames).toContain("CI/CD and DevOps Scan");
    expect(techniqueNames).toContain("Default Login Detection");
    expect(techniqueNames).toContain("Authenticated Nuclei Scan");
  });

  it("should have nuclei auto-detect technique with -as flag", async () => {
    const { TOOL_KNOWLEDGE_BASE } = await import("./lib/tool-knowledge-base");
    const nuclei = TOOL_KNOWLEDGE_BASE.nuclei;
    const autoTech = nuclei.techniques.find(t => t.name === "Automatic Tech-Stack Scan");
    expect(autoTech).toBeDefined();
    expect(autoTech!.command).toContain("-as");
  });

  it("should have nuclei capabilities including auto-detect and auth", async () => {
    const { TOOL_KNOWLEDGE_BASE } = await import("./lib/tool-knowledge-base");
    const nuclei = TOOL_KNOWLEDGE_BASE.nuclei;
    expect(nuclei.capabilities).toContain("Automatic tech-stack detection with -as flag");
    expect(nuclei.capabilities).toContain("Tag-based template selection by technology");
    expect(nuclei.capabilities).toContain("Authenticated scanning with cookies/headers");
  });
});
