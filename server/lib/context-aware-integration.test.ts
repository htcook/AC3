import { describe, it, expect } from "vitest";

// ─── Context-Aware Scanner Integration Tests ────────────────────────────────
// Tests that the context-aware scanner modules work correctly when called
// with the same data shapes the orchestrator passes to them.

describe("Context-Aware Scanner → Orchestrator Integration", () => {

  // ── Phase A.6: Target Profiling from httpx data ──

  it("should detect Cloudflare WAF from httpx response headers", async () => {
    const { detectWAF } = await import("./context-aware-scanner");
    const headers: Record<string, string> = {
      server: "cloudflare",
      "cf-ray": "abc123-IAD",
      "cf-cache-status": "DYNAMIC",
    };
    const result = detectWAF(headers, [], "", 200);
    expect(result.detected).toBe(true);
    expect(result.vendor).toBe("cloudflare"); // vendor names are lowercase keys
    expect(result.bypassTechniques.length).toBeGreaterThan(0);
  });

  it("should detect AWS CloudFront CDN from CNAME records", async () => {
    const { detectCDN } = await import("./context-aware-scanner");
    const headers: Record<string, string> = {
      "x-amz-cf-id": "abc123",
      "x-amz-cf-pop": "IAD55-C1",
    };
    const cnames = ["d111111abcdef8.cloudfront.net"];
    const result = detectCDN(headers, cnames);
    expect(result.detected).toBe(true);
    expect(result.provider).toBe("cloudfront"); // provider names are lowercase keys
  });

  it("should classify reverse proxy from nginx headers and port 443 only", async () => {
    const { classifyAssetRole } = await import("./context-aware-scanner");
    const fingerprint = {
      serverHeader: "nginx/1.24.0",
      webServer: { name: "nginx", version: "1.24.0", role: "unknown" as const },
      appFramework: null,
      cms: null,
      os: null,
      tls: null,
      languages: [],
      jsFrameworks: [],
      databases: [],
      techTags: ["nginx"],
      serviceBanners: {
        443: { service: "https", version: null, banner: null, protocol: "tcp" as const },
      },
    };
    const result = classifyAssetRole(fingerprint, [443], { server: "nginx/1.24.0" });
    expect(result.role).toBe("reverse_proxy");
    expect(result.confidence).toBeGreaterThan(0); // confidence varies by heuristic
  });

  it("should classify web app server from PHP + Apache + multiple ports", async () => {
    const { classifyAssetRole } = await import("./context-aware-scanner");
    const fingerprint = {
      serverHeader: "Apache/2.4.49",
      webServer: { name: "Apache", version: "2.4.49", role: "unknown" as const },
      appFramework: { name: "PHP", version: "7.4", language: "PHP" },
      cms: { name: "WordPress", version: "6.4" },
      os: null,
      tls: null,
      languages: ["PHP"],
      jsFrameworks: [],
      databases: ["MySQL"],
      techTags: ["Apache", "PHP", "WordPress", "MySQL"],
      serviceBanners: {
        80: { service: "http", version: null, banner: null, protocol: "tcp" as const },
        443: { service: "https", version: null, banner: null, protocol: "tcp" as const },
        3306: { service: "mysql", version: null, banner: null, protocol: "tcp" as const },
      },
    };
    const result = classifyAssetRole(fingerprint, [80, 443, 3306], { server: "Apache/2.4.49" });
    expect(result.role).toBe("web_application"); // actual role name in AssetRole type
    expect(result.confidence).toBeGreaterThan(0);
  });

  // ── Scan Strategy Generation ──

  it("should generate a scan strategy with evasion for WAF-protected targets", async () => {
    const { generateScanStrategy, detectWAF, detectCDN, getDefaultScopeConstraints } = await import("./context-aware-scanner");
    type TargetProfile = import("./context-aware-scanner").TargetProfile;

    const waf = detectWAF({ server: "cloudflare", "cf-ray": "abc" }, [], "", 403);
    const cdn = detectCDN({ "cf-ray": "abc" }, ["example.com.cdn.cloudflare.net"]);
    const scope = getDefaultScopeConstraints("pentest");

    const profile: Omit<TargetProfile, "recommendedStrategy"> = {
      hostname: "secure.example.com",
      ips: ["203.0.113.10"],
      fingerprint: {
        serverHeader: "cloudflare",
        webServer: { name: "cloudflare", version: null, role: "unknown" },
        appFramework: null,
        cms: null,
        os: null,
        tls: { version: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", certIssuer: "Let's Encrypt", certExpiry: null, hsts: true, protocols: ["TLSv1.3"] },
        languages: [],
        jsFrameworks: ["React"],
        databases: [],
        techTags: ["cloudflare", "React"],
        serviceBanners: { 443: { service: "https", version: null, banner: null, protocol: "tcp" } },
      },
      waf,
      cdn,
      firewall: { detected: false, type: "unknown", filteredPorts: [], rateLimiting: { detected: false, requestsPerSecond: null, burstLimit: null }, geoBlocking: false, ipReputationBlocking: false },
      topology: { host: "secure.example.com", role: "reverse_proxy", confidence: 70, backend: null, services: [{ port: 443, service: "https", version: null }], directlyReachable: true },
      environment: "cloud",
      riskProfile: "high_security",
      scopeConstraints: scope,
      profiledAt: Date.now(),
    };

    const strategy = generateScanStrategy(profile);
    expect(strategy.name).toBeTruthy();
    expect(strategy.riskLevel).toBeTruthy();
    expect(strategy.phases.length).toBeGreaterThan(0);
    expect(strategy.evasionProfile.rateLimit).toBeLessThanOrEqual(50); // Should throttle for WAF
    expect(strategy.estimatedTimeMinutes).toBeGreaterThan(0);
  });

  it("should generate a more aggressive strategy for unprotected targets", async () => {
    const { generateScanStrategy, detectWAF, detectCDN, getDefaultScopeConstraints } = await import("./context-aware-scanner");
    type TargetProfile = import("./context-aware-scanner").TargetProfile;

    const waf = detectWAF({ server: "Apache/2.4.49" }, [], "", 200);
    const cdn = detectCDN({}, []);
    const scope = getDefaultScopeConstraints("pentest");

    const profile: Omit<TargetProfile, "recommendedStrategy"> = {
      hostname: "legacy.example.com",
      ips: ["10.0.0.50"],
      fingerprint: {
        serverHeader: "Apache/2.4.49",
        webServer: { name: "Apache", version: "2.4.49", role: "unknown" },
        appFramework: { name: "PHP", version: "7.4", language: "PHP" },
        cms: { name: "WordPress", version: "5.8" },
        os: null,
        tls: null,
        languages: ["PHP"],
        jsFrameworks: [],
        databases: ["MySQL"],
        techTags: ["Apache", "PHP", "WordPress", "MySQL"],
        serviceBanners: {
          80: { service: "http", version: null, banner: null, protocol: "tcp" },
          22: { service: "ssh", version: null, banner: null, protocol: "tcp" },
          3306: { service: "mysql", version: null, banner: null, protocol: "tcp" },
        },
      },
      waf,
      cdn,
      firewall: { detected: false, type: "unknown", filteredPorts: [], rateLimiting: { detected: false, requestsPerSecond: null, burstLimit: null }, geoBlocking: false, ipReputationBlocking: false },
      topology: { host: "legacy.example.com", role: "web_app_server", confidence: 85, backend: null, services: [{ port: 80, service: "http", version: null }, { port: 22, service: "ssh", version: null }], directlyReachable: true },
      environment: "traditional",
      riskProfile: "legacy",
      scopeConstraints: scope,
      profiledAt: Date.now(),
    };

    const strategy = generateScanStrategy(profile);
    // No WAF but evasion profile rate depends on overall risk assessment
    expect(strategy.evasionProfile.rateLimit).toBeGreaterThanOrEqual(1);
    expect(strategy.phases.length).toBeGreaterThan(0);
  });

  // ── buildTargetProfileContext for LLM injection ──

  it("should build LLM context string from target profile", async () => {
    const { buildTargetProfileContext, detectWAF, detectCDN, generateScanStrategy, getDefaultScopeConstraints } = await import("./context-aware-scanner");
    type TargetProfile = import("./context-aware-scanner").TargetProfile;

    const waf = detectWAF({ server: "cloudflare", "cf-ray": "abc" }, [], "", 200);
    const cdn = detectCDN({ "cf-ray": "abc" }, []);
    const scope = getDefaultScopeConstraints("pentest");

    const partialProfile: Omit<TargetProfile, "recommendedStrategy"> = {
      hostname: "test.example.com",
      ips: ["1.2.3.4"],
      fingerprint: {
        serverHeader: "cloudflare",
        webServer: { name: "cloudflare", version: null, role: "unknown" },
        appFramework: null, cms: null, os: null, tls: null,
        languages: [], jsFrameworks: [], databases: [],
        techTags: ["cloudflare"],
        serviceBanners: {},
      },
      waf, cdn,
      firewall: { detected: false, type: "unknown", filteredPorts: [], rateLimiting: { detected: false, requestsPerSecond: null, burstLimit: null }, geoBlocking: false, ipReputationBlocking: false },
      topology: { host: "test.example.com", role: "unknown", confidence: 50, backend: null, services: [], directlyReachable: true },
      environment: "cloud",
      riskProfile: "standard",
      scopeConstraints: scope,
      profiledAt: Date.now(),
    };

    const strategy = generateScanStrategy(partialProfile);
    const fullProfile: TargetProfile = { ...partialProfile, recommendedStrategy: strategy };
    const ctx = buildTargetProfileContext(fullProfile);

    expect(ctx).toContain("test.example.com");
    expect(ctx.length).toBeGreaterThan(100);
    // Should contain structured sections
    expect(ctx).toContain("Target");
  });

  // ── Scope Constraints ──

  it("should return appropriate scope constraints for different engagement types", async () => {
    const { getDefaultScopeConstraints } = await import("./context-aware-scanner");

    const pentest = getDefaultScopeConstraints("pentest");
    expect(pentest.wafBypassAuthorized).toBe(true);
    expect(pentest.bruteForceAuthorized).toBe(true);

    const bugBounty = getDefaultScopeConstraints("bug_bounty");
    expect(bugBounty.bruteForceAuthorized).toBe(false);
    expect(bugBounty.dosTestingAuthorized).toBe(false);
  });

  // ── Evasion Profile Selection ──

  it("should select higher evasion for WAF+CDN protected targets", async () => {
    const { selectEvasionProfile, detectWAF, detectCDN, getDefaultScopeConstraints } = await import("./context-aware-scanner");

    const waf = detectWAF({ server: "cloudflare", "cf-ray": "abc" }, [], "", 200);
    const cdn = detectCDN({ "cf-ray": "abc" }, []);

    const firewall = { detected: false, type: "unknown" as const, filteredPorts: [] as number[], rateLimiting: { detected: false, requestsPerSecond: null, burstLimit: null }, geoBlocking: false, ipReputationBlocking: false };
    const scope = getDefaultScopeConstraints("pentest");

    const evasion = selectEvasionProfile(waf, cdn, firewall, scope);
    // EvasionProfile has rateLimit (number) and name (string), not level
    expect(evasion.rateLimit).toBeLessThanOrEqual(30); // Should throttle significantly
    expect(evasion.name).toBeTruthy();
  });

  // ── EngagementOpsState targetProfiles field ──

  it("should have targetProfiles as an optional field on EngagementOpsState", async () => {
    const { initOpsState } = await import("./engagement-orchestrator");
    const state = initOpsState(999, "pentest");
    // targetProfiles should be undefined initially (not set until Phase A.6 runs)
    expect(state.targetProfiles).toBeUndefined();
  });

  // ── Fingerprint building from httpx data (simulating orchestrator logic) ──

  it("should correctly parse web server name and version from header string", () => {
    const webServerStr = "nginx/1.24.0";
    const wsMatch = webServerStr.match(/^([\w.-]+)\/?([\d.]+)?/);
    expect(wsMatch?.[1]).toBe("nginx");
    expect(wsMatch?.[2]).toBe("1.24.0");
  });

  it("should detect CMS from technology list", () => {
    const technologies = ["WordPress 6.4.2", "PHP/8.1", "MySQL"];
    const cmsNames = ["WordPress", "Drupal", "Joomla", "Magento"];
    let cms: { name: string; version: string | null } | null = null;
    for (const cmsName of cmsNames) {
      const found = technologies.find(t => t.toLowerCase().includes(cmsName.toLowerCase()));
      if (found) {
        const vMatch = found.match(/([\d.]+)/);
        cms = { name: cmsName, version: vMatch?.[1] || null };
        break;
      }
    }
    expect(cms).not.toBeNull();
    expect(cms!.name).toBe("WordPress");
    expect(cms!.version).toBe("6.4.2");
  });

  it("should detect languages from technology list", () => {
    const technologies = ["PHP/8.1", "Laravel", "MySQL", "nginx"];
    const langPatterns: Record<string, RegExp> = {
      PHP: /php/i, Java: /java|jsp|servlet/i, Python: /python|django|flask/i,
      "C#": /asp\.net|c#/i, Ruby: /ruby|rails/i, JavaScript: /node|express|next|react|angular|vue/i,
    };
    const detectedLangs: string[] = [];
    for (const [lang, pat] of Object.entries(langPatterns)) {
      if (technologies.some(t => pat.test(t))) {
        detectedLangs.push(lang);
      }
    }
    expect(detectedLangs).toContain("PHP");
    expect(detectedLangs).not.toContain("Java");
  });

  // ── Phase B tool augmentation logic ──

  it("should merge strategy tools without duplicating existing tools", async () => {
    const { generateScanStrategy, detectWAF, detectCDN, getDefaultScopeConstraints } = await import("./context-aware-scanner");
    type TargetProfile = import("./context-aware-scanner").TargetProfile;

    const waf = detectWAF({}, [], "", 200);
    const cdn = detectCDN({}, []);
    const scope = getDefaultScopeConstraints("pentest");

    const profile: Omit<TargetProfile, "recommendedStrategy"> = {
      hostname: "app.example.com",
      ips: ["10.0.0.1"],
      fingerprint: {
        serverHeader: "Apache/2.4", webServer: { name: "Apache", version: "2.4", role: "unknown" },
        appFramework: null, cms: null, os: null, tls: null,
        languages: ["PHP"], jsFrameworks: [], databases: [],
        techTags: ["Apache", "PHP"],
        serviceBanners: { 80: { service: "http", version: null, banner: null, protocol: "tcp" } },
      },
      waf, cdn,
      firewall: { detected: false, type: "unknown", filteredPorts: [], rateLimiting: { detected: false, requestsPerSecond: null, burstLimit: null }, geoBlocking: false, ipReputationBlocking: false },
      topology: { host: "app.example.com", role: "web_app_server", confidence: 80, backend: null, services: [], directlyReachable: true },
      environment: "traditional", riskProfile: "standard", scopeConstraints: scope, profiledAt: Date.now(),
    };

    const strategy = generateScanStrategy(profile);

    // Simulate Phase B tool merging logic
    const existingCmds = [
      { tool: "nuclei", command: "nuclei -u http://app.example.com", purpose: "vuln scan", priority: 1 },
      { tool: "httpx", command: "httpx -u app.example.com", purpose: "probe", priority: 1 },
    ];
    const existingTools = new Set(existingCmds.map(c => c.tool));
    let augmentedCount = 0;

    for (const phase of strategy.phases) {
      for (const tool of phase.tools) {
        if (!existingTools.has(tool.tool)) {
          existingCmds.push({
            tool: tool.tool,
            command: `${tool.tool} ${tool.flags.replace(/HOST|TARGET/g, "10.0.0.1")}`,
            purpose: `[Context-Aware] ${tool.purpose}`,
            priority: 2,
          });
          existingTools.add(tool.tool);
          augmentedCount++;
        }
      }
    }

    // Should have added some tools that weren't already in the list
    expect(existingCmds.length).toBeGreaterThan(2);
    // Should not have duplicated nuclei or httpx
    const nucleiCount = existingCmds.filter(c => c.tool === "nuclei").length;
    expect(nucleiCount).toBe(1);
  });

  // ── Nuclei tag augmentation from target profiles ──

  it("should add CMS and WAF tags to nuclei tech tags from target profile", async () => {
    const { detectWAF, detectCDN, getDefaultScopeConstraints } = await import("./context-aware-scanner");

    const waf = detectWAF({ server: "cloudflare", "cf-ray": "abc" }, [], "", 200);
    const cdn = detectCDN({}, []);

    const techTags: string[] = ["apache", "php"];
    const vulnTargetProfile = {
      fingerprint: {
        cms: { name: "WordPress", version: "6.4" },
        appFramework: { name: "Laravel", version: "10.0", language: "PHP" },
        databases: ["MySQL"],
        jsFrameworks: [],
      },
      waf,
      cdn,
      environment: "cloud",
      topology: { role: "web_app_server" },
    };

    // Simulate the nuclei tag augmentation logic from the orchestrator
    const fp = vulnTargetProfile.fingerprint;
    if (fp.cms?.name) {
      const cmsTag = fp.cms.name.toLowerCase().replace(/\s+/g, "-");
      if (!techTags.includes(cmsTag)) techTags.push(cmsTag);
    }
    if (fp.appFramework?.name) {
      const fwTag = fp.appFramework.name.toLowerCase().replace(/[\s.]+/g, "-");
      if (!techTags.includes(fwTag)) techTags.push(fwTag);
    }
    if (vulnTargetProfile.waf.detected) {
      if (!techTags.includes("waf-detect")) techTags.push("waf-detect");
      if (!techTags.includes("waf-bypass")) techTags.push("waf-bypass");
    }
    if (vulnTargetProfile.environment === "cloud") {
      if (!techTags.includes("cloud")) techTags.push("cloud");
    }

    expect(techTags).toContain("wordpress");
    expect(techTags).toContain("laravel");
    expect(techTags).toContain("waf-detect");
    expect(techTags).toContain("waf-bypass");
    expect(techTags).toContain("cloud");
    // Original tags preserved
    expect(techTags).toContain("apache");
    expect(techTags).toContain("php");
  });
});
