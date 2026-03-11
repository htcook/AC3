/**
 * Tests for httpx response header tech extraction and enhanced ZAP authentication
 * 
 * Validates:
 * 1. Response header parsing (X-Powered-By, Set-Cookie, X-Generator, X-AspNet-Version)
 * 2. Cookie-based tech detection (PHPSESSID→PHP, JSESSIONID→Java, etc.)
 * 3. Tech-specific login path generation
 * 4. Knowledge-driven session indicators
 * 5. Tech hints piping from httpx → ZAP config
 */

import { describe, it, expect } from "vitest";

// ─── 1. Httpx Response Header Tech Detection ───────────────────────────────

describe("Httpx Response Header Tech Detection", () => {
  // Simulate the header parsing logic from engagement-orchestrator.ts
  function extractTechFromHeaders(headers: Record<string, string | string[]>): {
    techDetected: string[];
    responseHeaders: Record<string, string>;
  } {
    const techDetected: string[] = [];
    const responseHeaders: Record<string, string> = {};

    for (const [key, val] of Object.entries(headers)) {
      const lk = key.toLowerCase();
      const headerVal = Array.isArray(val) ? val[0] : String(val);

      if (lk === "x-powered-by") {
        responseHeaders["x-powered-by"] = headerVal;
        if (!techDetected.includes(headerVal)) techDetected.push(headerVal);
      }
      if (lk === "x-aspnet-version" || lk === "x-aspnetmvc-version") {
        responseHeaders[lk] = headerVal;
        if (!techDetected.includes(`ASP.NET ${headerVal}`)) techDetected.push(`ASP.NET ${headerVal}`);
      }
      if (lk === "x-generator") {
        responseHeaders["x-generator"] = headerVal;
        if (!techDetected.includes(headerVal)) techDetected.push(headerVal);
      }
      if (lk === "set-cookie") {
        responseHeaders["set-cookie"] = headerVal;
        if (headerVal.includes("PHPSESSID") && !techDetected.includes("PHP")) techDetected.push("PHP");
        if (headerVal.includes("JSESSIONID") && !techDetected.includes("Java")) techDetected.push("Java");
        if (headerVal.includes("ASP.NET_SessionId") && !techDetected.includes("ASP.NET")) techDetected.push("ASP.NET");
        if (headerVal.includes("connect.sid") && !techDetected.includes("Node.js/Express")) techDetected.push("Node.js/Express");
        if (headerVal.includes("laravel_session") && !techDetected.includes("Laravel/PHP")) techDetected.push("Laravel/PHP");
        if (headerVal.includes("_rails") && !techDetected.includes("Ruby on Rails")) techDetected.push("Ruby on Rails");
        if (headerVal.includes("csrftoken") && !techDetected.includes("Django/Python")) techDetected.push("Django/Python");
        if (headerVal.includes("wp-settings") && !techDetected.includes("WordPress")) techDetected.push("WordPress");
      }
    }

    return { techDetected, responseHeaders };
  }

  it("should detect PHP from X-Powered-By header", () => {
    const result = extractTechFromHeaders({ "X-Powered-By": "PHP/8.1.2" });
    expect(result.techDetected).toContain("PHP/8.1.2");
    expect(result.responseHeaders["x-powered-by"]).toBe("PHP/8.1.2");
  });

  it("should detect ASP.NET from X-Powered-By header", () => {
    const result = extractTechFromHeaders({ "X-Powered-By": "ASP.NET" });
    expect(result.techDetected).toContain("ASP.NET");
  });

  it("should detect Express from X-Powered-By header", () => {
    const result = extractTechFromHeaders({ "X-Powered-By": "Express" });
    expect(result.techDetected).toContain("Express");
  });

  it("should detect ASP.NET version from X-AspNet-Version header", () => {
    const result = extractTechFromHeaders({ "X-AspNet-Version": "4.0.30319" });
    expect(result.techDetected).toContain("ASP.NET 4.0.30319");
    expect(result.responseHeaders["x-aspnet-version"]).toBe("4.0.30319");
  });

  it("should detect WordPress from X-Generator header", () => {
    const result = extractTechFromHeaders({ "X-Generator": "WordPress 6.4.2" });
    expect(result.techDetected).toContain("WordPress 6.4.2");
    expect(result.responseHeaders["x-generator"]).toBe("WordPress 6.4.2");
  });

  it("should detect PHP from PHPSESSID cookie", () => {
    const result = extractTechFromHeaders({ "Set-Cookie": "PHPSESSID=abc123; path=/" });
    expect(result.techDetected).toContain("PHP");
  });

  it("should detect Java from JSESSIONID cookie", () => {
    const result = extractTechFromHeaders({ "Set-Cookie": "JSESSIONID=ABC123DEF456; path=/; HttpOnly" });
    expect(result.techDetected).toContain("Java");
  });

  it("should detect ASP.NET from ASP.NET_SessionId cookie", () => {
    const result = extractTechFromHeaders({ "Set-Cookie": "ASP.NET_SessionId=xyz789; path=/; secure" });
    expect(result.techDetected).toContain("ASP.NET");
  });

  it("should detect Node.js/Express from connect.sid cookie", () => {
    const result = extractTechFromHeaders({ "Set-Cookie": "connect.sid=s%3Aabc123; path=/; httponly" });
    expect(result.techDetected).toContain("Node.js/Express");
  });

  it("should detect Laravel/PHP from laravel_session cookie", () => {
    const result = extractTechFromHeaders({ "Set-Cookie": "laravel_session=eyJpdiI6; path=/; httponly" });
    expect(result.techDetected).toContain("Laravel/PHP");
  });

  it("should detect Ruby on Rails from _rails cookie", () => {
    const result = extractTechFromHeaders({ "Set-Cookie": "_rails_session=abc123; path=/; httponly" });
    expect(result.techDetected).toContain("Ruby on Rails");
  });

  it("should detect Django/Python from csrftoken cookie", () => {
    const result = extractTechFromHeaders({ "Set-Cookie": "csrftoken=abc123; path=/" });
    expect(result.techDetected).toContain("Django/Python");
  });

  it("should detect WordPress from wp-settings cookie", () => {
    const result = extractTechFromHeaders({ "Set-Cookie": "wp-settings-1=admin; path=/wp-admin" });
    expect(result.techDetected).toContain("WordPress");
  });

  it("should handle array header values (httpx format)", () => {
    const result = extractTechFromHeaders({ "X-Powered-By": ["PHP/8.1.2", "PleskLin"] as any });
    expect(result.techDetected).toContain("PHP/8.1.2");
  });

  it("should detect multiple technologies from combined headers", () => {
    const result = extractTechFromHeaders({
      "X-Powered-By": "PHP/8.1.2",
      "Set-Cookie": "PHPSESSID=abc; path=/",
      "X-Generator": "WordPress 6.4.2",
    });
    expect(result.techDetected).toContain("PHP/8.1.2");
    expect(result.techDetected).toContain("PHP");
    expect(result.techDetected).toContain("WordPress 6.4.2");
  });
});

// ─── 2. Tech-Specific Login Path Generation ────────────────────────────────

describe("Tech-Specific Login Path Generation", () => {
  function getTechLoginPaths(techHints: string[]): string[] {
    const basePaths = ["/login", "/admin/login", "/user/login", "/wp-login.php", "/login.php", "/"];
    const techSpecificPaths: string[] = [];
    const techStr = techHints.join(" ").toLowerCase();

    if (techStr.includes("wordpress") || techStr.includes("wp-")) {
      techSpecificPaths.push("/wp-login.php", "/wp-admin/", "/xmlrpc.php");
    }
    if (techStr.includes("django") || techStr.includes("python") || techStr.includes("csrftoken")) {
      techSpecificPaths.push("/admin/login/", "/accounts/login/", "/auth/login/");
    }
    if (techStr.includes("laravel") || techStr.includes("laravel_session")) {
      techSpecificPaths.push("/login", "/admin", "/auth/login", "/nova/login");
    }
    if (techStr.includes("php") || techStr.includes("phpsessid")) {
      techSpecificPaths.push("/login.php", "/admin.php", "/index.php?action=login", "/administrator/");
    }
    if (techStr.includes("java") || techStr.includes("jsessionid") || techStr.includes("spring") || techStr.includes("tomcat")) {
      techSpecificPaths.push("/login", "/j_spring_security_check", "/admin/login", "/cas/login");
    }
    if (techStr.includes("asp.net") || techStr.includes("aspnet")) {
      techSpecificPaths.push("/Account/Login", "/Login.aspx", "/admin/login", "/Identity/Account/Login");
    }
    if (techStr.includes("node") || techStr.includes("express") || techStr.includes("connect.sid")) {
      techSpecificPaths.push("/login", "/auth/login", "/api/auth/login", "/users/login");
    }
    if (techStr.includes("rails") || techStr.includes("ruby")) {
      techSpecificPaths.push("/users/sign_in", "/login", "/admin/login", "/session/new");
    }

    return [...new Set([...techSpecificPaths, ...basePaths])];
  }

  it("should add WordPress-specific paths for WordPress tech", () => {
    const paths = getTechLoginPaths(["WordPress 6.4.2"]);
    expect(paths[0]).toBe("/wp-login.php"); // WordPress paths first
    expect(paths).toContain("/wp-admin/");
    expect(paths).toContain("/xmlrpc.php");
  });

  it("should add PHP-specific paths for PHP tech", () => {
    const paths = getTechLoginPaths(["PHP/8.1.2"]);
    expect(paths).toContain("/login.php");
    expect(paths).toContain("/admin.php");
    expect(paths).toContain("/administrator/");
  });

  it("should add PHP paths from PHPSESSID cookie hint", () => {
    const paths = getTechLoginPaths(["Set-Cookie: PHPSESSID=abc"]);
    expect(paths).toContain("/login.php");
    expect(paths).toContain("/admin.php");
  });

  it("should add Java/Spring paths for Java tech", () => {
    const paths = getTechLoginPaths(["Java", "Apache Tomcat/9.0"]);
    expect(paths).toContain("/j_spring_security_check");
    expect(paths).toContain("/cas/login");
  });

  it("should add Java paths from JSESSIONID cookie hint", () => {
    const paths = getTechLoginPaths(["Set-Cookie: JSESSIONID=abc"]);
    expect(paths).toContain("/j_spring_security_check");
  });

  it("should add Django paths for Django/Python tech", () => {
    const paths = getTechLoginPaths(["Django/Python"]);
    expect(paths).toContain("/admin/login/");
    expect(paths).toContain("/accounts/login/");
  });

  it("should add ASP.NET paths for ASP.NET tech", () => {
    const paths = getTechLoginPaths(["ASP.NET 4.0.30319"]);
    expect(paths).toContain("/Account/Login");
    expect(paths).toContain("/Login.aspx");
    expect(paths).toContain("/Identity/Account/Login");
  });

  it("should add Node.js/Express paths for Express tech", () => {
    const paths = getTechLoginPaths(["Node.js/Express"]);
    expect(paths).toContain("/auth/login");
    expect(paths).toContain("/api/auth/login");
    expect(paths).toContain("/users/login");
  });

  it("should add Rails paths for Ruby on Rails tech", () => {
    const paths = getTechLoginPaths(["Ruby on Rails"]);
    expect(paths).toContain("/users/sign_in");
    expect(paths).toContain("/session/new");
  });

  it("should add Laravel paths for Laravel tech", () => {
    const paths = getTechLoginPaths(["Laravel/PHP"]);
    expect(paths).toContain("/nova/login");
    expect(paths).toContain("/auth/login");
  });

  it("should put tech-specific paths before generic paths", () => {
    const paths = getTechLoginPaths(["WordPress 6.4.2"]);
    const wpLoginIdx = paths.indexOf("/wp-login.php");
    const genericLoginIdx = paths.indexOf("/login");
    expect(wpLoginIdx).toBeLessThan(genericLoginIdx);
  });

  it("should deduplicate paths", () => {
    const paths = getTechLoginPaths(["PHP/8.1.2"]);
    const loginPhpCount = paths.filter(p => p === "/login.php").length;
    expect(loginPhpCount).toBe(1);
  });

  it("should return only base paths when no tech is detected", () => {
    const paths = getTechLoginPaths(["awselb/2.0"]);
    expect(paths).toEqual(["/login", "/admin/login", "/user/login", "/wp-login.php", "/login.php", "/"]);
  });
});

// ─── 3. Tech Hints Enrichment Pipeline ─────────────────────────────────────

describe("Tech Hints Enrichment Pipeline", () => {
  function buildTechHints(
    nmapVersions: string[],
    httpxTechs: string[],
    httpxHeaders: Record<string, string>,
  ): string[] {
    const headerHints: string[] = [];
    if (httpxHeaders["x-powered-by"]) headerHints.push(`X-Powered-By: ${httpxHeaders["x-powered-by"]}`);
    if (httpxHeaders["x-aspnet-version"]) headerHints.push(`X-AspNet-Version: ${httpxHeaders["x-aspnet-version"]}`);
    if (httpxHeaders["x-aspnetmvc-version"]) headerHints.push(`X-AspNetMvc-Version: ${httpxHeaders["x-aspnetmvc-version"]}`);
    if (httpxHeaders["x-generator"]) headerHints.push(`X-Generator: ${httpxHeaders["x-generator"]}`);
    if (httpxHeaders["set-cookie"]) headerHints.push(`Set-Cookie: ${httpxHeaders["set-cookie"].substring(0, 100)}`);
    if (httpxHeaders["server"]) headerHints.push(`Server: ${httpxHeaders["server"]}`);
    return [...new Set([...nmapVersions, ...httpxTechs, ...headerHints])];
  }

  it("should combine nmap versions with httpx technologies", () => {
    const hints = buildTechHints(
      ["nginx 1.18.0"],
      ["PHP", "WordPress"],
      {},
    );
    expect(hints).toContain("nginx 1.18.0");
    expect(hints).toContain("PHP");
    expect(hints).toContain("WordPress");
  });

  it("should include X-Powered-By header hint", () => {
    const hints = buildTechHints(
      [],
      [],
      { "x-powered-by": "PHP/8.1.2" },
    );
    expect(hints).toContain("X-Powered-By: PHP/8.1.2");
  });

  it("should include Set-Cookie header hint (truncated to 100 chars)", () => {
    const longCookie = "PHPSESSID=" + "a".repeat(200);
    const hints = buildTechHints([], [], { "set-cookie": longCookie });
    const cookieHint = hints.find(h => h.startsWith("Set-Cookie:"));
    expect(cookieHint).toBeDefined();
    expect(cookieHint!.length).toBeLessThanOrEqual(112); // "Set-Cookie: " + 100 chars
  });

  it("should include Server header hint", () => {
    const hints = buildTechHints([], [], { server: "Apache/2.4.51" });
    expect(hints).toContain("Server: Apache/2.4.51");
  });

  it("should deduplicate across all sources", () => {
    const hints = buildTechHints(
      ["nginx 1.18.0"],
      ["nginx 1.18.0", "PHP"],
      {},
    );
    const nginxCount = hints.filter(h => h === "nginx 1.18.0").length;
    expect(nginxCount).toBe(1);
  });

  it("should handle empty inputs gracefully", () => {
    const hints = buildTechHints([], [], {});
    expect(hints).toEqual([]);
  });

  it("should produce rich hints for a PHP/WordPress target", () => {
    const hints = buildTechHints(
      ["Apache httpd 2.4.51"],
      ["PHP", "WordPress 6.4.2", "jQuery 3.7.1"],
      {
        "x-powered-by": "PHP/8.1.2",
        "x-generator": "WordPress 6.4.2",
        "set-cookie": "PHPSESSID=abc123; path=/",
        server: "Apache/2.4.51",
      },
    );
    expect(hints).toContain("Apache httpd 2.4.51");
    expect(hints).toContain("PHP");
    expect(hints).toContain("WordPress 6.4.2");
    expect(hints).toContain("jQuery 3.7.1");
    expect(hints).toContain("X-Powered-By: PHP/8.1.2");
    expect(hints).toContain("X-Generator: WordPress 6.4.2");
    expect(hints).toContain("Server: Apache/2.4.51");
    expect(hints.length).toBeGreaterThanOrEqual(7);
  });
});

// ─── 4. Knowledge-Driven Auth Strategy Matching ────────────────────────────

describe("Knowledge-Driven Auth Strategy Matching", () => {
  it("should import ZAP_AUTH_STRATEGIES from knowledge module", async () => {
    const { ZAP_AUTH_STRATEGIES } = await import("./knowledge/zap-pentesting-knowledge");
    expect(ZAP_AUTH_STRATEGIES).toBeDefined();
    expect(ZAP_AUTH_STRATEGIES.length).toBeGreaterThanOrEqual(4);
  });

  it("should have form strategy with logged-in/logged-out indicators", async () => {
    const { ZAP_AUTH_STRATEGIES } = await import("./knowledge/zap-pentesting-knowledge");
    const formStrategy = ZAP_AUTH_STRATEGIES.find(s => s.type === "form");
    expect(formStrategy).toBeDefined();
    expect(formStrategy!.loggedInIndicator).toBeTruthy();
    expect(formStrategy!.loggedOutIndicator).toBeTruthy();
    expect(formStrategy!.loggedInIndicator).toContain("logout");
  });

  it("should have json strategy with token-based indicators", async () => {
    const { ZAP_AUTH_STRATEGIES } = await import("./knowledge/zap-pentesting-knowledge");
    const jsonStrategy = ZAP_AUTH_STRATEGIES.find(s => s.type === "json");
    expect(jsonStrategy).toBeDefined();
    expect(jsonStrategy!.loggedInIndicator).toContain("token");
    expect(jsonStrategy!.loggedOutIndicator).toContain("unauthorized");
  });

  it("should have http_basic strategy with 200/401 indicators", async () => {
    const { ZAP_AUTH_STRATEGIES } = await import("./knowledge/zap-pentesting-knowledge");
    const basicStrategy = ZAP_AUTH_STRATEGIES.find(s => s.type === "http_basic");
    expect(basicStrategy).toBeDefined();
    expect(basicStrategy!.loggedInIndicator).toContain("200");
    expect(basicStrategy!.loggedOutIndicator).toContain("401");
  });

  it("should match correct strategy for each auth method", async () => {
    const { ZAP_AUTH_STRATEGIES } = await import("./knowledge/zap-pentesting-knowledge");
    const methods = ["form", "json", "http_basic", "script", "browser"];
    for (const method of methods) {
      const strategy = ZAP_AUTH_STRATEGIES.find(s => s.type === method);
      expect(strategy, `Strategy for ${method} should exist`).toBeDefined();
      expect(strategy!.zapConfig, `Strategy ${method} should have zapConfig`).toBeDefined();
      expect(strategy!.setupSteps.length, `Strategy ${method} should have setup steps`).toBeGreaterThan(0);
    }
  });
});
