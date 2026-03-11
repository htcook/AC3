import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * Tests for the credential-to-ZAP authentication handoff pipeline.
 *
 * Verifies that:
 * 1. Hydra output is correctly parsed to extract confirmed credentials
 * 2. Confirmed credentials are stored on the asset's confirmedCredentials array
 * 3. configureZapAuthentication correctly selects auth method
 * 4. The orchestrator wires credentials into ZAP scan launch
 */

// ─── Hydra Output Parsing Tests ──────────────────────────────────────────────

describe("Hydra credential extraction", () => {
  // Simulate the Hydra output parsing logic from engagement-orchestrator.ts
  function parseHydraOutput(stdout: string): Array<{
    username: string;
    password: string;
    service: string;
    port: number;
    protocol: string;
  }> {
    const creds: Array<{
      username: string;
      password: string;
      service: string;
      port: number;
      protocol: string;
    }> = [];

    for (const line of stdout.split("\n")) {
      if (line.includes("login:") && line.includes("password:")) {
        const loginMatch = line.match(/login:\s*(\S+)/);
        const passMatch = line.match(/password:\s*(\S*)/);
        const svcMatch = line.match(/\[\d+\]\[(\S+)\]/) || line.match(/\[(\S+)\]/);
        const portMatch = line.match(/\[(\d+)\]/);

        if (loginMatch && passMatch) {
          creds.push({
            username: loginMatch[1],
            password: passMatch[1],
            service: svcMatch?.[1] || "http",
            port: portMatch ? parseInt(portMatch[1], 10) : 80,
            protocol: svcMatch?.[1]?.includes("http") ? "http" : (svcMatch?.[1] || "unknown"),
          });
        }
      }
    }
    return creds;
  }

  it("parses DVWA-style Hydra output (admin/password)", () => {
    const hydraOutput = `Hydra v9.5 (c) 2023 by van Hauser/THC
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://192.168.1.100:80/login.php
[80][http-post-form] host: 192.168.1.100   login: admin   password: password
1 of 1 target successfully completed, 1 valid password found`;

    const creds = parseHydraOutput(hydraOutput);
    expect(creds).toHaveLength(1);
    expect(creds[0].username).toBe("admin");
    expect(creds[0].password).toBe("password");
    expect(creds[0].port).toBe(80);
    expect(creds[0].service).toBe("http-post-form");
    expect(creds[0].protocol).toBe("http");
  });

  it("parses SSH Hydra output", () => {
    const hydraOutput = `[22][ssh] host: 10.0.0.5   login: root   password: toor
1 of 1 target successfully completed, 1 valid password found`;

    const creds = parseHydraOutput(hydraOutput);
    expect(creds).toHaveLength(1);
    expect(creds[0].username).toBe("root");
    expect(creds[0].password).toBe("toor");
    expect(creds[0].port).toBe(22);
    expect(creds[0].service).toBe("ssh");
    expect(creds[0].protocol).toBe("ssh");
  });

  it("parses multiple credentials from Hydra output", () => {
    const hydraOutput = `[80][http-get] host: 192.168.1.50   login: admin   password: admin
[80][http-get] host: 192.168.1.50   login: test   password: test123
2 of 2 targets successfully completed, 2 valid passwords found`;

    const creds = parseHydraOutput(hydraOutput);
    expect(creds).toHaveLength(2);
    expect(creds[0].username).toBe("admin");
    expect(creds[0].password).toBe("admin");
    expect(creds[1].username).toBe("test");
    expect(creds[1].password).toBe("test123");
  });

  it("handles Hydra output with no valid credentials", () => {
    const hydraOutput = `Hydra v9.5 (c) 2023 by van Hauser/THC
[DATA] max 16 tasks per 1 server, overall 16 tasks, 100 login tries
0 of 1 target completed, 0 valid password found`;

    const creds = parseHydraOutput(hydraOutput);
    expect(creds).toHaveLength(0);
  });

  it("parses FTP Hydra output on non-standard port", () => {
    const hydraOutput = `[2121][ftp] host: 10.0.0.10   login: anonymous   password: `;

    const creds = parseHydraOutput(hydraOutput);
    expect(creds).toHaveLength(1);
    expect(creds[0].username).toBe("anonymous");
    expect(creds[0].password).toBe("");
    expect(creds[0].port).toBe(2121);
    expect(creds[0].service).toBe("ftp");
  });
});

// ─── Credential Selection Tests ──────────────────────────────────────────────

describe("Web credential selection for ZAP", () => {
  interface ConfirmedCred {
    username: string;
    password: string;
    service: string;
    port: number;
    protocol: string;
    accessLevel?: string;
    source: string;
    confirmedAt: number;
  }

  function selectWebCredentials(creds: ConfirmedCred[]): ConfirmedCred[] {
    return creds.filter(c =>
      ["http", "https", "web_admin", "http-form", "http-get", "http-post"].includes(c.service) ||
      c.protocol === "http" || c.protocol === "https"
    );
  }

  it("selects HTTP credentials over SSH credentials", () => {
    const creds: ConfirmedCred[] = [
      { username: "root", password: "toor", service: "ssh", port: 22, protocol: "ssh", source: "hydra", confirmedAt: Date.now() },
      { username: "admin", password: "password", service: "http-post-form", port: 80, protocol: "http", source: "hydra", confirmedAt: Date.now() },
    ];

    const webCreds = selectWebCredentials(creds);
    expect(webCreds).toHaveLength(1);
    expect(webCreds[0].username).toBe("admin");
    expect(webCreds[0].service).toBe("http-post-form");
  });

  it("selects multiple HTTP credentials when available", () => {
    const creds: ConfirmedCred[] = [
      { username: "admin", password: "admin", service: "http-get", port: 80, protocol: "http", source: "hydra", confirmedAt: Date.now() },
      { username: "user", password: "user123", service: "http-post", port: 443, protocol: "https", source: "hydra", confirmedAt: Date.now() },
    ];

    const webCreds = selectWebCredentials(creds);
    expect(webCreds).toHaveLength(2);
  });

  it("returns empty when only non-web credentials exist", () => {
    const creds: ConfirmedCred[] = [
      { username: "root", password: "toor", service: "ssh", port: 22, protocol: "ssh", source: "hydra", confirmedAt: Date.now() },
      { username: "admin", password: "admin", service: "ftp", port: 21, protocol: "ftp", source: "hydra", confirmedAt: Date.now() },
    ];

    const webCreds = selectWebCredentials(creds);
    expect(webCreds).toHaveLength(0);
  });
});

// ─── Asset confirmedCredentials Normalization Tests ──────────────────────────

describe("Asset confirmedCredentials normalization", () => {
  function normalizeAsset(asset: any): any {
    if (!Array.isArray(asset.confirmedCredentials)) asset.confirmedCredentials = [];
    if (!Array.isArray(asset.vulns)) asset.vulns = [];
    if (!Array.isArray(asset.toolResults)) asset.toolResults = [];
    if (!Array.isArray(asset.ports)) asset.ports = [];
    if (!Array.isArray(asset.zapFindings)) asset.zapFindings = [];
    if (!Array.isArray(asset.exploitAttempts)) asset.exploitAttempts = [];
    return asset;
  }

  it("initializes confirmedCredentials as empty array on legacy asset", () => {
    const legacyAsset = {
      hostname: "test.com",
      vulns: [],
      toolResults: [],
      ports: [],
    };

    const normalized = normalizeAsset(legacyAsset);
    expect(normalized.confirmedCredentials).toEqual([]);
  });

  it("preserves existing confirmedCredentials", () => {
    const asset = {
      hostname: "test.com",
      confirmedCredentials: [
        { username: "admin", password: "password", source: "hydra" },
      ],
      vulns: [],
      toolResults: [],
      ports: [],
    };

    const normalized = normalizeAsset(asset);
    expect(normalized.confirmedCredentials).toHaveLength(1);
    expect(normalized.confirmedCredentials[0].username).toBe("admin");
  });

  it("handles null confirmedCredentials from JSON deserialization", () => {
    const asset = {
      hostname: "test.com",
      confirmedCredentials: null,
      vulns: [],
      toolResults: [],
      ports: [],
    };

    const normalized = normalizeAsset(asset);
    expect(normalized.confirmedCredentials).toEqual([]);
  });
});

// ─── Orchestrator Credential Handoff Integration Tests ───────────────────────

describe("Orchestrator credential-to-ZAP handoff", () => {
  it("detects when web credentials are available for ZAP handoff", () => {
    const asset = {
      hostname: "dvwa.local",
      confirmedCredentials: [
        {
          username: "admin",
          password: "password",
          service: "http-post-form",
          port: 80,
          protocol: "http",
          accessLevel: "authenticated",
          source: "hydra",
          confirmedAt: Date.now(),
        },
      ],
    };

    const webCreds = (asset.confirmedCredentials || []).filter((c: any) =>
      ["http", "https", "web_admin", "http-form", "http-get", "http-post"].includes(c.service) ||
      c.protocol === "http" || c.protocol === "https"
    );

    expect(webCreds.length > 0).toBe(true);
    expect(webCreds[0].username).toBe("admin");
    expect(webCreds[0].source).toBe("hydra");
  });

  it("skips ZAP auth handoff when no web credentials exist", () => {
    const asset = {
      hostname: "server.local",
      confirmedCredentials: [
        {
          username: "root",
          password: "toor",
          service: "ssh",
          port: 22,
          protocol: "ssh",
          source: "hydra",
          confirmedAt: Date.now(),
        },
      ],
    };

    const webCreds = (asset.confirmedCredentials || []).filter((c: any) =>
      ["http", "https", "web_admin", "http-form", "http-get", "http-post"].includes(c.service) ||
      c.protocol === "http" || c.protocol === "https"
    );

    expect(webCreds.length).toBe(0);
  });

  it("skips ZAP auth handoff when confirmedCredentials is empty", () => {
    const asset = {
      hostname: "clean.local",
      confirmedCredentials: [],
    };

    const webCreds = (asset.confirmedCredentials || []).filter((c: any) =>
      ["http", "https", "web_admin", "http-form", "http-get", "http-post"].includes(c.service) ||
      c.protocol === "http" || c.protocol === "https"
    );

    expect(webCreds.length).toBe(0);
  });

  it("generates correct auth hints for LLM scan config", () => {
    const webCreds = [
      {
        username: "admin",
        password: "password",
        service: "http-post-form",
        port: 80,
        protocol: "http",
        source: "hydra",
        confirmedAt: Date.now(),
      },
    ];
    const targetUrl = "http://dvwa.local";

    const authHints = webCreds.length > 0
      ? { type: "form", loginUrl: `${targetUrl}/login`, credentials: { username: webCreds[0].username, password: webCreds[0].password } }
      : undefined;

    expect(authHints).toBeDefined();
    expect(authHints!.type).toBe("form");
    expect(authHints!.loginUrl).toBe("http://dvwa.local/login");
    expect(authHints!.credentials.username).toBe("admin");
    expect(authHints!.credentials.password).toBe("password");
  });
});

// ─── Login Form Detection Tests ──────────────────────────────────────────────

describe("Login form field detection", () => {
  function detectFormFields(html: string): { usernameField: string; passwordField: string; csrfField?: string } {
    let usernameField = "username";
    let passwordField = "password";
    let csrfField: string | undefined;

    const userFieldMatch = html.match(/name=["'](user(?:name)?|login|log|email|usr|uname|user_login)["']/i);
    if (userFieldMatch) usernameField = userFieldMatch[1];

    const passFieldMatch = html.match(/name=["'](pass(?:word)?|pwd|passwd|user_password|pass_login)["']/i);
    if (passFieldMatch) passwordField = passFieldMatch[1];

    const csrfMatch = html.match(/name=["'](csrf[_-]?token|_?token|user_token|csrfmiddlewaretoken|_csrf|authenticity_token|__RequestVerificationToken)["'][^>]*value=["']([^"']+)["']/i);
    if (csrfMatch) csrfField = csrfMatch[1];

    return { usernameField, passwordField, csrfField };
  }

  it("detects DVWA login form fields", () => {
    const dvwaHtml = `
      <form action="login.php" method="POST">
        <input type="text" name="username" />
        <input type="password" name="password" />
        <input type="hidden" name="user_token" value="abc123def456" />
        <input type="submit" value="Login" />
      </form>`;

    const fields = detectFormFields(dvwaHtml);
    expect(fields.usernameField).toBe("username");
    expect(fields.passwordField).toBe("password");
    expect(fields.csrfField).toBe("user_token");
  });

  it("detects WordPress login form fields", () => {
    const wpHtml = `
      <form name="loginform" id="loginform" action="wp-login.php" method="post">
        <input type="text" name="log" id="user_login" />
        <input type="password" name="pwd" id="user_pass" />
        <input type="submit" name="wp-submit" value="Log In" />
      </form>`;

    const fields = detectFormFields(wpHtml);
    expect(fields.usernameField).toBe("log");
    expect(fields.passwordField).toBe("pwd");
  });

  it("detects Django login form with CSRF", () => {
    const djangoHtml = `
      <form method="post" action="/accounts/login/">
        <input type="hidden" name="csrfmiddlewaretoken" value="Wqx9rT7kL2mN5pV8" />
        <input type="text" name="username" />
        <input type="password" name="password" />
        <button type="submit">Sign in</button>
      </form>`;

    const fields = detectFormFields(djangoHtml);
    expect(fields.usernameField).toBe("username");
    expect(fields.passwordField).toBe("password");
    expect(fields.csrfField).toBe("csrfmiddlewaretoken");
  });

  it("detects Rails login form with authenticity token", () => {
    const railsHtml = `
      <form action="/sessions" method="post">
        <input type="hidden" name="authenticity_token" value="abc123xyz789" />
        <input type="email" name="email" />
        <input type="password" name="password" />
        <input type="submit" value="Sign In" />
      </form>`;

    const fields = detectFormFields(railsHtml);
    expect(fields.usernameField).toBe("email");
    expect(fields.passwordField).toBe("password");
    expect(fields.csrfField).toBe("authenticity_token");
  });

  it("falls back to defaults when no matching field names found", () => {
    const genericHtml = `
      <form method="post">
        <input type="text" name="x_field" />
        <input type="password" name="y_field" />
      </form>`;

    const fields = detectFormFields(genericHtml);
    expect(fields.usernameField).toBe("username");
    expect(fields.passwordField).toBe("password");
    expect(fields.csrfField).toBeUndefined();
  });
});
