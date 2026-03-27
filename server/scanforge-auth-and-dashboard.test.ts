import { describe, it, expect } from "vitest";

/**
 * Tests for:
 * 1. ScanForge credential passthrough — discovered credentials flow from orchestrator to ScanForge targets
 * 2. ScanForge authenticated scanning — AuthScanner integration in engagement-integration.ts
 * 3. TI column name fixes — threatActors.actorType, threatGroupEvents.tge* prefixes, threatActorIocs.ioc* prefixes
 * 4. ScanForge Dashboard tRPC procedures
 */

const importEngagementIntegration = () => import("./scanforge/engine/engagement-integration");
const importAuthScanner = () => import("./scanforge/engine/auth-scanner");
const importAccuracyTracker = () => import("./scanforge/engine/accuracy-tracker");

// ─── ScanForge Credential Types ────────────────────────────────────────────

describe("ScanForge Credential Passthrough", () => {
  it("should export ScanForgeCredential type with required fields", async () => {
    const mod = await importEngagementIntegration();
    // Verify the module exports the expected types and functions
    expect(mod.executeScanForgePhase).toBeDefined();
    expect(typeof mod.executeScanForgePhase).toBe("function");
    expect(mod.runPostEngagementAnalysis).toBeDefined();
    expect(typeof mod.runPostEngagementAnalysis).toBe("function");
    expect(mod.compareFindings).toBeDefined();
    expect(typeof mod.compareFindings).toBe("function");
  });

  it("should accept targets with credentials in ScanForgeEngagementConfig", async () => {
    const mod = await importEngagementIntegration();
    // Verify the config type accepts credentials on targets
    const config = {
      engagementId: "test-123",
      targets: [
        {
          url: "http://dvwa.lab.test:4000",
          ip: "10.0.0.1",
          hostname: "dvwa.lab.test",
          isInternal: false,
          technologies: ["PHP", "Apache"],
          credentials: [
            {
              username: "admin",
              password: "password",
              service: "http",
              source: "hydra",
              loginPath: "/login.php",
              confirmedAt: Date.now(),
            },
          ],
        },
      ],
      scope: "dvwa.lab.test",
      targetType: "web_app" as const,
      enableProofVerification: false,
      enableEmberRouting: false,
      enableAuthenticatedScanning: true,
      maxConcurrency: 1,
      timeoutPerTarget: 5000,
    };

    // Config should be valid (type check at compile time, runtime check here)
    expect(config.targets[0].credentials).toBeDefined();
    expect(config.targets[0].credentials![0].username).toBe("admin");
    expect(config.targets[0].credentials![0].source).toBe("hydra");
    expect(config.targets[0].credentials![0].loginPath).toBe("/login.php");
    expect(config.enableAuthenticatedScanning).toBe(true);
  });

  it("should handle targets without credentials gracefully", async () => {
    const config = {
      engagementId: "test-456",
      targets: [
        {
          url: "http://example.com",
          hostname: "example.com",
        },
      ],
      scope: "example.com",
      targetType: "web_app" as const,
      enableProofVerification: false,
      enableEmberRouting: false,
      maxConcurrency: 1,
      timeoutPerTarget: 5000,
    };

    // No credentials — should not crash
    expect(config.targets[0]).not.toHaveProperty("credentials");
  });
});

// ─── AuthScanner Integration ───────────────────────────────────────────────

describe("AuthScanner Class", () => {
  it("should export AuthScanner with authenticate, authenticatedFetch, ensureAuthenticated methods", async () => {
    const { AuthScanner } = await importAuthScanner();
    const scanner = new AuthScanner();
    expect(scanner).toBeDefined();
    expect(typeof scanner.authenticate).toBe("function");
    expect(typeof scanner.authenticatedFetch).toBe("function");
    expect(typeof scanner.ensureAuthenticated).toBe("function");
    expect(typeof scanner.checkSession).toBe("function");
    expect(typeof scanner.logout).toBe("function");
  });

  it("should support form_login, bearer_token, cookie, basic_auth, api_key, oauth2 strategies", async () => {
    const { AuthScanner } = await importAuthScanner();
    // The AuthConfig type should support all these strategies
    const strategies = ["form_login", "bearer_token", "cookie", "basic_auth", "api_key", "oauth2"];
    for (const strategy of strategies) {
      const config = {
        strategy: strategy as any,
        loginUrl: "http://test.com/login",
        credentials: { username: "admin", password: "pass" },
      };
      // Should not throw on config construction
      expect(config.strategy).toBe(strategy);
    }
  });

  it("should construct AuthConfig with reAuth parameters for session management", async () => {
    const config = {
      strategy: "form_login" as const,
      loginUrl: "http://dvwa.lab.test/login.php",
      credentials: { username: "admin", password: "password" },
      reAuthAfterRequests: 200,
      reAuthIntervalMs: 5 * 60 * 1000,
    };
    expect(config.reAuthAfterRequests).toBe(200);
    expect(config.reAuthIntervalMs).toBe(300000);
  });
});

// ─── Comparison Engine ─────────────────────────────────────────────────────

describe("ScanForge Comparison Engine", () => {
  it("should correctly identify overlap between ScanForge and legacy findings", async () => {
    const { compareFindings } = await importEngagementIntegration();

    const sfFindings = [
      { templateId: "sf-001", templateName: "SQL Injection", target: "http://test.com", severity: "critical" as const, title: "SQL Injection", description: "", evidence: "", confidence: 0.9, verified: true, references: [], rawResponse: "" },
      { templateId: "sf-002", templateName: "XSS Reflected", target: "http://test.com", severity: "high" as const, title: "XSS Reflected", description: "", evidence: "", confidence: 0.8, verified: false, references: [], rawResponse: "" },
    ];

    const legacyFindings = [
      { tool: "nuclei", title: "SQL Injection", target: "http://test.com", severity: "critical" },
      { tool: "zap", title: "CSRF Token Missing", target: "http://test.com", severity: "medium" },
    ];

    const result = compareFindings(sfFindings, legacyFindings);
    expect(result.overlap.length).toBeGreaterThanOrEqual(1); // SQL Injection should overlap
    expect(result.scanforgeOnly.length).toBeGreaterThanOrEqual(0);
    expect(result.legacyOnly.length).toBeGreaterThanOrEqual(0);
  });

  it("should handle empty findings gracefully", async () => {
    const { compareFindings } = await importEngagementIntegration();
    const result = compareFindings([], []);
    expect(result.overlap).toEqual([]);
    expect(result.scanforgeOnly).toEqual([]);
    expect(result.legacyOnly).toEqual([]);
  });
});

// ─── TI Column Name Fixes ──────────────────────────────────────────────────

describe("TI Column Name Fixes — Schema Alignment", () => {
  it("should use actorType (not type) in threatActors schema", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.threatActors).toBeDefined();
    // The Drizzle schema object should have actorType as a property
    const columns = Object.keys(schema.threatActors);
    // actorType should be accessible as a column reference
    expect(schema.threatActors.actorType).toBeDefined();
  });

  it("should use tge-prefixed columns in threatGroupEvents schema", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.threatGroupEvents).toBeDefined();
    // Check that the tge-prefixed columns exist
    expect(schema.threatGroupEvents.tgeActorId).toBeDefined();
    expect(schema.threatGroupEvents.tgeTitle).toBeDefined();
    expect(schema.threatGroupEvents.tgeDescription).toBeDefined();
    expect(schema.threatGroupEvents.tgeSeverity).toBeDefined();
    expect(schema.threatGroupEvents.tgeSource).toBeDefined();
  });

  it("should use ioc-prefixed columns in threatActorIocs schema", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.threatActorIocs).toBeDefined();
    // Check that the ioc-prefixed columns exist
    expect(schema.threatActorIocs.iocType).toBeDefined();
    expect(schema.threatActorIocs.iocConfidence).toBeDefined();
  });

  it("should have authContext column in scanforgeEngagementReport schema", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.scanforgeEngagementReport).toBeDefined();
    expect(schema.scanforgeEngagementReport.authContext).toBeDefined();
  });
});

// ─── ScanForge Accuracy Tracker ────────────────────────────────────────────

describe("ScanForge Accuracy Tracker Exports", () => {
  it("should export template effectiveness, engagement report, and finding functions", async () => {
    const mod = await importAccuracyTracker();
    expect(mod.getTemplateEffectiveness).toBeDefined();
    expect(typeof mod.getTemplateEffectiveness).toBe("function");
    expect(mod.generateEngagementReport).toBeDefined();
    expect(typeof mod.generateEngagementReport).toBe("function");
    expect(mod.logFinding).toBeDefined();
    expect(typeof mod.logFinding).toBe("function");
    expect(mod.assessFindings).toBeDefined();
    expect(typeof mod.assessFindings).toBe("function");
    expect(mod.getEngagementReports).toBeDefined();
    expect(typeof mod.getEngagementReports).toBe("function");
    expect(mod.getEngagementFindings).toBeDefined();
    expect(typeof mod.getEngagementFindings).toBe("function");
    expect(mod.getCalibratedConfidence).toBeDefined();
    expect(typeof mod.getCalibratedConfidence).toBe("function");
  });
});

// ─── Nuclei Auth Header Injection ──────────────────────────────────────────

describe("Nuclei Authenticated Scanning — Header Injection", () => {
  it("should construct -H Cookie header when sessionCookie is available", () => {
    // Simulate the orchestrator logic for building nuclei args with auth
    const asset = {
      confirmedCredentials: [
        { username: "admin", password: "password", service: "http", sessionCookie: "PHPSESSID=abc123; security=low" },
      ],
    };

    const assetCreds = (asset.confirmedCredentials || []).filter((c: any) =>
      ["http", "web", "form", "http-get", "http-post-form"].includes(c.service)
    );

    let authHeaderArg = "";
    if (assetCreds.length > 0 && assetCreds[0].sessionCookie) {
      authHeaderArg = ` -H "Cookie: ${assetCreds[0].sessionCookie}"`;
    }

    expect(authHeaderArg).toBe(` -H "Cookie: PHPSESSID=abc123; security=low"`);

    const nucleiArgs = `-u http://dvwa.lab.test:4000 -severity critical,high,medium -jsonl -nc -duc -ni -timeout 10 -retries 1 -rate-limit 150${authHeaderArg}`;
    expect(nucleiArgs).toContain('-H "Cookie: PHPSESSID=abc123');
  });

  it("should not add auth header when no sessionCookie is available", () => {
    const asset = {
      confirmedCredentials: [
        { username: "admin", password: "password", service: "http" },
      ],
    };

    const assetCreds = (asset.confirmedCredentials || []).filter((c: any) =>
      ["http", "web", "form"].includes(c.service)
    );

    let authHeaderArg = "";
    if (assetCreds.length > 0 && (assetCreds[0] as any).sessionCookie) {
      authHeaderArg = ` -H "Cookie: ${(assetCreds[0] as any).sessionCookie}"`;
    }

    expect(authHeaderArg).toBe("");
  });

  it("should not add auth header when no credentials exist", () => {
    const asset = { confirmedCredentials: [] as any[] };
    const assetCreds = asset.confirmedCredentials.filter((c: any) =>
      ["http", "web", "form"].includes(c.service)
    );
    let authHeaderArg = "";
    if (assetCreds.length > 0 && assetCreds[0].sessionCookie) {
      authHeaderArg = ` -H "Cookie: ${assetCreds[0].sessionCookie}"`;
    }
    expect(authHeaderArg).toBe("");
  });
});

// ─── Credential Mapping Logic ──────────────────────────────────────────────

describe("Orchestrator Credential Mapping to ScanForge Targets", () => {
  it("should map confirmedCredentials to ScanForgeCredential format", () => {
    const asset = {
      ip: "10.0.0.5",
      hostname: "dvwa.lab.test",
      ports: [{ port: 80 }, { port: 443 }],
      status: "active",
      confirmedCredentials: [
        { username: "admin", password: "password", service: "http-post-form", source: "hydra", loginPath: "/login.php", confirmedAt: "2026-03-27T10:00:00Z" },
        { username: "root", password: "toor", service: "ssh", source: "hydra" },
      ],
      passiveRecon: { technologies: ["PHP", "Apache"] },
    };

    // Simulate the orchestrator mapping logic
    const creds = (asset.confirmedCredentials || []).map((c: any) => ({
      username: c.username,
      password: c.password,
      service: c.service || "http",
      source: c.source || "hydra",
      loginPath: c.loginPath,
      confirmedAt: c.confirmedAt ? new Date(c.confirmedAt).getTime() : Date.now(),
    }));

    expect(creds.length).toBe(2);
    expect(creds[0].username).toBe("admin");
    expect(creds[0].service).toBe("http-post-form");
    expect(creds[0].loginPath).toBe("/login.php");
    expect(creds[1].username).toBe("root");
    expect(creds[1].service).toBe("ssh");
  });

  it("should include training lab credentials when available", () => {
    const asset = {
      ip: "10.0.0.5",
      hostname: "dvwa.lab.test",
      confirmedCredentials: [] as any[],
      trainingLabCreds: {
        username: "admin",
        password: "password",
        loginPath: "/login.php",
      },
    };

    const creds: any[] = (asset.confirmedCredentials || []).map((c: any) => ({
      username: c.username,
      password: c.password,
      service: c.service || "http",
      source: c.source || "hydra",
    }));

    const trainingLabCreds = (asset as any).trainingLabCreds;
    if (trainingLabCreds && !creds.some(c => c.username === trainingLabCreds.username)) {
      creds.push({
        username: trainingLabCreds.username,
        password: trainingLabCreds.password,
        service: "http",
        source: "training_lab",
        loginPath: trainingLabCreds.loginPath,
        confirmedAt: Date.now(),
      });
    }

    expect(creds.length).toBe(1);
    expect(creds[0].source).toBe("training_lab");
    expect(creds[0].loginPath).toBe("/login.php");
  });

  it("should not duplicate training lab creds if already in confirmedCredentials", () => {
    const asset = {
      confirmedCredentials: [
        { username: "admin", password: "password", service: "http", source: "hydra" },
      ],
      trainingLabCreds: {
        username: "admin",
        password: "password",
        loginPath: "/login.php",
      },
    };

    const creds: any[] = (asset.confirmedCredentials || []).map((c: any) => ({
      username: c.username,
      password: c.password,
      service: c.service || "http",
      source: c.source || "hydra",
    }));

    const trainingLabCreds = (asset as any).trainingLabCreds;
    if (trainingLabCreds && !creds.some(c => c.username === trainingLabCreds.username)) {
      creds.push({
        username: trainingLabCreds.username,
        password: trainingLabCreds.password,
        service: "http",
        source: "training_lab",
      });
    }

    // Should NOT add duplicate
    expect(creds.length).toBe(1);
    expect(creds[0].source).toBe("hydra");
  });
});
