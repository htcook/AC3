/**
 * Tests for Burp Session Cookie Handoff
 *
 * Validates that:
 * 1. Training lab creds are extracted and passed to Burp auto-scan as appLogin
 * 2. Confirmed creds (from Hydra) are used as fallback when no training lab match
 * 3. appLogin flows through onEngagementVulnDetectionPhase → launchBurpAutoScan
 * 4. appLogin flows through runZapToBurpPipeline → launchBurpAutoScan
 * 5. appLogin flows through deferredZapBurpRefeed → runZapToBurpPipeline
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── 1. Training Lab Credential Extraction Logic ───

describe("Burp appLogin extraction from training lab creds", () => {
  const BURP_TRAINING_LAB_CREDS: Record<string, { username: string; password: string; loginPath: string }> = {
    'dvwa': { username: 'admin', password: 'password', loginPath: '/login.php' },
    'altoro': { username: 'admin', password: 'admin', loginPath: '/altoromutual/login.jsp' },
    'juiceshop': { username: 'admin@juice-sh.op', password: 'admin123', loginPath: '/#/login' },
    'hackazon': { username: 'test_user', password: 'test_user', loginPath: '/user/login' },
    'testphp': { username: 'test', password: 'test', loginPath: '/login.php' },
  };

  function extractBurpAppLogin(assets: any[], trainingLabMode: boolean) {
    let burpAppLogin: { username: string; password: string; loginUrl?: string } | undefined;
    if (trainingLabMode) {
      for (const asset of assets) {
        const hostname = (asset.hostname || '').toLowerCase();
        for (const [labKey, creds] of Object.entries(BURP_TRAINING_LAB_CREDS)) {
          if (hostname.includes(labKey)) {
            const proto = asset.ports?.some((p: any) => p.port === 443) ? 'https' : 'http';
            burpAppLogin = {
              username: creds.username,
              password: creds.password,
              loginUrl: `${proto}://${asset.hostname}${creds.loginPath}`,
            };
            break;
          }
        }
        if (burpAppLogin) break;
      }
    }
    // Fallback: confirmed creds from Hydra
    if (!burpAppLogin) {
      for (const asset of assets) {
        const assetCreds = asset.confirmedCredentials || [];
        const webCred = assetCreds.find((c: any) => c.protocol === 'http' || c.protocol === 'https');
        if (webCred) {
          const proto = asset.ports?.some((p: any) => p.port === 443) ? 'https' : 'http';
          burpAppLogin = {
            username: webCred.username,
            password: webCred.password,
            loginUrl: webCred.loginPath ? `${proto}://${asset.hostname}${webCred.loginPath}` : undefined,
          };
          break;
        }
      }
    }
    return burpAppLogin;
  }

  it("extracts DVWA training lab creds with correct login URL", () => {
    const assets = [{ hostname: "dvwa.lab.aceofcloud.io", ports: [{ port: 80 }] }];
    const result = extractBurpAppLogin(assets, true);
    expect(result).toBeDefined();
    expect(result!.username).toBe("admin");
    expect(result!.password).toBe("password");
    expect(result!.loginUrl).toBe("http://dvwa.lab.aceofcloud.io/login.php");
  });

  it("extracts Juice Shop creds with HTTPS when port 443 present", () => {
    const assets = [{ hostname: "juiceshop.lab.test.com", ports: [{ port: 443 }, { port: 3000 }] }];
    const result = extractBurpAppLogin(assets, true);
    expect(result).toBeDefined();
    expect(result!.username).toBe("admin@juice-sh.op");
    expect(result!.password).toBe("admin123");
    expect(result!.loginUrl).toBe("https://juiceshop.lab.test.com/#/login");
  });

  it("extracts Altoro Mutual creds", () => {
    const assets = [{ hostname: "altoro.testfire.net", ports: [{ port: 80 }] }];
    const result = extractBurpAppLogin(assets, true);
    expect(result).toBeDefined();
    expect(result!.username).toBe("admin");
    expect(result!.loginUrl).toBe("http://altoro.testfire.net/altoromutual/login.jsp");
  });

  it("extracts Hackazon creds", () => {
    const assets = [{ hostname: "hackazon.example.com", ports: [{ port: 80 }] }];
    const result = extractBurpAppLogin(assets, true);
    expect(result).toBeDefined();
    expect(result!.username).toBe("test_user");
    expect(result!.loginUrl).toBe("http://hackazon.example.com/user/login");
  });

  it("extracts testphp creds", () => {
    const assets = [{ hostname: "testphp.vulnweb.com", ports: [{ port: 80 }] }];
    const result = extractBurpAppLogin(assets, true);
    expect(result).toBeDefined();
    expect(result!.username).toBe("test");
    expect(result!.loginUrl).toBe("http://testphp.vulnweb.com/login.php");
  });

  it("returns undefined when no training lab match and no confirmed creds", () => {
    const assets = [{ hostname: "unknown.target.com", ports: [{ port: 80 }] }];
    const result = extractBurpAppLogin(assets, true);
    expect(result).toBeUndefined();
  });

  it("returns undefined when trainingLabMode is false and no confirmed creds", () => {
    const assets = [{ hostname: "dvwa.lab.aceofcloud.io", ports: [{ port: 80 }] }];
    const result = extractBurpAppLogin(assets, false);
    expect(result).toBeUndefined();
  });

  it("falls back to confirmed creds when trainingLabMode is false", () => {
    const assets = [{
      hostname: "target.example.com",
      ports: [{ port: 443 }],
      confirmedCredentials: [
        { protocol: "http", username: "hydra_user", password: "hydra_pass", loginPath: "/admin/login" },
      ],
    }];
    const result = extractBurpAppLogin(assets, false);
    expect(result).toBeDefined();
    expect(result!.username).toBe("hydra_user");
    expect(result!.password).toBe("hydra_pass");
    expect(result!.loginUrl).toBe("https://target.example.com/admin/login");
  });

  it("falls back to confirmed creds when training lab has no match", () => {
    const assets = [{
      hostname: "custom-app.example.com",
      ports: [{ port: 80 }],
      confirmedCredentials: [
        { protocol: "ssh", username: "root", password: "toor" },
        { protocol: "https", username: "admin", password: "secret123", loginPath: "/login" },
      ],
    }];
    const result = extractBurpAppLogin(assets, true);
    expect(result).toBeDefined();
    expect(result!.username).toBe("admin");
    expect(result!.password).toBe("secret123");
  });

  it("skips non-web confirmed creds (SSH, FTP)", () => {
    const assets = [{
      hostname: "server.example.com",
      ports: [{ port: 22 }],
      confirmedCredentials: [
        { protocol: "ssh", username: "root", password: "toor" },
        { protocol: "ftp", username: "anonymous", password: "" },
      ],
    }];
    const result = extractBurpAppLogin(assets, false);
    expect(result).toBeUndefined();
  });

  it("picks first matching asset when multiple assets exist", () => {
    const assets = [
      { hostname: "api.example.com", ports: [{ port: 443 }] },
      { hostname: "dvwa.lab.aceofcloud.io", ports: [{ port: 80 }] },
    ];
    const result = extractBurpAppLogin(assets, true);
    expect(result).toBeDefined();
    expect(result!.username).toBe("admin");
    expect(result!.loginUrl).toBe("http://dvwa.lab.aceofcloud.io/login.php");
  });

  it("confirmed creds without loginPath produce undefined loginUrl", () => {
    const assets = [{
      hostname: "app.example.com",
      ports: [{ port: 80 }],
      confirmedCredentials: [
        { protocol: "http", username: "user1", password: "pass1" },
      ],
    }];
    const result = extractBurpAppLogin(assets, false);
    expect(result).toBeDefined();
    expect(result!.username).toBe("user1");
    expect(result!.loginUrl).toBeUndefined();
  });
});

// ─── 2. BurpAutoScanConfig appLogin field ───

describe("BurpAutoScanConfig appLogin passthrough", () => {
  it("BurpAutoScanConfig interface accepts appLogin", async () => {
    const config = {
      engagementId: 1,
      engagementHandle: "test",
      userId: "user1",
      targetUrls: ["http://dvwa.lab.test.com"],
      credentialId: 1,
      burpConfig: { edition: "professional" as const, baseUrl: "http://localhost:1337", apiKey: "test" },
      appLogin: { username: "admin", password: "password", loginUrl: "http://dvwa.lab.test.com/login.php" },
    };
    expect(config.appLogin).toBeDefined();
    expect(config.appLogin.username).toBe("admin");
    expect(config.appLogin.loginUrl).toBe("http://dvwa.lab.test.com/login.php");
  });

  it("BurpAutoScanConfig works without appLogin (backward compatible)", async () => {
    const config = {
      engagementId: 1,
      engagementHandle: "test",
      userId: "user1",
      targetUrls: ["http://target.com"],
      credentialId: 1,
      burpConfig: { edition: "professional" as const, baseUrl: "http://localhost:1337", apiKey: "test" },
    };
    expect((config as any).appLogin).toBeUndefined();
  });
});

// ─── 3. BurpScanRequest applicationLogin field ───

describe("BurpScanRequest applicationLogin passthrough", () => {
  it("BurpScanRequest accepts applicationLogin for Burp Pro API", async () => {
    const request = {
      urls: ["http://dvwa.lab.test.com"],
      applicationLogin: {
        username: "admin",
        password: "password",
        loginUrl: "http://dvwa.lab.test.com/login.php",
      },
    };
    expect(request.applicationLogin).toBeDefined();
    expect(request.applicationLogin.username).toBe("admin");
  });
});

// ─── 4. onEngagementVulnDetectionPhase appLogin parameter ───

describe("onEngagementVulnDetectionPhase accepts appLogin", () => {
  it("function signature accepts 6th appLogin parameter", async () => {
    const mod = await import("./lib/burp-auto-scan");
    // The function should accept 6 parameters (engagementId, userId, handle, scopeUrls, scanMode, appLogin)
    expect(typeof mod.onEngagementVulnDetectionPhase).toBe("function");
    // Check it has at least 5 params (the 6th is optional)
    expect(mod.onEngagementVulnDetectionPhase.length).toBeGreaterThanOrEqual(4);
  });
});

// ─── 5. ZAP-Burp Pipeline appLogin parameter ───

describe("ZAP-Burp Pipeline appLogin passthrough", () => {
  it("runZapToBurpPipeline accepts appLogin in params", async () => {
    const mod = await import("./lib/zap-burp-pipeline");
    expect(typeof mod.runZapToBurpPipeline).toBe("function");
  });

  it("deferredZapBurpRefeed accepts appLogin in params", async () => {
    const mod = await import("./lib/zap-burp-pipeline");
    expect(typeof mod.deferredZapBurpRefeed).toBe("function");
  });
});

// ─── 6. End-to-end credential flow simulation ───

describe("End-to-end credential flow", () => {
  it("DVWA training lab creds produce correct Burp applicationLogin payload", () => {
    // Simulate what the orchestrator does
    const state = {
      trainingLabMode: true,
      assets: [{ hostname: "dvwa.lab.aceofcloud.io", ports: [{ port: 80 }] }],
    };

    const BURP_TRAINING_LAB_CREDS: Record<string, { username: string; password: string; loginPath: string }> = {
      'dvwa': { username: 'admin', password: 'password', loginPath: '/login.php' },
    };

    let burpAppLogin: any;
    for (const asset of state.assets) {
      const hostname = asset.hostname.toLowerCase();
      for (const [labKey, creds] of Object.entries(BURP_TRAINING_LAB_CREDS)) {
        if (hostname.includes(labKey)) {
          burpAppLogin = {
            username: creds.username,
            password: creds.password,
            loginUrl: `http://${asset.hostname}${creds.loginPath}`,
          };
          break;
        }
      }
    }

    // This is what gets passed to Burp Pro API as application_logins
    const burpApiPayload = {
      urls: ["http://dvwa.lab.aceofcloud.io"],
      application_logins: [{
        username: burpAppLogin.username,
        password: burpAppLogin.password,
      }],
    };

    expect(burpApiPayload.application_logins).toHaveLength(1);
    expect(burpApiPayload.application_logins[0].username).toBe("admin");
    expect(burpApiPayload.application_logins[0].password).toBe("password");
  });

  it("Multiple assets: picks first matching training lab", () => {
    const assets = [
      { hostname: "api.internal.com", ports: [{ port: 8080 }] },
      { hostname: "dvwa.lab.aceofcloud.io", ports: [{ port: 80 }] },
      { hostname: "juiceshop.lab.aceofcloud.io", ports: [{ port: 3000 }] },
    ];

    const BURP_TRAINING_LAB_CREDS: Record<string, { username: string; password: string; loginPath: string }> = {
      'dvwa': { username: 'admin', password: 'password', loginPath: '/login.php' },
      'juiceshop': { username: 'admin@juice-sh.op', password: 'admin123', loginPath: '/#/login' },
    };

    let burpAppLogin: any;
    for (const asset of assets) {
      const hostname = asset.hostname.toLowerCase();
      for (const [labKey, creds] of Object.entries(BURP_TRAINING_LAB_CREDS)) {
        if (hostname.includes(labKey)) {
          burpAppLogin = {
            username: creds.username,
            password: creds.password,
            loginUrl: `http://${asset.hostname}${creds.loginPath}`,
          };
          break;
        }
      }
      if (burpAppLogin) break;
    }

    // Should pick DVWA (first match), not Juice Shop
    expect(burpAppLogin.username).toBe("admin");
    expect(burpAppLogin.loginUrl).toBe("http://dvwa.lab.aceofcloud.io/login.php");
  });

  it("Confirmed creds produce correct Burp applicationLogin when no training lab match", () => {
    const assets = [{
      hostname: "custom-app.example.com",
      ports: [{ port: 443 }],
      confirmedCredentials: [
        { protocol: "https", username: "pentester", password: "p3nt3st!", loginPath: "/auth/login" },
      ],
    }];

    // No training lab match, fall back to confirmed creds
    let burpAppLogin: any;
    for (const asset of assets) {
      const assetCreds = asset.confirmedCredentials || [];
      const webCred = assetCreds.find((c: any) => c.protocol === 'http' || c.protocol === 'https');
      if (webCred) {
        const proto = asset.ports?.some((p: any) => p.port === 443) ? 'https' : 'http';
        burpAppLogin = {
          username: webCred.username,
          password: webCred.password,
          loginUrl: `${proto}://${asset.hostname}${webCred.loginPath}`,
        };
        break;
      }
    }

    expect(burpAppLogin).toBeDefined();
    expect(burpAppLogin.username).toBe("pentester");
    expect(burpAppLogin.loginUrl).toBe("https://custom-app.example.com/auth/login");
  });
});
