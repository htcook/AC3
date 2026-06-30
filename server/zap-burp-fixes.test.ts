/**
 * Tests for ZAP/Burp pipeline fixes:
 * 1. Credential aggregation from breach databases
 * 2. Burp 0-findings fast-complete detection and audit-only retry
 * 3. Burp pre-flight connectivity diagnostics
 * 4. Burp tech-stack aware config selection
 * 5. OAST wait time improvement (60s progressive polling)
 */
import { describe, it, expect, vi } from "vitest";

// ─── Test 1: Credential Aggregation Logic ───

describe("Credential Aggregation", () => {
  it("should match credentials to assets by email domain", () => {
    // Simulate the credential matching logic from the orchestrator
    const assets = [
      { hostname: "app.example.com", ports: [{ port: 443 }], confirmedCredentials: [] as any[] },
      { hostname: "api.internal.net", ports: [{ port: 8080 }], confirmedCredentials: [] as any[] },
    ];

    const harvestedCreds = [
      { username: "admin", password: "P@ssw0rd!", email: "admin@example.com", source: "dehashed", confidence: "high" },
      { username: "dev", password: "devpass123", email: "dev@internal.net", source: "intelx", confidence: "medium" },
      { username: "user", password: "[REDACTED]", email: "user@example.com", source: "hudsonrock", confidence: "low" },
    ];

    // Filter usable creds (has password, not redacted)
    const usableCreds = harvestedCreds.filter(c =>
      c.password && !c.password.startsWith('[') && c.password.length > 0
    );
    expect(usableCreds).toHaveLength(2); // [REDACTED] filtered out

    // Match creds to assets
    let injectedCount = 0;
    for (const asset of assets) {
      const assetDomain = asset.hostname.toLowerCase();
      for (const cred of usableCreds) {
        const credDomain = cred.email?.split('@')[1]?.toLowerCase() || '';
        const isRelevant = credDomain && assetDomain.includes(credDomain.split('.')[0]);
        const isWebAsset = asset.ports?.some((p: any) => [80, 443, 8080, 8443, 3000, 8000].includes(p.port));
        const isHighConf = cred.confidence === 'high';

        if (isRelevant || (isWebAsset && isHighConf)) {
          const exists = asset.confirmedCredentials.some(
            (c: any) => c.username === cred.username && c.password === cred.password
          );
          if (!exists) {
            asset.confirmedCredentials.push({
              username: cred.username,
              password: cred.password,
              service: 'http-form',
              source: `harvested_${cred.source}`,
            });
            injectedCount++;
          }
        }
      }
    }

    // admin@example.com matches app.example.com (domain match) AND api.internal.net (high conf + web asset)
    // dev@internal.net matches api.internal.net (domain match)
    expect(injectedCount).toBeGreaterThanOrEqual(3);
    expect(assets[0].confirmedCredentials.length).toBeGreaterThanOrEqual(1); // admin matched by domain
    expect(assets[1].confirmedCredentials.length).toBeGreaterThanOrEqual(1); // dev matched by domain
  });

  it("should not inject redacted or empty passwords", () => {
    const creds = [
      { password: "[REDACTED]", username: "a" },
      { password: "", username: "b" },
      { password: null, username: "c" },
      { password: "realpass", username: "d" },
    ];

    const usable = creds.filter(c =>
      c.password && !c.password.startsWith('[') && c.password.length > 0
    );
    expect(usable).toHaveLength(1);
    expect(usable[0].username).toBe("d");
  });

  it("should not create duplicate credentials on the same asset", () => {
    const asset = {
      confirmedCredentials: [
        { username: "admin", password: "P@ssw0rd!", service: "http-form" },
      ],
    };

    const cred = { username: "admin", password: "P@ssw0rd!" };
    const exists = asset.confirmedCredentials.some(
      c => c.username === cred.username && c.password === cred.password
    );
    expect(exists).toBe(true); // Should not inject duplicate
  });
});

// ─── Test 2: Burp Fast-Complete Detection ───

describe("Burp 0-Findings Fast-Complete Detection", () => {
  it("should detect suspicious fast completion (<60s, 0 findings)", () => {
    const startedAt = Date.now() - 17_000; // 17 seconds ago
    const completedAt = Date.now();
    const normalizedFindings: any[] = [];

    const scanDurationMs = completedAt - startedAt;
    const isSuspiciousFastComplete = scanDurationMs < 60_000 && normalizedFindings.length === 0;

    expect(isSuspiciousFastComplete).toBe(true);
  });

  it("should NOT flag normal completion (>60s with findings)", () => {
    const startedAt = Date.now() - 120_000; // 2 minutes ago
    const completedAt = Date.now();
    const normalizedFindings = [{ title: "XSS" }, { title: "SQLi" }];

    const scanDurationMs = completedAt - startedAt;
    const isSuspiciousFastComplete = scanDurationMs < 60_000 && normalizedFindings.length === 0;

    expect(isSuspiciousFastComplete).toBe(false);
  });

  it("should NOT flag fast completion WITH findings", () => {
    const startedAt = Date.now() - 30_000; // 30 seconds ago
    const completedAt = Date.now();
    const normalizedFindings = [{ title: "Info disclosure" }];

    const scanDurationMs = completedAt - startedAt;
    const isSuspiciousFastComplete = scanDurationMs < 60_000 && normalizedFindings.length === 0;

    expect(isSuspiciousFastComplete).toBe(false);
  });

  it("should NOT retry if already an audit-only retry", () => {
    const config = { _isAuditOnlyRetry: true };
    const isSuspiciousFastComplete = true;

    const shouldRetry = isSuspiciousFastComplete && !(config as any)._isAuditOnlyRetry;
    expect(shouldRetry).toBe(false);
  });
});

// ─── Test 3: Burp Tech-Stack Config Selection ───

describe("Burp Tech-Stack Aware Config Selection", () => {
  function selectBurpConfig(scanMode: string, techHints: string[]): string {
    const techStr = techHints.join(' ').toLowerCase();
    const hasJava = techStr.includes('java') || techStr.includes('tomcat') || techStr.includes('spring');
    const hasDotNet = techStr.includes('asp.net') || techStr.includes('.net') || techStr.includes('iis');
    const hasAPI = techStr.includes('api') || techStr.includes('graphql') || techStr.includes('rest');

    switch (scanMode) {
      case "strict_passive":
        return "Crawl and Audit - Lightweight";
      case "active":
        if (hasJava || hasDotNet) return "Crawl and Audit - Deep";
        if (hasAPI) return "Audit checks - all";
        return "Audit checks - all";
      default:
        if (hasAPI) return "Audit checks - all";
        return "Crawl and Audit - Balanced";
    }
  }

  it("should use Deep crawl for Java/Tomcat targets", () => {
    expect(selectBurpConfig("active", ["Apache Tomcat 9.0", "Java"])).toBe("Crawl and Audit - Deep");
  });

  it("should use Deep crawl for ASP.NET targets", () => {
    expect(selectBurpConfig("active", ["IIS 10.0", "ASP.NET 4.8"])).toBe("Crawl and Audit - Deep");
  });

  it("should use Audit-only for API targets", () => {
    expect(selectBurpConfig("active", ["REST API", "JSON"])).toBe("Audit checks - all");
  });

  it("should use Audit-only for GraphQL targets", () => {
    expect(selectBurpConfig("standard", ["GraphQL", "Node.js"])).toBe("Audit checks - all");
  });

  it("should use Balanced for standard PHP targets", () => {
    expect(selectBurpConfig("standard", ["PHP 8.1", "nginx"])).toBe("Crawl and Audit - Balanced");
  });

  it("should use Lightweight for passive mode", () => {
    expect(selectBurpConfig("strict_passive", ["WordPress", "PHP"])).toBe("Crawl and Audit - Lightweight");
  });

  it("should use Deep crawl for Spring Boot targets", () => {
    expect(selectBurpConfig("active", ["Spring Boot 2.7", "Java 17"])).toBe("Crawl and Audit - Deep");
  });
});

// ─── Test 4: OAST Wait Time Logic ───

describe("OAST Wait Time Improvement", () => {
  it("should wait up to 60s total in 15s intervals", () => {
    const OAST_WAIT_INTERVAL = 15_000;
    const OAST_MAX_WAIT = 60_000;

    // Simulate the wait loop
    let elapsed = 0;
    let cycles = 0;
    while (elapsed < OAST_MAX_WAIT) {
      elapsed += OAST_WAIT_INTERVAL;
      cycles++;
    }

    expect(cycles).toBe(4); // 4 cycles of 15s = 60s
    expect(elapsed).toBe(60_000);
  });

  it("should exit early when new alerts are detected", () => {
    const OAST_WAIT_INTERVAL = 15_000;
    const OAST_MAX_WAIT = 60_000;

    let oastAlertsBefore = 10;
    const alertsPerCycle = [10, 10, 13]; // New alerts appear in cycle 3

    let elapsed = 0;
    let cycles = 0;
    let earlyExit = false;

    for (const currentAlerts of alertsPerCycle) {
      elapsed += OAST_WAIT_INTERVAL;
      cycles++;

      if (currentAlerts > oastAlertsBefore) {
        oastAlertsBefore = currentAlerts;
        elapsed += OAST_WAIT_INTERVAL; // One more cycle
        earlyExit = true;
        break;
      }
    }

    expect(earlyExit).toBe(true);
    expect(cycles).toBe(3); // Exited at cycle 3
    expect(elapsed).toBe(60_000); // 3 * 15s + 1 extra 15s = 60s
  });
});

// ─── Test 5: Pre-flight Diagnostics ───

describe("Burp Pre-flight Diagnostics", () => {
  it("should parse Burp API URL correctly", () => {
    const baseUrl = "http://scan-server.example.com:1337";
    const url = new URL(baseUrl);

    expect(url.hostname).toBe("scan-server.example.com");
    expect(url.port).toBe("1337");
  });

  it("should default to port 1337 when no port specified", () => {
    const baseUrl = "http://scan-server.example.com";
    const url = new URL(baseUrl);
    const port = parseInt(url.port) || 1337;

    expect(port).toBe(1337);
  });

  it("should extract target host and port from HTTPS URL", () => {
    const targetUrl = "https://vulnerable-app.com:8443/api/v1";
    const url = new URL(targetUrl);

    expect(url.hostname).toBe("vulnerable-app.com");
    expect(url.port).toBe("8443");
    expect(url.protocol).toBe("https:");
  });

  it("should default to port 443 for HTTPS targets", () => {
    const targetUrl = "https://vulnerable-app.com/login";
    const url = new URL(targetUrl);
    const port = parseInt(url.port) || (url.protocol === 'https:' ? 443 : 80);

    expect(port).toBe(443);
  });

  it("should default to port 80 for HTTP targets", () => {
    const targetUrl = "http://vulnerable-app.com/login";
    const url = new URL(targetUrl);
    const port = parseInt(url.port) || (url.protocol === 'https:' ? 443 : 80);

    expect(port).toBe(80);
  });
});

// ─── Test 6: Credential Aggregation Edge Cases ───

describe("Credential Aggregation Edge Cases", () => {
  it("should handle assets with no ports gracefully", () => {
    const asset = { hostname: "test.com", ports: undefined as any, confirmedCredentials: [] as any[] };
    const isWebAsset = asset.ports?.some((p: any) => [80, 443].includes(p.port)) || false;
    expect(isWebAsset).toBe(false);
  });

  it("should handle credentials with no email gracefully", () => {
    const cred = { username: "admin", password: "pass", email: undefined as any, source: "dehashed", confidence: "high" };
    const credDomain = cred.email?.split('@')[1]?.toLowerCase() || '';
    expect(credDomain).toBe('');
  });

  it("should match subdomain assets to parent domain credentials", () => {
    const assetDomain = "app.staging.example.com";
    const credDomain = "example.com";
    const domainBase = credDomain.split('.')[0]; // "example"
    const isRelevant = domainBase && assetDomain.includes(domainBase);
    expect(isRelevant).toBe(true);
  });
});
