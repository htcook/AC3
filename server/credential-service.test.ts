/**
 * Tests for credential-service and engagement result persistence.
 * 
 * Covers:
 * - getH1CredentialsForUser: env var fallback, user DB lookup
 * - getPlatformCredentials: platform routing
 * - saveEngagementResult / saveEngagementFindings: DB persistence
 * - engagement-results router: query procedures
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ─── Credential Service Tests ────────────────────────────────────────────────


// Skip in CI — requires production database connection
const __skipInCI = !process.env.DATABASE_URL || process.env.DATABASE_URL.includes("localhost");

describe.skipIf(__skipInCI)("credential-service", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env.HACKERONE_API_KEY = "test-api-key-12345";
    process.env.HACKERONE_API_USERNAME = "htc0";
    process.env.JWT_SECRET = "test-jwt-secret-for-encryption";
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    vi.restoreAllMocks();
  });

  it("should fall back to env vars when no userId is provided", async () => {
    const { getH1CredentialsForUser } = await import("./lib/credential-service");
    const creds = await getH1CredentialsForUser(null);
    expect(creds).not.toBeNull();
    expect(creds!.source).toBe("env_var");
    expect(creds!.username).toBe("htc0");
    expect(creds!.apiKey).toBe("test-api-key-12345");
  });

  it("should fall back to env vars when userId is provided but no DB credentials exist", async () => {
    const { getH1CredentialsForUser } = await import("./lib/credential-service");
    // User 999999 won't have credentials in DB
    const creds = await getH1CredentialsForUser(999999);
    expect(creds).not.toBeNull();
    expect(creds!.source).toBe("env_var");
    expect(creds!.username).toBe("htc0");
  });

  it("should return null when no env vars and no userId", async () => {
    delete process.env.HACKERONE_API_KEY;
    delete process.env.HACKERONE_API_USERNAME;
    // Need to re-import to pick up changed env
    vi.resetModules();
    const { getH1CredentialsForUser } = await import("./lib/credential-service");
    const creds = await getH1CredentialsForUser(null);
    expect(creds).toBeNull();
  });

  it("should route hackerone platform to getH1CredentialsForUser", async () => {
    const { getPlatformCredentials } = await import("./lib/credential-service");
    const creds = await getPlatformCredentials("hackerone", null);
    expect(creds).not.toBeNull();
    expect(creds!.source).toBe("env_var");
    expect(creds!.apiKey).toBe("test-api-key-12345");
  });

  it("should return null for unknown platforms without userId", async () => {
    const { getPlatformCredentials } = await import("./lib/credential-service");
    const creds = await getPlatformCredentials("bugcrowd", null);
    expect(creds).toBeNull();
  });
});

// ─── Bug Bounty Intelligence User Context Tests ─────────────────────────────

describe("bug-bounty-intelligence user context", () => {
  it("should export setActiveUser and getActiveUser", async () => {
    const { setActiveUser, getActiveUser } = await import("./lib/bug-bounty-intelligence");
    expect(typeof setActiveUser).toBe("function");
    expect(typeof getActiveUser).toBe("function");
  });

  it("should set and get active user ID", async () => {
    const { setActiveUser, getActiveUser } = await import("./lib/bug-bounty-intelligence");
    setActiveUser(42);
    expect(getActiveUser()).toBe(42);
    setActiveUser("123");
    expect(getActiveUser()).toBe("123");
    setActiveUser(null);
    expect(getActiveUser()).toBeNull();
  });
});

// ─── Bounty Intel Scheduler User Context Tests ──────────────────────────────

describe("bounty-intel-scheduler user context", () => {
  it("should export setSchedulerUser", async () => {
    const { setSchedulerUser } = await import("./lib/bounty-intel-scheduler");
    expect(typeof setSchedulerUser).toBe("function");
  });
});

// ─── Engagement Result DB Helpers Tests ─────────────────────────────────────

describe("engagement result DB helpers", () => {
  it("should export saveEngagementResult and saveEngagementFindings", async () => {
    const db = await import("./db");
    expect(typeof db.saveEngagementResult).toBe("function");
    expect(typeof db.saveEngagementFindings).toBe("function");
    expect(typeof db.getEngagementResult).toBe("function");
    expect(typeof db.getEngagementFindings).toBe("function");
  });

  it("should save and retrieve engagement results", async () => {
    const { saveEngagementResult, getEngagementResult } = await import("./db");
    
    // Use a unique engagement ID to avoid conflicts
    const testEngId = 9999990 + Math.floor(Math.random() * 1000);
    
    try {
      const resultId = await saveEngagementResult({
        engagementId: testEngId,
        operatorName: "test-operator",
        engagementType: "pentest",
        targetDomain: "test.example.com",
        status: "completed",
        startedAt: Date.now() - 60000,
        completedAt: Date.now(),
        durationMs: 60000,
        stats: {
          hostsScanned: 3,
          portsFound: 15,
          vulnsFound: 8,
          verifiedVulns: 5,
          unverifiedVulns: 3,
          exploitsAttempted: 4,
          exploitsSucceeded: 2,
          sessionsOpened: 1,
          zapScansRun: 2,
        },
        severityBreakdown: {
          critical: 1,
          high: 2,
          medium: 3,
          low: 1,
          info: 1,
        },
        owaspCoverage: {
          score: 75,
          totalTested: 18,
          totalPartial: 3,
          totalGaps: 4,
          criticalGaps: ["A01:2021", "A03:2021"],
        },
        summaryJson: { test: true },
      });

      expect(resultId).toBeGreaterThan(0);

      const result = await getEngagementResult(testEngId);
      expect(result).not.toBeNull();
      expect(result!.engagementId).toBe(testEngId);
      expect(result!.vulnsFound).toBe(8);
      expect(result!.criticalVulns).toBe(1);
      expect(result!.highVulns).toBe(2);
      expect(result!.owaspCoverageScore).toBe(75);
      expect(result!.status).toBe("completed");
    } catch (err: any) {
      // If DB is not available in test env, skip gracefully
      if (err.message?.includes("DATABASE_URL") || err.message?.includes("connect")) {
        console.log("Skipping DB test — no database connection available");
        return;
      }
      throw err;
    }
  });

  it("should save and retrieve engagement findings", async () => {
    const { saveEngagementFindings, getEngagementFindings } = await import("./db");
    
    const testEngId = 9999990 + Math.floor(Math.random() * 1000);
    
    try {
      const count = await saveEngagementFindings([
        {
          engagementId: testEngId,
          title: "SQL Injection in login form",
          severity: "critical",
          cve: "CVE-2024-1234",
          hostname: "test.example.com",
          port: 443,
          tool: "sqlmap",
          corroborationTier: "confirmed",
          exploitAttempted: true,
          exploitSucceeded: true,
          exploitTechnique: "union-based",
        },
        {
          engagementId: testEngId,
          title: "Missing HSTS header",
          severity: "low",
          hostname: "test.example.com",
          tool: "nmap",
          corroborationTier: "unverified",
        },
      ]);

      expect(count).toBe(2);

      const findings = await getEngagementFindings(testEngId);
      expect(findings.length).toBe(2);
      
      const sqli = findings.find(f => f.title.includes("SQL Injection"));
      expect(sqli).toBeDefined();
      expect(sqli!.severity).toBe("critical");
      expect(sqli!.exploitSucceeded).toBe(1);
    } catch (err: any) {
      if (err.message?.includes("DATABASE_URL") || err.message?.includes("connect")) {
        console.log("Skipping DB test — no database connection available");
        return;
      }
      throw err;
    }
  });

  it("should handle empty findings array gracefully", async () => {
    const { saveEngagementFindings } = await import("./db");
    const count = await saveEngagementFindings([]);
    expect(count).toBe(0);
  });
});
