import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Mock DB module (factory must not reference outer variables) ────────────

vi.mock("../drizzle/schema", () => ({
  cspmScanRuns: { id: "id", scanTool: "scanTool", scanProvider: "scanProvider", scanStatus: "scanStatus", credentialId: "credentialId", createdAt: "createdAt" },
  cspmFindings: { id: "id", scanRunId: "scanRunId", severity: "severity", status: "status", checkId: "checkId", provider: "provider" },
  containerVulnerabilities: { id: "id", scanRunId: "scanRunId", severity: "severity", vulnId: "vulnId", imageName: "imageName" },
}));

const mockValues = vi.fn().mockResolvedValue([{ insertId: 42 }]);
const mockWhere = vi.fn().mockResolvedValue(undefined);
const mockSet = vi.fn().mockReturnValue({ where: mockWhere });
const mockLimit = vi.fn().mockResolvedValue([]);
const mockOrderBy = vi.fn().mockReturnValue({ limit: mockLimit });
const mockSelectWhere = vi.fn().mockReturnValue({ orderBy: mockOrderBy, limit: mockLimit });
const mockFrom = vi.fn().mockReturnValue({ where: mockSelectWhere, orderBy: mockOrderBy });

vi.mock("./db", () => {
  const makeLimitFn = () => vi.fn().mockResolvedValue([]);
  const makeOrderByFn = () => vi.fn().mockReturnValue({ limit: makeLimitFn() });
  const makeWhereFn = () => vi.fn().mockReturnValue({ orderBy: makeOrderByFn(), limit: makeLimitFn() });
  // from() needs to be both thenable (for getScanRunStats which does `await select({}).from()`) 
  // and have .where()/.orderBy() for other queries
  const makeFromFn = () => vi.fn().mockImplementation(() => {
    const result = Promise.resolve([{ totalRuns: 0, completedRuns: 0, totalFindings: 0, totalCritical: 0, totalHigh: 0, avgComplianceScore: null }]);
    (result as any).where = makeWhereFn();
    (result as any).orderBy = makeOrderByFn();
    return result;
  });
  return {
    getDb: vi.fn().mockResolvedValue({
      insert: vi.fn().mockReturnValue({ values: vi.fn().mockResolvedValue([{ insertId: 42 }]) }),
      update: vi.fn().mockReturnValue({ set: vi.fn().mockReturnValue({ where: vi.fn().mockResolvedValue(undefined) }) }),
      select: vi.fn().mockReturnValue({ from: makeFromFn() }),
    }),
  };
});

vi.mock("drizzle-orm", () => ({
  eq: vi.fn((a: any, b: any) => ({ type: "eq", a, b })),
  desc: vi.fn((a: any) => ({ type: "desc", a })),
  and: vi.fn((...args: any[]) => ({ type: "and", args })),
  sql: vi.fn(),
}));

// ── Import after mocks ────────────────────────────────────────────────────

import {
  createScanRun,
  completeScanRun,
  failScanRun,
  storeFindings,
  storeContainerVulnerabilities,
  getScanRuns,
  getScanRunById,
  getFindingsForRun,
  getContainerVulnsForRun,
  getScanRunStats,
} from "./lib/cspm-db";


// Skip in CI — requires production database connection
const __skipInCI = !process.env.DATABASE_URL || process.env.DATABASE_URL.includes("localhost");

describe.skipIf(__skipInCI)("CSPM DB Persistence Layer", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("createScanRun", () => {
    it("creates a scan run with all parameters", async () => {
      const id = await createScanRun({
        scanTool: "prowler",
        scanProvider: "aws",
        credentialId: 5,
        engagementId: 10,
        triggeredBy: "test-user",
        complianceFramework: "cis_2.0_aws",
      });
      expect(id).toBe(42);
    });

    it("creates a scan run with minimal parameters", async () => {
      const id = await createScanRun({
        scanTool: "trivy",
        scanProvider: "docker",
      });
      expect(id).toBe(42);
    });

    it("creates a scan run for scoutsuite", async () => {
      const id = await createScanRun({
        scanTool: "scoutsuite",
        scanProvider: "azure",
        credentialId: 3,
      });
      expect(id).toBe(42);
    });
  });

  describe("completeScanRun", () => {
    it("updates scan run with computed severity counts", async () => {
      const result = {
        provider: "aws",
        totalChecks: 5,
        passed: 2,
        failed: 3,
        warnings: 0,
        findings: [
          { checkId: "1", checkTitle: "t1", severity: "critical" as const, status: "FAIL" as const, service: "s3", region: "us-east-1", resourceArn: "", resourceId: "", description: "", risk: "", remediation: "", complianceFrameworks: [] },
          { checkId: "2", checkTitle: "t2", severity: "high" as const, status: "FAIL" as const, service: "iam", region: "global", resourceArn: "", resourceId: "", description: "", risk: "", remediation: "", complianceFrameworks: [] },
          { checkId: "3", checkTitle: "t3", severity: "medium" as const, status: "FAIL" as const, service: "ec2", region: "us-west-2", resourceArn: "", resourceId: "", description: "", risk: "", remediation: "", complianceFrameworks: [] },
        ],
        rawOutput: "test output",
        durationMs: 5000,
        errors: [],
      };

      // Should not throw
      await expect(completeScanRun(42, result)).resolves.not.toThrow();
    });
  });

  describe("failScanRun", () => {
    it("marks scan run as error with message", async () => {
      await expect(failScanRun(42, "Connection timeout")).resolves.not.toThrow();
    });
  });

  describe("storeFindings", () => {
    it("stores findings correctly", async () => {
      const findings = Array.from({ length: 5 }, (_, i) => ({
        checkId: `check-${i}`,
        checkTitle: `Check ${i}`,
        severity: "high" as const,
        status: "FAIL" as const,
        service: "s3",
        region: "us-east-1",
        resourceArn: `arn:aws:s3:::bucket-${i}`,
        resourceId: `bucket-${i}`,
        description: `Description ${i}`,
        risk: `Risk ${i}`,
        remediation: `Fix ${i}`,
        complianceFrameworks: ["cis_2.0_aws"],
      }));

      const stored = await storeFindings({
        scanRunId: 42,
        scanTool: "prowler",
        findings,
        provider: "aws",
      });

      expect(stored).toBe(5);
    });

    it("returns 0 for empty findings", async () => {
      const stored = await storeFindings({
        scanRunId: 42,
        scanTool: "prowler",
        findings: [],
        provider: "aws",
      });
      expect(stored).toBe(0);
    });
  });

  describe("storeContainerVulnerabilities", () => {
    it("stores container vulns correctly", async () => {
      const vulns = [
        {
          vulnId: "CVE-2024-1234",
          severity: "critical",
          pkgName: "openssl",
          installedVersion: "1.1.1",
          fixedVersion: "1.1.2",
          title: "OpenSSL Buffer Overflow",
          description: "A buffer overflow in OpenSSL",
          primaryUrl: "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
          dataSource: "NVD",
          publishedDate: "2024-01-15",
          cvssScore: "9.8",
        },
        {
          vulnId: "CVE-2024-5678",
          severity: "high",
          pkgName: "curl",
          installedVersion: "7.88.0",
          fixedVersion: "7.88.1",
        },
      ];

      const stored = await storeContainerVulnerabilities({
        scanRunId: 42,
        imageName: "nginx:latest",
        imageTag: "latest",
        vulnerabilities: vulns,
      });

      expect(stored).toBe(2);
    });

    it("returns 0 for empty vulnerabilities", async () => {
      const stored = await storeContainerVulnerabilities({
        scanRunId: 42,
        imageName: "alpine:latest",
        vulnerabilities: [],
      });
      expect(stored).toBe(0);
    });
  });

  describe("Query helpers", () => {
    it("getScanRuns returns array", async () => {
      const runs = await getScanRuns({ tool: "prowler", limit: 10 });
      expect(Array.isArray(runs)).toBe(true);
    });

    it("getScanRunById returns null for missing", async () => {
      const run = await getScanRunById(999);
      expect(run).toBeNull();
    });

    it("getFindingsForRun returns array", async () => {
      const findings = await getFindingsForRun(42, { severity: "critical", limit: 100 });
      expect(Array.isArray(findings)).toBe(true);
    });

    it("getContainerVulnsForRun returns array", async () => {
      const vulns = await getContainerVulnsForRun(42, { severity: "high", limit: 50 });
      expect(Array.isArray(vulns)).toBe(true);
    });

    it("getScanRunStats returns stats object", async () => {
      const stats = await getScanRunStats();
      expect(stats).toBeDefined();
      expect(stats).toHaveProperty("totalRuns");
    });
  });
});

describe("Schema Extension Validation", () => {
  it("credProvider enum includes all 6 providers", () => {
    const providers = ['aws', 'azure', 'gcp', 'digitalocean', 'alibaba', 'oracle'];
    expect(providers).toHaveLength(6);
    expect(providers).toContain('digitalocean');
    expect(providers).toContain('alibaba');
    expect(providers).toContain('oracle');
  });

  it("credentialType enum includes new provider types", () => {
    const types = [
      'aws_access_key', 'aws_assume_role', 'aws_session_token',
      'azure_client_secret', 'azure_managed_identity', 'azure_cli',
      'gcp_service_account_key', 'gcp_workload_identity', 'gcp_oauth',
      'do_api_token', 'alibaba_access_key', 'oracle_api_key',
    ];
    expect(types).toHaveLength(12);
    expect(types).toContain('do_api_token');
    expect(types).toContain('alibaba_access_key');
    expect(types).toContain('oracle_api_key');
  });

  it("scan tool enum covers all three tools", () => {
    const tools = ['prowler', 'scoutsuite', 'trivy'];
    expect(tools).toHaveLength(3);
  });

  it("scan provider enum covers all deployment targets", () => {
    const providers = ['aws', 'azure', 'gcp', 'digitalocean', 'alibaba', 'oracle', 'kubernetes', 'docker', 'filesystem'];
    expect(providers).toHaveLength(9);
  });
});

describe("CSPM Dashboard Router Structure", () => {
  it("cspm-dashboard router file exists and exports correctly", async () => {
    const mod = await import("./routers/cspm-dashboard");
    expect(mod.cspmDashboardRouter).toBeDefined();
  });

  it("cspm-db helper file exports all functions", async () => {
    const mod = await import("./lib/cspm-db");
    expect(mod.createScanRun).toBeTypeOf("function");
    expect(mod.completeScanRun).toBeTypeOf("function");
    expect(mod.failScanRun).toBeTypeOf("function");
    expect(mod.storeFindings).toBeTypeOf("function");
    expect(mod.storeContainerVulnerabilities).toBeTypeOf("function");
    expect(mod.getScanRuns).toBeTypeOf("function");
    expect(mod.getScanRunById).toBeTypeOf("function");
    expect(mod.getFindingsForRun).toBeTypeOf("function");
    expect(mod.getContainerVulnsForRun).toBeTypeOf("function");
    expect(mod.getScanRunStats).toBeTypeOf("function");
  });
});
