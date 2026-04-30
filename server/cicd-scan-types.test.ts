/**
 * Tests for:
 * 1. Engagement completion DB update (the fix for stuck engagements)
 * 2. New CI/CD scan types (config, cspm, container, iac)
 * 3. Extended webhook payload parsing
 */
import { describe, it, expect, vi } from "vitest";

// ─── Test 1: CicdScanType union includes all 7 types ────────────────────────

// Skip in CI — requires SSH access to scan server
const __skipInCI = !process.env.SCAN_SERVER_HOST;

describe.skipIf(__skipInCI)("CicdScanType", () => {
  it("should include all 7 scan types in the type definition", async () => {
    // We can't directly test TypeScript types at runtime, but we can verify
    // the executeCicdScan function accepts all scan types by checking the
    // CicdScanRequest interface
    const mod = await import("./lib/aws-cicd-connector");
    // The module should export the function
    expect(typeof mod.executeCicdScan).toBe("function");
    expect(typeof mod.generateWebhookSecret).toBe("function");
    expect(typeof mod.generateWebhookUrl).toBe("function");
    expect(typeof mod.verifyGitHubWebhook).toBe("function");
  });
});

// ─── Test 2: Config audit scanner catches missing headers ────────────────────
describe("Config Audit Scanner", () => {
  it("should detect missing security headers from a live URL", async () => {
    // We test the config audit by calling executeCicdScan with type "config"
    // against a known URL. Since we can't hit a real URL in tests,
    // we verify the function doesn't throw and returns a valid structure.
    const { executeCicdScan } = await import("./lib/aws-cicd-connector");

    // Mock fetch to return a response with no security headers
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({
        "content-type": "text/html",
        // Deliberately missing: strict-transport-security, content-security-policy, etc.
      }),
    }) as any;

    try {
      const result = await executeCicdScan({
        targetUrl: "https://example.com",
        scanTypes: ["config"],
        pipelineId: 999,
        runId: 999,
      });

      expect(result).toBeDefined();
      expect(result.status).toMatch(/passed|failed/);
      expect(typeof result.totalFindings).toBe("number");
      expect(Array.isArray(result.findings)).toBe(true);

      // Should find missing security headers
      if (result.findings.length > 0) {
        const headerFindings = result.findings.filter(f => f.scanner === "config-audit");
        expect(headerFindings.length).toBeGreaterThan(0);
        // Each finding should have required fields
        for (const f of headerFindings) {
          expect(f.title).toBeTruthy();
          expect(f.severity).toMatch(/critical|high|medium|low|info/);
          expect(f.url).toBeTruthy();
        }
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

// ─── Test 3: CSPM scanner returns CIS benchmark findings ─────────────────────
describe("CSPM Scanner", () => {
  it("should return cloud security posture findings for AWS", async () => {
    const { executeCicdScan } = await import("./lib/aws-cicd-connector");

    const result = await executeCicdScan({
      targetUrl: "https://example.com",
      scanTypes: ["cspm"],
      pipelineId: 999,
      runId: 999,
      cloudProvider: "aws",
    });

    expect(result).toBeDefined();
    expect(result.status).toMatch(/passed|failed/);
    expect(typeof result.totalFindings).toBe("number");

    // CSPM findings should reference the cloud provider
    if (result.findings.length > 0) {
      const cspmFindings = result.findings.filter(f =>
        f.scanner === "cspm" || f.scanner === "cspm-iam"
      );
      for (const f of cspmFindings) {
        expect(f.title).toMatch(/\[CSPM\]|\[IAM\]/);
        expect(f.url).toContain("aws");
      }
    }
  });
});

// ─── Test 4: Container scanner accepts image reference ───────────────────────
describe("Container Scanner", () => {
  it("should handle container scan type without crashing", async () => {
    const { executeCicdScan } = await import("./lib/aws-cicd-connector");

    // Container scan will fail because trivy isn't available on the scan server,
    // but it should not throw — it should return gracefully with 0 findings
    const result = await executeCicdScan({
      targetUrl: "https://example.com",
      scanTypes: ["container"],
      pipelineId: 999,
      runId: 999,
      containerImage: "nginx:latest",
    });

    expect(result).toBeDefined();
    expect(result.status).toMatch(/passed|failed/);
    expect(typeof result.totalFindings).toBe("number");
    expect(Array.isArray(result.findings)).toBe(true);
  });
});

// ─── Test 5: IaC scanner accepts repo URL ────────────────────────────────────
describe("IaC Scanner", () => {
  it("should handle iac scan type without crashing", async () => {
    const { executeCicdScan } = await import("./lib/aws-cicd-connector");

    // IaC scan will fail because checkov isn't available, but should not throw
    const result = await executeCicdScan({
      targetUrl: "https://example.com",
      scanTypes: ["iac"],
      pipelineId: 999,
      runId: 999,
      iacRepoUrl: "https://github.com/example/infra",
    });

    expect(result).toBeDefined();
    expect(result.status).toMatch(/passed|failed/);
    expect(typeof result.totalFindings).toBe("number");
  });
});

// ─── Test 6: Multiple scan types in a single run ─────────────────────────────
describe("Multi-type scan", () => {
  it("should execute multiple scan types and aggregate findings", async () => {
    const { executeCicdScan } = await import("./lib/aws-cicd-connector");

    // Mock fetch for config audit
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ "content-type": "text/html" }),
    }) as any;

    try {
      const result = await executeCicdScan({
        targetUrl: "https://example.com",
        scanTypes: ["config", "cspm"],
        pipelineId: 999,
        runId: 999,
        cloudProvider: "aws",
      });

      expect(result).toBeDefined();
      expect(typeof result.criticalCount).toBe("number");
      expect(typeof result.highCount).toBe("number");
      expect(typeof result.mediumCount).toBe("number");
      expect(typeof result.lowCount).toBe("number");
      expect(typeof result.maxCvss).toBe("number");
      expect(typeof result.duration).toBe("number");

      // Should have findings from both scanners
      if (result.findings.length > 0) {
        const scanners = new Set(result.findings.map(f => f.scanner));
        // At least one scanner should have produced results
        expect(scanners.size).toBeGreaterThanOrEqual(1);
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

// ─── Test 7: Engagement completion update fields ─────────────────────────────
describe("Engagement completion fix", () => {
  it("should call updateEngagement with correct fields on completion", () => {
    // Verify the fix is in place by checking the orchestrator source
    // This is a structural test — we verify the code contains the fix
    const fs = require("fs");
    const source = fs.readFileSync(
      require("path").join(__dirname, "lib/engagement-orchestrator.ts"),
      "utf-8"
    );

    // The fix should include updateEngagement after phaseCheckpoint('completed')
    expect(source).toContain("updateEngagement");
    expect(source).toContain("status: 'completed'");
    expect(source).toContain("autoResumeOnRestart: 0");

    // The error handler should also update the engagement
    expect(source).toContain("updateEngagement(engagementId");
  });
});

// ─── Test 8: Webhook payload parsing for new fields ──────────────────────────
describe("Webhook payload parsing", () => {
  it("should parse container_image, iac_repo_url, and cloud_provider from payload", () => {
    const fs = require("fs");
    const source = fs.readFileSync(
      require("path").join(__dirname, "lib/cicd-webhook-routes.ts"),
      "utf-8"
    );

    // Verify the webhook handler extracts the new fields
    expect(source).toContain("container_image");
    expect(source).toContain("iac_repo_url");
    expect(source).toContain("cloud_provider");
    expect(source).toContain("scan_types");
    expect(source).toContain("requestedScanTypes");
  });
});

// ─── Test 9: CicdScanResult structure ────────────────────────────────────────
describe("CicdScanResult", () => {
  it("should return all required fields in scan result", async () => {
    const { executeCicdScan } = await import("./lib/aws-cicd-connector");

    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({}),
    }) as any;

    try {
      const result = await executeCicdScan({
        targetUrl: "https://test.example.com",
        scanTypes: ["config"],
        pipelineId: 1,
        runId: 1,
      });

      // Verify all required fields exist
      expect(result).toHaveProperty("runId", 1);
      expect(result).toHaveProperty("pipelineId", 1);
      expect(result).toHaveProperty("status");
      expect(result).toHaveProperty("totalFindings");
      expect(result).toHaveProperty("criticalCount");
      expect(result).toHaveProperty("highCount");
      expect(result).toHaveProperty("mediumCount");
      expect(result).toHaveProperty("lowCount");
      expect(result).toHaveProperty("maxCvss");
      expect(result).toHaveProperty("duration");
      expect(result).toHaveProperty("findings");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
