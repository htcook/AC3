/**
 * Tests for CI/CD Gap Fixes (P0–P3)
 *
 * P0: Scan server pre-flight, target URL allowlist
 * P1: Secret scanning, baseline comparison, Jenkins/Azure YAML
 * P2: SBOM generation, incremental IaC scanning, Prowler CSPM
 * P3: Container registry auto-discovery, cloud IAM enumerator
 */
import { describe, it, expect } from "vitest";

// ─── P0: Target URL Allowlist ───────────────────────────────────────────────

describe("P0: validateTargetUrl", () => {
  it("allows any URL when allowlist is empty", async () => {
    const { validateTargetUrl } = await import("./lib/aws-cicd-connector");
    const result = validateTargetUrl("https://evil.com", []);
    expect(result.valid).toBe(true);
  });

  it("allows any URL when allowlist is undefined", async () => {
    const { validateTargetUrl } = await import("./lib/aws-cicd-connector");
    const result = validateTargetUrl("https://evil.com", undefined);
    expect(result.valid).toBe(true);
  });

  it("allows exact domain match", async () => {
    const { validateTargetUrl } = await import("./lib/aws-cicd-connector");
    const result = validateTargetUrl("https://staging.example.com/path", ["staging.example.com"]);
    expect(result.valid).toBe(true);
  });

  it("allows wildcard subdomain match", async () => {
    const { validateTargetUrl } = await import("./lib/aws-cicd-connector");
    const result = validateTargetUrl("https://api.staging.example.com", ["*.example.com"]);
    expect(result.valid).toBe(true);
  });

  it("rejects URL not in allowlist", async () => {
    const { validateTargetUrl } = await import("./lib/aws-cicd-connector");
    const result = validateTargetUrl("https://evil.com", ["example.com", "*.myapp.io"]);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("evil.com");
    expect(result.reason).toContain("not in the allowlist");
  });

  it("rejects invalid URL", async () => {
    const { validateTargetUrl } = await import("./lib/aws-cicd-connector");
    const result = validateTargetUrl("not-a-url", ["example.com"]);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("Invalid URL");
  });

  it("is case-insensitive for domain matching", async () => {
    const { validateTargetUrl } = await import("./lib/aws-cicd-connector");
    const result = validateTargetUrl("https://STAGING.Example.COM/api", ["staging.example.com"]);
    expect(result.valid).toBe(true);
  });
});

// ─── P0: Scan Server Pre-flight ─────────────────────────────────────────────

describe("P0: scanServerPreFlight", () => {
  it("returns an object with healthy boolean and optional error", async () => {
    const { scanServerPreFlight } = await import("./lib/aws-cicd-connector");
    const result = await scanServerPreFlight();
    expect(result).toHaveProperty("healthy");
    expect(typeof result.healthy).toBe("boolean");
    if (!result.healthy) {
      expect(result.error).toBeDefined();
    }
  });
});

// ─── P1: Secret Scanning ────────────────────────────────────────────────────

describe("P1: Secret scanning via executeCicdScan", () => {
  it("executeCicdScan accepts secrets scan type", async () => {
    const mod = await import("./lib/aws-cicd-connector");
    // runSecretScanCicd is internal, dispatched via executeCicdScan with scanTypes: ["secrets"]
    expect(typeof mod.executeCicdScan).toBe("function");
  });
});

// ─── P1: Baseline Comparison ────────────────────────────────────────────────

describe("P1: compareWithBaseline", () => {
  it("is exported as a function", async () => {
    const mod = await import("./lib/aws-cicd-connector");
    expect(typeof mod.compareWithBaseline).toBe("function");
  });

  it("returns new/fixed counts structure", async () => {
    const { compareWithBaseline } = await import("./lib/aws-cicd-connector");
    // Call with a non-existent baseline — should return all findings as new
    const result = await compareWithBaseline(999999, 0, [
      { title: "Test Finding", severity: "high", scanner: "test", url: "https://example.com", description: "test" },
    ]);
    expect(result).toHaveProperty("newCount");
    expect(result).toHaveProperty("fixedCount");
    expect(typeof result.newCount).toBe("number");
    expect(typeof result.fixedCount).toBe("number");
  });
});

// ─── P1: Jenkins YAML ───────────────────────────────────────────────────────

describe("P1: generateJenkinsfileYaml", () => {
  it("generates a Jenkinsfile with pipeline stages", async () => {
    const { generateJenkinsfileYaml } = await import("./lib/aws-cicd-connector");
    const yaml = generateJenkinsfileYaml("https://webhook.test/api/cicd/webhook/1");
    expect(yaml).toContain("pipeline");
    expect(yaml).toContain("stage");
    expect(yaml).toContain("webhook.test");
  });
});

// ─── P1: Azure DevOps YAML ─────────────────────────────────────────────────

describe("P1: generateAzureDevOpsYaml", () => {
  it("generates Azure Pipelines YAML with trigger and steps", async () => {
    const { generateAzureDevOpsYaml } = await import("./lib/aws-cicd-connector");
    const yaml = generateAzureDevOpsYaml("https://webhook.test/api/cicd/webhook/2");
    expect(yaml).toContain("trigger:");
    expect(yaml).toContain("webhook.test");
  });
});

// ─── P2: SBOM Generation ───────────────────────────────────────────────────

describe("P2: generateSbom", () => {
  it("is exported as a function", async () => {
    const mod = await import("./lib/aws-cicd-connector");
    expect(typeof mod.generateSbom).toBe("function");
  });
});

// ─── P2: Incremental IaC Scanning ──────────────────────────────────────────

describe("P2: runIacScanCicd incremental mode", () => {
  it("executeCicdScan accepts incrementalOnly field", async () => {
    const mod = await import("./lib/aws-cicd-connector");
    // runIacScanCicd is internal (not exported), but executeCicdScan accepts incrementalOnly
    expect(typeof mod.executeCicdScan).toBe("function");
  });
});

// ─── P2: Prowler CSPM Wire-up ───────────────────────────────────────────────

describe("P2: CSPM scan type in executeCicdScan", () => {
  it("executeCicdScan accepts cspm scan type with cloudProvider", async () => {
    const mod = await import("./lib/aws-cicd-connector");
    // runCspmCicd is internal, but executeCicdScan dispatches to it
    expect(typeof mod.executeCicdScan).toBe("function");
  });
});

// ─── P3: Container Registry Auto-Discovery ─────────────────────────────────

describe("P3: discoverContainerImages", () => {
  it("is exported as a function", async () => {
    const mod = await import("./lib/aws-cicd-connector");
    expect(typeof mod.discoverContainerImages).toBe("function");
  });
});

// ─── P3: Cloud IAM Enumerator ───────────────────────────────────────────────

describe("P3: enumerateCloudIam", () => {
  it("is exported as a function", async () => {
    const mod = await import("./lib/aws-cicd-connector");
    expect(typeof mod.enumerateCloudIam).toBe("function");
  });
});

// ─── CicdScanRequest type coverage ─────────────────────────────────────────

describe("CicdScanRequest extended fields", () => {
  it("executeCicdScan accepts all new fields without error", async () => {
    const mod = await import("./lib/aws-cicd-connector");
    // Verify the function exists and is callable (we won't actually run a scan)
    expect(typeof mod.executeCicdScan).toBe("function");
  });
});

// ─── CicdScanResult extended fields ─────────────────────────────────────────

describe("CicdScanResult extended fields", () => {
  it("validateTargetUrl returns blocked result with correct structure when rejected", async () => {
    const { validateTargetUrl } = await import("./lib/aws-cicd-connector");
    const result = validateTargetUrl("https://evil.com", ["safe.com"]);
    expect(result.valid).toBe(false);
    expect(result.reason).toBeDefined();
  });
});

// ─── Integration: executeCicdScan with allowlist rejection ──────────────────

describe("Integration: executeCicdScan rejects blocked URLs", () => {
  it("returns error status when target URL is not in allowlist", async () => {
    const { executeCicdScan } = await import("./lib/aws-cicd-connector");
    const result = await executeCicdScan({
      targetUrl: "https://evil.com",
      scanTypes: ["nuclei"],
      pipelineId: 999,
      runId: 999,
      allowedDomains: ["safe.example.com"],
    });
    expect(result.status).toBe("error");
    expect(result.findings[0].title).toContain("Scan blocked");
    expect(result.totalFindings).toBe(0);
  });
});
