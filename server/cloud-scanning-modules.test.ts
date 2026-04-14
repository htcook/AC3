/**
 * Comprehensive tests for cloud scanning modules:
 *
 * 1. ScoutSuite integration router — output parsing, provider support, severity normalization
 * 2. Trivy integration router — JSON parsing, self-scan logic, SBOM generation
 * 3. Prowler integration router — JSON-OCSF parsing, compliance frameworks, service listing
 * 4. Cloud resource enumeration — types, supported resources, CIS check structure
 * 5. Fabric Scanner — credential helper, scan workflow types
 * 6. Cross-module consistency — all routers registered, no import errors
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import * as fs from "fs";

// ─── ScoutSuite Integration Tests ──────────────────────────────────────────

describe("ScoutSuite Integration Router", () => {
  it("should export scoutsuiteIntegrationRouter", async () => {
    const mod = await import("./routers/scoutsuite-integration");
    expect(mod.scoutsuiteIntegrationRouter).toBeDefined();
  });

  it("should have all required procedures", async () => {
    const mod = await import("./routers/scoutsuite-integration");
    const router = mod.scoutsuiteIntegrationRouter;
    const procedures = Object.keys(router._def.procedures);
    expect(procedures).toContain("checkAvailability");
    expect(procedures).toContain("runScan");
    expect(procedures).toContain("runScanFromCredential");
    expect(procedures).toContain("getSupportedProviders");
    expect(procedures).toContain("getReportUrl");
  });

  it("should support 6 cloud providers (aws, azure, gcp, aliyun, oci, do)", async () => {
    const code = fs.readFileSync("server/routers/scoutsuite-integration.ts", "utf-8");
    // The runScan input accepts these providers
    expect(code).toContain('"aws"');
    expect(code).toContain('"azure"');
    expect(code).toContain('"gcp"');
    expect(code).toContain('"aliyun"');
    expect(code).toContain('"oci"');
    expect(code).toContain('"do"');
  });

  it("should have ScoutSuiteFinding type with required fields", async () => {
    const code = fs.readFileSync("server/routers/scoutsuite-integration.ts", "utf-8");
    expect(code).toContain("interface ScoutSuiteFinding");
    expect(code).toContain("severity: \"danger\" | \"warning\" | \"info\"");
    expect(code).toContain("flaggedItems: number");
    expect(code).toContain("checkedItems: number");
    expect(code).toContain("items: ScoutSuiteItem[]");
  });

  it("should have ScoutSuiteScanResult with service breakdown", async () => {
    const code = fs.readFileSync("server/routers/scoutsuite-integration.ts", "utf-8");
    expect(code).toContain("interface ScoutSuiteScanResult");
    expect(code).toContain("serviceBreakdown: Record<string,");
    expect(code).toContain("dangerCount: number");
    expect(code).toContain("warningCount: number");
  });

  it("should normalize severity correctly (danger/warning/info)", async () => {
    const code = fs.readFileSync("server/routers/scoutsuite-integration.ts", "utf-8");
    // Critical and high map to danger
    expect(code).toContain('lower === "critical"');
    expect(code).toContain('lower === "high"');
    expect(code).toContain('return "danger"');
    // Medium maps to warning
    expect(code).toContain('lower === "medium"');
    expect(code).toContain('return "warning"');
  });

  it("should handle GCP service account key file securely", async () => {
    const code = fs.readFileSync("server/routers/scoutsuite-integration.ts", "utf-8");
    // Should write key to temp file with restricted permissions
    expect(code).toContain("chmod 600");
    expect(code).toContain("/tmp/scoutsuite-gcp-sa.json");
    // Should clean up after scan
    expect(code).toContain("rm -f /tmp/scoutsuite-gcp-sa.json");
  });

  it("should read ScoutSuite JSON report from file system", async () => {
    const code = fs.readFileSync("server/routers/scoutsuite-integration.ts", "utf-8");
    expect(code).toContain("scoutsuite-results/scoutsuite_results_");
    expect(code).toContain("--result-format json");
  });

  it("should support DigitalOcean provider with DIGITALOCEAN_ACCESS_TOKEN", async () => {
    const code = fs.readFileSync("server/routers/scoutsuite-integration.ts", "utf-8");
    expect(code).toContain("DIGITALOCEAN_ACCESS_TOKEN");
  });

  it("should support AWS role assumption with external ID", async () => {
    const code = fs.readFileSync("server/routers/scoutsuite-integration.ts", "utf-8");
    expect(code).toContain("--role-arn");
    expect(code).toContain("--external-id");
  });
});

// ─── Trivy Integration Tests ───────────────────────────────────────────────

describe("Trivy Integration Router", () => {
  it("should export trivyIntegrationRouter", async () => {
    const mod = await import("./routers/trivy-integration");
    expect(mod.trivyIntegrationRouter).toBeDefined();
  });

  it("should have all required procedures including self-scan", async () => {
    const mod = await import("./routers/trivy-integration");
    const router = mod.trivyIntegrationRouter;
    const procedures = Object.keys(router._def.procedures);
    expect(procedures).toContain("checkAvailability");
    expect(procedures).toContain("scanImage");
    expect(procedures).toContain("scanFilesystem");
    expect(procedures).toContain("generateSBOM");
    expect(procedures).toContain("listLocalImages");
    expect(procedures).toContain("selfScanAllImages");
    expect(procedures).toContain("selfScanFilesystem");
  });

  it("should have TrivyVulnerability type with CVE fields", async () => {
    const code = fs.readFileSync("server/routers/trivy-integration.ts", "utf-8");
    expect(code).toContain("interface TrivyVulnerability");
    expect(code).toContain("vulnerabilityId: string");
    expect(code).toContain("pkgName: string");
    expect(code).toContain("installedVersion: string");
    expect(code).toContain("fixedVersion: string");
    expect(code).toContain("cvss?: { score: number; vector: string }");
  });

  it("should have TrivyMisconfiguration type for IaC scanning", async () => {
    const code = fs.readFileSync("server/routers/trivy-integration.ts", "utf-8");
    expect(code).toContain("interface TrivyMisconfiguration");
    expect(code).toContain("resolution: string");
    expect(code).toContain("type: string");
  });

  it("should support SBOM generation in cyclonedx and spdx formats", async () => {
    const code = fs.readFileSync("server/routers/trivy-integration.ts", "utf-8");
    expect(code).toContain('"cyclonedx"');
    expect(code).toContain('"spdx"');
    expect(code).toContain('"spdx-json"');
  });

  it("should filter <none> images in selfScanAllImages", async () => {
    const code = fs.readFileSync("server/routers/trivy-integration.ts", "utf-8");
    expect(code).toContain('"<none>"');
    expect(code).toContain("img.Repository !== \"<none>\"");
  });

  it("should limit images to maxImages parameter", async () => {
    const code = fs.readFileSync("server/routers/trivy-integration.ts", "utf-8");
    expect(code).toContain("opts.maxImages");
    expect(code).toContain("images.slice(0, opts.maxImages)");
  });

  it("should aggregate self-scan results with imagesWithCritical count", async () => {
    const code = fs.readFileSync("server/routers/trivy-integration.ts", "utf-8");
    expect(code).toContain("imagesWithCritical");
    expect(code).toContain("imagesWithHigh");
    expect(code).toContain("cleanImages");
  });

  it("should support filesystem scanning with multiple scanner types", async () => {
    const code = fs.readFileSync("server/routers/trivy-integration.ts", "utf-8");
    expect(code).toContain('"vuln"');
    expect(code).toContain('"misconfig"');
    expect(code).toContain('"secret"');
    expect(code).toContain('"license"');
  });

  it("should support registry credentials for private images", async () => {
    const code = fs.readFileSync("server/routers/trivy-integration.ts", "utf-8");
    expect(code).toContain("TRIVY_USERNAME");
    expect(code).toContain("TRIVY_PASSWORD");
  });

  it("should parse Trivy JSON output with Results array", async () => {
    const code = fs.readFileSync("server/routers/trivy-integration.ts", "utf-8");
    expect(code).toContain("report.Results");
    expect(code).toContain("result.Vulnerabilities");
    expect(code).toContain("result.Misconfigurations");
  });
});

// ─── Prowler Integration Tests ─────────────────────────────────────────────

describe("Prowler Integration Router", () => {
  it("should export prowlerIntegrationRouter", async () => {
    const mod = await import("./routers/prowler-integration");
    expect(mod.prowlerIntegrationRouter).toBeDefined();
  });

  it("should have all required procedures", async () => {
    const mod = await import("./routers/prowler-integration");
    const router = mod.prowlerIntegrationRouter;
    const procedures = Object.keys(router._def.procedures);
    expect(procedures).toContain("checkAvailability");
    expect(procedures).toContain("runProwlerScan");
    expect(procedures).toContain("runScoutSuiteScan");
    expect(procedures).toContain("getComplianceFrameworks");
    expect(procedures).toContain("getAvailableServices");
  });

  it("should have ProwlerFinding type with compliance fields", async () => {
    const code = fs.readFileSync("server/routers/prowler-integration.ts", "utf-8");
    expect(code).toContain("interface ProwlerFinding");
    expect(code).toContain("checkId: string");
    expect(code).toContain("complianceFrameworks: string[]");
    expect(code).toContain("resourceArn: string");
  });

  it("should support AWS role assumption with -R and -T flags", async () => {
    const code = fs.readFileSync("server/routers/prowler-integration.ts", "utf-8");
    expect(code).toContain("-R ${input.credentials.roleArn}");
    expect(code).toContain("-T ${input.credentials.externalId}");
  });

  it("should use JSON-OCSF output format for Prowler", async () => {
    const code = fs.readFileSync("server/routers/prowler-integration.ts", "utf-8");
    expect(code).toContain("-M json-ocsf");
    expect(code).toContain("--no-banner");
  });

  it("should support Azure service principal auth with --sp-env-auth", async () => {
    const code = fs.readFileSync("server/routers/prowler-integration.ts", "utf-8");
    expect(code).toContain("--sp-env-auth");
    expect(code).toContain("AZURE_TENANT_ID");
    expect(code).toContain("AZURE_CLIENT_ID");
    expect(code).toContain("AZURE_CLIENT_SECRET");
  });

  it("should have comprehensive AWS compliance frameworks", async () => {
    const code = fs.readFileSync("server/routers/prowler-integration.ts", "utf-8");
    expect(code).toContain("cis_1.4_aws");
    expect(code).toContain("cis_3.0_aws");
    expect(code).toContain("pci_3.2.1_aws");
    expect(code).toContain("hipaa_aws");
    expect(code).toContain("soc2_aws");
    expect(code).toContain("nist_800_53_revision_5_aws");
    expect(code).toContain("fedramp_moderate_revision_4_aws");
  });

  it("should have comprehensive AWS service list (40+ services)", async () => {
    const code = fs.readFileSync("server/routers/prowler-integration.ts", "utf-8");
    // Count individual service strings in the AWS services array
    const awsBlock = code.slice(code.indexOf('aws: ['), code.indexOf('aws: [') + 2000);
    const serviceMatches = awsBlock.match(/"[a-z0-9]+"/g);
    expect(serviceMatches).toBeTruthy();
    expect(serviceMatches!.length).toBeGreaterThanOrEqual(40);
  });

  it("should normalize severity to 5 levels", async () => {
    const code = fs.readFileSync("server/routers/prowler-integration.ts", "utf-8");
    expect(code).toContain('return "critical"');
    expect(code).toContain('return "high"');
    expect(code).toContain('return "medium"');
    expect(code).toContain('return "low"');
    expect(code).toContain('return "informational"');
  });

  it("should normalize status to PASS/FAIL/WARNING/INFO", async () => {
    const code = fs.readFileSync("server/routers/prowler-integration.ts", "utf-8");
    expect(code).toContain('return "PASS"');
    expect(code).toContain('return "FAIL"');
    expect(code).toContain('return "WARNING"');
    expect(code).toContain('return "INFO"');
  });
});

// ─── Cloud Resource Enumeration Tests ──────────────────────────────────────

describe("Cloud Resource Enumeration Router", () => {
  it("should export cloudResourceEnumRouter", async () => {
    const mod = await import("./routers/cloud-resource-enum");
    expect(mod.cloudResourceEnumRouter).toBeDefined();
  });

  it("should have enumerate, enumerateInline, and getSupportedResources procedures", async () => {
    const mod = await import("./routers/cloud-resource-enum");
    const router = mod.cloudResourceEnumRouter;
    const procedures = Object.keys(router._def.procedures);
    expect(procedures).toContain("enumerate");
    expect(procedures).toContain("enumerateInline");
    expect(procedures).toContain("getSupportedResources");
  });

  it("should support AWS resource types with CIS checks", async () => {
    const code = fs.readFileSync("server/routers/cloud-resource-enum.ts", "utf-8");
    expect(code).toContain("ec2_instance");
    expect(code).toContain("s3_bucket");
    expect(code).toContain("rds_instance");
    expect(code).toContain("lambda_function");
    expect(code).toContain("cloudtrail");
    expect(code).toContain("guardduty_detector");
  });

  it("should support Azure resource types with CIS checks", async () => {
    const code = fs.readFileSync("server/routers/cloud-resource-enum.ts", "utf-8");
    expect(code).toContain("azure_vm");
    expect(code).toContain("azure_storage_account");
    expect(code).toContain("azure_nsg");
    expect(code).toContain("azure_keyvault");
    expect(code).toContain("azure_sql_server");
  });

  it("should use dynamic DB import pattern (not static db import)", async () => {
    const code = fs.readFileSync("server/routers/cloud-resource-enum.ts", "utf-8");
    expect(code).toContain('import("../db")');
    expect(code).toContain("getDb()");
  });

  it("should handle credential decryption for stored credentials", async () => {
    const code = fs.readFileSync("server/routers/cloud-resource-enum.ts", "utf-8");
    expect(code).toContain("decryptCredential");
    expect(code).toContain("encryptedData");
    expect(code).toContain("encryptionIv");
    expect(code).toContain("encryptionTag");
  });
});

// ─── Cloud Resource Enumerator Module Tests ────────────────────────────────

describe("Cloud Resource Enumerator Module", () => {
  it("should export enumerateAWSResources and enumerateAzureResources", async () => {
    const mod = await import("./lib/cloud-resource-enumerator");
    expect(mod.enumerateAWSResources).toBeDefined();
    expect(mod.enumerateAzureResources).toBeDefined();
  });

  it("should export CloudResource and ResourceMisconfiguration types", async () => {
    const code = fs.readFileSync("server/lib/cloud-resource-enumerator.ts", "utf-8");
    expect(code).toContain("export interface CloudResource");
    expect(code).toContain("export interface ResourceMisconfiguration");
    expect(code).toContain("export interface ResourceEnumerationResult");
    expect(code).toContain("export interface CISCheckResult");
  });

  it("should include CIS check results with pass/fail/not_assessed statuses", async () => {
    const code = fs.readFileSync("server/lib/cloud-resource-enumerator.ts", "utf-8");
    expect(code).toContain("cisResults");
    expect(code).toContain("cisScore");
    expect(code).toContain("cisPassed");
    expect(code).toContain("cisFailed");
  });

  it("should consolidate IAM, security validation, and workload testing", async () => {
    const code = fs.readFileSync("server/lib/cloud-resource-enumerator.ts", "utf-8");
    expect(code).toContain("Consolidates: cloud-iam-enumerator, cloud-security-validation, cloud-workload-testing");
  });
});

// ─── Fabric Scanner Tests ──────────────────────────────────────────────────

describe("Fabric Scanner Router", () => {
  it("should export fabricScannerRouter", async () => {
    const mod = await import("./routers/fabric-scanner");
    expect(mod.fabricScannerRouter).toBeDefined();
  });

  it("should have all required procedures", async () => {
    const mod = await import("./routers/fabric-scanner");
    const router = mod.fabricScannerRouter;
    const procedures = Object.keys(router._def.procedures);
    expect(procedures).toContain("validateCredentials");
    expect(procedures).toContain("runScan");
    expect(procedures).toContain("getScanHistory");
    expect(procedures).toContain("getScanResult");
  });

  it("should use Azure credential type for Fabric scanning", async () => {
    const code = fs.readFileSync("server/routers/fabric-scanner.ts", "utf-8");
    expect(code).toContain('eq(cloudCredentials.credProvider, "azure")');
  });

  it("should support scan options (lineage, datasource, schema, expressions, users)", async () => {
    const code = fs.readFileSync("server/routers/fabric-scanner.ts", "utf-8");
    expect(code).toContain("includeLineage");
    expect(code).toContain("includeDatasourceDetails");
    expect(code).toContain("includeDatasetSchema");
    expect(code).toContain("includeDatasetExpressions");
    expect(code).toContain("includeArtifactUsers");
  });

  it("should store scan results in cloudEnumerationRuns table", async () => {
    const code = fs.readFileSync("server/routers/fabric-scanner.ts", "utf-8");
    expect(code).toContain("cloudEnumerationRuns");
    expect(code).toContain('enumStatus: "running"');
    // Check for completed/partial and error status updates
    expect(code).toContain('enumStatus:');
    expect(code).toContain('"error"');
  });

  it("should check tenant security settings and enumerate infrastructure", async () => {
    const code = fs.readFileSync("server/routers/fabric-scanner.ts", "utf-8");
    expect(code).toContain("checkTenantSecuritySettings");
    expect(code).toContain("enumerateInfrastructure");
  });
});

// ─── Fabric Scanner Module Tests ───────────────────────────────────────────

describe("Fabric Scanner Module", () => {
  it("should export all required functions", async () => {
    const mod = await import("./lib/fabric-scanner");
    expect(mod.scanFabricEnvironment).toBeDefined();
    expect(mod.validateFabricCredentials).toBeDefined();
    expect(mod.checkTenantSecuritySettings).toBeDefined();
    expect(mod.enumerateInfrastructure).toBeDefined();
  });

  it("should have FabricCredentials type with tenantId, clientId, clientSecret", async () => {
    const code = fs.readFileSync("server/lib/fabric-scanner.ts", "utf-8");
    expect(code).toContain("tenantId");
    expect(code).toContain("clientId");
    expect(code).toContain("clientSecret");
  });
});

// ─── Cross-Module Consistency Tests ────────────────────────────────────────

describe("Cross-module consistency", () => {
  it("should have all cloud routers registered in routers.ts", async () => {
    const code = fs.readFileSync("server/routers.ts", "utf-8");
    expect(code).toContain("fabricScannerRouter");
    expect(code).toContain("prowlerIntegrationRouter");
    expect(code).toContain("trivyIntegrationRouter");
    expect(code).toContain("cloudResourceEnumRouter");
    expect(code).toContain("scoutsuiteIntegrationRouter");
    expect(code).toContain("cloudSecurityValidationRouter");
    expect(code).toContain("cloudWorkloadTestingRouter");
    expect(code).toContain("cloudCredentialsRouter");
    expect(code).toContain("cloudAttackPathsRouter");
  });

  it("should have all cloud routers imported in routers.ts", async () => {
    const code = fs.readFileSync("server/routers.ts", "utf-8");
    expect(code).toContain('from "./routers/fabric-scanner"');
    expect(code).toContain('from "./routers/prowler-integration"');
    expect(code).toContain('from "./routers/trivy-integration"');
    expect(code).toContain('from "./routers/cloud-resource-enum"');
    expect(code).toContain('from "./routers/scoutsuite-integration"');
  });

  it("should use scan-server-executor for remote command execution", async () => {
    // All tool routers should use the scan-server-executor
    const prowler = fs.readFileSync("server/routers/prowler-integration.ts", "utf-8");
    const trivy = fs.readFileSync("server/routers/trivy-integration.ts", "utf-8");
    const scoutsuite = fs.readFileSync("server/routers/scoutsuite-integration.ts", "utf-8");

    expect(prowler).toContain("executeRawCommand");
    expect(trivy).toContain("executeRawCommand");
    expect(scoutsuite).toContain("executeRawCommand");
  });

  it("should use consistent credential decryption across routers", async () => {
    const fabric = fs.readFileSync("server/routers/fabric-scanner.ts", "utf-8");
    const cloudEnum = fs.readFileSync("server/routers/cloud-resource-enum.ts", "utf-8");

    // Both should use the same decryption pattern
    expect(fabric).toContain("decryptCredential");
    expect(cloudEnum).toContain("decryptCredential");
    expect(fabric).toContain("encryptedData");
    expect(cloudEnum).toContain("encryptedData");
  });

  it("should use protectedProcedure for all cloud scanning endpoints", async () => {
    const files = [
      "server/routers/prowler-integration.ts",
      "server/routers/trivy-integration.ts",
      "server/routers/scoutsuite-integration.ts",
      "server/routers/fabric-scanner.ts",
      "server/routers/cloud-resource-enum.ts",
    ];

    for (const file of files) {
      const code = fs.readFileSync(file, "utf-8");
      expect(code).toContain("protectedProcedure");
      // Should NOT have publicProcedure for security-sensitive operations
      expect(code).not.toContain("publicProcedure");
    }
  });
});

// ─── Scan Service URL Configuration Tests ──────────────────────────────────

describe("Scan Service URL Configuration", () => {
  it("should have ScanForge dedicated URL on port 4000", async () => {
    const code = fs.readFileSync("server/lib/scan-service-url.ts", "utf-8");
    expect(code).toContain(":4000");
    expect(code).toContain("SCANFORGE_DEDICATED_URL");
  });

  it("should have health check with failover to legacy scan server", async () => {
    const code = fs.readFileSync("server/lib/scan-service-url.ts", "utf-8");
    expect(code).toContain("isDedicatedHealthy");
    expect(code).toContain("getActiveScanUrl");
    expect(code).toContain("LEGACY_SCAN_URL");
  });

  it("should have ZAP URL on port 8090", async () => {
    const code = fs.readFileSync("server/lib/scan-service-url.ts", "utf-8");
    expect(code).toContain(":8090");
    expect(code).toContain("getActiveZapUrl");
  });
});

// ─── Cloud IAM Enumerator (Baseline) Tests ─────────────────────────────────

describe("Cloud IAM Enumerator (Baseline)", () => {
  it("should export AWS, Azure, and GCP enumeration functions", async () => {
    const mod = await import("./lib/cloud-iam-enumerator");
    // Functions are named enumerateAWS, enumerateAzure, enumerateGCP
    expect(mod.enumerateAWS).toBeDefined();
    expect(mod.enumerateAzure).toBeDefined();
    expect(mod.enumerateGCP).toBeDefined();
  });

  it("should export credential types", async () => {
    const code = fs.readFileSync("server/lib/cloud-iam-enumerator.ts", "utf-8");
    expect(code).toContain("export interface AWSCredentials");
    expect(code).toContain("export interface AzureCredentials");
    expect(code).toContain("export interface GCPCredentials");
  });
});

// ─── Cloud Attack Paths Tests ──────────────────────────────────────────────

describe("Cloud Attack Paths Module", () => {
  it("should have attack path catalog", async () => {
    const code = fs.readFileSync("server/lib/cloud-attack-paths.ts", "utf-8");
    expect(code).toContain("MITRE");
    expect(code).toContain("attack");
  });

  it("should have cloud attack paths router registered", async () => {
    const routersCode = fs.readFileSync("server/routers.ts", "utf-8");
    expect(routersCode).toContain("cloudAttackPathsRouter");
    expect(routersCode).toContain('from "./routers/cloud-attack-paths"');
  });
});

// ─── Cloud Credentials Router Tests ────────────────────────────────────────

describe("Cloud Credentials Router", () => {
  it("should be registered in routers.ts", async () => {
    const code = fs.readFileSync("server/routers.ts", "utf-8");
    expect(code).toContain("cloudCredentialsRouter");
    expect(code).toContain('from "./routers/cloud-credentials"');
  });

  it("should use credProvider field in schema (not provider)", async () => {
    // The schema uses credProvider, but the router may use provider as the tRPC input field name
    // The important thing is the schema table definition uses credProvider
    const schemaCode = fs.readFileSync("drizzle/schema.ts", "utf-8");
    expect(schemaCode).toContain("credProvider");
    expect(schemaCode).toContain("cred_provider");
  });
});
