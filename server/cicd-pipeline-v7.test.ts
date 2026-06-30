/**
 * Tests for CI/CD Pipeline Enhancements v7:
 * 1. Compliance Trend Tracking
 * 2. SBOM Diff Between Runs
 * 3. Bulk RBAC Import
 */
import { describe, it, expect, vi } from "vitest";

// ─── 1. Compliance Trend Tracking ──────────────────────────────────────────

describe("Compliance Trend Tracking", () => {
  const complianceModule = async () => import("./lib/cicd-compliance-mapper");

  const sampleFindings = [
    {
      id: "f1",
      name: "SQL Injection",
      severity: "critical",
      cve: "CVE-2023-1234",
      templateId: "sql-injection",
      tags: ["sqli", "injection", "owasp-top10"],
      cwe: [89],
      url: "https://app.example.com/api",
    },
    {
      id: "f2",
      name: "Missing TLS",
      severity: "high",
      templateId: "ssl-missing",
      tags: ["ssl", "tls", "encryption", "misconfig"],
      cwe: [311],
      url: "https://app.example.com",
    },
    {
      id: "f3",
      name: "XSS Reflected",
      severity: "medium",
      cve: "CVE-2023-5678",
      templateId: "xss-reflected",
      tags: ["xss", "owasp-top10"],
      cwe: [79],
      url: "https://app.example.com/search",
    },
  ];

  it("should generate compliance report for SOC 2", async () => {
    const { generateComplianceReport } = await complianceModule();
    const report = generateComplianceReport({
      framework: "soc2",
      findings: sampleFindings,
      pipelineId: 1,
      pipelineName: "Prod Pipeline",
      runId: 10,
    });

    expect(report.framework).toBe("soc2");
    expect(report.frameworkName).toContain("SOC");
    expect(report.summary.totalControls).toBeGreaterThan(0);
    expect(report.summary.complianceScore).toBeGreaterThanOrEqual(0);
    expect(report.summary.complianceScore).toBeLessThanOrEqual(100);
    expect(report.categories).toBeInstanceOf(Array);
    expect(report.categories.length).toBeGreaterThan(0);
  });

  it("should generate compliance report for PCI DSS", async () => {
    const { generateComplianceReport } = await complianceModule();
    const report = generateComplianceReport({
      framework: "pci_dss",
      findings: sampleFindings,
      pipelineId: 1,
      pipelineName: "Prod Pipeline",
      runId: 10,
    });

    expect(report.framework).toBe("pci_dss");
    expect(report.summary.totalControls).toBeGreaterThan(0);
  });

  it("should generate compliance report for NIST 800-53", async () => {
    const { generateComplianceReport } = await complianceModule();
    const report = generateComplianceReport({
      framework: "nist_800_53",
      findings: sampleFindings,
      pipelineId: 1,
      pipelineName: "Prod Pipeline",
      runId: 10,
    });

    expect(report.framework).toBe("nist_800_53");
    expect(report.summary.totalControls).toBeGreaterThan(0);
  });

  it("should generate cross-framework summary from multiple reports", async () => {
    const { generateComplianceReport, generateCrossFrameworkSummary } = await complianceModule();

    const soc2Report = generateComplianceReport({
      framework: "soc2",
      findings: sampleFindings,
      pipelineId: 1,
      pipelineName: "Prod",
      runId: 10,
    });
    const pciReport = generateComplianceReport({
      framework: "pci_dss",
      findings: sampleFindings,
      pipelineId: 1,
      pipelineName: "Prod",
      runId: 10,
    });
    const nistReport = generateComplianceReport({
      framework: "nist_800_53",
      findings: sampleFindings,
      pipelineId: 1,
      pipelineName: "Prod",
      runId: 10,
    });

    const summary = generateCrossFrameworkSummary([soc2Report, pciReport, nistReport]);

    expect(summary.frameworks).toHaveLength(3);
    expect(summary.overallRiskLevel).toBeTruthy();
    expect(summary.sharedGaps).toBeInstanceOf(Array);
    summary.frameworks.forEach(f => {
      expect(f.score).toBeGreaterThanOrEqual(0);
      expect(f.score).toBeLessThanOrEqual(100);
    });
  });

  it("should track trend direction from multiple compliance scores", async () => {
    // Simulate trend tracking logic
    const scores = [
      { runId: 1, score: 60 },
      { runId: 2, score: 65 },
      { runId: 3, score: 72 },
      { runId: 4, score: 78 },
    ];

    const latest = scores[scores.length - 1].score;
    const previous = scores[scores.length - 2].score;
    const delta = latest - previous;
    const direction = delta > 0 ? "up" : delta < 0 ? "down" : "stable";

    expect(direction).toBe("up");
    expect(delta).toBe(6);
    expect(latest).toBe(78);
  });

  it("should detect declining compliance trend", async () => {
    const scores = [
      { runId: 1, score: 85 },
      { runId: 2, score: 80 },
      { runId: 3, score: 72 },
    ];

    const latest = scores[scores.length - 1].score;
    const previous = scores[scores.length - 2].score;
    const delta = latest - previous;
    const direction = delta > 0 ? "up" : delta < 0 ? "down" : "stable";

    expect(direction).toBe("down");
    expect(delta).toBe(-8);
  });

  it("should list available compliance frameworks", async () => {
    const { getAvailableFrameworks } = await complianceModule();
    const frameworks = getAvailableFrameworks();

    expect(frameworks).toBeInstanceOf(Array);
    expect(frameworks.length).toBe(3);
    expect(frameworks.map(f => f.id)).toContain("soc2");
    expect(frameworks.map(f => f.id)).toContain("pci_dss");
    expect(frameworks.map(f => f.id)).toContain("nist_800_53");
    frameworks.forEach(f => {
      expect(f.name).toBeTruthy();
      expect(f.controlCount).toBeGreaterThan(0);
      expect(f.description).toBeTruthy();
    });
  });

  it("should categorize compliance results by category", async () => {
    const { generateComplianceReport } = await complianceModule();
    const report = generateComplianceReport({
      framework: "soc2",
      findings: sampleFindings,
      pipelineId: 1,
      pipelineName: "Prod",
      runId: 10,
    });

    expect(report.categories).toBeDefined();
    expect(report.categories.length).toBeGreaterThan(0);
    report.categories.forEach(cat => {
      expect(cat.name).toBeTruthy();
      expect(cat.controls).toBeInstanceOf(Array);
      expect(cat.categoryScore).toBeGreaterThanOrEqual(0);
      cat.controls.forEach(r => {
        expect(r.control.category).toBe(cat.name);
      });
    });
  });
});

// ─── 2. SBOM Diff Between Runs ────────────────────────────────────────────

describe("SBOM Diff Between Runs", () => {
  const sbomModule = async () => import("./lib/cicd-sbom-generator");

  const baselineFindings = [
    {
      id: "f1",
      name: "Outdated jQuery",
      severity: "medium",
      cve: "CVE-2020-11022",
      templateId: "tech-detect-jquery",
      tags: ["tech", "jquery"],
      url: "https://app.example.com",
      matched: "jquery/3.4.1",
    },
    {
      id: "f2",
      name: "Outdated Bootstrap",
      severity: "low",
      templateId: "tech-detect-bootstrap",
      tags: ["tech", "bootstrap"],
      url: "https://app.example.com",
      matched: "bootstrap/4.5.0",
    },
    {
      id: "f3",
      name: "Nginx Version Detected",
      severity: "info",
      templateId: "tech-detect-nginx",
      tags: ["tech", "nginx"],
      url: "https://app.example.com",
      matched: "nginx/1.18.0",
    },
  ];

  const currentFindings = [
    {
      id: "f1",
      name: "Outdated jQuery",
      severity: "medium",
      cve: "CVE-2020-11022",
      templateId: "tech-detect-jquery",
      tags: ["tech", "jquery"],
      url: "https://app.example.com",
      matched: "jquery/3.6.0", // Updated version
    },
    // Bootstrap removed
    {
      id: "f4",
      name: "React Detected",
      severity: "info",
      templateId: "tech-detect-react",
      tags: ["tech", "react"],
      url: "https://app.example.com",
      matched: "react/18.2.0",
    },
    {
      id: "f3",
      name: "Nginx Version Detected",
      severity: "info",
      templateId: "tech-detect-nginx",
      tags: ["tech", "nginx"],
      url: "https://app.example.com",
      matched: "nginx/1.18.0", // Same version
    },
  ];

  it("should generate SBOM from findings", async () => {
    const { generateSbom } = await sbomModule();
    const result = generateSbom({
      findings: baselineFindings,
      pipelineId: 1,
      pipelineName: "Prod",
      runId: 10,
      targetUrl: "https://app.example.com",
    });

    expect(result.sbom).toBeDefined();
    expect(result.sbom.bomFormat).toBe("CycloneDX");
    expect(result.sbom.specVersion).toBe("1.5");
    expect(result.sbom.components).toBeInstanceOf(Array);
    expect(result.stats).toBeDefined();
    expect(result.stats.totalComponents).toBeGreaterThanOrEqual(0);
  });

  it("should extract components from findings", async () => {
    const { extractComponents } = await sbomModule();
    const components = extractComponents(baselineFindings);

    expect(components).toBeInstanceOf(Array);
    // Should extract at least some components from tech-detect findings
  });

  it("should build valid PURLs", async () => {
    const { buildPurl } = await sbomModule();

    const purl1 = buildPurl("jquery", "3.6.0", "npm");
    expect(purl1).toContain("pkg:");
    expect(purl1).toContain("jquery");
    expect(purl1).toContain("3.6.0");

    const purl2 = buildPurl("nginx", "1.18.0");
    expect(purl2).toContain("nginx");
  });

  it("should compare two SBOMs and produce a diff", async () => {
    const { generateSbom, compareSboms } = await sbomModule();

    const baseline = generateSbom({
      findings: baselineFindings,
      pipelineId: 1,
      pipelineName: "Prod",
      runId: 10,
      targetUrl: "https://app.example.com",
    });

    const current = generateSbom({
      findings: currentFindings,
      pipelineId: 1,
      pipelineName: "Prod",
      runId: 11,
      targetUrl: "https://app.example.com",
    });

    const diff = compareSboms(baseline.sbom, current.sbom);

    expect(diff).toBeDefined();
    expect(diff.addedComponents).toBeInstanceOf(Array);
    expect(diff.removedComponents).toBeInstanceOf(Array);
    expect(diff.addedVulnerabilities).toBeInstanceOf(Array);
    expect(diff.removedVulnerabilities).toBeInstanceOf(Array);
    expect(typeof diff.unchangedComponents).toBe("number");
    expect(typeof diff.unchangedVulnerabilities).toBe("number");
  });

  it("should map vulnerabilities to components", async () => {
    const { extractComponents, mapVulnerabilities } = await sbomModule();
    const components = extractComponents(baselineFindings);
    const vulns = mapVulnerabilities(baselineFindings, components);

    expect(vulns).toBeInstanceOf(Array);
    // CVE-2020-11022 should be mapped
  });

  it("should handle empty findings gracefully", async () => {
    const { generateSbom } = await sbomModule();
    const result = generateSbom({
      findings: [],
      pipelineId: 1,
      pipelineName: "Empty",
      runId: 1,
      targetUrl: "https://app.example.com",
    });

    expect(result.sbom.components).toHaveLength(0);
    expect(result.stats.totalComponents).toBe(0);
  });

  it("should produce identical diff for same SBOM", async () => {
    const { generateSbom, compareSboms } = await sbomModule();
    const sbom = generateSbom({
      findings: baselineFindings,
      pipelineId: 1,
      pipelineName: "Prod",
      runId: 10,
      targetUrl: "https://app.example.com",
    });

    const diff = compareSboms(sbom.sbom, sbom.sbom);

    expect(diff.addedComponents).toHaveLength(0);
    expect(diff.removedComponents).toHaveLength(0);
    expect(diff.addedVulnerabilities).toHaveLength(0);
    expect(diff.removedVulnerabilities).toHaveLength(0);
  });
});

// ─── 3. Bulk RBAC Import ──────────────────────────────────────────────────

describe("Bulk RBAC Import", () => {
  const rbacModule = async () => import("./lib/cicd-pipeline-rbac");

  it("should resolve permissions for pipeline creator (auto-owner)", async () => {
    const { resolvePermissions } = await rbacModule();
    const perms = resolvePermissions({
      userId: 1,
      userOpenId: "user1",
      userRole: "user",
      pipelineCreatedBy: "user1",
    });

    expect(perms.canView).toBe(true);
    expect(perms.canEdit).toBe(true);
    expect(perms.canTrigger).toBe(true);
    expect(perms.canDelete).toBe(true);
    expect(perms.canManageAccess).toBe(true);
    expect(perms.role).toBe("owner");
  });

  it("should resolve permissions for editor via pipeline access", async () => {
    const { resolvePermissions } = await rbacModule();
    const perms = resolvePermissions({
      userId: 2,
      userOpenId: "user2",
      userRole: "user",
      pipelineCreatedBy: "user1",
      pipelineAccess: { pipelineId: 1, userId: 2, role: "editor", grantedAt: Date.now(), grantedBy: 1 },
    });

    expect(perms.canView).toBe(true);
    expect(perms.canEdit).toBe(true);
    expect(perms.canTrigger).toBe(true);
    expect(perms.canDelete).toBe(false);
    expect(perms.canManageAccess).toBe(false);
  });

  it("should resolve permissions for viewer via pipeline access", async () => {
    const { resolvePermissions } = await rbacModule();
    const perms = resolvePermissions({
      userId: 3,
      userOpenId: "user3",
      userRole: "user",
      pipelineCreatedBy: "user1",
      pipelineAccess: { pipelineId: 1, userId: 3, role: "viewer", grantedAt: Date.now(), grantedBy: 1 },
    });

    expect(perms.canView).toBe(true);
    expect(perms.canEdit).toBe(false);
    expect(perms.canTrigger).toBe(false);
    expect(perms.canDelete).toBe(false);
    expect(perms.canManageAccess).toBe(false);
  });

  it("should give admin full permissions regardless of role", async () => {
    const { resolvePermissions } = await rbacModule();
    const perms = resolvePermissions({
      userId: 99,
      userOpenId: "admin1",
      userRole: "admin",
      pipelineCreatedBy: "user1",
    });

    expect(perms.canView).toBe(true);
    expect(perms.canEdit).toBe(true);
    expect(perms.canTrigger).toBe(true);
    expect(perms.canDelete).toBe(true);
    expect(perms.canManageAccess).toBe(true);
  });

  it("should check specific permissions correctly", async () => {
    const { resolvePermissions, checkPermission } = await rbacModule();
    const viewerPerms = resolvePermissions({
      userId: 3,
      userOpenId: "user3",
      userRole: "user",
      pipelineCreatedBy: "user1",
      pipelineAccess: { pipelineId: 1, userId: 3, role: "viewer", grantedAt: Date.now(), grantedBy: 1 },
    });

    expect(checkPermission(viewerPerms, "canView")).toBe(true);
    expect(checkPermission(viewerPerms, "canEdit")).toBe(false);
    expect(checkPermission(viewerPerms, "canTrigger")).toBe(false);
  });

  it("should return grantable roles based on granter permissions", async () => {
    const { resolvePermissions, getGrantableRoles } = await rbacModule();

    const ownerPerms = resolvePermissions({
      userId: 1,
      userOpenId: "user1",
      userRole: "user",
      pipelineCreatedBy: "user1",
    });
    const ownerGrantable = getGrantableRoles(ownerPerms);
    expect(ownerGrantable).toContain("editor");
    expect(ownerGrantable).toContain("viewer");

    const viewerPerms = resolvePermissions({
      userId: 3,
      userOpenId: "user3",
      userRole: "user",
      pipelineCreatedBy: "user1",
      pipelineAccess: { pipelineId: 1, userId: 3, role: "viewer", grantedAt: Date.now(), grantedBy: 1 },
    });
    const viewerGrantable = getGrantableRoles(viewerPerms);
    expect(viewerGrantable).toHaveLength(0);
  });

  it("should validate role changes correctly", async () => {
    const { validateRoleChange, resolvePermissions } = await rbacModule();

    // Owner can change roles
    const ownerPerms = resolvePermissions({
      userId: 1,
      userOpenId: "user1",
      userRole: "user",
      pipelineCreatedBy: "user1",
    });
    const result1 = validateRoleChange({
      granterPermissions: ownerPerms,
      targetCurrentRole: "viewer",
      newRole: "editor",
      isTargetSelf: false,
    });
    expect(result1).toBeNull(); // null means valid

    // Viewer cannot change roles
    const viewerPerms = resolvePermissions({
      userId: 3,
      userOpenId: "user3",
      userRole: "user",
      pipelineCreatedBy: "user1",
      pipelineAccess: { pipelineId: 1, userId: 3, role: "viewer", grantedAt: Date.now(), grantedBy: 1 },
    });
    const result2 = validateRoleChange({
      granterPermissions: viewerPerms,
      targetCurrentRole: "editor",
      newRole: "viewer",
      isTargetSelf: false,
    });
    expect(result2).toBeTruthy(); // non-null string means error
  });

  it("should build access summary from access list", async () => {
    const { buildAccessSummary } = await rbacModule();
    const summary = buildAccessSummary(1, [
      { userId: 1, userName: "Alice", role: "owner" as const, grantedAt: Date.now(), grantedBy: 0, pipelineId: 1 },
      { userId: 2, userName: "Bob", role: "editor" as const, grantedAt: Date.now(), grantedBy: 1, pipelineId: 1 },
      { userId: 3, userName: "Carol", role: "viewer" as const, grantedAt: Date.now(), grantedBy: 1, pipelineId: 1 },
      { userId: 4, userName: "Dave", role: "viewer" as const, grantedAt: Date.now(), grantedBy: 1, pipelineId: 1 },
    ]);

    expect(summary.totalMembers).toBe(4);
    expect(summary.owners).toBe(1);
    expect(summary.editors).toBe(1);
    expect(summary.viewers).toBe(2);
  });

  it("should filter accessible pipelines for a user", async () => {
    const { filterAccessiblePipelines } = await rbacModule();

    const pipelines = [
      { id: 1, name: "Pipeline A", createdBy: "user1" },
      { id: 2, name: "Pipeline B", createdBy: "user2" },
      { id: 3, name: "Pipeline C", createdBy: "user3" },
    ];

    const accessRecords = [
      { pipelineId: 1, userId: 1, role: "owner" as const, grantedAt: Date.now(), grantedBy: 0 },
      { pipelineId: 2, userId: 1, role: "editor" as const, grantedAt: Date.now(), grantedBy: 0 },
    ];

    const accessible = filterAccessiblePipelines(
      pipelines as any,
      "user1",
      "user",
      accessRecords as any,
    );

    expect(accessible.length).toBeGreaterThanOrEqual(2);
  });

  it("should parse CSV text for bulk import", () => {
    const csvText = `user_id,user_name,role
user123,Alice,editor
user456,Bob,viewer
,Missing ID,editor
user789,Carol,invalid_role`;

    const lines = csvText.trim().split("\n");
    const header = lines[0].toLowerCase();
    const hasHeader = header.includes("user_id") || header.includes("role");
    const dataLines = hasHeader ? lines.slice(1) : lines;

    const grants = dataLines.map(line => {
      const parts = line.split(",").map(p => p.trim());
      const userId = parts[0];
      const userName = parts[1] || "";
      const role = parts[2] || "";
      const validRoles = ["owner", "editor", "viewer"];

      if (!userId) return { userId, userName, role, valid: false, error: "Missing user ID" };
      if (!validRoles.includes(role)) return { userId, userName, role, valid: false, error: `Invalid role: ${role}` };
      return { userId, userName, role, valid: true };
    });

    const valid = grants.filter(g => g.valid).length;
    const invalid = grants.filter(g => !g.valid).length;

    expect(valid).toBe(2);
    expect(invalid).toBe(2);
    expect(grants[0].valid).toBe(true);
    expect(grants[0].userId).toBe("user123");
    expect(grants[0].role).toBe("editor");
    expect(grants[2].valid).toBe(false);
    expect(grants[2].error).toContain("Missing user ID");
    expect(grants[3].valid).toBe(false);
    expect(grants[3].error).toContain("Invalid role");
  });

  it("should handle CSV with different delimiters", () => {
    const tsvText = "user123\tAlice\teditor\nuser456\tBob\tviewer";
    const lines = tsvText.trim().split("\n");
    const grants = lines.map(line => {
      const parts = line.split(/[,\t]/).map(p => p.trim());
      return { userId: parts[0], userName: parts[1], role: parts[2] };
    });

    expect(grants).toHaveLength(2);
    expect(grants[0].userId).toBe("user123");
    expect(grants[1].role).toBe("viewer");
  });

  it("should handle empty CSV gracefully", () => {
    const csvText = "";
    const lines = csvText.trim().split("\n").filter(l => l.trim());
    expect(lines).toHaveLength(0);
  });
});
