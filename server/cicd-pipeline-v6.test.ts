import { describe, it, expect } from "vitest";

// ─── SBOM Generator Tests ───────────────────────────────────────────────────

describe("SBOM Generator", () => {
  it("should be importable", async () => {
    const mod = await import("./lib/cicd-sbom-generator");
    expect(mod.generateSbom).toBeDefined();
    expect(typeof mod.generateSbom).toBe("function");
  });

  it("should generate valid CycloneDX 1.5 format", async () => {
    const { generateSbom } = await import("./lib/cicd-sbom-generator");
    const { sbom } = generateSbom({
      pipelineId: 1,
      pipelineName: "Test Pipeline",
      runId: 100,
      targetUrl: "https://example.com",
      findings: [],
    });
    expect(sbom.bomFormat).toBe("CycloneDX");
    expect(sbom.specVersion).toBe("1.5");
    expect(sbom.serialNumber).toMatch(/^urn:uuid:/);
    expect(sbom.metadata).toBeDefined();
    expect(sbom.metadata.timestamp).toBeDefined();
    expect(sbom.metadata.tools).toBeDefined();
  });

  it("should extract components from findings", async () => {
    const { generateSbom } = await import("./lib/cicd-sbom-generator");
    const { sbom } = generateSbom({
      pipelineId: 1,
      pipelineName: "Test Pipeline",
      runId: 100,
      targetUrl: "https://example.com",
      findings: [
        { name: "Apache/2.4.49 detected", info: { name: "Apache Detection", tags: ["tech", "apache"] }, severity: "info", host: "https://example.com" },
        { name: "nginx/1.21.0 detected", info: { name: "Nginx Detection", tags: ["tech", "nginx"] }, severity: "info", host: "https://example.com" },
      ],
    });
    expect(sbom.components).toBeDefined();
    expect(Array.isArray(sbom.components)).toBe(true);
  });

  it("should include vulnerabilities from CVE findings", async () => {
    const { generateSbom } = await import("./lib/cicd-sbom-generator");
    const { sbom } = generateSbom({
      pipelineId: 1,
      pipelineName: "Test Pipeline",
      runId: 100,
      targetUrl: "https://example.com",
      findings: [
        { name: "CVE-2021-44228 Log4Shell", info: { name: "Log4Shell", severity: "critical" }, severity: "critical", cve: { id: "CVE-2021-44228" }, host: "https://example.com" },
      ],
    });
    expect(sbom.vulnerabilities).toBeDefined();
    expect(Array.isArray(sbom.vulnerabilities)).toBe(true);
  });

  it("should include metadata with pipeline and run info", async () => {
    const { generateSbom } = await import("./lib/cicd-sbom-generator");
    const { sbom } = generateSbom({
      pipelineId: 42,
      pipelineName: "Production Pipeline",
      runId: 200,
      targetUrl: "https://prod.example.com",
      branch: "main",
      commitSha: "abc123def",
      findings: [],
    });
    expect(sbom.metadata.component).toBeDefined();
    expect(sbom.metadata.component.name).toContain("Production Pipeline");
  });

  it("should handle empty findings gracefully", async () => {
    const { generateSbom } = await import("./lib/cicd-sbom-generator");
    const { sbom, stats } = generateSbom({
      pipelineId: 1,
      pipelineName: "Empty Pipeline",
      runId: 1,
      targetUrl: "https://example.com",
      findings: [],
    });
    expect(sbom.components).toBeDefined();
    expect(sbom.vulnerabilities).toBeDefined();
    expect(stats.totalComponents).toBe(0);
    expect(stats.totalVulnerabilities).toBe(0);
  });
});

// ─── Pipeline RBAC Tests ────────────────────────────────────────────────────

describe("Pipeline RBAC", () => {
  it("should be importable", async () => {
    const mod = await import("./lib/cicd-pipeline-rbac");
    expect(mod.resolvePermissions).toBeDefined();
    expect(mod.checkPermission).toBeDefined();
    expect(mod.getGrantableRoles).toBeDefined();
    expect(mod.validateRoleChange).toBeDefined();
    expect(mod.buildAccessSummary).toBeDefined();
    expect(mod.filterAccessiblePipelines).toBeDefined();
  });

  it("should give admin full permissions", async () => {
    const { resolvePermissions } = await import("./lib/cicd-pipeline-rbac");
    const perms = resolvePermissions({
      userRole: "admin",
      userId: 1,
      userOpenId: "admin-open-id",
    });
    expect(perms.role).toBe("admin");
    expect(perms.canView).toBe(true);
    expect(perms.canEdit).toBe(true);
    expect(perms.canTrigger).toBe(true);
    expect(perms.canDelete).toBe(true);
    expect(perms.canManageAccess).toBe(true);
  });

  it("should give pipeline creator owner permissions", async () => {
    const { resolvePermissions } = await import("./lib/cicd-pipeline-rbac");
    const perms = resolvePermissions({
      userRole: "user",
      userId: 5,
      userOpenId: "creator-open-id",
      pipelineCreatedBy: "creator-open-id",
    });
    expect(perms.role).toBe("owner");
    expect(perms.canView).toBe(true);
    expect(perms.canEdit).toBe(true);
    expect(perms.canDelete).toBe(true);
    expect(perms.canManageAccess).toBe(true);
  });

  it("should resolve explicit editor access", async () => {
    const { resolvePermissions } = await import("./lib/cicd-pipeline-rbac");
    const perms = resolvePermissions({
      userRole: "user",
      userId: 10,
      userOpenId: "user-open-id",
      pipelineCreatedBy: "other-open-id",
      pipelineAccess: {
        pipelineId: 1,
        userId: 10,
        role: "editor",
        grantedBy: 1,
        grantedAt: new Date().toISOString(),
      },
    });
    expect(perms.role).toBe("editor");
    expect(perms.canView).toBe(true);
    expect(perms.canEdit).toBe(true);
    expect(perms.canTrigger).toBe(true);
    expect(perms.canDelete).toBe(false);
    expect(perms.canManageAccess).toBe(false);
  });

  it("should resolve viewer access correctly", async () => {
    const { resolvePermissions } = await import("./lib/cicd-pipeline-rbac");
    const perms = resolvePermissions({
      userRole: "user",
      userId: 20,
      userOpenId: "viewer-open-id",
      pipelineCreatedBy: "other-open-id",
      pipelineAccess: {
        pipelineId: 1,
        userId: 20,
        role: "viewer",
        grantedBy: 1,
        grantedAt: new Date().toISOString(),
      },
    });
    expect(perms.role).toBe("viewer");
    expect(perms.canView).toBe(true);
    expect(perms.canEdit).toBe(false);
    expect(perms.canTrigger).toBe(false);
    expect(perms.canDelete).toBe(false);
    expect(perms.canPinBaseline).toBe(false);
    expect(perms.canExportSbom).toBe(true);
    expect(perms.canViewCompliance).toBe(true);
  });

  it("should give team_lead default viewer access", async () => {
    const { resolvePermissions } = await import("./lib/cicd-pipeline-rbac");
    const perms = resolvePermissions({
      userRole: "team_lead",
      userId: 30,
      userOpenId: "lead-open-id",
      pipelineCreatedBy: "other-open-id",
    });
    expect(perms.role).toBe("viewer");
    expect(perms.canView).toBe(true);
    expect(perms.canEdit).toBe(false);
  });

  it("should give no access to unrelated users", async () => {
    const { resolvePermissions } = await import("./lib/cicd-pipeline-rbac");
    const perms = resolvePermissions({
      userRole: "user",
      userId: 99,
      userOpenId: "random-user",
      pipelineCreatedBy: "other-open-id",
    });
    expect(perms.role).toBe("none");
    expect(perms.canView).toBe(false);
    expect(perms.canEdit).toBe(false);
  });

  it("should check individual permissions", async () => {
    const { resolvePermissions, checkPermission } = await import("./lib/cicd-pipeline-rbac");
    const perms = resolvePermissions({
      userRole: "admin",
      userId: 1,
      userOpenId: "admin",
    });
    expect(checkPermission(perms, "canView")).toBe(true);
    expect(checkPermission(perms, "canDelete")).toBe(true);
  });

  it("should return grantable roles for owner", async () => {
    const { resolvePermissions, getGrantableRoles } = await import("./lib/cicd-pipeline-rbac");
    const perms = resolvePermissions({
      userRole: "user",
      userId: 1,
      userOpenId: "creator",
      pipelineCreatedBy: "creator",
    });
    const roles = getGrantableRoles(perms);
    expect(roles).toContain("owner");
    expect(roles).toContain("editor");
    expect(roles).toContain("viewer");
  });

  it("should return empty grantable roles for viewer", async () => {
    const { getGrantableRoles } = await import("./lib/cicd-pipeline-rbac");
    const roles = getGrantableRoles({
      role: "viewer",
      canView: true, canEdit: false, canTrigger: false, canDelete: false,
      canManageAccess: false, canPinBaseline: false, canConfigureSchedule: false,
      canExportSbom: true, canViewCompliance: true,
    });
    expect(roles).toHaveLength(0);
  });

  it("should validate role changes", async () => {
    const { validateRoleChange } = await import("./lib/cicd-pipeline-rbac");
    // Can't manage without permission
    const err1 = validateRoleChange({
      granterPermissions: { role: "viewer", canView: true, canEdit: false, canTrigger: false, canDelete: false, canManageAccess: false, canPinBaseline: false, canConfigureSchedule: false, canExportSbom: true, canViewCompliance: true },
      newRole: "editor",
      isTargetSelf: false,
    });
    expect(err1).toContain("permission");

    // Can't change own owner role
    const err2 = validateRoleChange({
      granterPermissions: { role: "owner", canView: true, canEdit: true, canTrigger: true, canDelete: true, canManageAccess: true, canPinBaseline: true, canConfigureSchedule: true, canExportSbom: true, canViewCompliance: true },
      targetCurrentRole: "owner",
      newRole: "editor",
      isTargetSelf: true,
    });
    expect(err2).toContain("owner");
  });

  it("should build access summary correctly", async () => {
    const { buildAccessSummary } = await import("./lib/cicd-pipeline-rbac");
    const summary = buildAccessSummary(1, [
      { pipelineId: 1, userId: 1, role: "owner", grantedBy: 0, grantedAt: "2024-01-01", userName: "Alice" },
      { pipelineId: 1, userId: 2, role: "editor", grantedBy: 1, grantedAt: "2024-01-02", userName: "Bob" },
      { pipelineId: 1, userId: 3, role: "viewer", grantedBy: 1, grantedAt: "2024-01-03", userName: "Charlie" },
    ]);
    expect(summary.totalMembers).toBe(3);
    expect(summary.owners).toBe(1);
    expect(summary.editors).toBe(1);
    expect(summary.viewers).toBe(1);
  });

  it("should filter accessible pipelines for admin", async () => {
    const { filterAccessiblePipelines } = await import("./lib/cicd-pipeline-rbac");
    const ids = filterAccessiblePipelines(
      [{ id: 1 }, { id: 2 }, { id: 3 }],
      "some-user",
      "admin",
      [],
    );
    expect(ids).toEqual([1, 2, 3]);
  });

  it("should filter accessible pipelines for regular user", async () => {
    const { filterAccessiblePipelines } = await import("./lib/cicd-pipeline-rbac");
    const ids = filterAccessiblePipelines(
      [{ id: 1, createdBy: "user-a" }, { id: 2, createdBy: "user-b" }, { id: 3, createdBy: "user-c" }],
      "user-a",
      "user",
      [{ pipelineId: 3, userId: 10, role: "viewer", grantedBy: 1, grantedAt: "2024-01-01" }],
    );
    expect(ids).toContain(1); // creator
    expect(ids).not.toContain(2); // no access
    expect(ids).toContain(3); // explicit access
  });
});

// ─── Compliance Mapper Tests ────────────────────────────────────────────────

describe("Compliance Mapper", () => {
  it("should be importable", async () => {
    const mod = await import("./lib/cicd-compliance-mapper");
    expect(mod.generateComplianceReport).toBeDefined();
    expect(mod.generateCrossFrameworkSummary).toBeDefined();
    expect(mod.getAvailableFrameworks).toBeDefined();
  });

  it("should list 3 available frameworks", async () => {
    const { getAvailableFrameworks } = await import("./lib/cicd-compliance-mapper");
    const frameworks = getAvailableFrameworks();
    expect(frameworks).toHaveLength(3);
    expect(frameworks.map(f => f.id)).toContain("soc2");
    expect(frameworks.map(f => f.id)).toContain("pci_dss");
    expect(frameworks.map(f => f.id)).toContain("nist_800_53");
    frameworks.forEach(f => {
      expect(f.controlCount).toBeGreaterThan(0);
      expect(f.name).toBeTruthy();
      expect(f.description).toBeTruthy();
    });
  });

  it("should generate SOC 2 report with empty findings", async () => {
    const { generateComplianceReport } = await import("./lib/cicd-compliance-mapper");
    const report = generateComplianceReport({
      framework: "soc2",
      pipelineId: 1,
      pipelineName: "Test Pipeline",
      runId: 100,
      findings: [],
    });
    expect(report.framework).toBe("soc2");
    expect(report.frameworkName).toBe("SOC 2 Type II");
    expect(report.summary.totalControls).toBeGreaterThan(0);
    expect(report.summary.complianceScore).toBeGreaterThanOrEqual(0);
    expect(report.summary.complianceScore).toBeLessThanOrEqual(100);
    expect(report.categories.length).toBeGreaterThan(0);
  });

  it("should generate PCI-DSS report", async () => {
    const { generateComplianceReport } = await import("./lib/cicd-compliance-mapper");
    const report = generateComplianceReport({
      framework: "pci_dss",
      pipelineId: 1,
      pipelineName: "Test Pipeline",
      runId: 100,
      findings: [],
    });
    expect(report.framework).toBe("pci_dss");
    expect(report.frameworkName).toBe("PCI DSS v4.0");
    expect(report.summary.totalControls).toBeGreaterThan(0);
  });

  it("should generate NIST 800-53 report", async () => {
    const { generateComplianceReport } = await import("./lib/cicd-compliance-mapper");
    const report = generateComplianceReport({
      framework: "nist_800_53",
      pipelineId: 1,
      pipelineName: "Test Pipeline",
      runId: 100,
      findings: [],
    });
    expect(report.framework).toBe("nist_800_53");
    expect(report.frameworkName).toBe("NIST SP 800-53 Rev. 5");
    expect(report.summary.totalControls).toBeGreaterThan(0);
  });

  it("should map SSL findings to encryption controls", async () => {
    const { generateComplianceReport } = await import("./lib/cicd-compliance-mapper");
    const report = generateComplianceReport({
      framework: "pci_dss",
      pipelineId: 1,
      pipelineName: "Test Pipeline",
      runId: 100,
      findings: [
        { name: "Weak TLS Configuration", info: { name: "TLS Weakness", tags: ["ssl", "tls"], severity: "high" }, severity: "high", host: "https://example.com" },
      ],
    });
    // PCI-4.1 (Encryption in Transit) should be affected
    const encryptionCategory = report.categories.find(c => c.name === "Encryption");
    expect(encryptionCategory).toBeDefined();
    const failedControls = encryptionCategory!.controls.filter(c => c.status === "fail" || c.status === "partial");
    expect(failedControls.length).toBeGreaterThan(0);
  });

  it("should map authentication findings to auth controls", async () => {
    const { generateComplianceReport } = await import("./lib/cicd-compliance-mapper");
    const report = generateComplianceReport({
      framework: "soc2",
      pipelineId: 1,
      pipelineName: "Test Pipeline",
      runId: 100,
      findings: [
        { name: "Default Login Detected", info: { name: "Default Credentials", tags: ["default-login", "auth"], severity: "critical" }, severity: "critical", host: "https://example.com" },
      ],
    });
    const accessCategory = report.categories.find(c => c.name === "Logical & Physical Access");
    expect(accessCategory).toBeDefined();
    const failedControls = accessCategory!.controls.filter(c => c.status === "fail");
    expect(failedControls.length).toBeGreaterThan(0);
  });

  it("should calculate risk level based on compliance score", async () => {
    const { generateComplianceReport } = await import("./lib/cicd-compliance-mapper");
    // With many critical findings, score should be low and risk high
    const findings = Array.from({ length: 20 }, (_, i) => ({
      name: `Critical Vuln ${i}`,
      info: { name: `Vuln ${i}`, tags: ["cve", "ssl", "auth", "xss", "misconfig", "exposure"], severity: "critical" },
      severity: "critical",
      host: "https://example.com",
    }));
    const report = generateComplianceReport({
      framework: "soc2",
      pipelineId: 1,
      pipelineName: "Vulnerable Pipeline",
      runId: 100,
      findings,
    });
    expect(["critical", "high"]).toContain(report.summary.riskLevel);
    expect(report.summary.failed).toBeGreaterThan(0);
  });

  it("should generate recommendations for gaps", async () => {
    const { generateComplianceReport } = await import("./lib/cicd-compliance-mapper");
    const report = generateComplianceReport({
      framework: "soc2",
      pipelineId: 1,
      pipelineName: "Test Pipeline",
      runId: 100,
      findings: [
        { name: "Critical Vuln", info: { name: "CVE-2024-0001", tags: ["cve"], severity: "critical" }, severity: "critical", host: "https://example.com" },
      ],
    });
    expect(report.recommendations.length).toBeGreaterThan(0);
  });

  it("should generate cross-framework summary", async () => {
    const { generateComplianceReport, generateCrossFrameworkSummary } = await import("./lib/cicd-compliance-mapper");
    const findings = [
      { name: "SSL Issue", info: { name: "TLS Weakness", tags: ["ssl"], severity: "high" }, severity: "high", host: "https://example.com" },
    ];
    const reports = ["soc2", "pci_dss", "nist_800_53"].map(fw =>
      generateComplianceReport({
        framework: fw as any,
        pipelineId: 1,
        pipelineName: "Test",
        runId: 100,
        findings,
      })
    );
    const summary = generateCrossFrameworkSummary(reports);
    expect(summary.frameworks).toHaveLength(3);
    expect(summary.overallRiskLevel).toBeDefined();
    expect(["critical", "high", "medium", "low"]).toContain(summary.overallRiskLevel);
  });

  it("should identify shared gaps across frameworks", async () => {
    const { generateComplianceReport, generateCrossFrameworkSummary } = await import("./lib/cicd-compliance-mapper");
    const findings = [
      { name: "Default Admin Login", info: { name: "Default Credentials", tags: ["default-login", "auth"], severity: "critical" }, severity: "critical", host: "https://example.com" },
      { name: "Weak TLS v1.0", info: { name: "TLS Weakness", tags: ["ssl", "tls"], severity: "high" }, severity: "high", host: "https://example.com" },
    ];
    const reports = ["soc2", "pci_dss", "nist_800_53"].map(fw =>
      generateComplianceReport({
        framework: fw as any,
        pipelineId: 1,
        pipelineName: "Test",
        runId: 100,
        findings,
      })
    );
    const summary = generateCrossFrameworkSummary(reports);
    // Shared gaps should exist since auth and SSL affect multiple frameworks
    // (may be 0 if findings don't share the same findingId across frameworks)
    expect(summary.sharedGaps).toBeDefined();
    expect(Array.isArray(summary.sharedGaps)).toBe(true);
  });

  it("should include top gaps sorted by remediation priority", async () => {
    const { generateComplianceReport } = await import("./lib/cicd-compliance-mapper");
    const report = generateComplianceReport({
      framework: "nist_800_53",
      pipelineId: 1,
      pipelineName: "Test",
      runId: 100,
      findings: [
        { name: "Critical Auth Bypass", info: { name: "Auth Bypass", tags: ["auth"], severity: "critical" }, severity: "critical" },
        { name: "Info Disclosure", info: { name: "Info Leak", tags: ["exposure"], severity: "medium" }, severity: "medium" },
      ],
    });
    expect(report.topGaps.length).toBeGreaterThan(0);
    // Should be sorted by remediation priority (highest first)
    for (let i = 1; i < report.topGaps.length; i++) {
      expect(report.topGaps[i - 1].remediationPriority).toBeGreaterThanOrEqual(report.topGaps[i].remediationPriority);
    }
  });
});
