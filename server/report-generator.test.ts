import { describe, it, expect, vi } from "vitest";

// Mock the LLM module before importing
vi.mock("./_core/llm", () => ({
  invokeLLM: vi.fn().mockResolvedValue({
    choices: [{
      message: {
        content: JSON.stringify({
          executiveSummary: "This engagement tested 10 techniques across 5 tactics. The overall security posture shows room for improvement with a 60% detection rate.",
          recommendations: [
            "Implement Sigma rules for credential access techniques",
            "Enhance logging for lateral movement detection",
            "Deploy YARA rules for malware artifacts",
            "Review SIEM correlation rules",
            "Conduct monthly purple team exercises",
          ],
          conclusion: "The engagement revealed 4 critical detection gaps. Immediate remediation is recommended for the high-severity findings.",
        }),
      },
    }],
  }),
}));

import { generateReport, renderReportHTML } from "./lib/report-generator";

describe("Report Generator", () => {
  const mockOperationData = {
    id: "test-op-1",
    name: "Test Purple Team Exercise",
    state: "finished",
    chain: [
      {
        id: "step-1",
        ability: { technique_id: "T1059.001", technique_name: "PowerShell", name: "Run PowerShell", tactic: "execution", ability_id: "abc" },
        status: 0, finish: "2026-01-15T10:00:00Z", decide: "2026-01-15T09:59:00Z", paw: "agent1",
      },
      {
        id: "step-2",
        ability: { technique_id: "T1003.001", technique_name: "LSASS Memory", name: "Dump LSASS", tactic: "credential-access", ability_id: "def" },
        status: 0, finish: "2026-01-15T10:05:00Z", decide: "2026-01-15T10:04:00Z", paw: "agent1",
      },
      {
        id: "step-3",
        ability: { technique_id: "T1021.001", technique_name: "Remote Desktop Protocol", name: "RDP Lateral", tactic: "lateral-movement", ability_id: "ghi" },
        status: 1, finish: "2026-01-15T10:10:00Z", decide: "2026-01-15T10:09:00Z", paw: "agent1",
      },
    ],
    techniques: [
      { id: "T1059.001", name: "PowerShell", tactic: "execution", status: "success", steps: [{ status: "success" }] },
      { id: "T1003.001", name: "LSASS Memory", tactic: "credential-access", status: "success", steps: [{ status: "success" }] },
      { id: "T1021.001", name: "Remote Desktop Protocol", tactic: "lateral-movement", status: "failed", steps: [{ status: "failed" }] },
    ],
    timeline: [
      { time: "2026-01-15T09:59:00Z", abilityName: "Run PowerShell", techniqueId: "T1059.001", status: "success" },
      { time: "2026-01-15T10:04:00Z", abilityName: "Dump LSASS", techniqueId: "T1003.001", status: "success" },
      { time: "2026-01-15T10:09:00Z", abilityName: "RDP Lateral", techniqueId: "T1021.001", status: "failed" },
    ],
    metrics: {
      totalSteps: 3, completedSteps: 3, successSteps: 2, failedSteps: 1,
      successRate: 67, detectionRate: 33, progress: 100,
    },
  };

  it("should generate a report with correct metadata", async () => {
    const report = await generateReport({
      operationId: "test-op-1",
      operationData: mockOperationData,
      clientName: "Acme Corp",
      engagementType: "Purple Team Exercise",
    });

    expect(report.metadata.author).toBe("Ace C3");
    expect(report.metadata.company).toBe("AceofCloud");
    expect(report.metadata.website).toBe("https://aceofcloud.com");
    expect(report.metadata.clientName).toBe("Acme Corp");
    expect(report.metadata.engagementType).toBe("Purple Team Exercise");
    expect(report.metadata.operationId).toBe("test-op-1");
    expect(report.metadata.classification).toBe("CONFIDENTIAL");
  });

  it("should include executive summary from LLM", async () => {
    const report = await generateReport({
      operationId: "test-op-1",
      operationData: mockOperationData,
    });

    expect(report.executiveSummary).toContain("10 techniques");
    expect(report.executiveSummary.length).toBeGreaterThan(0);
  });

  it("should include recommendations from LLM", async () => {
    const report = await generateReport({
      operationId: "test-op-1",
      operationData: mockOperationData,
    });

    expect(report.recommendations.length).toBeGreaterThan(0);
    expect(report.recommendations[0]).toContain("Sigma");
  });

  it("should include conclusion from LLM", async () => {
    const report = await generateReport({
      operationId: "test-op-1",
      operationData: mockOperationData,
    });

    expect(report.conclusion).toContain("detection gaps");
  });

  it("should calculate correct attack chain results", async () => {
    const report = await generateReport({
      operationId: "test-op-1",
      operationData: mockOperationData,
    });

    expect(report.attackChainResults.length).toBe(3);
    const powershell = report.attackChainResults.find(r => r.techniqueId === "T1059.001");
    expect(powershell).toBeDefined();
    expect(powershell?.status).toBe("success");
  });

  it("should identify findings for undetected techniques", async () => {
    const report = await generateReport({
      operationId: "test-op-1",
      operationData: mockOperationData,
    });

    // PowerShell and LSASS succeeded without detection
    const undetected = report.findings.filter(f => f.severity === "critical" || f.severity === "high");
    expect(undetected.length).toBeGreaterThan(0);
  });

  it("should assign correct severity based on tactic", async () => {
    const report = await generateReport({
      operationId: "test-op-1",
      operationData: mockOperationData,
    });

    const credFinding = report.findings.find(f => f.techniqueId === "T1003.001");
    if (credFinding) {
      expect(credFinding.severity).toBe("critical"); // credential-access is critical
    }
  });

  it("should build MITRE mapping organized by tactic", async () => {
    const report = await generateReport({
      operationId: "test-op-1",
      operationData: mockOperationData,
    });

    expect(report.mitreMapping.length).toBeGreaterThan(0);
    const executionTactic = report.mitreMapping.find(m => m.tactic === "execution");
    expect(executionTactic).toBeDefined();
    expect(executionTactic?.techniques.some(t => t.id === "T1059.001")).toBe(true);
  });

  it("should include scope and methodology text", async () => {
    const report = await generateReport({
      operationId: "test-op-1",
      operationData: mockOperationData,
      engagementType: "Red Team Assessment",
    });

    expect(report.scopeAndMethodology).toContain("Red Team Assessment");
    expect(report.scopeAndMethodology).toContain("MITRE ATT&CK");
  });

  it("should include operation timeline", async () => {
    const report = await generateReport({
      operationId: "test-op-1",
      operationData: mockOperationData,
    });

    expect(report.operationTimeline.length).toBe(3);
    expect(report.operationTimeline[0].event).toBe("Run PowerShell");
  });

  it("should render valid HTML report", async () => {
    const report = await generateReport({
      operationId: "test-op-1",
      operationData: mockOperationData,
      clientName: "Test Client",
    });

    const html = renderReportHTML(report);
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("ACEOFCLOUD");
    expect(html).toContain("Ace C3");
    expect(html).toContain("Test Client");
    expect(html).toContain("CONFIDENTIAL");
    expect(html).toContain("Executive Summary");
    expect(html).toContain("Attack Chain Results");
    expect(html).toContain("MITRE ATT&CK Mapping");
    expect(html).toContain("Detection Coverage Analysis");
    expect(html).toContain("Findings");
    expect(html).toContain("Recommendations");
    expect(html).toContain("Conclusion");
  });

  it("should include metrics in HTML report", async () => {
    const report = await generateReport({
      operationId: "test-op-1",
      operationData: mockOperationData,
    });

    const html = renderReportHTML(report);
    expect(html).toContain("Total Steps Executed");
    expect(html).toContain("Attack Success Rate");
    expect(html).toContain("Detection Rate");
    expect(html).toContain("Tactics Covered");
  });

  it("should handle missing coverage data gracefully", async () => {
    const report = await generateReport({
      operationId: "test-op-1",
      operationData: mockOperationData,
      // No coverageData provided
    });

    expect(report.detectionCoverage).toBeDefined();
    expect(report.detectionCoverage.totalTechniques).toBeGreaterThanOrEqual(0);
  });

  it("should use default values when optional inputs are missing", async () => {
    const report = await generateReport({
      operationId: "test-op-1",
      operationData: mockOperationData,
    });

    expect(report.metadata.clientName).toBe("Client");
    expect(report.metadata.engagementType).toBe("Purple Team Exercise");
  });

  it("should handle empty operation chain", async () => {
    const report = await generateReport({
      operationId: "test-op-1",
      operationData: { ...mockOperationData, chain: [], techniques: [], timeline: [], metrics: {} },
    });

    expect(report.attackChainResults.length).toBe(0);
    expect(report.findings.length).toBe(0);
    expect(report.operationTimeline.length).toBe(0);
  });
});
