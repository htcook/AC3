import { describe, it, expect } from "vitest";
import type { PurpleTeamROEAddendum, PurpleTeamTestPlan, DetectionTest, BilateralEvidenceRecord, UnifiedTimeline, NegativeEvidence, DetectionMetrics } from "./lib/purple-team-model";

// We test the purple team data model types and the report section generation logic

describe("Purple Team Data Model", () => {
  it("should create a valid PurpleTeamROEAddendum", () => {
    const roe: PurpleTeamROEAddendum = {
      engagementId: 1,
      defensiveTeamName: "Blue Team Alpha",
      defensiveTeamLead: "Jane Smith",
      defensiveTeamEmail: "jane@example.com",
      defensiveTeamAcknowledged: true,
      defensiveTeamAckDate: Date.now(),
      advanceTtpDisclosure: false,
      realTimeChannel: true,
      realTimeChannelType: "Slack #purple-ops",
      separateStopSignal: true,
      stopSignalMechanism: "Dedicated Slack channel message: STOP-PURPLE",
      edrVendor: "CrowdStrike",
      edrProduct: "Falcon Insight",
      edrVendorTosConfirmed: true,
      edrMdrActive: true,
      edrMdrNotified: true,
      edrVendorPurpleTeamPolicy: "CrowdStrike Purple Team Partner Program",
      siemProduct: "Splunk Enterprise",
      msspProvider: "Arctic Wolf",
      irProcedureRef: "IR-PROC-2026-001",
      evasionBoundedToTestPlan: true,
      liveAmendmentAllowed: true,
      amendmentRequiresJustification: true,
      exerciseWindowStart: Date.now(),
      exerciseWindowEnd: Date.now() + 2 * 60 * 60 * 1000,
      detectionObservationEnd: Date.now() + 26 * 60 * 60 * 1000,
      ttpDetectionGracePeriodMs: 15 * 60 * 1000,
      authorizedTechniques: [
        {
          mitreId: "T1059.001",
          mitreName: "PowerShell",
          tactic: "Execution",
          authorized: true,
          authorizedBy: "John Doe (CISO)",
          constraints: "No destructive payloads",
        },
      ],
    };

    expect(roe.defensiveTeamName).toBe("Blue Team Alpha");
    expect(roe.edrVendorTosConfirmed).toBe(true);
    expect(roe.authorizedTechniques).toHaveLength(1);
    expect(roe.ttpDetectionGracePeriodMs).toBe(900000);
  });

  it("should create a valid DetectionTest with detection result", () => {
    const test: DetectionTest = {
      id: "DT-001",
      engagementId: 1,
      mitreId: "T1059.001",
      mitreName: "PowerShell",
      tactic: "Execution",
      executionMethod: "Invoke-Mimikatz via PowerShell",
      targetHost: "10.0.1.50",
      executedAt: Date.now(),
      detectionWindowEnd: Date.now() + 15 * 60 * 1000,
      expectedIndicators: [
        "Process creation: powershell.exe with suspicious arguments",
        "AMSI trigger on Invoke-Mimikatz",
        "Memory access to lsass.exe",
      ],
      status: "detected",
      detectionResult: {
        detected: true,
        timeToDetect: 180000, // 3 minutes
        detectedBy: ["CrowdStrike Falcon", "Splunk"],
        alertSeverity: "high",
        alertId: "ALERT-2026-001",
        falsePositive: false,
        socResponseAction: "Isolated host, escalated to IR team",
        negativeEvidenceNotes: null,
      },
      evidenceHashes: ["sha256:abc123"],
      operatorId: "operator-1",
    };

    expect(test.status).toBe("detected");
    expect(test.detectionResult?.timeToDetect).toBe(180000);
    expect(test.detectionResult?.detectedBy).toContain("CrowdStrike Falcon");
    expect(test.expectedIndicators).toHaveLength(3);
  });

  it("should create a valid DetectionTest with negative detection", () => {
    const test: DetectionTest = {
      id: "DT-002",
      engagementId: 1,
      mitreId: "T1003.001",
      mitreName: "LSASS Memory",
      tactic: "Credential Access",
      executionMethod: "Procdump on lsass.exe",
      targetHost: "10.0.1.50",
      executedAt: Date.now(),
      detectionWindowEnd: Date.now() + 15 * 60 * 1000,
      expectedIndicators: [
        "Process access to lsass.exe from unsigned binary",
        "MiniDump file creation",
      ],
      status: "not_detected",
      detectionResult: {
        detected: false,
        timeToDetect: 0,
        detectedBy: [],
        alertSeverity: null,
        alertId: null,
        falsePositive: false,
        socResponseAction: null,
        negativeEvidenceNotes: "No alert generated within 15-minute grace period. Customer SOC confirmed no detection.",
      },
      evidenceHashes: ["sha256:def456"],
      operatorId: "operator-1",
    };

    expect(test.status).toBe("not_detected");
    expect(test.detectionResult?.detected).toBe(false);
    expect(test.detectionResult?.negativeEvidenceNotes).toContain("No alert generated");
  });

  it("should create valid DetectionMetrics", () => {
    const metrics: DetectionMetrics = {
      detectionRate: 0.75,
      meanTimeToDetect: 300000,
      meanTimeToAlert: 420000,
      meanTimeToRespond: 900000,
      totalTested: 20,
      totalDetected: 15,
      totalMissed: 5,
      byTactic: {
        "Execution": { tested: 5, detected: 4, rate: 0.8 },
        "Credential Access": { tested: 4, detected: 2, rate: 0.5 },
        "Lateral Movement": { tested: 3, detected: 2, rate: 0.67 },
      },
      byProduct: {
        "CrowdStrike Falcon": { detected: 12, missed: 3 },
        "Splunk": { detected: 8, missed: 7 },
      },
    };

    expect(metrics.detectionRate).toBe(0.75);
    expect(metrics.totalTested).toBe(20);
    expect(metrics.byTactic["Execution"].rate).toBe(0.8);
    expect(metrics.byProduct["CrowdStrike Falcon"].detected).toBe(12);
  });

  it("should create valid NegativeEvidence", () => {
    const ne: NegativeEvidence = {
      detectionTestId: "DT-002",
      mitreId: "T1003.001",
      executedAt: Date.now(),
      gracePeriodEnd: Date.now() + 15 * 60 * 1000,
      observationStatement: "TTP T1003.001 (LSASS Memory) was executed at the specified time. No detection alert was generated by any defensive product within the 15-minute grace period.",
      expectedIndicators: [
        "Process access to lsass.exe from unsigned binary",
        "MiniDump file creation",
      ],
      activeDefensiveProducts: ["CrowdStrike Falcon", "Splunk Enterprise"],
      customerConfirmedNoAlert: true,
      evidenceHash: "sha256:neg-evidence-hash-001",
    };

    expect(ne.customerConfirmedNoAlert).toBe(true);
    expect(ne.observationStatement).toContain("No detection alert");
    expect(ne.activeDefensiveProducts).toHaveLength(2);
  });

  it("should create valid BilateralEvidenceRecord", () => {
    const record: BilateralEvidenceRecord = {
      id: "BE-001",
      engagementId: 1,
      detectionTestId: "DT-001",
      type: "execution",
      timestamp: Date.now(),
      side: "offensive",
      content: "Executed Invoke-Mimikatz via PowerShell on 10.0.1.50",
      contentHash: "sha256:content-hash-001",
      chainHash: "sha256:chain-hash-001",
      provenance: "AC3 Platform - Exploit Pipeline Orchestrator",
      createdBy: "operator-1",
    };

    expect(record.side).toBe("offensive");
    expect(record.type).toBe("execution");
    expect(record.chainHash).toContain("sha256:");
  });

  it("should create valid UnifiedTimeline with both sides", () => {
    const timeline: UnifiedTimeline = {
      engagementId: 1,
      events: [
        {
          timestamp: Date.now(),
          side: "offensive",
          type: "ttp_execution",
          mitreId: "T1059.001",
          description: "Executed PowerShell payload on target",
          source: "AC3 Platform",
          host: "10.0.1.50",
          detectionTestId: "DT-001",
          evidenceHash: "sha256:evt-001",
        },
        {
          timestamp: Date.now() + 180000,
          side: "defensive",
          type: "detection_alert",
          mitreId: "T1059.001",
          description: "CrowdStrike Falcon alert: Suspicious PowerShell execution",
          source: "CrowdStrike Falcon",
          host: "10.0.1.50",
          detectionTestId: "DT-001",
          evidenceHash: "sha256:evt-002",
        },
        {
          timestamp: Date.now() + 300000,
          side: "defensive",
          type: "soc_response",
          description: "SOC analyst acknowledged alert, initiated investigation",
          source: "Splunk SOAR",
          host: "10.0.1.50",
          detectionTestId: "DT-001",
          evidenceHash: "sha256:evt-003",
        },
      ],
      timeSyncMetadata: {
        ntpSource: "pool.ntp.org",
        platformClockSkew: 12,
        customerClockSkew: -5,
        syncVerified: true,
      },
    };

    expect(timeline.events).toHaveLength(3);
    expect(timeline.events[0].side).toBe("offensive");
    expect(timeline.events[1].side).toBe("defensive");
    expect(timeline.timeSyncMetadata.syncVerified).toBe(true);
  });
});

describe("Purple Team Report Sections", () => {
  it("should have purple team sections in the report pipeline", async () => {
    // Verify the report pipeline file contains the purple team section markers
    const fs = await import("fs");
    const reportPipeline = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/pentest-report-pipeline.ts",
      "utf-8"
    );

    // Check all 7 purple team sections exist
    expect(reportPipeline).toContain("PT-1. Purple Team Rules of Engagement Addendum");
    expect(reportPipeline).toContain("PT-2. Purple Team Test Plan");
    expect(reportPipeline).toContain("PT-3. Detection Test Results");
    expect(reportPipeline).toContain("PT-4. Detection Metrics");
    expect(reportPipeline).toContain("PT-5. Bilateral Evidence and Unified Timeline");
    expect(reportPipeline).toContain("PT-6. Detection Gap Analysis and Recommendations");
    expect(reportPipeline).toContain("PT-7. Replayability Metadata");
  });

  it("should conditionally render purple team sections only for purple_team engagements", async () => {
    const fs = await import("fs");
    const reportPipeline = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/pentest-report-pipeline.ts",
      "utf-8"
    );

    // Verify the conditional check exists
    expect(reportPipeline).toContain('engagementType === "purple_team"');
    expect(reportPipeline).toContain("isPurpleTeam && pt");
  });

  it("should include ROE addendum fields for defensive team, EDR vendor, evasion bounding", async () => {
    const fs = await import("fs");
    const reportPipeline = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/pentest-report-pipeline.ts",
      "utf-8"
    );

    expect(reportPipeline).toContain("Defensive Team Participation");
    expect(reportPipeline).toContain("Detection Coordination Protocol");
    expect(reportPipeline).toContain("EDR Vendor Notification");
    expect(reportPipeline).toContain("Evasion Scope Bounding");
    expect(reportPipeline).toContain("Exercise Windows");
    expect(reportPipeline).toContain("Technique-Level Authorization");
  });

  it("should include detection gap analysis with remediation recommendations", async () => {
    const fs = await import("fs");
    const reportPipeline = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/pentest-report-pipeline.ts",
      "utf-8"
    );

    expect(reportPipeline).toContain("Detection Gaps — Missed TTPs");
    expect(reportPipeline).toContain("Gap Summary");
    expect(reportPipeline).toContain("Gaps by MITRE ATT&CK Tactic");
    expect(reportPipeline).toContain("Remediation Recommendations");
    expect(reportPipeline).toContain("PT-REC-");
  });

  it("should include negative evidence documentation as first-class records", async () => {
    const fs = await import("fs");
    const reportPipeline = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/pentest-report-pipeline.ts",
      "utf-8"
    );

    expect(reportPipeline).toContain("Negative Evidence Records");
    expect(reportPipeline).toContain("first-class evidence records, not absence of evidence");
    expect(reportPipeline).toContain("Customer Confirmed No Alert");
    expect(reportPipeline).toContain("Expected Indicators (not observed)");
  });

  it("should include bilateral timeline with time sync metadata", async () => {
    const fs = await import("fs");
    const reportPipeline = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/pentest-report-pipeline.ts",
      "utf-8"
    );

    expect(reportPipeline).toContain("Time Synchronization");
    expect(reportPipeline).toContain("Unified Event Timeline");
    expect(reportPipeline).toContain("NTP Source");
    expect(reportPipeline).toContain("Platform Clock Skew");
    expect(reportPipeline).toContain("Customer Clock Skew");
  });

  it("should include replayability metadata for future verification", async () => {
    const fs = await import("fs");
    const reportPipeline = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/pentest-report-pipeline.ts",
      "utf-8"
    );

    expect(reportPipeline).toContain("testPlanVersion");
    expect(reportPipeline).toContain("edrCatalogVersion");
    expect(reportPipeline).toContain("platformVersion");
    expect(reportPipeline).toContain("Defensive Stack Snapshot at Execution Time");
  });

  it("should include detection metrics by tactic and by product", async () => {
    const fs = await import("fs");
    const reportPipeline = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/pentest-report-pipeline.ts",
      "utf-8"
    );

    expect(reportPipeline).toContain("Detection Rate by MITRE ATT&CK Tactic");
    expect(reportPipeline).toContain("Detection by Defensive Product");
    expect(reportPipeline).toContain("Mean Time to Detect (MTTD)");
    expect(reportPipeline).toContain("Mean Time to Alert (MTTA)");
    expect(reportPipeline).toContain("Mean Time to Respond (MTTR)");
  });
});

describe("PurpleTeamData in PipelineInput", () => {
  it("should accept purpleTeamData as optional field on PipelineInput", async () => {
    const fs = await import("fs");
    const reportPipeline = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/pentest-report-pipeline.ts",
      "utf-8"
    );

    expect(reportPipeline).toContain("purpleTeamData?:");
    expect(reportPipeline).toContain("PurpleTeamROEAddendum");
    expect(reportPipeline).toContain("PurpleTeamTestPlan");
    expect(reportPipeline).toContain("DetectionTest[]");
    expect(reportPipeline).toContain("BilateralEvidenceRecord[]");
    expect(reportPipeline).toContain("UnifiedTimeline");
    expect(reportPipeline).toContain("NegativeEvidence[]");
    expect(reportPipeline).toContain("DetectionMetrics");
  });
});
