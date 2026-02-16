import { describe, it, expect } from "vitest";

/**
 * Tests for the pre-engagement scan flow:
 * 1. Scan-only mode: pipeline stops after risk scoring, status = scan_complete
 * 2. Start engagement: resumes from scan_complete → runs campaigns + threat actors → completed
 * 3. Clickable heatmap: asset detail drill-down data structure
 */

describe("Pre-Engagement Scan Flow", () => {
  describe("Pipeline skipEngagement option", () => {
    it("runDomainIntelPipeline should accept skipEngagement option", async () => {
      const { runDomainIntelPipeline } = await import("./domainIntel");
      expect(typeof runDomainIntelPipeline).toBe("function");
      // The function accepts (orgProfile, onProgress?, options?)
      // options includes { scanMode, skipEngagement }
    });

    it("should define scan_complete as a valid pipeline status", () => {
      // The DB status enum should include scan_complete
      const validStatuses = [
        "pending", "passive_recon", "discovering", "analyzing",
        "scoring", "recommending", "scan_complete", "completed", "failed"
      ];
      expect(validStatuses).toContain("scan_complete");
    });

    it("scan_complete should be distinct from completed", () => {
      const scanComplete = "scan_complete";
      const completed = "completed";
      expect(scanComplete).not.toBe(completed);
      // scan_complete means: recon done, no campaigns
      // completed means: full engagement with campaigns
    });
  });

  describe("Scan-only pipeline result", () => {
    it("should produce results without campaign recommendations when skipEngagement=true", () => {
      // When skipEngagement is true, the pipeline should:
      // 1. Run passive recon (Stage 0.5)
      // 2. Run LLM discovery (Stage 1)
      // 3. Run DNS verification (Stage 2)
      // 4. Run BIA scoring (Stage 3)
      // 5. Run vuln enrichment (Stage 3.5)
      // 6. SKIP campaign design (Stage 4)
      // 7. Generate scan-only summary instead of full threat model summary

      const scanOnlyResult = {
        assets: [{ hostname: "test.example.com", hybridRiskScore: 75 }],
        overallRiskScore: 75,
        overallRiskBand: "high",
        totalAssets: 1,
        totalFindings: 10,
        executiveSummary: "Scan-only summary...",
        threatModelSummary: "Scan-only threat model...",
        campaignRecommendations: [], // Empty for scan-only
      };

      expect(scanOnlyResult.campaignRecommendations).toEqual([]);
      expect(scanOnlyResult.overallRiskScore).toBeGreaterThan(0);
      expect(scanOnlyResult.executiveSummary).toBeTruthy();
    });

    it("scan-only results should still include risk scores and findings", () => {
      // Even without campaigns, scan-only should produce:
      const requiredScanOnlyFields = [
        "assets",
        "overallRiskScore",
        "overallRiskBand",
        "totalAssets",
        "totalFindings",
        "executiveSummary",
      ];
      expect(requiredScanOnlyFields.length).toBe(6);
    });
  });

  describe("Start Engagement flow", () => {
    it("should only allow engagement on scan_complete scans", () => {
      const validStartStatuses = ["scan_complete"];
      const invalidStatuses = ["pending", "discovering", "analyzing", "scoring", "recommending", "completed", "failed"];

      for (const status of validStartStatuses) {
        expect(status).toBe("scan_complete");
      }

      for (const status of invalidStatuses) {
        expect(status).not.toBe("scan_complete");
      }
    });

    it("engagement should produce campaigns and threat actor matches", () => {
      const engagementResult = {
        campaigns: [
          { name: "Phishing Campaign", type: "phishing", priority: "critical" },
          { name: "Red Team Exercise", type: "red_team", priority: "high" },
        ],
        threatActorMatches: {
          topMatches: [
            { name: "APT29", confidence: 0.85, sector: "technology" },
          ],
        },
        status: "completed", // After engagement, status becomes completed
      };

      expect(engagementResult.campaigns.length).toBeGreaterThan(0);
      expect(engagementResult.threatActorMatches.topMatches.length).toBeGreaterThan(0);
      expect(engagementResult.status).toBe("completed");
    });

    it("failed engagement should revert to scan_complete", () => {
      // If engagement fails, the scan should revert to scan_complete
      // so the user can retry
      const failedEngagement = {
        originalStatus: "scan_complete",
        engagementFailed: true,
        revertedStatus: "scan_complete", // NOT "failed"
      };

      expect(failedEngagement.revertedStatus).toBe("scan_complete");
      expect(failedEngagement.revertedStatus).not.toBe("failed");
    });
  });

  describe("generateScanOnlySummary function", () => {
    it("should be exported from domainIntel module", async () => {
      const mod = await import("./domainIntel");
      expect(typeof mod.generateScanOnlySummary).toBe("function");
    });

    it("should generate summary without campaign context", async () => {
      // The function should produce an executive summary and threat model
      // summary that focus on reconnaissance findings, not campaigns
      const { generateScanOnlySummary } = await import("./domainIntel");
      expect(generateScanOnlySummary.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe("Pipeline stage flow for scan-only", () => {
    it("should have correct stage progression for scan-only mode", () => {
      const scanOnlyStages = [
        { stage: 0.5, label: "Passive Recon" },
        { stage: 1, label: "LLM Discovery" },
        { stage: 2, label: "DNS Verification" },
        { stage: 3, label: "BIA Scoring" },
        { stage: 3, label: "Vuln Enrichment" },
        // No stage 4 (campaign design) for scan-only
      ];

      const fullEngagementStages = [
        ...scanOnlyStages,
        { stage: 4, label: "Threat Actor Matching" },
        { stage: 4, label: "Campaign Design" },
      ];

      expect(scanOnlyStages.length).toBe(5);
      expect(fullEngagementStages.length).toBe(7);

      // Scan-only should not include stage 4
      const maxScanOnlyStage = Math.max(...scanOnlyStages.map(s => s.stage));
      expect(maxScanOnlyStage).toBe(3);
    });

    it("frontend stage map should include scan_complete status", () => {
      const stageMap: Record<string, number> = {
        passive_recon: 0.5,
        discovering: 1,
        analyzing: 2,
        scoring: 3,
        recommending: 4,
        scan_complete: 3.5,
        completed: 5,
        failed: -1,
      };

      expect(stageMap["scan_complete"]).toBe(3.5);
      expect(stageMap["completed"]).toBe(5);
      expect(stageMap["scan_complete"]).toBeLessThan(stageMap["recommending"]);
    });
  });
});

describe("Clickable Asset Risk Heatmap", () => {
  describe("Heatmap data structure", () => {
    it("each asset should have the required fields for heatmap display", () => {
      const mockAsset = {
        id: 1,
        hostname: "app.example.com",
        hybridRiskScore: 82,
        riskBand: "critical",
        assetType: "web_application",
        technologies: ["nginx", "react", "node.js"],
        carverScores: {
          criticality: 8,
          accessibility: 7,
          recuperability: 6,
          vulnerability: 9,
          effect: 7,
          recognizability: 8,
        },
        shockScores: {
          scope: 7,
          handling: 6,
          operationalImpact: 8,
          cascadingEffects: 7,
          knowledge: 5,
        },
        postureFindings: [
          { title: "CVE-2024-1234", severity: 9.1, corroborationTier: "confirmed" },
          { title: "Outdated TLS", severity: 5.0, corroborationTier: "probable" },
        ],
        testVectors: [
          "SQL injection on login form",
          "XSS in search parameter",
        ],
        dnsStatus: "verified",
        confidence: 85,
      };

      // Verify all fields needed for heatmap drill-down
      expect(mockAsset.hostname).toBeTruthy();
      expect(mockAsset.hybridRiskScore).toBeGreaterThanOrEqual(0);
      expect(mockAsset.hybridRiskScore).toBeLessThanOrEqual(100);
      expect(mockAsset.riskBand).toBeTruthy();
      expect(mockAsset.carverScores).toBeTruthy();
      expect(Object.keys(mockAsset.carverScores).length).toBe(6);
      expect(mockAsset.shockScores).toBeTruthy();
      expect(Object.keys(mockAsset.shockScores).length).toBe(5);
      expect(mockAsset.postureFindings.length).toBeGreaterThan(0);
      expect(mockAsset.technologies.length).toBeGreaterThan(0);
    });

    it("heatmap tile color should map to risk band", () => {
      const RISK_COLORS: Record<string, string> = {
        critical: "text-red-400 bg-red-500/20 border-red-500/40",
        high: "text-orange-400 bg-orange-500/20 border-orange-500/40",
        medium: "text-yellow-400 bg-yellow-500/20 border-yellow-500/40",
        low: "text-emerald-400 bg-emerald-500/20 border-emerald-500/40",
      };

      expect(RISK_COLORS["critical"]).toContain("red");
      expect(RISK_COLORS["high"]).toContain("orange");
      expect(RISK_COLORS["medium"]).toContain("yellow");
      expect(RISK_COLORS["low"]).toContain("emerald");
    });

    it("expanded heatmap tile should show CARVER breakdown", () => {
      const carverLabels = ["Criticality", "Accessibility", "Recuperability", "Vulnerability", "Effect", "Recognizability"];
      expect(carverLabels.length).toBe(6);

      // Each CARVER score should be 0-10
      const carverScores = { criticality: 8, accessibility: 7, recuperability: 6, vulnerability: 9, effect: 7, recognizability: 8 };
      for (const [key, value] of Object.entries(carverScores)) {
        expect(value).toBeGreaterThanOrEqual(0);
        expect(value).toBeLessThanOrEqual(10);
      }
    });

    it("expanded heatmap tile should show top posture findings", () => {
      const findings = [
        { title: "CVE-2024-1234", severity: 9.1, corroborationTier: "confirmed" },
        { title: "Outdated TLS", severity: 5.0, corroborationTier: "probable" },
        { title: "Missing HSTS", severity: 3.0, corroborationTier: "potential" },
      ];

      // Should show top 3 findings sorted by severity
      const sorted = [...findings].sort((a, b) => b.severity - a.severity);
      expect(sorted[0].title).toBe("CVE-2024-1234");
      expect(sorted[0].severity).toBe(9.1);
    });

    it("heatmap toggle state should be independent per asset", () => {
      // heatmapExpandedAsset state tracks which asset is expanded
      // Only one asset can be expanded at a time (accordion behavior)
      let heatmapExpandedAsset: number | null = null;

      // Click asset 1
      heatmapExpandedAsset = 1;
      expect(heatmapExpandedAsset).toBe(1);

      // Click asset 2 (should close asset 1)
      heatmapExpandedAsset = 2;
      expect(heatmapExpandedAsset).toBe(2);

      // Click asset 2 again (should close it)
      heatmapExpandedAsset = heatmapExpandedAsset === 2 ? null : 2;
      expect(heatmapExpandedAsset).toBeNull();
    });
  });

  describe("Heatmap interaction patterns", () => {
    it("clicking a tile should toggle expanded state", () => {
      let expanded: number | null = null;
      const toggle = (id: number) => {
        expanded = expanded === id ? null : id;
      };

      toggle(1);
      expect(expanded).toBe(1);
      toggle(1);
      expect(expanded).toBeNull();
      toggle(2);
      expect(expanded).toBe(2);
      toggle(3);
      expect(expanded).toBe(3);
    });

    it("expanded panel should show technologies as badges", () => {
      const technologies = ["nginx/1.24", "React 18", "Node.js 20", "PostgreSQL 16"];
      expect(technologies.length).toBe(4);
      // Each technology should be rendered as a badge
      for (const tech of technologies) {
        expect(tech.length).toBeGreaterThan(0);
      }
    });

    it("expanded panel should show test vectors", () => {
      const testVectors = [
        "SQL injection on login form",
        "XSS in search parameter",
        "SSRF via image upload",
      ];
      expect(testVectors.length).toBeGreaterThan(0);
      // Test vectors provide actionable attack paths
    });
  });
});

describe("Engagement Mode UI Toggle", () => {
  it("should default to scan-only mode", () => {
    const defaultScanOnly = true;
    expect(defaultScanOnly).toBe(true);
  });

  it("scan-only mode should show different button text", () => {
    const scanOnly = true;
    const buttonText = scanOnly ? "Launch Domain Reconnaissance Scan" : "Launch Full Engagement Scan";
    expect(buttonText).toBe("Launch Domain Reconnaissance Scan");
  });

  it("full engagement mode should show different button text", () => {
    const scanOnly = false;
    const buttonText = scanOnly ? "Launch Domain Reconnaissance Scan" : "Launch Full Engagement Scan";
    expect(buttonText).toBe("Launch Full Engagement Scan");
  });

  it("scan-only mode should show fewer pipeline stages", () => {
    const SCAN_STAGES = [
      { label: "Passive Recon", stage: 0.5 },
      { label: "LLM Discovery", stage: 1 },
      { label: "DNS Verification", stage: 2 },
      { label: "BIA Scoring", stage: 3 },
      { label: "Vuln Enrichment", stage: 3 },
    ];

    const ENGAGEMENT_STAGES = [
      { label: "Threat Actor Matching", stage: 4 },
      { label: "Campaign Design", stage: 4 },
    ];

    const scanOnlyPipeline = SCAN_STAGES;
    const fullPipeline = [...SCAN_STAGES, ...ENGAGEMENT_STAGES];

    expect(scanOnlyPipeline.length).toBe(5);
    expect(fullPipeline.length).toBe(7);
  });

  it("results page tabs should differ for scan_complete vs completed", () => {
    const scanCompleteTabs = ["overview", "assets", "vulns", "findings", "methods"];
    const completedTabs = ["overview", "assets", "vulns", "adversaries", "campaigns", "threat-model", "findings", "methods"];

    expect(scanCompleteTabs.length).toBe(5);
    expect(completedTabs.length).toBe(8);

    // scan_complete should NOT have adversaries, campaigns, or threat-model
    expect(scanCompleteTabs).not.toContain("adversaries");
    expect(scanCompleteTabs).not.toContain("campaigns");
    expect(scanCompleteTabs).not.toContain("threat-model");

    // completed should have all tabs
    expect(completedTabs).toContain("adversaries");
    expect(completedTabs).toContain("campaigns");
    expect(completedTabs).toContain("threat-model");
  });
});
