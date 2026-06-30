import { describe, it, expect, beforeEach } from "vitest";

/**
 * Tests for the three new features:
 * 1. Hypothesis Generator — Orchestrator Post-Recon Hook
 * 2. Submission Prep — tRPC router procedures
 * 3. Negative Example Feedback Loop — Calibration integration
 */

// ─── Feature 1: Hypothesis Generator Orchestrator Hook ───────────────────────

const importHook = () => import("./lib/hypothesis-orchestrator-hook");

describe("Hypothesis Generator — Orchestrator Hook", () => {
  describe("extractReconDataFromState", () => {
    it("should extract tech stack from passive recon technologies", async () => {
      const { extractReconDataFromState } = await importHook();
      const state = {
        engagementType: "pentest",
        phase: "passive_discovery",
        assets: [{
          hostname: "example.com",
          type: "web",
          status: "active",
          ports: [{ port: 443, service: "https", version: "nginx/1.21" }],
          vulns: [],
          passiveRecon: {
            technologies: ["React", "Node.js", "nginx"],
          },
        }],
      };
      const reconData = extractReconDataFromState(state as any);
      expect(reconData.targetDomain).toBe("example.com");
      expect(reconData.techStack.length).toBeGreaterThanOrEqual(3);
      expect(reconData.techStack.some(t => t.technology === "React")).toBe(true);
      expect(reconData.techStack.some(t => t.technology === "Node.js")).toBe(true);
      expect(reconData.openPorts.length).toBe(1);
      expect(reconData.openPorts[0].port).toBe(443);
    });

    it("should extract subdomains from assets", async () => {
      const { extractReconDataFromState } = await importHook();
      const state = {
        engagementType: "bug_bounty",
        phase: "passive_discovery",
        assets: [
          { hostname: "example.com", type: "web", status: "active", ports: [], vulns: [] },
          { hostname: "api.example.com", type: "web", status: "active", ports: [], vulns: [] },
          { hostname: "admin.example.com", type: "web", status: "active", ports: [], vulns: [] },
        ],
      };
      const reconData = extractReconDataFromState(state as any);
      expect(reconData.subdomains).toContain("api.example.com");
      expect(reconData.subdomains).toContain("admin.example.com");
      expect(reconData.subdomains).not.toContain("example.com");
    });

    it("should extract config anomalies from risk signals", async () => {
      const { extractReconDataFromState } = await importHook();
      const state = {
        engagementType: "pentest",
        phase: "passive_discovery",
        assets: [{
          hostname: "example.com",
          type: "web",
          status: "active",
          ports: [],
          vulns: [],
          passiveRecon: {
            riskSignals: [
              { severity: "high", rationale: "Missing CORS headers on API endpoints", category: "cors" },
              { severity: "medium", rationale: "Weak TLS configuration detected", category: "tls" },
            ],
          },
        }],
      };
      const reconData = extractReconDataFromState(state as any);
      expect(reconData.configAnomalies.length).toBe(2);
      expect(reconData.configAnomalies[0].category).toBe("cors");
      expect(reconData.configAnomalies[1].category).toBe("tls");
    });

    it("should handle empty assets gracefully", async () => {
      const { extractReconDataFromState } = await importHook();
      const state = {
        engagementType: "pentest",
        phase: "passive_discovery",
        assets: [],
      };
      const reconData = extractReconDataFromState(state as any);
      expect(reconData.targetDomain).toBe("unknown");
      expect(reconData.techStack).toEqual([]);
      expect(reconData.openPorts).toEqual([]);
    });
  });

  describe("runHypothesisGeneration", () => {
    it("should return generated=false when no assets exist", async () => {
      const { runHypothesisGeneration } = await importHook();
      const state = {
        engagementType: "pentest",
        phase: "passive_discovery",
        assets: [],
        metadata: {},
      };
      const result = await runHypothesisGeneration(state as any);
      expect(result.generated).toBe(false);
      expect(result.hypothesisCount).toBe(0);
    });

    it("should generate hypotheses when assets have tech stack data", async () => {
      const { runHypothesisGeneration } = await importHook();
      const state = {
        engagementType: "pentest",
        phase: "passive_discovery",
        assets: [{
          hostname: "testapp.example.com",
          type: "web",
          status: "active",
          ports: [
            { port: 80, service: "http" },
            { port: 443, service: "https" },
            { port: 22, service: "ssh" },
          ],
          vulns: [],
          passiveRecon: {
            technologies: ["WordPress", "PHP", "Apache", "MySQL"],
            headers: { "X-Powered-By": "PHP/7.4" },
          },
        }],
        metadata: {},
      };
      const result = await runHypothesisGeneration(state as any);
      expect(result.generated).toBe(true);
      expect(result.hypothesisCount).toBeGreaterThan(0);
      expect(result.reconQualityScore).toBeGreaterThan(0);
      expect(result.topHypotheses.length).toBeGreaterThan(0);
      // Verify hypotheses are stored in metadata
      expect((state.metadata as any).hypothesisResults).toBeDefined();
      expect((state.metadata as any).hypothesisResults.hypotheses.length).toBeGreaterThan(0);
    });

    it("should use program-aware generation for bug_bounty engagements", async () => {
      const { runHypothesisGeneration } = await importHook();
      const state = {
        engagementType: "bug_bounty",
        phase: "passive_discovery",
        assets: [{
          hostname: "target.example.com",
          type: "web",
          status: "active",
          ports: [{ port: 443, service: "https" }],
          vulns: [],
          passiveRecon: { technologies: ["React", "Express"] },
        }],
        metadata: {},
        bbRoeConfig: {
          programHandle: "test-program",
          platform: "hackerone",
          rewardStructure: { avgBounty: 500, maxBounty: 5000 },
        },
      };
      const result = await runHypothesisGeneration(state as any);
      expect(result.generated).toBe(true);
      expect(result.hypothesisCount).toBeGreaterThan(0);
    });
  });

  describe("buildScanPriorityAdjustments", () => {
    it("should return empty array when no hypotheses exist", async () => {
      const { buildScanPriorityAdjustments } = await importHook();
      const state = { metadata: {}, assets: [] };
      const result = buildScanPriorityAdjustments(state as any);
      expect(result).toEqual([]);
    });

    it("should generate priorities from high-confidence hypotheses", async () => {
      const { buildScanPriorityAdjustments } = await importHook();
      const state = {
        assets: [],
        metadata: {
          hypothesisResults: {
            hypotheses: [
              {
                id: "h1",
                title: "SQL Injection in login",
                vulnClass: "sqli",
                affectedEndpoint: "/api/login",
                confidence: "high",
                confidenceScore: 0.9,
                potentialSeverity: "critical",
                chainPotential: [],
              },
              {
                id: "h2",
                title: "Info disclosure",
                vulnClass: "info_disclosure",
                affectedEndpoint: "/api/debug",
                confidence: "low",
                confidenceScore: 0.3,
                potentialSeverity: "low",
                chainPotential: [],
              },
            ],
          },
        },
      };
      const result = buildScanPriorityAdjustments(state as any);
      expect(result.length).toBeGreaterThanOrEqual(1);
      expect(result[0].endpoint).toBe("/api/login");
      expect(result[0].priority).toBe("critical");
    });
  });

  describe("formatHypothesisLogEntry", () => {
    it("should format a non-generated result", async () => {
      const { formatHypothesisLogEntry } = await importHook();
      const result = formatHypothesisLogEntry({
        generated: false,
        hypothesisCount: 0,
        highConfidenceCount: 0,
        topHypotheses: [],
        reconQualityScore: 0,
        missingReconData: ["No assets"],
        chainOpportunities: 0,
        estimatedResearchHours: 0,
        generatedAt: Date.now(),
      });
      expect(result.title).toContain("No assets");
    });

    it("should format a generated result with top hypotheses", async () => {
      const { formatHypothesisLogEntry } = await importHook();
      const result = formatHypothesisLogEntry({
        generated: true,
        hypothesisCount: 5,
        highConfidenceCount: 2,
        topHypotheses: [
          { title: "SQLi", vulnClass: "sqli", confidence: "high", confidenceScore: 0.9, severity: "critical", endpoint: "/login", estimatedEffort: "2h" },
        ],
        reconQualityScore: 75,
        missingReconData: [],
        chainOpportunities: 1,
        estimatedResearchHours: 8,
        generatedAt: Date.now(),
      });
      expect(result.title).toContain("5 hypotheses");
      expect(result.title).toContain("2 high-confidence");
      expect(result.detail).toContain("75/100");
    });
  });
});

// ─── Feature 3: Negative Example Feedback Loop ──────────────────────────────

const importFeedback = () => import("./lib/negative-example-feedback-loop");

describe("Negative Example Feedback Loop", () => {
  describe("negativeExampleToCalibrationRecord", () => {
    it("should convert a false_positive rejection to a calibration record", async () => {
      const { negativeExampleToCalibrationRecord } = await importFeedback();
      const example = {
        id: "neg-1",
        vulnClass: "xss",
        title: "Reflected XSS in search",
        affectedEndpoint: "/search",
        severity: "high",
        rejectionReason: "false_positive" as const,
        rejectionDetail: "Not exploitable due to CSP",
        submittedAt: "2025-01-01T00:00:00Z",
        rejectedAt: "2025-01-02T00:00:00Z",
        lessonsLearned: ["Check CSP before reporting XSS"],
        tags: ["xss"],
      };
      const record = negativeExampleToCalibrationRecord(example);
      expect(record.vulnClass).toBe("xss");
      expect(record.actualOutcome).toBe("rejected");
      expect(record.predictedConfidence).toBeGreaterThanOrEqual(0.7);
      expect(record.timestamp).toBeGreaterThan(0);
    });

    it("should map duplicate rejections correctly", async () => {
      const { negativeExampleToCalibrationRecord } = await importFeedback();
      const example = {
        id: "neg-2",
        vulnClass: "sqli",
        title: "SQL Injection",
        affectedEndpoint: "/api/users",
        severity: "critical",
        rejectionReason: "duplicate" as const,
        rejectionDetail: "Already reported by another researcher",
        submittedAt: "2025-01-01T00:00:00Z",
        rejectedAt: "2025-01-02T00:00:00Z",
        lessonsLearned: ["Check for duplicates first"],
        tags: ["sqli"],
      };
      const record = negativeExampleToCalibrationRecord(example);
      expect(record.actualOutcome).toBe("duplicate");
    });

    it("should map informational_only rejections correctly", async () => {
      const { negativeExampleToCalibrationRecord } = await importFeedback();
      const example = {
        id: "neg-3",
        vulnClass: "info_disclosure",
        title: "Server version disclosure",
        affectedEndpoint: "/",
        severity: "info",
        rejectionReason: "informational_only" as const,
        rejectionDetail: "Not a vulnerability",
        submittedAt: "2025-01-01T00:00:00Z",
        rejectedAt: "2025-01-02T00:00:00Z",
        lessonsLearned: ["Info disclosures rarely qualify"],
        tags: ["info"],
      };
      const record = negativeExampleToCalibrationRecord(example);
      expect(record.actualOutcome).toBe("informational");
    });
  });

  describe("negativeExampleToOutcomeEntry", () => {
    it("should convert a negative example to an outcome entry", async () => {
      const { negativeExampleToOutcomeEntry } = await importFeedback();
      const example = {
        id: "neg-4",
        vulnClass: "ssrf",
        title: "SSRF via image proxy",
        affectedEndpoint: "/api/proxy",
        severity: "high",
        rejectionReason: "false_positive" as const,
        rejectionDetail: "URL validation prevents exploitation",
        submittedAt: "2025-01-01T00:00:00Z",
        rejectedAt: "2025-01-02T00:00:00Z",
        lessonsLearned: ["Verify URL bypass before reporting SSRF", "Check allowlist"],
        tags: ["ssrf"],
      };
      const entry = negativeExampleToOutcomeEntry(example);
      expect(entry.vulnClass).toBe("ssrf");
      expect(entry.outcome).toBe("rejected");
      expect(entry.extractedPatterns.length).toBe(2);
      expect(entry.extractedPatterns[0].pattern).toContain("Verify URL bypass");
    });
  });

  describe("NegativeExampleFeedbackLoop", () => {
    it("should process a single rejection and update calibration", async () => {
      const { NegativeExampleFeedbackLoop } = await importFeedback();
      const loop = new NegativeExampleFeedbackLoop();

      const mockCalibration = {
        records: [] as any[],
        recordOutcome(record: any) { this.records.push(record); },
        detectDrift() {
          return { hasDrift: false, severity: "none" as const, direction: "well_calibrated" as const, overallBias: 0, worstVulnClasses: [], recommendation: "OK", lastChecked: Date.now() };
        },
      };

      const example = {
        id: "neg-5",
        vulnClass: "xss",
        title: "DOM XSS",
        affectedEndpoint: "/app",
        severity: "medium",
        rejectionReason: "false_positive" as const,
        rejectionDetail: "Sanitized by framework",
        submittedAt: "2025-01-01T00:00:00Z",
        rejectedAt: "2025-01-02T00:00:00Z",
        lessonsLearned: ["Check framework sanitization"],
        tags: ["xss"],
      };

      const result = loop.processRejection(example, mockCalibration);
      expect(result.processed).toBe(true);
      expect(result.calibrationUpdated).toBe(true);
      expect(mockCalibration.records.length).toBe(1);
      expect(mockCalibration.records[0].vulnClass).toBe("xss");
      expect(mockCalibration.records[0].actualOutcome).toBe("rejected");
      expect(result.trainingSignals.length).toBeGreaterThanOrEqual(1);
    });

    it("should process a batch and detect drift when threshold met", async () => {
      const { NegativeExampleFeedbackLoop } = await importFeedback();
      const loop = new NegativeExampleFeedbackLoop({ driftDetectionThreshold: 3 });

      let driftCalls = 0;
      const mockCalibration = {
        recordOutcome(_record: any) {},
        detectDrift() {
          driftCalls++;
          return { hasDrift: true, severity: "mild" as const, direction: "overconfident" as const, overallBias: 0.12, worstVulnClasses: [], recommendation: "Lower thresholds", lastChecked: Date.now() };
        },
      };

      const examples = Array.from({ length: 5 }, (_, i) => ({
        id: `neg-batch-${i}`,
        vulnClass: "xss",
        title: `Finding ${i}`,
        affectedEndpoint: `/endpoint-${i}`,
        severity: "medium",
        rejectionReason: "false_positive" as const,
        rejectionDetail: "FP",
        submittedAt: "2025-01-01T00:00:00Z",
        rejectedAt: "2025-01-02T00:00:00Z",
        lessonsLearned: ["lesson"],
        tags: ["xss"],
      }));

      const result = loop.processBatch(examples, mockCalibration);
      expect(result.processed).toBe(5);
      expect(result.calibrationUpdates).toBe(5);
      expect(driftCalls).toBeGreaterThanOrEqual(1);
    });

    it("should track stats correctly", async () => {
      const { NegativeExampleFeedbackLoop } = await importFeedback();
      const loop = new NegativeExampleFeedbackLoop();

      const mockCalibration = {
        recordOutcome(_record: any) {},
        detectDrift() {
          return { hasDrift: false, severity: "none" as const, direction: "well_calibrated" as const, overallBias: 0, worstVulnClasses: [], recommendation: "OK", lastChecked: Date.now() };
        },
      };

      const example = {
        id: "neg-stats",
        vulnClass: "sqli",
        title: "SQLi",
        affectedEndpoint: "/api",
        severity: "high",
        rejectionReason: "duplicate" as const,
        rejectionDetail: "Already reported",
        submittedAt: "2025-01-01T00:00:00Z",
        rejectedAt: "2025-01-02T00:00:00Z",
        lessonsLearned: ["Check duplicates"],
        tags: ["sqli"],
      };

      loop.processRejection(example, mockCalibration);
      const stats = loop.getStats();
      expect(stats.totalRejectionsProcessed).toBe(1);
      expect(stats.totalCalibrationUpdates).toBe(1);
      expect(stats.rejectionsByReason["duplicate"]).toBe(1);
    });

    it("should apply false_positive weight boost", async () => {
      const { NegativeExampleFeedbackLoop } = await importFeedback();
      const loop = new NegativeExampleFeedbackLoop({ falsePositiveWeightBoost: 1.5, autoCalibrate: true, driftDetectionThreshold: 100, outOfScopeWeightBoost: 1.2, enableEventBus: false, maxCalibrationRecords: 10000 });

      const records: any[] = [];
      const mockCalibration = {
        recordOutcome(record: any) { records.push(record); },
        detectDrift() {
          return { hasDrift: false, severity: "none" as const, direction: "well_calibrated" as const, overallBias: 0, worstVulnClasses: [], recommendation: "OK", lastChecked: Date.now() };
        },
      };

      const fpExample = {
        id: "neg-fp",
        vulnClass: "xss",
        title: "XSS",
        affectedEndpoint: "/search",
        severity: "high",
        rejectionReason: "false_positive" as const,
        rejectionDetail: "Not exploitable",
        submittedAt: "2025-01-01T00:00:00Z",
        rejectedAt: "2025-01-02T00:00:00Z",
        lessonsLearned: ["Verify exploitation"],
        tags: ["xss"],
      };

      const nonFpExample = {
        ...fpExample,
        id: "neg-nonfp",
        rejectionReason: "known_issue" as const,
      };

      loop.processRejection(fpExample, mockCalibration);
      loop.processRejection(nonFpExample, mockCalibration);

      // FP should have boosted confidence (higher predicted = more overconfident signal)
      expect(records[0].predictedConfidence).toBeGreaterThan(records[1].predictedConfidence);
    });

    it("should publish events to event bus when enabled", async () => {
      const { NegativeExampleFeedbackLoop } = await importFeedback();
      const loop = new NegativeExampleFeedbackLoop({ enableEventBus: true, autoCalibrate: true, driftDetectionThreshold: 100, falsePositiveWeightBoost: 1.5, outOfScopeWeightBoost: 1.2, maxCalibrationRecords: 10000 });

      const mockCalibration = {
        recordOutcome(_record: any) {},
        detectDrift() {
          return { hasDrift: false, severity: "none" as const, direction: "well_calibrated" as const, overallBias: 0, worstVulnClasses: [], recommendation: "OK", lastChecked: Date.now() };
        },
      };

      const publishedEvents: any[] = [];
      const mockEventBus = {
        publish(source: any, eventType: any, payload: any, meta: any) {
          publishedEvents.push({ source, eventType, payload, meta });
          return { id: "evt-1", timestamp: Date.now(), source, eventType, payload, sourceMetadata: meta, isHoldout: false, biasWeight: 1.0, processedBy: [] };
        },
      };

      const example = {
        id: "neg-bus",
        vulnClass: "idor",
        title: "IDOR",
        affectedEndpoint: "/api/users/1",
        severity: "high",
        rejectionReason: "intended_behavior" as const,
        rejectionDetail: "Access control is by design",
        submittedAt: "2025-01-01T00:00:00Z",
        rejectedAt: "2025-01-02T00:00:00Z",
        lessonsLearned: ["Verify access control design"],
        tags: ["idor"],
      };

      const result = loop.processRejection(example, mockCalibration, mockEventBus as any);
      expect(result.eventPublished).toBe(true);
      expect(publishedEvents.length).toBe(1);
      expect(publishedEvents[0].source).toBe("bug_bounty");
      expect(publishedEvents[0].eventType).toBe("finding_rejected");
    });

    it("should reset state correctly", async () => {
      const { NegativeExampleFeedbackLoop } = await importFeedback();
      const loop = new NegativeExampleFeedbackLoop();

      const mockCalibration = {
        recordOutcome(_record: any) {},
        detectDrift() {
          return { hasDrift: false, severity: "none" as const, direction: "well_calibrated" as const, overallBias: 0, worstVulnClasses: [], recommendation: "OK", lastChecked: Date.now() };
        },
      };

      loop.processRejection({
        id: "neg-reset",
        vulnClass: "xss",
        title: "XSS",
        affectedEndpoint: "/",
        severity: "medium",
        rejectionReason: "false_positive" as const,
        rejectionDetail: "FP",
        submittedAt: "2025-01-01T00:00:00Z",
        rejectedAt: "2025-01-02T00:00:00Z",
        lessonsLearned: [],
        tags: [],
      }, mockCalibration);

      expect(loop.getStats().totalRejectionsProcessed).toBe(1);
      loop.reset();
      expect(loop.getStats().totalRejectionsProcessed).toBe(0);
      expect(loop.getCalibrationRecords().length).toBe(0);
    });
  });
});
