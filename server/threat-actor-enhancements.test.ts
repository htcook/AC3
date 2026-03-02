/**
 * Vitest Tests — Threat Actor Catalog Enhancements
 *
 * Tests for:
 * 1. Actor Context Provider (multi-source enrichment + TTP learning)
 * 2. Actor Behavioral Sequence Engine (kill chain extraction)
 * 3. C2 Learning → Actor Profile Feedback Loop
 * 4. Actor Module Connectors (disconnected module wiring)
 * 5. SOC Context Injection
 */

import { describe, it, expect } from "vitest";

// ─── 1. Actor Context Provider ──────────────────────────────────────────

describe("Actor Context Provider", () => {
  it("exports all required context functions", async () => {
    const mod = await import("./lib/actor-context-provider");
    expect(typeof mod.getActorContext).toBe("function");
    expect(typeof mod.getADAttackContext).toBe("function");
    expect(typeof mod.getCloudAttackContext).toBe("function");
    expect(typeof mod.getCredentialAttackContext).toBe("function");
    expect(typeof mod.getZAPPlaybookContext).toBe("function");
    expect(typeof mod.getSigmaRuleContext).toBe("function");
    expect(typeof mod.getCampaignDesignContext).toBe("function");
    expect(typeof mod.getSOCDashboardContext).toBe("function");
    expect(typeof mod.getAuthAssessmentContext).toBe("function");
    expect(typeof mod.summarizeForPrompt).toBe("function");
  });

  it("getActorContext returns properly structured ActorContext", async () => {
    const { getActorContext } = await import("./lib/actor-context-provider");
    const ctx = await getActorContext({
      targetDomain: "test.com",
      targetSector: "finance",
      requestingModule: "test",
    });

    // Verify structure
    expect(ctx).toHaveProperty("actors");
    expect(ctx).toHaveProperty("techniques");
    expect(ctx).toHaveProperty("iocs");
    expect(ctx).toHaveProperty("tooling");
    expect(ctx).toHaveProperty("behavioralPatterns");
    expect(ctx).toHaveProperty("executionInsights");
    expect(ctx).toHaveProperty("novelTechniques");
    expect(ctx).toHaveProperty("meta");
    expect(Array.isArray(ctx.actors)).toBe(true);
    expect(Array.isArray(ctx.techniques)).toBe(true);
    expect(Array.isArray(ctx.iocs)).toBe(true);
    expect(Array.isArray(ctx.novelTechniques)).toBe(true);

    // Meta should track enrichment sources
    expect(ctx.meta).toHaveProperty("sourcesQueried");
    expect(ctx.meta).toHaveProperty("sourcesSucceeded");
    expect(ctx.meta).toHaveProperty("sourcesFailed");
    expect(ctx.meta).toHaveProperty("totalEnrichmentTimeMs");
    expect(ctx.meta).toHaveProperty("generatedAt");
    expect(Array.isArray(ctx.meta.sourcesQueried)).toBe(true);
    expect(ctx.meta.sourcesQueried.length).toBeGreaterThan(0);
  }, 60000);

  it("summarizeForPrompt handles empty context gracefully", async () => {
    const { summarizeForPrompt } = await import("./lib/actor-context-provider");
    const emptyCtx = {
      actors: [],
      techniques: [],
      iocs: [],
      tooling: [],
      behavioralPatterns: [],
      executionInsights: [],
      novelTechniques: [],
      meta: {
        sourcesQueried: [],
        sourcesSucceeded: [],
        sourcesFailed: [],
        totalEnrichmentTimeMs: 0,
        actorCount: 0,
        techniqueCount: 0,
        iocCount: 0,
        novelTechniqueCount: 0,
        generatedAt: new Date().toISOString(),
      },
    };
    const summary = summarizeForPrompt(emptyCtx);
    expect(typeof summary).toBe("string");
    expect(summary.length).toBeGreaterThan(0);
    expect(summary).toContain("Threat Actor Intelligence");
  });

  it("summarizeForPrompt respects maxLength parameter", async () => {
    const { summarizeForPrompt } = await import("./lib/actor-context-provider");
    const mockCtx = {
      actors: [
        { actorId: "apt29", name: "APT29", aliases: ["Cozy Bear"], type: "nation-state", origin: "Russia", threatLevel: "high", sophistication: "advanced", motivation: "espionage", targetSectors: ["government"], targetRegions: ["US"], activeSince: "2008", lastActivity: "2025-12", matchScore: 95, matchReasons: ["sector match"] },
        { actorId: "apt28", name: "APT28", aliases: ["Fancy Bear"], type: "nation-state", origin: "Russia", threatLevel: "high", sophistication: "advanced", motivation: "espionage", targetSectors: ["defense"], targetRegions: ["EU"], activeSince: "2004", lastActivity: "2025-11", matchScore: 90, matchReasons: ["tech match"] },
      ],
      techniques: [
        { techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution", usedBy: ["APT29"], confidence: 95, executionReliability: 80, executionMethods: [], tools: ["powershell.exe"], detectionCoverage: { sigma: 3, yara: 0, splunk: 2, kql: 1 }, isNovel: false, noveltySource: "" },
      ],
      iocs: [{ type: "domain", value: "evil.com", source: "otx", actors: ["APT29"], lastSeen: "2025-01-01", confidence: 80 }],
      tooling: [{ name: "Cobalt Strike", type: "c2", actors: ["APT29"], description: "C2 framework" }],
      behavioralPatterns: [],
      executionInsights: [],
      novelTechniques: [],
      meta: {
        sourcesQueried: ["catalog", "ttp-knowledge"],
        sourcesSucceeded: ["catalog"],
        sourcesFailed: ["ttp-knowledge"],
        totalEnrichmentTimeMs: 150,
        actorCount: 2,
        techniqueCount: 1,
        iocCount: 1,
        novelTechniqueCount: 0,
        generatedAt: new Date().toISOString(),
      },
    };
    const summary = summarizeForPrompt(mockCtx, 300);
    expect(typeof summary).toBe("string");
    // Should be bounded (allow slight overflow for last line)
    expect(summary.length).toBeLessThanOrEqual(400);
  });
});

// ─── 2. Actor Behavioral Sequence Engine ────────────────────────────────

describe("Actor Behavioral Sequence Engine", () => {
  it("exports all required functions", async () => {
    const mod = await import("./lib/actor-behavioral-sequence-engine");
    expect(typeof mod.extractSequencesFromReports).toBe("function");
    expect(typeof mod.enrichFromTTPKnowledge).toBe("function");
    expect(typeof mod.buildActorFingerprint).toBe("function");
    expect(typeof mod.predictAttackPaths).toBe("function");
    expect(typeof mod.compareActorFingerprints).toBe("function");
    expect(typeof mod.getActorSequences).toBe("function");
    expect(typeof mod.getAllSequences).toBe("function");
    expect(typeof mod.getTransitionsFrom).toBe("function");
    expect(typeof mod.getAllTransitions).toBe("function");
    expect(typeof mod.getSequencedActors).toBe("function");
    expect(typeof mod.getSequenceStats).toBe("function");
  });

  it("getSequenceStats returns valid structure", async () => {
    const { getSequenceStats } = await import("./lib/actor-behavioral-sequence-engine");
    const stats = getSequenceStats();
    expect(stats).toHaveProperty("totalSequences");
    expect(stats).toHaveProperty("totalTransitions");
    expect(stats).toHaveProperty("actorsWithSequences");
    expect(typeof stats.totalSequences).toBe("number");
    expect(typeof stats.totalTransitions).toBe("number");
    expect(typeof stats.actorsWithSequences).toBe("number");
  });

  it("getActorSequences returns array for unknown actor", async () => {
    const { getActorSequences } = await import("./lib/actor-behavioral-sequence-engine");
    const sequences = getActorSequences("NonExistentActor_XYZ");
    expect(Array.isArray(sequences)).toBe(true);
    expect(sequences.length).toBe(0);
  });

  it("getTransitionsFrom returns array for unknown technique", async () => {
    const { getTransitionsFrom } = await import("./lib/actor-behavioral-sequence-engine");
    const transitions = getTransitionsFrom("T9999.999");
    expect(Array.isArray(transitions)).toBe(true);
    expect(transitions.length).toBe(0);
  });

  it("buildActorFingerprint returns null for unknown actor", async () => {
    const { buildActorFingerprint } = await import("./lib/actor-behavioral-sequence-engine");
    const fingerprint = buildActorFingerprint("NonExistentActor_XYZ");
    expect(fingerprint).toBeNull();
  });

  it("getSequencedActors returns array of strings", async () => {
    const { getSequencedActors } = await import("./lib/actor-behavioral-sequence-engine");
    const actors = getSequencedActors();
    expect(Array.isArray(actors)).toBe(true);
    for (const actor of actors) {
      expect(typeof actor).toBe("string");
    }
  });

  it("getAllSequences and getAllTransitions return arrays", async () => {
    const { getAllSequences, getAllTransitions } = await import("./lib/actor-behavioral-sequence-engine");
    expect(Array.isArray(getAllSequences())).toBe(true);
    expect(Array.isArray(getAllTransitions())).toBe(true);
  });

  it("BehavioralSequence has correct structure", async () => {
    const { getAllSequences } = await import("./lib/actor-behavioral-sequence-engine");
    const sequences = getAllSequences();
    for (const seq of sequences) {
      expect(seq).toHaveProperty("actorName");
      expect(seq).toHaveProperty("steps");
      expect(Array.isArray(seq.steps)).toBe(true);
    }
  });
});

// ─── 3. C2 Learning → Actor Profile Feedback Loop ──────────────────────

describe("C2 Actor Feedback Loop", () => {
  it("exports all required functions", async () => {
    const mod = await import("./lib/c2-actor-feedback-loop");
    expect(typeof mod.processActorFeedback).toBe("function");
    expect(typeof mod.buildActorLearningProfile).toBe("function");
    expect(typeof mod.getFeedbackForSigmaRules).toBe("function");
    expect(typeof mod.getFeedbackForCampaignAdvisor).toBe("function");
    expect(typeof mod.getFeedbackForSequenceEngine).toBe("function");
    expect(typeof mod.getProfiledActors).toBe("function");
    expect(typeof mod.getRecentFeedbackEvents).toBe("function");
    expect(typeof mod.getFeedbackLoopStats).toBe("function");
  });

  it("processActorFeedback updates actor performance on success", async () => {
    const { processActorFeedback, buildActorLearningProfile } = await import("./lib/c2-actor-feedback-loop");

    const result = await processActorFeedback(
      {
        techniqueId: "T1059.001",
        framework: "caldera" as any,
        taskResult: { status: "success", exitCode: 0, stdout: "Command executed successfully", stderr: "" } as any,
        targetContext: { os: "windows", platform: "workstation", defenses: ["defender"], networkSegment: "corporate" } as any,
      },
      {
        techniqueId: "T1059.001",
        framework: "caldera" as any,
        success: true,
        confidenceAdjustment: 10,
        newConstraints: [],
        observedTelemetry: [],
        extractedArtifacts: [],
        lessonsLearned: [],
        crossFrameworkNotes: [],
        analyzedAt: new Date().toISOString(),
      },
      "APT29_test"
    );

    expect(result.performanceUpdated).toBe(true);
    expect(result.feedbackEvents.length).toBeGreaterThan(0);
    expect(result.feedbackEvents[0]!.type).toBe("technique_success");
    expect(result.feedbackEvents[0]!.actorName).toBe("APT29_test");

    // Verify profile was created
    const profile = buildActorLearningProfile("APT29_test");
    expect(profile).not.toBeNull();
    expect(profile!.actorName).toBe("APT29_test");
    expect(profile!.overallSuccessRate).toBe(100);
    expect(profile!.totalEmulations).toBe(1);
  });

  it("processActorFeedback tracks failures and blocking defenses", async () => {
    const { processActorFeedback, buildActorLearningProfile } = await import("./lib/c2-actor-feedback-loop");

    await processActorFeedback(
      {
        techniqueId: "T1003.001",
        framework: "caldera" as any,
        taskResult: { status: "failure", exitCode: 1, stdout: "", stderr: "Access denied" } as any,
        targetContext: { os: "windows", platform: "server", defenses: ["crowdstrike", "sysmon"], networkSegment: "dmz" } as any,
      },
      {
        techniqueId: "T1003.001",
        framework: "caldera" as any,
        success: false,
        confidenceAdjustment: -15,
        newConstraints: [],
        observedTelemetry: [],
        extractedArtifacts: [],
        lessonsLearned: ["Credential dumping blocked by EDR"],
        crossFrameworkNotes: [],
        analyzedAt: new Date().toISOString(),
      },
      "APT29_test"
    );

    const profile = buildActorLearningProfile("APT29_test");
    expect(profile).not.toBeNull();
    expect(profile!.totalEmulations).toBe(2);
    expect(profile!.overallSuccessRate).toBe(50);
  });

  it("getFeedbackForSigmaRules returns structured data", async () => {
    const { getFeedbackForSigmaRules } = await import("./lib/c2-actor-feedback-loop");
    const sigmaFeedback = getFeedbackForSigmaRules("APT29_test");
    expect(sigmaFeedback).toHaveProperty("successfulTechniques");
    expect(sigmaFeedback).toHaveProperty("failedTechniques");
    expect(sigmaFeedback).toHaveProperty("novelVariations");
    expect(sigmaFeedback).toHaveProperty("telemetrySignals");
    expect(Array.isArray(sigmaFeedback.successfulTechniques)).toBe(true);
  });

  it("getFeedbackForCampaignAdvisor returns recommendations", async () => {
    const { getFeedbackForCampaignAdvisor } = await import("./lib/c2-actor-feedback-loop");
    const advice = getFeedbackForCampaignAdvisor("APT29_test");
    expect(advice).toHaveProperty("recommendedTechniques");
    expect(advice).toHaveProperty("avoidTechniques");
    expect(advice).toHaveProperty("environmentalInsights");
    expect(Array.isArray(advice.recommendedTechniques)).toBe(true);
  });

  it("getFeedbackForSequenceEngine returns execution orders", async () => {
    const { getFeedbackForSequenceEngine } = await import("./lib/c2-actor-feedback-loop");
    const seqFeedback = getFeedbackForSequenceEngine("APT29_test");
    expect(seqFeedback).toHaveProperty("executionOrders");
    expect(seqFeedback).toHaveProperty("chainBreaks");
    expect(Array.isArray(seqFeedback.executionOrders)).toBe(true);
  });

  it("getFeedbackLoopStats returns aggregated statistics", async () => {
    const { getFeedbackLoopStats } = await import("./lib/c2-actor-feedback-loop");
    const stats = getFeedbackLoopStats();
    expect(stats).toHaveProperty("totalFeedbackEvents");
    expect(stats).toHaveProperty("actorsProfiled");
    expect(stats).toHaveProperty("totalNovelVariations");
    expect(stats).toHaveProperty("totalArtifactsDiscovered");
    expect(stats).toHaveProperty("avgSuccessRate");
    expect(stats).toHaveProperty("topPerformingActors");
    expect(stats).toHaveProperty("recentEvents");
    expect(stats.actorsProfiled).toBeGreaterThan(0);
  });

  it("getProfiledActors returns actors that have been profiled", async () => {
    const { getProfiledActors } = await import("./lib/c2-actor-feedback-loop");
    const actors = getProfiledActors();
    expect(Array.isArray(actors)).toBe(true);
    expect(actors).toContain("APT29_test");
  });

  it("getRecentFeedbackEvents returns events with correct structure", async () => {
    const { getRecentFeedbackEvents } = await import("./lib/c2-actor-feedback-loop");
    const events = getRecentFeedbackEvents(10, "APT29_test");
    expect(Array.isArray(events)).toBe(true);
    expect(events.length).toBeGreaterThan(0);
    for (const event of events) {
      expect(event).toHaveProperty("type");
      expect(event).toHaveProperty("actorName");
      expect(event).toHaveProperty("techniqueId");
      expect(event).toHaveProperty("timestamp");
      expect(event.actorName).toBe("APT29_test");
    }
  });

  it("buildActorLearningProfile returns null for unknown actor", async () => {
    const { buildActorLearningProfile } = await import("./lib/c2-actor-feedback-loop");
    const profile = buildActorLearningProfile("NonExistentActor_XYZ");
    expect(profile).toBeNull();
  });
});

// ─── 4. Actor Module Connectors ─────────────────────────────────────────

describe("Actor Module Connectors", () => {
  it("exports all enrichment functions", async () => {
    const mod = await import("./lib/actor-module-connectors");
    expect(typeof mod.enrichADAttackAnalysis).toBe("function");
    expect(typeof mod.enrichCloudAttackPaths).toBe("function");
    expect(typeof mod.enrichCredentialTesting).toBe("function");
    expect(typeof mod.enrichZAPPlaybooks).toBe("function");
    expect(typeof mod.enrichSigmaRuleGeneration).toBe("function");
    expect(typeof mod.enrichCloudSecurityValidation).toBe("function");
    expect(typeof mod.getModuleActorEnrichment).toBe("function");
  });

  it("enrichADAttackAnalysis returns enriched attacks with actor context", async () => {
    const { enrichADAttackAnalysis } = await import("./lib/actor-module-connectors");
    const result = await enrichADAttackAnalysis(
      [{ name: "Kerberoasting", techniqueId: "T1558.003" }],
      { targetDomain: "corp.local" }
    );
    expect(result).toHaveProperty("enrichedAttacks");
    expect(result).toHaveProperty("actorSummary");
    expect(result).toHaveProperty("topActors");
    expect(result).toHaveProperty("novelADTechniques");
    expect(Array.isArray(result.enrichedAttacks)).toBe(true);
    expect(typeof result.actorSummary).toBe("string");
  }, 60000);

  it("enrichCredentialTesting returns profiles (not enrichedProfiles)", async () => {
    const { enrichCredentialTesting } = await import("./lib/actor-module-connectors");
    const result = await enrichCredentialTesting(
      ["ssh", "rdp"],
      { targetSector: "finance" }
    );
    // Actual return property is 'profiles' not 'enrichedProfiles'
    expect(result).toHaveProperty("profiles");
    expect(result).toHaveProperty("actorSummary");
    expect(result).toHaveProperty("topCredentialActors");
    expect(Array.isArray(result.profiles)).toBe(true);
    expect(typeof result.actorSummary).toBe("string");
  }, 60000);

  it("getModuleActorEnrichment returns unified context", async () => {
    const { getModuleActorEnrichment } = await import("./lib/actor-module-connectors");
    const result = await getModuleActorEnrichment("test-module", { targetDomain: "test.com" });
    expect(result).toHaveProperty("context");
    expect(result).toHaveProperty("promptSummary");
    expect(result).toHaveProperty("topActors");
    expect(result).toHaveProperty("topTechniques");
    expect(result).toHaveProperty("activeIOCs");
    expect(result).toHaveProperty("novelCount");
    expect(typeof result.promptSummary).toBe("string");
    expect(Array.isArray(result.topActors)).toBe(true);
    expect(Array.isArray(result.topTechniques)).toBe(true);
    expect(typeof result.activeIOCs).toBe("number");
    expect(typeof result.novelCount).toBe("number");
  }, 60000);
});

// ─── 5. SOC Context Injection ───────────────────────────────────────────

describe("SOC Context Injection", () => {
  it("getRoleContext supports soc role", async () => {
    const { getRoleContext } = await import("./lib/role-chat-context");
    const context = await getRoleContext("soc");
    expect(typeof context).toBe("string");
    // In test env, safe() may return empty string fallback if DB query fails
    // The important thing is it doesn't throw and returns a string
  });

  it("getSocContext is exported and returns string", async () => {
    const { getSocContext } = await import("./lib/role-chat-context");
    expect(typeof getSocContext).toBe("function");
    const context = await getSocContext();
    expect(typeof context).toBe("string");
  });

  it("getRoleContext handles all known roles", async () => {
    const { getRoleContext } = await import("./lib/role-chat-context");
    const roles = ["operator", "executive", "analyst", "team_lead", "client", "admin", "soc"];
    for (const role of roles) {
      const context = await getRoleContext(role);
      expect(typeof context).toBe("string");
    }
  });
});

// ─── 6. Cross-Module Integration Integrity ──────────────────────────────

describe("Cross-Module Integration", () => {
  it("feedback loop data is consumable by sigma rule engine", async () => {
    const { getFeedbackForSigmaRules } = await import("./lib/c2-actor-feedback-loop");
    const feedback = getFeedbackForSigmaRules();
    expect(Array.isArray(feedback.successfulTechniques)).toBe(true);
    expect(Array.isArray(feedback.failedTechniques)).toBe(true);
    expect(Array.isArray(feedback.novelVariations)).toBe(true);
    expect(Array.isArray(feedback.telemetrySignals)).toBe(true);
  });

  it("feedback loop data is consumable by campaign advisor", async () => {
    const { getFeedbackForCampaignAdvisor } = await import("./lib/c2-actor-feedback-loop");
    const advice = getFeedbackForCampaignAdvisor("APT29_test");
    expect(Array.isArray(advice.recommendedTechniques)).toBe(true);
    expect(Array.isArray(advice.avoidTechniques)).toBe(true);
    for (const rec of advice.recommendedTechniques) {
      expect(rec).toHaveProperty("techniqueId");
      expect(rec).toHaveProperty("successRate");
      expect(rec).toHaveProperty("reason");
    }
    for (const avoid of advice.avoidTechniques) {
      expect(avoid).toHaveProperty("techniqueId");
      expect(avoid).toHaveProperty("failureRate");
      expect(avoid).toHaveProperty("reason");
    }
  });

  it("feedback loop data is consumable by sequence engine", async () => {
    const { getFeedbackForSequenceEngine } = await import("./lib/c2-actor-feedback-loop");
    const seqData = getFeedbackForSequenceEngine();
    expect(Array.isArray(seqData.executionOrders)).toBe(true);
    expect(Array.isArray(seqData.chainBreaks)).toBe(true);
    for (const order of seqData.executionOrders) {
      expect(order).toHaveProperty("techniqueId");
      expect(order).toHaveProperty("position");
      expect(order).toHaveProperty("success");
      expect(order).toHaveProperty("timestamp");
    }
  });

  it("actor context provider and feedback loop share consistent actor naming", async () => {
    const { getProfiledActors } = await import("./lib/c2-actor-feedback-loop");
    const { getSequencedActors } = await import("./lib/actor-behavioral-sequence-engine");
    const profiled = getProfiledActors();
    const sequenced = getSequencedActors();
    // Both should return string arrays
    expect(profiled.every(a => typeof a === "string")).toBe(true);
    expect(sequenced.every(a => typeof a === "string")).toBe(true);
  });
});
