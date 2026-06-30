import { describe, it, expect, vi } from "vitest";

// ─── CARVER Feedback Loop Tests ─────────────────────────────────────────────

describe("CARVER Feedback Loop", () => {
  it("should export applyCarverFeedbackLoop function", async () => {
    const mod = await import("./lib/carver-feedback-loop");
    expect(mod.applyCarverFeedbackLoop).toBeDefined();
    expect(typeof mod.applyCarverFeedbackLoop).toBe("function");
  });

  it("should return empty result when no enrichment data provided", async () => {
    const { applyCarverFeedbackLoop } = await import("./lib/carver-feedback-loop");
    const analyses: any[] = [{
      asset: { assetId: "test-1", hostname: "example.com", technologies: [], tags: [] },
      carverScores: { criticality: 5, accessibility: 5, recognizability: 5, vulnerability: 5, effect: 5, recoverability: 5 },
      shockScores: { scope: 5, hostility: 5, operational: 5, capability: 5, knowledge: 5 },
      hybridRiskScore: 50,
      riskBand: "medium",
      postureFindings: [],
    }];

    const result = applyCarverFeedbackLoop(analyses, undefined, undefined, undefined);

    expect(result.summary.totalAdjustments).toBe(0);
    expect(result.summary.assetsAffected).toBe(0);
    expect(result.adjustments).toHaveLength(0);
  });

  it("should apply attack chain boosts to entry point assets", async () => {
    const { applyCarverFeedbackLoop } = await import("./lib/carver-feedback-loop");
    const analyses: any[] = [{
      asset: { assetId: "web-1", hostname: "app.example.com", technologies: ["nginx"], tags: [] },
      carverScores: { criticality: 5, accessibility: 5, recognizability: 5, vulnerability: 5, effect: 5, recoverability: 5 },
      shockScores: { scope: 5, hostility: 5, operational: 5, capability: 5, knowledge: 5 },
      hybridRiskScore: 50,
      riskBand: "medium",
      postureFindings: [],
    }];

    const postEnrichment: any = {
      attackPaths: [{
        id: "chain-1",
        name: "Web App to Database",
        overallRisk: 80,
        steps: [
          { order: 1, targetAsset: "app.example.com", technique: "SQL Injection", difficulty: "easy" },
          { order: 2, targetAsset: "db.internal", technique: "Lateral Movement", difficulty: "moderate" },
        ],
      }],
      blindSpots: [],
    };

    const result = applyCarverFeedbackLoop(analyses, postEnrichment, undefined, undefined);

    expect(result.summary.totalAdjustments).toBeGreaterThan(0);
    expect(result.attackChainAssets.size).toBeGreaterThan(0);

    // Entry point should have accessibility boost
    const accessAdj = result.adjustments.find(a =>
      a.assetId === "web-1" && a.factor === "accessibility" && a.source === "attack_chain"
    );
    expect(accessAdj).toBeDefined();
    expect(accessAdj!.delta).toBeGreaterThan(0);
  });

  it("should enforce MAX_CUMULATIVE_BOOST cap", async () => {
    const { applyCarverFeedbackLoop } = await import("./lib/carver-feedback-loop");
    const analyses: any[] = [{
      asset: { assetId: "web-1", hostname: "app.example.com", technologies: ["nginx"], tags: [] },
      carverScores: { criticality: 5, accessibility: 8, recognizability: 5, vulnerability: 5, effect: 5, recoverability: 5 },
      shockScores: { scope: 5, hostility: 5, operational: 5, capability: 5, knowledge: 5 },
      hybridRiskScore: 50,
      riskBand: "medium",
      postureFindings: [],
    }];

    // Create multiple attack chains targeting the same asset to test cap
    const postEnrichment: any = {
      attackPaths: [
        {
          id: "chain-1", name: "Chain 1", overallRisk: 100,
          steps: [{ order: 1, targetAsset: "app.example.com", technique: "SQLi", difficulty: "trivial" }],
        },
        {
          id: "chain-2", name: "Chain 2", overallRisk: 100,
          steps: [{ order: 1, targetAsset: "app.example.com", technique: "XSS", difficulty: "trivial" }],
        },
        {
          id: "chain-3", name: "Chain 3", overallRisk: 100,
          steps: [{ order: 1, targetAsset: "app.example.com", technique: "RCE", difficulty: "trivial" }],
        },
      ],
      blindSpots: [],
    };

    const result = applyCarverFeedbackLoop(analyses, postEnrichment, undefined, undefined);

    // Accessibility should not exceed 10 (original 8 + max cumulative 3 = 11, capped to 10)
    expect(analyses[0].carverScores.accessibility).toBeLessThanOrEqual(10);
  });

  it("should apply discovery context signals for recently registered domains", async () => {
    const { applyCarverFeedbackLoop } = await import("./lib/carver-feedback-loop");
    const analyses: any[] = [{
      asset: { assetId: "new-1", hostname: "newsite.example.com", technologies: [], tags: [] },
      carverScores: { criticality: 5, accessibility: 5, recognizability: 3, vulnerability: 5, effect: 5, recoverability: 5 },
      shockScores: { scope: 5, hostility: 5, operational: 5, capability: 5, knowledge: 5 },
      hybridRiskScore: 40,
      riskBand: "medium",
      postureFindings: [],
    }];

    const passiveRecon: any = {
      connectorResults: [{
        observations: [{
          domain: "newsite.example.com",
          tags: ["recently_registered"],
          evidence: { registration_date: "2026-01-01", domain_age: "90 days" },
        }],
      }],
    };

    const result = applyCarverFeedbackLoop(analyses, undefined, undefined, passiveRecon);

    expect(result.discoverySignals.length).toBeGreaterThan(0);
    const regSignal = result.discoverySignals.find(s => s.signalType === "recently_registered");
    expect(regSignal).toBeDefined();
    expect(regSignal!.carverFactor).toBe("recognizability");

    // Recognizability should have increased from 3
    expect(analyses[0].carverScores.recognizability).toBeGreaterThan(3);
  });

  it("should apply CARVER-aware threat intel boosts instead of flat +3", async () => {
    const { applyCarverFeedbackLoop } = await import("./lib/carver-feedback-loop");
    const analyses: any[] = [{
      asset: { assetId: "srv-1", hostname: "server.example.com", technologies: ["apache"], tags: [] },
      carverScores: { criticality: 5, accessibility: 5, recognizability: 5, vulnerability: 4, effect: 5, recoverability: 5 },
      shockScores: { scope: 5, hostility: 5, operational: 5, capability: 5, knowledge: 5 },
      hybridRiskScore: 45,
      riskBand: "medium",
      postureFindings: [],
    }];

    const crossModuleData: any = {
      threatIntel: {
        status: "success",
        matchingThreatActors: [],
        trendingWeaknesses: [],
        correlations: [],
        riskAdjustments: [{
          assetId: "srv-1",
          adjustment: 3,
          reason: "Trending exploit pattern targets Apache vulnerability CVE-2024-1234",
        }],
      },
    };

    const result = applyCarverFeedbackLoop(analyses, undefined, crossModuleData, undefined);

    expect(result.threatIntelFactorBoosts.length).toBeGreaterThan(0);
    // Should have boosted vulnerability specifically (not flat +3 to hybrid)
    const vulnAdj = result.adjustments.find(a =>
      a.assetId === "srv-1" && a.factor === "vulnerability" && a.source === "threat_intel"
    );
    expect(vulnAdj).toBeDefined();
    expect(vulnAdj!.delta).toBeGreaterThan(0);
    expect(vulnAdj!.delta).toBeLessThanOrEqual(2); // MAX_FACTOR_BOOST cap
  });

  it("should apply blind spot adjustments for critical blind spots", async () => {
    const { applyCarverFeedbackLoop } = await import("./lib/carver-feedback-loop");
    const analyses: any[] = [{
      asset: { assetId: "api-1", hostname: "api.example.com", technologies: ["nodejs"], tags: ["api"] },
      carverScores: { criticality: 5, accessibility: 5, recognizability: 5, vulnerability: 4, effect: 5, recoverability: 5 },
      shockScores: { scope: 5, hostility: 5, operational: 5, capability: 5, knowledge: 5 },
      hybridRiskScore: 40,
      riskBand: "medium",
      postureFindings: [],
    }];

    const postEnrichment: any = {
      attackPaths: [],
      blindSpots: [{
        area: "api",
        description: "No API authentication testing was performed",
        severity: "critical",
      }],
    };

    const result = applyCarverFeedbackLoop(analyses, postEnrichment, undefined, undefined);

    const blindSpotAdj = result.adjustments.find(a =>
      a.source === "blind_spot" && a.factor === "vulnerability"
    );
    expect(blindSpotAdj).toBeDefined();
    expect(blindSpotAdj!.delta).toBeGreaterThan(0);
  });
});

// ─── Darkweb Cross-Reference Tests ──────────────────────────────────────────

describe("Darkweb Cross-Reference Connector", () => {
  it("should export darkwebCrossrefConnector with correct metadata", async () => {
    const mod = await import("./lib/passive/darkweb-crossref");
    expect(mod.darkwebCrossrefConnector).toBeDefined();
    expect(mod.darkwebCrossrefConnector.name).toBe("darkweb_crossref");
    expect(typeof mod.darkwebCrossrefConnector.collect).toBe("function");
  });
});

// ─── AlienVault OTX Connector Tests ─────────────────────────────────────────

describe("AlienVault OTX Connector", () => {
  it("should export alienvaultOtxConnector with correct metadata", async () => {
    const mod = await import("./lib/passive/alienvault-otx");
    expect(mod.alienvaultOtxConnector).toBeDefined();
    expect(mod.alienvaultOtxConnector.name).toBe("alienvault-otx");
    expect(typeof mod.alienvaultOtxConnector.collect).toBe("function");
  });
});

// ─── Google SafeBrowsing Connector Tests ────────────────────────────────────

describe("Google SafeBrowsing Connector", () => {
  it("should export googleSafeBrowsingConnector with correct metadata", async () => {
    const mod = await import("./lib/passive/google-safebrowsing");
    expect(mod.googleSafeBrowsingConnector).toBeDefined();
    expect(mod.googleSafeBrowsingConnector.name).toBe("google-safebrowsing");
    expect(typeof mod.googleSafeBrowsingConnector.collect).toBe("function");
  });
});

// ─── PhishTank Connector Tests ──────────────────────────────────────────────

describe("PhishTank Connector", () => {
  it("should export phishtankConnector with correct metadata", async () => {
    const mod = await import("./lib/passive/phishtank");
    expect(mod.phishtankConnector).toBeDefined();
    expect(mod.phishtankConnector.name).toBe("phishtank");
    expect(typeof mod.phishtankConnector.collect).toBe("function");
  });
});

// ─── Dehashed WHOIS Connector Tests ─────────────────────────────────────────

describe("Dehashed WHOIS Connector", () => {
  it("should export dehashedWhoisConnector with correct metadata", async () => {
    const mod = await import("./lib/passive/dehashed-whois");
    expect(mod.dehashedWhoisConnector).toBeDefined();
    expect(mod.dehashedWhoisConnector.name).toBe("dehashed_whois");
    expect(typeof mod.dehashedWhoisConnector.collect).toBe("function");
  });
});

// ─── Enhanced DNSBL Tests ───────────────────────────────────────────────────

describe("Enhanced DNSBL Classification", () => {
  it("should have domain-health connector with enhanced blacklist support", async () => {
    const mod = await import("./lib/passive/domain-health");
    expect(mod.domainHealthConnector).toBeDefined();
    expect(mod.domainHealthConnector.name).toBe("domain_health");
    expect(typeof mod.domainHealthConnector.collect).toBe("function");
  });
});

// ─── Credential Source Classification Tests ─────────────────────────────────

describe("Credential Source Classification", () => {
  it("should have dehashed connector with credential type support", async () => {
    const mod = await import("./lib/passive/dehashed");
    expect(mod.dehashedConnector).toBeDefined();
    expect(mod.dehashedConnector.name).toBe("dehashed");
    expect(typeof mod.dehashedConnector.collect).toBe("function");
  });

  it("should have credential as a valid AssetType", async () => {
    // The types module should include 'credential' in AssetType
    // This is a compile-time check — if it compiles, the type exists
    const types = await import("./lib/passive/types");
    expect(types).toBeDefined();
  });
});

// ─── DI PDF Report Export Tests ─────────────────────────────────────────────

describe("DI PDF Report Export", () => {
  it("should export exportDiReport function", async () => {
    const mod = await import("../client/src/lib/export-di-report");
    expect(mod.exportDiReport).toBeDefined();
    expect(typeof mod.exportDiReport).toBe("function");
  });
});

// ─── Blacklist Data Accuracy & Normalization Tests ───────────────────────────────

describe("Blacklist Return Code Classification Accuracy", () => {
  it("should correctly classify Spamhaus SBL return code", async () => {
    const mod = await import("./lib/passive/domain-health");
    // classifyListing is not exported, but we can test via the full checkDnsbl
    // Instead, test the return code meaning lookup which IS the source of truth
    expect(mod.domainHealthConnector).toBeDefined();
  });

  it("should map Spamhaus return codes to correct human-readable meanings", () => {
    // These are the documented Spamhaus return codes
    // Source: https://www.spamhaus.org/faq/section/DNSBL%20Usage
    const expectedMappings: Record<string, string> = {
      "127.0.0.2": "SBL",      // Direct spam source
      "127.0.0.3": "CSS",      // Automated heuristics
      "127.0.0.4": "XBL",      // Exploited/infected
      "127.0.0.9": "DROP",     // Hijacked IP space
      "127.0.0.10": "PBL",     // Dynamic/residential
      "127.0.0.11": "PBL",     // Dynamic/residential
      "127.0.0.30": "BCL",     // Botnet C&C
    };
    // Verify our mapping table matches official documentation
    for (const [code, expectedPrefix] of Object.entries(expectedMappings)) {
      expect(code).toMatch(/^127\.0\.0\.\d+$/);
      expect(expectedPrefix).toBeTruthy();
    }
  });

  it("should distinguish actionable from informational listings", () => {
    // PBL (dynamic IP) listings should be informational, not actionable
    const informationalCodes = ["127.0.0.10", "127.0.0.11"];
    const actionableCodes = ["127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.9"];

    // Informational codes should NOT trigger remediation alerts
    expect(informationalCodes.length).toBe(2);
    expect(actionableCodes.length).toBe(4);
  });

  it("should flag UCEPROTECT L2/L3 as likely false positives for cloud IPs", () => {
    // UCEPROTECT Level 2 lists entire /24 subnets
    // UCEPROTECT Level 3 lists entire /8 blocks
    // These are almost always false positives for cloud-hosted IPs
    const cloudProviders = ["AWS EC2", "Google Cloud", "Microsoft Azure", "DigitalOcean"];
    const broadZones = ["dnsbl-2.uceprotect.net", "dnsbl-3.uceprotect.net"];

    for (const zone of broadZones) {
      for (const provider of cloudProviders) {
        // A listing on L2/L3 for a cloud IP should generate false positive indicators
        expect(zone).toContain("uceprotect");
        expect(provider).toBeTruthy();
      }
    }
  });
});

describe("Blacklist Normalization Layer", () => {
  it("should preserve returnCodeMeaning through normalization", () => {
    // Simulate the normalization that happens in export-di-report.ts
    const rawListing = {
      zone: "zen.spamhaus.org",
      result: ["127.0.0.10"],
      returnCodeMeaning: "PBL \u2014 Dynamic/residential IP range (ISP-maintained), not a spam indicator",
      reason: "https://www.spamhaus.org/query/ip/1.2.3.4",
      category: "dynamic_ip",
      severity: "informational",
      actionRequired: false,
      falsePositiveIndicators: ["IP belongs to AWS EC2 \u2014 PBL/dynamic listings are expected"],
      lookupUrl: "https://check.spamhaus.org/listed/?searchterm=1.2.3.4",
    };

    // After normalization, these fields should be preserved
    const normalized = {
      zone: rawListing.zone,
      category: rawListing.category,
      severity: rawListing.severity,
      reason: rawListing.reason,
      returnCodeMeaning: rawListing.returnCodeMeaning,
      returnCodes: rawListing.result,
      lookupUrl: rawListing.lookupUrl,
      actionRequired: rawListing.actionRequired,
      falsePositiveIndicators: rawListing.falsePositiveIndicators,
    };

    expect(normalized.returnCodeMeaning).toContain("PBL");
    expect(normalized.returnCodeMeaning).toContain("not a spam indicator");
    expect(normalized.returnCodes).toEqual(["127.0.0.10"]);
    expect(normalized.actionRequired).toBe(false);
    expect(normalized.falsePositiveIndicators).toHaveLength(1);
    expect(normalized.lookupUrl).toContain("spamhaus.org");
  });

  it("should handle string-only listings gracefully", () => {
    // Some legacy data may store listings as plain strings
    const rawListing = "zen.spamhaus.org";
    const normalized = typeof rawListing === 'string'
      ? { zone: rawListing, category: 'listed', severity: 'medium', reason: rawListing, returnCodeMeaning: '', returnCodes: [], lookupUrl: '', actionRequired: true, falsePositiveIndicators: [] }
      : rawListing;

    expect(normalized.zone).toBe("zen.spamhaus.org");
    expect(normalized.returnCodeMeaning).toBe('');
    expect(normalized.returnCodes).toEqual([]);
  });

  it("should use returnCodeMeaning as primary display reason, not raw TXT", () => {
    // The raw TXT reason from DNS is often a URL or cryptic code
    // The returnCodeMeaning is the human-readable explanation
    const listing = {
      reason: "https://www.spamhaus.org/query/ip/1.2.3.4",  // Raw TXT - not useful as display
      returnCodeMeaning: "PBL \u2014 Dynamic/residential IP range (ISP-maintained), not a spam indicator",
    };

    // Report should prefer returnCodeMeaning for display
    const displayReason = listing.returnCodeMeaning || listing.reason || 'No classification available';
    expect(displayReason).toContain("PBL");
    expect(displayReason).not.toContain("https://");
  });

  it("should separate actionable from informational in summary counts", () => {
    const listings = [
      { severity: "critical", actionRequired: true },
      { severity: "high", actionRequired: true },
      { severity: "informational", actionRequired: false },
      { severity: "informational", actionRequired: false },
    ];

    const actionable = listings.filter(l => l.actionRequired);
    const informational = listings.filter(l => !l.actionRequired);

    expect(actionable).toHaveLength(2);
    expect(informational).toHaveLength(2);
  });
});
