import { describe, it, expect } from "vitest";

// ─── Gov Access Broker Monitor Tests ──────────────────────────────────────

describe("Gov Access Broker Monitor", () => {
  it("should be importable", async () => {
    const mod = await import("./lib/gov-access-broker-monitor");
    expect(mod.GOV_IAB_KNOWLEDGE_BASE).toBeDefined();
    expect(mod.getKnownGovBrokers).toBeDefined();
    expect(mod.searchGovBrokers).toBeDefined();
    expect(mod.detectGovTargeting).toBeDefined();
    expect(mod.calculateGovRiskScore).toBeDefined();
    expect(mod.enrichWithGovIntel).toBeDefined();
    expect(mod.getGovBrokerStats).toBeDefined();
    expect(mod.getForumActivityPatterns).toBeDefined();
  });

  // ─── Knowledge Base ──────────────────────────────────────────────────────

  it("should have a populated knowledge base with known gov IABs", async () => {
    const { GOV_IAB_KNOWLEDGE_BASE } = await import("./lib/gov-access-broker-monitor");
    expect(GOV_IAB_KNOWLEDGE_BASE.length).toBeGreaterThanOrEqual(10);
    for (const profile of GOV_IAB_KNOWLEDGE_BASE) {
      expect(profile.brokerId).toBeTruthy();
      expect(profile.brokerName).toBeTruthy();
      expect(profile.riskScore).toBeGreaterThanOrEqual(0);
      expect(profile.riskScore).toBeLessThanOrEqual(100);
      expect(profile.govTargeting.agencies.length).toBeGreaterThan(0);
      expect(profile.govTargeting.domains.length).toBeGreaterThan(0);
    }
  });

  it("should include Pioneer Kitten as a known state-sponsored IAB", async () => {
    const { GOV_IAB_KNOWLEDGE_BASE } = await import("./lib/gov-access-broker-monitor");
    const pk = GOV_IAB_KNOWLEDGE_BASE.find(b => b.brokerId === "iab-pioneer-kitten");
    expect(pk).toBeDefined();
    expect(pk!.sponsorship).toBe("state-sponsored");
    expect(pk!.attribution).toContain("Iran");
    expect(pk!.aliases).toContain("Fox Kitten");
    expect(pk!.mitreTechniques.length).toBeGreaterThan(0);
    expect(pk!.cisaAdvisories.length).toBeGreaterThan(0);
  });

  it("should include Scattered Spider as a known hybrid IAB", async () => {
    const { GOV_IAB_KNOWLEDGE_BASE } = await import("./lib/gov-access-broker-monitor");
    const ss = GOV_IAB_KNOWLEDGE_BASE.find(b => b.brokerId === "iab-scattered-spider");
    expect(ss).toBeDefined();
    expect(ss!.sponsorship).toBe("cybercrime");
    expect(ss!.accessTypes).toContain("cloud_access");
  });

  it("should have profiles with MITRE techniques and CISA advisories", async () => {
    const { GOV_IAB_KNOWLEDGE_BASE } = await import("./lib/gov-access-broker-monitor");
    const withMitre = GOV_IAB_KNOWLEDGE_BASE.filter(b => b.mitreTechniques.length > 0);
    expect(withMitre.length).toBeGreaterThanOrEqual(5);
    const withCisa = GOV_IAB_KNOWLEDGE_BASE.filter(b => b.cisaAdvisories.length > 0);
    expect(withCisa.length).toBeGreaterThanOrEqual(3);
  });

  // ─── Search ──────────────────────────────────────────────────────────────

  it("should return all brokers when no search query", async () => {
    const { getKnownGovBrokers, GOV_IAB_KNOWLEDGE_BASE } = await import("./lib/gov-access-broker-monitor");
    const all = getKnownGovBrokers();
    expect(all.length).toBe(GOV_IAB_KNOWLEDGE_BASE.length);
  });

  it("should search brokers by name", async () => {
    const { searchGovBrokers } = await import("./lib/gov-access-broker-monitor");
    const results = searchGovBrokers("pioneer");
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results.some(b => b.brokerName.toLowerCase().includes("pioneer"))).toBe(true);
  });

  it("should search brokers by alias", async () => {
    const { searchGovBrokers } = await import("./lib/gov-access-broker-monitor");
    const results = searchGovBrokers("fox kitten");
    expect(results.length).toBeGreaterThanOrEqual(1);
  });

  it("should search brokers by agency target", async () => {
    const { searchGovBrokers } = await import("./lib/gov-access-broker-monitor");
    const results = searchGovBrokers("DOD");
    expect(results.length).toBeGreaterThanOrEqual(1);
  });

  it("should search brokers by linked group", async () => {
    const { searchGovBrokers } = await import("./lib/gov-access-broker-monitor");
    const results = searchGovBrokers("ALPHV");
    expect(results.length).toBeGreaterThanOrEqual(1);
  });

  it("should return empty array for non-matching search", async () => {
    const { searchGovBrokers } = await import("./lib/gov-access-broker-monitor");
    const results = searchGovBrokers("xyznonexistent12345");
    expect(results.length).toBe(0);
  });

  // ─── Gov Targeting Detection ─────────────────────────────────────────────

  it("should detect gov targeting from .gov domain", async () => {
    const { detectGovTargeting } = await import("./lib/gov-access-broker-monitor");
    const result = detectGovTargeting({
      victimSector: "Technology",
      victimCountry: "United States",
      description: "VPN access to network at agency.gov",
    });
    expect(result.isGov).toBe(true);
    expect(result.confidence).toBeGreaterThan(0);
  });

  it("should detect gov targeting from government sector", async () => {
    const { detectGovTargeting } = await import("./lib/gov-access-broker-monitor");
    const result = detectGovTargeting({
      victimSector: "Government",
      victimCountry: "United States",
    });
    expect(result.isGov).toBe(true);
  });

  it("should detect gov targeting from federal agency keywords", async () => {
    const { detectGovTargeting } = await import("./lib/gov-access-broker-monitor");
    const result = detectGovTargeting({
      victimSector: "Unknown",
      victimCountry: "US",
      description: "RDP access to Department of Defense contractor network",
    });
    expect(result.isGov).toBe(true);
    expect(result.matchedPatterns.length).toBeGreaterThan(0);
  });

  it("should not flag non-gov targets", async () => {
    const { detectGovTargeting } = await import("./lib/gov-access-broker-monitor");
    const result = detectGovTargeting({
      victimSector: "Retail",
      victimCountry: "Germany",
      description: "Access to small e-commerce shop",
    });
    expect(result.isGov).toBe(false);
  });

  it("should detect .mil domain targeting", async () => {
    const { detectGovTargeting } = await import("./lib/gov-access-broker-monitor");
    const result = detectGovTargeting({
      victimSector: "Unknown",
      victimCountry: "United States",
      description: "Citrix access to network at army.mil",
    });
    expect(result.isGov).toBe(true);
  });

  // ─── Risk Score Calculation ──────────────────────────────────────────────

  it("should calculate higher risk for domain admin access", async () => {
    const { calculateGovRiskScore } = await import("./lib/gov-access-broker-monitor");
    const highRisk = calculateGovRiskScore({
      accessLevel: "domain_admin",
      accessType: "vpn_access",
      askingPrice: "$50,000",
      brokerReputation: "established",
      govConfidence: 90,
    });
    const lowRisk = calculateGovRiskScore({
      accessLevel: "user",
      accessType: "webshell",
      askingPrice: "$500",
      brokerReputation: "new",
      govConfidence: 20,
    });
    expect(highRisk.score).toBeGreaterThan(lowRisk.score);
  });

  it("should factor in broker reputation", async () => {
    const { calculateGovRiskScore } = await import("./lib/gov-access-broker-monitor");
    const established = calculateGovRiskScore({
      accessLevel: "local_admin",
      accessType: "rdp_access",
      askingPrice: "$10,000",
      brokerReputation: "established",
      govConfidence: 80,
    });
    const newBroker = calculateGovRiskScore({
      accessLevel: "local_admin",
      accessType: "rdp_access",
      askingPrice: "$10,000",
      brokerReputation: "new",
      govConfidence: 80,
    });
    expect(established.score).toBeGreaterThan(newBroker.score);
  });

  it("should return score between 0 and 100", async () => {
    const { calculateGovRiskScore } = await import("./lib/gov-access-broker-monitor");
    const result = calculateGovRiskScore({
      accessLevel: "domain_admin",
      accessType: "vpn_access",
      askingPrice: "$100,000",
      brokerReputation: "established",
      govConfidence: 95,
    });
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(result.factors.length).toBeGreaterThan(0);
  });

  // ─── Enrichment ──────────────────────────────────────────────────────────

  it("should enrich a gov-targeting listing with full context", async () => {
    const { enrichWithGovIntel } = await import("./lib/gov-access-broker-monitor");
    const result = enrichWithGovIntel({
      brokerId: "iab-pioneer-kitten",
      brokerName: "Pioneer Kitten",
      victimSector: "Government",
      victimCountry: "United States",
      description: "VPN access to federal agency network",
      accessType: "vpn_access",
      accessLevel: "domain_admin",
      askingPrice: "$50,000",
      brokerReputation: "established",
    });
    expect(result.isGovTarget).toBe(true);
    expect(result.knownProfile).toBeDefined();
    expect(result.knownProfile!.brokerName).toBe("Pioneer Kitten");
    expect(result.riskScore).toBeGreaterThan(0);
    expect(result.riskFactors.length).toBeGreaterThan(0);
  });

  it("should enrich an unknown broker with gov detection", async () => {
    const { enrichWithGovIntel } = await import("./lib/gov-access-broker-monitor");
    const result = enrichWithGovIntel({
      brokerId: "unknown-123",
      brokerName: "NewBroker2025",
      victimSector: "Government",
      victimCountry: "United States",
      description: "Citrix access to state.gov email system",
      accessType: "citrix_access",
      accessLevel: "local_admin",
      askingPrice: "$25,000",
      brokerReputation: "rising",
    });
    expect(result.isGovTarget).toBe(true);
    expect(result.knownProfile).toBeNull();
    expect(result.riskScore).toBeGreaterThan(0);
    expect(result.matchedPatterns.length).toBeGreaterThan(0);
  });

  it("should not enrich a non-gov listing", async () => {
    const { enrichWithGovIntel } = await import("./lib/gov-access-broker-monitor");
    const result = enrichWithGovIntel({
      brokerId: "random-broker",
      brokerName: "RandomBroker",
      victimSector: "Retail",
      victimCountry: "Brazil",
      description: "Access to small online store",
      accessType: "webshell",
      accessLevel: "user",
      askingPrice: "$200",
      brokerReputation: "new",
    });
    expect(result.isGovTarget).toBe(false);
  });

  // ─── Stats ───────────────────────────────────────────────────────────────

  it("should return comprehensive gov broker stats", async () => {
    const { getGovBrokerStats } = await import("./lib/gov-access-broker-monitor");
    const stats = getGovBrokerStats();
    expect(stats.totalKnownBrokers).toBeGreaterThanOrEqual(10);
    expect(stats.activeBrokers).toBeGreaterThanOrEqual(0);
    expect(stats.activeBrokers).toBeLessThanOrEqual(stats.totalKnownBrokers);
    expect(stats.avgAskingPrice).toBeGreaterThan(0);
    expect(stats.totalForumListings).toBeGreaterThan(0);
    expect(stats.topTargetedAgencies.length).toBeGreaterThan(0);
    expect(stats.topTargetedAgencies[0].agency).toBeTruthy();
    expect(stats.topTargetedAgencies[0].count).toBeGreaterThan(0);
  });

  it("should have stats sorted by count descending", async () => {
    const { getGovBrokerStats } = await import("./lib/gov-access-broker-monitor");
    const stats = getGovBrokerStats();
    for (let i = 1; i < stats.topTargetedAgencies.length; i++) {
      expect(stats.topTargetedAgencies[i - 1].count).toBeGreaterThanOrEqual(
        stats.topTargetedAgencies[i].count
      );
    }
  });

  // ─── Forum Activity ──────────────────────────────────────────────────────

  it("should return forum activity patterns", async () => {
    const { getForumActivityPatterns } = await import("./lib/gov-access-broker-monitor");
    const patterns = getForumActivityPatterns();
    expect(patterns.length).toBeGreaterThan(0);
    for (const p of patterns) {
      expect(p.forum).toBeTruthy();
      expect(p.govListings).toBeGreaterThanOrEqual(0);
      expect(p.avgPrice).toBeGreaterThanOrEqual(0);
      expect(p.riskLevel).toMatch(/^(critical|high|medium|low)$/);
      expect(p.topAccessTypes.length).toBeGreaterThan(0);
    }
  });

  it("should include known dark web forums", async () => {
    const { getForumActivityPatterns } = await import("./lib/gov-access-broker-monitor");
    const patterns = getForumActivityPatterns();
    const forumNames = patterns.map(p => p.forum.toLowerCase());
    // Should include at least some of the major forums
    const knownForums = ["exploit", "ramp", "xss", "breachforums"];
    const foundCount = knownForums.filter(f => forumNames.some(fn => fn.includes(f))).length;
    expect(foundCount).toBeGreaterThanOrEqual(2);
  });

  it("should have forum patterns with valid risk levels", async () => {
    const { getForumActivityPatterns } = await import("./lib/gov-access-broker-monitor");
    const patterns = getForumActivityPatterns();
    const riskLevels = new Set(patterns.map(p => p.riskLevel));
    expect(riskLevels.size).toBeGreaterThanOrEqual(2); // Should have at least 2 different risk levels
  });
});
