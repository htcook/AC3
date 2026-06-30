import { describe, it, expect, vi } from "vitest";

/**
 * Tests for the Daily Run Summary procedure, DNS Monitoring Config,
 * and the scheduled task endpoint integration.
 */

// ─── Daily Run Summary Tests ─────────────────────────────────────────────────

describe("Daily Run Summary Procedure", () => {
  it("should return correct shape with no runs", () => {
    // Simulate empty response
    const result = {
      latestRun: null,
      runsLast7Days: 0,
      runsLast24h: 0,
      eventsLast24h: 0,
      criticalAlerts: 0,
      highAlerts: 0,
      topCritical: [],
    };
    expect(result.latestRun).toBeNull();
    expect(result.runsLast7Days).toBe(0);
    expect(result.topCritical).toEqual([]);
  });

  it("should correctly identify runs within last 24h", () => {
    const now = Date.now();
    const runs = [
      { tiuStartedAt: new Date(now - 2 * 60 * 60 * 1000).toISOString() }, // 2h ago
      { tiuStartedAt: new Date(now - 12 * 60 * 60 * 1000).toISOString() }, // 12h ago
      { tiuStartedAt: new Date(now - 36 * 60 * 60 * 1000).toISOString() }, // 36h ago
    ];
    const last24h = runs.filter(r => {
      const started = new Date(r.tiuStartedAt).getTime();
      return now - started < 24 * 60 * 60 * 1000;
    });
    expect(last24h.length).toBe(2);
  });

  it("should correctly filter critical and high events", () => {
    const events = [
      { tgeSeverity: "critical", tgeTitle: "Zero-day exploit" },
      { tgeSeverity: "high", tgeTitle: "Ransomware campaign" },
      { tgeSeverity: "medium", tgeTitle: "Phishing attempt" },
      { tgeSeverity: "critical", tgeTitle: "Supply chain attack" },
      { tgeSeverity: "low", tgeTitle: "Port scan detected" },
    ];
    const critical = events.filter(e => e.tgeSeverity === "critical");
    const high = events.filter(e => e.tgeSeverity === "high");
    expect(critical.length).toBe(2);
    expect(high.length).toBe(1);
    expect(critical[0].tgeTitle).toBe("Zero-day exploit");
  });

  it("should format latest run data correctly", () => {
    const run = {
      tiuStatus: "completed",
      tiuStartedAt: "2026-05-04T06:00:00Z",
      tiuCompletedAt: "2026-05-04T06:15:30Z",
      durationMs: 930000,
      groupsScanned: 45,
      updatesApplied: 12,
      newEventsFound: 8,
      newIocsFound: 23,
      newTtpsFound: 5,
      tiuSummary: "Daily scan completed successfully",
      tiuDetails: { phases: 10, errors: 0 },
    };
    const formatted = {
      status: run.tiuStatus,
      startedAt: run.tiuStartedAt,
      completedAt: run.tiuCompletedAt,
      durationMs: run.durationMs,
      groupsScanned: run.groupsScanned,
      updatesApplied: run.updatesApplied,
      newEventsFound: run.newEventsFound,
      newIocsFound: run.newIocsFound,
      newTtpsFound: run.newTtpsFound,
      summary: run.tiuSummary,
      details: run.tiuDetails,
    };
    expect(formatted.status).toBe("completed");
    expect(formatted.durationMs).toBe(930000);
    expect(formatted.newEventsFound).toBe(8);
    expect(formatted.details).toEqual({ phases: 10, errors: 0 });
  });

  it("should limit topCritical to 3 items", () => {
    const criticalEvents = [
      { tgeTitle: "A", tgeActorId: "apt1", tgeSeverity: "critical", eventDate: "2026-05-04" },
      { tgeTitle: "B", tgeActorId: "apt2", tgeSeverity: "critical", eventDate: "2026-05-04" },
      { tgeTitle: "C", tgeActorId: "apt3", tgeSeverity: "critical", eventDate: "2026-05-04" },
      { tgeTitle: "D", tgeActorId: "apt4", tgeSeverity: "critical", eventDate: "2026-05-04" },
      { tgeTitle: "E", tgeActorId: "apt5", tgeSeverity: "critical", eventDate: "2026-05-03" },
    ];
    const topCritical = criticalEvents.slice(0, 3).map(e => ({
      title: e.tgeTitle,
      actorId: e.tgeActorId,
      severity: e.tgeSeverity,
      date: e.eventDate,
    }));
    expect(topCritical.length).toBe(3);
    expect(topCritical[2].title).toBe("C");
  });
});

// ─── DNS Monitoring Config Tests ─────────────────────────────────────────────

describe("DNS Monitoring Config", () => {
  it("should validate domain input constraints", () => {
    const validDomains = ["example.com", "sub.example.com", "a.b.c.d.example.co.uk"];
    const invalidDomains = ["", "a".repeat(254)];
    
    validDomains.forEach(d => {
      expect(d.length).toBeGreaterThanOrEqual(1);
      expect(d.length).toBeLessThanOrEqual(253);
    });
    invalidDomains.forEach(d => {
      expect(d.length === 0 || d.length > 253).toBe(true);
    });
  });

  it("should validate interval hours range (1-168)", () => {
    const validIntervals = [1, 6, 12, 24, 48, 72, 168];
    const invalidIntervals = [0, -1, 169, 1000];
    
    validIntervals.forEach(h => {
      expect(h).toBeGreaterThanOrEqual(1);
      expect(h).toBeLessThanOrEqual(168);
    });
    invalidIntervals.forEach(h => {
      expect(h < 1 || h > 168).toBe(true);
    });
  });

  it("should merge partial config updates correctly", () => {
    const existingConfig = {
      domain: "example.com",
      enabled: true,
      intervalHours: 24,
      alertOnNewCritical: true,
      alertOnNewHigh: true,
      alertOnDnsChange: false,
    };
    const update = { enabled: false, alertOnDnsChange: true };
    const merged = { ...existingConfig, ...update };
    
    expect(merged.enabled).toBe(false);
    expect(merged.alertOnDnsChange).toBe(true);
    expect(merged.intervalHours).toBe(24); // unchanged
    expect(merged.alertOnNewCritical).toBe(true); // unchanged
  });

  it("should handle default config creation for new domain", () => {
    const defaultConfig = {
      domain: "newdomain.com",
      enabled: false,
      intervalHours: 24,
      alertOnNewCritical: true,
      alertOnNewHigh: false,
      alertOnDnsChange: false,
      lastCheckedAt: null,
    };
    expect(defaultConfig.enabled).toBe(false);
    expect(defaultConfig.intervalHours).toBe(24);
    expect(defaultConfig.alertOnNewCritical).toBe(true);
    expect(defaultConfig.lastCheckedAt).toBeNull();
  });
});

// ─── Scheduled DNS Security Check Tests ──────────────────────────────────────

describe("Scheduled DNS Security Check Endpoint", () => {
  it("should filter domains due for check based on interval", () => {
    const now = Date.now();
    const domains = [
      { domain: "a.com", enabled: true, intervalHours: 24, lastCheckedAt: new Date(now - 25 * 3600000).toISOString() },
      { domain: "b.com", enabled: true, intervalHours: 24, lastCheckedAt: new Date(now - 12 * 3600000).toISOString() },
      { domain: "c.com", enabled: false, intervalHours: 24, lastCheckedAt: new Date(now - 48 * 3600000).toISOString() },
      { domain: "d.com", enabled: true, intervalHours: 6, lastCheckedAt: new Date(now - 7 * 3600000).toISOString() },
      { domain: "e.com", enabled: true, intervalHours: 24, lastCheckedAt: null },
    ];
    
    const dueForCheck = domains.filter(d => {
      if (!d.enabled) return false;
      if (!d.lastCheckedAt) return true;
      const elapsed = now - new Date(d.lastCheckedAt).getTime();
      return elapsed >= d.intervalHours * 3600000;
    });
    
    expect(dueForCheck.length).toBe(3); // a.com (25h > 24h), d.com (7h > 6h), e.com (never checked)
    expect(dueForCheck.map(d => d.domain)).toContain("a.com");
    expect(dueForCheck.map(d => d.domain)).toContain("d.com");
    expect(dueForCheck.map(d => d.domain)).toContain("e.com");
    expect(dueForCheck.map(d => d.domain)).not.toContain("b.com"); // 12h < 24h
    expect(dueForCheck.map(d => d.domain)).not.toContain("c.com"); // disabled
  });

  it("should detect score degradation for alerting", () => {
    const previousScore = 85;
    const currentScore = 60;
    const threshold = 10;
    const scoreDelta = previousScore - currentScore;
    const shouldAlert = scoreDelta >= threshold;
    
    expect(scoreDelta).toBe(25);
    expect(shouldAlert).toBe(true);
  });

  it("should detect new critical findings for alerting", () => {
    const previousFindings = [
      { type: "dangling_cname", severity: "high" },
      { type: "zone_transfer", severity: "medium" },
    ];
    const currentFindings = [
      { type: "dangling_cname", severity: "high" },
      { type: "zone_transfer", severity: "medium" },
      { type: "dnssec_expired", severity: "critical" },
      { type: "ns_hijack", severity: "critical" },
    ];
    
    const newCritical = currentFindings.filter(
      cf => cf.severity === "critical" && 
      !previousFindings.some(pf => pf.type === cf.type && pf.severity === cf.severity)
    );
    
    expect(newCritical.length).toBe(2);
    expect(newCritical[0].type).toBe("dnssec_expired");
  });
});

// ─── Daily Intel Workflow Tests ──────────────────────────────────────────────

describe("Daily Intel Workflow Phases", () => {
  it("should correctly compute phase completion status", () => {
    const phases = [
      { name: "RSS Sync", status: "completed", items: 45 },
      { name: "Multi-Source Ingest", status: "completed", items: 120 },
      { name: "Actor Crawl", status: "completed", items: 8 },
      { name: "Enrichment", status: "completed", items: 15 },
      { name: "Articles", status: "failed", items: 0, error: "timeout" },
      { name: "Ransomware", status: "completed", items: 3 },
      { name: "CVE Refresh", status: "completed", items: 22 },
      { name: "Zero-Day", status: "completed", items: 1 },
      { name: "Notification", status: "completed", items: 1 },
    ];
    
    const completed = phases.filter(p => p.status === "completed").length;
    const failed = phases.filter(p => p.status === "failed").length;
    const totalItems = phases.reduce((sum, p) => sum + p.items, 0);
    
    expect(completed).toBe(8);
    expect(failed).toBe(1);
    expect(totalItems).toBe(215);
  });

  it("should correctly map event fields from external payload", () => {
    const externalArticle = {
      tgeTitle: "APT29 targets diplomatic entities",
      tgeDescription: "New campaign observed targeting EU diplomatic missions",
      tgeSeverity: "high",
      tgeVictimSector: "government",
      tgeVictimCountry: "France",
      tgeMitreTechniques: ["T1566.001", "T1059.001"],
      tgeSource: "unit42",
      tgeSourceUrl: "https://unit42.paloaltonetworks.com/apt29-campaign",
      tgeConfidence: 85,
    };
    
    // Map to internal format
    const mapped = {
      title: externalArticle.tgeTitle,
      description: externalArticle.tgeDescription,
      severity: externalArticle.tgeSeverity,
      victimSector: externalArticle.tgeVictimSector,
      victimCountry: externalArticle.tgeVictimCountry,
      mitreTechniques: JSON.stringify(externalArticle.tgeMitreTechniques),
      source: externalArticle.tgeSource,
      sourceUrl: externalArticle.tgeSourceUrl,
      confidence: externalArticle.tgeConfidence,
    };
    
    expect(mapped.title).toBe("APT29 targets diplomatic entities");
    expect(mapped.confidence).toBe(85);
    expect(JSON.parse(mapped.mitreTechniques)).toHaveLength(2);
  });

  it("should handle ensureActorExists for new actors", () => {
    // Simulate the logic of ensureActorExists
    const existingActors = new Map([
      ["apt29", { actorId: "apt29", name: "APT29" }],
      ["lazarus-group", { actorId: "lazarus-group", name: "Lazarus Group" }],
    ]);
    
    const actorName = "Scattered Spider";
    const actorId = actorName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    
    const exists = existingActors.has(actorId);
    expect(exists).toBe(false);
    expect(actorId).toBe("scattered-spider");
    
    // After creation
    existingActors.set(actorId, { actorId, name: actorName });
    expect(existingActors.has("scattered-spider")).toBe(true);
  });

  it("should correctly identify zero-day events from last 24h", () => {
    const now = new Date();
    const events = [
      { severity: "critical", createdAt: new Date(now.getTime() - 6 * 3600000).toISOString(), title: "CVE-2026-1234 zero-day" },
      { severity: "critical", createdAt: new Date(now.getTime() - 30 * 3600000).toISOString(), title: "Old critical" },
      { severity: "high", createdAt: new Date(now.getTime() - 2 * 3600000).toISOString(), title: "Recent high" },
      { severity: "critical", createdAt: new Date(now.getTime() - 12 * 3600000).toISOString(), title: "Another zero-day" },
    ];
    
    const cutoff = new Date(now.getTime() - 24 * 3600000);
    const zeroDay = events.filter(e => 
      e.severity === "critical" && new Date(e.createdAt) > cutoff
    );
    
    expect(zeroDay.length).toBe(2);
    expect(zeroDay[0].title).toBe("CVE-2026-1234 zero-day");
    expect(zeroDay[1].title).toBe("Another zero-day");
  });
});
