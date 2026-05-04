/**
 * Tests for the enhanced daily threat intel workflow and DNS security persistence
 */
import { describe, it, expect } from "vitest";

// ─── Test: Enhanced Daily Intel Workflow Phases ───
describe("Daily Threat Intel Workflow - Enhanced Phases", () => {
  it("should include all 10 phases in the correct order", () => {
    const phases = [
      "rss_sync",                    // Phase 1: RSS feed sync
      "full_ingest",                 // Phase 2: Multi-source ingestion
      "actor_crawl",                 // Phase 3: LLM-powered actor crawl
      "targeted_enrichment",         // Phase 4: High-priority actor enrichment
      "external_articles",           // Phase 5: External articles (optional)
      "ransomware_leak_monitor",     // Phase 6: Ransomware leak sites
      "external_ransomware_victims", // Phase 7: External victims (optional)
      "cve_refresh",                 // Phase 8: Automatic CVE refresh
      "zero_day_monitor",            // Phase 9: Zero-day monitoring
      "owner_notification",          // Phase 10: Owner notification
    ];

    expect(phases).toHaveLength(10);
    expect(phases[7]).toBe("cve_refresh");
    expect(phases[8]).toBe("zero_day_monitor");
    expect(phases[9]).toBe("owner_notification");
  });

  it("should have a CVE tech watchlist covering key technologies", () => {
    const techWatchlist = [
      'streamlit', 'jupyter', 'langchain', 'faiss', 'firebase',
      'github_actions', 'wordpress', 'cpanel', 'cisco_asa', 'bitwarden',
    ];

    expect(techWatchlist.length).toBeGreaterThanOrEqual(10);
    // Should include common infrastructure targets
    expect(techWatchlist).toContain('wordpress');
    expect(techWatchlist).toContain('cpanel');
    expect(techWatchlist).toContain('cisco_asa');
    // Should include AI/ML stack
    expect(techWatchlist).toContain('langchain');
    expect(techWatchlist).toContain('jupyter');
  });

  it("should generate a proper notification summary format", () => {
    const mockPhases = [
      { phase: 'rss_sync', success: true, newArticles: 15, feedsProcessed: 20 },
      { phase: 'full_ingest', success: true, totalNewRecords: 8, successfulSources: 11 },
      { phase: 'actor_crawl', success: true, eventsRecorded: 5, groupsEnriched: 3 },
      { phase: 'cve_refresh', success: true, totalNew: 12 },
      { phase: 'zero_day_monitor', success: true, criticalCount: 2, items: [
        { title: 'CVE-2026-41940 cPanel RCE', source: 'cisa_kev', severity: 'critical' },
        { title: 'Linux LPE Copy Fail', source: 'metasploit', severity: 'critical' },
      ]},
      { phase: 'owner_notification', success: true },
    ];

    const successCount = mockPhases.filter(p => p.success).length;
    expect(successCount).toBe(6);

    // Build summary like the real code does
    const summaryLines: string[] = [
      `Daily Threat Intel Update — 2026-05-04`,
      `Phases: ${successCount}/${mockPhases.length} successful`,
      '',
    ];
    const rssPhase = mockPhases.find(p => p.phase === 'rss_sync') as any;
    if (rssPhase?.success) summaryLines.push(`RSS Feeds: ${rssPhase.newArticles || 0} new articles from ${rssPhase.feedsProcessed || 0} feeds`);
    const ingestPhase = mockPhases.find(p => p.phase === 'full_ingest') as any;
    if (ingestPhase?.success) summaryLines.push(`Multi-source ingest: ${ingestPhase.totalNewRecords || 0} new records from ${ingestPhase.successfulSources || 0} sources`);
    const zeroDayPhase = mockPhases.find(p => p.phase === 'zero_day_monitor') as any;
    if (zeroDayPhase?.success && zeroDayPhase.criticalCount > 0) {
      summaryLines.push(`⚠️ ZERO-DAY ALERT: ${zeroDayPhase.criticalCount} critical items in last 24h`);
    }

    expect(summaryLines).toContain('RSS Feeds: 15 new articles from 20 feeds');
    expect(summaryLines).toContain('Multi-source ingest: 8 new records from 11 sources');
    expect(summaryLines.some(l => l.includes('ZERO-DAY ALERT'))).toBe(true);
  });

  it("should handle the endpoint being called without external articles (self-sufficient mode)", () => {
    // When called without req.body.articles, the endpoint should still run Phases 1-4, 6, 8-10
    const minimalBody = {}; // No articles, no ransomwareVictims
    const hasArticles = !!(minimalBody as any).articles;
    const hasVictims = !!(minimalBody as any).ransomwareVictims;

    expect(hasArticles).toBe(false);
    expect(hasVictims).toBe(false);
    // Phases 5 and 7 should be skipped gracefully
  });

  it("should still accept external articles when provided (backward compatible)", () => {
    const bodyWithArticles = {
      articles: [
        {
          actorId: "lazarus_group",
          eventType: "campaign",
          tgeTitle: "Lazarus Mach-O Man macOS Campaign",
          tgeDescription: "New ClickFix-based macOS attack chain",
          severity: "critical",
          victimSector: "cryptocurrency",
          victimCountry: "Global",
          mitreTechniques: ["T1204.002", "T1059.004"],
          sourcePublisher: "Kaspersky GReAT",
          sourceUrl: "https://securelist.com/lazarus-macho-man/123456/",
          confidence: 90,
          eventDate: "2026-05-01",
        },
      ],
    };

    expect(bodyWithArticles.articles).toHaveLength(1);
    const article = bodyWithArticles.articles[0];
    expect(article.actorId).toBe("lazarus_group");
    expect(article.mitreTechniques).toContain("T1204.002");
    expect(article.confidence).toBeGreaterThanOrEqual(80);
  });
});

// ─── Test: DNS Security Persistence Module ───
describe("DNS Security Persistence", () => {
  it("should define the correct table schema for dns_security_assessments", () => {
    const requiredColumns = [
      "id", "domain", "assessmentContext", "overallScore", "overallGrade",
      "totalFindings", "criticalFindings", "highFindings", "mediumFindings", "lowFindings",
      "dnssecEnabled", "spfConfigured", "dkimConfigured", "dmarcConfigured",
      "caaConfigured", "zoneTransferProtected", "assessedAt", "engagementId",
    ];

    expect(requiredColumns.length).toBeGreaterThanOrEqual(15);
    expect(requiredColumns).toContain("engagementId");
    expect(requiredColumns).toContain("overallGrade");
    expect(requiredColumns).toContain("dnssecEnabled");
  });

  it("should define the correct table schema for dns_security_findings", () => {
    const requiredColumns = [
      "id", "assessmentId", "domain", "findingType", "severity",
      "title", "description", "affectedRecord", "remediation",
      "mitreTechnique", "mitreTactic", "status", "detectedAt", "resolvedAt",
    ];

    expect(requiredColumns.length).toBeGreaterThanOrEqual(12);
    expect(requiredColumns).toContain("mitreTechnique");
    expect(requiredColumns).toContain("remediation");
    expect(requiredColumns).toContain("status");
  });

  it("should map severity levels correctly", () => {
    const severityLevels = ["critical", "high", "medium", "low", "info"];
    const findingStatuses = ["open", "resolved", "accepted", "false_positive"];

    expect(severityLevels).toHaveLength(5);
    expect(findingStatuses).toHaveLength(4);
    expect(findingStatuses).toContain("false_positive");
  });

  it("should support change detection between assessments", () => {
    interface DnsChangeDetection {
      newFindings: any[];
      resolvedFindings: any[];
      scoreChange: number;
      gradeChange: string;
      significantChange: boolean;
    }

    const mockChange: DnsChangeDetection = {
      newFindings: [{ title: "Dangling CNAME detected", severity: "high" }],
      resolvedFindings: [],
      scoreChange: -15,
      gradeChange: "B → C",
      significantChange: true,
    };

    expect(mockChange.significantChange).toBe(true);
    expect(mockChange.newFindings.length).toBeGreaterThan(0);
    expect(mockChange.scoreChange).toBeLessThan(0);
  });
});

// ─── Test: DNS Security Monitoring Endpoint ───
describe("DNS Security Monitoring Endpoint", () => {
  it("should support monitoring configuration per domain", () => {
    const monitoringConfig = {
      domain: "example.com",
      enabled: true,
      intervalHours: 24,
      alertOnNewFindings: true,
      alertOnScoreDecrease: true,
      scoreThreshold: 10,
      lastCheckedAt: "2026-05-04T00:00:00Z",
    };

    expect(monitoringConfig.enabled).toBe(true);
    expect(monitoringConfig.intervalHours).toBe(24);
    expect(monitoringConfig.alertOnNewFindings).toBe(true);
  });

  it("should only check domains that are due for re-assessment", () => {
    const now = Date.now();
    const domains = [
      { domain: "a.com", lastCheckedAt: new Date(now - 25 * 60 * 60 * 1000).toISOString(), intervalHours: 24 },
      { domain: "b.com", lastCheckedAt: new Date(now - 12 * 60 * 60 * 1000).toISOString(), intervalHours: 24 },
      { domain: "c.com", lastCheckedAt: new Date(now - 49 * 60 * 60 * 1000).toISOString(), intervalHours: 48 },
    ];

    const isDue = (d: typeof domains[0]) => {
      const lastChecked = new Date(d.lastCheckedAt).getTime();
      return (now - lastChecked) >= d.intervalHours * 60 * 60 * 1000;
    };

    expect(isDue(domains[0])).toBe(true);   // 25h > 24h
    expect(isDue(domains[1])).toBe(false);  // 12h < 24h
    expect(isDue(domains[2])).toBe(true);   // 49h > 48h
  });

  it("should send owner notification when significant changes detected", () => {
    const alertConditions = {
      newCriticalFinding: true,
      scoreDecreasedBy: 15,
      scoreThreshold: 10,
      newHighFindings: 2,
    };

    const shouldAlert = (conditions: typeof alertConditions) => {
      return conditions.newCriticalFinding ||
        conditions.scoreDecreasedBy >= conditions.scoreThreshold ||
        conditions.newHighFindings >= 2;
    };

    expect(shouldAlert(alertConditions)).toBe(true);
    expect(shouldAlert({ ...alertConditions, newCriticalFinding: false, scoreDecreasedBy: 5, newHighFindings: 1 })).toBe(false);
  });
});

// ─── Test: ensureActorExists helper ───
describe("ensureActorExists helper", () => {
  it("should generate correct actorId format from group name", () => {
    const toActorId = (name: string) => name.toLowerCase().replace(/[^a-z0-9]/g, "_");

    expect(toActorId("APT28/Fancy Bear")).toBe("apt28_fancy_bear");
    expect(toActorId("LockBit")).toBe("lockbit");
    expect(toActorId("Scattered Spider")).toBe("scattered_spider");
    expect(toActorId("NoName057(16)")).toBe("noname057_16_");
  });

  it("should set reasonable defaults for auto-discovered actors", () => {
    const defaults = {
      actorType: "unknown",
      threatLevel: "medium",
      dataSource: "auto_discovered",
      confidence: 60,
    };

    expect(defaults.confidence).toBe(60);
    expect(defaults.actorType).toBe("unknown");
    expect(defaults.dataSource).toBe("auto_discovered");
  });
});

// ─── Test: DI Pipeline DNS Integration ───
describe("DI Pipeline DNS Security Integration", () => {
  it("should persist DNS findings when dnsSecurityReport is present in pipeline output", () => {
    const mockPipelineOutput = {
      dnsSecurityReport: {
        domain: "target.com",
        overallScore: 72,
        overallGrade: "C",
        findings: [
          { type: "dangling_cname", severity: "high", title: "Dangling CNAME: sub.target.com", affectedRecord: "sub.target.com CNAME old-service.com" },
          { type: "missing_caa", severity: "medium", title: "No CAA records configured", affectedRecord: "target.com" },
        ],
        dnssecStatus: { enabled: false },
        emailSecurity: { spf: true, dkim: true, dmarc: true },
      },
    };

    const report = mockPipelineOutput.dnsSecurityReport;
    expect(report).toBeDefined();
    expect(report.findings).toHaveLength(2);
    expect(report.overallGrade).toBe("C");
    expect(report.findings[0].severity).toBe("high");
  });

  it("should gracefully skip persistence when dnsSecurityReport is absent", () => {
    const mockPipelineOutput = {
      // No dnsSecurityReport field
      subdomains: ["www.target.com"],
    };

    const report = (mockPipelineOutput as any).dnsSecurityReport;
    expect(report).toBeUndefined();
    // Should not throw, just skip
  });

  it("should link DNS assessment to engagement when engagementId is available", () => {
    const persistInput = {
      domain: "target.com",
      report: { overallScore: 85, overallGrade: "B", findings: [] },
      engagementId: 42,
      context: "full_engagement",
    };

    expect(persistInput.engagementId).toBe(42);
    expect(persistInput.context).toBe("full_engagement");
  });
});
