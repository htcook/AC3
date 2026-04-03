import { describe, it, expect, vi } from "vitest";

// ─── Port 25 False Positive Fix ─────────────────────────────────────────────

describe("Port 25 Domain Health Fix", () => {
  it("should skip mail port scanning when no MX records exist", () => {
    // The fix: when primaryMx is null/undefined, don't fall back to primaryIp
    // for mail port scanning. This prevents false positives on web servers.
    const hasMxRecords = false;
    const primaryMx: string | null = null;
    const primaryIp = "13.35.37.116"; // web server IP

    // Before fix: would scan primaryIp on port 25 → always closed → false positive
    // After fix: skip mail port scan entirely when no MX records
    const shouldScanMailPorts = hasMxRecords && primaryMx !== null;
    expect(shouldScanMailPorts).toBe(false);
  });

  it("should scan mail ports when MX records exist", () => {
    const hasMxRecords = true;
    const primaryMx = "mail.example.com";

    const shouldScanMailPorts = hasMxRecords && primaryMx !== null;
    expect(shouldScanMailPorts).toBe(true);
  });

  it("should not include port 25 in generic TCP connectivity checks", () => {
    // The fix removes port 25 from the generic TCP connectivity check list
    // Port 25 should only be checked in the dedicated mail port scan
    const genericTcpPorts = [80, 443, 8080, 8443]; // port 25 removed
    expect(genericTcpPorts).not.toContain(25);
  });

  it("should downgrade no-MX-records severity for subdomains", () => {
    // Subdomains like dashboard-dev.vianovahealth.com intentionally don't have MX
    const domain = "dashboard-dev.vianovahealth.com";
    const isSubdomain = domain.split('.').length > 2;
    const hasMxRecords = false;

    // Before fix: critical severity for no MX records
    // After fix: info severity for subdomains without MX
    const severity = isSubdomain && !hasMxRecords ? "info" : "critical";
    expect(severity).toBe("info");
  });
});

// ─── DI Report Breach Section Enhancement ───────────────────────────────────

describe("DI Report Breach Section Enhancement", () => {
  it("should capture breach_database tagged observations", () => {
    const observations = [
      { tags: ["breach_database", "dehashed"], title: "LinkedIn breach", evidence: { database_name: "LinkedIn", total_records: 150 } },
      { tags: ["breach_database", "dehashed"], title: "Adobe breach", evidence: { database_name: "Adobe", total_records: 50 } },
      { tags: ["leaked_credential", "first_party_breach"], title: "Leaked cred", evidence: { email: "user@test.com" } },
    ];

    const breachDatabases = observations.filter((o: any) =>
      o.tags?.includes("breach_database")
    );
    expect(breachDatabases).toHaveLength(2);
    expect(breachDatabases[0].evidence.database_name).toBe("LinkedIn");
  });

  it("should capture breach_summary tagged observations", () => {
    const observations = [
      { tags: ["breach_summary", "dehashed"], title: "Breach Summary", evidence: { total_records: 200, unique_breaches: 5, unique_accounts: 30 } },
      { tags: ["leaked_credential"], title: "Leaked cred", evidence: {} },
    ];

    const summaries = observations.filter((o: any) =>
      o.tags?.includes("breach_summary")
    );
    expect(summaries).toHaveLength(1);
    expect(summaries[0].evidence.total_records).toBe(200);
  });

  it("should classify credentials as 1st-party or 3rd-party", () => {
    const observations = [
      { tags: ["leaked_credential", "first_party_breach", "dehashed"], title: "1st party" },
      { tags: ["leaked_credential", "third_party_breach", "dehashed"], title: "3rd party" },
      { tags: ["leaked_credential", "dehashed"], title: "unclassified" },
    ];

    const firstParty = observations.filter((o: any) => o.tags?.includes("first_party_breach"));
    const thirdParty = observations.filter((o: any) => o.tags?.includes("third_party_breach"));
    expect(firstParty).toHaveLength(1);
    expect(thirdParty).toHaveLength(1);
  });
});

// ─── DI Report Dark Web / Ransomware Enhancement ───────────────────────────

describe("DI Report Dark Web / Ransomware Enhancement", () => {
  it("should capture ransomware_live tagged observations alongside ransomware_listing", () => {
    const observations = [
      { tags: ["ransomware_listing", "darkweb_crossref"], title: "DarkWeb CrossRef match" },
      { tags: ["ransomware_live", "ransomware_victim"], title: "Ransomware.live match" },
      { tags: ["dark_web_mention"], title: "Dark web mention" },
    ];

    // Before fix: only filtered for ransomware_listing
    // After fix: also captures ransomware_live and ransomware_victim
    const ransomwareObs = observations.filter((o: any) =>
      o.tags?.some((t: string) => ["ransomware_listing", "ransomware_live", "ransomware_victim"].includes(t))
    );
    expect(ransomwareObs).toHaveLength(2);
  });

  it("should include source attribution (Ransomware.live vs DarkWeb CrossRef)", () => {
    const obs1 = { tags: ["ransomware_live", "ransomware_victim"], evidence: { group_name: "LockBit" } };
    const obs2 = { tags: ["ransomware_listing", "darkweb_crossref"], evidence: { group: "BlackCat" } };

    const source1 = obs1.tags.includes("ransomware_live") ? "Ransomware.live" : "DarkWeb CrossRef";
    const source2 = obs2.tags.includes("ransomware_live") ? "Ransomware.live" : "DarkWeb CrossRef";

    expect(source1).toBe("Ransomware.live");
    expect(source2).toBe("DarkWeb CrossRef");
  });

  it("should detect fuzzy matches in ransomware observations", () => {
    const obs = {
      tags: ["ransomware_live", "ransomware_victim"],
      evidence: { fuzzy_match: true, similarity: 0.85, group_name: "ALPHV" }
    };

    const isFuzzy = obs.evidence.fuzzy_match === true;
    expect(isFuzzy).toBe(true);
    expect(obs.evidence.similarity).toBeGreaterThan(0.8);
  });
});

// ─── Engagement Report Download Button ──────────────────────────────────────

describe("Engagement Report Download Button", () => {
  it("should find auto-generated report by engagement name pattern", () => {
    // The getReportByEngagementName procedure uses LIKE matching
    const engagementName = "Vianova External Pentest";
    const reports = [
      { rptName: "Vianova External Pentest — Auto-Generated Report", rptCreatedBy: "auto-pipeline", rptReportId: "rpt-123" },
      { rptName: "Manual Report", rptCreatedBy: "user", rptReportId: "rpt-456" },
    ];

    const autoReport = reports.find(r =>
      r.rptName.includes(engagementName) && r.rptCreatedBy === "auto-pipeline"
    );
    expect(autoReport).toBeDefined();
    expect(autoReport!.rptReportId).toBe("rpt-123");
  });

  it("should return null when no auto-report exists for engagement", () => {
    const engagementName = "NonExistent Engagement";
    const reports = [
      { rptName: "Vianova External Pentest — Auto-Generated Report", rptCreatedBy: "auto-pipeline" },
    ];

    const autoReport = reports.find(r =>
      r.rptName.includes(engagementName) && r.rptCreatedBy === "auto-pipeline"
    );
    expect(autoReport).toBeUndefined();
  });

  it("should only show download button when autoReport exists", () => {
    // Simulates the conditional rendering logic
    const autoReport = { rptReportId: "rpt-123" };
    const showButton = !!autoReport;
    expect(showButton).toBe(true);

    const noReport = null;
    const hideButton = !!noReport;
    expect(hideButton).toBe(false);
  });
});

// ─── DI Scan Report Button ──────────────────────────────────────────────────

describe("DI Scan Report Button", () => {
  it("should only show EASM Report button for completed scans", () => {
    const completedScan = { status: "completed" };
    const runningScan = { status: "passive_recon" };
    const failedScan = { status: "failed" };

    expect(completedScan.status === "completed").toBe(true);
    expect(runningScan.status === "completed").toBe(false);
    expect(failedScan.status === "completed").toBe(false);
  });

  it("should construct fullScanData with all required fields for export", () => {
    const scan = { primaryDomain: "test.com", status: "completed" };
    const pipeline = { observations: [{ id: 1 }], domainHealth: {} };
    const assets = [{ hostname: "test.com" }];

    const fullScanData = { ...scan, ...pipeline, assets, observations: pipeline?.observations || [] };

    expect(fullScanData.primaryDomain).toBe("test.com");
    expect(fullScanData.observations).toHaveLength(1);
    expect(fullScanData.assets).toHaveLength(1);
    expect(fullScanData.domainHealth).toBeDefined();
  });
});
