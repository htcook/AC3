/**
 * Tests for:
 * 1. Discovery Context History Snapshotting logic
 * 2. Comparison diff detection (change detection between snapshots)
 * 3. Export CSV column structure and formatting
 * 4. Export Markdown report structure
 */
import { describe, it, expect } from "vitest";

// ─── Snapshot History Logic ─────────────────────────────────────────

describe("Discovery Context History Snapshotting", () => {
  // Replicate the server-side snapshotting logic for unit testing
  function buildHistorySnapshot(
    existing: { discoveryContext: any; discoveryContextHistory: any; discoveryContextAnalyzedAt: string | null } | null,
    newContext: any,
  ) {
    let history: any[] = [];
    if (existing?.discoveryContextHistory && Array.isArray(existing.discoveryContextHistory)) {
      history = [...existing.discoveryContextHistory];
    }
    if (existing?.discoveryContext) {
      history.push({
        context: existing.discoveryContext,
        analyzedAt: existing.discoveryContextAnalyzedAt || new Date().toISOString(),
        snapshotId: `snap-${Date.now()}`,
      });
      if (history.length > 10) history = history.slice(-10);
    }
    return history;
  }

  it("creates empty history when no previous context exists", () => {
    const history = buildHistorySnapshot(null, { some: "new context" });
    expect(history).toEqual([]);
  });

  it("creates empty history when existing has null discoveryContext", () => {
    const history = buildHistorySnapshot(
      { discoveryContext: null, discoveryContextHistory: null, discoveryContextAnalyzedAt: null },
      { some: "new context" },
    );
    expect(history).toEqual([]);
  });

  it("snapshots previous context into history on first re-analysis", () => {
    const existing = {
      discoveryContext: { attribution: { primaryClaim: { attributedTo: { organization: "Acme" } } } },
      discoveryContextHistory: null,
      discoveryContextAnalyzedAt: "2025-01-15 10:00:00",
    };
    const history = buildHistorySnapshot(existing, { attribution: { primaryClaim: { attributedTo: { organization: "Acme Corp" } } } });
    expect(history).toHaveLength(1);
    expect(history[0].context.attribution.primaryClaim.attributedTo.organization).toBe("Acme");
    expect(history[0].analyzedAt).toBe("2025-01-15 10:00:00");
    expect(history[0].snapshotId).toMatch(/^snap-\d+$/);
  });

  it("appends to existing history", () => {
    const existing = {
      discoveryContext: { version: 2 },
      discoveryContextHistory: [
        { context: { version: 1 }, analyzedAt: "2025-01-10 08:00:00", snapshotId: "snap-100" },
      ],
      discoveryContextAnalyzedAt: "2025-01-15 10:00:00",
    };
    const history = buildHistorySnapshot(existing, { version: 3 });
    expect(history).toHaveLength(2);
    expect(history[0].context.version).toBe(1);
    expect(history[1].context.version).toBe(2);
  });

  it("caps history at 10 snapshots", () => {
    const existingHistory = Array.from({ length: 10 }, (_, i) => ({
      context: { version: i },
      analyzedAt: `2025-01-${String(i + 1).padStart(2, "0")} 08:00:00`,
      snapshotId: `snap-${i}`,
    }));
    const existing = {
      discoveryContext: { version: 10 },
      discoveryContextHistory: existingHistory,
      discoveryContextAnalyzedAt: "2025-01-11 08:00:00",
    };
    const history = buildHistorySnapshot(existing, { version: 11 });
    expect(history).toHaveLength(10);
    // Oldest (version 0) should be dropped
    expect(history[0].context.version).toBe(1);
    expect(history[9].context.version).toBe(10);
  });

  it("preserves existing history array when discoveryContext is null", () => {
    const existing = {
      discoveryContext: null,
      discoveryContextHistory: [
        { context: { version: 1 }, analyzedAt: "2025-01-10", snapshotId: "snap-1" },
      ],
      discoveryContextAnalyzedAt: null,
    };
    const history = buildHistorySnapshot(existing, { version: 2 });
    // No new snapshot added because discoveryContext is null
    expect(history).toHaveLength(1);
    expect(history[0].context.version).toBe(1);
  });
});

// ─── Comparison Diff Detection ──────────────────────────────────────

// Replicate the client-side change detection helpers for unit testing
interface FieldChange {
  field: string;
  label: string;
  oldValue: any;
  newValue: any;
  changeType: "added" | "removed" | "modified" | "unchanged";
  delta?: number;
}

function detectAttributionChanges(oldAttr: any, newAttr: any): FieldChange[] {
  const changes: FieldChange[] = [];
  const oldPrimary = oldAttr?.primaryClaim;
  const newPrimary = newAttr?.primaryClaim;

  const oldOrg = oldPrimary?.attributedTo?.organization || null;
  const newOrg = newPrimary?.attributedTo?.organization || null;
  changes.push({
    field: "attribution.organization",
    label: "Primary Organization",
    oldValue: oldOrg,
    newValue: newOrg,
    changeType: oldOrg === newOrg ? "unchanged" : (!oldOrg ? "added" : !newOrg ? "removed" : "modified"),
  });

  const oldConf = oldPrimary?.confidenceScore ?? null;
  const newConf = newPrimary?.confidenceScore ?? null;
  changes.push({
    field: "attribution.confidence",
    label: "Attribution Confidence",
    oldValue: oldConf,
    newValue: newConf,
    changeType: oldConf === newConf ? "unchanged" : (oldConf == null ? "added" : newConf == null ? "removed" : "modified"),
    delta: (oldConf != null && newConf != null) ? newConf - oldConf : undefined,
  });

  return changes;
}

function detectRoleChanges(oldRole: any, newRole: any): FieldChange[] {
  const changes: FieldChange[] = [];
  const oldR = oldRole?.role || {};
  const newR = newRole?.role || {};

  for (const [key, label] of [
    ["exposure", "Exposure Level"],
    ["environment", "Environment"],
    ["criticality", "Criticality"],
  ] as const) {
    const oldVal = oldR[key] || null;
    const newVal = newR[key] || null;
    changes.push({
      field: `role.${key}`,
      label,
      oldValue: oldVal,
      newValue: newVal,
      changeType: oldVal === newVal ? "unchanged" : (!oldVal ? "added" : !newVal ? "removed" : "modified"),
    });
  }
  return changes;
}

function detectLifecycleChanges(oldLc: any, newLc: any): FieldChange[] {
  const changes: FieldChange[] = [];
  const oldStage = oldLc?.stage || null;
  const newStage = newLc?.stage || null;
  changes.push({
    field: "lifecycle.stage",
    label: "Lifecycle Stage",
    oldValue: oldStage,
    newValue: newStage,
    changeType: oldStage === newStage ? "unchanged" : (!oldStage ? "added" : !newStage ? "removed" : "modified"),
  });

  const oldDir = oldLc?.direction || null;
  const newDir = newLc?.direction || null;
  changes.push({
    field: "lifecycle.direction",
    label: "Trajectory Direction",
    oldValue: oldDir,
    newValue: newDir,
    changeType: oldDir === newDir ? "unchanged" : (!oldDir ? "added" : !newDir ? "removed" : "modified"),
  });
  return changes;
}

function detectThreatRelevanceChanges(oldTr: any, newTr: any): FieldChange[] {
  const changes: FieldChange[] = [];
  const oldScore = oldTr?.overallThreatScore ?? null;
  const newScore = newTr?.overallThreatScore ?? null;
  changes.push({
    field: "threatRelevance.overallScore",
    label: "Overall Threat Score",
    oldValue: oldScore,
    newValue: newScore,
    changeType: oldScore === newScore ? "unchanged" : (oldScore == null ? "added" : newScore == null ? "removed" : "modified"),
    delta: (oldScore != null && newScore != null) ? newScore - oldScore : undefined,
  });

  const oldBand = oldTr?.threatBand || null;
  const newBand = newTr?.threatBand || null;
  changes.push({
    field: "threatRelevance.threatBand",
    label: "Threat Band",
    oldValue: oldBand,
    newValue: newBand,
    changeType: oldBand === newBand ? "unchanged" : (!oldBand ? "added" : !newBand ? "removed" : "modified"),
  });
  return changes;
}

describe("Discovery Context Comparison - Change Detection", () => {
  it("detects no changes when contexts are identical", () => {
    const ctx = {
      attribution: { primaryClaim: { attributedTo: { organization: "Acme" }, confidenceScore: 75 } },
      role: { role: { exposure: "customer_facing", environment: "production", criticality: "high" } },
      lifecycle: { stage: "active", direction: "stable" },
      threatRelevance: { overallThreatScore: 65, threatBand: "medium" },
    };
    const attrChanges = detectAttributionChanges(ctx.attribution, ctx.attribution);
    expect(attrChanges.every(c => c.changeType === "unchanged")).toBe(true);

    const roleChanges = detectRoleChanges(ctx.role, ctx.role);
    expect(roleChanges.every(c => c.changeType === "unchanged")).toBe(true);

    const lcChanges = detectLifecycleChanges(ctx.lifecycle, ctx.lifecycle);
    expect(lcChanges.every(c => c.changeType === "unchanged")).toBe(true);

    const trChanges = detectThreatRelevanceChanges(ctx.threatRelevance, ctx.threatRelevance);
    expect(trChanges.every(c => c.changeType === "unchanged")).toBe(true);
  });

  it("detects attribution organization change", () => {
    const oldAttr = { primaryClaim: { attributedTo: { organization: "Acme" }, confidenceScore: 60 } };
    const newAttr = { primaryClaim: { attributedTo: { organization: "Acme Corp" }, confidenceScore: 75 } };
    const changes = detectAttributionChanges(oldAttr, newAttr);
    const orgChange = changes.find(c => c.field === "attribution.organization");
    expect(orgChange?.changeType).toBe("modified");
    expect(orgChange?.oldValue).toBe("Acme");
    expect(orgChange?.newValue).toBe("Acme Corp");

    const confChange = changes.find(c => c.field === "attribution.confidence");
    expect(confChange?.changeType).toBe("modified");
    expect(confChange?.delta).toBe(15);
  });

  it("detects attribution added from null", () => {
    const changes = detectAttributionChanges(null, {
      primaryClaim: { attributedTo: { organization: "NewCo" }, confidenceScore: 50 },
    });
    const orgChange = changes.find(c => c.field === "attribution.organization");
    expect(orgChange?.changeType).toBe("added");
    expect(orgChange?.newValue).toBe("NewCo");
  });

  it("detects attribution removed", () => {
    const changes = detectAttributionChanges(
      { primaryClaim: { attributedTo: { organization: "OldCo" }, confidenceScore: 70 } },
      null,
    );
    const orgChange = changes.find(c => c.field === "attribution.organization");
    expect(orgChange?.changeType).toBe("removed");
    expect(orgChange?.oldValue).toBe("OldCo");
  });

  it("detects role exposure change", () => {
    const oldRole = { role: { exposure: "internal", environment: "production", criticality: "medium" } };
    const newRole = { role: { exposure: "customer_facing", environment: "production", criticality: "high" } };
    const changes = detectRoleChanges(oldRole, newRole);
    const exposureChange = changes.find(c => c.field === "role.exposure");
    expect(exposureChange?.changeType).toBe("modified");
    expect(exposureChange?.oldValue).toBe("internal");
    expect(exposureChange?.newValue).toBe("customer_facing");

    const envChange = changes.find(c => c.field === "role.environment");
    expect(envChange?.changeType).toBe("unchanged");

    const critChange = changes.find(c => c.field === "role.criticality");
    expect(critChange?.changeType).toBe("modified");
  });

  it("detects lifecycle stage transition", () => {
    const oldLc = { stage: "active", direction: "stable" };
    const newLc = { stage: "decommissioning", direction: "declining" };
    const changes = detectLifecycleChanges(oldLc, newLc);
    const stageChange = changes.find(c => c.field === "lifecycle.stage");
    expect(stageChange?.changeType).toBe("modified");
    expect(stageChange?.oldValue).toBe("active");
    expect(stageChange?.newValue).toBe("decommissioning");

    const dirChange = changes.find(c => c.field === "lifecycle.direction");
    expect(dirChange?.changeType).toBe("modified");
    expect(dirChange?.oldValue).toBe("stable");
    expect(dirChange?.newValue).toBe("declining");
  });

  it("detects threat score increase with positive delta", () => {
    const oldTr = { overallThreatScore: 40, threatBand: "low" };
    const newTr = { overallThreatScore: 72, threatBand: "high" };
    const changes = detectThreatRelevanceChanges(oldTr, newTr);
    const scoreChange = changes.find(c => c.field === "threatRelevance.overallScore");
    expect(scoreChange?.changeType).toBe("modified");
    expect(scoreChange?.delta).toBe(32);

    const bandChange = changes.find(c => c.field === "threatRelevance.threatBand");
    expect(bandChange?.changeType).toBe("modified");
    expect(bandChange?.oldValue).toBe("low");
    expect(bandChange?.newValue).toBe("high");
  });

  it("detects threat score decrease with negative delta", () => {
    const oldTr = { overallThreatScore: 80, threatBand: "high" };
    const newTr = { overallThreatScore: 55, threatBand: "medium" };
    const changes = detectThreatRelevanceChanges(oldTr, newTr);
    const scoreChange = changes.find(c => c.field === "threatRelevance.overallScore");
    expect(scoreChange?.delta).toBe(-25);
  });

  it("handles null old and new contexts gracefully", () => {
    const attrChanges = detectAttributionChanges(null, null);
    expect(attrChanges.every(c => c.changeType === "unchanged")).toBe(true);

    const roleChanges = detectRoleChanges(null, null);
    expect(roleChanges.every(c => c.changeType === "unchanged")).toBe(true);

    const lcChanges = detectLifecycleChanges(null, null);
    expect(lcChanges.every(c => c.changeType === "unchanged")).toBe(true);

    const trChanges = detectThreatRelevanceChanges(null, null);
    expect(trChanges.every(c => c.changeType === "unchanged")).toBe(true);
  });
});

// ─── Export CSV Formatting ──────────────────────────────────────────

describe("Discovery Context Export - CSV Formatting", () => {
  const CSV_HEADERS = [
    "Hostname", "Analyzed At",
    "Attribution Org", "Attribution Confidence", "Attribution Tier",
    "Role Exposure", "Role Environment", "Role Criticality",
    "Lifecycle Stage", "Lifecycle Direction",
    "Business Function", "Revenue Impact",
    "Threat Score", "Threat Band", "Actor Types",
    "Analysis Mode",
  ];

  function escapeCsv(v: any): string {
    if (v == null) return "";
    const s = String(v);
    return s.includes(",") || s.includes('"') || s.includes("\n")
      ? `"${s.replace(/"/g, '""')}"`
      : s;
  }

  function buildCsvRow(row: { hostname: string; discoveryContextAnalyzedAt: string | null; discoveryContext: any }) {
    const ctx = row.discoveryContext;
    if (!ctx) return null;
    const attr = ctx.attribution?.primaryClaim;
    const role = ctx.role?.role;
    const lc = ctx.lifecycle;
    const bc = ctx.businessContext;
    const tr = ctx.threatRelevance;
    return [
      escapeCsv(row.hostname),
      escapeCsv(row.discoveryContextAnalyzedAt),
      escapeCsv(attr?.attributedTo?.organization),
      escapeCsv(attr?.confidenceScore),
      escapeCsv(attr?.claimType),
      escapeCsv(role?.exposure),
      escapeCsv(role?.environment),
      escapeCsv(role?.criticality),
      escapeCsv(lc?.stage),
      escapeCsv(lc?.direction),
      escapeCsv(bc?.businessFunction),
      escapeCsv(bc?.revenueImpact),
      escapeCsv(tr?.overallThreatScore),
      escapeCsv(tr?.threatBand),
      escapeCsv((tr?.relevantActorTypes || []).join("; ")),
      escapeCsv(ctx.attribution?.metadata?.mode || "unknown"),
    ].join(",");
  }

  it("CSV headers have 16 columns", () => {
    expect(CSV_HEADERS).toHaveLength(16);
  });

  it("builds correct CSV row for a fully populated context", () => {
    const row = {
      hostname: "api.example.com",
      discoveryContextAnalyzedAt: "2025-04-20 14:30:00",
      discoveryContext: {
        attribution: {
          primaryClaim: {
            attributedTo: { organization: "Example Corp" },
            confidenceScore: 85,
            claimType: "direct_ownership",
          },
          metadata: { mode: "full_llm" },
        },
        role: { role: { exposure: "customer_facing", environment: "production", criticality: "high" } },
        lifecycle: { stage: "active", direction: "growing" },
        businessContext: { businessFunction: "API Gateway", revenueImpact: "high" },
        threatRelevance: {
          overallThreatScore: 72,
          threatBand: "high",
          relevantActorTypes: ["APT", "ransomware"],
        },
      },
    };
    const csvRow = buildCsvRow(row);
    expect(csvRow).toBeTruthy();
    const cols = csvRow!.split(",");
    expect(cols[0]).toBe("api.example.com");
    expect(cols[2]).toBe("Example Corp");
    expect(cols[3]).toBe("85");
    expect(cols[4]).toBe("direct_ownership");
    expect(cols[5]).toBe("customer_facing");
    expect(cols[6]).toBe("production");
    expect(cols[7]).toBe("high");
    expect(cols[8]).toBe("active");
    expect(cols[9]).toBe("growing");
    expect(cols[10]).toBe("API Gateway");
    expect(cols[11]).toBe("high");
    expect(cols[12]).toBe("72");
    expect(cols[13]).toBe("high");
    expect(cols[14]).toBe("APT; ransomware");
    expect(cols[15]).toBe("full_llm");
  });

  it("handles null discovery context gracefully", () => {
    const row = { hostname: "test.com", discoveryContextAnalyzedAt: null, discoveryContext: null };
    const csvRow = buildCsvRow(row);
    expect(csvRow).toBeNull();
  });

  it("handles empty/missing fields with empty strings", () => {
    const row = {
      hostname: "bare.example.com",
      discoveryContextAnalyzedAt: "2025-04-20",
      discoveryContext: {
        attribution: { metadata: { mode: "deterministic_only" } },
        role: {},
        lifecycle: {},
      },
    };
    const csvRow = buildCsvRow(row);
    expect(csvRow).toBeTruthy();
    const cols = csvRow!.split(",");
    expect(cols[0]).toBe("bare.example.com");
    expect(cols[2]).toBe(""); // no org
    expect(cols[3]).toBe(""); // no confidence
    expect(cols[15]).toBe("deterministic_only");
  });

  it("escapes CSV values with commas", () => {
    expect(escapeCsv("Hello, World")).toBe('"Hello, World"');
  });

  it("escapes CSV values with quotes", () => {
    expect(escapeCsv('He said "hello"')).toBe('"He said ""hello"""');
  });

  it("escapes CSV values with newlines", () => {
    expect(escapeCsv("Line1\nLine2")).toBe('"Line1\nLine2"');
  });

  it("returns empty string for null/undefined", () => {
    expect(escapeCsv(null)).toBe("");
    expect(escapeCsv(undefined)).toBe("");
  });
});

// ─── Export Markdown Report Structure ───────────────────────────────

describe("Discovery Context Export - Markdown Report Structure", () => {
  function buildMarkdownReport(rows: any[], domain: string) {
    let md = `# Discovery Context Intelligence Report\n\n`;
    md += `**Domain:** ${domain}  \n`;
    md += `**Assets Analyzed:** ${rows.filter(r => r.discoveryContext).length}/${rows.length}  \n\n`;
    md += `---\n\n`;
    md += `## Summary\n\n`;
    md += `| Hostname | Attribution | Confidence | Lifecycle | Threat Score | Threat Band |\n`;
    md += `|----------|-------------|------------|-----------|--------------|-------------|\n`;
    for (const row of rows) {
      const ctx = row.discoveryContext;
      if (!ctx) continue;
      const attr = ctx.attribution?.primaryClaim;
      const lc = ctx.lifecycle;
      const tr = ctx.threatRelevance;
      md += `| ${row.hostname} | ${attr?.attributedTo?.organization || "\u2014"} | ${attr?.confidenceScore ?? "\u2014"}% | ${lc?.stage || "\u2014"} | ${tr?.overallThreatScore ?? "\u2014"} | ${tr?.threatBand || "\u2014"} |\n`;
    }
    md += `\n## Per-Asset Analysis\n\n`;
    for (const row of rows) {
      const ctx = row.discoveryContext;
      if (!ctx) continue;
      md += `### ${row.hostname}\n\n`;
    }
    return md;
  }

  it("generates report with correct title", () => {
    const md = buildMarkdownReport([], "example.com");
    expect(md).toContain("# Discovery Context Intelligence Report");
    expect(md).toContain("**Domain:** example.com");
  });

  it("generates summary table with correct headers", () => {
    const md = buildMarkdownReport([], "example.com");
    expect(md).toContain("| Hostname | Attribution | Confidence | Lifecycle | Threat Score | Threat Band |");
  });

  it("includes per-asset sections", () => {
    const rows = [
      {
        hostname: "api.example.com",
        discoveryContext: {
          attribution: { primaryClaim: { attributedTo: { organization: "ExCo" }, confidenceScore: 80 } },
          lifecycle: { stage: "active" },
          threatRelevance: { overallThreatScore: 65, threatBand: "medium" },
        },
      },
      {
        hostname: "mail.example.com",
        discoveryContext: {
          attribution: { primaryClaim: { attributedTo: { organization: "ExCo" }, confidenceScore: 70 } },
          lifecycle: { stage: "mature" },
          threatRelevance: { overallThreatScore: 45, threatBand: "low" },
        },
      },
    ];
    const md = buildMarkdownReport(rows, "example.com");
    expect(md).toContain("### api.example.com");
    expect(md).toContain("### mail.example.com");
    expect(md).toContain("**Assets Analyzed:** 2/2");
  });

  it("handles rows with null discoveryContext", () => {
    const rows = [
      { hostname: "empty.example.com", discoveryContext: null },
      {
        hostname: "api.example.com",
        discoveryContext: {
          attribution: { primaryClaim: { attributedTo: { organization: "Test" }, confidenceScore: 50 } },
          lifecycle: { stage: "active" },
          threatRelevance: { overallThreatScore: 30, threatBand: "low" },
        },
      },
    ];
    const md = buildMarkdownReport(rows, "example.com");
    expect(md).toContain("**Assets Analyzed:** 1/2");
    expect(md).not.toContain("### empty.example.com");
    expect(md).toContain("### api.example.com");
  });

  it("uses em dash for missing values in summary table", () => {
    const rows = [
      {
        hostname: "bare.example.com",
        discoveryContext: {
          attribution: {},
          lifecycle: {},
          threatRelevance: {},
        },
      },
    ];
    const md = buildMarkdownReport(rows, "example.com");
    expect(md).toContain("| bare.example.com | \u2014 | \u2014% | \u2014 | \u2014 | \u2014 |");
  });
});

// ─── Stale Analysis Detection (supplementary) ──────────────────────

describe("Discovery Context - Stale Analysis Detection", () => {
  const STALE_THRESHOLD_DAYS = 7;
  const STALE_THRESHOLD_MS = STALE_THRESHOLD_DAYS * 24 * 60 * 60 * 1000;

  function isStaleAnalysis(analyzedAt: string | number | undefined): boolean {
    if (!analyzedAt) return false;
    const ts = typeof analyzedAt === "number" ? analyzedAt : new Date(analyzedAt).getTime();
    return Date.now() - ts > STALE_THRESHOLD_MS;
  }

  it("returns false for recent analysis", () => {
    expect(isStaleAnalysis(new Date().toISOString())).toBe(false);
    expect(isStaleAnalysis(Date.now())).toBe(false);
  });

  it("returns true for analysis older than 7 days", () => {
    const eightDaysAgo = Date.now() - 8 * 24 * 60 * 60 * 1000;
    expect(isStaleAnalysis(eightDaysAgo)).toBe(true);
    expect(isStaleAnalysis(new Date(eightDaysAgo).toISOString())).toBe(true);
  });

  it("returns false for undefined/null", () => {
    expect(isStaleAnalysis(undefined)).toBe(false);
  });

  it("correctly identifies boundary case at exactly 7 days", () => {
    const exactlySevenDays = Date.now() - STALE_THRESHOLD_MS - 1;
    expect(isStaleAnalysis(exactlySevenDays)).toBe(true);
    const justUnder = Date.now() - STALE_THRESHOLD_MS + 60000; // 1 min under
    expect(isStaleAnalysis(justUnder)).toBe(false);
  });
});
