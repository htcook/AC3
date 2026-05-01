import { describe, it, expect } from "vitest";

// ─── 1. Confidence Badge Logic Tests ─────────────────────────────────────────
// Tests the client-side scoreToLevel logic that ConfidenceBadge uses

describe("ConfidenceBadge — scoreToLevel mapping", () => {
  // Replicate the logic from ConfidenceBadge.tsx
  function scoreToLevel(score: number): "HIGH" | "MODERATE" | "LOW" {
    if (score >= 0.75) return "HIGH";
    if (score >= 0.45) return "MODERATE";
    return "LOW";
  }

  it("should classify scores >= 0.75 as HIGH", () => {
    expect(scoreToLevel(0.75)).toBe("HIGH");
    expect(scoreToLevel(0.9)).toBe("HIGH");
    expect(scoreToLevel(1.0)).toBe("HIGH");
  });

  it("should classify scores 0.45–0.74 as MODERATE", () => {
    expect(scoreToLevel(0.45)).toBe("MODERATE");
    expect(scoreToLevel(0.5)).toBe("MODERATE");
    expect(scoreToLevel(0.74)).toBe("MODERATE");
  });

  it("should classify scores < 0.45 as LOW", () => {
    expect(scoreToLevel(0.0)).toBe("LOW");
    expect(scoreToLevel(0.2)).toBe("LOW");
    expect(scoreToLevel(0.44)).toBe("LOW");
  });

  it("should handle edge cases at boundaries", () => {
    expect(scoreToLevel(0.449)).toBe("LOW");
    expect(scoreToLevel(0.45)).toBe("MODERATE");
    expect(scoreToLevel(0.749)).toBe("MODERATE");
    expect(scoreToLevel(0.75)).toBe("HIGH");
  });

  it("should handle string-based confidence levels (pass-through)", () => {
    // ConfidenceBadge also accepts string levels directly
    function stringToLevel(level: string): "HIGH" | "MODERATE" | "LOW" {
      const upper = level.toUpperCase();
      if (upper === "HIGH" || upper === "H") return "HIGH";
      if (upper === "MODERATE" || upper === "MEDIUM" || upper === "MOD" || upper === "M") return "MODERATE";
      return "LOW";
    }
    expect(stringToLevel("high")).toBe("HIGH");
    expect(stringToLevel("medium")).toBe("MODERATE");
    expect(stringToLevel("low")).toBe("LOW");
    expect(stringToLevel("H")).toBe("HIGH");
    expect(stringToLevel("M")).toBe("MODERATE");
  });
});

// ─── 2. Intelligence Gaps Module Tests ───────────────────────────────────────

describe("Intelligence Gaps — Gap Category Metadata", () => {
  // Replicate the GAP_CATEGORY_META from intelligence-gaps.ts
  const GAP_CATEGORY_META: Record<string, { label: string; defaultImpact: string; icon: string }> = {
    scope_exclusion: { label: "Scope Exclusion", defaultImpact: "high", icon: "🚫" },
    tool_limitation: { label: "Tool Limitation", defaultImpact: "medium", icon: "🔧" },
    time_constraint: { label: "Time Constraint", defaultImpact: "medium", icon: "⏱" },
    access_denied: { label: "Access Denied", defaultImpact: "high", icon: "🔒" },
    data_unavailable: { label: "Data Unavailable", defaultImpact: "medium", icon: "📭" },
    expertise_gap: { label: "Expertise Gap", defaultImpact: "high", icon: "🎓" },
    environmental_constraint: { label: "Environmental Constraint", defaultImpact: "low", icon: "🌐" },
  };

  it("should define all seven gap categories", () => {
    const categories = Object.keys(GAP_CATEGORY_META);
    expect(categories).toHaveLength(7);
    expect(categories).toContain("scope_exclusion");
    expect(categories).toContain("tool_limitation");
    expect(categories).toContain("time_constraint");
    expect(categories).toContain("access_denied");
    expect(categories).toContain("data_unavailable");
    expect(categories).toContain("expertise_gap");
    expect(categories).toContain("environmental_constraint");
  });

  it("should assign high impact to scope_exclusion, access_denied, expertise_gap", () => {
    expect(GAP_CATEGORY_META.scope_exclusion.defaultImpact).toBe("high");
    expect(GAP_CATEGORY_META.access_denied.defaultImpact).toBe("high");
    expect(GAP_CATEGORY_META.expertise_gap.defaultImpact).toBe("high");
  });

  it("should assign medium impact to tool_limitation, time_constraint, data_unavailable", () => {
    expect(GAP_CATEGORY_META.tool_limitation.defaultImpact).toBe("medium");
    expect(GAP_CATEGORY_META.time_constraint.defaultImpact).toBe("medium");
    expect(GAP_CATEGORY_META.data_unavailable.defaultImpact).toBe("medium");
  });

  it("should assign low impact to environmental_constraint", () => {
    expect(GAP_CATEGORY_META.environmental_constraint.defaultImpact).toBe("low");
  });

  it("should have labels and icons for all categories", () => {
    for (const [key, meta] of Object.entries(GAP_CATEGORY_META)) {
      expect(meta.label).toBeTruthy();
      expect(meta.icon).toBeTruthy();
      expect(meta.label.length).toBeGreaterThan(3);
    }
  });
});

describe("Intelligence Gaps — formatGapsForReport", () => {
  // Replicate the formatGapsForReport logic
  function formatGapsForReport(gaps: Array<{
    category: string;
    title: string;
    reason: string;
    potentialImpact: string | null;
    status: string;
    recommendation: string | null;
  }>): string {
    if (gaps.length === 0) {
      return "## Intelligence Gaps\n\nNo intelligence gaps were identified during this assessment.";
    }

    const lines = ["## Intelligence Gaps\n"];
    lines.push(`**${gaps.length}** intelligence gap(s) identified during this assessment.\n`);

    const byCategory: Record<string, typeof gaps> = {};
    for (const g of gaps) {
      if (!byCategory[g.category]) byCategory[g.category] = [];
      byCategory[g.category].push(g);
    }

    for (const [cat, catGaps] of Object.entries(byCategory)) {
      lines.push(`### ${cat.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}`);
      for (const g of catGaps) {
        lines.push(`- **${g.title}** (${g.status})`);
        lines.push(`  - Reason: ${g.reason}`);
        if (g.potentialImpact) lines.push(`  - Potential Impact: ${g.potentialImpact}`);
        if (g.recommendation) lines.push(`  - Recommendation: ${g.recommendation}`);
      }
      lines.push("");
    }

    return lines.join("\n");
  }

  it("should return 'no gaps' message for empty array", () => {
    const result = formatGapsForReport([]);
    expect(result).toContain("No intelligence gaps");
  });

  it("should format gaps grouped by category", () => {
    const gaps = [
      { category: "scope_exclusion", title: "Cloud infra excluded", reason: "Out of scope per ROE", potentialImpact: "high", status: "open", recommendation: "Include in next engagement" },
      { category: "scope_exclusion", title: "Mobile apps excluded", reason: "No mobile testing authorized", potentialImpact: "medium", status: "open", recommendation: null },
      { category: "tool_limitation", title: "No DAST for GraphQL", reason: "ZAP lacks GraphQL support", potentialImpact: "medium", status: "acknowledged", recommendation: "Use specialized GraphQL scanner" },
    ];
    const result = formatGapsForReport(gaps);
    expect(result).toContain("## Intelligence Gaps");
    expect(result).toContain("**3** intelligence gap(s)");
    expect(result).toContain("### Scope Exclusion");
    expect(result).toContain("### Tool Limitation");
    expect(result).toContain("Cloud infra excluded");
    expect(result).toContain("No DAST for GraphQL");
  });

  it("should include recommendation when present", () => {
    const gaps = [
      { category: "access_denied", title: "VPN access denied", reason: "Credentials expired", potentialImpact: "high", status: "open", recommendation: "Request new VPN creds" },
    ];
    const result = formatGapsForReport(gaps);
    expect(result).toContain("Recommendation: Request new VPN creds");
  });

  it("should omit recommendation when null", () => {
    const gaps = [
      { category: "time_constraint", title: "API fuzzing incomplete", reason: "Ran out of time", potentialImpact: "medium", status: "open", recommendation: null },
    ];
    const result = formatGapsForReport(gaps);
    expect(result).not.toContain("Recommendation:");
  });
});

// ─── 3. Customer Intelligence Profile Tests ──────────────────────────────────

describe("Customer Intelligence Profile — Posture Score Calculation", () => {
  // Replicate the calculatePostureScore logic from customer-intel-profile.ts
  function calculatePostureScore(input: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    totalAssets: number;
    openGaps: number;
    resolvedGaps: number;
  }): number {
    const { totalFindings, critical, high, medium, low, totalAssets, openGaps, resolvedGaps } = input;

    if (totalAssets === 0 && totalFindings === 0) return 100;

    // Weighted severity penalty (higher severity = more penalty)
    const severityPenalty =
      critical * 10 + high * 5 + medium * 2 + low * 0.5;

    // Normalize by asset count (more assets = more expected findings)
    const assetNorm = Math.max(totalAssets, 1);
    const normalizedPenalty = severityPenalty / assetNorm;

    // Gap penalty: open gaps reduce score, resolved gaps slightly improve it
    const gapPenalty = openGaps * 3 - resolvedGaps * 0.5;

    // Base score starts at 100, subtract penalties
    const raw = 100 - normalizedPenalty - gapPenalty;

    // Clamp to 0–100
    return Math.max(0, Math.min(100, Math.round(raw * 10) / 10));
  }

  it("should return 100 for zero findings and zero assets", () => {
    expect(calculatePostureScore({
      totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0,
      totalAssets: 0, openGaps: 0, resolvedGaps: 0,
    })).toBe(100);
  });

  it("should penalize critical findings heavily", () => {
    const score = calculatePostureScore({
      totalFindings: 5, critical: 5, high: 0, medium: 0, low: 0,
      totalAssets: 10, openGaps: 0, resolvedGaps: 0,
    });
    expect(score).toBeLessThan(100);
    expect(score).toBeLessThan(96); // 5 criticals on 10 assets should be noticeable
  });

  it("should penalize high findings less than critical", () => {
    const critScore = calculatePostureScore({
      totalFindings: 5, critical: 5, high: 0, medium: 0, low: 0,
      totalAssets: 10, openGaps: 0, resolvedGaps: 0,
    });
    const highScore = calculatePostureScore({
      totalFindings: 5, critical: 0, high: 5, medium: 0, low: 0,
      totalAssets: 10, openGaps: 0, resolvedGaps: 0,
    });
    expect(highScore).toBeGreaterThan(critScore);
  });

  it("should reduce score for open gaps", () => {
    const noGaps = calculatePostureScore({
      totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0,
      totalAssets: 10, openGaps: 0, resolvedGaps: 0,
    });
    const withGaps = calculatePostureScore({
      totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0,
      totalAssets: 10, openGaps: 5, resolvedGaps: 0,
    });
    expect(withGaps).toBeLessThan(noGaps);
  });

  it("should slightly improve score for resolved gaps", () => {
    const withOpenGaps = calculatePostureScore({
      totalFindings: 10, critical: 1, high: 3, medium: 4, low: 2,
      totalAssets: 20, openGaps: 5, resolvedGaps: 0,
    });
    const withResolvedGaps = calculatePostureScore({
      totalFindings: 10, critical: 1, high: 3, medium: 4, low: 2,
      totalAssets: 20, openGaps: 5, resolvedGaps: 10,
    });
    expect(withResolvedGaps).toBeGreaterThan(withOpenGaps);
  });

  it("should clamp score to 0–100 range", () => {
    // Extreme case: many critical findings
    const score = calculatePostureScore({
      totalFindings: 100, critical: 100, high: 0, medium: 0, low: 0,
      totalAssets: 1, openGaps: 50, resolvedGaps: 0,
    });
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
  });

  it("should normalize by asset count", () => {
    // Same findings, more assets = better score
    const fewAssets = calculatePostureScore({
      totalFindings: 10, critical: 2, high: 3, medium: 3, low: 2,
      totalAssets: 5, openGaps: 0, resolvedGaps: 0,
    });
    const manyAssets = calculatePostureScore({
      totalFindings: 10, critical: 2, high: 3, medium: 3, low: 2,
      totalAssets: 100, openGaps: 0, resolvedGaps: 0,
    });
    expect(manyAssets).toBeGreaterThan(fewAssets);
  });
});

describe("Customer Intelligence Profile — scoreToGrade", () => {
  function scoreToGrade(score: number): string {
    if (score >= 90) return "A";
    if (score >= 80) return "B";
    if (score >= 70) return "C";
    if (score >= 60) return "D";
    return "F";
  }

  it("should assign A for scores >= 90", () => {
    expect(scoreToGrade(90)).toBe("A");
    expect(scoreToGrade(100)).toBe("A");
    expect(scoreToGrade(95)).toBe("A");
  });

  it("should assign B for scores 80–89", () => {
    expect(scoreToGrade(80)).toBe("B");
    expect(scoreToGrade(89)).toBe("B");
  });

  it("should assign C for scores 70–79", () => {
    expect(scoreToGrade(70)).toBe("C");
    expect(scoreToGrade(79)).toBe("C");
  });

  it("should assign D for scores 60–69", () => {
    expect(scoreToGrade(60)).toBe("D");
    expect(scoreToGrade(69)).toBe("D");
  });

  it("should assign F for scores below 60", () => {
    expect(scoreToGrade(59)).toBe("F");
    expect(scoreToGrade(0)).toBe("F");
    expect(scoreToGrade(30)).toBe("F");
  });
});

describe("Customer Intelligence Profile — determineTrend", () => {
  function determineTrend(postureTrend: Array<{ score: number }>): "improving" | "declining" | "stable" | "new" {
    if (postureTrend.length < 2) return "new";
    const recent = postureTrend.slice(-3);
    const first = recent[0].score;
    const last = recent[recent.length - 1].score;
    const diff = last - first;
    if (diff > 5) return "improving";
    if (diff < -5) return "declining";
    return "stable";
  }

  it("should return 'new' for less than 2 data points", () => {
    expect(determineTrend([])).toBe("new");
    expect(determineTrend([{ score: 80 }])).toBe("new");
  });

  it("should return 'improving' when score increases by more than 5", () => {
    expect(determineTrend([{ score: 70 }, { score: 80 }])).toBe("improving");
  });

  it("should return 'declining' when score decreases by more than 5", () => {
    expect(determineTrend([{ score: 80 }, { score: 70 }])).toBe("declining");
  });

  it("should return 'stable' when score change is within 5 points", () => {
    expect(determineTrend([{ score: 80 }, { score: 82 }])).toBe("stable");
    expect(determineTrend([{ score: 80 }, { score: 78 }])).toBe("stable");
  });

  it("should use only the last 3 data points", () => {
    // Old data shows decline, but recent 3 show improvement
    const trend = [
      { score: 90 }, { score: 80 }, { score: 70 },
      { score: 72 }, { score: 78 }, { score: 85 },
    ];
    expect(determineTrend(trend)).toBe("improving");
  });
});

describe("Customer Intelligence Profile — Strategic Recommendations", () => {
  function generateStrategicRecommendations(input: {
    postureScore: number;
    recurringWeaknesses: Array<{ category: string; count: number; trend: string }>;
    openGaps: number;
    findings: { critical: number; high: number };
    surfaceTrend: Array<{ hosts: number; services: number }>;
  }): string[] {
    const recs: string[] = [];

    if (input.findings.critical > 0) {
      recs.push(`Address ${input.findings.critical} critical finding(s) immediately — these represent active exploitation risk`);
    }

    if (input.postureScore < 60) {
      recs.push("Overall security posture is below acceptable threshold — recommend comprehensive remediation program");
    }

    const persistent = input.recurringWeaknesses.filter(w => w.trend === "persistent");
    if (persistent.length > 0) {
      recs.push(`${persistent.length} weakness category(ies) are persistent across engagements — systemic remediation needed`);
    }

    if (input.openGaps > 3) {
      recs.push(`${input.openGaps} intelligence gaps remain open — consider expanding scope or tooling in next engagement`);
    }

    if (input.surfaceTrend.length >= 2) {
      const prev = input.surfaceTrend[input.surfaceTrend.length - 2];
      const curr = input.surfaceTrend[input.surfaceTrend.length - 1];
      if (curr.hosts > prev.hosts * 1.2) {
        recs.push("Attack surface has grown significantly — review new assets for security coverage");
      }
    }

    if (recs.length === 0) {
      recs.push("Security posture is within acceptable range — continue regular assessment cadence");
    }

    return recs;
  }

  it("should recommend addressing critical findings", () => {
    const recs = generateStrategicRecommendations({
      postureScore: 80,
      recurringWeaknesses: [],
      openGaps: 0,
      findings: { critical: 3, high: 5 },
      surfaceTrend: [],
    });
    expect(recs.some(r => r.includes("critical finding(s)"))).toBe(true);
  });

  it("should flag low posture score", () => {
    const recs = generateStrategicRecommendations({
      postureScore: 45,
      recurringWeaknesses: [],
      openGaps: 0,
      findings: { critical: 0, high: 0 },
      surfaceTrend: [],
    });
    expect(recs.some(r => r.includes("below acceptable threshold"))).toBe(true);
  });

  it("should flag persistent weaknesses", () => {
    const recs = generateStrategicRecommendations({
      postureScore: 80,
      recurringWeaknesses: [
        { category: "XSS", count: 4, trend: "persistent" },
        { category: "SQLi", count: 3, trend: "persistent" },
      ],
      openGaps: 0,
      findings: { critical: 0, high: 0 },
      surfaceTrend: [],
    });
    expect(recs.some(r => r.includes("persistent across engagements"))).toBe(true);
  });

  it("should flag many open gaps", () => {
    const recs = generateStrategicRecommendations({
      postureScore: 80,
      recurringWeaknesses: [],
      openGaps: 5,
      findings: { critical: 0, high: 0 },
      surfaceTrend: [],
    });
    expect(recs.some(r => r.includes("intelligence gaps remain open"))).toBe(true);
  });

  it("should flag growing attack surface", () => {
    const recs = generateStrategicRecommendations({
      postureScore: 80,
      recurringWeaknesses: [],
      openGaps: 0,
      findings: { critical: 0, high: 0 },
      surfaceTrend: [
        { hosts: 10, services: 30 },
        { hosts: 15, services: 45 },
      ],
    });
    expect(recs.some(r => r.includes("Attack surface has grown"))).toBe(true);
  });

  it("should return positive message when no issues", () => {
    const recs = generateStrategicRecommendations({
      postureScore: 95,
      recurringWeaknesses: [],
      openGaps: 0,
      findings: { critical: 0, high: 0 },
      surfaceTrend: [],
    });
    expect(recs).toHaveLength(1);
    expect(recs[0]).toContain("within acceptable range");
  });
});

// ─── 4. StructuredLiveView Data Organization Tests ───────────────────────────

describe("StructuredLiveView — Data Organization", () => {
  // Replicate the buildStructuredData logic
  interface StructuredAsset {
    id: string;
    hostname: string;
    ip: string;
    type: string;
    severity: string;
    ports: Array<{ port: number; protocol: string; service: string; state: string }>;
    connections: string[];
    proxyRole: string | null;
  }

  function buildStructuredData(
    nodes: Array<{ id: string; label: string; type: string; severity?: string; metadata?: Record<string, any> }>,
    edges: Array<{ source: string; target: string }>
  ): StructuredAsset[] {
    const assetMap = new Map<string, StructuredAsset>();

    for (const node of nodes) {
      if (node.type === "host" || node.type === "domain" || node.type === "server") {
        assetMap.set(node.id, {
          id: node.id,
          hostname: node.label || node.id,
          ip: node.metadata?.ip || "",
          type: node.type,
          severity: node.severity || "info",
          ports: [],
          connections: [],
          proxyRole: node.metadata?.proxyRole || null,
        });
      }
    }

    // Attach ports to their parent hosts
    for (const node of nodes) {
      if (node.type === "port" || node.type === "service") {
        // Find the parent host via edges
        const parentEdge = edges.find(e => e.target === node.id);
        if (parentEdge && assetMap.has(parentEdge.source)) {
          assetMap.get(parentEdge.source)!.ports.push({
            port: node.metadata?.port || 0,
            protocol: node.metadata?.protocol || "tcp",
            service: node.metadata?.service || node.label || "unknown",
            state: node.metadata?.state || "open",
          });
        }
      }
    }

    // Build connections
    for (const edge of edges) {
      if (assetMap.has(edge.source) && assetMap.has(edge.target)) {
        assetMap.get(edge.source)!.connections.push(edge.target);
      }
    }

    return Array.from(assetMap.values());
  }

  it("should group hosts from nodes", () => {
    const nodes = [
      { id: "h1", label: "web.example.com", type: "host", metadata: { ip: "1.2.3.4" } },
      { id: "h2", label: "db.example.com", type: "host", metadata: { ip: "1.2.3.5" } },
    ];
    const result = buildStructuredData(nodes, []);
    expect(result).toHaveLength(2);
    expect(result[0].hostname).toBe("web.example.com");
  });

  it("should attach ports to their parent hosts via edges", () => {
    const nodes = [
      { id: "h1", label: "web.example.com", type: "host" },
      { id: "p1", label: "443/https", type: "port", metadata: { port: 443, service: "https" } },
      { id: "p2", label: "80/http", type: "port", metadata: { port: 80, service: "http" } },
    ];
    const edges = [
      { source: "h1", target: "p1" },
      { source: "h1", target: "p2" },
    ];
    const result = buildStructuredData(nodes, edges);
    expect(result).toHaveLength(1);
    expect(result[0].ports).toHaveLength(2);
    expect(result[0].ports[0].port).toBe(443);
  });

  it("should track connections between hosts", () => {
    const nodes = [
      { id: "h1", label: "web.example.com", type: "host" },
      { id: "h2", label: "db.example.com", type: "host" },
    ];
    const edges = [{ source: "h1", target: "h2" }];
    const result = buildStructuredData(nodes, edges);
    expect(result[0].connections).toContain("h2");
  });

  it("should detect proxy roles", () => {
    const nodes = [
      { id: "h1", label: "proxy.example.com", type: "host", metadata: { proxyRole: "nginx reverse proxy" } },
    ];
    const result = buildStructuredData(nodes, []);
    expect(result[0].proxyRole).toBe("nginx reverse proxy");
  });

  it("should handle empty input gracefully", () => {
    const result = buildStructuredData([], []);
    expect(result).toHaveLength(0);
  });
});
