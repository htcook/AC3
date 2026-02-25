/**
 * Evasion Playbook Generator & Defense Heatmap
 * ═════════════════════════════════════════════
 * Compiles evasion findings into shareable playbook reports grouped by
 * target and defense product, and aggregates defense effectiveness data
 * into a heatmap structure for visualization.
 */

import {
  getFindings,
  getOrchestratorStats,
  ESCALATION_LADDER,
  type EvasionFinding,
  type EvasionDomain,
  type EscalationResult,
  type EvasionAttempt,
} from "./evasion-orchestrator";

// ═══════════════════════════════════════════════════════════════════════
// §1 — PLAYBOOK TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface PlaybookEntry {
  target: string;
  domain: EvasionDomain;
  operation: string;
  defensesDetected: string[];
  successfulTechnique: {
    id: string;
    name: string;
    category: string;
    description: string;
    escalationLevel: number;
    mitreTechnique?: string;
  } | null;
  escalationPath: {
    techniqueId: string;
    techniqueName: string;
    result: EscalationResult;
    blockSignal?: string;
  }[];
  totalAttempts: number;
  bypassRate: number;
  timestamp: number;
}

export interface PlaybookTargetGroup {
  target: string;
  totalEngagements: number;
  successfulBypasses: number;
  overallBypassRate: number;
  defensesEncountered: string[];
  domains: EvasionDomain[];
  entries: PlaybookEntry[];
  recommendedApproach: {
    bestTechnique: string;
    bestCategory: string;
    avgEscalationLevel: number;
    notes: string;
  } | null;
}

export interface PlaybookDefenseGroup {
  defense: string;
  timesEncountered: number;
  timesBypassed: number;
  bypassRate: number;
  effectiveAgainst: string[];   // techniques that failed
  vulnerableTo: string[];       // techniques that succeeded
  avgEscalationToBypass: number;
  riskLevel: "low" | "medium" | "high" | "critical";
}

export interface EvasionPlaybook {
  id: string;
  generatedAt: number;
  title: string;
  summary: {
    totalFindings: number;
    totalTargets: number;
    totalDefenses: number;
    overallBypassRate: number;
    domainBreakdown: Record<EvasionDomain, { total: number; bypassed: number }>;
    avgEscalationDepth: number;
  };
  targetGroups: PlaybookTargetGroup[];
  defenseGroups: PlaybookDefenseGroup[];
  techniqueEffectiveness: {
    techniqueId: string;
    techniqueName: string;
    category: string;
    level: number;
    timesUsed: number;
    timesBypassed: number;
    successRate: number;
    bestAgainst: string[];
  }[];
  recommendations: string[];
  mitreMappings: {
    techniqueId: string;
    techniqueName: string;
    mitreId: string;
    usageCount: number;
  }[];
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — HEATMAP TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface HeatmapCell {
  defense: string;
  technique: string;
  techniqueCategory: string;
  encounters: number;
  bypasses: number;
  blocks: number;
  bypassRate: number;
  avgLatencyMs: number;
  intensity: number; // 0-1 normalized for color mapping
}

export interface HeatmapRow {
  defense: string;
  totalEncounters: number;
  overallBypassRate: number;
  cells: HeatmapCell[];
}

export interface DefenseHeatmap {
  generatedAt: number;
  defenses: string[];
  techniques: string[];
  rows: HeatmapRow[];
  summary: {
    mostEffectiveDefense: { name: string; bypassRate: number } | null;
    leastEffectiveDefense: { name: string; bypassRate: number } | null;
    mostEffectiveTechnique: { name: string; successRate: number } | null;
    leastEffectiveTechnique: { name: string; successRate: number } | null;
    totalDataPoints: number;
  };
  domainFilter?: EvasionDomain;
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — PLAYBOOK GENERATOR
// ═══════════════════════════════════════════════════════════════════════

/**
 * Generate a full Evasion Playbook from stored findings.
 */
export function generatePlaybook(options?: {
  domain?: EvasionDomain;
  target?: string;
  onlySuccessful?: boolean;
  title?: string;
}): EvasionPlaybook {
  let findings = getFindings({ domain: options?.domain, target: options?.target, limit: 200 });

  if (options?.onlySuccessful) {
    findings = findings.filter(f => f.finalResult === "bypassed");
  }

  // Build target groups
  const targetMap = new Map<string, EvasionFinding[]>();
  for (const f of findings) {
    const existing = targetMap.get(f.target) || [];
    existing.push(f);
    targetMap.set(f.target, existing);
  }

  const targetGroups: PlaybookTargetGroup[] = [];
  for (const [target, tFindings] of targetMap) {
    const entries: PlaybookEntry[] = tFindings.map(f => ({
      target: f.target,
      domain: f.domain,
      operation: f.operation,
      defensesDetected: f.defensesDetected,
      successfulTechnique: f.successfulTechnique
        ? {
            ...f.successfulTechnique,
            mitreTechnique: ESCALATION_LADDER.find(t => t.id === f.successfulTechnique!.id)?.mitreTechnique,
          }
        : null,
      escalationPath: f.attempts.map(a => ({
        techniqueId: a.techniqueId,
        techniqueName: a.techniqueName,
        result: a.result,
        blockSignal: a.blockSignal,
      })),
      totalAttempts: f.totalAttempts,
      bypassRate: f.evasionScorecard.bypassRate,
      timestamp: f.completedAt,
    }));

    const successfulEntries = entries.filter(e => e.successfulTechnique);
    const allDefenses = [...new Set(tFindings.flatMap(f => f.defensesDetected))];
    const allDomains = [...new Set(tFindings.map(f => f.domain))] as EvasionDomain[];

    // Determine recommended approach
    let recommendedApproach: PlaybookTargetGroup["recommendedApproach"] = null;
    if (successfulEntries.length > 0) {
      const techCounts = new Map<string, { count: number; name: string; category: string; levels: number[] }>();
      for (const e of successfulEntries) {
        if (e.successfulTechnique) {
          const existing = techCounts.get(e.successfulTechnique.id) || {
            count: 0,
            name: e.successfulTechnique.name,
            category: e.successfulTechnique.category,
            levels: [],
          };
          existing.count++;
          existing.levels.push(e.successfulTechnique.escalationLevel);
          techCounts.set(e.successfulTechnique.id, existing);
        }
      }
      const best = [...techCounts.entries()].sort((a, b) => b[1].count - a[1].count)[0];
      if (best) {
        const avgLevel = best[1].levels.reduce((a, b) => a + b, 0) / best[1].levels.length;
        recommendedApproach = {
          bestTechnique: best[1].name,
          bestCategory: best[1].category,
          avgEscalationLevel: Math.round(avgLevel * 10) / 10,
          notes: `${best[1].name} succeeded ${best[1].count} time(s) against ${allDefenses.join(", ") || "unknown defenses"} at avg escalation level ${avgLevel.toFixed(1)}`,
        };
      }
    }

    targetGroups.push({
      target,
      totalEngagements: tFindings.length,
      successfulBypasses: tFindings.filter(f => f.finalResult === "bypassed").length,
      overallBypassRate: tFindings.length > 0
        ? Math.round((tFindings.filter(f => f.finalResult === "bypassed").length / tFindings.length) * 100)
        : 0,
      defensesEncountered: allDefenses,
      domains: allDomains,
      entries,
      recommendedApproach,
    });
  }

  // Build defense groups
  const defenseMap = new Map<string, { bypassed: string[]; blocked: string[]; findings: EvasionFinding[] }>();
  for (const f of findings) {
    for (const defense of f.defensesDetected) {
      const existing = defenseMap.get(defense) || { bypassed: [], blocked: [], findings: [] };
      existing.findings.push(f);
      if (f.finalResult === "bypassed" && f.successfulTechnique) {
        existing.bypassed.push(f.successfulTechnique.name);
      }
      // Collect techniques that were blocked
      for (const a of f.attempts) {
        if (a.result === "blocked") {
          existing.blocked.push(a.techniqueName);
        }
      }
      defenseMap.set(defense, existing);
    }
  }

  const defenseGroups: PlaybookDefenseGroup[] = [];
  for (const [defense, data] of defenseMap) {
    const bypassRate = data.findings.length > 0
      ? Math.round((data.findings.filter(f => f.finalResult === "bypassed").length / data.findings.length) * 100)
      : 0;
    const avgEscalation = data.findings
      .filter(f => f.finalResult === "bypassed")
      .reduce((sum, f) => sum + f.evasionScorecard.escalationDepth, 0);
    const bypassedCount = data.findings.filter(f => f.finalResult === "bypassed").length;

    defenseGroups.push({
      defense,
      timesEncountered: data.findings.length,
      timesBypassed: bypassedCount,
      bypassRate,
      effectiveAgainst: [...new Set(data.blocked)],
      vulnerableTo: [...new Set(data.bypassed)],
      avgEscalationToBypass: bypassedCount > 0 ? Math.round((avgEscalation / bypassedCount) * 10) / 10 : 0,
      riskLevel: bypassRate >= 75 ? "critical" : bypassRate >= 50 ? "high" : bypassRate >= 25 ? "medium" : "low",
    });
  }

  // Build technique effectiveness
  const techMap = new Map<string, { used: number; bypassed: number; bestAgainst: Set<string> }>();
  for (const f of findings) {
    for (const a of f.attempts) {
      const existing = techMap.get(a.techniqueId) || { used: 0, bypassed: 0, bestAgainst: new Set<string>() };
      existing.used++;
      if (a.result === "bypassed") {
        existing.bypassed++;
        for (const d of f.defensesDetected) {
          existing.bestAgainst.add(d);
        }
      }
      techMap.set(a.techniqueId, existing);
    }
  }

  const techniqueEffectiveness = [...techMap.entries()].map(([techId, data]) => {
    const ladderEntry = ESCALATION_LADDER.find(t => t.id === techId);
    return {
      techniqueId: techId,
      techniqueName: ladderEntry?.name || techId,
      category: ladderEntry?.category || "unknown",
      level: ladderEntry?.level || 0,
      timesUsed: data.used,
      timesBypassed: data.bypassed,
      successRate: data.used > 0 ? Math.round((data.bypassed / data.used) * 100) : 0,
      bestAgainst: [...data.bestAgainst],
    };
  }).sort((a, b) => b.successRate - a.successRate);

  // Build MITRE mappings
  const mitreMap = new Map<string, { name: string; mitreId: string; count: number }>();
  for (const f of findings) {
    if (f.successfulTechnique) {
      const ladderEntry = ESCALATION_LADDER.find(t => t.id === f.successfulTechnique!.id);
      if (ladderEntry?.mitreTechnique) {
        const key = ladderEntry.mitreTechnique;
        const existing = mitreMap.get(key) || { name: ladderEntry.name, mitreId: key, count: 0 };
        existing.count++;
        mitreMap.set(key, existing);
      }
    }
  }

  const mitreMappings = [...mitreMap.entries()].map(([_, data]) => ({
    techniqueId: data.name,
    techniqueName: data.name,
    mitreId: data.mitreId,
    usageCount: data.count,
  })).sort((a, b) => b.usageCount - a.usageCount);

  // Build summary
  const domainBreakdown: Record<EvasionDomain, { total: number; bypassed: number }> = {
    scanning: { total: 0, bypassed: 0 },
    c2: { total: 0, bypassed: 0 },
    exploit: { total: 0, bypassed: 0 },
  };
  for (const f of findings) {
    domainBreakdown[f.domain].total++;
    if (f.finalResult === "bypassed") domainBreakdown[f.domain].bypassed++;
  }

  const avgDepth = findings.length > 0
    ? Math.round((findings.reduce((s, f) => s + f.evasionScorecard.escalationDepth, 0) / findings.length) * 10) / 10
    : 0;

  // Generate recommendations
  const recommendations = generatePlaybookRecommendations(targetGroups, defenseGroups, techniqueEffectiveness);

  return {
    id: `pb-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`,
    generatedAt: Date.now(),
    title: options?.title || "Evasion Playbook — Red Team Engagement Report",
    summary: {
      totalFindings: findings.length,
      totalTargets: targetGroups.length,
      totalDefenses: defenseGroups.length,
      overallBypassRate: findings.length > 0
        ? Math.round((findings.filter(f => f.finalResult === "bypassed").length / findings.length) * 100)
        : 0,
      domainBreakdown,
      avgEscalationDepth: avgDepth,
    },
    targetGroups,
    defenseGroups,
    techniqueEffectiveness,
    recommendations,
    mitreMappings,
  };
}

function generatePlaybookRecommendations(
  targets: PlaybookTargetGroup[],
  defenses: PlaybookDefenseGroup[],
  techniques: EvasionPlaybook["techniqueEffectiveness"],
): string[] {
  const recs: string[] = [];

  // Identify hardest targets
  const hardTargets = targets.filter(t => t.overallBypassRate < 25);
  if (hardTargets.length > 0) {
    recs.push(
      `${hardTargets.length} target(s) showed strong defense posture (<25% bypass rate). Consider advanced payload staging or out-of-band delivery for: ${hardTargets.map(t => t.target).join(", ")}`
    );
  }

  // Identify weak defenses
  const weakDefenses = defenses.filter(d => d.riskLevel === "critical");
  if (weakDefenses.length > 0) {
    recs.push(
      `Critical finding: ${weakDefenses.map(d => d.defense).join(", ")} showed ≥75% bypass rate. Recommend upgrading or supplementing these defense products.`
    );
  }

  // Identify most effective techniques
  const topTechs = techniques.filter(t => t.successRate >= 60 && t.timesUsed >= 2);
  if (topTechs.length > 0) {
    recs.push(
      `Most reliable bypass techniques: ${topTechs.slice(0, 3).map(t => `${t.techniqueName} (${t.successRate}% success)`).join(", ")}. Prioritize these in future engagements.`
    );
  }

  // Identify techniques that never worked
  const failedTechs = techniques.filter(t => t.successRate === 0 && t.timesUsed >= 3);
  if (failedTechs.length > 0) {
    recs.push(
      `Techniques with 0% success rate across 3+ attempts: ${failedTechs.map(t => t.techniqueName).join(", ")}. Consider removing from escalation ladder for similar targets.`
    );
  }

  // Domain-specific recommendations
  const domainStats = { scanning: { total: 0, bypassed: 0 }, c2: { total: 0, bypassed: 0 }, exploit: { total: 0, bypassed: 0 } };
  for (const t of targets) {
    for (const e of t.entries) {
      domainStats[e.domain].total++;
      if (e.successfulTechnique) domainStats[e.domain].bypassed++;
    }
  }

  if (domainStats.scanning.total > 0 && domainStats.scanning.bypassed / domainStats.scanning.total < 0.3) {
    recs.push("Scanning bypass rate is below 30%. Consider using distributed scanning infrastructure or cloud-based scan proxies.");
  }
  if (domainStats.c2.total > 0 && domainStats.c2.bypassed / domainStats.c2.total < 0.3) {
    recs.push("C2 bypass rate is below 30%. Consider domain fronting via legitimate CDNs or encrypted DNS channels.");
  }
  if (domainStats.exploit.total > 0 && domainStats.exploit.bypassed / domainStats.exploit.total < 0.3) {
    recs.push("Exploit delivery bypass rate is below 30%. Consider multi-stage payloads with initial benign dropper.");
  }

  if (recs.length === 0) {
    recs.push("No findings available yet. Run evasion-wrapped operations to populate the playbook.");
  }

  return recs;
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — MARKDOWN EXPORT
// ═══════════════════════════════════════════════════════════════════════

/**
 * Export the playbook as a formatted Markdown report.
 */
export function exportPlaybookMarkdown(playbook: EvasionPlaybook): string {
  const lines: string[] = [];
  const ts = new Date(playbook.generatedAt).toISOString();

  lines.push(`# ${playbook.title}`);
  lines.push("");
  lines.push(`**Generated:** ${ts}  `);
  lines.push(`**Report ID:** ${playbook.id}`);
  lines.push("");

  // Executive Summary
  lines.push("## Executive Summary");
  lines.push("");
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total Engagements | ${playbook.summary.totalFindings} |`);
  lines.push(`| Targets Tested | ${playbook.summary.totalTargets} |`);
  lines.push(`| Defenses Encountered | ${playbook.summary.totalDefenses} |`);
  lines.push(`| Overall Bypass Rate | ${playbook.summary.overallBypassRate}% |`);
  lines.push(`| Avg Escalation Depth | ${playbook.summary.avgEscalationDepth} |`);
  lines.push("");

  // Domain breakdown
  lines.push("### Domain Breakdown");
  lines.push("");
  lines.push("| Domain | Total | Bypassed | Rate |");
  lines.push("|--------|-------|----------|------|");
  for (const [domain, stats] of Object.entries(playbook.summary.domainBreakdown)) {
    const rate = stats.total > 0 ? Math.round((stats.bypassed / stats.total) * 100) : 0;
    lines.push(`| ${domain} | ${stats.total} | ${stats.bypassed} | ${rate}% |`);
  }
  lines.push("");

  // Target Analysis
  lines.push("## Target Analysis");
  lines.push("");
  for (const tg of playbook.targetGroups) {
    lines.push(`### ${tg.target}`);
    lines.push("");
    lines.push(`- **Engagements:** ${tg.totalEngagements}`);
    lines.push(`- **Successful Bypasses:** ${tg.successfulBypasses}`);
    lines.push(`- **Bypass Rate:** ${tg.overallBypassRate}%`);
    lines.push(`- **Defenses Detected:** ${tg.defensesEncountered.join(", ") || "None detected"}`);
    lines.push(`- **Domains Tested:** ${tg.domains.join(", ")}`);
    if (tg.recommendedApproach) {
      lines.push(`- **Recommended Approach:** ${tg.recommendedApproach.bestTechnique} (${tg.recommendedApproach.bestCategory}) — ${tg.recommendedApproach.notes}`);
    }
    lines.push("");

    // Escalation paths
    if (tg.entries.length > 0) {
      lines.push("#### Escalation History");
      lines.push("");
      for (const entry of tg.entries.slice(0, 5)) {
        const status = entry.successfulTechnique ? `✅ Bypassed via ${entry.successfulTechnique.name}` : "❌ Blocked";
        lines.push(`- **${entry.operation}** (${entry.domain}) — ${status}`);
        if (entry.escalationPath.length > 0) {
          for (const step of entry.escalationPath) {
            const icon = step.result === "bypassed" ? "✅" : "❌";
            lines.push(`  - ${icon} ${step.techniqueName} → ${step.result}${step.blockSignal ? ` (${step.blockSignal})` : ""}`);
          }
        }
      }
      if (tg.entries.length > 5) {
        lines.push(`  - ... and ${tg.entries.length - 5} more engagements`);
      }
      lines.push("");
    }
  }

  // Defense Analysis
  lines.push("## Defense Product Analysis");
  lines.push("");
  if (playbook.defenseGroups.length > 0) {
    lines.push("| Defense | Encountered | Bypassed | Bypass Rate | Risk Level | Avg Escalation |");
    lines.push("|---------|-------------|----------|-------------|------------|----------------|");
    for (const dg of playbook.defenseGroups.sort((a, b) => b.bypassRate - a.bypassRate)) {
      const riskEmoji = dg.riskLevel === "critical" ? "🔴" : dg.riskLevel === "high" ? "🟠" : dg.riskLevel === "medium" ? "🟡" : "🟢";
      lines.push(`| ${dg.defense} | ${dg.timesEncountered} | ${dg.timesBypassed} | ${dg.bypassRate}% | ${riskEmoji} ${dg.riskLevel} | ${dg.avgEscalationToBypass} |`);
    }
    lines.push("");

    for (const dg of playbook.defenseGroups) {
      if (dg.vulnerableTo.length > 0) {
        lines.push(`**${dg.defense}** — Vulnerable to: ${dg.vulnerableTo.join(", ")}`);
      }
      if (dg.effectiveAgainst.length > 0) {
        lines.push(`**${dg.defense}** — Effective against: ${dg.effectiveAgainst.slice(0, 5).join(", ")}${dg.effectiveAgainst.length > 5 ? ` (+${dg.effectiveAgainst.length - 5} more)` : ""}`);
      }
    }
    lines.push("");
  } else {
    lines.push("No defense products detected in current findings.");
    lines.push("");
  }

  // Technique Effectiveness
  lines.push("## Technique Effectiveness");
  lines.push("");
  if (playbook.techniqueEffectiveness.length > 0) {
    lines.push("| Technique | Category | Level | Used | Bypassed | Success Rate |");
    lines.push("|-----------|----------|-------|------|----------|--------------|");
    for (const te of playbook.techniqueEffectiveness) {
      lines.push(`| ${te.techniqueName} | ${te.category} | ${te.level} | ${te.timesUsed} | ${te.timesBypassed} | ${te.successRate}% |`);
    }
    lines.push("");
  }

  // MITRE ATT&CK Mappings
  if (playbook.mitreMappings.length > 0) {
    lines.push("## MITRE ATT&CK Mappings");
    lines.push("");
    lines.push("| Technique | MITRE ID | Usage Count |");
    lines.push("|-----------|----------|-------------|");
    for (const m of playbook.mitreMappings) {
      lines.push(`| ${m.techniqueName} | ${m.mitreId} | ${m.usageCount} |`);
    }
    lines.push("");
  }

  // Recommendations
  lines.push("## Recommendations");
  lines.push("");
  for (let i = 0; i < playbook.recommendations.length; i++) {
    lines.push(`${i + 1}. ${playbook.recommendations[i]}`);
  }
  lines.push("");

  lines.push("---");
  lines.push(`*Report generated by Ace Strike Evasion Orchestrator*`);
  lines.push("");

  return lines.join("\n");
}

/**
 * Export the playbook as a JSON string.
 */
export function exportPlaybookJSON(playbook: EvasionPlaybook): string {
  return JSON.stringify(playbook, null, 2);
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — DEFENSE HEATMAP GENERATOR
// ═══════════════════════════════════════════════════════════════════════

/**
 * Generate a defense heatmap from stored findings.
 * Rows = defense products, Columns = evasion techniques.
 * Cell value = bypass rate for that technique against that defense.
 */
export function generateDefenseHeatmap(options?: {
  domain?: EvasionDomain;
  minEncounters?: number;
}): DefenseHeatmap {
  const findings = getFindings({ domain: options?.domain, limit: 200 });
  const minEncounters = options?.minEncounters || 1;

  // Build a matrix: defense → technique → { encounters, bypasses, blocks, latencies }
  const matrix = new Map<string, Map<string, {
    encounters: number;
    bypasses: number;
    blocks: number;
    latencies: number[];
  }>>();

  const allDefenses = new Set<string>();
  const allTechniques = new Set<string>();

  for (const f of findings) {
    if (f.defensesDetected.length === 0) continue;

    for (const defense of f.defensesDetected) {
      allDefenses.add(defense);
      if (!matrix.has(defense)) matrix.set(defense, new Map());
      const defenseRow = matrix.get(defense)!;

      for (const attempt of f.attempts) {
        allTechniques.add(attempt.techniqueName);
        const existing = defenseRow.get(attempt.techniqueName) || {
          encounters: 0,
          bypasses: 0,
          blocks: 0,
          latencies: [],
        };
        existing.encounters++;
        if (attempt.result === "bypassed") {
          existing.bypasses++;
        } else if (attempt.result === "blocked") {
          existing.blocks++;
        }
        existing.latencies.push(attempt.latencyMs);
        defenseRow.set(attempt.techniqueName, existing);
      }
    }
  }

  // Build heatmap rows
  const techniqueList = [...allTechniques].sort();
  const rows: HeatmapRow[] = [];

  for (const defense of [...allDefenses].sort()) {
    const defenseRow = matrix.get(defense);
    if (!defenseRow) continue;

    let totalEnc = 0;
    let totalBypass = 0;
    const cells: HeatmapCell[] = [];

    for (const technique of techniqueList) {
      const data = defenseRow.get(technique);
      if (!data || data.encounters < minEncounters) {
        cells.push({
          defense,
          technique,
          techniqueCategory: ESCALATION_LADDER.find(t => t.name === technique)?.category || "unknown",
          encounters: 0,
          bypasses: 0,
          blocks: 0,
          bypassRate: 0,
          avgLatencyMs: 0,
          intensity: 0,
        });
        continue;
      }

      totalEnc += data.encounters;
      totalBypass += data.bypasses;
      const bypassRate = Math.round((data.bypasses / data.encounters) * 100);
      const avgLatency = data.latencies.length > 0
        ? Math.round(data.latencies.reduce((a, b) => a + b, 0) / data.latencies.length)
        : 0;

      cells.push({
        defense,
        technique,
        techniqueCategory: ESCALATION_LADDER.find(t => t.name === technique)?.category || "unknown",
        encounters: data.encounters,
        bypasses: data.bypasses,
        blocks: data.blocks,
        bypassRate,
        avgLatencyMs: avgLatency,
        intensity: bypassRate / 100,
      });
    }

    rows.push({
      defense,
      totalEncounters: totalEnc,
      overallBypassRate: totalEnc > 0 ? Math.round((totalBypass / totalEnc) * 100) : 0,
      cells,
    });
  }

  // Compute summary
  const allCells = rows.flatMap(r => r.cells).filter(c => c.encounters > 0);

  // Most/least effective defense (lowest/highest bypass rate)
  const defenseRates = rows.filter(r => r.totalEncounters > 0);
  const mostEffectiveDefense = defenseRates.length > 0
    ? defenseRates.sort((a, b) => a.overallBypassRate - b.overallBypassRate)[0]
    : null;
  const leastEffectiveDefense = defenseRates.length > 0
    ? defenseRates.sort((a, b) => b.overallBypassRate - a.overallBypassRate)[0]
    : null;

  // Most/least effective technique (highest/lowest success rate across all defenses)
  const techRates = new Map<string, { total: number; bypassed: number }>();
  for (const cell of allCells) {
    const existing = techRates.get(cell.technique) || { total: 0, bypassed: 0 };
    existing.total += cell.encounters;
    existing.bypassed += cell.bypasses;
    techRates.set(cell.technique, existing);
  }
  const techRateList = [...techRates.entries()]
    .map(([name, data]) => ({ name, successRate: data.total > 0 ? Math.round((data.bypassed / data.total) * 100) : 0 }))
    .sort((a, b) => b.successRate - a.successRate);

  return {
    generatedAt: Date.now(),
    defenses: [...allDefenses].sort(),
    techniques: techniqueList,
    rows,
    summary: {
      mostEffectiveDefense: mostEffectiveDefense
        ? { name: mostEffectiveDefense.defense, bypassRate: mostEffectiveDefense.overallBypassRate }
        : null,
      leastEffectiveDefense: leastEffectiveDefense
        ? { name: leastEffectiveDefense.defense, bypassRate: leastEffectiveDefense.overallBypassRate }
        : null,
      mostEffectiveTechnique: techRateList.length > 0 ? techRateList[0] : null,
      leastEffectiveTechnique: techRateList.length > 0 ? techRateList[techRateList.length - 1] : null,
      totalDataPoints: allCells.length,
    },
    domainFilter: options?.domain,
  };
}
