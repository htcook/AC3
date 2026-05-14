import {
  ESCALATION_LADDER,
  getFindings
} from "./chunk-SP7DWOM3.js";
import "./chunk-JGUFAE3I.js";
import "./chunk-KFQGP6VL.js";

// server/lib/evasion-playbook.ts
function generatePlaybook(options) {
  let findings = getFindings({ domain: options?.domain, target: options?.target, limit: 200 });
  if (options?.onlySuccessful) {
    findings = findings.filter((f) => f.finalResult === "bypassed");
  }
  const targetMap = /* @__PURE__ */ new Map();
  for (const f of findings) {
    const existing = targetMap.get(f.target) || [];
    existing.push(f);
    targetMap.set(f.target, existing);
  }
  const targetGroups = [];
  for (const [target, tFindings] of targetMap) {
    const entries = tFindings.map((f) => ({
      target: f.target,
      domain: f.domain,
      operation: f.operation,
      defensesDetected: f.defensesDetected,
      successfulTechnique: f.successfulTechnique ? {
        ...f.successfulTechnique,
        mitreTechnique: ESCALATION_LADDER.find((t) => t.id === f.successfulTechnique.id)?.mitreTechnique
      } : null,
      escalationPath: f.attempts.map((a) => ({
        techniqueId: a.techniqueId,
        techniqueName: a.techniqueName,
        result: a.result,
        blockSignal: a.blockSignal
      })),
      totalAttempts: f.totalAttempts,
      bypassRate: f.evasionScorecard.bypassRate,
      timestamp: f.completedAt
    }));
    const successfulEntries = entries.filter((e) => e.successfulTechnique);
    const allDefenses = [...new Set(tFindings.flatMap((f) => f.defensesDetected))];
    const allDomains = [...new Set(tFindings.map((f) => f.domain))];
    let recommendedApproach = null;
    if (successfulEntries.length > 0) {
      const techCounts = /* @__PURE__ */ new Map();
      for (const e of successfulEntries) {
        if (e.successfulTechnique) {
          const existing = techCounts.get(e.successfulTechnique.id) || {
            count: 0,
            name: e.successfulTechnique.name,
            category: e.successfulTechnique.category,
            levels: []
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
          notes: `${best[1].name} succeeded ${best[1].count} time(s) against ${allDefenses.join(", ") || "unknown defenses"} at avg escalation level ${avgLevel.toFixed(1)}`
        };
      }
    }
    targetGroups.push({
      target,
      totalEngagements: tFindings.length,
      successfulBypasses: tFindings.filter((f) => f.finalResult === "bypassed").length,
      overallBypassRate: tFindings.length > 0 ? Math.round(tFindings.filter((f) => f.finalResult === "bypassed").length / tFindings.length * 100) : 0,
      defensesEncountered: allDefenses,
      domains: allDomains,
      entries,
      recommendedApproach
    });
  }
  const defenseMap = /* @__PURE__ */ new Map();
  for (const f of findings) {
    for (const defense of f.defensesDetected) {
      const existing = defenseMap.get(defense) || { bypassed: [], blocked: [], findings: [] };
      existing.findings.push(f);
      if (f.finalResult === "bypassed" && f.successfulTechnique) {
        existing.bypassed.push(f.successfulTechnique.name);
      }
      for (const a of f.attempts) {
        if (a.result === "blocked") {
          existing.blocked.push(a.techniqueName);
        }
      }
      defenseMap.set(defense, existing);
    }
  }
  const defenseGroups = [];
  for (const [defense, data] of defenseMap) {
    const bypassRate = data.findings.length > 0 ? Math.round(data.findings.filter((f) => f.finalResult === "bypassed").length / data.findings.length * 100) : 0;
    const avgEscalation = data.findings.filter((f) => f.finalResult === "bypassed").reduce((sum, f) => sum + f.evasionScorecard.escalationDepth, 0);
    const bypassedCount = data.findings.filter((f) => f.finalResult === "bypassed").length;
    defenseGroups.push({
      defense,
      timesEncountered: data.findings.length,
      timesBypassed: bypassedCount,
      bypassRate,
      effectiveAgainst: [...new Set(data.blocked)],
      vulnerableTo: [...new Set(data.bypassed)],
      avgEscalationToBypass: bypassedCount > 0 ? Math.round(avgEscalation / bypassedCount * 10) / 10 : 0,
      riskLevel: bypassRate >= 75 ? "critical" : bypassRate >= 50 ? "high" : bypassRate >= 25 ? "medium" : "low"
    });
  }
  const techMap = /* @__PURE__ */ new Map();
  for (const f of findings) {
    for (const a of f.attempts) {
      const existing = techMap.get(a.techniqueId) || { used: 0, bypassed: 0, bestAgainst: /* @__PURE__ */ new Set() };
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
    const ladderEntry = ESCALATION_LADDER.find((t) => t.id === techId);
    return {
      techniqueId: techId,
      techniqueName: ladderEntry?.name || techId,
      category: ladderEntry?.category || "unknown",
      level: ladderEntry?.level || 0,
      timesUsed: data.used,
      timesBypassed: data.bypassed,
      successRate: data.used > 0 ? Math.round(data.bypassed / data.used * 100) : 0,
      bestAgainst: [...data.bestAgainst]
    };
  }).sort((a, b) => b.successRate - a.successRate);
  const mitreMap = /* @__PURE__ */ new Map();
  for (const f of findings) {
    if (f.successfulTechnique) {
      const ladderEntry = ESCALATION_LADDER.find((t) => t.id === f.successfulTechnique.id);
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
    usageCount: data.count
  })).sort((a, b) => b.usageCount - a.usageCount);
  const domainBreakdown = {
    scanning: { total: 0, bypassed: 0 },
    c2: { total: 0, bypassed: 0 },
    exploit: { total: 0, bypassed: 0 }
  };
  for (const f of findings) {
    domainBreakdown[f.domain].total++;
    if (f.finalResult === "bypassed") domainBreakdown[f.domain].bypassed++;
  }
  const avgDepth = findings.length > 0 ? Math.round(findings.reduce((s, f) => s + f.evasionScorecard.escalationDepth, 0) / findings.length * 10) / 10 : 0;
  const recommendations = generatePlaybookRecommendations(targetGroups, defenseGroups, techniqueEffectiveness);
  return {
    id: `pb-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`,
    generatedAt: Date.now(),
    title: options?.title || "Evasion Playbook \u2014 Red Team Engagement Report",
    summary: {
      totalFindings: findings.length,
      totalTargets: targetGroups.length,
      totalDefenses: defenseGroups.length,
      overallBypassRate: findings.length > 0 ? Math.round(findings.filter((f) => f.finalResult === "bypassed").length / findings.length * 100) : 0,
      domainBreakdown,
      avgEscalationDepth: avgDepth
    },
    targetGroups,
    defenseGroups,
    techniqueEffectiveness,
    recommendations,
    mitreMappings
  };
}
function generatePlaybookRecommendations(targets, defenses, techniques) {
  const recs = [];
  const hardTargets = targets.filter((t) => t.overallBypassRate < 25);
  if (hardTargets.length > 0) {
    recs.push(
      `${hardTargets.length} target(s) showed strong defense posture (<25% bypass rate). Consider advanced payload staging or out-of-band delivery for: ${hardTargets.map((t) => t.target).join(", ")}`
    );
  }
  const weakDefenses = defenses.filter((d) => d.riskLevel === "critical");
  if (weakDefenses.length > 0) {
    recs.push(
      `Critical finding: ${weakDefenses.map((d) => d.defense).join(", ")} showed \u226575% bypass rate. Recommend upgrading or supplementing these defense products.`
    );
  }
  const topTechs = techniques.filter((t) => t.successRate >= 60 && t.timesUsed >= 2);
  if (topTechs.length > 0) {
    recs.push(
      `Most reliable bypass techniques: ${topTechs.slice(0, 3).map((t) => `${t.techniqueName} (${t.successRate}% success)`).join(", ")}. Prioritize these in future engagements.`
    );
  }
  const failedTechs = techniques.filter((t) => t.successRate === 0 && t.timesUsed >= 3);
  if (failedTechs.length > 0) {
    recs.push(
      `Techniques with 0% success rate across 3+ attempts: ${failedTechs.map((t) => t.techniqueName).join(", ")}. Consider removing from escalation ladder for similar targets.`
    );
  }
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
function exportPlaybookMarkdown(playbook) {
  const lines = [];
  const ts = new Date(playbook.generatedAt).toISOString();
  lines.push(`# ${playbook.title}`);
  lines.push("");
  lines.push(`**Generated:** ${ts}  `);
  lines.push(`**Report ID:** ${playbook.id}`);
  lines.push("");
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
  lines.push("### Domain Breakdown");
  lines.push("");
  lines.push("| Domain | Total | Bypassed | Rate |");
  lines.push("|--------|-------|----------|------|");
  for (const [domain, stats] of Object.entries(playbook.summary.domainBreakdown)) {
    const rate = stats.total > 0 ? Math.round(stats.bypassed / stats.total * 100) : 0;
    lines.push(`| ${domain} | ${stats.total} | ${stats.bypassed} | ${rate}% |`);
  }
  lines.push("");
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
      lines.push(`- **Recommended Approach:** ${tg.recommendedApproach.bestTechnique} (${tg.recommendedApproach.bestCategory}) \u2014 ${tg.recommendedApproach.notes}`);
    }
    lines.push("");
    if (tg.entries.length > 0) {
      lines.push("#### Escalation History");
      lines.push("");
      for (const entry of tg.entries.slice(0, 5)) {
        const status = entry.successfulTechnique ? `\u2705 Bypassed via ${entry.successfulTechnique.name}` : "\u274C Blocked";
        lines.push(`- **${entry.operation}** (${entry.domain}) \u2014 ${status}`);
        if (entry.escalationPath.length > 0) {
          for (const step of entry.escalationPath) {
            const icon = step.result === "bypassed" ? "\u2705" : "\u274C";
            lines.push(`  - ${icon} ${step.techniqueName} \u2192 ${step.result}${step.blockSignal ? ` (${step.blockSignal})` : ""}`);
          }
        }
      }
      if (tg.entries.length > 5) {
        lines.push(`  - ... and ${tg.entries.length - 5} more engagements`);
      }
      lines.push("");
    }
  }
  lines.push("## Defense Product Analysis");
  lines.push("");
  if (playbook.defenseGroups.length > 0) {
    lines.push("| Defense | Encountered | Bypassed | Bypass Rate | Risk Level | Avg Escalation |");
    lines.push("|---------|-------------|----------|-------------|------------|----------------|");
    for (const dg of playbook.defenseGroups.sort((a, b) => b.bypassRate - a.bypassRate)) {
      const riskEmoji = dg.riskLevel === "critical" ? "\u{1F534}" : dg.riskLevel === "high" ? "\u{1F7E0}" : dg.riskLevel === "medium" ? "\u{1F7E1}" : "\u{1F7E2}";
      lines.push(`| ${dg.defense} | ${dg.timesEncountered} | ${dg.timesBypassed} | ${dg.bypassRate}% | ${riskEmoji} ${dg.riskLevel} | ${dg.avgEscalationToBypass} |`);
    }
    lines.push("");
    for (const dg of playbook.defenseGroups) {
      if (dg.vulnerableTo.length > 0) {
        lines.push(`**${dg.defense}** \u2014 Vulnerable to: ${dg.vulnerableTo.join(", ")}`);
      }
      if (dg.effectiveAgainst.length > 0) {
        lines.push(`**${dg.defense}** \u2014 Effective against: ${dg.effectiveAgainst.slice(0, 5).join(", ")}${dg.effectiveAgainst.length > 5 ? ` (+${dg.effectiveAgainst.length - 5} more)` : ""}`);
      }
    }
    lines.push("");
  } else {
    lines.push("No defense products detected in current findings.");
    lines.push("");
  }
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
function exportPlaybookJSON(playbook) {
  return JSON.stringify(playbook, null, 2);
}
function generateDefenseHeatmap(options) {
  const findings = getFindings({ domain: options?.domain, limit: 200 });
  const minEncounters = options?.minEncounters || 1;
  const matrix = /* @__PURE__ */ new Map();
  const allDefenses = /* @__PURE__ */ new Set();
  const allTechniques = /* @__PURE__ */ new Set();
  for (const f of findings) {
    if (f.defensesDetected.length === 0) continue;
    for (const defense of f.defensesDetected) {
      allDefenses.add(defense);
      if (!matrix.has(defense)) matrix.set(defense, /* @__PURE__ */ new Map());
      const defenseRow = matrix.get(defense);
      for (const attempt of f.attempts) {
        allTechniques.add(attempt.techniqueName);
        const existing = defenseRow.get(attempt.techniqueName) || {
          encounters: 0,
          bypasses: 0,
          blocks: 0,
          latencies: []
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
  const techniqueList = [...allTechniques].sort();
  const rows = [];
  for (const defense of [...allDefenses].sort()) {
    const defenseRow = matrix.get(defense);
    if (!defenseRow) continue;
    let totalEnc = 0;
    let totalBypass = 0;
    const cells = [];
    for (const technique of techniqueList) {
      const data = defenseRow.get(technique);
      if (!data || data.encounters < minEncounters) {
        cells.push({
          defense,
          technique,
          techniqueCategory: ESCALATION_LADDER.find((t) => t.name === technique)?.category || "unknown",
          encounters: 0,
          bypasses: 0,
          blocks: 0,
          bypassRate: 0,
          avgLatencyMs: 0,
          intensity: 0
        });
        continue;
      }
      totalEnc += data.encounters;
      totalBypass += data.bypasses;
      const bypassRate = Math.round(data.bypasses / data.encounters * 100);
      const avgLatency = data.latencies.length > 0 ? Math.round(data.latencies.reduce((a, b) => a + b, 0) / data.latencies.length) : 0;
      cells.push({
        defense,
        technique,
        techniqueCategory: ESCALATION_LADDER.find((t) => t.name === technique)?.category || "unknown",
        encounters: data.encounters,
        bypasses: data.bypasses,
        blocks: data.blocks,
        bypassRate,
        avgLatencyMs: avgLatency,
        intensity: bypassRate / 100
      });
    }
    rows.push({
      defense,
      totalEncounters: totalEnc,
      overallBypassRate: totalEnc > 0 ? Math.round(totalBypass / totalEnc * 100) : 0,
      cells
    });
  }
  const allCells = rows.flatMap((r) => r.cells).filter((c) => c.encounters > 0);
  const defenseRates = rows.filter((r) => r.totalEncounters > 0);
  const mostEffectiveDefense = defenseRates.length > 0 ? defenseRates.sort((a, b) => a.overallBypassRate - b.overallBypassRate)[0] : null;
  const leastEffectiveDefense = defenseRates.length > 0 ? defenseRates.sort((a, b) => b.overallBypassRate - a.overallBypassRate)[0] : null;
  const techRates = /* @__PURE__ */ new Map();
  for (const cell of allCells) {
    const existing = techRates.get(cell.technique) || { total: 0, bypassed: 0 };
    existing.total += cell.encounters;
    existing.bypassed += cell.bypasses;
    techRates.set(cell.technique, existing);
  }
  const techRateList = [...techRates.entries()].map(([name, data]) => ({ name, successRate: data.total > 0 ? Math.round(data.bypassed / data.total * 100) : 0 })).sort((a, b) => b.successRate - a.successRate);
  return {
    generatedAt: Date.now(),
    defenses: [...allDefenses].sort(),
    techniques: techniqueList,
    rows,
    summary: {
      mostEffectiveDefense: mostEffectiveDefense ? { name: mostEffectiveDefense.defense, bypassRate: mostEffectiveDefense.overallBypassRate } : null,
      leastEffectiveDefense: leastEffectiveDefense ? { name: leastEffectiveDefense.defense, bypassRate: leastEffectiveDefense.overallBypassRate } : null,
      mostEffectiveTechnique: techRateList.length > 0 ? techRateList[0] : null,
      leastEffectiveTechnique: techRateList.length > 0 ? techRateList[techRateList.length - 1] : null,
      totalDataPoints: allCells.length
    },
    domainFilter: options?.domain
  };
}
export {
  exportPlaybookJSON,
  exportPlaybookMarkdown,
  generateDefenseHeatmap,
  generatePlaybook
};
