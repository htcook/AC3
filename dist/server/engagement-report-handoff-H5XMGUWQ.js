import {
  init_llm,
  invokeLLM
} from "./chunk-L5VXSJ4F.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-GN2OC6SU.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/engagement-report-handoff.ts
async function generateTestPlanAdherence(state, testPlan) {
  const ptesPhaseCompletion = analyzePtesPhaseCompletion(state);
  const plannedVsActual = testPlan ? compareTestPlanToExecution(testPlan, state) : [];
  const coverageGaps = identifyCoverageGaps(ptesPhaseCompletion, plannedVsActual, state);
  const recommendations = await generateAdherenceRecommendations(
    ptesPhaseCompletion,
    plannedVsActual,
    coverageGaps,
    state
  );
  const totalPlanned = plannedVsActual.length || ptesPhaseCompletion.length;
  const executed = plannedVsActual.filter((p) => p.status === "executed").length;
  const partial = plannedVsActual.filter((p) => p.status === "partially_executed").length;
  const skipped = plannedVsActual.filter((p) => p.status === "not_executed").length;
  const blocked = plannedVsActual.filter((p) => p.status === "blocked").length;
  const plannedAdherence = totalPlanned > 0 && plannedVsActual.length > 0 ? Math.round((executed + partial * 0.5) / totalPlanned * 100) : 0;
  const phaseAdherence = calculatePhaseAdherence(ptesPhaseCompletion);
  const adherencePercentage = Math.max(plannedAdherence, phaseAdherence);
  return {
    totalPlannedTests: totalPlanned,
    executedTests: executed,
    partiallyExecutedTests: partial,
    skippedTests: skipped,
    blockedTests: blocked,
    adherencePercentage,
    ptesPhaseCompletion,
    plannedVsActual,
    coverageGaps,
    recommendations,
    generatedAt: Date.now()
  };
}
function analyzePtesPhaseCompletion(state) {
  return PTES_PHASES.map((ptesDef) => {
    const matchingLogs = state.log.filter((entry) => {
      const phaseMatch = ptesDef.logPhases.some((lp) => entry.phase === lp);
      const indicatorMatch = ptesDef.indicators.some(
        (ind) => (entry.title || "").toLowerCase().includes(ind) || (entry.detail || "").toLowerCase().includes(ind)
      );
      return phaseMatch || indicatorMatch;
    });
    const phaseFindings = countFindingsForPhase(ptesDef.logPhases, state);
    const evidence = matchingLogs.filter((l) => l.type === "phase_complete" || l.type === "scan_result" || l.type === "finding" || l.type === "evidence").map((l) => l.title).slice(0, 10);
    let status;
    if (matchingLogs.length === 0) {
      status = "skipped";
    } else if (evidence.length >= 2 || phaseFindings > 0) {
      status = "completed";
    } else {
      status = "partial";
    }
    if (ptesDef.phase === "Pre-engagement Interactions" && state.phase === "completed") {
      status = "completed";
    }
    if (ptesDef.phase === "Reporting" && state.metadata?.autoReportId) {
      status = "completed";
    }
    return {
      phase: ptesDef.phase,
      ptesSection: ptesDef.ptesSection,
      nistSection: ptesDef.nistSection,
      status,
      evidence,
      findings: phaseFindings,
      notes: generatePhaseNotes(ptesDef.phase, matchingLogs, state)
    };
  });
}
function compareTestPlanToExecution(testPlan, state) {
  const attackVectors = testPlan.structuredData?.attackVectors || [];
  const toolMatrix = testPlan.structuredData?.toolMatrix || [];
  const usedTools = /* @__PURE__ */ new Set();
  const toolTargets = /* @__PURE__ */ new Map();
  for (const asset of state.assets) {
    for (const tr of asset.toolResults || []) {
      if (tr.tool) {
        usedTools.add(tr.tool.toLowerCase());
        if (!toolTargets.has(tr.tool.toLowerCase())) {
          toolTargets.set(tr.tool.toLowerCase(), /* @__PURE__ */ new Set());
        }
        toolTargets.get(tr.tool.toLowerCase()).add(asset.hostname || asset.ip);
      }
    }
    for (const v of asset.vulns) {
      const src = (v.source || v.tool || "").toLowerCase();
      if (src) usedTools.add(src);
    }
    if (asset.zapFindings.length > 0) usedTools.add("zap");
    if (asset.nucleiFindings && asset.nucleiFindings.length > 0) usedTools.add("nuclei");
    for (const ea of asset.exploitAttempts) {
      if (ea.tool) usedTools.add(ea.tool.toLowerCase());
    }
  }
  for (const entry of state.log) {
    const text = `${entry.title} ${entry.detail || ""}`.toLowerCase();
    const toolPatterns = [
      "naabu",
      "masscan",
      "nerva",
      "nuclei",
      "zap",
      "sqlmap",
      "hydra",
      "nikto",
      "commix",
      "tplmap",
      "ffuf",
      "httpx",
      "metasploit",
      "xsstrike",
      "testssl",
      "ssh-audit",
      "gobuster",
      "dirsearch",
      "wfuzz",
      "burp"
    ];
    for (const tool of toolPatterns) {
      if (text.includes(tool)) usedTools.add(tool);
    }
  }
  const results = [];
  for (const av of attackVectors) {
    const plannedTools = av.tools.map((t) => t.toLowerCase());
    const toolsUsed = plannedTools.filter((t) => usedTools.has(t));
    const targetsHit = av.targets.filter(
      (t) => state.assets.some(
        (a) => (a.hostname || "").includes(t) || (a.ip || "").includes(t)
      )
    );
    let findingsCount = 0;
    for (const asset of state.assets) {
      for (const v of asset.vulns) {
        const src = (v.source || v.tool || "").toLowerCase();
        if (plannedTools.some((pt) => src.includes(pt))) findingsCount++;
      }
    }
    let status;
    let reason;
    if (toolsUsed.length === 0 && targetsHit.length === 0) {
      status = "not_executed";
      reason = `None of the planned tools (${av.tools.join(", ")}) were used against the targets`;
    } else if (toolsUsed.length === plannedTools.length && targetsHit.length >= av.targets.length) {
      status = "executed";
    } else if (toolsUsed.length > 0 || targetsHit.length > 0) {
      status = "partially_executed";
      reason = `${toolsUsed.length}/${plannedTools.length} tools used, ${targetsHit.length}/${av.targets.length} targets covered`;
    } else {
      status = "blocked";
      reason = "Target not reachable or tool execution failed";
    }
    results.push({
      plannedTest: av.name,
      ptesPhase: av.ptesPhase,
      tool: av.tools.join(", "),
      target: av.targets.join(", "),
      status,
      reason,
      findingsFromTest: findingsCount,
      evidenceCollected: findingsCount > 0
    });
  }
  for (const tm of toolMatrix) {
    const alreadyCovered = results.some(
      (r) => r.tool.toLowerCase().includes(tm.tool.toLowerCase())
    );
    if (alreadyCovered) continue;
    const toolUsed = usedTools.has(tm.tool.toLowerCase());
    results.push({
      plannedTest: `${tm.purpose} (${tm.tool})`,
      ptesPhase: tm.phase,
      tool: tm.tool,
      target: tm.targets.join(", "),
      status: toolUsed ? "executed" : "not_executed",
      findingsFromTest: 0,
      evidenceCollected: toolUsed
    });
  }
  return results;
}
function identifyCoverageGaps(ptesPhases, plannedVsActual, state) {
  const gaps = [];
  for (const phase of ptesPhases) {
    if (phase.status === "skipped" && phase.phase !== "Post-Exploitation") {
      gaps.push({
        area: phase.phase,
        ptesPhase: phase.ptesSection,
        severity: phase.phase === "Vulnerability Analysis" || phase.phase === "Exploitation" ? "critical" : "medium",
        description: `PTES ${phase.ptesSection} (${phase.phase}) was not executed during this engagement`,
        recommendation: `Include ${phase.phase.toLowerCase()} activities in the next engagement iteration`
      });
    }
  }
  const skippedHighPriority = plannedVsActual.filter(
    (p) => p.status === "not_executed" && p.ptesPhase.includes("Exploitation")
  );
  for (const test of skippedHighPriority) {
    gaps.push({
      area: test.plannedTest,
      ptesPhase: test.ptesPhase,
      severity: "high",
      description: `Planned exploitation test "${test.plannedTest}" was not executed`,
      recommendation: `Schedule follow-up testing with ${test.tool} against ${test.target}`
    });
  }
  const assetsWithNoFindings = state.assets.filter(
    (a) => a.vulns.length === 0 && a.zapFindings.length === 0
  );
  if (assetsWithNoFindings.length > 0) {
    gaps.push({
      area: "Asset Coverage",
      ptesPhase: "\xA74-5",
      severity: "medium",
      description: `${assetsWithNoFindings.length} assets had no findings \u2014 possible false negatives or insufficient testing depth`,
      recommendation: `Perform manual testing on: ${assetsWithNoFindings.map((a) => a.hostname || a.ip).slice(0, 5).join(", ")}`
    });
  }
  const hasExploits = state.stats.exploitsSucceeded > 0;
  const hasPostExploit = ptesPhases.find((p) => p.phase === "Post-Exploitation")?.status === "completed";
  if (hasExploits && !hasPostExploit) {
    gaps.push({
      area: "Post-Exploitation",
      ptesPhase: "\xA76",
      severity: "high",
      description: `${state.stats.exploitsSucceeded} exploits succeeded but post-exploitation activities were not performed`,
      recommendation: "Conduct post-exploitation assessment including privilege escalation, lateral movement, and data access validation"
    });
  }
  const unverifiedCount = state.assets.reduce(
    (sum, a) => sum + a.vulns.filter((v) => v.corroborationTier === "unverified").length,
    0
  );
  if (unverifiedCount > 5) {
    gaps.push({
      area: "Evidence Quality",
      ptesPhase: "\xA77",
      severity: "medium",
      description: `${unverifiedCount} findings lack verification evidence \u2014 may affect report credibility`,
      recommendation: "Re-run targeted scans to collect verification evidence for unconfirmed findings"
    });
  }
  return gaps;
}
async function generateAdherenceRecommendations(ptesPhases, plannedVsActual, gaps, state) {
  try {
    const context = {
      ptesCompletion: ptesPhases.map((p) => `${p.phase} (${p.ptesSection}): ${p.status} \u2014 ${p.findings} findings`).join("\n"),
      executionSummary: `${state.stats.vulnsFound} vulns, ${state.stats.exploitsSucceeded}/${state.stats.exploitsAttempted} exploits, ${state.assets.length} assets`,
      gaps: gaps.map((g) => `[${g.severity}] ${g.area}: ${g.description}`).join("\n"),
      skippedTests: plannedVsActual.filter((p) => p.status === "not_executed").map((p) => p.plannedTest).join(", ")
    };
    const resp = await invokeLLM({
      _caller: "engagement-report-handoff.recommendations",
      messages: [
        {
          role: "system",
          content: "You are a senior penetration testing consultant reviewing engagement execution against the test plan. Provide 3-5 specific, actionable recommendations for improving test coverage and adherence to PTES/NIST standards. Focus on practical next steps, not generic advice."
        },
        {
          role: "user",
          content: `Review this engagement execution and provide recommendations:

PTES Phase Completion:
${context.ptesCompletion}

Execution Summary: ${context.executionSummary}

Coverage Gaps:
${context.gaps || "None identified"}

Skipped Tests: ${context.skippedTests || "None"}

Provide 3-5 specific recommendations as a JSON array of strings.`
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "recommendations",
          strict: true,
          schema: {
            type: "object",
            properties: {
              recommendations: {
                type: "array",
                items: { type: "string" }
              }
            },
            required: ["recommendations"],
            additionalProperties: false
          }
        }
      }
    });
    const content = resp.choices?.[0]?.message?.content;
    if (content) {
      const parsed = JSON.parse(content);
      return parsed.recommendations || [];
    }
  } catch (err) {
    console.warn("[ReportHandoff] LLM recommendations failed:", err.message);
  }
  const recs = [];
  const skippedPhases = ptesPhases.filter((p) => p.status === "skipped");
  if (skippedPhases.length > 0) {
    recs.push(`Complete skipped PTES phases: ${skippedPhases.map((p) => p.phase).join(", ")}`);
  }
  if (gaps.some((g) => g.severity === "critical")) {
    recs.push("Address critical coverage gaps before finalizing the report");
  }
  if (state.stats.exploitsSucceeded === 0 && state.stats.vulnsFound > 0) {
    recs.push("Consider manual exploitation of high-severity findings to validate impact");
  }
  return recs;
}
function countFindingsForPhase(logPhases, state) {
  let count = 0;
  for (const entry of state.log) {
    if (logPhases.includes(entry.phase) && (entry.type === "finding" || entry.type === "scan_result")) {
      count++;
    }
  }
  return count;
}
function generatePhaseNotes(phase, logs, state) {
  switch (phase) {
    case "Intelligence Gathering":
      return `${state.assets.length} assets discovered, ${state.stats.portsFound} ports enumerated`;
    case "Vulnerability Analysis":
      return `${state.stats.vulnsFound} vulnerabilities identified across ${state.assets.length} assets`;
    case "Exploitation":
      return `${state.stats.exploitsSucceeded}/${state.stats.exploitsAttempted} exploits succeeded, ${state.stats.sessionsOpened || 0} sessions opened`;
    case "Reporting":
      return state.metadata?.autoReportId ? `Auto-report ${state.metadata.autoReportId} generated with ${state.metadata.autoReportFindings || 0} findings` : "Report generation pending";
    default:
      return `${logs.length} log entries recorded`;
  }
}
function calculatePhaseAdherence(phases) {
  const weights = {
    "Pre-engagement Interactions": 5,
    "Intelligence Gathering": 20,
    "Threat Modeling": 10,
    "Vulnerability Analysis": 25,
    "Exploitation": 25,
    "Post-Exploitation": 10,
    "Reporting": 5
  };
  let totalWeight = 0;
  let completedWeight = 0;
  for (const phase of phases) {
    const weight = weights[phase.phase] || 10;
    totalWeight += weight;
    if (phase.status === "completed") completedWeight += weight;
    else if (phase.status === "partial") completedWeight += weight * 0.5;
  }
  return totalWeight > 0 ? Math.round(completedWeight / totalWeight * 100) : 0;
}
function adherenceToMarkdown(adherence) {
  const lines = [];
  lines.push("# Test Plan Adherence Report");
  lines.push("");
  lines.push(`**Generated:** ${new Date(adherence.generatedAt).toISOString()}`);
  lines.push(`**Overall Adherence:** ${adherence.adherencePercentage}%`);
  lines.push("");
  lines.push("## Execution Summary");
  lines.push("");
  lines.push("| Metric | Count |");
  lines.push("|--------|-------|");
  lines.push(`| Total Planned Tests | ${adherence.totalPlannedTests} |`);
  lines.push(`| Executed | ${adherence.executedTests} |`);
  lines.push(`| Partially Executed | ${adherence.partiallyExecutedTests} |`);
  lines.push(`| Skipped | ${adherence.skippedTests} |`);
  lines.push(`| Blocked | ${adherence.blockedTests} |`);
  lines.push("");
  lines.push("## PTES Phase Completion");
  lines.push("");
  lines.push("| Phase | PTES | NIST | Status | Findings | Notes |");
  lines.push("|-------|------|------|--------|----------|-------|");
  for (const phase of adherence.ptesPhaseCompletion) {
    const statusIcon = phase.status === "completed" ? "\u2705" : phase.status === "partial" ? "\u26A0\uFE0F" : phase.status === "skipped" ? "\u274C" : "N/A";
    lines.push(`| ${phase.phase} | ${phase.ptesSection} | ${phase.nistSection} | ${statusIcon} ${phase.status} | ${phase.findings} | ${phase.notes} |`);
  }
  lines.push("");
  if (adherence.plannedVsActual.length > 0) {
    lines.push("## Planned vs Actual Execution");
    lines.push("");
    lines.push("| Test | Phase | Tool | Status | Findings | Evidence |");
    lines.push("|------|-------|------|--------|----------|----------|");
    for (const pva of adherence.plannedVsActual) {
      const statusIcon = pva.status === "executed" ? "\u2705" : pva.status === "partially_executed" ? "\u26A0\uFE0F" : pva.status === "blocked" ? "\u{1F6AB}" : "\u274C";
      lines.push(`| ${pva.plannedTest} | ${pva.ptesPhase} | ${pva.tool} | ${statusIcon} | ${pva.findingsFromTest} | ${pva.evidenceCollected ? "Yes" : "No"} |`);
    }
    lines.push("");
  }
  if (adherence.coverageGaps.length > 0) {
    lines.push("## Coverage Gaps");
    lines.push("");
    for (const gap of adherence.coverageGaps) {
      const sevIcon = gap.severity === "critical" ? "\u{1F534}" : gap.severity === "high" ? "\u{1F7E0}" : gap.severity === "medium" ? "\u{1F7E1}" : "\u{1F7E2}";
      lines.push(`### ${sevIcon} ${gap.area} (${gap.ptesPhase})`);
      lines.push("");
      lines.push(gap.description);
      lines.push("");
      lines.push(`**Recommendation:** ${gap.recommendation}`);
      lines.push("");
    }
  }
  if (adherence.recommendations.length > 0) {
    lines.push("## Recommendations");
    lines.push("");
    for (let i = 0; i < adherence.recommendations.length; i++) {
      lines.push(`${i + 1}. ${adherence.recommendations[i]}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}
var PTES_PHASES;
var init_engagement_report_handoff = __esm({
  "server/lib/engagement-report-handoff.ts"() {
    init_llm();
    PTES_PHASES = [
      {
        phase: "Pre-engagement Interactions",
        ptesSection: "\xA71",
        nistSection: "\xA73.1",
        logPhases: ["idle"],
        indicators: ["roe", "scope", "authorization", "pre-engagement"]
      },
      {
        phase: "Intelligence Gathering",
        ptesSection: "\xA72",
        nistSection: "\xA73.2",
        logPhases: ["recon", "enumeration"],
        indicators: ["dns", "whois", "subdomain", "osint", "fingerprint", "naabu", "masscan", "nerva", "discovery"]
      },
      {
        phase: "Threat Modeling",
        ptesSection: "\xA73",
        nistSection: "\xA73.3",
        logPhases: ["recon"],
        indicators: ["threat", "attack surface", "carver", "risk", "model", "mitre"]
      },
      {
        phase: "Vulnerability Analysis",
        ptesSection: "\xA74",
        nistSection: "\xA74.1",
        logPhases: ["vuln_detection"],
        indicators: ["vuln", "nuclei", "zap", "scan", "cve", "weakness"]
      },
      {
        phase: "Exploitation",
        ptesSection: "\xA75",
        nistSection: "\xA74.2",
        logPhases: ["exploitation"],
        indicators: ["exploit", "payload", "shell", "session", "metasploit", "sqlmap", "commix"]
      },
      {
        phase: "Post-Exploitation",
        ptesSection: "\xA76",
        nistSection: "\xA74.3",
        logPhases: ["post_exploit"],
        indicators: ["post-exploit", "pivot", "lateral", "privilege", "exfil", "persist"]
      },
      {
        phase: "Reporting",
        ptesSection: "\xA77",
        nistSection: "\xA75",
        logPhases: ["reporting", "completed"],
        indicators: ["report", "narrative", "executive", "summary", "evidence", "screenshot"]
      }
    ];
  }
});
init_engagement_report_handoff();
export {
  adherenceToMarkdown,
  generateTestPlanAdherence
};
