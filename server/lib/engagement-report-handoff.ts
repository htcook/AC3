/**
 * engagement-report-handoff.ts
 * 
 * Bridges the Test Plan Generator output into the engagement completion
 * and auto-report generation pipeline. When an engagement completes, this
 * module:
 * 
 * 1. Retrieves the test plan that was generated from the DI scan
 * 2. Compares planned tests vs actual execution (planned-vs-actual analysis)
 * 3. Injects PTES phase completion status into the report
 * 4. Generates a "Test Plan Adherence" section for the report
 * 5. Identifies gaps between planned and executed tests
 * 
 * PTES Reference: http://www.pentest-standard.org/index.php/Main_Page
 * NIST SP 800-115: Technical Guide to Information Security Testing and Assessment
 */

import { invokeLLM } from "../_core/llm";

// ─── Types ───────────────────────────────────────────────────────────────────

/** PTES phase completion tracking */
export interface PtesPhaseStatus {
  phase: string;
  ptesSection: string;
  nistSection: string;
  status: "completed" | "partial" | "skipped" | "not_applicable";
  evidence: string[];
  findings: number;
  notes: string;
}

/** Planned test vs actual execution comparison */
export interface PlannedVsActual {
  plannedTest: string;
  ptesPhase: string;
  tool: string;
  target: string;
  status: "executed" | "partially_executed" | "not_executed" | "blocked";
  reason?: string;
  findingsFromTest: number;
  evidenceCollected: boolean;
  timeSpent?: string;
}

/** Test plan adherence summary */
export interface TestPlanAdherence {
  totalPlannedTests: number;
  executedTests: number;
  partiallyExecutedTests: number;
  skippedTests: number;
  blockedTests: number;
  adherencePercentage: number;
  ptesPhaseCompletion: PtesPhaseStatus[];
  plannedVsActual: PlannedVsActual[];
  coverageGaps: CoverageGap[];
  recommendations: string[];
  generatedAt: number;
}

/** Coverage gap identified between plan and execution */
export interface CoverageGap {
  area: string;
  ptesPhase: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  recommendation: string;
}

/** Engagement state shape (subset of fields we need) */
interface EngagementStateForHandoff {
  engagementId: number;
  engagementName?: string;
  engagementType: string;
  phase: string;
  assets: Array<{
    hostname: string;
    ip: string;
    ports: Array<{ port: number; service?: string; protocol?: string }>;
    vulns: Array<{
      title?: string;
      name?: string;
      severity?: string;
      source?: string;
      tool?: string;
      cve?: string;
      endpoint?: string;
      corroborationTier?: string;
    }>;
    zapFindings: Array<{
      alert?: string;
      risk?: string;
      url?: string;
    }>;
    nucleiFindings?: Array<{
      templateId?: string;
      severity?: string;
    }>;
    exploitAttempts: Array<{
      tool?: string;
      success?: boolean;
      exploitOutput?: string;
    }>;
    toolResults?: Array<{
      tool?: string;
      command?: string;
      exitCode?: number;
      findingCount?: number;
    }>;
  }>;
  stats: {
    hostsScanned: number;
    portsFound: number;
    vulnsFound: number;
    exploitsAttempted: number;
    exploitsSucceeded: number;
    zapScansRun?: number;
    sessionsOpened?: number;
  };
  log: Array<{
    phase: string;
    type: string;
    title: string;
    detail?: string;
    ts?: number;
  }>;
  startedAt?: number;
  completedAt?: number;
  metadata?: Record<string, any>;
}

/** Test plan shape (from test-plan-generator.ts) */
interface TestPlanForHandoff {
  metadata: {
    planId: string;
    generatedAt: string;
    orgName: string;
    targetDomain: string;
    planType: string;
  };
  sections: Array<{
    id: string;
    title: string;
    ptesPhase: string;
    nistSection: string;
    content: string;
  }>;
  structuredData?: {
    attackVectors?: Array<{
      id: string;
      name: string;
      tools: string[];
      targets: string[];
      ptesPhase: string;
      estimatedHours: number;
      priority: string;
    }>;
    schedule?: {
      phases: Array<{
        name: string;
        duration: string;
        activities: string[];
      }>;
      totalDuration: string;
    };
    toolMatrix?: Array<{
      tool: string;
      purpose: string;
      targets: string[];
      phase: string;
    }>;
    riskMitigation?: {
      communicationPlan: {
        escalationMatrix: Array<{
          severity: string;
          action: string;
          contact: string;
          timeframe: string;
        }>;
      };
    };
  };
}

// ─── PTES Phase Definitions ──────────────────────────────────────────────────

const PTES_PHASES = [
  {
    phase: "Pre-engagement Interactions",
    ptesSection: "§1",
    nistSection: "§3.1",
    logPhases: ["idle", "scoping", "test_plan", "test_plan_approval"],
    indicators: ["roe", "scope", "authorization", "pre-engagement", "rules of engagement", "test plan", "approval", "comms protocol", "engagement start"],
  },
  {
    phase: "Intelligence Gathering",
    ptesSection: "§2",
    nistSection: "§3.2",
    logPhases: ["recon", "enumeration", "passive_discovery", "discovery", "targeted_enum"],
    indicators: ["dns", "whois", "subdomain", "osint", "fingerprint", "naabu", "masscan", "nerva", "discovery", "port", "service", "httpx", "host", "asset", "domain", "ip ", "certificate", "banner", "technology"],
  },
  {
    phase: "Threat Modeling",
    ptesSection: "§3",
    nistSection: "§3.3",
    logPhases: ["recon", "scoping", "test_plan"],
    indicators: ["threat", "attack surface", "carver", "risk", "model", "mitre", "att&ck", "tactic", "technique", "attack vector", "target priorit", "high-value", "crown jewel", "kill chain", "methodology"],
  },
  {
    phase: "Vulnerability Analysis",
    ptesSection: "§4",
    nistSection: "§4.1",
    logPhases: ["vuln_detection", "credential_testing"],
    indicators: ["vuln", "nuclei", "zap", "scan", "cve", "weakness", "injection", "xss", "sqli", "rce", "ssrf", "lfi", "misconfig", "exposed", "default", "hydra", "credential", "brute", "nikto", "burp", "testssl"],
  },
  {
    phase: "Exploitation",
    ptesSection: "§5",
    nistSection: "§4.2",
    logPhases: ["exploitation"],
    indicators: ["exploit", "payload", "shell", "session", "metasploit", "sqlmap", "commix", "reverse", "bind", "meterpreter", "access gained", "credential valid", "authenticated", "login success"],
  },
  {
    phase: "Post-Exploitation",
    ptesSection: "§6",
    nistSection: "§4.3",
    logPhases: ["post_exploit"],
    indicators: ["post-exploit", "pivot", "lateral", "privilege", "exfil", "persist", "escalat", "dump", "hashdump", "mimikatz", "bloodhound", "data access"],
  },
  {
    phase: "Reporting",
    ptesSection: "§7",
    nistSection: "§5",
    logPhases: ["reporting", "completed"],
    indicators: ["report", "narrative", "executive", "summary", "evidence", "screenshot", "finding", "deliverable", "compliance", "owasp"],
  },
] as const;

// ─── Core Functions ──────────────────────────────────────────────────────────

/**
 * Analyze engagement execution against the test plan to produce
 * a PTES phase completion status and planned-vs-actual comparison.
 */
export async function generateTestPlanAdherence(
  state: EngagementStateForHandoff,
  testPlan: TestPlanForHandoff | null,
): Promise<TestPlanAdherence> {
  // ── Step 1: Analyze PTES phase completion from engagement logs ──
  const ptesPhaseCompletion = analyzePtesPhaseCompletion(state);

  // ── Step 2: Compare planned tests vs actual execution ──
  const plannedVsActual = testPlan
    ? compareTestPlanToExecution(testPlan, state)
    : [];

  // ── Step 3: Identify coverage gaps ──
  const coverageGaps = identifyCoverageGaps(ptesPhaseCompletion, plannedVsActual, state);

  // ── Step 4: Generate recommendations via LLM ──
  const recommendations = await generateAdherenceRecommendations(
    ptesPhaseCompletion,
    plannedVsActual,
    coverageGaps,
    state,
  );

  // ── Step 5: Calculate adherence percentage ──
  const totalPlanned = plannedVsActual.length || ptesPhaseCompletion.length;
  const executed = plannedVsActual.filter(p => p.status === "executed").length;
  const partial = plannedVsActual.filter(p => p.status === "partially_executed").length;
  const skipped = plannedVsActual.filter(p => p.status === "not_executed").length;
  const blocked = plannedVsActual.filter(p => p.status === "blocked").length;

  // Calculate from planned-vs-actual if available, but also calculate phase-based adherence
  // as a floor. This prevents 0% adherence when PTES phases are completed but the test plan's
  // attack vector tool names don't exactly match the tools used in execution.
  const plannedAdherence = totalPlanned > 0 && plannedVsActual.length > 0
    ? Math.round(((executed + partial * 0.5) / totalPlanned) * 100)
    : 0;
  const phaseAdherence = calculatePhaseAdherence(ptesPhaseCompletion);
  // Use the higher of the two — if phases show 60% completion but tool matching shows 0%,
  // the phase-based score is more accurate than a false 0%
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
    generatedAt: Date.now(),
  };
}

/**
 * Analyze engagement logs to determine PTES phase completion status.
 */
function analyzePtesPhaseCompletion(state: EngagementStateForHandoff): PtesPhaseStatus[] {
  return PTES_PHASES.map(ptesDef => {
    // Check if any log entries match this PTES phase
    const matchingLogs = state.log.filter(entry => {
      const phaseMatch = ptesDef.logPhases.some(lp => entry.phase === lp);
      const indicatorMatch = ptesDef.indicators.some(ind =>
        (entry.title || "").toLowerCase().includes(ind) ||
        (entry.detail || "").toLowerCase().includes(ind)
      );
      return phaseMatch || indicatorMatch;
    });

    // Count findings from this phase
    const phaseFindings = countFindingsForPhase(ptesDef.logPhases as unknown as string[], state);

    // Collect evidence indicators — include more log types that demonstrate phase activity
    const evidence = matchingLogs
      .filter(l => l.type === "phase_complete" || l.type === "scan_result" || l.type === "finding" || l.type === "evidence" || l.type === "scan_start" || l.type === "tool_exec")
      .map(l => l.title)
      .slice(0, 10);

    // Count substantive activity logs (info entries that show real work, not just status messages)
    const activityLogs = matchingLogs.filter(l =>
      l.type === "phase_complete" || l.type === "scan_result" || l.type === "finding" ||
      l.type === "evidence" || l.type === "scan_start" || l.type === "tool_exec" ||
      l.type === "llm_decision" || l.type === "info"
    );

    // Determine status — a phase is "completed" if it has meaningful activity,
    // not just if it produced findings. PTES measures whether the phase was EXECUTED.
    let status: PtesPhaseStatus["status"];
    if (matchingLogs.length === 0) {
      status = "skipped";
    } else if (evidence.length >= 2 || phaseFindings > 0 || activityLogs.length >= 3) {
      // Phase completed: has evidence entries, findings, or at least 3 substantive activity logs
      status = "completed";
    } else if (activityLogs.length >= 1) {
      // Phase partially completed: some activity but minimal evidence
      status = "partial";
    } else {
      status = "partial";
    }

    // Special case: pre-engagement is always completed if engagement ran
    if (ptesDef.phase === "Pre-engagement Interactions" && state.phase === "completed") {
      status = "completed";
    }

    // Special case: exploitation is completed if exploits were attempted (even if 0 succeeded)
    if (ptesDef.phase === "Exploitation" && state.stats.exploitsAttempted > 0) {
      status = "completed";
    }

    // Special case: vulnerability analysis is completed if vulns were found
    if (ptesDef.phase === "Vulnerability Analysis" && state.stats.vulnsFound > 0) {
      status = "completed";
    }

    // Special case: intelligence gathering is completed if hosts were scanned and ports found
    if (ptesDef.phase === "Intelligence Gathering" && state.stats.hostsScanned > 0 && state.stats.portsFound > 0) {
      status = "completed";
    }

    // Special case: reporting is completed if auto-report was generated
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
      notes: generatePhaseNotes(ptesDef.phase, matchingLogs, state),
    };
  });
}

/**
 * Compare test plan attack vectors to actual engagement execution.
 */
function compareTestPlanToExecution(
  testPlan: TestPlanForHandoff,
  state: EngagementStateForHandoff,
): PlannedVsActual[] {
  const attackVectors = testPlan.structuredData?.attackVectors || [];
  const toolMatrix = testPlan.structuredData?.toolMatrix || [];

  // Build a set of tools that were actually used during the engagement
  const usedTools = new Set<string>();
  const toolTargets = new Map<string, Set<string>>();

  for (const asset of state.assets) {
    for (const tr of asset.toolResults || []) {
      if (tr.tool) {
        usedTools.add(tr.tool.toLowerCase());
        if (!toolTargets.has(tr.tool.toLowerCase())) {
          toolTargets.set(tr.tool.toLowerCase(), new Set());
        }
        toolTargets.get(tr.tool.toLowerCase())!.add(asset.hostname || asset.ip);
      }
    }
    // Check vuln sources
    for (const v of asset.vulns) {
      const src = (v.source || v.tool || "").toLowerCase();
      if (src) usedTools.add(src);
    }
    // Check ZAP
    if (asset.zapFindings.length > 0) usedTools.add("zap");
    // Check Nuclei
    if (asset.nucleiFindings && asset.nucleiFindings.length > 0) usedTools.add("nuclei");
    // Check exploit tools
    for (const ea of asset.exploitAttempts) {
      if (ea.tool) usedTools.add(ea.tool.toLowerCase());
    }
  }

  // Also check log entries for tool usage
  for (const entry of state.log) {
    const text = `${entry.title} ${entry.detail || ""}`.toLowerCase();
    const toolPatterns = [
      "naabu", "masscan", "nerva", "nuclei", "zap", "sqlmap", "hydra", "nikto", "commix",
      "tplmap", "ffuf", "httpx", "metasploit", "xsstrike", "testssl",
      "ssh-audit", "gobuster", "dirsearch", "wfuzz", "burp",
    ];
    for (const tool of toolPatterns) {
      if (text.includes(tool)) usedTools.add(tool);
    }
  }

  const results: PlannedVsActual[] = [];

  // Compare each planned attack vector
  for (const av of attackVectors) {
    const plannedTools = av.tools.map(t => t.toLowerCase());
    const toolsUsed = plannedTools.filter(t => usedTools.has(t));
    const targetsHit = av.targets.filter(t =>
      state.assets.some(a =>
        (a.hostname || "").includes(t) || (a.ip || "").includes(t)
      )
    );

    // Count findings from this attack vector's tools
    let findingsCount = 0;
    for (const asset of state.assets) {
      for (const v of asset.vulns) {
        const src = (v.source || v.tool || "").toLowerCase();
        if (plannedTools.some(pt => src.includes(pt))) findingsCount++;
      }
    }

    let status: PlannedVsActual["status"];
    let reason: string | undefined;

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
      evidenceCollected: findingsCount > 0,
    });
  }

  // Also compare tool matrix entries not covered by attack vectors
  for (const tm of toolMatrix) {
    const alreadyCovered = results.some(r =>
      r.tool.toLowerCase().includes(tm.tool.toLowerCase())
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
      evidenceCollected: toolUsed,
    });
  }

  return results;
}

/**
 * Identify coverage gaps between planned and executed tests.
 */
function identifyCoverageGaps(
  ptesPhases: PtesPhaseStatus[],
  plannedVsActual: PlannedVsActual[],
  state: EngagementStateForHandoff,
): CoverageGap[] {
  const gaps: CoverageGap[] = [];

  // Check for skipped PTES phases
  for (const phase of ptesPhases) {
    if (phase.status === "skipped" && phase.phase !== "Post-Exploitation") {
      gaps.push({
        area: phase.phase,
        ptesPhase: phase.ptesSection,
        severity: phase.phase === "Vulnerability Analysis" || phase.phase === "Exploitation"
          ? "critical"
          : "medium",
        description: `PTES ${phase.ptesSection} (${phase.phase}) was not executed during this engagement`,
        recommendation: `Include ${phase.phase.toLowerCase()} activities in the next engagement iteration`,
      });
    }
  }

  // Check for high-priority planned tests that weren't executed
  const skippedHighPriority = plannedVsActual.filter(
    p => p.status === "not_executed" && p.ptesPhase.includes("Exploitation")
  );
  for (const test of skippedHighPriority) {
    gaps.push({
      area: test.plannedTest,
      ptesPhase: test.ptesPhase,
      severity: "high",
      description: `Planned exploitation test "${test.plannedTest}" was not executed`,
      recommendation: `Schedule follow-up testing with ${test.tool} against ${test.target}`,
    });
  }

  // Check for assets with no findings (potential blind spots)
  const assetsWithNoFindings = state.assets.filter(
    a => a.vulns.length === 0 && a.zapFindings.length === 0
  );
  if (assetsWithNoFindings.length > 0) {
    gaps.push({
      area: "Asset Coverage",
      ptesPhase: "§4-5",
      severity: "medium",
      description: `${assetsWithNoFindings.length} assets had no findings — possible false negatives or insufficient testing depth`,
      recommendation: `Perform manual testing on: ${assetsWithNoFindings.map(a => a.hostname || a.ip).slice(0, 5).join(", ")}`,
    });
  }

  // Check for exploitation without post-exploitation
  const hasExploits = state.stats.exploitsSucceeded > 0;
  const hasPostExploit = ptesPhases.find(p => p.phase === "Post-Exploitation")?.status === "completed";
  if (hasExploits && !hasPostExploit) {
    gaps.push({
      area: "Post-Exploitation",
      ptesPhase: "§6",
      severity: "high",
      description: `${state.stats.exploitsSucceeded} exploits succeeded but post-exploitation activities were not performed`,
      recommendation: "Conduct post-exploitation assessment including privilege escalation, lateral movement, and data access validation",
    });
  }

  // Check for unverified findings
  const unverifiedCount = state.assets.reduce(
    (sum, a) => sum + a.vulns.filter(v => v.corroborationTier === "unverified").length,
    0
  );
  if (unverifiedCount > 5) {
    gaps.push({
      area: "Evidence Quality",
      ptesPhase: "§7",
      severity: "medium",
      description: `${unverifiedCount} findings lack verification evidence — may affect report credibility`,
      recommendation: "Re-run targeted scans to collect verification evidence for unconfirmed findings",
    });
  }

  return gaps;
}

/**
 * Generate LLM-powered recommendations based on adherence analysis.
 */
async function generateAdherenceRecommendations(
  ptesPhases: PtesPhaseStatus[],
  plannedVsActual: PlannedVsActual[],
  gaps: CoverageGap[],
  state: EngagementStateForHandoff,
): Promise<string[]> {
  try {
    const context = {
      ptesCompletion: ptesPhases.map(p => `${p.phase} (${p.ptesSection}): ${p.status} — ${p.findings} findings`).join("\n"),
      executionSummary: `${state.stats.vulnsFound} vulns, ${state.stats.exploitsSucceeded}/${state.stats.exploitsAttempted} exploits, ${state.assets.length} assets`,
      gaps: gaps.map(g => `[${g.severity}] ${g.area}: ${g.description}`).join("\n"),
      skippedTests: plannedVsActual.filter(p => p.status === "not_executed").map(p => p.plannedTest).join(", "),
    };

    const resp = await invokeLLM({
      _caller: "engagement-report-handoff.recommendations",
      messages: [
        {
          role: "system",
          content: "You are a senior penetration testing consultant reviewing engagement execution against the test plan. Provide 3-5 specific, actionable recommendations for improving test coverage and adherence to PTES/NIST standards. Focus on practical next steps, not generic advice.",
        },
        {
          role: "user",
          content: `Review this engagement execution and provide recommendations:\n\nPTES Phase Completion:\n${context.ptesCompletion}\n\nExecution Summary: ${context.executionSummary}\n\nCoverage Gaps:\n${context.gaps || "None identified"}\n\nSkipped Tests: ${context.skippedTests || "None"}\n\nProvide 3-5 specific recommendations as a JSON array of strings.`,
        },
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
                items: { type: "string" },
              },
            },
            required: ["recommendations"],
            additionalProperties: false,
          },
        },
      },
    });

    const content = resp.choices?.[0]?.message?.content;
    if (content) {
      const parsed = JSON.parse(content);
      return parsed.recommendations || [];
    }
  } catch (err: any) {
    console.warn("[ReportHandoff] LLM recommendations failed:", err.message);
  }

  // Fallback: generate deterministic recommendations
  const recs: string[] = [];
  const skippedPhases = ptesPhases.filter(p => p.status === "skipped");
  if (skippedPhases.length > 0) {
    recs.push(`Complete skipped PTES phases: ${skippedPhases.map(p => p.phase).join(", ")}`);
  }
  if (gaps.some(g => g.severity === "critical")) {
    recs.push("Address critical coverage gaps before finalizing the report");
  }
  if (state.stats.exploitsSucceeded === 0 && state.stats.vulnsFound > 0) {
    recs.push("Consider manual exploitation of high-severity findings to validate impact");
  }
  return recs;
}

// ─── Helper Functions ────────────────────────────────────────────────────────

function countFindingsForPhase(logPhases: string[], state: EngagementStateForHandoff): number {
  let count = 0;
  for (const entry of state.log) {
    if (logPhases.includes(entry.phase) && (
      entry.type === "finding" || entry.type === "scan_result" ||
      entry.type === "tool_exec" || entry.type === "scan_start"
    )) {
      count++;
    }
  }
  // Also count findings from assets that map to these phases
  // (e.g., vuln_detection phase findings are stored on assets, not just in logs)
  if (logPhases.includes("vuln_detection") || logPhases.includes("credential_testing")) {
    for (const asset of state.assets) {
      count += asset.vulns.length;
      count += asset.zapFindings.length;
    }
  }
  if (logPhases.includes("exploitation")) {
    for (const asset of state.assets) {
      count += (asset.exploitAttempts || []).length;
    }
  }
  return count;
}

function generatePhaseNotes(phase: string, logs: Array<any>, state: EngagementStateForHandoff): string {
  switch (phase) {
    case "Intelligence Gathering":
      return `${state.assets.length} assets discovered, ${state.stats.portsFound} ports enumerated`;
    case "Vulnerability Analysis":
      return `${state.stats.vulnsFound} vulnerabilities identified across ${state.assets.length} assets`;
    case "Exploitation":
      return `${state.stats.exploitsSucceeded}/${state.stats.exploitsAttempted} exploits succeeded, ${state.stats.sessionsOpened || 0} sessions opened`;
    case "Reporting":
      return state.metadata?.autoReportId
        ? `Auto-report ${state.metadata.autoReportId} generated with ${state.metadata.autoReportFindings || 0} findings`
        : "Report generation pending";
    default:
      return `${logs.length} log entries recorded`;
  }
}

function calculatePhaseAdherence(phases: PtesPhaseStatus[]): number {
  const weights: Record<string, number> = {
    "Pre-engagement Interactions": 5,
    "Intelligence Gathering": 20,
    "Threat Modeling": 10,
    "Vulnerability Analysis": 25,
    "Exploitation": 25,
    "Post-Exploitation": 10,
    "Reporting": 5,
  };

  let totalWeight = 0;
  let completedWeight = 0;

  for (const phase of phases) {
    const weight = weights[phase.phase] || 10;
    totalWeight += weight;
    if (phase.status === "completed") completedWeight += weight;
    else if (phase.status === "partial") completedWeight += weight * 0.5;
  }

  return totalWeight > 0 ? Math.round((completedWeight / totalWeight) * 100) : 0;
}

/**
 * Format the test plan adherence as a markdown section for the report.
 */
export function adherenceToMarkdown(adherence: TestPlanAdherence): string {
  const lines: string[] = [];

  lines.push("# Test Plan Adherence Report");
  lines.push("");
  lines.push(`**Generated:** ${new Date(adherence.generatedAt).toISOString()}`);
  lines.push(`**Overall Adherence:** ${adherence.adherencePercentage}%`);
  lines.push("");

  // Summary metrics
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

  // PTES Phase Completion
  lines.push("## PTES Phase Completion");
  lines.push("");
  lines.push("| Phase | PTES | NIST | Status | Findings | Notes |");
  lines.push("|-------|------|------|--------|----------|-------|");
  for (const phase of adherence.ptesPhaseCompletion) {
    const statusIcon = phase.status === "completed" ? "✅"
      : phase.status === "partial" ? "⚠️"
      : phase.status === "skipped" ? "❌"
      : "N/A";
    lines.push(`| ${phase.phase} | ${phase.ptesSection} | ${phase.nistSection} | ${statusIcon} ${phase.status} | ${phase.findings} | ${phase.notes} |`);
  }
  lines.push("");

  // Planned vs Actual
  if (adherence.plannedVsActual.length > 0) {
    lines.push("## Planned vs Actual Execution");
    lines.push("");
    lines.push("| Test | Phase | Tool | Status | Findings | Evidence |");
    lines.push("|------|-------|------|--------|----------|----------|");
    for (const pva of adherence.plannedVsActual) {
      const statusIcon = pva.status === "executed" ? "✅"
        : pva.status === "partially_executed" ? "⚠️"
        : pva.status === "blocked" ? "🚫"
        : "❌";
      lines.push(`| ${pva.plannedTest} | ${pva.ptesPhase} | ${pva.tool} | ${statusIcon} | ${pva.findingsFromTest} | ${pva.evidenceCollected ? "Yes" : "No"} |`);
    }
    lines.push("");
  }

  // Coverage Gaps
  if (adherence.coverageGaps.length > 0) {
    lines.push("## Coverage Gaps");
    lines.push("");
    for (const gap of adherence.coverageGaps) {
      const sevIcon = gap.severity === "critical" ? "🔴"
        : gap.severity === "high" ? "🟠"
        : gap.severity === "medium" ? "🟡"
        : "🟢";
      lines.push(`### ${sevIcon} ${gap.area} (${gap.ptesPhase})`);
      lines.push("");
      lines.push(gap.description);
      lines.push("");
      lines.push(`**Recommendation:** ${gap.recommendation}`);
      lines.push("");
    }
  }

  // Recommendations
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
