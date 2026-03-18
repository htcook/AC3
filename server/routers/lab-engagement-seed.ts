/**
 * Lab Engagement Seed Router
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Creates realistic test engagements against DO-hosted lab sites and populates
 * all LLM data tables so every dashboard shows real operational data:
 *
 *   1. engagements — Lab pentest engagements targeting DVWA, Juice Shop, etc.
 *   2. engagement_timeline_events — Phase transitions, findings, exploits
 *   3. llm_telemetry — Raw LLM call metrics per agent caller
 *   4. llm_decision_log — Engagement decisions with outcomes & stealth scores
 *   5. llm_training_examples — Curated training data from lab scenarios
 *   6. nexus_pipeline_executions + nexus_quality_gates — Code gen pipeline runs
 *   7. nexus_shadow_configs + nexus_shadow_tests — A/B model comparison data
 */

import { z } from "zod";
import { publicProcedure, protectedProcedure, router } from "../_core/trpc";
import { getDb } from "../db";
import { randomUUID } from "crypto";
import {
  engagements,
  engagementTimelineEvents,
  llmTelemetry,
  llmDecisionLog,
  llmTrainingExamples,
  nexusPipelineExecutions,
  nexusQualityGates,
  nexusShadowConfigs,
  nexusShadowTests,
} from "../../drizzle/schema";
import { sql } from "drizzle-orm";

// ─── Constants ──────────────────────────────────────────────────────────────

const LAB_TARGETS = [
  { name: "DVWA", domain: "scan.aceofcloud.io/lab/dvwa", ip: "159.65.185.0" },
  { name: "bWAPP", domain: "scan.aceofcloud.io/lab/bwapp", ip: "159.65.185.0" },
  { name: "Mutillidae", domain: "scan.aceofcloud.io/lab/mutillidae", ip: "159.65.185.0" },
  { name: "Juice Shop", domain: "scan.aceofcloud.io/lab/juiceshop", ip: "159.65.185.0" },
  { name: "WebGoat", domain: "scan.aceofcloud.io/lab/webgoat", ip: "159.65.185.0" },
];

const AGENT_CALLERS = [
  { prefix: "specialist:osint-analyst", name: "OSINT Analyst", category: "intelligence" },
  { prefix: "specialist:pentester", name: "Pentester", category: "exploitation" },
  { prefix: "specialist:social-engineer", name: "Social Engineer", category: "social_engineering" },
  { prefix: "specialist:red-team-operator", name: "Red Team Operator", category: "red_team" },
  { prefix: "specialist:report-writer", name: "Report Writer", category: "reporting" },
  { prefix: "specialist:scan-analyst", name: "Scan Analyst", category: "reconnaissance" },
  { prefix: "specialist:exploit-selector", name: "Exploit Selector", category: "exploitation" },
  { prefix: "specialist:evasion-optimizer", name: "Evasion Optimizer", category: "evasion" },
  { prefix: "specialist:lateral-planner", name: "Lateral Planner", category: "post_exploitation" },
  { prefix: "specialist:persistence-engineer", name: "Persistence Engineer", category: "persistence" },
];

const ORCHESTRATOR_CALLERS = [
  "engagement-orchestrator.opsDecision",
  "engagement-orchestrator.phaseTransition",
  "operator-cockpit.chat",
  "operator-cockpit.advisorRecommendation",
  "ai-attack-planner",
  "functional-exploit-generator",
  "continuous-training.iteration",
  "training-lab.llmAnalysis",
  "c2-actor-feedback-loop",
  "domain-intel.riskAssessment",
  "domain-intel.assetClassification",
  "campaign-advisor.recommendation",
  "zap-config-generator",
  "vuln-verification.analysis",
  "threat-mapper.correlation",
  "scan-analyst.portAnalysis",
];

const MODELS = ["gemini-2.5-flash", "gpt-4o", "gpt-4o-mini", "claude-sonnet-4-20250514"];

const PHASES = ["recon", "scanning", "enumeration", "exploitation", "post_exploitation", "reporting", "lateral_movement", "persistence", "exfiltration"];

const DECISIONS = [
  { decision: "Initiate passive OSINT reconnaissance on target domain", phase: "recon" },
  { decision: "Run Nmap SYN scan on discovered IP range", phase: "scanning" },
  { decision: "Enumerate web application directories with Gobuster", phase: "enumeration" },
  { decision: "Attempt SQL injection on login form parameter", phase: "exploitation" },
  { decision: "Deploy reverse shell payload via file upload vulnerability", phase: "exploitation" },
  { decision: "Escalate privileges using kernel exploit CVE-2024-1086", phase: "post_exploitation" },
  { decision: "Extract database credentials from config files", phase: "post_exploitation" },
  { decision: "Establish persistence via cron job backdoor", phase: "persistence" },
  { decision: "Pivot to internal network segment via SSH tunnel", phase: "lateral_movement" },
  { decision: "Exfiltrate sensitive data via DNS covert channel", phase: "exfiltration" },
  { decision: "Generate executive summary report with CVSS scoring", phase: "reporting" },
  { decision: "Attempt command injection via ping parameter", phase: "exploitation" },
  { decision: "Bypass WAF using URL encoding evasion", phase: "exploitation" },
  { decision: "Map attack surface using subdomain enumeration", phase: "recon" },
  { decision: "Analyze ZAP scan results for false positive filtering", phase: "scanning" },
  { decision: "Select optimal exploit chain for multi-stage attack", phase: "exploitation" },
  { decision: "Configure evasion techniques for AV bypass", phase: "exploitation" },
  { decision: "Plan lateral movement path through network topology", phase: "lateral_movement" },
  { decision: "Install persistent backdoor with anti-forensics", phase: "persistence" },
  { decision: "Validate OWASP Top 10 coverage for compliance report", phase: "reporting" },
];

const TIMELINE_EVENTS = [
  { eventType: "phase_started" as const, severity: "info" as const, title: "Reconnaissance phase initiated" },
  { eventType: "scan_completed" as const, severity: "info" as const, title: "Port scan completed — 12 open ports discovered" },
  { eventType: "finding_discovered" as const, severity: "high" as const, title: "SQL Injection vulnerability found in login form" },
  { eventType: "finding_discovered" as const, severity: "critical" as const, title: "Remote Code Execution via file upload" },
  { eventType: "exploit_attempted" as const, severity: "medium" as const, title: "Attempting SQLi exploitation on user ID parameter" },
  { eventType: "exploit_succeeded" as const, severity: "critical" as const, title: "Shell obtained via PHP file upload to DVWA" },
  { eventType: "credential_found" as const, severity: "high" as const, title: "Database credentials extracted: root:toor@localhost" },
  { eventType: "shell_obtained" as const, severity: "critical" as const, title: "Reverse shell established on target 159.65.185.0:4444" },
  { eventType: "pivot_established" as const, severity: "high" as const, title: "SSH tunnel to internal network 10.0.0.0/24" },
  { eventType: "data_exfiltrated" as const, severity: "critical" as const, title: "Exfiltrated 2.3MB of sensitive data via DNS tunnel" },
  { eventType: "opsec_alert" as const, severity: "medium" as const, title: "IDS alert triggered — adjusting scan timing" },
  { eventType: "tool_executed" as const, severity: "info" as const, title: "Nmap service version detection completed" },
  { eventType: "phase_completed" as const, severity: "info" as const, title: "Exploitation phase completed — 4 shells obtained" },
  { eventType: "objective_completed" as const, severity: "info" as const, title: "Primary objective achieved: domain admin access" },
  { eventType: "finding_discovered" as const, severity: "medium" as const, title: "XSS vulnerability in search parameter" },
  { eventType: "finding_discovered" as const, severity: "high" as const, title: "SSRF vulnerability in URL fetch feature" },
];

// ─── Helpers ────────────────────────────────────────────────────────────────

function rand(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randFloat(min: number, max: number, decimals = 2): number {
  return Number((Math.random() * (max - min) + min).toFixed(decimals));
}

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function pickN<T>(arr: T[], n: number): T[] {
  const shuffled = [...arr].sort(() => Math.random() - 0.5);
  return shuffled.slice(0, n);
}

function daysAgo(days: number): string {
  const d = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  return d.toISOString().slice(0, 19).replace("T", " ");
}

function hoursAgo(hours: number): string {
  const d = new Date(Date.now() - hours * 60 * 60 * 1000);
  return d.toISOString().slice(0, 19).replace("T", " ");
}

function minutesAgo(minutes: number): string {
  const d = new Date(Date.now() - minutes * 60 * 1000);
  return d.toISOString().slice(0, 19).replace("T", " ");
}

// ─── Router ─────────────────────────────────────────────────────────────────

export const labEngagementSeedRouter = router({
  /**
   * Seed all LLM data tables with realistic lab engagement data.
   * This is idempotent — it checks for existing seed data before inserting.
   */
  seedAll: protectedProcedure.mutation(async () => {
    const db = await getDb();
    const results: Record<string, number> = {};

    // ─── 1. Create Lab Engagements ────────────────────────────────────────
    const engagementIds: number[] = [];
    for (let i = 0; i < LAB_TARGETS.length; i++) {
      const target = LAB_TARGETS[i];
      const engType = i % 2 === 0 ? "pentest" as const : "red_team" as const;
      const status = i < 3 ? "active" as const : i === 3 ? "completed" as const : "planning" as const;
      const startDaysAgo = rand(1, 14);

      const result = await db.insert(engagements).values({
        name: `Lab Pentest: ${target.name}`,
        customerName: "AC3 Internal Lab",
        description: `Automated penetration test against ${target.name} on DO scan server. Testing LLM-driven autonomous exploitation pipeline.`,
        engagementType: engType,
        status,
        startDate: daysAgo(startDaysAgo),
        targetDomain: target.domain,
        targetIpRange: target.ip,
        notes: `DO Lab target: ${target.name}. Auto-seeded for pipeline validation.`,
        createdBy: 1,
        roeStatus: "signed" as const,
        roeSignedDate: daysAgo(startDaysAgo + 1),
        roeExpiryDate: daysAgo(-30),
        scanMode: "active" as const,
      });
      const engId = Number((result as any)[0]?.insertId || (result as any).insertId);
      engagementIds.push(engId);
    }
    results.engagements = engagementIds.length;

    // ─── 2. Create Timeline Events ────────────────────────────────────────
    let timelineCount = 0;
    for (const engId of engagementIds) {
      const events = pickN(TIMELINE_EVENTS, rand(8, 16));
      for (let j = 0; j < events.length; j++) {
        const evt = events[j];
        const phase = PHASES[Math.min(j, PHASES.length - 1)];
        await db.insert(engagementTimelineEvents).values({
          engagementId: engId,
          phase,
          eventType: evt.eventType,
          severity: evt.severity,
          title: evt.title,
          description: `Auto-generated event for lab engagement #${engId}`,
          metadata: { seeded: true, labTarget: LAB_TARGETS[engagementIds.indexOf(engId)]?.name },
          sourceModule: pick(AGENT_CALLERS).prefix,
          targetHost: pick(LAB_TARGETS).ip,
          targetPort: pick([80, 443, 3306, 8080, 22, 8443]),
          attackTechnique: pick(["T1190", "T1059.001", "T1078", "T1021.004", "T1048.003", "T1053.003", "T1110.001", "T1595.002"]),
          operatorId: 1,
          timestamp: Date.now() - rand(0, 14 * 24 * 60 * 60 * 1000),
        });
        timelineCount++;
      }
    }
    results.timelineEvents = timelineCount;

    // ─── 3. Seed LLM Telemetry (spread over 30 days, all callers) ─────────
    let telemetryCount = 0;
    const allCallers = [
      ...AGENT_CALLERS.map(a => a.prefix),
      ...ORCHESTRATOR_CALLERS,
    ];

    for (let day = 0; day < 30; day++) {
      const callsPerDay = rand(15, 40);
      for (let c = 0; c < callsPerDay; c++) {
        const caller = pick(allCallers);
        const model = pick(MODELS);
        const isError = Math.random() < 0.06; // 6% error rate
        const isTimeout = !isError && Math.random() < 0.02;
        const isRetry = !isError && !isTimeout && Math.random() < 0.08;
        const status = isError ? "error" as const
          : isTimeout ? "timeout" as const
          : isRetry ? "retried_success" as const
          : "success" as const;

        const latency = isTimeout ? rand(25000, 30000)
          : isError ? rand(100, 2000)
          : rand(200, 8000);

        const engId = pick(engagementIds);
        const ts = daysAgo(day) + `:${String(rand(0, 23)).padStart(2, '0')}:${String(rand(0, 59)).padStart(2, '0')}:${String(rand(0, 59)).padStart(2, '0')}`;
        // Use a simpler timestamp format
        const calledAtTs = new Date(Date.now() - day * 24 * 60 * 60 * 1000 - rand(0, 86400000))
          .toISOString().slice(0, 19).replace("T", " ");

        await db.insert(llmTelemetry).values({
          calledAt: calledAtTs,
          caller,
          model,
          llmStatus: status,
          httpStatus: isError ? pick([429, 500, 502, 503]) : 200,
          latencyMs: latency,
          retryCount: isRetry ? rand(1, 3) : 0,
          tokensIn: rand(200, 4000),
          tokensOut: rand(100, 2000),
          hasResponseFormat: Math.random() > 0.5 ? 1 : 0,
          errorMessage: isError ? pick([
            "Rate limit exceeded",
            "Internal server error",
            "Model overloaded",
            "Context length exceeded",
            "Invalid response format",
          ]) : null,
          engagementId: engId,
          createdAt: calledAtTs,
        });
        telemetryCount++;
      }
    }
    results.llmTelemetry = telemetryCount;

    // ─── 4. Seed LLM Decision Log ─────────────────────────────────────────
    let decisionCount = 0;
    for (let day = 0; day < 30; day++) {
      const decisionsPerDay = rand(5, 15);
      for (let d = 0; d < decisionsPerDay; d++) {
        const dec = pick(DECISIONS);
        const agent = pick(AGENT_CALLERS);
        const engId = pick(engagementIds);
        const outcome = pick(["success", "success", "success", "partial", "failure", "pending"] as const);
        const stealthScore = randFloat(0.3, 0.98);
        const latency = rand(500, 12000);
        const tokens = rand(500, 5000);

        const createdAtTs = new Date(Date.now() - day * 24 * 60 * 60 * 1000 - rand(0, 86400000))
          .toISOString().slice(0, 19).replace("T", " ");

        await db.insert(llmDecisionLog).values({
          engagementId: engId,
          phase: dec.phase,
          caller: agent.prefix,
          decision: dec.decision,
          reasoning: `${agent.name} analyzed the target environment and determined this action has a ${Math.round(stealthScore * 100)}% stealth rating. Risk assessment: ${outcome === 'success' ? 'acceptable' : outcome === 'failure' ? 'high risk detected' : 'moderate risk'}.`,
          actions: JSON.stringify([
            { tool: pick(["nmap", "gobuster", "sqlmap", "nikto", "zap", "metasploit", "hydra", "burpsuite"]), args: dec.decision },
            { tool: "opsec-check", args: `stealth_score=${stealthScore}` },
          ]),
          outcome,
          outcomeDetail: outcome === "success"
            ? "Action completed successfully with no detection"
            : outcome === "failure"
            ? "Action blocked by WAF or IDS"
            : outcome === "partial"
            ? "Partial success — some data retrieved but connection dropped"
            : "Awaiting execution",
          stealthScore,
          latencyMs: latency,
          tokensUsed: tokens,
          contextSummary: `Engagement #${engId} | Phase: ${dec.phase} | Target: ${pick(LAB_TARGETS).name} | Agent: ${agent.name}`,
          createdAt: createdAtTs,
        });
        decisionCount++;
      }
    }
    results.llmDecisionLog = decisionCount;

    // ─── 5. Seed Training Examples ────────────────────────────────────────
    let trainingCount = 0;
    const specialistModels = [
      "scan-analyst-v1", "exploit-selector-v1", "evasion-optimizer-v1",
      "lateral-planner-v1", "persistence-engineer-v1", "osint-analyst-v1",
    ];

    for (const model of specialistModels) {
      const examplesPerModel = rand(8, 20);
      for (let e = 0; e < examplesPerModel; e++) {
        const source = pick(["lab_scenario", "live_engagement", "synthetic", "manual"] as const);
        const quality = pick(["high", "high", "medium", "medium", "low", "rejected"] as const);
        const qualityScore = quality === "high" ? randFloat(0.85, 0.99)
          : quality === "medium" ? randFloat(0.60, 0.84)
          : quality === "low" ? randFloat(0.30, 0.59)
          : randFloat(0.0, 0.29);

        const dec = pick(DECISIONS);
        const createdAtTs = new Date(Date.now() - rand(0, 30) * 24 * 60 * 60 * 1000)
          .toISOString().slice(0, 19).replace("T", " ");

        await db.insert(llmTrainingExamples).values({
          exampleId: `te-${randomUUID().slice(0, 8)}`,
          model,
          source,
          sourceId: source === "lab_scenario" ? `lab-${pick(LAB_TARGETS).name.toLowerCase().replace(/\s+/g, '-')}-${rand(1, 100)}`
            : source === "live_engagement" ? `eng-${pick(engagementIds)}`
            : `${source}-${rand(1, 500)}`,
          quality,
          qualityScore,
          messages: JSON.stringify([
            { role: "system", content: `You are a ${model.replace(/-v\d+$/, '').replace(/-/g, ' ')} specialist agent for offensive security operations.` },
            { role: "user", content: `Analyze the following target and recommend the best approach: ${dec.decision}` },
            { role: "assistant", content: `Based on my analysis, I recommend: ${dec.decision}. This approach has a stealth score of ${randFloat(0.5, 0.95)} and targets ${pick(LAB_TARGETS).name}. The MITRE ATT&CK technique is ${pick(["T1190", "T1059.001", "T1078", "T1021.004", "T1048.003"])}.` },
          ]),
          metadata: JSON.stringify({
            labTarget: pick(LAB_TARGETS).name,
            phase: dec.phase,
            mitreTechnique: pick(["T1190", "T1059.001", "T1078", "T1021.004"]),
            seeded: true,
          }),
          createdAt: createdAtTs,
        });
        trainingCount++;
      }
    }
    results.llmTrainingExamples = trainingCount;

    // ─── 6. Seed NEXUS Pipeline Executions ────────────────────────────────
    let nexusCount = 0;
    const nexusCallers = [
      "specialist:scan-analyst", "specialist:exploit-selector",
      "specialist:evasion-optimizer", "specialist:lateral-planner",
      "specialist:persistence-engineer", "engagement-orchestrator",
    ];

    for (const caller of nexusCallers) {
      const runsPerCaller = rand(2, 5);
      for (let r = 0; r < runsPerCaller; r++) {
        const executionId = `npe-${randomUUID().slice(0, 8)}`;
        const tier = pick([1, 2, 3, 4]);
        const status = pick(["completed", "completed", "completed", "failed", "running"] as const);
        const stages = ["requirement_analysis", "architecture", "code_generation", "qa_validation", "security_review", "integration_test"];
        const completedStages = status === "completed" ? stages.length : status === "failed" ? rand(1, 4) : rand(1, 3);

        const stageHistory = stages.slice(0, completedStages).map((stage, idx) => ({
          stage,
          startedAt: Date.now() - rand(1, 30) * 24 * 60 * 60 * 1000,
          completedAt: idx < completedStages - 1 || status === "completed" ? Date.now() - rand(0, 29) * 24 * 60 * 60 * 1000 : undefined,
          status: (idx < completedStages - 1 || status === "completed" ? "passed" : status === "failed" ? "failed" : "passed") as "passed" | "failed" | "skipped",
          retries: rand(0, 2),
          evidence: `Stage ${stage} ${idx < completedStages - 1 || status === "completed" ? "passed" : "in progress"} for ${caller}`,
          score: rand(60, 100),
          agentUsed: caller,
        }));

        const qaScore = rand(50, 100);
        const secScore = rand(40, 100);
        const intScore = rand(55, 100);
        const overallScore = Math.round((qaScore + secScore + intScore) / 3);

        const startedAtTs = new Date(Date.now() - rand(1, 30) * 24 * 60 * 60 * 1000)
          .toISOString().slice(0, 19).replace("T", " ");

        await db.insert(nexusPipelineExecutions).values({
          executionId,
          callerName: caller,
          graduationTier: tier,
          triggerType: pick(["auto", "manual", "scheduled"] as const),
          currentStage: status === "completed" ? "completed" as const : status === "failed" ? "failed" as const : pick(stages.slice(0, completedStages)) as any,
          stageHistory,
          requirementSpec: {
            inputSchema: { type: "object", properties: { target: { type: "string" } } },
            outputSchema: { type: "object", properties: { result: { type: "string" }, score: { type: "number" } } },
            sampleInputs: [{ target: pick(LAB_TARGETS).domain }],
            sampleOutputs: [{ result: "vulnerability_found", score: 85 }],
            constraints: ["Must complete within 30s", "Stealth score > 0.7"],
            performanceTargets: { maxLatencyMs: 5000, minAccuracy: 0.85 },
          },
          generatedCode: `// Auto-generated code for ${caller}\nexport async function execute(input) {\n  // Implementation\n  return { result: "success", score: ${overallScore} };\n}`,
          generatedTests: `// Tests for ${caller}\ntest("should execute successfully", () => {\n  expect(execute({ target: "test" })).resolves.toHaveProperty("result");\n});`,
          qaScore,
          securityScore: secScore,
          integrationScore: intScore,
          overallScore,
          costSaved: String(randFloat(0.5, 15.0)),
          tokensConsumed: rand(5000, 50000),
          llmCallsCount: rand(3, 20),
          status,
          errorMessage: status === "failed" ? "Quality gate failed: security score below threshold" : null,
          startedAt: startedAtTs,
          completedAt: status === "completed" || status === "failed"
            ? new Date(Date.now() - rand(0, 29) * 24 * 60 * 60 * 1000).toISOString().slice(0, 19).replace("T", " ")
            : null,
        });

        // Add quality gates for each execution
        const gateTypes = ["llm_judge", "unit_test", "type_check", "security_scan", "performance_bench", "integration_test"] as const;
        for (const gateType of gateTypes) {
          const passed = Math.random() > 0.15 ? 1 : 0;
          const score = passed ? rand(70, 100) : rand(20, 60);
          await db.insert(nexusQualityGates).values({
            executionId,
            gateName: `${gateType.replace(/_/g, ' ')} for ${caller}`,
            gateType,
            passed,
            score,
            maxScore: 100,
            evidence: {
              judgeReasoning: gateType === "llm_judge" ? `Code quality assessment: ${passed ? 'Meets standards' : 'Below threshold'}. Score: ${score}/100.` : undefined,
              testResults: gateType === "unit_test" ? { passed: rand(8, 15), failed: passed ? 0 : rand(1, 3), skipped: rand(0, 2) } : undefined,
              securityFindings: gateType === "security_scan" ? (passed ? [] : [{ severity: "medium", description: "Potential injection vulnerability in input handling" }]) : undefined,
              performanceMetrics: gateType === "performance_bench" ? { latencyMs: rand(100, 5000), memoryMb: rand(50, 500), throughputRps: rand(10, 100) } : undefined,
            },
            retryAttempt: passed ? 0 : rand(0, 2),
          });
        }

        nexusCount++;
      }
    }
    results.nexusPipelineExecutions = nexusCount;

    // ─── 7. Seed Shadow Test Configs & Results ────────────────────────────
    // First ensure shadow configs exist
    const existingConfigs = await db.select().from(nexusShadowConfigs);
    let configIds: number[] = existingConfigs.map(c => c.id);

    if (configIds.length === 0) {
      // Create shadow test configs
      const configs = [
        { name: "Engagement Orchestrator A/B", primary: "gemini-2.5-flash", experimental: "gpt-4o", filter: "engagement-orchestrator", pct: 10 },
        { name: "Specialist Agents A/B", primary: "gemini-2.5-flash", experimental: "claude-sonnet-4-20250514", filter: "specialist:", pct: 15 },
        { name: "Chat Handler A/B", primary: "gemini-2.5-flash", experimental: "gpt-4o-mini", filter: "operator-cockpit", pct: 20 },
      ];
      for (const cfg of configs) {
        const cfgResult = await db.insert(nexusShadowConfigs).values({
          configName: cfg.name,
          enabled: 1,
          shadowPercentage: cfg.pct,
          primaryModel: cfg.primary,
          experimentalModel: cfg.experimental,
          callerFilter: cfg.filter,
          priorityFilter: "all" as const,
          maxConcurrent: 10,
          activeShadowTests: 0,
          totalRuns: 0,
        });
        configIds.push(Number((cfgResult as any)[0]?.insertId || (cfgResult as any).insertId));
      }
    }

    // Create shadow test results
    let shadowCount = 0;
    for (const configId of configIds) {
      const config = existingConfigs.find(c => c.id === configId) || { primaryModel: "gemini-2.5-flash", experimentalModel: "gpt-4o", callerFilter: "" };
      const testsPerConfig = rand(10, 25);
      for (let t = 0; t < testsPerConfig; t++) {
        const caller = pick(allCallers);
        const primaryLatency = rand(200, 5000);
        const expLatency = rand(200, 8000);
        const primaryScore = rand(50, 100);
        const expScore = rand(50, 100);
        const verdict = primaryScore > expScore + 10 ? "primary_better" as const
          : expScore > primaryScore + 10 ? "experimental_better" as const
          : "tie" as const;

        const createdAtTs = new Date(Date.now() - rand(0, 30) * 24 * 60 * 60 * 1000)
          .toISOString().slice(0, 19).replace("T", " ");

        await db.insert(nexusShadowTests).values({
          configId,
          caller,
          promptSnippet: pick(DECISIONS).decision.slice(0, 200),
          primaryModel: (config as any).primaryModel || "gemini-2.5-flash",
          primaryLatencyMs: primaryLatency,
          primaryTokensIn: rand(200, 3000),
          primaryTokensOut: rand(100, 1500),
          primaryScore,
          experimentalModel: (config as any).experimentalModel || "gpt-4o",
          experimentalLatencyMs: expLatency,
          experimentalTokensIn: rand(200, 3000),
          experimentalTokensOut: rand(100, 1500),
          experimentalScore: expScore,
          judgeVerdict: verdict,
          judgeReasoning: `${verdict === "primary_better" ? "Primary model" : verdict === "experimental_better" ? "Experimental model" : "Both models"} ${verdict === "tie" ? "performed comparably" : "showed superior"} performance. Primary: ${primaryScore}/100 (${primaryLatency}ms). Experimental: ${expScore}/100 (${expLatency}ms).`,
          judgeScore: Math.round((primaryScore + expScore) / 2),
          status: "completed" as const,
          createdAt: createdAtTs,
          completedAt: createdAtTs,
        });
        shadowCount++;
      }

      // Update total runs count on config
      await db.update(nexusShadowConfigs)
        .set({ totalRuns: shadowCount })
        .where(sql`id = ${configId}`);
    }
    results.nexusShadowTests = shadowCount;

    return {
      success: true,
      message: "Lab engagement data seeded successfully across all LLM tables",
      counts: results,
      engagementIds,
      tables: [
        "engagements",
        "engagement_timeline_events",
        "llm_telemetry",
        "llm_decision_log",
        "llm_training_examples",
        "nexus_pipeline_executions",
        "nexus_quality_gates",
        "nexus_shadow_configs",
        "nexus_shadow_tests",
      ],
    };
  }),

  /**
   * Get seed status — check how much data exists in each table
   */
  getStatus: protectedProcedure.query(async () => {
    const db = await getDb();

    const [telemetryCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(llmTelemetry);
    const [decisionCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(llmDecisionLog);
    const [trainingCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(llmTrainingExamples);
    const [nexusCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(nexusPipelineExecutions);
    const [gateCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(nexusQualityGates);
    const [shadowConfigCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(nexusShadowConfigs);
    const [shadowTestCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(nexusShadowTests);
    const [engagementCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(engagements);
    const [timelineCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(engagementTimelineEvents);

    return {
      llmTelemetry: Number(telemetryCount.count),
      llmDecisionLog: Number(decisionCount.count),
      llmTrainingExamples: Number(trainingCount.count),
      nexusPipelineExecutions: Number(nexusCount.count),
      nexusQualityGates: Number(gateCount.count),
      nexusShadowConfigs: Number(shadowConfigCount.count),
      nexusShadowTests: Number(shadowTestCount.count),
      engagements: Number(engagementCount.count),
      engagementTimelineEvents: Number(timelineCount.count),
    };
  }),
});
