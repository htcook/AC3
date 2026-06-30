/**
 * Tests for Exploit Guardrails + Learning Engine Integration
 *
 * Covers:
 *   1. Guardrail module: CVE grounding, port grounding, tech grounding, scope enforcement, drift detection
 *   2. Learning engine: vuln classification, outcome accumulation, prioritization, self-correction, chain discovery
 *   3. Integration: guardrails wired into exploit generator, learning context injected into prompts
 *   4. crAPI and new lab targets added to TRAINING_LABS maps
 *   5. Heartbeat touches in exploitation phase
 */

import { describe, it, expect, beforeEach } from "vitest";
import fs from "fs";

// ─── Guardrails Module Tests ─────────────────────────────────────────────────


// Skip in CI — requires SSH access to scan server
const __skipInCI = !process.env.SCAN_SERVER_HOST;

describe.skipIf(__skipInCI)("Exploit Guardrails Module", () => {
  const guardrailsSrc = fs.readFileSync("server/lib/exploit-guardrails.ts", "utf-8");

  it("exports GroundingContext interface with required fields", () => {
    expect(guardrailsSrc).toContain("export interface GroundingContext");
    expect(guardrailsSrc).toContain("confirmedPorts");
    expect(guardrailsSrc).toContain("confirmedTechnologies");
    expect(guardrailsSrc).toContain("confirmedCVEs");
    expect(guardrailsSrc).toContain("scopeTargets");
    expect(guardrailsSrc).toContain("targetHostname");
    expect(guardrailsSrc).toContain("reconEvidence");
  });

  it("exports ExploitProposal interface with correct fields", () => {
    expect(guardrailsSrc).toContain("export interface ExploitProposal");
    expect(guardrailsSrc).toContain("cveId?: string");
    expect(guardrailsSrc).toContain("targetPort?: number");
    expect(guardrailsSrc).toContain("assumedTechnologies?: string[]");
    expect(guardrailsSrc).toContain("confidence: number");
    expect(guardrailsSrc).toContain("code: string");
  });

  it("exports GuardrailResult interface with passed, riskScore, blockedReasons", () => {
    expect(guardrailsSrc).toContain("export interface GuardrailResult");
    expect(guardrailsSrc).toContain("passed: boolean");
    expect(guardrailsSrc).toContain("riskScore: number");
    expect(guardrailsSrc).toContain("blockedReasons: string[]");
    expect(guardrailsSrc).toContain("requiresApproval: boolean");
  });

  it("validates CVE grounding with fake CVE pattern detection", () => {
    expect(guardrailsSrc).toContain("FAKE_CVE_PATTERNS");
    expect(guardrailsSrc).toContain("CVE-\\d{4}-0{4,}");
    expect(guardrailsSrc).toContain("Suspected fabricated CVE");
  });

  it("validates port grounding against confirmed open ports", () => {
    expect(guardrailsSrc).toContain("validatePortGrounding");
    expect(guardrailsSrc).toContain("not confirmed open by recon");
  });

  it("validates technology grounding against confirmed tech stack", () => {
    expect(guardrailsSrc).toContain("validateTechnologyGrounding");
  });

  it("validates scope enforcement against in-scope targets", () => {
    expect(guardrailsSrc).toContain("validateScopeEnforcement");
  });

  it("detects drift signals with severity levels", () => {
    expect(guardrailsSrc).toContain("export interface DriftSignal");
    expect(guardrailsSrc).toContain("cve_fabrication");
    expect(guardrailsSrc).toContain("port_hallucination");
    expect(guardrailsSrc).toContain("tech_drift");
    expect(guardrailsSrc).toContain("scope_creep");
    expect(guardrailsSrc).toContain("confidence_inflation");
  });

  it("detects false positive exploit claims", () => {
    expect(guardrailsSrc).toContain("export function detectFalsePositive");
    expect(guardrailsSrc).toContain("EXPLOIT_SUCCESS");
    expect(guardrailsSrc).toContain("isFalsePositive");
    expect(guardrailsSrc).toContain("Connection refused");
  });

  it("runs all guardrail checks in runGuardrails function", () => {
    expect(guardrailsSrc).toContain("export function runGuardrails");
    expect(guardrailsSrc).toContain("validateCVEGrounding");
    expect(guardrailsSrc).toContain("validatePortGrounding");
    expect(guardrailsSrc).toContain("validateTechnologyGrounding");
    expect(guardrailsSrc).toContain("validateScopeEnforcement");
    expect(guardrailsSrc).toContain("validateConfidenceGating");
    expect(guardrailsSrc).toContain("detectDrift");
  });

  it("formats guardrail summary for logging", () => {
    expect(guardrailsSrc).toContain("export function formatGuardrailSummary");
    expect(guardrailsSrc).toContain("PASSED");
    expect(guardrailsSrc).toContain("BLOCKED");
  });

  it("calculates risk score from critical, high, and medium failures", () => {
    expect(guardrailsSrc).toContain("criticalFailures.length * 40");
    expect(guardrailsSrc).toContain("highFailures.length * 20");
    expect(guardrailsSrc).toContain("mediumFailures.length * 10");
  });
});

// ─── Learning Engine Tests ───────────────────────────────────────────────────

describe("Exploit Learning Engine", () => {
  const learningSrc = fs.readFileSync("server/lib/exploit-learning-engine.ts", "utf-8");

  it("classifies vulnerability classes from title and description", () => {
    expect(learningSrc).toContain("export function classifyVulnClass");
    expect(learningSrc).toContain("vulnClass: 'sqli'");
    expect(learningSrc).toContain("vulnClass: 'xss'");
    expect(learningSrc).toContain("vulnClass: 'rce'");
    expect(learningSrc).toContain("vulnClass: 'ssti'");
    expect(learningSrc).toContain("vulnClass: 'file_inclusion'");
    expect(learningSrc).toContain("vulnClass: 'ssrf'");
    expect(learningSrc).toContain("vulnClass: 'xxe'");
    expect(learningSrc).toContain("vulnClass: 'auth_bypass'");
    expect(learningSrc).toContain("vulnClass: 'deserialization'");
  });

  it("accumulates exploit outcomes into pattern knowledge", () => {
    expect(learningSrc).toContain("export function accumulateOutcome");
    expect(learningSrc).toContain("recentOutcomes.push(outcome)");
    expect(learningSrc).toContain("exploitPatterns.set(key, pattern)");
    expect(learningSrc).toContain("successfulApproaches");
    expect(learningSrc).toContain("failedApproaches");
  });

  it("extracts failure reasons from stderr/stdout", () => {
    expect(learningSrc).toContain("connection_refused");
    expect(learningSrc).toContain("timeout");
    expect(learningSrc).toContain("waf_blocked");
    expect(learningSrc).toContain("endpoint_not_found");
    expect(learningSrc).toContain("auth_required");
    expect(learningSrc).toContain("target_patched");
    expect(learningSrc).toContain("missing_dependency");
  });

  it("prioritizes vulnerabilities by exploitability score", () => {
    expect(learningSrc).toContain("export function prioritizeVulns");
    expect(learningSrc).toContain("exploitabilityScore");
    expect(learningSrc).toContain("suggestedApproach");
    expect(learningSrc).toContain("chainOpportunities");
  });

  it("applies vuln-class inherent exploitability boost", () => {
    expect(learningSrc).toContain("rce: 15");
    expect(learningSrc).toContain("sqli: 12");
    expect(learningSrc).toContain("ssti: 10");
  });

  it("builds self-correction prompts with mandatory rules", () => {
    expect(learningSrc).toContain("export async function buildSelfCorrectionPrompt");
    expect(learningSrc).toContain("DO NOT repeat the same approach");
    expect(learningSrc).toContain("DO NOT ignore guardrail violations");
    expect(learningSrc).toContain("MUST be materially different");
  });

  it("determines retry eligibility with shouldRetry", () => {
    expect(learningSrc).toContain("export function shouldRetry");
    expect(learningSrc).toContain("MAX_SELF_CORRECTIONS");
    expect(learningSrc).toContain("Exploit succeeded");
    expect(learningSrc).toContain("Non-retryable failure");
    expect(learningSrc).toContain("target_patched");
    expect(learningSrc).toContain("connection_refused");
  });

  it("discovers exploit chains using LLM with grounding checks", () => {
    expect(learningSrc).toContain("export async function discoverExploitChains");
    expect(learningSrc).toContain("GROUNDING RULES (MANDATORY)");
    expect(learningSrc).toContain("allStepsGrounded");
    expect(learningSrc).toContain("hallucination guard");
  });

  it("builds learning context for LLM prompts", () => {
    expect(learningSrc).toContain("export function buildLearningContext");
    expect(learningSrc).toContain("Approaches That Worked");
    expect(learningSrc).toContain("Approaches That FAILED (DO NOT REPEAT)");
    expect(learningSrc).toContain("Known Exploit Chains");
  });

  it("builds grounding context from asset data", () => {
    expect(learningSrc).toContain("export function buildGroundingContextFromAsset");
    expect(learningSrc).toContain("confirmedPorts");
    expect(learningSrc).toContain("confirmedTechnologies");
    expect(learningSrc).toContain("confirmedCVEs");
    expect(learningSrc).toContain("scopeTargets");
  });

  it("provides learning stats for reporting", () => {
    expect(learningSrc).toContain("export function getLearningStats");
    expect(learningSrc).toContain("totalOutcomes");
    expect(learningSrc).toContain("successRate");
    expect(learningSrc).toContain("patternsLearned");
    expect(learningSrc).toContain("chainsDiscovered");
    expect(learningSrc).toContain("falsePositivesDetected");
    expect(learningSrc).toContain("guardrailBlocks");
  });

  it("caps recent outcomes at MAX_RECENT_OUTCOMES", () => {
    expect(learningSrc).toContain("MAX_RECENT_OUTCOMES = 500");
    expect(learningSrc).toContain("recentOutcomes.shift()");
  });

  it("limits self-correction to MAX_SELF_CORRECTIONS attempts", () => {
    expect(learningSrc).toContain("MAX_SELF_CORRECTIONS = 3");
  });
});

// ─── Integration: Guardrails Wired into Exploit Generator ────────────────────

describe("Guardrails + Learning Engine Integration in Exploit Generator", () => {
  const exploitGenSrc = fs.readFileSync("server/lib/functional-exploit-generator.ts", "utf-8");

  it("imports guardrail functions", () => {
    expect(exploitGenSrc).toContain("import {");
    expect(exploitGenSrc).toContain("runGuardrails");
    expect(exploitGenSrc).toContain("detectFalsePositive");
    expect(exploitGenSrc).toContain("formatGuardrailSummary");
    expect(exploitGenSrc).toContain("type GroundingContext");
    expect(exploitGenSrc).toContain("type ExploitProposal");
  });

  it("imports learning engine functions", () => {
    expect(exploitGenSrc).toContain("classifyVulnClass");
    expect(exploitGenSrc).toContain("buildLearningContext");
    expect(exploitGenSrc).toContain("buildGroundingContextFromAsset");
    expect(exploitGenSrc).toContain("prioritizeVulns");
    expect(exploitGenSrc).toContain("discoverExploitChains");
    expect(exploitGenSrc).toContain("accumulateOutcome");
    expect(exploitGenSrc).toContain("shouldRetry");
    expect(exploitGenSrc).toContain("buildSelfCorrectionPrompt");
  });

  it("adds hallucination guardrail rules to system prompt", () => {
    expect(exploitGenSrc).toContain("HALLUCINATION & DRIFT GUARDRAILS (MANDATORY)");
    expect(exploitGenSrc).toContain("Port Grounding");
    expect(exploitGenSrc).toContain("Technology Grounding");
    expect(exploitGenSrc).toContain("CVE Grounding");
    expect(exploitGenSrc).toContain("Scope Grounding");
    expect(exploitGenSrc).toContain("Capability Grounding");
    expect(exploitGenSrc).toContain("Evidence Grounding");
    expect(exploitGenSrc).toContain("Drift Prevention");
    expect(exploitGenSrc).toContain("False Positive Awareness");
    expect(exploitGenSrc).toContain("No Hallucinated Endpoints");
    expect(exploitGenSrc).toContain("Payload Realism");
  });

  it("injects learning context into the knowledge context", () => {
    expect(exploitGenSrc).toContain("classifyVulnClass(context.vulnerability.title");
    expect(exploitGenSrc).toContain("buildLearningContext(vulnClass");
    expect(exploitGenSrc).toContain("learningContext");
  });

  it("builds grounding context from asset data", () => {
    expect(exploitGenSrc).toContain("buildGroundingContextFromAsset({");
    expect(exploitGenSrc).toContain("hostname: context.target.hostname");
    expect(exploitGenSrc).toContain("ports: context.target.ports");
    expect(exploitGenSrc).toContain("technologies: context.target.technologies");
  });

  it("injects grounding summary into user message", () => {
    expect(exploitGenSrc).toContain("GROUNDING CONTEXT (verified recon data");
    expect(exploitGenSrc).toContain("groundingContext.targetHostname");
    expect(exploitGenSrc).toContain("groundingContext.confirmedPorts");
    expect(exploitGenSrc).toContain("groundingContext.confirmedTechnologies");
    expect(exploitGenSrc).toContain("groundingContext.confirmedCVEs");
    expect(exploitGenSrc).toContain("groundingContext.scopeTargets");
  });

  it("runs post-generation guardrail validation", () => {
    expect(exploitGenSrc).toContain("Post-Generation Guardrail Validation");
    expect(exploitGenSrc).toContain("runGuardrails(proposal, groundingContext)");
    expect(exploitGenSrc).toContain("guardrailResult.blockedReasons");
    expect(exploitGenSrc).toContain("formatGuardrailSummary(guardrailResult)");
  });

  it("reduces confidence based on guardrail risk score", () => {
    expect(exploitGenSrc).toContain("adjustedConfidence = Math.max(5, adjustedConfidence - guardrailResult.riskScore)");
  });

  it("checks for false positive signals pre-execution", () => {
    expect(exploitGenSrc).toContain("detectFalsePositive({");
    expect(exploitGenSrc).toContain("stdout: ''");
    expect(exploitGenSrc).toContain("stderr: ''");
    expect(exploitGenSrc).toContain("exitCode: 0");
  });

  it("appends guardrail notes to reasoning output", () => {
    expect(exploitGenSrc).toContain("guardrailAnnotation");
    expect(exploitGenSrc).toContain("GUARDRAIL NOTES");
    expect(exploitGenSrc).toContain("reasoning: parsed.reasoning + guardrailAnnotation");
  });

  it("returns adjusted confidence instead of raw parsed confidence", () => {
    expect(exploitGenSrc).toContain("confidence: adjustedConfidence");
  });

  it("wraps guardrail check in try/catch for non-blocking failure", () => {
    expect(exploitGenSrc).toContain("Guardrail check failed (non-blocking)");
  });
});

// ─── Integration: Learning Engine Wired into Orchestrator ────────────────────

describe("Learning Engine Integration in Engagement Orchestrator", () => {
  const orchestratorSrc = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

  it("imports learning engine functions", () => {
    expect(orchestratorSrc).toContain("accumulateOutcome as accumulateLearningOutcome");
    expect(orchestratorSrc).toContain("classifyVulnClass");
    expect(orchestratorSrc).toContain("getLearningStats");
    expect(orchestratorSrc).toContain("type ExploitOutcome as LearningExploitOutcome");
  });

  it("accumulates exploit outcomes in the exploitation phase", () => {
    expect(orchestratorSrc).toContain("Learning Engine: accumulate exploit outcome");
    expect(orchestratorSrc).toContain("accumulateLearningOutcome({");
    expect(orchestratorSrc).toContain("attemptId:");
    expect(orchestratorSrc).toContain("vulnClass: classifyVulnClass(");
    expect(orchestratorSrc).toContain("targetTechnologies: asset?.technologies || []");
  });

  it("logs learning engine stats summary at end of exploitation phase", () => {
    expect(orchestratorSrc).toContain("Learning Engine Summary");
    expect(orchestratorSrc).toContain("getPersistedLearningStats()");
    expect(orchestratorSrc).toContain("patterns");
    expect(orchestratorSrc).toContain("chains");
    expect(orchestratorSrc).toContain("FP detected");
    expect(orchestratorSrc).toContain("guardrail blocks");
    expect(orchestratorSrc).toContain("Cross-engagement DB");
    expect(orchestratorSrc).toContain("lifetime success rate");
  });

  it("wraps learning engine calls in try/catch for resilience", () => {
    expect(orchestratorSrc).toContain("[LearningEngine] Failed to accumulate outcome");
    expect(orchestratorSrc).toContain("[LearningEngine] Stats summary failed");
  });

  it("adds heartbeat touches before and after exploit pipeline calls", () => {
    // Before enhanced exploit pipeline
    const heartbeatBeforeExploit = orchestratorSrc.indexOf("Update heartbeat before long-running LLM exploit generation");
    const enhancedPipelineCall = orchestratorSrc.indexOf("executeEnhancedExploitWithChaining({");
    expect(heartbeatBeforeExploit).toBeGreaterThan(-1);
    expect(enhancedPipelineCall).toBeGreaterThan(-1);
    expect(heartbeatBeforeExploit).toBeLessThan(enhancedPipelineCall);

    // After enhanced exploit pipeline
    const heartbeatAfterExploit = orchestratorSrc.indexOf("Update heartbeat after exploit pipeline completes");
    expect(heartbeatAfterExploit).toBeGreaterThan(-1);
    expect(heartbeatAfterExploit).toBeGreaterThan(enhancedPipelineCall);
  });
});

// ─── crAPI and New Lab Targets in TRAINING_LABS ──────────────────────────────

describe("crAPI and New Lab Targets in TRAINING_LABS", () => {
  const automationSrc = fs.readFileSync("server/routers/engagement-automation.ts", "utf-8");

  it("includes crAPI in TRAINING_LABS map", () => {
    expect(automationSrc).toContain("'crapi.lab.aceofcloud.io'");
    expect(automationSrc).toContain("crAPI (AceOfCloud Lab)");
    expect(automationSrc).toContain("BOLA");
    expect(automationSrc).toContain("Mass Assignment");
    expect(automationSrc).toContain("Rate Limiting Bypass");
  });

  it("includes bWAPP in TRAINING_LABS map", () => {
    expect(automationSrc).toContain("'bwapp.lab.aceofcloud.io'");
    expect(automationSrc).toContain("bWAPP (AceOfCloud Lab)");
    expect(automationSrc).toContain("Shellshock");
    expect(automationSrc).toContain("PHP Code Injection");
  });

  it("includes Mutillidae in TRAINING_LABS map", () => {
    expect(automationSrc).toContain("'mutillidae.lab.aceofcloud.io'");
    expect(automationSrc).toContain("Mutillidae (AceOfCloud Lab)");
    expect(automationSrc).toContain("Log Injection");
    expect(automationSrc).toContain("HTTP Parameter Pollution");
  });

  it("has crAPI in both single-target and batch TRAINING_LABS maps", () => {
    // Count occurrences of crAPI in the file — should appear in both maps
    const crApiOccurrences = (automationSrc.match(/crapi\.lab\.aceofcloud\.io/g) || []).length;
    expect(crApiOccurrences).toBeGreaterThanOrEqual(2);
  });

  it("has bWAPP in both single-target and batch TRAINING_LABS maps", () => {
    const bwappOccurrences = (automationSrc.match(/bwapp\.lab\.aceofcloud\.io/g) || []).length;
    expect(bwappOccurrences).toBeGreaterThanOrEqual(2);
  });

  it("has Mutillidae in both single-target and batch TRAINING_LABS maps", () => {
    const mutillidaeOccurrences = (automationSrc.match(/mutillidae\.lab\.aceofcloud\.io/g) || []).length;
    expect(mutillidaeOccurrences).toBeGreaterThanOrEqual(2);
  });

  it("crAPI expected vulns include API-specific vulnerability classes", () => {
    // Find the crAPI entry and verify it has API-specific vulns
    const crApiSection = automationSrc.slice(
      automationSrc.indexOf("'crapi.lab.aceofcloud.io'"),
      automationSrc.indexOf("'crapi.lab.aceofcloud.io'") + 500
    );
    expect(crApiSection).toContain("BOLA");
    expect(crApiSection).toContain("Mass Assignment");
    expect(crApiSection).toContain("Excessive Data Exposure");
    expect(crApiSection).toContain("Rate Limiting Bypass");
    expect(crApiSection).toContain("SSRF");
    expect(crApiSection).toContain("JWT Vulnerabilities");
    expect(crApiSection).toContain("IDOR");
  });
});

// ─── Guardrail Rules in System Prompt ────────────────────────────────────────

describe("Guardrail Rules in Exploit Generator System Prompt", () => {
  const exploitGenSrc = fs.readFileSync("server/lib/functional-exploit-generator.ts", "utf-8");

  it("guardrail rules appear before OWASP WSTG references", () => {
    const guardrailPos = exploitGenSrc.indexOf("HALLUCINATION & DRIFT GUARDRAILS");
    const owaspPos = exploitGenSrc.indexOf("OWASP WSTG METHODOLOGY REFERENCES");
    expect(guardrailPos).toBeGreaterThan(-1);
    expect(owaspPos).toBeGreaterThan(-1);
    expect(guardrailPos).toBeLessThan(owaspPos);
  });

  it("includes all 10 guardrail rules", () => {
    const rules = [
      "Port Grounding", "Technology Grounding", "CVE Grounding",
      "Scope Grounding", "Capability Grounding", "Evidence Grounding",
      "Drift Prevention", "False Positive Awareness",
      "No Hallucinated Endpoints", "Payload Realism",
    ];
    for (const rule of rules) {
      expect(exploitGenSrc).toContain(rule);
    }
  });

  it("includes rejection warning for guardrail violations", () => {
    expect(exploitGenSrc).toContain("VIOLATING THESE RULES WILL CAUSE YOUR EXPLOIT TO BE REJECTED BY THE GUARDRAIL ENGINE");
  });
});

// ─── ExploitOutcome Type Contract ────────────────────────────────────────────

describe("ExploitOutcome Type Contract", () => {
  const learningSrc = fs.readFileSync("server/lib/exploit-learning-engine.ts", "utf-8");

  it("ExploitOutcome has all required fields for accumulation", () => {
    expect(learningSrc).toContain("attemptId: string");
    expect(learningSrc).toContain("engagementId: number");
    expect(learningSrc).toContain("vulnTitle: string");
    expect(learningSrc).toContain("vulnCVE?: string");
    expect(learningSrc).toContain("vulnSeverity: string");
    expect(learningSrc).toContain("vulnClass: string");
    expect(learningSrc).toContain("targetHostname: string");
    expect(learningSrc).toContain("targetPort?: number");
    expect(learningSrc).toContain("targetTechnologies: string[]");
    expect(learningSrc).toContain("language: string");
    expect(learningSrc).toContain("code: string");
    expect(learningSrc).toContain("success: boolean");
    expect(learningSrc).toContain("exitCode: number");
    expect(learningSrc).toContain("executionTimeMs: number");
    expect(learningSrc).toContain("attemptNumber: number");
    expect(learningSrc).toContain("previousAttemptIds: string[]");
  });

  it("ExploitPattern tracks successful and failed approaches", () => {
    expect(learningSrc).toContain("export interface ExploitPattern");
    expect(learningSrc).toContain("successfulApproaches:");
    expect(learningSrc).toContain("failedApproaches:");
    expect(learningSrc).toContain("knownChains:");
    expect(learningSrc).toContain("successRate: number");
    expect(learningSrc).toContain("failureReason: string");
    expect(learningSrc).toContain("failureCount: number");
  });

  it("SelfCorrectionContext includes previous attempts and guardrail violations", () => {
    expect(learningSrc).toContain("export interface SelfCorrectionContext");
    expect(learningSrc).toContain("previousAttempts:");
    expect(learningSrc).toContain("guardrailViolations: string[]");
    expect(learningSrc).toContain("driftSignals: DriftSignal[]");
    expect(learningSrc).toContain("relevantPatterns: ExploitPattern[]");
  });
});
