/**
 * Authentication Pipeline Orchestration Engine
 *
 * Implements the orchestration spec from Auth Testing Pack v1.2:
 * - Workflow Controller: execute pipelines, track state, handle retries/backoff
 * - Policy Guardrail Engine: scope checks, rate limiting, lockout avoidance, FedRAMP mode
 * - Tool Adapters: invoke tools, parse outputs, emit normalized events
 * - Evidence Store: store requests/responses, timings, artifacts, provenance
 * - LLM Reasoner: hypothesis generation, decisioning, report drafting
 *
 * CROSS-MODULE PATTERN: The PipelineStep / PipelineGuardrails / WorkflowController
 * pattern is generic and reusable by ANY engine (credential attacks, exploitation,
 * lateral movement, privesc, OPSEC). This module exports the base abstractions.
 */

import {
  PipelineGuardrails,
  STRICT_MODE_GUARDRAILS,
  STANDARD_MODE_GUARDRAILS,
  validateAgainstGuardrails,
  AUTH_TESTING_PHASES,
  AUTH_ATTACK_TAXONOMY,
  SSO_ASSESSMENT_CHECKS,
  AUTH_REASONING_SYSTEM_PROMPT,
  type AuthEvidenceEvent,
  type AuthFinding,
} from "./auth-testing-knowledge";

// ─── Pipeline Primitives ────────────────────────────────────────────────────

export type PipelineStepStatus = "pending" | "running" | "completed" | "failed" | "skipped" | "blocked";

export interface PipelineStep {
  id: string;
  tool: string;
  description: string;
  inputs: Record<string, any>;
  guards: Partial<PipelineGuardrails>;
  outputs: Record<string, any>;
  status: PipelineStepStatus;
  startedAt?: number;
  completedAt?: number;
  error?: string;
  evidenceEvents: AuthEvidenceEvent[];
}

export interface Pipeline {
  id: string;
  name: string;
  description: string;
  mode: "strict" | "standard";
  steps: PipelineStep[];
  status: "draft" | "running" | "completed" | "failed" | "paused";
  createdAt: number;
  startedAt?: number;
  completedAt?: number;
  findings: AuthFinding[];
  guardrails: PipelineGuardrails;
  metadata: Record<string, any>;
}

// ─── Pre-Built Pipeline Templates ───────────────────────────────────────────

export interface PipelineTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  defaultMode: "strict" | "standard";
  steps: Array<{
    id: string;
    tool: string;
    description: string;
    defaultInputs: Record<string, any>;
    guards: Partial<PipelineGuardrails>;
    expectedOutputs: string[];
  }>;
  applicablePhases: string[];
}

export const PIPELINE_TEMPLATES: PipelineTemplate[] = [
  {
    id: "auth-recon-flow-capture",
    name: "Auth Recon + Flow Capture",
    description: "Discover authentication endpoints, fingerprint services, and capture the full auth flow for analysis. Safe for strict mode.",
    category: "reconnaissance",
    defaultMode: "strict",
    steps: [
      {
        id: "discover_endpoints",
        tool: "ffuf",
        description: "Discover login, register, reset, callback, and other auth-related endpoints via content discovery",
        defaultInputs: { wordlist: "auth-endpoints", extensions: "html,php,asp,aspx,jsp", rateLimit: 0.5 },
        guards: { maxRps: 0.5 },
        expectedOutputs: ["endpoints"],
      },
      {
        id: "fingerprint_services",
        tool: "scanforge-discovery",
        description: "Fingerprint web services, identify TLS configuration, and detect auth-related headers",
        defaultInputs: { scripts: ["http-auth", "http-methods", "http-enum", "ssl-cert", "ssl-enum-ciphers"], timing: "T2" },
        guards: { maxRps: 0.2 },
        expectedOutputs: ["services", "tls_config"],
      },
      {
        id: "capture_flow",
        tool: "zap",
        description: "Spider the auth flow, capture HAR file, and run passive scan for initial alerts",
        defaultInputs: { mode: "passive", captureHar: true, followRedirects: true },
        guards: { maxRps: 0.2 },
        expectedOutputs: ["har", "alerts", "cookies"],
      },
    ],
    applicablePhases: ["Recon & Identification"],
  },
  {
    id: "enumeration-signals-safe",
    name: "Enumeration Signals (Safe)",
    description: "Detect username enumeration via response timing and length differences. Designed for strict mode with minimal impact.",
    category: "enumeration",
    defaultMode: "strict",
    steps: [
      {
        id: "enum_probe",
        tool: "custom_http_probe",
        description: "Send controlled probes to login endpoint with known-valid and known-invalid usernames, measuring response deltas",
        defaultInputs: { probeCount: 5, measureTiming: true, measureLength: true, jitterThreshold: 50 },
        guards: { maxRps: 0.1, maxAttemptsPerAccount: 2, stopOnLockoutSignal: true },
        expectedOutputs: ["deltas", "enumeration_signals"],
      },
    ],
    applicablePhases: ["Enumeration Testing"],
  },
  {
    id: "session-token-checks",
    name: "Session & Token Checks",
    description: "Comprehensive audit of session management, cookie security, JWT handling, and TLS configuration.",
    category: "session_analysis",
    defaultMode: "strict",
    steps: [
      {
        id: "cookie_audit",
        tool: "zap",
        description: "Audit all cookies for Secure, HttpOnly, SameSite flags and session fixation indicators",
        defaultInputs: { checkFlags: true, checkFixation: true, checkLogout: true },
        guards: { maxRps: 0.2 },
        expectedOutputs: ["cookie_findings"],
      },
      {
        id: "jwt_inspect",
        tool: "jwt_tool",
        description: "Decode and inspect JWT tokens for algorithm, claims, audience, issuer, and expiry",
        defaultInputs: { checkAlgorithm: true, checkClaims: true, checkSignature: true },
        guards: { maxRps: 0.2 },
        expectedOutputs: ["jwt_findings"],
      },
      {
        id: "tls_audit",
        tool: "testssl",
        description: "Assess TLS configuration for weak ciphers, protocol versions, and certificate issues",
        defaultInputs: { checkProtocols: true, checkCiphers: true, checkVulnerabilities: true },
        guards: { maxRps: 0.2 },
        expectedOutputs: ["tls_findings"],
      },
    ],
    applicablePhases: ["Session & Token Security"],
  },
  {
    id: "oauth-oidc-assessment",
    name: "OAuth/OIDC Flow Assessment",
    description: "Systematic assessment of OAuth/OIDC implementation including redirect URI, state, PKCE, nonce, and token validation.",
    category: "sso_assessment",
    defaultMode: "strict",
    steps: [
      {
        id: "redirect_uri_check",
        tool: "custom_http_probe",
        description: "Test redirect_uri validation for exact match, open redirect, and wildcard patterns",
        defaultInputs: { testPatterns: ["subdomain", "path_traversal", "fragment", "parameter_pollution"] },
        guards: { maxRps: 0.1 },
        expectedOutputs: ["redirect_findings"],
      },
      {
        id: "state_nonce_check",
        tool: "mitmproxy",
        description: "Intercept OAuth flow to verify state parameter binding and nonce validation",
        defaultInputs: { captureFlow: true, testStateMissing: true, testStateReplay: true },
        guards: { maxRps: 0.1 },
        expectedOutputs: ["state_findings", "nonce_findings"],
      },
      {
        id: "token_validation",
        tool: "jwt_tool",
        description: "Inspect ID tokens and access tokens for audience, issuer, and signature validation",
        defaultInputs: { checkAudience: true, checkIssuer: true, checkSignature: true },
        guards: { maxRps: 0.2 },
        expectedOutputs: ["token_findings"],
      },
    ],
    applicablePhases: ["Session & Token Security", "Flow Manipulation"],
  },
  {
    id: "saml-assertion-assessment",
    name: "SAML Assertion Assessment",
    description: "Systematic assessment of SAML implementation including signature validation, audience restriction, and replay protection.",
    category: "sso_assessment",
    defaultMode: "strict",
    steps: [
      {
        id: "saml_signature_check",
        tool: "saml_decoder",
        description: "Validate SAML assertion signatures, certificate chain, and detect signature wrapping",
        defaultInputs: { checkSignature: true, checkCertChain: true, testWrapping: true },
        guards: { maxRps: 0.1 },
        expectedOutputs: ["signature_findings"],
      },
      {
        id: "saml_assertion_check",
        tool: "saml_decoder",
        description: "Verify InResponseTo, audience restriction, recipient/destination, and clock skew",
        defaultInputs: { checkInResponseTo: true, checkAudience: true, checkRecipient: true, checkTimestamps: true },
        guards: { maxRps: 0.1 },
        expectedOutputs: ["assertion_findings"],
      },
    ],
    applicablePhases: ["Session & Token Security", "Flow Manipulation"],
  },
  {
    id: "credential-defense-assessment",
    name: "Credential Defense Assessment",
    description: "Safely assess lockout thresholds, rate limiting, CAPTCHA effectiveness, and password policy without triggering lockouts.",
    category: "credential_surface",
    defaultMode: "strict",
    steps: [
      {
        id: "lockout_threshold",
        tool: "custom_http_probe",
        description: "Carefully probe lockout threshold with controlled attempts (stop before lockout)",
        defaultInputs: { maxAttempts: 3, stopOnWarning: true, measureBackoff: true },
        guards: { maxRps: 0.1, maxAttemptsPerAccount: 1, stopOnLockoutSignal: true },
        expectedOutputs: ["lockout_findings"],
      },
      {
        id: "rate_limit_check",
        tool: "custom_http_probe",
        description: "Detect rate limiting mechanisms and measure their thresholds",
        defaultInputs: { rampUp: true, startRps: 0.05, maxRps: 0.5 },
        guards: { maxRps: 0.5, stopOnLockoutSignal: true },
        expectedOutputs: ["rate_limit_findings"],
      },
      {
        id: "password_policy_check",
        tool: "custom_http_probe",
        description: "Assess password policy enforcement via registration/reset endpoints",
        defaultInputs: { testWeakPasswords: true, testPolicyBoundary: true },
        guards: { maxRps: 0.1 },
        expectedOutputs: ["password_policy_findings"],
      },
    ],
    applicablePhases: ["Credential Surface Analysis"],
  },
];

// ─── Workflow Controller ────────────────────────────────────────────────────

export interface WorkflowState {
  pipelineId: string;
  currentStepIndex: number;
  totalSteps: number;
  status: Pipeline["status"];
  startedAt: number;
  lastUpdated: number;
  evidenceCount: number;
  findingCount: number;
  guardrailViolations: string[];
  humanApprovalRequired: boolean;
  humanApprovalReason?: string;
}

/**
 * Initialize a pipeline from a template with target-specific configuration.
 */
export function initializePipeline(
  templateId: string,
  target: string,
  mode: "strict" | "standard",
  overrides?: Partial<PipelineGuardrails>
): Pipeline | null {
  const template = PIPELINE_TEMPLATES.find(t => t.id === templateId);
  if (!template) return null;

  const guardrails = {
    ...(mode === "strict" ? STRICT_MODE_GUARDRAILS : STANDARD_MODE_GUARDRAILS),
    ...overrides,
  };

  const pipeline: Pipeline = {
    id: `pipeline-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    name: template.name,
    description: template.description,
    mode,
    steps: template.steps.map(s => ({
      id: s.id,
      tool: s.tool,
      description: s.description,
      inputs: { ...s.defaultInputs, target },
      guards: { ...guardrails, ...s.guards },
      outputs: {},
      status: "pending" as PipelineStepStatus,
      evidenceEvents: [],
    })),
    status: "draft",
    createdAt: Date.now(),
    findings: [],
    guardrails,
    metadata: { target, templateId, mode },
  };

  return pipeline;
}

/**
 * Validate a pipeline step against its guardrails before execution.
 * Returns approval status and any violations.
 */
export function validateStepExecution(
  step: PipelineStep,
  pipelineGuardrails: PipelineGuardrails
): { approved: boolean; violations: string[]; requiresHumanApproval: boolean; reason?: string } {
  const mergedGuardrails = { ...pipelineGuardrails, ...step.guards };

  const validation = validateAgainstGuardrails(
    {
      rps: step.inputs.rateLimit || step.inputs.rps || step.inputs.maxRps,
      attemptsPerAccount: step.inputs.maxAttempts || step.inputs.attemptsPerAccount,
      target: step.inputs.target,
      hasEvidence: true,
    },
    mergedGuardrails
  );

  // Human-in-the-loop gates
  const requiresHumanApproval =
    step.tool === "hydra" ||
    step.tool === "medusa" ||
    step.tool === "netexec" ||
    (step.inputs.allowCredentialGuessing === true) ||
    (step.inputs.rateLimit && step.inputs.rateLimit > 0.1) ||
    (step.inputs.activeScanning === true && pipelineGuardrails.maxRps <= 0.1);

  const reason = requiresHumanApproval
    ? `Step "${step.id}" (${step.tool}) requires operator approval: ${
        step.tool === "hydra" || step.tool === "medusa" || step.tool === "netexec"
          ? "credential testing tool"
          : step.inputs.activeScanning
          ? "active scanning in strict mode"
          : "rate exceeds strict threshold"
      }`
    : undefined;

  return {
    approved: validation.valid && !requiresHumanApproval,
    violations: validation.violations,
    requiresHumanApproval,
    reason,
  };
}

/**
 * Get the current workflow state for a pipeline.
 */
export function getWorkflowState(pipeline: Pipeline): WorkflowState {
  const currentStepIndex = pipeline.steps.findIndex(s => s.status === "running" || s.status === "pending");
  const evidenceCount = pipeline.steps.reduce((sum, s) => sum + s.evidenceEvents.length, 0);

  const allViolations = pipeline.steps.flatMap(s => {
    const v = validateStepExecution(s, pipeline.guardrails);
    return v.violations;
  });

  const pendingApproval = pipeline.steps.some(s => {
    const v = validateStepExecution(s, pipeline.guardrails);
    return v.requiresHumanApproval && s.status === "pending";
  });

  return {
    pipelineId: pipeline.id,
    currentStepIndex: currentStepIndex >= 0 ? currentStepIndex : pipeline.steps.length,
    totalSteps: pipeline.steps.length,
    status: pipeline.status,
    startedAt: pipeline.startedAt || pipeline.createdAt,
    lastUpdated: Date.now(),
    evidenceCount,
    findingCount: pipeline.findings.length,
    guardrailViolations: allViolations,
    humanApprovalRequired: pendingApproval,
    humanApprovalReason: pendingApproval
      ? pipeline.steps.find(s => {
          const v = validateStepExecution(s, pipeline.guardrails);
          return v.requiresHumanApproval && s.status === "pending";
        })?.description
      : undefined,
  };
}

/**
 * Advance a pipeline to the next step (simulated execution).
 * In production, this would invoke actual tool adapters.
 */
export function advancePipeline(
  pipeline: Pipeline,
  stepResults?: { outputs: Record<string, any>; evidenceEvents?: AuthEvidenceEvent[]; findings?: AuthFinding[] }
): Pipeline {
  const updated = { ...pipeline, steps: [...pipeline.steps] };

  // Find current running step and complete it
  const runningIdx = updated.steps.findIndex(s => s.status === "running");
  if (runningIdx >= 0 && stepResults) {
    updated.steps[runningIdx] = {
      ...updated.steps[runningIdx],
      status: "completed",
      completedAt: Date.now(),
      outputs: stepResults.outputs,
      evidenceEvents: stepResults.evidenceEvents || [],
    };
    if (stepResults.findings) {
      updated.findings = [...updated.findings, ...stepResults.findings];
    }
  }

  // Start next pending step
  const nextIdx = updated.steps.findIndex(s => s.status === "pending");
  if (nextIdx >= 0) {
    const validation = validateStepExecution(updated.steps[nextIdx], updated.guardrails);
    if (validation.requiresHumanApproval) {
      updated.status = "paused";
    } else if (validation.approved) {
      updated.steps[nextIdx] = {
        ...updated.steps[nextIdx],
        status: "running",
        startedAt: Date.now(),
      };
      updated.status = "running";
      if (!updated.startedAt) updated.startedAt = Date.now();
    } else {
      updated.steps[nextIdx] = {
        ...updated.steps[nextIdx],
        status: "blocked",
        error: validation.violations.join("; "),
      };
    }
  } else if (runningIdx < 0) {
    // All steps complete
    updated.status = "completed";
    updated.completedAt = Date.now();
  }

  return updated;
}

/**
 * Approve a human-in-the-loop gate and continue pipeline execution.
 */
export function approveAndContinue(pipeline: Pipeline, stepId: string, approverNote: string): Pipeline {
  const updated = { ...pipeline, steps: [...pipeline.steps] };
  const stepIdx = updated.steps.findIndex(s => s.id === stepId);

  if (stepIdx >= 0 && updated.steps[stepIdx].status === "pending") {
    updated.steps[stepIdx] = {
      ...updated.steps[stepIdx],
      status: "running",
      startedAt: Date.now(),
      inputs: {
        ...updated.steps[stepIdx].inputs,
        _humanApproval: { approved: true, note: approverNote, timestamp: Date.now() },
      },
    };
    updated.status = "running";
    if (!updated.startedAt) updated.startedAt = Date.now();
  }

  return updated;
}

// ─── LLM Reasoner Interface ────────────────────────────────────────────────

export interface ReasonerInput {
  pipeline: Pipeline;
  evidenceEvents: AuthEvidenceEvent[];
  currentPhase: string;
  targetInfo: { url: string; authType?: string; ssoProvider?: string };
}

export interface ReasonerOutput {
  hypotheses: Array<{
    finding: string;
    confidence: "high" | "medium" | "low";
    evidence: string[];
    nextStep: string;
    opsecRisk: "low" | "medium" | "high";
  }>;
  recommendedNextPipeline?: string;
  summary: string;
}

/**
 * Build the LLM prompt for auth reasoning based on pipeline evidence.
 * This generates the context that gets sent to the LLM for analysis.
 */
export function buildReasonerPrompt(input: ReasonerInput): string {
  const sections: string[] = [];

  sections.push(AUTH_REASONING_SYSTEM_PROMPT);

  sections.push(`\n## Current Engagement Context`);
  sections.push(`Target: ${input.targetInfo.url}`);
  sections.push(`Auth Type: ${input.targetInfo.authType || "Unknown — classify from evidence"}`);
  sections.push(`SSO Provider: ${input.targetInfo.ssoProvider || "Not identified"}`);
  sections.push(`Current Phase: ${input.currentPhase}`);
  sections.push(`Pipeline: ${input.pipeline.name} (${input.pipeline.mode} mode)`);

  // Include completed step outputs
  const completedSteps = input.pipeline.steps.filter(s => s.status === "completed");
  if (completedSteps.length > 0) {
    sections.push(`\n## Completed Steps`);
    for (const step of completedSteps) {
      sections.push(`### ${step.id} (${step.tool})`);
      sections.push(`Outputs: ${JSON.stringify(step.outputs, null, 2)}`);
      if (step.evidenceEvents.length > 0) {
        sections.push(`Evidence events: ${step.evidenceEvents.length}`);
      }
    }
  }

  // Include evidence summary
  if (input.evidenceEvents.length > 0) {
    sections.push(`\n## Evidence Summary (${input.evidenceEvents.length} events)`);
    const bySeverity = input.evidenceEvents.reduce((acc, e) => {
      const sev = e.severity || "info";
      acc[sev] = (acc[sev] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    sections.push(`Severity breakdown: ${JSON.stringify(bySeverity)}`);
  }

  // Include findings so far
  if (input.pipeline.findings.length > 0) {
    sections.push(`\n## Findings So Far (${input.pipeline.findings.length})`);
    for (const f of input.pipeline.findings) {
      sections.push(`- [${f.severity.toUpperCase()}] ${f.title}: ${f.summary}`);
    }
  }

  sections.push(`\n## Task`);
  sections.push(`Based on the evidence above, generate hypotheses about authentication vulnerabilities, recommend the next safe step, and produce findings with MITRE ATT&CK mappings and CARVER scores.`);

  return sections.join("\n");
}

// ─── Deterministic Reasoner (No LLM Fallback) ──────────────────────────────

/**
 * Deterministic analysis of pipeline evidence without LLM.
 * Applies rule-based detection for common auth vulnerabilities.
 */
export function deterministicAnalysis(pipeline: Pipeline): ReasonerOutput {
  const hypotheses: ReasonerOutput["hypotheses"] = [];
  const completedSteps = pipeline.steps.filter(s => s.status === "completed");

  for (const step of completedSteps) {
    const outputs = step.outputs;

    // Cookie flag analysis
    if (outputs.cookie_findings) {
      const cookies = outputs.cookie_findings;
      if (Array.isArray(cookies)) {
        for (const cookie of cookies) {
          if (cookie.missingSecure) {
            hypotheses.push({
              finding: "Missing Secure flag on authentication cookie",
              confidence: "high",
              evidence: [`Cookie: ${cookie.name}`, `Step: ${step.id}`],
              nextStep: "Verify cookie is transmitted over HTTPS only",
              opsecRisk: "low",
            });
          }
          if (cookie.missingHttpOnly) {
            hypotheses.push({
              finding: "Missing HttpOnly flag — cookie accessible via JavaScript",
              confidence: "high",
              evidence: [`Cookie: ${cookie.name}`, `Step: ${step.id}`],
              nextStep: "Check for XSS vectors that could steal this cookie",
              opsecRisk: "low",
            });
          }
        }
      }
    }

    // Enumeration signal analysis
    if (outputs.deltas) {
      const d = outputs.deltas;
      if (d.length_difference && d.length_difference > 50) {
        hypotheses.push({
          finding: `Username enumeration via response length (${d.length_difference} byte delta)`,
          confidence: d.length_difference > 100 ? "high" : "medium",
          evidence: [`Length delta: ${d.length_difference}`, `Step: ${step.id}`],
          nextStep: "Confirm with additional controlled probes",
          opsecRisk: "low",
        });
      }
      if (d.timing_difference_ms && d.timing_difference_ms > 100) {
        hypotheses.push({
          finding: `Username enumeration via timing side-channel (${d.timing_difference_ms}ms delta)`,
          confidence: d.timing_difference_ms > 200 ? "high" : "medium",
          evidence: [`Timing delta: ${d.timing_difference_ms}ms`, `Step: ${step.id}`],
          nextStep: "Confirm with statistical analysis (multiple samples)",
          opsecRisk: "low",
        });
      }
    }

    // JWT analysis
    if (outputs.jwt_findings) {
      const jwt = outputs.jwt_findings;
      if (jwt.algorithmNone) {
        hypotheses.push({
          finding: "JWT accepts 'none' algorithm — critical authentication bypass",
          confidence: "high",
          evidence: [`Algorithm: none accepted`, `Step: ${step.id}`],
          nextStep: "Craft unsigned JWT and test access",
          opsecRisk: "medium",
        });
      }
      if (jwt.weakSecret) {
        hypotheses.push({
          finding: "JWT signed with weak/guessable secret",
          confidence: "high",
          evidence: [`Secret cracked`, `Step: ${step.id}`],
          nextStep: "Forge JWT with discovered secret",
          opsecRisk: "medium",
        });
      }
    }

    // TLS analysis
    if (outputs.tls_findings) {
      const tls = outputs.tls_findings;
      if (tls.weakCiphers && tls.weakCiphers.length > 0) {
        hypotheses.push({
          finding: `Weak TLS ciphers detected: ${tls.weakCiphers.join(", ")}`,
          confidence: "high",
          evidence: [`Weak ciphers: ${tls.weakCiphers.length}`, `Step: ${step.id}`],
          nextStep: "Document for compliance report (SC-12, SC-23)",
          opsecRisk: "low",
        });
      }
    }
  }

  // Recommend next pipeline based on what's been done
  const completedCategories = new Set(
    PIPELINE_TEMPLATES
      .filter(t => completedSteps.some(s => t.steps.some(ts => ts.id === s.id)))
      .map(t => t.category)
  );

  let recommendedNextPipeline: string | undefined;
  if (!completedCategories.has("reconnaissance")) {
    recommendedNextPipeline = "auth-recon-flow-capture";
  } else if (!completedCategories.has("enumeration")) {
    recommendedNextPipeline = "enumeration-signals-safe";
  } else if (!completedCategories.has("session_analysis")) {
    recommendedNextPipeline = "session-token-checks";
  }

  return {
    hypotheses,
    recommendedNextPipeline,
    summary: `Deterministic analysis of ${completedSteps.length} completed steps produced ${hypotheses.length} hypotheses. ${recommendedNextPipeline ? `Recommended next: ${recommendedNextPipeline}` : "All standard pipelines completed."}`,
  };
}
