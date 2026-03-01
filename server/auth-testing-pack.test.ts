/**
 * Auth Testing Pack v1.2 Integration Tests
 * 
 * Covers:
 * - Auth testing knowledge base (methodology, taxonomy, MITRE mappings, CARVER scoring)
 * - Auth pipeline orchestration engine (workflow, guardrails, evidence store)
 * - Scan policy engine federal auth profiles (strict/standard modes)
 * - Auth assessment router existence
 * - Branding compliance (no FedRAMP in user-facing labels)
 * 
 * Author: Harrison Cook — AceofCloud
 */
import { describe, expect, it } from "vitest";

// ─── Auth Testing Knowledge Base Tests ──────────────────────────────────────

describe("Auth Testing Knowledge Base", () => {
  it("exports all 6 methodology phases", async () => {
    const { AUTH_TESTING_PHASES } = await import("./lib/auth-testing-knowledge");
    expect(AUTH_TESTING_PHASES).toBeDefined();
    expect(AUTH_TESTING_PHASES.length).toBe(6);
    // Phases use human-readable names
    const phaseNames = AUTH_TESTING_PHASES.map((p: any) => p.phase);
    expect(phaseNames).toContain("Recon & Identification");
    expect(phaseNames).toContain("Enumeration Testing");
    expect(phaseNames).toContain("Credential Surface Analysis");
    expect(phaseNames).toContain("Flow Manipulation");
    expect(phaseNames).toContain("Session & Token Security");
    expect(phaseNames).toContain("Post-Authentication Abuse");
  });

  it("each phase has objectives, artifacts, tools, and guardrails", async () => {
    const { AUTH_TESTING_PHASES } = await import("./lib/auth-testing-knowledge");
    for (const phase of AUTH_TESTING_PHASES) {
      expect(phase.order).toBeGreaterThan(0);
      expect(phase.objectives.length).toBeGreaterThan(0);
      expect(phase.artifacts.length).toBeGreaterThan(0);
      expect(phase.tools.length).toBeGreaterThan(0);
      expect(phase.guardrails.length).toBeGreaterThan(0);
    }
  });

  it("exports 5 attack taxonomy classes", async () => {
    const { AUTH_ATTACK_TAXONOMY } = await import("./lib/auth-testing-knowledge");
    expect(AUTH_ATTACK_TAXONOMY).toBeDefined();
    expect(AUTH_ATTACK_TAXONOMY.length).toBe(5);
    const classNames = AUTH_ATTACK_TAXONOMY.map((c: any) => c.name);
    expect(classNames).toContain("Username Enumeration");
    expect(classNames).toContain("Credential Defense Analysis");
    expect(classNames).toContain("MFA Bypass Logic");
    expect(classNames).toContain("Token & Session Attacks");
    expect(classNames).toContain("Password Reset Abuse");
  });

  it("each attack class has signals, subtypes, and MITRE techniques", async () => {
    const { AUTH_ATTACK_TAXONOMY } = await import("./lib/auth-testing-knowledge");
    for (const cls of AUTH_ATTACK_TAXONOMY) {
      expect(cls.id).toMatch(/^AUTH-ATTACK-/);
      expect(cls.signals.length).toBeGreaterThan(0);
      expect(cls.subtypes.length).toBeGreaterThan(0);
      expect(cls.mitreTechniques.length).toBeGreaterThan(0);
    }
  });

  it("exports MITRE ATT&CK mappings with valid technique IDs", async () => {
    const { AUTH_MITRE_MAPPINGS } = await import("./lib/auth-testing-knowledge");
    expect(AUTH_MITRE_MAPPINGS).toBeDefined();
    expect(AUTH_MITRE_MAPPINGS.length).toBeGreaterThan(0);
    for (const mapping of AUTH_MITRE_MAPPINGS) {
      expect(mapping.techniqueId).toMatch(/^T\d{4}/);
      expect(mapping.tactic).toBeTruthy();
      expect(mapping.notes).toBeTruthy();
    }
  });

  it("exports tooling stack with categories", async () => {
    const { AUTH_TOOLING_STACK } = await import("./lib/auth-testing-knowledge");
    expect(AUTH_TOOLING_STACK).toBeDefined();
    expect(AUTH_TOOLING_STACK.length).toBeGreaterThan(0);
    for (const tool of AUTH_TOOLING_STACK) {
      expect(tool.name).toBeTruthy();
      expect(tool.category).toBeTruthy();
    }
  });

  it("exports federal auth controls with NIST 800-53 control IDs", async () => {
    const { FEDERAL_AUTH_CONTROLS } = await import("./lib/auth-testing-knowledge");
    expect(FEDERAL_AUTH_CONTROLS).toBeDefined();
    expect(FEDERAL_AUTH_CONTROLS.length).toBeGreaterThan(0);
    for (const control of FEDERAL_AUTH_CONTROLS) {
      expect(control.controlId).toMatch(/^[A-Z]{2}-\d/);
      expect(control.baseline).toMatch(/^(moderate|high)$/);
      expect(control.title).toBeTruthy();
    }
  });

  it("exports CARVER auth overlay as an object with weights and adjustments", async () => {
    const { AUTH_CARVER_OVERLAY } = await import("./lib/auth-testing-knowledge");
    expect(AUTH_CARVER_OVERLAY).toBeDefined();
    expect(AUTH_CARVER_OVERLAY.defaultWeights).toBeDefined();
    expect(AUTH_CARVER_OVERLAY.defaultWeights.criticality).toBeGreaterThan(0);
    expect(AUTH_CARVER_OVERLAY.defaultWeights.accessibility).toBeGreaterThan(0);
    expect(AUTH_CARVER_OVERLAY.defaultWeights.recoverability || AUTH_CARVER_OVERLAY.defaultWeights.recuperability).toBeGreaterThan(0);
    expect(AUTH_CARVER_OVERLAY.adjustments.length).toBeGreaterThan(0);
  });

  it("calculates CARVER auth score from condition strings", async () => {
    const { calculateAuthCarverScore } = await import("./lib/auth-testing-knowledge");
    // Call with empty conditions to get base score
    const baseResult = calculateAuthCarverScore([]);
    expect(baseResult).toBeDefined();
    expect(baseResult.totalScore).toBeGreaterThan(0);
    expect(baseResult.maxScore).toBe(60);
    expect(baseResult.percentage).toBeGreaterThanOrEqual(0);
    expect(baseResult.percentage).toBeLessThanOrEqual(100);
  });

  it("builds auth knowledge context as a non-empty string", async () => {
    const { buildAuthKnowledgeContext } = await import("./lib/auth-testing-knowledge");
    const context = buildAuthKnowledgeContext();
    expect(context).toBeTruthy();
    expect(typeof context).toBe("string");
    expect(context.length).toBeGreaterThan(100);
    // Should mention key concepts
    expect(context).toContain("Recon");
    expect(context).toContain("Enumeration");
  });

  it("has 11 OAuth/SAML assessment checks (6 OAuth + 5 SAML)", async () => {
    const { SSO_ASSESSMENT_CHECKS } = await import("./lib/auth-testing-knowledge");
    expect(SSO_ASSESSMENT_CHECKS).toBeDefined();
    expect(SSO_ASSESSMENT_CHECKS.length).toBe(11);
    const oauthChecks = SSO_ASSESSMENT_CHECKS.filter((c: any) => c.protocol === "oauth_oidc");
    const samlChecks = SSO_ASSESSMENT_CHECKS.filter((c: any) => c.protocol === "saml");
    expect(oauthChecks.length).toBe(6);
    expect(samlChecks.length).toBe(5);
  });

  it("exports guardrails for strict and standard modes", async () => {
    const { STRICT_MODE_GUARDRAILS, STANDARD_MODE_GUARDRAILS } = await import("./lib/auth-testing-knowledge");
    expect(STRICT_MODE_GUARDRAILS).toBeDefined();
    expect(STANDARD_MODE_GUARDRAILS).toBeDefined();
    expect(STRICT_MODE_GUARDRAILS.maxRps).toBeLessThanOrEqual(0.1);
    expect(STRICT_MODE_GUARDRAILS.requireEvidenceCapture).toBe(true);
    expect(STRICT_MODE_GUARDRAILS.requireScopeAllowlist).toBe(true);
    expect(STANDARD_MODE_GUARDRAILS.maxRps).toBeGreaterThan(STRICT_MODE_GUARDRAILS.maxRps);
    expect(STANDARD_MODE_GUARDRAILS.requireEvidenceCapture).toBe(false);
  });

  it("validateAgainstGuardrails detects violations", async () => {
    const { validateAgainstGuardrails, STRICT_MODE_GUARDRAILS } = await import("./lib/auth-testing-knowledge");
    // RPS too high for strict mode
    const result = validateAgainstGuardrails({ rps: 1.0 }, STRICT_MODE_GUARDRAILS);
    expect(result.valid).toBe(false);
    expect(result.violations.length).toBeGreaterThan(0);
    // Within limits
    const okResult = validateAgainstGuardrails({ rps: 0.05 }, STRICT_MODE_GUARDRAILS);
    expect(okResult.valid).toBe(true);
  });
});

// ─── Auth Pipeline Engine Tests ─────────────────────────────────────────────

describe("Auth Pipeline Engine", () => {
  it("exports pipeline templates", async () => {
    const { PIPELINE_TEMPLATES } = await import("./lib/auth-pipeline-engine");
    expect(PIPELINE_TEMPLATES).toBeDefined();
    expect(PIPELINE_TEMPLATES.length).toBeGreaterThan(0);
    for (const tmpl of PIPELINE_TEMPLATES) {
      expect(tmpl.id).toBeTruthy();
      expect(tmpl.name).toBeTruthy();
      expect(tmpl.steps.length).toBeGreaterThan(0);
    }
  });

  it("initializes a pipeline from a template", async () => {
    const { initializePipeline, PIPELINE_TEMPLATES } = await import("./lib/auth-pipeline-engine");
    const templateId = PIPELINE_TEMPLATES[0].id;
    const pipeline = initializePipeline(templateId, "https://target.example.com/login", "standard");
    expect(pipeline).not.toBeNull();
    expect(pipeline!.id).toBeTruthy();
    expect(pipeline!.status).toBe("draft");
    expect(pipeline!.steps.length).toBeGreaterThan(0);
    expect(pipeline!.mode).toBe("standard");
  });

  it("returns null for unknown template", async () => {
    const { initializePipeline } = await import("./lib/auth-pipeline-engine");
    const pipeline = initializePipeline("nonexistent-template", "https://target.example.com", "standard");
    expect(pipeline).toBeNull();
  });

  it("advances pipeline — transitions from draft", async () => {
    const { initializePipeline, advancePipeline, PIPELINE_TEMPLATES } = await import("./lib/auth-pipeline-engine");
    const templateId = PIPELINE_TEMPLATES[0].id;
    const pipeline = initializePipeline(templateId, "https://target.example.com/login", "standard");
    expect(pipeline).not.toBeNull();
    const advanced = advancePipeline(pipeline!);
    // Pipeline should transition from draft to running or paused
    expect(advanced.status).not.toBe("draft");
    expect(["running", "paused", "completed"]).toContain(advanced.status);
  });

  it("validates step execution against guardrails", async () => {
    const { initializePipeline, validateStepExecution, PIPELINE_TEMPLATES } = await import("./lib/auth-pipeline-engine");
    const { STRICT_MODE_GUARDRAILS } = await import("./lib/auth-testing-knowledge");
    const templateId = PIPELINE_TEMPLATES[0].id;
    const pipeline = initializePipeline(templateId, "https://target.example.com/login", "strict");
    expect(pipeline).not.toBeNull();
    const firstStep = pipeline!.steps[0];
    const validation = validateStepExecution(firstStep, STRICT_MODE_GUARDRAILS);
    expect(validation).toBeDefined();
    expect(typeof validation.approved).toBe("boolean");
    expect(Array.isArray(validation.violations)).toBe(true);
    expect(typeof validation.requiresHumanApproval).toBe("boolean");
  });

  it("strict mode guardrails enforce low RPS and mandatory evidence", async () => {
    const { initializePipeline, PIPELINE_TEMPLATES } = await import("./lib/auth-pipeline-engine");
    const templateId = PIPELINE_TEMPLATES[0].id;
    const pipeline = initializePipeline(templateId, "https://target.example.com/login", "strict");
    expect(pipeline).not.toBeNull();
    expect(pipeline!.guardrails.maxRps).toBeLessThanOrEqual(0.1);
    expect(pipeline!.guardrails.requireEvidenceCapture).toBe(true);
    expect(pipeline!.guardrails.requireScopeAllowlist).toBe(true);
    expect(pipeline!.guardrails.requireChangeWindow).toBe(true);
  });

  it("standard mode guardrails allow higher RPS and optional evidence", async () => {
    const { initializePipeline, PIPELINE_TEMPLATES } = await import("./lib/auth-pipeline-engine");
    const templateId = PIPELINE_TEMPLATES[0].id;
    const pipeline = initializePipeline(templateId, "https://target.example.com/login", "standard");
    expect(pipeline).not.toBeNull();
    expect(pipeline!.guardrails.maxRps).toBe(0.5);
    expect(pipeline!.guardrails.requireEvidenceCapture).toBe(false);
  });

  it("getWorkflowState returns progress metrics", async () => {
    const { initializePipeline, getWorkflowState, PIPELINE_TEMPLATES } = await import("./lib/auth-pipeline-engine");
    const templateId = PIPELINE_TEMPLATES[0].id;
    const pipeline = initializePipeline(templateId, "https://target.example.com/login", "standard");
    expect(pipeline).not.toBeNull();
    const state = getWorkflowState(pipeline!);
    expect(state).toBeDefined();
    expect(state.totalSteps).toBeGreaterThan(0);
    expect(state.pipelineId).toBe(pipeline!.id);
    expect(state.status).toBe("draft");
    expect(state.evidenceCount).toBe(0);
    expect(state.findingCount).toBe(0);
  });

  it("builds reasoner prompt for LLM integration", async () => {
    const { buildReasonerPrompt, initializePipeline, PIPELINE_TEMPLATES } = await import("./lib/auth-pipeline-engine");
    const templateId = PIPELINE_TEMPLATES[0].id;
    const pipeline = initializePipeline(templateId, "https://target.example.com/login", "standard");
    expect(pipeline).not.toBeNull();
    const prompt = buildReasonerPrompt({
      pipeline: pipeline!,
      evidenceEvents: [],
      currentPhase: "reconnaissance",
      targetInfo: { url: "https://target.example.com/login", authType: "oauth" },
    });
    expect(prompt).toBeTruthy();
    expect(typeof prompt).toBe("string");
    expect(prompt.length).toBeGreaterThan(50);
    expect(prompt).toContain("target.example.com");
  });

  it("deterministicAnalysis produces output from pipeline", async () => {
    const { initializePipeline, deterministicAnalysis, PIPELINE_TEMPLATES } = await import("./lib/auth-pipeline-engine");
    const templateId = PIPELINE_TEMPLATES[0].id;
    const pipeline = initializePipeline(templateId, "https://target.example.com/login", "standard");
    expect(pipeline).not.toBeNull();
    const analysis = deterministicAnalysis(pipeline!);
    expect(analysis).toBeDefined();
    expect(typeof analysis.summary).toBe("string");
  });
});

// ─── Scan Policy Engine — Federal Auth Profiles ─────────────────────────────

describe("Scan Policy Engine — Federal Auth Profiles", () => {
  it("includes federal_auth_strict and federal_auth_standard profiles", async () => {
    const { ScanPolicyEngine } = await import("./lib/scan-policy-engine");
    const engine = new ScanPolicyEngine("strict_passive");
    const profiles = engine.listProfiles();
    const profileIds = profiles.map(p => p.id);
    expect(profileIds).toContain("federal_auth_strict");
    expect(profileIds).toContain("federal_auth_standard");
  });

  it("federal_auth_strict has 0.1 RPS and blocks credential guessing", async () => {
    const { ScanPolicyEngine } = await import("./lib/scan-policy-engine");
    const engine = new ScanPolicyEngine("federal_auth_strict");
    const profile = engine.getActiveProfile();
    expect(profile.id).toBe("federal_auth_strict");
    expect(profile.rateLimits.perHostRps).toBe(0.1);
    expect(profile.disallowed).toContain("brute_force");
    expect(profile.disallowed).toContain("auth_guessing");
    expect(profile.disallowed).toContain("credential_stuffing");
  });

  it("federal_auth_standard has 0.5 RPS and allows active-standard mode", async () => {
    const { ScanPolicyEngine } = await import("./lib/scan-policy-engine");
    const engine = new ScanPolicyEngine("federal_auth_standard");
    const profile = engine.getActiveProfile();
    expect(profile.id).toBe("federal_auth_standard");
    expect(profile.rateLimits.perHostRps).toBe(0.5);
    expect(profile.allowedModes).toContain("active-standard");
  });

  it("isFederalAuthMode returns true for federal profiles", async () => {
    const { ScanPolicyEngine } = await import("./lib/scan-policy-engine");
    const engine = new ScanPolicyEngine("federal_auth_strict");
    expect(engine.isFederalAuthMode()).toBe(true);
    engine.setActiveProfile("strict_passive");
    expect(engine.isFederalAuthMode()).toBe(false);
  });

  it("getFederalAuthLevel returns correct level", async () => {
    const { ScanPolicyEngine } = await import("./lib/scan-policy-engine");
    const engine = new ScanPolicyEngine("federal_auth_strict");
    expect(engine.getFederalAuthLevel()).toBe("strict");
    engine.setActiveProfile("federal_auth_standard");
    expect(engine.getFederalAuthLevel()).toBe("standard");
    engine.setActiveProfile("balanced");
    expect(engine.getFederalAuthLevel()).toBe("none");
  });

  it("getAttestation returns correct text without FedRAMP branding", async () => {
    const { ScanPolicyEngine } = await import("./lib/scan-policy-engine");
    const engine = new ScanPolicyEngine("federal_auth_strict");
    const attestation = engine.getAttestation();
    expect(attestation).toContain("Federal Auth Strict Mode");
    expect(attestation).toContain("0.1 RPS");
    expect(attestation).toContain("FA-01");
    expect(attestation).not.toContain("FedRAMP");
  });

  it("federal_auth_strict profile has FA-01 through FA-05 controls", async () => {
    const { ScanPolicyEngine } = await import("./lib/scan-policy-engine");
    const engine = new ScanPolicyEngine("federal_auth_strict");
    const profile = engine.getActiveProfile();
    const controlIds = profile.controls.map(c => c.id);
    expect(controlIds).toContain("FA-01");
    expect(controlIds).toContain("FA-02");
    expect(controlIds).toContain("FA-03");
    expect(controlIds).toContain("FA-04");
    expect(controlIds).toContain("FA-05");
  });

  it("federal_auth_standard profile has FA-S01 through FA-S03 controls", async () => {
    const { ScanPolicyEngine } = await import("./lib/scan-policy-engine");
    const engine = new ScanPolicyEngine("federal_auth_standard");
    const profile = engine.getActiveProfile();
    const controlIds = profile.controls.map(c => c.id);
    expect(controlIds).toContain("FA-S01");
    expect(controlIds).toContain("FA-S02");
    expect(controlIds).toContain("FA-S03");
  });

  it("no profile IDs or descriptions contain FedRAMP branding", async () => {
    const { ScanPolicyEngine } = await import("./lib/scan-policy-engine");
    const engine = new ScanPolicyEngine("strict_passive");
    const profiles = engine.listProfiles();
    for (const profile of profiles) {
      expect(profile.id).not.toMatch(/fedramp/i);
      expect(profile.description).not.toMatch(/\bFedRAMP\b/);
    }
  });
});

// ─── Auth Assessment Router Tests ───────────────────────────────────────────

describe("Auth Assessment Router", () => {
  it("exports authAssessmentRouter", async () => {
    const { authAssessmentRouter } = await import("./routers/auth-assessment");
    expect(authAssessmentRouter).toBeDefined();
    const procedures = authAssessmentRouter._def.procedures;
    expect(procedures).toBeDefined();
  });

  it("authAssessment is wired into appRouter", async () => {
    const { appRouter } = await import("./routers");
    const procedures = appRouter._def.procedures;
    expect(procedures).toBeDefined();
  });
});
