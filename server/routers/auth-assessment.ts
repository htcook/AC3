/**
 * OAuth/SAML Assessment Router — Auth Pack v1.2 Integration
 *
 * Provides tRPC procedures for assessing target SSO implementations:
 * - 6 OAuth/OIDC checks (redirect URI, state, PKCE, nonce, audience/issuer, refresh tokens)
 * - 5 SAML checks (signature, InResponseTo, audience, recipient/destination, clock skew)
 * - Auth pipeline orchestration (create, advance, approve, analyze)
 * - Federal compliance strict/standard mode enforcement
 * - CARVER auth scoring overlay
 *
 * This is OFFENSIVE testing of TARGET SSO portals — distinct from the platform's
 * own SAML authentication (saml-auth.ts).
 */

import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import {
  SSO_ASSESSMENT_CHECKS,
  AUTH_TESTING_PHASES,
  AUTH_ATTACK_TAXONOMY,
  AUTH_MITRE_MAPPINGS,
  AUTH_TOOLING_STACK,
  FEDERAL_AUTH_CONTROLS,
  AUTH_CARVER_OVERLAY,
  calculateAuthCarverScore,
  buildAuthKnowledgeContext,
  type AuthFinding,
  type AuthEvidenceEvent,
  type SSOCheck,
} from "../lib/auth-testing-knowledge";
import {
  PIPELINE_TEMPLATES,
  initializePipeline,
  validateStepExecution,
  getWorkflowState,
  advancePipeline,
  approveAndContinue,
  deterministicAnalysis,
  buildReasonerPrompt,
  type Pipeline,
} from "../lib/auth-pipeline-engine";

// ─── In-memory pipeline store (per-session) ─────────────────────────────────
const activePipelines = new Map<string, Pipeline>();

export const authAssessmentRouter = router({
  // ─── Knowledge Base Queries ─────────────────────────────────────────────

  /** Get all auth testing phases */
  getTestingPhases: protectedProcedure.query(() => {
    return AUTH_TESTING_PHASES;
  }),

  /** Get all auth attack classes */
  getAttackTaxonomy: protectedProcedure.query(() => {
    return AUTH_ATTACK_TAXONOMY;
  }),

  /** Get all SSO assessment checks */
  getSSOChecks: protectedProcedure
    .input(z.object({
      protocol: z.enum(["oauth_oidc", "saml", "all"]).optional(),
    }).optional())
    .query(({ input }) => {
      const protocol = input?.protocol || "all";
      if (protocol === "all") return SSO_ASSESSMENT_CHECKS;
      return SSO_ASSESSMENT_CHECKS.filter(c => c.protocol === protocol);
    }),

  /** Get auth-specific MITRE mappings */
  getMitreMappings: protectedProcedure.query(() => {
    return AUTH_MITRE_MAPPINGS;
  }),

  /** Get auth tooling stack */
  getToolingStack: protectedProcedure.query(() => {
    return AUTH_TOOLING_STACK;
  }),

  /** Get federal compliance auth controls (mapped to NIST 800-53 baselines) */
  getFederalAuthControls: protectedProcedure
    .input(z.object({
      baseline: z.enum(["moderate", "high", "all"]).optional(),
    }).optional())
    .query(({ input }) => {
      const baseline = input?.baseline || "all";
      if (baseline === "all") return FEDERAL_AUTH_CONTROLS;
      return FEDERAL_AUTH_CONTROLS.filter(c => c.baseline === baseline);
    }),

  /** Get auth knowledge context for LLM injection */
  getKnowledgeContext: protectedProcedure.query(() => {
    return buildAuthKnowledgeContext();
  }),

  // ─── SSO Assessment Execution ───────────────────────────────────────────

  /** Run a specific SSO check (deterministic) */
  runSSOCheck: protectedProcedure
    .input(z.object({
      checkId: z.string(),
      targetUrl: z.string(),
      evidence: z.record(z.any()).optional(),
      operatorNotes: z.string().optional(),
    }))
    .mutation(({ input }) => {
      const check = SSO_ASSESSMENT_CHECKS.find(c => c.id === input.checkId);
      if (!check) {
        return { success: false, error: "Check not found" };
      }

      // Build assessment result
      const result: {
        check: SSOCheck;
        target: string;
        status: "pass" | "fail" | "partial" | "not_tested";
        findings: string[];
        evidenceCollected: string[];
        complianceImpact: string[];
        timestamp: number;
      } = {
        check,
        target: input.targetUrl,
        status: "not_tested",
        findings: [],
        evidenceCollected: [],
        complianceImpact: check.fedrampControls,
        timestamp: Date.now(),
      };

      // If evidence provided, run deterministic analysis
      if (input.evidence) {
        const evidence = input.evidence;

        // Redirect URI check
        if (check.id === "SSO-OAUTH-001" && evidence.redirectUri) {
          const uri = evidence.redirectUri as string;
          if (uri.includes("*") || uri.includes("..")) {
            result.status = "fail";
            result.findings.push("Wildcard or path traversal pattern detected in redirect URI");
          } else if (evidence.openRedirectTested && evidence.openRedirectBlocked) {
            result.status = "pass";
            result.findings.push("Redirect URI validation enforces exact match");
          } else {
            result.status = "partial";
            result.findings.push("Redirect URI validation present but needs further testing");
          }
          result.evidenceCollected.push(`Redirect URI: ${uri}`);
        }

        // State parameter check
        if (check.id === "SSO-OAUTH-002" && evidence.stateParam !== undefined) {
          if (!evidence.stateParam) {
            result.status = "fail";
            result.findings.push("State parameter missing from authorization request — CSRF risk");
          } else if (evidence.stateBoundToSession) {
            result.status = "pass";
            result.findings.push("State parameter present and bound to session");
          } else {
            result.status = "partial";
            result.findings.push("State parameter present but session binding not confirmed");
          }
        }

        // PKCE check
        if (check.id === "SSO-OAUTH-003" && evidence.pkce !== undefined) {
          if (!evidence.pkce) {
            result.status = "fail";
            result.findings.push("PKCE not enforced for public client");
          } else if (evidence.pkceMethod === "S256") {
            result.status = "pass";
            result.findings.push("PKCE enforced with S256 method");
          } else {
            result.status = "partial";
            result.findings.push("PKCE present but using plain method instead of S256");
          }
        }

        // SAML signature check
        if (check.id === "SSO-SAML-001" && evidence.signaturePresent !== undefined) {
          if (!evidence.signaturePresent) {
            result.status = "fail";
            result.findings.push("SAML assertion not signed — critical vulnerability");
          } else if (evidence.signatureValid && evidence.certChainValid) {
            result.status = "pass";
            result.findings.push("SAML signature valid with trusted certificate chain");
          } else {
            result.status = "partial";
            result.findings.push("Signature present but validation issues detected");
          }
        }

        // Generic evidence handling for other checks
        if (result.status === "not_tested" && Object.keys(evidence).length > 0) {
          result.status = "partial";
          result.findings.push("Evidence collected — manual review required");
          result.evidenceCollected.push(...Object.keys(evidence).map(k => `${k}: ${JSON.stringify(evidence[k])}`));
        }
      }

      if (input.operatorNotes) {
        result.evidenceCollected.push(`Operator notes: ${input.operatorNotes}`);
      }

      return { success: true, result };
    }),

  /** Run all SSO checks for a protocol (batch assessment) */
  runBatchAssessment: protectedProcedure
    .input(z.object({
      protocol: z.enum(["oauth_oidc", "saml"]),
      targetUrl: z.string(),
      checkResults: z.array(z.object({
        checkId: z.string(),
        status: z.enum(["pass", "fail", "partial", "not_tested"]),
        notes: z.string().optional(),
        evidence: z.record(z.any()).optional(),
      })),
    }))
    .mutation(({ input }) => {
      const checks = SSO_ASSESSMENT_CHECKS.filter(c => c.protocol === input.protocol);
      const results = checks.map(check => {
        const userResult = input.checkResults.find(r => r.checkId === check.id);
        return {
          check,
          status: userResult?.status || "not_tested",
          notes: userResult?.notes || "",
          evidence: userResult?.evidence || {},
        };
      });

      const passCount = results.filter(r => r.status === "pass").length;
      const failCount = results.filter(r => r.status === "fail").length;
      const partialCount = results.filter(r => r.status === "partial").length;
      const notTestedCount = results.filter(r => r.status === "not_tested").length;

      // Generate findings for failures
      const findings: AuthFinding[] = results
        .filter(r => r.status === "fail")
        .map((r, idx) => ({
          findingId: `AUTH-FIND-${Date.now().toString(36)}-${idx}`,
          title: `${r.check.name} — Failed`,
          severity: r.check.severity,
          summary: `${r.check.name} check failed for ${input.targetUrl}. ${r.notes || r.check.commonFindings[0] || ""}`,
          mitre: AUTH_MITRE_MAPPINGS.find(m =>
            r.check.name.toLowerCase().includes(m.findingType.replace(/_/g, " "))
          ) ? {
            tactic: AUTH_MITRE_MAPPINGS[0].tactic,
            techniqueId: AUTH_MITRE_MAPPINGS[0].techniqueId,
            techniqueName: AUTH_MITRE_MAPPINGS[0].techniqueName,
          } : undefined,
          fedrampControls: r.check.fedrampControls,
          evidenceRefs: Object.keys(r.evidence).map(k => `${k}: ${JSON.stringify(r.evidence[k])}`),
          remediation: r.check.whatToVerify,
        }));

      return {
        protocol: input.protocol,
        target: input.targetUrl,
        totalChecks: checks.length,
        passCount,
        failCount,
        partialCount,
        notTestedCount,
        score: Math.round((passCount / checks.length) * 100),
        results,
        findings,
        timestamp: Date.now(),
      };
    }),

  // ─── CARVER Auth Scoring ────────────────────────────────────────────────

  /** Calculate CARVER score with auth-specific adjustments */
  calculateCarverScore: protectedProcedure
    .input(z.object({
      conditions: z.array(z.string()),
    }))
    .query(({ input }) => {
      return calculateAuthCarverScore(input.conditions);
    }),

  /** Get available CARVER adjustment conditions */
  getCarverConditions: protectedProcedure.query(() => {
    return AUTH_CARVER_OVERLAY.adjustments.map(a => ({
      key: a.conditionKey,
      label: a.condition,
      changes: a.changes,
    }));
  }),

  // ─── Pipeline Orchestration ─────────────────────────────────────────────

  /** Get available pipeline templates */
  getPipelineTemplates: protectedProcedure.query(() => {
    return PIPELINE_TEMPLATES.map(t => ({
      id: t.id,
      name: t.name,
      description: t.description,
      category: t.category,
      defaultMode: t.defaultMode,
      stepCount: t.steps.length,
      applicablePhases: t.applicablePhases,
    }));
  }),

  /** Create a new pipeline from template */
  createPipeline: protectedProcedure
    .input(z.object({
      templateId: z.string(),
      target: z.string(),
      mode: z.enum(["strict", "standard"]),
      guardrailOverrides: z.object({
        maxRps: z.number().optional(),
        maxAttemptsPerAccount: z.number().optional(),
        scopeAllowlist: z.array(z.string()).optional(),
      }).optional(),
    }))
    .mutation(({ input }) => {
      const pipeline = initializePipeline(
        input.templateId,
        input.target,
        input.mode,
        input.guardrailOverrides
      );
      if (!pipeline) {
        return { success: false, error: "Template not found" };
      }
      activePipelines.set(pipeline.id, pipeline);
      return { success: true, pipeline, state: getWorkflowState(pipeline) };
    }),

  /** Get pipeline status */
  getPipelineState: protectedProcedure
    .input(z.object({ pipelineId: z.string() }))
    .query(({ input }) => {
      const pipeline = activePipelines.get(input.pipelineId);
      if (!pipeline) return null;
      return { pipeline, state: getWorkflowState(pipeline) };
    }),

  /** Start or advance a pipeline */
  advancePipeline: protectedProcedure
    .input(z.object({
      pipelineId: z.string(),
      stepResults: z.object({
        outputs: z.record(z.any()),
        evidenceEvents: z.array(z.object({
          timestamp: z.string(),
          tool: z.string(),
          target: z.string(),
          eventType: z.string(),
          severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
          evidenceRefs: z.array(z.string()),
          metadata: z.record(z.any()).optional(),
        })).optional(),
      }).optional(),
    }))
    .mutation(({ input }) => {
      const pipeline = activePipelines.get(input.pipelineId);
      if (!pipeline) return { success: false, error: "Pipeline not found" };

      const updated = advancePipeline(pipeline, input.stepResults);
      activePipelines.set(updated.id, updated);
      return { success: true, pipeline: updated, state: getWorkflowState(updated) };
    }),

  /** Approve a human-in-the-loop gate */
  approveStep: protectedProcedure
    .input(z.object({
      pipelineId: z.string(),
      stepId: z.string(),
      approverNote: z.string(),
    }))
    .mutation(({ input }) => {
      const pipeline = activePipelines.get(input.pipelineId);
      if (!pipeline) return { success: false, error: "Pipeline not found" };

      const updated = approveAndContinue(pipeline, input.stepId, input.approverNote);
      activePipelines.set(updated.id, updated);
      return { success: true, pipeline: updated, state: getWorkflowState(updated) };
    }),

  /** Run deterministic analysis on pipeline results */
  analyzePipeline: protectedProcedure
    .input(z.object({ pipelineId: z.string() }))
    .query(({ input }) => {
      const pipeline = activePipelines.get(input.pipelineId);
      if (!pipeline) return null;
      return deterministicAnalysis(pipeline);
    }),

  /** Get LLM reasoner prompt for pipeline (for AI chat integration) */
  getReasonerPrompt: protectedProcedure
    .input(z.object({
      pipelineId: z.string(),
      currentPhase: z.string(),
      targetUrl: z.string(),
      authType: z.string().optional(),
      ssoProvider: z.string().optional(),
    }))
    .query(({ input }) => {
      const pipeline = activePipelines.get(input.pipelineId);
      if (!pipeline) return null;

      const allEvidence = pipeline.steps.flatMap(s => s.evidenceEvents);
      return buildReasonerPrompt({
        pipeline,
        evidenceEvents: allEvidence,
        currentPhase: input.currentPhase,
        targetInfo: {
          url: input.targetUrl,
          authType: input.authType,
          ssoProvider: input.ssoProvider,
        },
      });
    }),

  /** List all active pipelines */
  listPipelines: protectedProcedure.query(() => {
    const pipelines: Array<{ id: string; name: string; status: string; mode: string; target: string; stepCount: number; createdAt: number }> = [];
    for (const [, p] of activePipelines) {
      pipelines.push({
        id: p.id,
        name: p.name,
        status: p.status,
        mode: p.mode,
        target: p.metadata.target,
        stepCount: p.steps.length,
        createdAt: p.createdAt,
      });
    }
    return pipelines.sort((a, b) => b.createdAt - a.createdAt);
  }),
});
