/**
 * AI Governance & Guardrails tRPC Router
 *
 * Exposes the unified AI governance module through API endpoints
 * for the dashboard UI, compliance reporting, and audit trail access.
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  getModelRegistry,
  registerModel,
  deregisterModel,
  validateInput,
  validateOutput,
  requestHumanApproval,
  approveRequest,
  denyRequest,
  getPendingApprovals,
  getApprovalQueue,
  logGovernanceAudit,
  queryAuditLog,
  getAuditStats,
  assessBias,
  getBiasAssessments,
  generateComplianceAttestation,
  reportIncident,
  updateIncident,
  getIncidents,
  getGovernanceDashboard,
  hashContent,
} from "../lib/ai-governance";
import type {
  ComplianceFramework,
  RiskLevel,
  HumanOversightLevel,
} from "../lib/ai-governance";

export const aiGovernanceRouter = router({
  // ─── Dashboard ────────────────────────────────────────────────────────────
  getDashboard: protectedProcedure.query(async () => {
    return getGovernanceDashboard();
  }),

  // ─── Model Registry ──────────────────────────────────────────────────────
  getModels: protectedProcedure.query(async () => {
    return getModelRegistry();
  }),

  registerModel: protectedProcedure
    .input(z.object({
      modelId: z.string(),
      modelName: z.string(),
      modelVersion: z.string(),
      provider: z.string(),
      modelType: z.enum(["llm", "classifier", "embedding", "image_gen", "speech_to_text"]),
      deploymentType: z.enum(["api", "self_hosted", "edge"]),
      capabilities: z.array(z.string()),
      limitations: z.array(z.string()),
      riskClassification: z.enum(["minimal", "low", "moderate", "high", "critical"]),
      humanOversightLevel: z.enum(["none", "monitoring", "approval_required", "human_in_the_loop"]),
      approvedUseCases: z.array(z.string()),
      prohibitedUseCases: z.array(z.string()),
    }))
    .mutation(async ({ input }) => {
      registerModel({
        ...input,
        trainingDataSources: [],
        knownBiases: [],
        lastEvaluated: Date.now(),
        complianceStatus: {
          NIST_AI_RMF_1_0: "not_assessed",
          NIST_AI_600_1: "not_assessed",
          OMB_M_24_10: "not_assessed",
          DOD_RAI: "not_assessed",
          EO_14110: "not_assessed",
          MITRE_ATLAS: "not_assessed",
          CMMC_AI: "not_assessed",
          FEDRAMP_AI: "not_assessed",
        },
      });
      return { success: true };
    }),

  deregisterModel: protectedProcedure
    .input(z.object({ modelId: z.string() }))
    .mutation(async ({ input }) => {
      return { success: deregisterModel(input.modelId) };
    }),

  // ─── Input/Output Validation ──────────────────────────────────────────────
  testInputValidation: protectedProcedure
    .input(z.object({
      text: z.string(),
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const result = validateInput(input.text, {
        engagementId: input.engagementId,
        userId: ctx.user.id.toString(),
        role: ctx.user.role,
      });

      logGovernanceAudit({
        action: "test_input_validation",
        category: "input_validation",
        inputHash: hashContent(input.text),
        modelId: "ac3-primary",
        modelVersion: "1.0.0",
        latencyMs: result.processingTimeMs,
        guardrailActions: [result.action],
        violations: result.violations.map(v => ({
          type: v.type,
          severity: v.severity,
          description: v.description,
        })),
        complianceFrameworks: [...new Set(result.violations.map(v => v.framework))],
        controlIds: [...new Set(result.violations.map(v => v.controlId))],
        result: result.safe ? "success" : "blocked",
      });

      return result;
    }),

  testOutputValidation: protectedProcedure
    .input(z.object({
      text: z.string(),
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const result = validateOutput(input.text, {
        engagementId: input.engagementId,
      });

      logGovernanceAudit({
        action: "test_output_validation",
        category: "output_validation",
        inputHash: hashContent(input.text),
        modelId: "ac3-primary",
        modelVersion: "1.0.0",
        latencyMs: result.processingTimeMs,
        guardrailActions: [result.action],
        violations: result.violations.map(v => ({
          type: v.type,
          severity: v.severity,
          description: v.description,
        })),
        complianceFrameworks: [...new Set(result.violations.map(v => v.framework))],
        controlIds: [...new Set(result.violations.map(v => v.controlId))],
        confabulationRisk: result.confabulationRisk,
        result: result.safe ? "success" : "blocked",
      });

      return result;
    }),

  // ─── Human Approval Queue ─────────────────────────────────────────────────
  getPendingApprovals: protectedProcedure.query(async () => {
    return getPendingApprovals();
  }),

  getApprovalHistory: protectedProcedure
    .input(z.object({ limit: z.number().optional() }))
    .query(async ({ input }) => {
      return getApprovalQueue().slice(0, input.limit || 50);
    }),

  approveAction: protectedProcedure
    .input(z.object({ requestId: z.string() }))
    .mutation(async ({ input, ctx }) => {
      const success = approveRequest(input.requestId, ctx.user.name || ctx.user.id.toString());
      logGovernanceAudit({
        action: "approve_human_request",
        category: "human_approval",
        inputHash: hashContent(input.requestId),
        modelId: "ac3-primary",
        modelVersion: "1.0.0",
        latencyMs: 0,
        guardrailActions: ["allowed"],
        violations: [],
        complianceFrameworks: ["DOD_RAI", "OMB_M_24_10"],
        controlIds: ["GOVERNABLE", "5c.iv.E"],
        humanApprovalId: input.requestId,
        result: success ? "success" : "error",
        userId: ctx.user.id.toString(),
      });
      return { success };
    }),

  denyAction: protectedProcedure
    .input(z.object({
      requestId: z.string(),
      reason: z.string(),
    }))
    .mutation(async ({ input, ctx }) => {
      const success = denyRequest(input.requestId, ctx.user.name || ctx.user.id.toString(), input.reason);
      logGovernanceAudit({
        action: "deny_human_request",
        category: "human_approval",
        inputHash: hashContent(input.requestId),
        modelId: "ac3-primary",
        modelVersion: "1.0.0",
        latencyMs: 0,
        guardrailActions: ["blocked"],
        violations: [{ type: "human_denial", severity: "moderate" as RiskLevel, description: input.reason }],
        complianceFrameworks: ["DOD_RAI", "OMB_M_24_10"],
        controlIds: ["GOVERNABLE", "5c.iv.E"],
        humanApprovalId: input.requestId,
        result: success ? "success" : "error",
        userId: ctx.user.id.toString(),
      });
      return { success };
    }),

  // ─── Audit Trail ──────────────────────────────────────────────────────────
  getAuditLog: protectedProcedure
    .input(z.object({
      startTime: z.number().optional(),
      endTime: z.number().optional(),
      category: z.string().optional(),
      result: z.string().optional(),
      engagementId: z.number().optional(),
      limit: z.number().optional(),
    }))
    .query(async ({ input }) => {
      return queryAuditLog(input as any);
    }),

  getAuditStats: protectedProcedure
    .input(z.object({ windowMs: z.number().optional() }))
    .query(async ({ input }) => {
      return getAuditStats(input.windowMs);
    }),

  // ─── Bias Assessment ──────────────────────────────────────────────────────
  runBiasAssessment: protectedProcedure
    .input(z.object({
      modelId: z.string(),
      samples: z.array(z.object({
        input: z.string(),
        output: z.string(),
        category: z.string(),
      })),
    }))
    .mutation(async ({ input }) => {
      return assessBias({
        modelId: input.modelId,
        outputSamples: input.samples,
      });
    }),

  getBiasHistory: protectedProcedure.query(async () => {
    return getBiasAssessments();
  }),

  // ─── Compliance Attestation ───────────────────────────────────────────────
  getComplianceAttestation: protectedProcedure
    .input(z.object({
      framework: z.enum([
        "NIST_AI_RMF_1_0", "NIST_AI_600_1", "OMB_M_24_10",
        "DOD_RAI", "EO_14110", "MITRE_ATLAS", "CMMC_AI", "FEDRAMP_AI",
      ]),
    }))
    .query(async ({ input }) => {
      return generateComplianceAttestation(input.framework as ComplianceFramework);
    }),

  getAllComplianceAttestations: protectedProcedure.query(async () => {
    const frameworks: ComplianceFramework[] = [
      "NIST_AI_RMF_1_0", "NIST_AI_600_1", "OMB_M_24_10",
      "DOD_RAI", "EO_14110", "MITRE_ATLAS",
    ];
    return frameworks.map(fw => generateComplianceAttestation(fw));
  }),

  // ─── Incident Management ─────────────────────────────────────────────────
  reportIncident: protectedProcedure
    .input(z.object({
      severity: z.enum(["P1_critical", "P2_high", "P3_moderate", "P4_low"]),
      title: z.string(),
      description: z.string(),
      affectedModels: z.array(z.string()),
      affectedEngagements: z.array(z.number()).optional(),
    }))
    .mutation(async ({ input }) => {
      return reportIncident(input);
    }),

  updateIncident: protectedProcedure
    .input(z.object({
      id: z.string(),
      status: z.enum(["detected", "investigating", "mitigating", "resolved", "post_mortem"]).optional(),
      rootCause: z.string().optional(),
      mitigationActions: z.array(z.string()).optional(),
      postMortem: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { id, ...updates } = input;
      return updateIncident(id, updates);
    }),

  getIncidents: protectedProcedure
    .input(z.object({
      severity: z.enum(["P1_critical", "P2_high", "P3_moderate", "P4_low"]).optional(),
      status: z.enum(["detected", "investigating", "mitigating", "resolved", "post_mortem"]).optional(),
    }).optional())
    .query(async ({ input }) => {
      return getIncidents(input as any);
    }),
});
