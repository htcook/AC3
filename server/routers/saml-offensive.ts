/**
 * SAML / IdP Offensive Testing Router
 * Exposes the Golden SAML offensive engine via tRPC procedures.
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  planSAMLAttack as planSamlAttack,
  createSAMLEvidenceRecord as createSamlEvidenceRecord,
  generateSOCDetectionPlaybook as generateSamlSOCPlaybook,
  SAML_OFFENSIVE_TECHNIQUES as SAML_TECHNIQUES,
  type SAMLTargetConfig as SamlTargetConfig,
  type SAMLAttackContext as SamlAttackContext,
} from "../lib/saml-offensive-engine";

export const samlOffensiveRouter = router({
  // List all available SAML/IdP attack techniques
  listTechniques: protectedProcedure.query(() => {
    return SAML_TECHNIQUES.map((t) => ({
      id: t.id,
      name: t.name,
      attackId: t.attackId,
      category: t.category,
      description: t.description,
      difficulty: t.difficulty,
      opsecRisk: t.opsecRisk,
      noiseLevel: t.noiseLevel,
      prerequisites: t.prerequisites,
    }));
  }),

  // Get full technique details including operator guidance
  getTechnique: protectedProcedure
    .input(z.object({ techniqueId: z.string() }))
    .query(({ input }) => {
      const technique = SAML_TECHNIQUES.find((t) => t.id === input.techniqueId);
      if (!technique) return null;
      return technique;
    }),

  // Plan a SAML/IdP attack using LLM intelligence
  planAttack: protectedProcedure
    .input(
      z.object({
        target: z.object({
          idpProvider: z.enum(["google_workspace", "okta", "azure_ad", "ping_identity", "adfs"]),
          samlVersion: z.enum(["2.0", "1.1"]).default("2.0"),
          spTargets: z.array(z.string()),
          mfaEnabled: z.boolean(),
          mfaType: z.string().optional(),
          certificateRotationPolicy: z.string().optional(),
          federationProtocol: z.enum(["saml", "oidc", "ws_fed"]).default("saml"),
          cloudTarget: z.enum(["aws_govcloud", "aws_commercial", "azure_gov", "gcp"]).default("aws_govcloud"),
        }),
        context: z.object({
          engagementId: z.number(),
          currentAccess: z.object({
            level: z.enum(["none", "user", "admin", "idp_admin", "super_admin"]),
            hasIdpAccess: z.boolean(),
            hasMetadataAccess: z.boolean(),
            hasCertificateAccess: z.boolean(),
            compromisedAccounts: z.array(z.string()).optional(),
          }),
          targetAccess: z.string(),
          detectionEnvironment: z.object({
            siemEnabled: z.boolean(),
            cloudTrailEnabled: z.boolean(),
            idpAuditLogsEnabled: z.boolean(),
            anomalyDetectionEnabled: z.boolean(),
            certificateMonitoringEnabled: z.boolean(),
          }),
          constraints: z
            .object({
              maxOpsecRisk: z.number().optional(),
              preferSilent: z.boolean().optional(),
              avoidTechniques: z.array(z.string()).optional(),
              timeWindow: z.string().optional(),
            })
            .optional(),
        }),
      })
    )
    .mutation(async ({ input }) => {
      const plan = await planSamlAttack(
        input.target as SamlTargetConfig,
        input.context as SamlAttackContext
      );
      return plan;
    }),

  // Record evidence from a SAML attack execution
  recordEvidence: protectedProcedure
    .input(
      z.object({
        techniqueId: z.string(),
        action: z.string(),
        result: z.object({
          success: z.boolean(),
          sourceContext: z.string(),
          targetResource: z.string(),
          commandExecuted: z.string().optional(),
          rawOutput: z.string().optional(),
          impactAchieved: z.string().optional(),
          operatorNotes: z.string().optional(),
        }),
      })
    )
    .mutation(({ input }) => {
      const record = createSamlEvidenceRecord(
        input.techniqueId,
        input.action,
        input.result
      );
      return record;
    }),

  // Generate SOC playbook from evidence records
  generateSOCPlaybook: protectedProcedure
    .input(z.object({ records: z.array(z.any()) }))
    .mutation(({ input }) => {
      return generateSamlSOCPlaybook(input.records);
    }),
});
