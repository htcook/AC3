/**
 * GitOps / Supply Chain Offensive Assessment Router
 * Exposes the ArgoCD/Atlantis/GitHub offensive engine via tRPC procedures.
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  planGitOpsAttack,
  createGitOpsEvidenceRecord,
  generateGitOpsSOCPlaybook,
  GITOPS_TECHNIQUES,
  type GitOpsTargetConfig,
  type GitOpsAttackContext,
  type GitOpsEvidenceRecord,
} from "../lib/gitops-offensive-engine";

export const gitopsOffensiveRouter = router({
  // List all available GitOps/supply chain attack techniques
  listTechniques: protectedProcedure.query(() => {
    return GITOPS_TECHNIQUES.map((t) => ({
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
      const technique = GITOPS_TECHNIQUES.find((t) => t.id === input.techniqueId);
      if (!technique) return null;
      return technique;
    }),

  // Plan a GitOps/supply chain attack using LLM intelligence
  planAttack: protectedProcedure
    .input(
      z.object({
        target: z.object({
          gitProvider: z.enum(["github_enterprise", "gitlab", "bitbucket"]),
          cicdPlatform: z.enum(["argocd", "atlantis", "github_actions", "jenkins", "multiple"]),
          containerRegistry: z.enum(["ecr", "ghcr", "dockerhub", "harbor"]),
          terraformBackend: z.enum(["s3", "terraform_cloud", "consul"]).optional(),
          helmRepos: z.array(z.string()).optional(),
          imageSigningEnabled: z.boolean().default(false),
          branchProtectionEnabled: z.boolean().default(true),
          codeOwnersEnabled: z.boolean().default(false),
          deploymentEnvironment: z.enum(["govcloud", "commercial", "hybrid"]).default("govcloud"),
        }),
        context: z.object({
          engagementId: z.number(),
          currentAccess: z.object({
            level: z.enum(["read_only", "contributor", "maintainer", "admin", "org_owner"]),
            repositories: z.array(z.string()).optional(),
            argocdAccess: z.enum(["none", "readonly", "project_admin", "cluster_admin"]).optional(),
            atlantisAccess: z.enum(["none", "plan_only", "apply"]).optional(),
            registryAccess: z.enum(["pull", "push", "admin"]).optional(),
          }),
          targetAccess: z.string(),
          detectionEnvironment: z.object({
            githubAuditLogEnabled: z.boolean(),
            argocdAuditEnabled: z.boolean(),
            branchProtectionAlerts: z.boolean(),
            secretScanningEnabled: z.boolean(),
            dependabotEnabled: z.boolean(),
            siemIntegration: z.boolean(),
          }),
          constraints: z
            .object({
              maxOpsecRisk: z.number().optional(),
              preferSilent: z.boolean().optional(),
              avoidRepositories: z.array(z.string()).optional(),
              timeWindow: z.string().optional(),
            })
            .optional(),
        }),
      })
    )
    .mutation(async ({ input }) => {
      const plan = await planGitOpsAttack(
        input.target as GitOpsTargetConfig,
        input.context as GitOpsAttackContext
      );
      return plan;
    }),

  // Record evidence from a GitOps attack execution
  recordEvidence: protectedProcedure
    .input(
      z.object({
        techniqueId: z.string(),
        action: z.string(),
        result: z.object({
          success: z.boolean(),
          sourceContext: z.string(),
          targetResource: z.string(),
          repository: z.string().optional(),
          commandExecuted: z.string().optional(),
          rawOutput: z.string().optional(),
          impactAchieved: z.string().optional(),
          operatorNotes: z.string().optional(),
        }),
      })
    )
    .mutation(({ input }) => {
      const record = createGitOpsEvidenceRecord(
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
      return generateGitOpsSOCPlaybook(input.records);
    }),
});
