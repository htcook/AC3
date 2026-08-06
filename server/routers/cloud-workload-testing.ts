import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import {
  runUnifiedAssessment,
  compareCloudProviders,
  getAvailableCategories,
  K8S_SECURITY_CHECKS,
  SERVERLESS_SECURITY_CHECKS,
  type CloudProvider,
  type CloudTestConfig,
} from "../lib/cloud-workload-testing";

export const cloudWorkloadTestingRouter = router({
  /** Get available test categories for a cloud provider */
  getCategories: protectedProcedure
    .input(z.object({
      provider: z.enum(["aws", "azure", "gcp"]),
    }))
    .query(({ input }) => {
      return getAvailableCategories(input.provider as CloudProvider);
    }),

  /** Run a unified cloud security assessment */
  runAssessment: protectedProcedure
    .input(z.object({
      provider: z.enum(["aws", "azure", "gcp"]),
      categories: z.array(z.string()).optional(),
      targetAccount: z.string().optional(),
      region: z.string().optional(),
      dryRun: z.boolean().default(false),
    }))
    .mutation(({ input }) => {
      return runUnifiedAssessment({
        provider: input.provider as CloudProvider,
        categories: (input.categories ?? ["cis_benchmark"]) as any,
        targetAccount: input.targetAccount,
        region: input.region,
        dryRun: input.dryRun,
      });
    }),

  /** Compare security posture across multiple cloud providers */
  compareProviders: protectedProcedure
    .input(z.object({
      providers: z.array(z.enum(["aws", "azure", "gcp"])).min(2),
    }))
    .mutation(({ input }) => {
      const defaultCategories = ["cis_benchmark", "iam_audit", "storage_scan"] as const;
      const reports = input.providers.map(p =>
        runUnifiedAssessment({ provider: p as CloudProvider, categories: [...defaultCategories] as any })
      );
      return compareCloudProviders(reports);
    }),

  /** Get Kubernetes security checks catalog */
  getK8sChecks: protectedProcedure.query(() => {
    return K8S_SECURITY_CHECKS;
  }),

  /** Get serverless security checks catalog */
  getServerlessChecks: protectedProcedure.query(() => {
    return SERVERLESS_SECURITY_CHECKS;
  }),
});
