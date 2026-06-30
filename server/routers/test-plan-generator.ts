import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  generateTestPlan,
  testPlanToMarkdown,
  type TestPlanInput,
} from "../lib/test-plan-generator";

export const testPlanGeneratorRouter = router({
  /**
   * Generate a PTES/NIST-structured test plan from DI scan results.
   *
   * Called from the DomainIntelResults page after a completed scan.
   * The frontend sends the scan data + pipeline output; we map it
   * into the TestPlanInput shape expected by the generator lib.
   */
  generate: protectedProcedure
    .input(
      z.object({
        scanId: z.number(),
        domain: z.string(),
        orgName: z.string().optional(),
        planType: z
          .enum(["penetration_test", "red_team_exercise"])
          .default("penetration_test"),
        assets: z
          .array(
            z.object({
              hostname: z.string(),
              ip: z.string().optional(),
              ports: z.array(z.number()).optional(),
              technologies: z.array(z.string()).optional(),
              hybridRiskScore: z.number().optional(),
              carverScores: z
                .object({
                  criticality: z.number().optional(),
                  accessibility: z.number().optional(),
                  recuperability: z.number().optional(),
                  vulnerability: z.number().optional(),
                  effect: z.number().optional(),
                  recognizability: z.number().optional(),
                })
                .optional(),
              missionFunction: z.string().optional(),
              essentialService: z.string().optional(),
              type: z.string().optional(),
              services: z
                .array(
                  z.object({
                    port: z.number(),
                    service: z.string(),
                    version: z.string().optional(),
                  })
                )
                .optional(),
              cloudProvider: z.string().optional(),
              wafDetected: z.string().optional(),
              certificates: z
                .array(
                  z.object({
                    subject: z.string(),
                    issuer: z.string().optional(),
                    validTo: z.string().optional(),
                  })
                )
                .optional(),
            })
          )
          .optional(),
        observations: z
          .array(
            z.object({
              category: z.string(),
              severity: z.string().optional(),
              title: z.string().optional(),
              description: z.string().optional(),
              evidence: z.any().optional(),
              tags: z.array(z.string()).optional(),
            })
          )
          .optional(),
        domainHealthData: z.any().optional(),
        wafNgfwData: z.any().optional(),
        breachData: z.any().optional(),
        threatActorData: z.any().optional(),
        dnsAssessmentData: z.any().optional(),
        llmAnalysis: z.any().optional(),
        carverFeedback: z.any().optional(),
        passiveRecon: z.any().optional(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      // Derive org name from domain if not provided
      const orgName =
        input.orgName ||
        input.domain.replace(/^www\./, "").split(".")[0].replace(/-/g, " ");

      // Map assets to the lib's expected format
      const mappedAssets = (input.assets || []).map((a) => ({
        hostname: a.hostname,
        ip: a.ip,
        type: a.type || "web_server",
        services: a.services || (a.ports || []).map((p) => ({ port: p, service: `port-${p}` })),
        technologies: a.technologies || [],
        cloudProvider: a.cloudProvider,
        wafDetected: a.wafDetected,
        certificates: a.certificates || [],
      }));

      // Build passive recon summary per asset
      const passiveReconResults: Record<string, any> = {};
      for (const asset of mappedAssets) {
        passiveReconResults[asset.hostname] = {
          subdomains: [],
          ipAddresses: asset.ip ? [asset.ip] : [],
          technologies: asset.technologies || [],
          services: asset.services || [],
          wafDetected: asset.wafDetected,
          cloudProvider: asset.cloudProvider,
          certificates: asset.certificates || [],
          riskSignals: [],
        };
      }

      // Merge in connector-level passive recon if available
      if (input.passiveRecon?.connectorResults) {
        for (const cr of input.passiveRecon.connectorResults) {
          if (cr.connector === "dehashed" && cr.data?.totalResults) {
            for (const key of Object.keys(passiveReconResults)) {
              passiveReconResults[key].breachExposure = {
                count: cr.data.totalResults,
                sources: (cr.data.entries || [])
                  .map((e: any) => e.database_name)
                  .filter(Boolean)
                  .slice(0, 10),
              };
            }
          }
        }
      }

      const testPlanInput: TestPlanInput = {
        engagementId: input.scanId,
        engagementName: `DI Scan — ${input.domain}`,
        planType: input.planType,
        engagementType: input.planType === "red_team_exercise" ? "red_team" : "pentest",
        organizationName: orgName,
        systemName: input.domain,
        dataSensitivity: "moderate",
        roe: {
          status: "pending",
          authorizedDomains: [input.domain],
          authorizedIps: mappedAssets
            .map((a) => a.ip)
            .filter(Boolean) as string[],
          excludedTargets: [],
          testingWindows: ["Business hours (0800-1800 EST)"],
          escalationContacts: [],
          emergencyProcedure:
            "Stop testing immediately and contact client POC",
          dataHandling:
            "All data encrypted at rest and in transit. Destroyed within 30 days of engagement completion.",
        },
        passiveReconResults,
        assets: mappedAssets,
        dnsAssessmentData: input.dnsAssessmentData,
        operatorName: ctx.user.name || "AceofCloud Operator",
        assessorOrganization: "AceofCloud",
      };

      const plan = await generateTestPlan(testPlanInput);
      const markdown = testPlanToMarkdown(plan);

      return {
        plan,
        markdown,
        generatedAt: new Date().toISOString(),
        generatedBy: ctx.user.name || ctx.user.openId,
      };
    }),

  /**
   * Export a previously generated test plan to markdown
   */
  toMarkdown: protectedProcedure
    .input(z.object({ plan: z.any() }))
    .mutation(({ input }) => {
      return { markdown: testPlanToMarkdown(input.plan) };
    }),
});
