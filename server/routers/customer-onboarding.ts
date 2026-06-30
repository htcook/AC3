import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import * as fs from "fs";
import * as path from "path";

export const customerOnboardingRouter = router({
  generateCloudFormation: protectedProcedure
    .input(
      z.object({
        customerName: z.string().min(2).max(128),
        customerAccountId: z.string().regex(/^\d{12}$/, "Must be a 12-digit AWS account ID"),
        externalId: z.string().min(16).max(128).regex(/^[a-zA-Z0-9_\-]+$/),
        enableCSPM: z.boolean().default(true),
        enableContainerScanning: z.boolean().default(true),
        enableCodePipelineCallback: z.boolean().default(true),
        enableCloudWatchLogs: z.boolean().default(false),
      })
    )
    .mutation(async ({ input }) => {
      // Read the base CloudFormation template
      const templatePath = path.join(process.cwd(), "deploy", "cloudformation", "ac3-customer-cross-account-role.yaml");
      
      let template: string;
      try {
        template = fs.readFileSync(templatePath, "utf-8");
      } catch {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "CloudFormation template not found on server",
        });
      }

      // Add a header comment with customer-specific metadata
      const timestamp = new Date().toISOString();
      const sanitizedName = input.customerName.replace(/[^a-zA-Z0-9\s\-_]/g, "").trim();
      
      const header = `# ═══════════════════════════════════════════════════════════════════════════════
# AC3 Cross-Account Role — Generated for: ${sanitizedName}
# Customer AWS Account: ${input.customerAccountId}
# Generated: ${timestamp}
# 
# Modules enabled:
#   Environment Discovery: ALWAYS ON
#   CSPM Assessment:       ${input.enableCSPM ? "ENABLED" : "DISABLED"}
#   Container Scanning:    ${input.enableContainerScanning ? "ENABLED" : "DISABLED"}
#   CodePipeline Callback: ${input.enableCodePipelineCallback ? "ENABLED" : "DISABLED"}
#   CloudWatch Logs:       ${input.enableCloudWatchLogs ? "ENABLED" : "DISABLED"}
#
# Deploy with:
#   aws cloudformation deploy \\
#     --template-file ${sanitizedName.toLowerCase().replace(/\s+/g, "-")}-ac3-role.yaml \\
#     --stack-name ac3-cross-account-role \\
#     --parameter-overrides AC3AccountId=808038814732 ExternalId=${input.externalId} \\
#       ${!input.enableCSPM ? "EnableCSPM=false " : ""}${!input.enableContainerScanning ? "EnableContainerScanning=false " : ""}${!input.enableCodePipelineCallback ? "EnableCodePipelineCallback=false " : ""}${input.enableCloudWatchLogs ? "EnableCloudWatchLogs=true " : ""}\\
#     --capabilities CAPABILITY_NAMED_IAM
# ═══════════════════════════════════════════════════════════════════════════════

`;

      const customizedTemplate = header + template;
      const filename = `${sanitizedName.toLowerCase().replace(/\s+/g, "-")}-ac3-role.yaml`;

      return {
        template: customizedTemplate,
        filename,
        externalId: input.externalId,
        customerName: sanitizedName,
        customerAccountId: input.customerAccountId,
        generatedAt: timestamp,
      };
    }),
});
