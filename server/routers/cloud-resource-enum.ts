/**
 * Cloud Resource Enumeration Router
 *
 * Exposes the unified cloud resource enumeration that covers:
 * - AWS: EC2, S3, RDS, Lambda, VPC, CloudTrail, GuardDuty
 * - Azure: VMs, Storage, NSGs, Key Vaults, SQL, Subscriptions
 *
 * Also provides CIS benchmark checks wired to real enumeration data.
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { enumerateAWSResources, enumerateAzureResources } from "../lib/cloud-resource-enumerator";

export const cloudResourceEnumRouter = router({

  // ── Run full resource enumeration for a stored credential ──
  enumerate: protectedProcedure
    .input(z.object({
      credentialId: z.number(),
      regions: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { cloudCredentials } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const { decryptCredential } = await import("../lib/credential-crypto");

      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [cred] = await db
        .select()
        .from(cloudCredentials)
        .where(eq(cloudCredentials.id, input.credentialId))
        .limit(1);

      if (!cred) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Credential not found" });
      }

      const credRow = cred as any;
      const decrypted = decryptCredential({
        encryptedData: credRow.encryptedData,
        iv: credRow.encryptionIv,
        tag: credRow.encryptionTag,
      });
      const provider = credRow.credProvider as string;
      const parsed = JSON.parse(decrypted);

      if (provider === "aws") {
        return enumerateAWSResources({
          accessKeyId: parsed.accessKeyId || parsed.access_key_id,
          secretAccessKey: parsed.secretAccessKey || parsed.secret_access_key,
          sessionToken: parsed.sessionToken || parsed.session_token,
          region: input.regions?.[0] || parsed.region || "us-east-1",
          roleArn: parsed.roleArn || parsed.role_arn,
          externalId: parsed.externalId || parsed.external_id,
        });
      }

      if (provider === "azure") {
        return enumerateAzureResources({
          tenantId: parsed.tenantId || parsed.tenant_id || credRow.tenantId,
          clientId: parsed.clientId || parsed.client_id,
          clientSecret: parsed.clientSecret || parsed.client_secret,
          subscriptionId: parsed.subscriptionId || parsed.subscription_id || credRow.subscriptionId,
        });
      }

      throw new TRPCError({ code: "BAD_REQUEST", message: `Provider ${provider} resource enumeration not yet implemented` });
    }),

  // ── Run enumeration with inline credentials (no DB storage) ──
  enumerateInline: protectedProcedure
    .input(z.object({
      provider: z.enum(["aws", "azure", "gcp"]),
      credentials: z.record(z.string()),
      regions: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      if (input.provider === "aws") {
        return enumerateAWSResources({
          accessKeyId: input.credentials.accessKeyId || input.credentials.access_key_id || "",
          secretAccessKey: input.credentials.secretAccessKey || input.credentials.secret_access_key || "",
          sessionToken: input.credentials.sessionToken || input.credentials.session_token,
          region: input.regions?.[0] || input.credentials.region || "us-east-1",
          roleArn: input.credentials.roleArn || input.credentials.role_arn,
          externalId: input.credentials.externalId || input.credentials.external_id,
        });
      }

      if (input.provider === "azure") {
        return enumerateAzureResources({
          tenantId: input.credentials.tenantId || input.credentials.tenant_id || "",
          clientId: input.credentials.clientId || input.credentials.client_id || "",
          clientSecret: input.credentials.clientSecret || input.credentials.client_secret || "",
          subscriptionId: input.credentials.subscriptionId || input.credentials.subscription_id,
        });
      }

      throw new TRPCError({ code: "BAD_REQUEST", message: `Provider ${input.provider} not yet implemented` });
    }),

  // ── Get supported resource types per provider ──
  getSupportedResources: protectedProcedure
    .input(z.object({ provider: z.enum(["aws", "azure", "gcp"]) }))
    .query(({ input }) => {
      const resources: Record<string, Array<{ type: string; label: string; cisChecks: number }>> = {
        aws: [
          { type: "ec2_instance", label: "EC2 Instances", cisChecks: 2 },
          { type: "ebs_volume", label: "EBS Volumes", cisChecks: 1 },
          { type: "s3_bucket", label: "S3 Buckets", cisChecks: 3 },
          { type: "rds_instance", label: "RDS Instances", cisChecks: 2 },
          { type: "lambda_function", label: "Lambda Functions", cisChecks: 1 },
          { type: "vpc", label: "VPCs", cisChecks: 1 },
          { type: "security_group", label: "Security Groups", cisChecks: 1 },
          { type: "cloudtrail", label: "CloudTrail Trails", cisChecks: 2 },
          { type: "guardduty_detector", label: "GuardDuty Detectors", cisChecks: 1 },
        ],
        azure: [
          { type: "azure_vm", label: "Virtual Machines", cisChecks: 2 },
          { type: "azure_disk", label: "Managed Disks", cisChecks: 1 },
          { type: "azure_storage_account", label: "Storage Accounts", cisChecks: 3 },
          { type: "azure_nsg", label: "Network Security Groups", cisChecks: 1 },
          { type: "azure_keyvault", label: "Key Vaults", cisChecks: 2 },
          { type: "azure_sql_server", label: "SQL Servers", cisChecks: 2 },
          { type: "azure_sql_database", label: "SQL Databases", cisChecks: 1 },
          { type: "azure_activity_log", label: "Activity Log Profiles", cisChecks: 1 },
          { type: "azure_subscription", label: "Subscriptions", cisChecks: 0 },
        ],
        gcp: [
          { type: "gcp_instance", label: "Compute Instances", cisChecks: 1 },
          { type: "gcp_bucket", label: "Cloud Storage Buckets", cisChecks: 2 },
          { type: "gcp_sql_instance", label: "Cloud SQL Instances", cisChecks: 2 },
          { type: "gcp_function", label: "Cloud Functions", cisChecks: 1 },
        ],
      };
      return resources[input.provider] || [];
    }),
});
