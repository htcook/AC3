/**
 * Cloud Credentials & Live IAM Enumeration Router
 * Manages encrypted cloud provider credentials and runs live IAM enumeration
 * against AWS, Azure, and GCP environments.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

const providerEnum = z.enum(["aws", "azure", "gcp"]);
const credTypeEnum = z.enum([
  "aws_access_key", "aws_assume_role", "aws_session_token",
  "azure_client_secret", "azure_managed_identity", "azure_cli",
  "gcp_service_account_key", "gcp_workload_identity", "gcp_oauth",
]);

export const cloudCredentialsRouter = router({
  /** List all stored credentials (masked) */
  listCredentials: protectedProcedure
    .input(z.object({
      provider: providerEnum.optional(),
      engagementId: z.number().optional(),
    }).optional())
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cloudCredentials } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, and, desc } = await import("drizzle-orm");

      const conditions = [];
      if (input?.provider) conditions.push(eq(cloudCredentials.provider, input.provider));
      if (input?.engagementId) conditions.push(eq(cloudCredentials.engagementId, input.engagementId));

      const creds = conditions.length > 0
        ? await db.select().from(cloudCredentials).where(and(...conditions)).orderBy(desc(cloudCredentials.createdAt))
        : await db.select().from(cloudCredentials).orderBy(desc(cloudCredentials.createdAt));

      // Return masked credentials (never expose encrypted data)
      return creds.map(c => ({
        id: c.id,
        providerId: c.providerId,
        engagementId: c.engagementId,
        provider: c.provider,
        credentialName: c.credentialName,
        credentialType: c.credentialType,
        accountId: c.accountId,
        region: c.region,
        roleArn: c.roleArn,
        tenantId: c.tenantId,
        subscriptionId: c.subscriptionId,
        projectId: c.projectId,
        status: c.status,
        lastValidatedAt: c.lastValidatedAt,
        lastUsedAt: c.lastUsedAt,
        expiresAt: c.expiresAt,
        createdBy: c.createdBy,
        createdAt: c.createdAt,
      }));
    }),

  /** Store a new cloud credential (encrypted at rest) */
  addCredential: protectedProcedure
    .input(z.object({
      provider: providerEnum,
      credentialName: z.string().min(1),
      credentialType: credTypeEnum,
      credentialData: z.record(z.string(), z.string()), // key-value pairs of credential fields
      engagementId: z.number().optional(),
      providerId: z.number().optional(),
      accountId: z.string().optional(),
      region: z.string().optional(),
      roleArn: z.string().optional(),
      externalId: z.string().optional(),
      tenantId: z.string().optional(),
      subscriptionId: z.string().optional(),
      projectId: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { cloudCredentials } = await import("../../drizzle/schema");
      const { encryptCredentialObject } = await import("../lib/credential-crypto");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const encrypted = encryptCredentialObject(input.credentialData);

      const [result] = await db.insert(cloudCredentials).values({
        providerId: input.providerId ?? null,
        engagementId: input.engagementId ?? null,
        provider: input.provider,
        credentialName: input.credentialName,
        credentialType: input.credentialType,
        encryptedData: encrypted.encryptedData,
        encryptionIv: encrypted.iv,
        encryptionTag: encrypted.tag,
        accountId: input.accountId ?? null,
        region: input.region ?? null,
        roleArn: input.roleArn ?? null,
        externalId: input.externalId ?? null,
        tenantId: input.tenantId ?? null,
        subscriptionId: input.subscriptionId ?? null,
        projectId: input.projectId ?? null,
        status: "active",
        createdBy: ctx.user?.name || ctx.user?.openId || null,
      });

      return { id: result.insertId, success: true };
    }),

  /** Validate a stored credential by testing connectivity */
  validateCredential: protectedProcedure
    .input(z.object({ credentialId: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cloudCredentials } = await import("../../drizzle/schema");
      const { decryptCredentialObject } = await import("../lib/credential-crypto");
      const { validateAWSCredentials, validateAzureCredentials, validateGCPCredentials } = await import("../lib/cloud-iam-enumerator");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [cred] = await db.select().from(cloudCredentials).where(eq(cloudCredentials.id, input.credentialId));
      if (!cred) throw new TRPCError({ code: "NOT_FOUND", message: "Credential not found" });

      const decrypted = decryptCredentialObject({
        encryptedData: cred.encryptedData,
        iv: cred.encryptionIv,
        tag: cred.encryptionTag,
      });

      let validationResult: { valid: boolean; identity?: string; error?: string };

      switch (cred.provider) {
        case "aws":
          validationResult = await validateAWSCredentials({
            accessKeyId: decrypted.accessKeyId,
            secretAccessKey: decrypted.secretAccessKey,
            sessionToken: decrypted.sessionToken,
            region: cred.region || undefined,
            roleArn: cred.roleArn || undefined,
            externalId: cred.externalId || undefined,
          });
          break;
        case "azure":
          validationResult = await validateAzureCredentials({
            clientId: decrypted.clientId,
            clientSecret: decrypted.clientSecret,
            tenantId: cred.tenantId || decrypted.tenantId,
          });
          break;
        case "gcp":
          validationResult = await validateGCPCredentials({
            projectId: cred.projectId || decrypted.projectId || "",
            serviceAccountKey: typeof decrypted === "string" ? decrypted : JSON.stringify(decrypted),
          });
          break;
        default:
          throw new TRPCError({ code: "BAD_REQUEST", message: `Unsupported provider: ${cred.provider}` });
      }

      // Update status
      await db.update(cloudCredentials)
        .set({
          status: validationResult.valid ? "active" : "error",
          lastValidatedAt: new Date(),
        })
        .where(eq(cloudCredentials.id, input.credentialId));

      return validationResult;
    }),

  /** Delete a stored credential */
  deleteCredential: protectedProcedure
    .input(z.object({ credentialId: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cloudCredentials } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      await db.delete(cloudCredentials).where(eq(cloudCredentials.id, input.credentialId));
      return { success: true };
    }),

  /** Run live IAM enumeration using a stored credential */
  runEnumeration: protectedProcedure
    .input(z.object({
      credentialId: z.number(),
      engagementId: z.number().optional(),
      providerId: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cloudCredentials, cloudEnumerationRuns, cloudIdentities, cloudMisconfigurations } = await import("../../drizzle/schema");
      const { decryptCredentialObject } = await import("../lib/credential-crypto");
      const { enumerateAWS, enumerateAzure, enumerateGCP } = await import("../lib/cloud-iam-enumerator");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [cred] = await db.select().from(cloudCredentials).where(eq(cloudCredentials.id, input.credentialId));
      if (!cred) throw new TRPCError({ code: "NOT_FOUND", message: "Credential not found" });

      const decrypted = decryptCredentialObject({
        encryptedData: cred.encryptedData,
        iv: cred.encryptionIv,
        tag: cred.encryptionTag,
      });

      // Create enumeration run record
      const [run] = await db.insert(cloudEnumerationRuns).values({
        credentialId: input.credentialId,
        providerId: input.providerId ?? cred.providerId ?? null,
        engagementId: input.engagementId ?? cred.engagementId ?? null,
        provider: cred.provider,
        status: "running",
        startedAt: new Date(),
      });
      const runId = run.insertId;

      try {
        let enumResult: any;

        switch (cred.provider) {
          case "aws":
            enumResult = await enumerateAWS({
              accessKeyId: decrypted.accessKeyId,
              secretAccessKey: decrypted.secretAccessKey,
              sessionToken: decrypted.sessionToken,
              region: cred.region || undefined,
              roleArn: cred.roleArn || undefined,
              externalId: cred.externalId || undefined,
            });
            break;
          case "azure":
            enumResult = await enumerateAzure({
              clientId: decrypted.clientId,
              clientSecret: decrypted.clientSecret,
              tenantId: cred.tenantId || decrypted.tenantId,
              subscriptionId: cred.subscriptionId || undefined,
            });
            break;
          case "gcp":
            enumResult = await enumerateGCP({
              projectId: cred.projectId || decrypted.projectId || "",
              serviceAccountKey: typeof decrypted === "string" ? decrypted : JSON.stringify(decrypted),
            });
            break;
          default:
            throw new Error(`Unsupported provider: ${cred.provider}`);
        }

        // Store identities in cloud_identities table
        const allIdentities = [
          ...enumResult.users,
          ...enumResult.roles,
          ...enumResult.groups,
          ...enumResult.serviceAccounts,
        ];

        const providerId = input.providerId ?? cred.providerId;
        if (providerId) {
          for (const identity of allIdentities) {
            try {
              await db.insert(cloudIdentities).values({
                providerId,
                identityType: identity.identityType,
                arn: identity.arn ?? null,
                name: identity.name,
                email: identity.email ?? null,
                isPrivileged: identity.isPrivileged,
                lastActivity: identity.lastActivity ?? null,
                permissions: identity.permissions ?? null,
                policies: identity.policies ?? null,
                metadata: identity.metadata ?? null,
              });
            } catch { /* skip duplicates */ }
          }

          // Store misconfigurations
          for (const misconfig of enumResult.misconfigurations) {
            try {
              await db.insert(cloudMisconfigurations).values({
                providerId,
                resourceType: misconfig.type,
                misconfigType: misconfig.type,
                severity: misconfig.severity || "medium",
                description: misconfig.description,
                currentValue: JSON.stringify(misconfig.affectedResources),
              });
            } catch { /* skip */ }
          }
        }

        // Update enumeration run
        await db.update(cloudEnumerationRuns)
          .set({
            status: enumResult.errors.length > 0 ? "partial" : "completed",
            totalUsersFound: enumResult.summary.totalUsers,
            totalRolesFound: enumResult.summary.totalRoles,
            totalPoliciesFound: enumResult.summary.totalPolicies,
            totalGroupsFound: enumResult.summary.totalGroups,
            totalServiceAccountsFound: enumResult.summary.totalServiceAccounts,
            totalMisconfigsFound: enumResult.summary.totalMisconfigs,
            results: enumResult.summary,
            errorLog: enumResult.errors.length > 0 ? enumResult.errors : null,
            completedAt: new Date(),
          })
          .where(eq(cloudEnumerationRuns.id, Number(runId)));

        // Update credential last used
        await db.update(cloudCredentials)
          .set({ lastUsedAt: new Date(), status: "active" })
          .where(eq(cloudCredentials.id, input.credentialId));

        return {
          runId: Number(runId),
          success: true,
          summary: enumResult.summary,
          errors: enumResult.errors,
        };
      } catch (e: any) {
        await db.update(cloudEnumerationRuns)
          .set({ status: "error", errorLog: [e.message], completedAt: new Date() })
          .where(eq(cloudEnumerationRuns.id, Number(runId)));
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `Enumeration failed: ${e.message}` });
      }
    }),

  /** List enumeration runs */
  listEnumerationRuns: protectedProcedure
    .input(z.object({
      credentialId: z.number().optional(),
      engagementId: z.number().optional(),
      provider: providerEnum.optional(),
    }).optional())
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cloudEnumerationRuns } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, and, desc } = await import("drizzle-orm");

      const conditions = [];
      if (input?.credentialId) conditions.push(eq(cloudEnumerationRuns.credentialId, input.credentialId));
      if (input?.engagementId) conditions.push(eq(cloudEnumerationRuns.engagementId, input.engagementId));
      if (input?.provider) conditions.push(eq(cloudEnumerationRuns.provider, input.provider));

      const runs = conditions.length > 0
        ? await db.select().from(cloudEnumerationRuns).where(and(...conditions)).orderBy(desc(cloudEnumerationRuns.createdAt))
        : await db.select().from(cloudEnumerationRuns).orderBy(desc(cloudEnumerationRuns.createdAt));
      return runs;
    }),

  /** Get enumeration stats */
  getEnumerationStats: protectedProcedure
    .input(z.object({}).optional())
    .query(async () => {
      const { getDb } = await import("../db");
      const { cloudCredentials, cloudEnumerationRuns } = await import("../../drizzle/schema");
      const { count } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [credCount] = await db.select({ count: count() }).from(cloudCredentials);
      const [runCount] = await db.select({ count: count() }).from(cloudEnumerationRuns);

      return {
        totalCredentials: credCount.count,
        totalEnumerationRuns: runCount.count,
      };
    }),
});
