/**
 * Credential Auto-Rotation Router
 *
 * tRPC procedures for managing auto-rotation policies, executing rotations,
 * and viewing the rotation audit trail.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import {
  rotateAwsAccessKey,
  deleteAwsAccessKey,
  listAwsAccessKeys,
  rotateAzureClientSecret,
  removeAzurePassword,
  rotateGcpServiceAccountKey,
  deleteGcpServiceAccountKey,
  listGcpServiceAccountKeys,
  calculateNextRotation,
  isPolicyDueForRotation,
  generateRotationSummary,
  DEFAULT_ROTATION_INTERVALS,
  type RotationPolicy,
  type RotationAuditEntry,
  type RotationProvider,
  type AwsCredentials,
  type AzureCredentials,
  type GcpCredentials,
} from "../lib/credential-auto-rotation";
import { decryptCredentialObject, encryptCredentialObject } from "../lib/credential-crypto";

async function getDbOrThrow() {
  const { getDb } = await import("../db");
  const db = await getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
  return db;
}

export const credentialAutoRotationRouter = router({
  // ─── List all rotation policies ──────────────────────────────────────────
  listPolicies: protectedProcedure.query(async () => {
    const db = await getDbOrThrow();
    const { credentialRotationPolicies } = await import("../../drizzle/schema");
    const { desc } = await import("drizzle-orm");
    const policies = await db.select().from(credentialRotationPolicies).orderBy(desc(credentialRotationPolicies.createdAt));
    return policies;
  }),

  // ─── Get a single policy ─────────────────────────────────────────────────
  getPolicy: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await getDbOrThrow();
      const { credentialRotationPolicies } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const [policy] = await db.select()
        .from(credentialRotationPolicies)
        .where(eq(credentialRotationPolicies.id, input.id));
      return policy || null;
    }),

  // ─── Create a rotation policy ────────────────────────────────────────────
  createPolicy: protectedProcedure
    .input(z.object({
      credentialId: z.number(),
      provider: z.enum(["aws", "azure", "gcp"]),
      credentialName: z.string(),
      enabled: z.boolean().default(false),
      rotationIntervalDays: z.number().min(1).max(365).default(90),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbOrThrow();
      const { credentialRotationPolicies } = await import("../../drizzle/schema");

      const nextRotation = new Date();
      nextRotation.setDate(nextRotation.getDate() + input.rotationIntervalDays);

      const [result] = await db.insert(credentialRotationPolicies).values({
        credentialId: input.credentialId,
        provider: input.provider,
        credentialName: input.credentialName,
        enabled: input.enabled,
        rotationIntervalDays: input.rotationIntervalDays,
        nextRotationAt: nextRotation,
        maxRetries: 3,
        retryCount: 0,
        createdBy: String(ctx.user.id),
      }).$returningId();

      return { id: result.id, message: "Rotation policy created" };
    }),

  // ─── Update a rotation policy ────────────────────────────────────────────
  updatePolicy: protectedProcedure
    .input(z.object({
      id: z.number(),
      enabled: z.boolean().optional(),
      rotationIntervalDays: z.number().min(1).max(365).optional(),
      maxRetries: z.number().min(1).max(10).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbOrThrow();
      const { credentialRotationPolicies } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");

      const updates: Record<string, any> = {};
      if (input.enabled !== undefined) updates.enabled = input.enabled;
      if (input.rotationIntervalDays !== undefined) {
        updates.rotationIntervalDays = input.rotationIntervalDays;
        const [policy] = await db.select()
          .from(credentialRotationPolicies)
          .where(eq(credentialRotationPolicies.id, input.id));
        if (policy?.lastRotatedAt) {
          updates.nextRotationAt = calculateNextRotation(policy.lastRotatedAt, input.rotationIntervalDays);
        }
      }
      if (input.maxRetries !== undefined) updates.maxRetries = input.maxRetries;
      updates.updatedAt = new Date();

      await db.update(credentialRotationPolicies)
        .set(updates)
        .where(eq(credentialRotationPolicies.id, input.id));

      return { success: true };
    }),

  // ─── Delete a rotation policy ────────────────────────────────────────────
  deletePolicy: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbOrThrow();
      const { credentialRotationPolicies } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");

      await db.delete(credentialRotationPolicies)
        .where(eq(credentialRotationPolicies.id, input.id));
      return { success: true };
    }),

  // ─── Execute rotation for a specific policy ──────────────────────────────
  executeRotation: protectedProcedure
    .input(z.object({ policyId: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbOrThrow();
      const { credentialRotationPolicies, credentialRotationAudit, cloudCredentials } = await import("../../drizzle/schema");
      const { eq, sql } = await import("drizzle-orm");

      // Get the policy
      const [policy] = await db.select()
        .from(credentialRotationPolicies)
        .where(eq(credentialRotationPolicies.id, input.policyId));

      if (!policy) throw new TRPCError({ code: "NOT_FOUND", message: "Rotation policy not found" });

      // Get the credential
      const [credential] = await db.select()
        .from(cloudCredentials)
        .where(eq(cloudCredentials.id, policy.credentialId));

      if (!credential) throw new TRPCError({ code: "NOT_FOUND", message: "Associated credential not found" });

      // Log start of rotation
      const [auditEntry] = await db.insert(credentialRotationAudit).values({
        policyId: policy.id,
        credentialId: policy.credentialId,
        provider: policy.provider as "aws" | "azure" | "gcp",
        status: "in_progress" as const,
        initiatedBy: String(ctx.user.id),
        durationMs: 0,
      }).$returningId();

      try {
        // Decrypt current credentials
        const currentCreds = decryptCredentialObject({
          encryptedData: credential.encryptedData,
          iv: credential.encryptionIv,
          tag: credential.encryptionTag,
        });

        // Execute rotation based on provider
        let result;
        switch (policy.provider) {
          case "aws":
            result = await rotateAwsAccessKey(currentCreds as any);
            break;
          case "azure":
            result = await rotateAzureClientSecret(currentCreds as any);
            break;
          case "gcp":
            result = await rotateGcpServiceAccountKey(currentCreds as any);
            break;
          default:
            throw new Error(`Unsupported provider: ${policy.provider}`);
        }

        if (result.success && result.newCredentials) {
          // Re-encrypt new credentials
          const encrypted = encryptCredentialObject(result.newCredentials);

          // Update the credential vault
          await db.update(cloudCredentials).set({
            encryptedData: encrypted.encryptedData,
            encryptionIv: encrypted.iv,
            encryptionTag: encrypted.tag,
            status: "active",
            lastValidatedAt: new Date(),
            updatedAt: new Date(),
          }).where(eq(cloudCredentials.id, credential.id));

          // Update policy
          const now = new Date();
          await db.update(credentialRotationPolicies).set({
            lastRotatedAt: now,
            nextRotationAt: calculateNextRotation(now, policy.rotationIntervalDays),
            retryCount: 0,
            updatedAt: now,
          }).where(eq(credentialRotationPolicies.id, policy.id));

          // Update audit entry
          await db.update(credentialRotationAudit).set({
            status: "success",
            oldKeyIdentifier: result.oldKeyId,
            newKeyIdentifier: result.newKeyId,
            durationMs: result.durationMs,
          }).where(eq(credentialRotationAudit.id, auditEntry.id));

          // Step 2: Delete old key using new credentials (post-vault-update)
          let oldKeyCleanup: { success: boolean; error: string | null } = { success: true, error: null };
          if (result.oldKeyId && result.newCredentials) {
            switch (policy.provider) {
              case "aws": {
                const newAwsCreds: AwsCredentials = {
                  accessKeyId: result.newCredentials.accessKeyId,
                  secretAccessKey: result.newCredentials.secretAccessKey,
                  region: result.newCredentials.region,
                };
                oldKeyCleanup = await deleteAwsAccessKey(
                  newAwsCreds,
                  result.oldKeyId,
                  result.newCredentials.userName || ""
                );
                break;
              }
              case "azure": {
                const newAzureCreds: AzureCredentials = {
                  tenantId: result.newCredentials.tenantId,
                  clientId: result.newCredentials.clientId,
                  clientSecret: result.newCredentials.clientSecret,
                };
                // Note: old Azure password removal requires the old keyId, not the generic label
                // The old key cleanup is best-effort; the new secret is already active
                if (result.newCredentials.applicationObjectId) {
                  oldKeyCleanup = await removeAzurePassword(
                    newAzureCreds,
                    result.newCredentials.applicationObjectId,
                    result.oldKeyId
                  );
                }
                break;
              }
              case "gcp": {
                const newGcpCreds: GcpCredentials = {
                  projectId: result.newCredentials.projectId,
                  clientEmail: result.newCredentials.clientEmail,
                  privateKey: result.newCredentials.privateKey,
                };
                oldKeyCleanup = await deleteGcpServiceAccountKey(newGcpCreds, result.oldKeyId);
                break;
              }
            }
          }

          return {
            success: true,
            oldKeyId: result.oldKeyId,
            newKeyId: result.newKeyId,
            durationMs: result.durationMs,
            oldKeyDeleted: oldKeyCleanup.success,
            oldKeyDeleteError: oldKeyCleanup.error,
          };
        } else {
          throw new Error(result.error || "Rotation failed");
        }
      } catch (err: any) {
        // Update audit entry with failure
        await db.update(credentialRotationAudit).set({
          status: "failed",
          errorMessage: err.message,
          durationMs: 0,
        }).where(eq(credentialRotationAudit.id, auditEntry.id));

        // Increment retry count
        await db.update(credentialRotationPolicies).set({
          retryCount: sql`${credentialRotationPolicies.retryCount} + 1`,
          updatedAt: new Date(),
        }).where(eq(credentialRotationPolicies.id, policy.id));

        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: err.message });
      }
    }),

  // ─── Get audit trail ─────────────────────────────────────────────────────
  getAuditTrail: protectedProcedure
    .input(z.object({
      policyId: z.number().optional(),
      credentialId: z.number().optional(),
      limit: z.number().min(1).max(100).default(50),
    }))
    .query(async ({ input }) => {
      const db = await getDbOrThrow();
      const { credentialRotationAudit } = await import("../../drizzle/schema");
      const { eq, desc, and } = await import("drizzle-orm");

      const conditions = [];
      if (input.policyId) conditions.push(eq(credentialRotationAudit.policyId, input.policyId));
      if (input.credentialId) conditions.push(eq(credentialRotationAudit.credentialId, input.credentialId));

      let query = db.select().from(credentialRotationAudit);
      if (conditions.length > 0) {
        query = query.where(conditions.length === 1 ? conditions[0] : and(...conditions)) as any;
      }

      const entries = await query
        .orderBy(desc(credentialRotationAudit.createdAt))
        .limit(input.limit);

      return entries;
    }),

  // ─── Get rotation summary ────────────────────────────────────────────────
  getSummary: protectedProcedure.query(async () => {
    const db = await getDbOrThrow();
    const { credentialRotationPolicies, credentialRotationAudit } = await import("../../drizzle/schema");
    const { desc } = await import("drizzle-orm");

    const policies = await db.select().from(credentialRotationPolicies);
    const recentAudit = await db.select()
      .from(credentialRotationAudit)
      .orderBy(desc(credentialRotationAudit.createdAt))
      .limit(100);

    const mappedPolicies: RotationPolicy[] = policies.map((p: any) => ({
      id: p.id,
      credentialId: p.credentialId,
      provider: p.provider as RotationProvider,
      credentialName: p.credentialName,
      enabled: p.enabled,
      rotationIntervalDays: p.rotationIntervalDays,
      lastRotatedAt: p.lastRotatedAt,
      nextRotationAt: p.nextRotationAt,
      maxRetries: p.maxRetries,
      retryCount: p.retryCount,
      createdBy: p.createdBy || "",
      createdAt: p.createdAt || new Date(),
      updatedAt: p.updatedAt || new Date(),
    }));

    const mappedAudit: RotationAuditEntry[] = recentAudit.map((a: any) => ({
      id: a.id,
      policyId: a.policyId,
      credentialId: a.credentialId,
      provider: a.provider as RotationProvider,
      status: a.status,
      oldKeyIdentifier: a.oldKeyIdentifier,
      newKeyIdentifier: a.newKeyIdentifier,
      errorMessage: a.errorMessage,
      durationMs: a.durationMs,
      initiatedBy: a.initiatedBy,
      createdAt: a.createdAt || new Date(),
    }));

    return generateRotationSummary(mappedPolicies, mappedAudit);
  }),

  // ─── Get due policies ────────────────────────────────────────────────────
  getDuePolicies: protectedProcedure.query(async () => {
    const db = await getDbOrThrow();
    const { credentialRotationPolicies } = await import("../../drizzle/schema");
    const { eq } = await import("drizzle-orm");

    const policies = await db.select()
      .from(credentialRotationPolicies)
      .where(eq(credentialRotationPolicies.enabled, true));

    return policies.filter((p: any) => {
      const mapped: RotationPolicy = {
        id: p.id,
        credentialId: p.credentialId,
        provider: p.provider as RotationProvider,
        credentialName: p.credentialName,
        enabled: p.enabled,
        rotationIntervalDays: p.rotationIntervalDays,
        lastRotatedAt: p.lastRotatedAt,
        nextRotationAt: p.nextRotationAt,
        maxRetries: p.maxRetries,
        retryCount: p.retryCount,
        createdBy: p.createdBy || "",
        createdAt: p.createdAt || new Date(),
        updatedAt: p.updatedAt || new Date(),
      };
      return isPolicyDueForRotation(mapped);
    });
  }),

  // ─── List provider keys (pre-rotation check) ────────────────────────────
  listProviderKeys: protectedProcedure
    .input(z.object({
      credentialId: z.number(),
      provider: z.enum(["aws", "azure", "gcp"]),
    }))
    .query(async ({ input }) => {
      const db = await getDbOrThrow();
      const { cloudCredentials } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");

      const [credential] = await db.select()
        .from(cloudCredentials)
        .where(eq(cloudCredentials.id, input.credentialId));

      if (!credential) throw new TRPCError({ code: "NOT_FOUND", message: "Credential not found" });

      const currentCreds = decryptCredentialObject({
        encryptedData: credential.encryptedData,
        iv: credential.encryptionIv,
        tag: credential.encryptionTag,
      });

      switch (input.provider) {
        case "aws": {
          const awsCreds = currentCreds as AwsCredentials;
          return await listAwsAccessKeys(awsCreds);
        }
        case "gcp": {
          const gcpCreds = currentCreds as GcpCredentials;
          return await listGcpServiceAccountKeys(gcpCreds);
        }
        case "azure": {
          // Azure doesn't have a simple key listing equivalent;
          // return a placeholder indicating the current secret is active
          return {
            keys: [{ accessKeyId: "current-client-secret", status: "Active", createDate: undefined }],
            error: null,
          };
        }
        default:
          return { keys: [], error: "Unsupported provider" };
      }
    }),

  // ─── Delete old key manually (post-rotation cleanup) ────────────────────
  deleteOldKey: protectedProcedure
    .input(z.object({
      credentialId: z.number(),
      provider: z.enum(["aws", "azure", "gcp"]),
      oldKeyId: z.string(),
      userName: z.string().optional(),
      applicationObjectId: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbOrThrow();
      const { cloudCredentials } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");

      const [credential] = await db.select()
        .from(cloudCredentials)
        .where(eq(cloudCredentials.id, input.credentialId));

      if (!credential) throw new TRPCError({ code: "NOT_FOUND", message: "Credential not found" });

      const currentCreds = decryptCredentialObject({
        encryptedData: credential.encryptedData,
        iv: credential.encryptionIv,
        tag: credential.encryptionTag,
      });

      switch (input.provider) {
        case "aws": {
          const awsCreds = currentCreds as AwsCredentials;
          return await deleteAwsAccessKey(awsCreds, input.oldKeyId, input.userName || "");
        }
        case "azure": {
          const azureCreds = currentCreds as AzureCredentials;
          if (!input.applicationObjectId) {
            throw new TRPCError({ code: "BAD_REQUEST", message: "applicationObjectId required for Azure" });
          }
          return await removeAzurePassword(azureCreds, input.applicationObjectId, input.oldKeyId);
        }
        case "gcp": {
          const gcpCreds = currentCreds as GcpCredentials;
          return await deleteGcpServiceAccountKey(gcpCreds, input.oldKeyId);
        }
        default:
          throw new TRPCError({ code: "BAD_REQUEST", message: "Unsupported provider" });
      }
    }),

  // ─── Get default intervals ───────────────────────────────────────────────
  getDefaults: protectedProcedure.query(() => {
    return DEFAULT_ROTATION_INTERVALS;
  }),
});
