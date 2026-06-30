/**
 * Container Registry Router
 *
 * tRPC procedures for managing container registry credentials,
 * listing repositories/tags, and scanning container images.
 */

import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import {
  testRegistryConnection,
  listRepositories,
  listTags,
  scanContainerImage,
  enrichWithNvd,
  type RegistryType,
  type RegistryAuthConfig,
} from "../lib/container-registry-service";

// ─── Helpers ────────────────────────────────────────────────────────

function encryptAuthConfig(config: RegistryAuthConfig): string {
  // In production, use proper encryption (AES-256-GCM with a KMS key).
  // For now, base64 encode to avoid plaintext storage.
  return Buffer.from(JSON.stringify(config)).toString("base64");
}

function decryptAuthConfig(encrypted: string): RegistryAuthConfig {
  try {
    return JSON.parse(Buffer.from(encrypted, "base64").toString("utf-8"));
  } catch {
    return {};
  }
}

// ─── Router ─────────────────────────────────────────────────────────

export const containerRegistryRouter = router({
  /**
   * Add a new registry credential
   */
  addRegistry: protectedProcedure
    .input(z.object({
      registryType: z.enum([
        "docker_hub", "ecr", "acr", "gcr", "harbor",
        "artifactory", "nexus", "gitlab", "ghcr", "quay", "custom",
      ]),
      name: z.string().min(1).max(255),
      registryUrl: z.string().max(512),
      engagementId: z.number().optional(),
      authConfig: z.object({
        username: z.string().optional(),
        password: z.string().optional(),
        token: z.string().optional(),
        awsAccessKeyId: z.string().optional(),
        awsSecretAccessKey: z.string().optional(),
        awsRegion: z.string().optional(),
        awsAccountId: z.string().optional(),
        azureTenantId: z.string().optional(),
        azureClientId: z.string().optional(),
        azureClientSecret: z.string().optional(),
        azureSubscriptionId: z.string().optional(),
        gcpServiceAccountJson: z.string().optional(),
        gcpProjectId: z.string().optional(),
        customUrl: z.string().optional(),
      }),
    }))
    .mutation(async ({ ctx, input }) => {
      // Test connection first
      const testResult = await testRegistryConnection(
        input.registryType as RegistryType,
        input.authConfig
      );

      const { getDbRequired } = await import("../db");
      const { containerRegistries } = await import("../../drizzle/schema");
      const dbConn = await getDbRequired();

      const [inserted] = await dbConn.insert(containerRegistries).values({
        userId: ctx.user.id,
        engagementId: input.engagementId || null,
        registryType: input.registryType,
        name: input.name,
        registryUrl: input.registryUrl || testResult.registryUrl,
        authConfig: encryptAuthConfig(input.authConfig),
        status: testResult.success ? "active" : "error",
        lastValidated: testResult.success ? new Date() : null,
        lastError: testResult.error || null,
        repoCount: testResult.repoCount || 0,
      });

      return {
        id: inserted.insertId,
        success: testResult.success,
        message: testResult.message,
        repoCount: testResult.repoCount,
        latency: testResult.latency,
      };
    }),

  /**
   * List all registries for the current user
   */
  listRegistries: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
    }).optional())
    .query(async ({ ctx, input }) => {
      const { getDbRequired } = await import("../db");
      const { containerRegistries } = await import("../../drizzle/schema");
      const { eq, and, desc } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const conditions = [eq(containerRegistries.userId, ctx.user.id)];
      if (input?.engagementId) {
        conditions.push(eq(containerRegistries.engagementId, input.engagementId));
      }

      const registries = await dbConn
        .select({
          id: containerRegistries.id,
          registryType: containerRegistries.registryType,
          name: containerRegistries.name,
          registryUrl: containerRegistries.registryUrl,
          status: containerRegistries.status,
          lastValidated: containerRegistries.lastValidated,
          lastError: containerRegistries.lastError,
          repoCount: containerRegistries.repoCount,
          imageCount: containerRegistries.imageCount,
          lastSyncAt: containerRegistries.lastSyncAt,
          createdAt: containerRegistries.createdAt,
        })
        .from(containerRegistries)
        .where(and(...conditions))
        .orderBy(desc(containerRegistries.createdAt));

      return registries;
    }),

  /**
   * Test an existing registry connection
   */
  testConnection: protectedProcedure
    .input(z.object({ registryId: z.number() }))
    .mutation(async ({ ctx, input }) => {
      const { getDbRequired } = await import("../db");
      const { containerRegistries } = await import("../../drizzle/schema");
      const { eq, and } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const [registry] = await dbConn
        .select()
        .from(containerRegistries)
        .where(and(
          eq(containerRegistries.id, input.registryId),
          eq(containerRegistries.userId, ctx.user.id),
        ));

      if (!registry) throw new TRPCError({ code: "NOT_FOUND", message: "Registry not found" });

      const authConfig = decryptAuthConfig(registry.authConfig);
      const result = await testRegistryConnection(registry.registryType as RegistryType, authConfig);

      await dbConn.update(containerRegistries)
        .set({
          status: result.success ? "active" : "error",
          lastValidated: result.success ? new Date() : undefined,
          lastError: result.error || null,
          repoCount: result.repoCount || registry.repoCount,
        })
        .where(eq(containerRegistries.id, input.registryId));

      return result;
    }),

  /**
   * Delete a registry credential
   */
  deleteRegistry: protectedProcedure
    .input(z.object({ registryId: z.number() }))
    .mutation(async ({ ctx, input }) => {
      const { getDbRequired } = await import("../db");
      const { containerRegistries } = await import("../../drizzle/schema");
      const { eq, and } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      await dbConn.delete(containerRegistries)
        .where(and(
          eq(containerRegistries.id, input.registryId),
          eq(containerRegistries.userId, ctx.user.id),
        ));
      return { success: true };
    }),

  /**
   * List repositories in a registry
   */
  listRepos: protectedProcedure
    .input(z.object({
      registryId: z.number(),
      limit: z.number().min(1).max(500).optional(),
      namespace: z.string().optional(),
    }))
    .query(async ({ ctx, input }) => {
      const { getDbRequired } = await import("../db");
      const { containerRegistries } = await import("../../drizzle/schema");
      const { eq, and } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const [registry] = await dbConn
        .select()
        .from(containerRegistries)
        .where(and(
          eq(containerRegistries.id, input.registryId),
          eq(containerRegistries.userId, ctx.user.id),
        ));

      if (!registry) throw new TRPCError({ code: "NOT_FOUND", message: "Registry not found" });

      const authConfig = decryptAuthConfig(registry.authConfig);
      return listRepositories(
        registry.registryType as RegistryType,
        authConfig,
        { limit: input.limit, namespace: input.namespace }
      );
    }),

  /**
   * List tags for a repository
   */
  listTags: protectedProcedure
    .input(z.object({
      registryId: z.number(),
      repository: z.string(),
      limit: z.number().min(1).max(200).optional(),
    }))
    .query(async ({ ctx, input }) => {
      const { getDbRequired } = await import("../db");
      const { containerRegistries } = await import("../../drizzle/schema");
      const { eq, and } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const [registry] = await dbConn
        .select()
        .from(containerRegistries)
        .where(and(
          eq(containerRegistries.id, input.registryId),
          eq(containerRegistries.userId, ctx.user.id),
        ));

      if (!registry) throw new TRPCError({ code: "NOT_FOUND", message: "Registry not found" });

      const authConfig = decryptAuthConfig(registry.authConfig);
      return listTags(
        registry.registryType as RegistryType,
        authConfig,
        input.repository,
        { limit: input.limit }
      );
    }),

  /**
   * Scan a container image
   */
  scanImage: protectedProcedure
    .input(z.object({
      registryId: z.number(),
      repository: z.string(),
      tag: z.string().default("latest"),
      engagementId: z.number().optional(),
      enrichNvd: z.boolean().default(false),
    }))
    .mutation(async ({ ctx, input }) => {
      const { getDbRequired } = await import("../db");
      const { containerRegistries, containerImageScans } = await import("../../drizzle/schema");
      const { eq, and } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const [registry] = await dbConn
        .select()
        .from(containerRegistries)
        .where(and(
          eq(containerRegistries.id, input.registryId),
          eq(containerRegistries.userId, ctx.user.id),
        ));

      if (!registry) throw new TRPCError({ code: "NOT_FOUND", message: "Registry not found" });

      const authConfig = decryptAuthConfig(registry.authConfig);

      // Run the scan
      let result = await scanContainerImage(
        registry.registryType as RegistryType,
        authConfig,
        input.repository,
        input.tag
      );

      // Optionally enrich with NVD data
      if (input.enrichNvd && result.vulnerabilities.length > 0) {
        result.vulnerabilities = await enrichWithNvd(result.vulnerabilities);
      }

      // Store scan result in DB
      const [inserted] = await dbConn.insert(containerImageScans).values({
        registryId: input.registryId,
        engagementId: input.engagementId || registry.engagementId || null,
        userId: ctx.user.id,
        repository: input.repository,
        tag: input.tag,
        digest: result.digest || null,
        imageSize: result.imageSize || null,
        architecture: result.architecture || null,
        os: result.os || null,
        status: "complete",
        totalVulnerabilities: result.totalVulnerabilities,
        criticalCount: result.criticalCount,
        highCount: result.highCount,
        mediumCount: result.mediumCount,
        lowCount: result.lowCount,
        negligibleCount: result.negligibleCount,
        fixedAvailable: result.fixedAvailable,
        vulnerabilities: result.vulnerabilities,
        packages: result.packages,
        baseImage: result.baseImage || null,
        layers: result.layers,
        complianceIssues: result.complianceIssues,
        malwareDetected: result.malwareDetected,
        secretsDetected: result.secretsDetected,
        scanDurationMs: result.scanDurationMs,
        scanEngine: result.scanEngine,
      });

      // Update registry image count
      const scanCount = await dbConn
        .select({ id: containerImageScans.id })
        .from(containerImageScans)
        .where(eq(containerImageScans.registryId, input.registryId));

      await dbConn.update(containerRegistries)
        .set({
          imageCount: scanCount.length,
          lastSyncAt: new Date(),
        })
        .where(eq(containerRegistries.id, input.registryId));

      return {
        scanId: inserted.insertId,
        ...result,
      };
    }),

  /**
   * List scan results
   */
  listScans: protectedProcedure
    .input(z.object({
      registryId: z.number().optional(),
      engagementId: z.number().optional(),
      limit: z.number().min(1).max(100).default(50),
    }))
    .query(async ({ ctx, input }) => {
      const { getDbRequired } = await import("../db");
      const { containerImageScans } = await import("../../drizzle/schema");
      const { eq, and, desc } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const conditions = [eq(containerImageScans.userId, ctx.user.id)];
      if (input.registryId) conditions.push(eq(containerImageScans.registryId, input.registryId));
      if (input.engagementId) conditions.push(eq(containerImageScans.engagementId, input.engagementId));

      return dbConn
        .select({
          id: containerImageScans.id,
          registryId: containerImageScans.registryId,
          repository: containerImageScans.repository,
          tag: containerImageScans.tag,
          digest: containerImageScans.digest,
          architecture: containerImageScans.architecture,
          os: containerImageScans.os,
          status: containerImageScans.status,
          totalVulnerabilities: containerImageScans.totalVulnerabilities,
          criticalCount: containerImageScans.criticalCount,
          highCount: containerImageScans.highCount,
          mediumCount: containerImageScans.mediumCount,
          lowCount: containerImageScans.lowCount,
          fixedAvailable: containerImageScans.fixedAvailable,
          baseImage: containerImageScans.baseImage,
          malwareDetected: containerImageScans.malwareDetected,
          secretsDetected: containerImageScans.secretsDetected,
          scanDurationMs: containerImageScans.scanDurationMs,
          createdAt: containerImageScans.createdAt,
        })
        .from(containerImageScans)
        .where(and(...conditions))
        .orderBy(desc(containerImageScans.createdAt))
        .limit(input.limit);
    }),

  /**
   * Get detailed scan result
   */
  getScan: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .query(async ({ ctx, input }) => {
      const { getDbRequired } = await import("../db");
      const { containerImageScans } = await import("../../drizzle/schema");
      const { eq, and } = await import("drizzle-orm");
      const dbConn = await getDbRequired();

      const [scan] = await dbConn
        .select()
        .from(containerImageScans)
        .where(and(
          eq(containerImageScans.id, input.scanId),
          eq(containerImageScans.userId, ctx.user.id),
        ));

      if (!scan) throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found" });
      return scan;
    }),
});
