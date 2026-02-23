/**
 * AD Domain Connector Router
 * Manages LDAP/LDAPS connections and live AD enumeration
 * to pull real AD objects into the attack simulation module.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const adDomainConnectorRouter = router({
  /** List all domain connections */
  listConnections: protectedProcedure
    .input(z.object({
      environmentId: z.number().optional(),
      engagementId: z.number().optional(),
    }).optional())
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { adDomainConnections } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, and, desc } = await import("drizzle-orm");

      const conditions = [];
      if (input?.environmentId) conditions.push(eq(adDomainConnections.environmentId, input.environmentId));
      if (input?.engagementId) conditions.push(eq(adDomainConnections.engagementId, input.engagementId));

      const conns = conditions.length > 0
        ? await db.select().from(adDomainConnections).where(and(...conditions)).orderBy(desc(adDomainConnections.createdAt))
        : await db.select().from(adDomainConnections).orderBy(desc(adDomainConnections.createdAt));

      // Mask bind password fields
      return conns.map(c => ({
        ...c,
        encryptedBindPassword: c.encryptedBindPassword ? "****" : null,
        bindPasswordIv: null,
        bindPasswordTag: null,
      }));
    }),

  /** Add a new domain connection */
  addConnection: protectedProcedure
    .input(z.object({
      connectionName: z.string().min(1),
      serverHost: z.string().min(1),
      serverPort: z.number().default(389),
      useTls: z.boolean().default(false),
      tlsRejectUnauthorized: z.boolean().default(true),
      baseDn: z.string().min(1),
      bindDn: z.string().optional(),
      bindPassword: z.string().optional(),
      domainName: z.string().min(1),
      searchScope: z.enum(["base", "one", "sub"]).default("sub"),
      environmentId: z.number().optional(),
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { adDomainConnections } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      let encryptedPassword: string | null = null;
      let passwordIv: string | null = null;
      let passwordTag: string | null = null;

      if (input.bindPassword) {
        const { encryptCredential } = await import("../lib/credential-crypto");
        const encrypted = encryptCredential(input.bindPassword);
        encryptedPassword = encrypted.encryptedData;
        passwordIv = encrypted.iv;
        passwordTag = encrypted.tag;
      }

      const [result] = await db.insert(adDomainConnections).values({
        environmentId: input.environmentId ?? null,
        engagementId: input.engagementId ?? null,
        connectionName: input.connectionName,
        serverHost: input.serverHost,
        serverPort: input.serverPort,
        useTls: input.useTls,
        tlsRejectUnauthorized: input.tlsRejectUnauthorized,
        baseDn: input.baseDn,
        bindDn: input.bindDn ?? null,
        encryptedBindPassword: encryptedPassword,
        bindPasswordIv: passwordIv,
        bindPasswordTag: passwordTag,
        domainName: input.domainName,
        searchScope: input.searchScope,
        status: "disconnected",
        createdBy: ctx.user?.name || ctx.user?.openId || null,
      });

      return { id: result.insertId, success: true };
    }),

  /** Test an LDAP connection */
  testConnection: protectedProcedure
    .input(z.object({ connectionId: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { adDomainConnections } = await import("../../drizzle/schema");
      const { decryptCredential } = await import("../lib/credential-crypto");
      const { testConnection } = await import("../lib/ad-domain-connector");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [conn] = await db.select().from(adDomainConnections).where(eq(adDomainConnections.id, input.connectionId));
      if (!conn) throw new TRPCError({ code: "NOT_FOUND", message: "Connection not found" });

      let bindPassword: string | undefined;
      if (conn.encryptedBindPassword && conn.bindPasswordIv && conn.bindPasswordTag) {
        bindPassword = decryptCredential({
          encryptedData: conn.encryptedBindPassword,
          iv: conn.bindPasswordIv,
          tag: conn.bindPasswordTag,
        });
      }

      const result = await testConnection({
        serverHost: conn.serverHost,
        serverPort: conn.serverPort,
        useTls: conn.useTls ?? false,
        tlsRejectUnauthorized: conn.tlsRejectUnauthorized ?? true,
        baseDn: conn.baseDn,
        bindDn: conn.bindDn || undefined,
        bindPassword,
      });

      await db.update(adDomainConnections)
        .set({
          status: result.success ? "connected" : "error",
          lastConnectedAt: result.success ? new Date() : null,
          errorMessage: result.success ? null : result.message,
        })
        .where(eq(adDomainConnections.id, input.connectionId));

      return result;
    }),

  /** Delete a domain connection */
  deleteConnection: protectedProcedure
    .input(z.object({ connectionId: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { adDomainConnections } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      await db.delete(adDomainConnections).where(eq(adDomainConnections.id, input.connectionId));
      return { success: true };
    }),

  /** Run live AD enumeration using a stored connection */
  runEnumeration: protectedProcedure
    .input(z.object({
      connectionId: z.number(),
      scope: z.enum(["full", "users", "groups", "computers", "gpos", "ous", "trusts", "spns", "certificates"]).default("full"),
      environmentId: z.number().optional(),
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { adDomainConnections, adEnumerationRuns, adObjects } = await import("../../drizzle/schema");
      const { decryptCredential } = await import("../lib/credential-crypto");
      const { enumerateADDomain, analyzeAttackSurface } = await import("../lib/ad-domain-connector");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [conn] = await db.select().from(adDomainConnections).where(eq(adDomainConnections.id, input.connectionId));
      if (!conn) throw new TRPCError({ code: "NOT_FOUND", message: "Connection not found" });

      let bindPassword: string | undefined;
      if (conn.encryptedBindPassword && conn.bindPasswordIv && conn.bindPasswordTag) {
        bindPassword = decryptCredential({
          encryptedData: conn.encryptedBindPassword,
          iv: conn.bindPasswordIv,
          tag: conn.bindPasswordTag,
        });
      }

      // Create enumeration run record
      const [run] = await db.insert(adEnumerationRuns).values({
        connectionId: input.connectionId,
        environmentId: input.environmentId ?? conn.environmentId ?? null,
        engagementId: input.engagementId ?? conn.engagementId ?? null,
        status: "running",
        scope: input.scope,
        startedAt: new Date(),
      });
      const runId = run.insertId;

      try {
        const enumResult = await enumerateADDomain({
          serverHost: conn.serverHost,
          serverPort: conn.serverPort,
          useTls: conn.useTls ?? false,
          tlsRejectUnauthorized: conn.tlsRejectUnauthorized ?? true,
          baseDn: conn.baseDn,
          bindDn: conn.bindDn || undefined,
          bindPassword,
        }, input.scope);

        // Store objects in ad_objects table
        const envId = input.environmentId ?? conn.environmentId;
        if (envId) {
          const allObjects = [
            ...enumResult.users,
            ...enumResult.groups,
            ...enumResult.computers,
            ...enumResult.gpos,
            ...enumResult.ous,
            ...enumResult.trusts,
            ...enumResult.spns,
            ...enumResult.certificateTemplates,
          ];

          for (const obj of allObjects) {
            try {
              await db.insert(adObjects).values({
                environmentId: envId,
                objectType: obj.objectType,
                distinguishedName: obj.distinguishedName,
                samAccountName: obj.samAccountName ?? null,
                displayName: obj.displayName ?? null,
                isPrivileged: obj.isPrivileged,
                isEnabled: obj.isEnabled,
                memberOf: obj.memberOf ?? null,
                members: obj.members ?? null,
                properties: obj.properties ?? null,
              });
            } catch { /* skip duplicates */ }
          }
        }

        // Analyze attack surface
        const attackSurface = analyzeAttackSurface(enumResult);

        // Update enumeration run
        await db.update(adEnumerationRuns)
          .set({
            status: enumResult.errors.length > 0 ? "partial" : "completed",
            totalUsersFound: enumResult.summary.totalUsers,
            totalGroupsFound: enumResult.summary.totalGroups,
            totalComputersFound: enumResult.summary.totalComputers,
            totalGposFound: enumResult.summary.totalGpos,
            totalOusFound: enumResult.summary.totalOus,
            totalTrustsFound: enumResult.summary.totalTrusts,
            totalSpnsFound: enumResult.summary.totalSpns,
            privilegedUsersFound: enumResult.summary.privilegedUsers,
            kerberoastableFound: enumResult.summary.kerberoastableUsers,
            asrepRoastableFound: enumResult.summary.asrepRoastableUsers,
            results: { summary: enumResult.summary, attackSurface: { riskScore: attackSurface.riskScore, riskFactors: attackSurface.riskFactors } },
            errorLog: enumResult.errors.length > 0 ? enumResult.errors : null,
            completedAt: new Date(),
          })
          .where(eq(adEnumerationRuns.id, Number(runId)));

        // Update connection status
        await db.update(adDomainConnections)
          .set({
            status: "connected",
            lastEnumerationAt: new Date(),
            errorMessage: null,
          })
          .where(eq(adDomainConnections.id, input.connectionId));

        return {
          runId: Number(runId),
          success: true,
          summary: enumResult.summary,
          attackSurface: {
            riskScore: attackSurface.riskScore,
            riskFactors: attackSurface.riskFactors,
            kerberoastTargets: attackSurface.kerberoastTargets.length,
            asrepRoastTargets: attackSurface.asrepRoastTargets.length,
            privilegedAccounts: attackSurface.privilegedAccounts.length,
            vulnerableCertTemplates: attackSurface.vulnerableCertTemplates.length,
          },
          errors: enumResult.errors,
        };
      } catch (e: any) {
        await db.update(adEnumerationRuns)
          .set({ status: "error", errorLog: [e.message], completedAt: new Date() })
          .where(eq(adEnumerationRuns.id, Number(runId)));
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `AD enumeration failed: ${e.message}` });
      }
    }),

  /** List enumeration runs */
  listEnumerationRuns: protectedProcedure
    .input(z.object({
      connectionId: z.number().optional(),
      engagementId: z.number().optional(),
    }).optional())
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { adEnumerationRuns } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, and, desc } = await import("drizzle-orm");

      const conditions = [];
      if (input?.connectionId) conditions.push(eq(adEnumerationRuns.connectionId, input.connectionId));
      if (input?.engagementId) conditions.push(eq(adEnumerationRuns.engagementId, input.engagementId));

      const runs = conditions.length > 0
        ? await db.select().from(adEnumerationRuns).where(and(...conditions)).orderBy(desc(adEnumerationRuns.createdAt))
        : await db.select().from(adEnumerationRuns).orderBy(desc(adEnumerationRuns.createdAt));
      return runs;
    }),

  /** Get connector stats */
  getStats: protectedProcedure
    .input(z.object({}).optional())
    .query(async () => {
      const { getDb } = await import("../db");
      const { adDomainConnections, adEnumerationRuns } = await import("../../drizzle/schema");
      const { count } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [connCount] = await db.select({ count: count() }).from(adDomainConnections);
      const [runCount] = await db.select({ count: count() }).from(adEnumerationRuns);

      return {
        totalConnections: connCount.count,
        totalEnumerationRuns: runCount.count,
      };
    }),
});
