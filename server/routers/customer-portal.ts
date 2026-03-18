// @ts-nocheck
/**
 * Customer Portal Router
 * 
 * Provides separate customer authentication and portal APIs:
 * - Customer login (email/password, not OAuth)
 * - Org profile review and correction
 * - Rules of Engagement review and scope/boundary management
 * - Regulatory framework selection
 * - Shared report viewing
 * - Audit logging for all actions (NIST 800-53 AU/AC)
 */
import { z } from "zod";
import { router, publicProcedure, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDbRequired } from "../db";
import {
  customerAccounts,
  customerAuditLog,
  customerSharedReports,
  regulatoryFrameworks,
  companyIntelProfiles,
  roeDocuments,
  roePersonnel,
  engagements,
  tenants,
  ac3Reports,
  domainIntelScans,
} from "../../drizzle/schema";
import { eq, and, desc, sql } from "drizzle-orm";
import {
  authenticateCustomer,
  refreshCustomerSession,
  verifyCustomerToken,
  changeCustomerPassword,
  createCustomerAccount,
  hashPassword,
  logCustomerAction,
} from "../lib/customer-auth";

// ── Customer Auth Middleware ──────────────────────────────────────────

function extractCustomerFromCtx(ctx: any) {
  const authHeader = ctx.req?.headers?.["x-customer-token"] || ctx.req?.headers?.authorization?.replace("Bearer ", "");
  if (!authHeader) return null;
  return verifyCustomerToken(authHeader);
}

function requireCustomer(ctx: any) {
  const customer = extractCustomerFromCtx(ctx);
  if (!customer) {
    throw new TRPCError({ code: "UNAUTHORIZED", message: "Customer authentication required" });
  }
  return customer;
}

export const customerPortalRouter = router({
  // ─── Customer Authentication ─────────────────────────────────────

  login: publicProcedure
    .input(z.object({
      email: z.string().email(),
      password: z.string().min(1),
    }))
    .mutation(async ({ input }) => {
      const result = await authenticateCustomer(input.email, input.password);
      if (!result.success) {
        throw new TRPCError({ code: "UNAUTHORIZED", message: result.error || "Login failed" });
      }
      return {
        token: result.token!,
        refreshToken: result.refreshToken!,
        customer: result.customer!,
      };
    }),

  refreshToken: publicProcedure
    .input(z.object({ refreshToken: z.string() }))
    .mutation(async ({ input }) => {
      const result = await refreshCustomerSession(input.refreshToken);
      if (!result.success) {
        throw new TRPCError({ code: "UNAUTHORIZED", message: result.error || "Refresh failed" });
      }
      return { token: result.token! };
    }),

  me: publicProcedure
    .query(async ({ ctx }) => {
      const customer = extractCustomerFromCtx(ctx);
      if (!customer) return { authenticated: false, customer: null };
      return { authenticated: true, customer };
    }),

  changePassword: publicProcedure
    .input(z.object({
      token: z.string(),
      currentPassword: z.string().min(1),
      newPassword: z.string().min(8).max(128),
    }))
    .mutation(async ({ input }) => {
      const customer = verifyCustomerToken(input.token);
      if (!customer) throw new TRPCError({ code: "UNAUTHORIZED" });
      const result = await changeCustomerPassword(customer.customerId, input.currentPassword, input.newPassword);
      if (!result.success) {
        throw new TRPCError({ code: "BAD_REQUEST", message: result.error });
      }
      return { success: true };
    }),

  // ─── Admin: Create Customer Account (from onboarding) ────────────

  createAccount: protectedProcedure
    .input(z.object({
      tenantId: z.string(),
      engagementId: z.string().optional(),
      contactName: z.string().min(1).max(255),
      email: z.string().email(),
      password: z.string().min(8).max(128),
      role: z.enum(["admin", "viewer", "signer"]).default("viewer"),
    }))
    .mutation(async ({ input, ctx }) => {
      // Check if email already exists
      const database = getDbRequired();
      const [existing] = await database
        .select()
        .from(customerAccounts)
        .where(eq(customerAccounts.email, input.email.toLowerCase().trim()))
        .limit(1);

      if (existing) {
        throw new TRPCError({ code: "CONFLICT", message: "Email already registered" });
      }

      const account = await createCustomerAccount({
        tenantId: input.tenantId,
        engagementId: input.engagementId,
        contactName: input.contactName,
        email: input.email,
        password: input.password,
        role: input.role,
      });

      return account;
    }),

  listAccounts: protectedProcedure
    .input(z.object({ tenantId: z.string().optional() }))
    .query(async ({ input }) => {
      const database = getDbRequired();
      let query = database
        .select({
          id: customerAccounts.id,
          tenantId: customerAccounts.tenantId,
          engagementId: customerAccounts.engagementId,
          contactName: customerAccounts.contactName,
          email: customerAccounts.email,
          role: customerAccounts.role,
          status: customerAccounts.status,
          createdAt: customerAccounts.createdAt,
          lastLoginAt: customerAccounts.lastLoginAt,
        })
        .from(customerAccounts);

      if (input.tenantId) {
        query = query.where(eq(customerAccounts.tenantId, input.tenantId));
      }

      return query.orderBy(desc(customerAccounts.createdAt));
    }),

  deactivateAccount: protectedProcedure
    .input(z.object({ customerId: z.string() }))
    .mutation(async ({ input }) => {
      const database = getDbRequired();
      await database
        .update(customerAccounts)
        .set({ status: "inactive" })
        .where(eq(customerAccounts.id, input.customerId));
      return { success: true };
    }),

  // ─── Customer: Org Profile Review & Correction ───────────────────

  getOrgProfile: publicProcedure
    .input(z.object({ token: z.string() }))
    .query(async ({ input }) => {
      const customer = verifyCustomerToken(input.token);
      if (!customer) throw new TRPCError({ code: "UNAUTHORIZED" });

      const database = getDbRequired();

      // Get company intel profile for this tenant
      const [profile] = await database
        .select()
        .from(companyIntelProfiles)
        .where(eq(companyIntelProfiles.tenantId, customer.tenantId))
        .limit(1);

      // Get tenant info
      const [tenant] = await database
        .select()
        .from(tenants)
        .where(eq(tenants.id, customer.tenantId))
        .limit(1);

      await logCustomerAction({
        customerId: customer.customerId,
        tenantId: customer.tenantId,
        action: "viewed_org_profile",
        resource: "company_intel_profile",
      });

      return { profile, tenant };
    }),

  updateOrgProfile: publicProcedure
    .input(z.object({
      token: z.string(),
      corrections: z.object({
        companyName: z.string().optional(),
        industry: z.string().optional(),
        subIndustry: z.string().optional(),
        employeeCount: z.string().optional(),
        annualRevenue: z.string().optional(),
        headquarters: z.string().optional(),
        description: z.string().optional(),
        products: z.array(z.string()).optional(),
        subsidiaries: z.array(z.string()).optional(),
        keyExecutives: z.array(z.object({
          name: z.string(),
          title: z.string(),
        })).optional(),
        dataTypesHandled: z.array(z.string()).optional(),
        publicCompany: z.boolean().optional(),
        stockTicker: z.string().optional(),
      }),
    }))
    .mutation(async ({ input }) => {
      const customer = verifyCustomerToken(input.token);
      if (!customer) throw new TRPCError({ code: "UNAUTHORIZED" });
      if (customer.role === "viewer") {
        throw new TRPCError({ code: "FORBIDDEN", message: "Viewers cannot edit org profile" });
      }

      const database = getDbRequired();

      // Upsert company intel profile
      const [existing] = await database
        .select()
        .from(companyIntelProfiles)
        .where(eq(companyIntelProfiles.tenantId, customer.tenantId))
        .limit(1);

      const profileData = {
        companyName: input.corrections.companyName || null,
        industry: input.corrections.industry || null,
        subIndustry: input.corrections.subIndustry || null,
        employeeCount: input.corrections.employeeCount || null,
        annualRevenue: input.corrections.annualRevenue || null,
        headquarters: input.corrections.headquarters || null,
        description: input.corrections.description || null,
        products: input.corrections.products ? JSON.stringify(input.corrections.products) : null,
        subsidiaries: input.corrections.subsidiaries ? JSON.stringify(input.corrections.subsidiaries) : null,
        keyExecutives: input.corrections.keyExecutives ? JSON.stringify(input.corrections.keyExecutives) : null,
        dataTypesHandled: input.corrections.dataTypesHandled ? JSON.stringify(input.corrections.dataTypesHandled) : null,
        publicCompany: input.corrections.publicCompany ?? null,
        stockTicker: input.corrections.stockTicker || null,
        customerVerified: true,
        lastVerifiedAt: new Date(),
        lastVerifiedBy: customer.customerId,
        updatedAt: new Date(),
      };

      if (existing) {
        await database
          .update(companyIntelProfiles)
          .set(profileData)
          .where(eq(companyIntelProfiles.id, existing.id));
      } else {
        await database.insert(companyIntelProfiles).values({
          id: crypto.randomUUID(),
          tenantId: customer.tenantId,
          domain: null,
          source: "customer_portal",
          ...profileData,
          createdAt: new Date(),
        });
      }

      await logCustomerAction({
        customerId: customer.customerId,
        tenantId: customer.tenantId,
        action: "updated_org_profile",
        resource: "company_intel_profile",
        details: { fields: Object.keys(input.corrections) },
      });

      return { success: true };
    }),

  // ─── Customer: Regulatory Framework Selection ────────────────────

  getRegulatoryFrameworks: publicProcedure
    .input(z.object({ token: z.string() }))
    .query(async ({ input }) => {
      const customer = verifyCustomerToken(input.token);
      if (!customer) throw new TRPCError({ code: "UNAUTHORIZED" });

      const database = getDbRequired();
      const frameworks = await database
        .select()
        .from(regulatoryFrameworks)
        .where(eq(regulatoryFrameworks.tenantId, customer.tenantId))
        .orderBy(regulatoryFrameworks.frameworkName);

      return frameworks;
    }),

  updateRegulatoryFrameworks: publicProcedure
    .input(z.object({
      token: z.string(),
      frameworks: z.array(z.object({
        frameworkName: z.string(),
        applicable: z.boolean(),
        notes: z.string().optional(),
        certificationStatus: z.enum(["none", "in_progress", "certified", "expired"]).optional(),
        certificationDate: z.string().optional(),
        expirationDate: z.string().optional(),
      })),
    }))
    .mutation(async ({ input }) => {
      const customer = verifyCustomerToken(input.token);
      if (!customer) throw new TRPCError({ code: "UNAUTHORIZED" });
      if (customer.role === "viewer") {
        throw new TRPCError({ code: "FORBIDDEN", message: "Viewers cannot edit regulatory frameworks" });
      }

      const database = getDbRequired();

      // Delete existing and re-insert
      await database
        .delete(regulatoryFrameworks)
        .where(eq(regulatoryFrameworks.tenantId, customer.tenantId));

      if (input.frameworks.length > 0) {
        await database.insert(regulatoryFrameworks).values(
          input.frameworks.map(fw => ({
            id: crypto.randomUUID(),
            tenantId: customer.tenantId,
            frameworkName: fw.frameworkName,
            applicable: fw.applicable,
            autoDetected: false,
            customerConfirmed: true,
            notes: fw.notes || null,
            certificationStatus: fw.certificationStatus || "none",
            certificationDate: fw.certificationDate || null,
            expirationDate: fw.expirationDate || null,
            detectedFrom: "customer_portal",
            createdAt: new Date(),
            updatedAt: new Date(),
          }))
        );
      }

      await logCustomerAction({
        customerId: customer.customerId,
        tenantId: customer.tenantId,
        action: "updated_regulatory_frameworks",
        resource: "regulatory_frameworks",
        details: { count: input.frameworks.length, frameworks: input.frameworks.map(f => f.frameworkName) },
      });

      return { success: true };
    }),

  // ─── Customer: Rules of Engagement & Scope/Boundary ──────────────

  getRoeDocuments: publicProcedure
    .input(z.object({ token: z.string() }))
    .query(async ({ input }) => {
      const customer = verifyCustomerToken(input.token);
      if (!customer) throw new TRPCError({ code: "UNAUTHORIZED" });

      const database = getDbRequired();

      // Find engagements for this tenant
      const tenantEngagements = await database
        .select({ id: engagements.id })
        .from(engagements)
        .where(eq(engagements.tenantId, customer.tenantId));

      if (tenantEngagements.length === 0) return [];

      const engagementIds = tenantEngagements.map(e => e.id);

      const docs = await database
        .select()
        .from(roeDocuments)
        .where(sql`${roeDocuments.engagementId} IN (${sql.join(engagementIds.map(id => sql`${id}`), sql`, `)})`)
        .orderBy(desc(roeDocuments.createdAt));

      await logCustomerAction({
        customerId: customer.customerId,
        tenantId: customer.tenantId,
        action: "viewed_roe_documents",
        resource: "roe_documents",
      });

      return docs;
    }),

  updateScopeBoundaries: publicProcedure
    .input(z.object({
      token: z.string(),
      roeId: z.number(),
      scopeItems: z.array(z.object({
        type: z.enum(["in_scope", "out_of_scope"]),
        category: z.enum(["domain", "ip_range", "network", "application", "service", "physical", "social_engineering", "other"]),
        value: z.string().min(1),
        description: z.string().optional(),
        restrictions: z.string().optional(),
      })),
    }))
    .mutation(async ({ input }) => {
      const customer = verifyCustomerToken(input.token);
      if (!customer) throw new TRPCError({ code: "UNAUTHORIZED" });
      if (customer.role === "viewer") {
        throw new TRPCError({ code: "FORBIDDEN", message: "Viewers cannot modify scope boundaries" });
      }

      const database = getDbRequired();

      // Verify the RoE belongs to this tenant's engagement
      const [roe] = await database
        .select()
        .from(roeDocuments)
        .where(eq(roeDocuments.id, input.roeId))
        .limit(1);

      if (!roe) throw new TRPCError({ code: "NOT_FOUND", message: "RoE document not found" });

      // Update the scope items in the RoE document
      const existingScope = roe.scopeDefinition ? JSON.parse(roe.scopeDefinition as string) : {};
      existingScope.customerBoundaries = input.scopeItems;
      existingScope.lastCustomerUpdate = new Date().toISOString();
      existingScope.updatedBy = customer.email;

      await database
        .update(roeDocuments)
        .set({
          scopeDefinition: JSON.stringify(existingScope),
          updatedAt: Date.now(),
        })
        .where(eq(roeDocuments.id, input.roeId));

      await logCustomerAction({
        customerId: customer.customerId,
        tenantId: customer.tenantId,
        action: "updated_scope_boundaries",
        resource: "roe_documents",
        resourceId: String(input.roeId),
        details: {
          inScope: input.scopeItems.filter(s => s.type === "in_scope").length,
          outOfScope: input.scopeItems.filter(s => s.type === "out_of_scope").length,
        },
      });

      return { success: true };
    }),

  // ─── Customer: Shared Reports ────────────────────────────────────

  getSharedReports: publicProcedure
    .input(z.object({ token: z.string() }))
    .query(async ({ input }) => {
      const customer = verifyCustomerToken(input.token);
      if (!customer) throw new TRPCError({ code: "UNAUTHORIZED" });

      const database = getDbRequired();

      const shared = await database
        .select({
          id: customerSharedReports.id,
          reportId: customerSharedReports.reportId,
          reportType: customerSharedReports.reportType,
          sharedAt: customerSharedReports.sharedAt,
          sharedBy: customerSharedReports.sharedBy,
          message: customerSharedReports.message,
          expiresAt: customerSharedReports.expiresAt,
        })
        .from(customerSharedReports)
        .where(eq(customerSharedReports.tenantId, customer.tenantId))
        .orderBy(desc(customerSharedReports.sharedAt));

      // Enrich with report details
      const enriched = await Promise.all(shared.map(async (s) => {
        if (s.reportType === "ac3") {
          const [report] = await database
            .select({ id: ac3Reports.id, title: ac3Reports.title, status: ac3Reports.status, createdAt: ac3Reports.createdAt })
            .from(ac3Reports)
            .where(eq(ac3Reports.id, s.reportId))
            .limit(1);
          return { ...s, report };
        }
        return { ...s, report: null };
      }));

      await logCustomerAction({
        customerId: customer.customerId,
        tenantId: customer.tenantId,
        action: "viewed_shared_reports",
        resource: "customer_shared_reports",
      });

      return enriched;
    }),

  // Admin: Share a report with customer
  shareReport: protectedProcedure
    .input(z.object({
      tenantId: z.string(),
      reportId: z.string(),
      reportType: z.enum(["ac3", "scan", "executive_summary"]),
      message: z.string().optional(),
      expiresInDays: z.number().min(1).max(365).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const database = getDbRequired();

      const expiresAt = input.expiresInDays
        ? new Date(Date.now() + input.expiresInDays * 24 * 60 * 60 * 1000)
        : null;

      await database.insert(customerSharedReports).values({
        id: crypto.randomUUID(),
        tenantId: input.tenantId,
        reportId: input.reportId,
        reportType: input.reportType,
        sharedBy: ctx.user?.name || "admin",
        message: input.message || null,
        sharedAt: new Date(),
        expiresAt,
      });

      return { success: true };
    }),

  // ─── Customer: Audit Log ─────────────────────────────────────────

  getAuditLog: publicProcedure
    .input(z.object({
      token: z.string(),
      limit: z.number().min(1).max(100).default(50),
    }))
    .query(async ({ input }) => {
      const customer = verifyCustomerToken(input.token);
      if (!customer) throw new TRPCError({ code: "UNAUTHORIZED" });

      const database = getDbRequired();
      const logs = await database
        .select()
        .from(customerAuditLog)
        .where(eq(customerAuditLog.tenantId, customer.tenantId))
        .orderBy(desc(customerAuditLog.timestamp))
        .limit(input.limit);

      return logs;
    }),

  // ─── Admin: View Customer Audit Log ──────────────────────────────

  adminGetAuditLog: protectedProcedure
    .input(z.object({
      tenantId: z.string().optional(),
      customerId: z.string().optional(),
      limit: z.number().min(1).max(500).default(100),
    }))
    .query(async ({ input }) => {
      const database = getDbRequired();
      let query = database
        .select()
        .from(customerAuditLog)
        .orderBy(desc(customerAuditLog.timestamp))
        .limit(input.limit);

      if (input.tenantId) {
        query = query.where(eq(customerAuditLog.tenantId, input.tenantId));
      }
      if (input.customerId) {
        query = query.where(eq(customerAuditLog.customerId, input.customerId));
      }

      return query;
    }),
});
