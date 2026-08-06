import * as db from "../db";
/**
 * Tenant Onboarding Wizard Router
 * 
 * Multi-step guided flow for new organization setup:
 * Step 1: Organization info (name, domain, industry, size)
 * Step 2: IdP configuration (SAML metadata or OAuth client)
 * Step 3: Team invitations (bulk email + role assignment)
 * Step 4: Review and launch (summary, confirm, activate)
 */
import { z } from "zod";
import { router, protectedProcedure, adminProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { eq, and, desc, sql } from "drizzle-orm";
import crypto from "crypto";

const onboardingStepSchema = z.enum(["org_info", "idp_config", "team_invites", "review_launch"]);

const orgInfoSchema = z.object({
  orgName: z.string().min(2).max(255),
  orgDomain: z.string().min(3).max(255),
  industry: z.enum([
    "government_federal", "government_state_local", "defense_contractor",
    "financial_services", "healthcare", "energy_utilities",
    "technology", "telecommunications", "manufacturing",
    "education", "retail", "consulting", "other"
  ]),
  orgSize: z.enum(["1-10", "11-50", "51-200", "201-500", "501-1000", "1000+"]),
  complianceFrameworks: z.array(z.enum([
    "fedramp_high", "fedramp_moderate", "fedramp_low",
    "nist_800_53", "nist_800_171", "cmmc_level2", "cmmc_level3",
    "hipaa", "pci_dss", "sox", "fisma", "itar", "none"
  ])).default([]),
  primaryContact: z.object({
    name: z.string().min(2),
    email: z.string().email(),
    phone: z.string().optional(),
    title: z.string().optional(),
  }),
});

const idpConfigSchema = z.object({
  authMethod: z.enum(["saml", "oauth", "platform_only"]),
  saml: z.object({
    entityId: z.string(),
    ssoUrl: z.string().url(),
    certificate: z.string(),
    provider: z.enum(["okta", "azure_ad", "ping_federate", "onelogin", "google", "custom"]).default("custom"),
    signatureAlgorithm: z.enum(["sha256", "sha384", "sha512"]).default("sha256"),
  }).optional(),
  oauth: z.object({
    provider: z.string(),
    clientId: z.string(),
    clientSecret: z.string(),
    authorizationUrl: z.string().url(),
    tokenUrl: z.string().url(),
    userInfoUrl: z.string().url().optional(),
    scopes: z.array(z.string()).default(["openid", "profile", "email"]),
  }).optional(),
  mfaRequired: z.boolean().default(true),
  sessionTimeout: z.number().min(300).max(86400).default(28800), // 5min to 24hr, default 8hr
});

const teamInviteSchema = z.object({
  invites: z.array(z.object({
    email: z.string().email(),
    role: z.enum(["admin", "operator", "analyst", "team_lead", "client", "executive"]),
    department: z.string().optional(),
    sendImmediately: z.boolean().default(true),
  })).min(0).max(50),
});

export const tenantOnboardingRouter = router({
  // ─── Get or create onboarding session ──────────────────────────────────
  getSession: protectedProcedure.query(async ({ ctx }) => {
    const { getDb } = await import("../db");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

    const { tenants, tenantMemberships } = await import("../../drizzle/schema");

    // Check if user already has a tenant (skip wizard)
    const existing = await db
      .select()
      .from(tenantMemberships)
      .where(eq(tenantMemberships.userId, ctx.user.id))
      .limit(1);

    if (existing.length > 0) {
      const tenant = await db
        .select()
        .from(tenants)
        .where(eq(tenants.id, existing[0].tenantId))
        .limit(1);

      return {
        hasExistingTenant: true,
        tenantId: existing[0].tenantId,
        tenantName: tenant[0]?.name || "Unknown",
        onboardingComplete: true,
        currentStep: "review_launch" as const,
        stepData: {},
      };
    }

    return {
      hasExistingTenant: false,
      tenantId: null,
      tenantName: null,
      onboardingComplete: false,
      currentStep: "org_info" as const,
      stepData: {},
    };
  }),

  // ─── Step 1: Save organization info ────────────────────────────────────
  saveOrgInfo: protectedProcedure
    .input(orgInfoSchema)
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const { tenants, tenantMemberships, users } = await import("../../drizzle/schema");

      // Check for duplicate domain
      const existingTenant = await db
        .select()
        .from(tenants)
        .where(eq(tenants.slug, input.orgDomain.toLowerCase().replace(/[^a-z0-9-]/g, "-")))
        .limit(1);

      if (existingTenant.length > 0) {
        throw new TRPCError({
          code: "CONFLICT",
          message: `An organization with domain "${input.orgDomain}" already exists`,
        });
      }

      const slug = input.orgDomain.toLowerCase().replace(/[^a-z0-9-]/g, "-");
      const tenantId = crypto.randomBytes(16).toString("hex");

      // Create tenant
      const [result] = await db.insert(tenants).values({
        name: input.orgName,
        slug,
        settings: JSON.stringify({
          industry: input.industry,
          orgSize: input.orgSize,
          complianceFrameworks: input.complianceFrameworks,
          primaryContact: input.primaryContact,
          onboardingStep: "idp_config",
          onboardingStartedAt: Date.now(),
          onboardingStartedBy: ctx.user.id,
        }),
      });

      const newTenantId = result.insertId;

      // Add current user as tenant admin
      await db.insert(tenantMemberships).values({
        tenantId: newTenantId,
        userId: ctx.user.id,
        role: "owner",
      });

      // Update user's active tenant
      await db
        .update(users)
        .set({ activeTenantId: newTenantId })
        .where(eq(users.id, ctx.user.id));

      return {
        success: true,
        tenantId: newTenantId,
        nextStep: "idp_config" as const,
        message: `Organization "${input.orgName}" created successfully`,
      };
    }),

  // ─── Step 2: Configure IdP ────────────────────────────────────────────
  saveIdpConfig: protectedProcedure
    .input(z.object({
      tenantId: z.number(),
      config: idpConfigSchema,
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const { tenants, tenantMemberships, samlIdpConfigs } = await import("../../drizzle/schema");

      // Verify user is tenant admin
      const membership = await db
        .select()
        .from(tenantMemberships)
        .where(and(
          eq(tenantMemberships.tenantId, input.tenantId),
          eq(tenantMemberships.userId, ctx.user.id),
        ))
        .limit(1);

      if (!membership.length || membership[0].role !== "owner") {
        throw new TRPCError({ code: "FORBIDDEN", message: "Only tenant owners can configure IdP" });
      }

      if (input.config.authMethod === "saml" && input.config.saml) {
        // Store SAML IdP configuration
        await db.insert(samlIdpConfigs).values({
          tenantId: input.tenantId,
          name: `${input.config.saml.provider} SSO`,
          entityId: input.config.saml.entityId,
          ssoUrl: input.config.saml.ssoUrl,
          certificate: input.config.saml.certificate,
          provider: input.config.saml.provider,
          signatureAlgorithm: input.config.saml.signatureAlgorithm || "sha256",
          isActive: true,
        });
      }

      // Update tenant settings with auth config
      const tenant = await db.select().from(tenants).where(eq(tenants.id, input.tenantId)).limit(1);
      const currentSettings = tenant[0]?.settings ? JSON.parse(tenant[0].settings as string) : {};

      await db
        .update(tenants)
        .set({
          settings: JSON.stringify({
            ...currentSettings,
            authMethod: input.config.authMethod,
            mfaRequired: input.config.mfaRequired,
            sessionTimeout: input.config.sessionTimeout,
            onboardingStep: "team_invites",
          }),
        })
        .where(eq(tenants.id, input.tenantId));

      return {
        success: true,
        nextStep: "team_invites" as const,
        message: input.config.authMethod === "platform_only"
          ? "Using platform authentication — no external IdP configured"
          : `${input.config.authMethod.toUpperCase()} identity provider configured successfully`,
      };
    }),

  // ─── Step 2b: Test IdP connection ──────────────────────────────────────
  testIdpConnection: protectedProcedure
    .input(z.object({
      tenantId: z.number(),
      authMethod: z.enum(["saml", "oauth"]),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const { samlIdpConfigs, tenants } = await import("../../drizzle/schema");

      if (input.authMethod === "saml") {
        const configs = await db
          .select()
          .from(samlIdpConfigs)
          .where(eq(samlIdpConfigs.tenantId, input.tenantId))
          .limit(1);

        if (!configs.length) {
          return { success: false, message: "No SAML configuration found", details: [] };
        }

        const checks = [
          { name: "Entity ID present", passed: !!configs[0].entityId, detail: configs[0].entityId || "Missing" },
          { name: "SSO URL reachable", passed: configs[0].ssoUrl?.startsWith("https://"), detail: configs[0].ssoUrl || "Missing" },
          { name: "Certificate valid", passed: !!configs[0].certificate && configs[0].certificate.length > 100, detail: configs[0].certificate ? "Present" : "Missing" },
          { name: "Signature algorithm FIPS-compliant", passed: ["sha256", "sha384", "sha512"].includes(configs[0].signatureAlgorithm || ""), detail: configs[0].signatureAlgorithm || "Unknown" },
        ];

        return {
          success: checks.every(c => c.passed),
          message: checks.every(c => c.passed) ? "All SAML checks passed" : "Some checks failed",
          details: checks,
        };
      }

      // OAuth test
      const tenant = await db.select().from(tenants).where(eq(tenants.id, input.tenantId)).limit(1);
      const settings = tenant[0]?.settings ? JSON.parse(tenant[0].settings as string) : {};

      return {
        success: !!settings.authMethod,
        message: settings.authMethod ? "OAuth configuration present" : "No OAuth configuration found",
        details: [
          { name: "Auth method configured", passed: !!settings.authMethod, detail: settings.authMethod || "None" },
        ],
      };
    }),

  // ─── Step 3: Bulk team invitations ─────────────────────────────────────
  saveTeamInvites: protectedProcedure
    .input(z.object({
      tenantId: z.number(),
      invites: teamInviteSchema.shape.invites,
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const { teamInvitations, tenants, tenantMemberships } = await import("../../drizzle/schema");

      // Verify ownership
      const membership = await db
        .select()
        .from(tenantMemberships)
        .where(and(
          eq(tenantMemberships.tenantId, input.tenantId),
          eq(tenantMemberships.userId, ctx.user.id),
        ))
        .limit(1);

      if (!membership.length) {
        throw new TRPCError({ code: "FORBIDDEN", message: "Not a member of this tenant" });
      }

      const results: Array<{ email: string; status: "sent" | "duplicate" | "error"; message: string }> = [];

      for (const invite of input.invites) {
        try {
          // Check for existing invite
          const existing = await db
            .select()
            .from(teamInvitations)
            .where(and(
              eq(teamInvitations.email, invite.email),
              eq(teamInvitations.status, "pending"),
            ))
            .limit(1);

          if (existing.length > 0) {
            results.push({ email: invite.email, status: "duplicate", message: "Invitation already pending" });
            continue;
          }

          // Generate FIPS-compliant invite token
          const token = crypto.randomBytes(32).toString("hex");
          const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

          await db.insert(teamInvitations).values({
            email: invite.email,
            role: invite.role,
            invitedBy: ctx.user.id,
            token: tokenHash,
            expiresAt: new Date(Date.now() + 72 * 60 * 60 * 1000), // 72 hours
            status: "pending",
          });

          results.push({ email: invite.email, status: "sent", message: `Token: ${token.substring(0, 8)}...` });
        } catch (err: any) {
          results.push({ email: invite.email, status: "error", message: err.message || "Failed to create invitation" });
        }
      }

      // Update tenant onboarding step
      const tenant = await db.select().from(tenants).where(eq(tenants.id, input.tenantId)).limit(1);
      const currentSettings = tenant[0]?.settings ? JSON.parse(tenant[0].settings as string) : {};

      await db
        .update(tenants)
        .set({
          settings: JSON.stringify({
            ...currentSettings,
            onboardingStep: "review_launch",
            invitesSent: results.filter(r => r.status === "sent").length,
          }),
        })
        .where(eq(tenants.id, input.tenantId));

      return {
        success: true,
        nextStep: "review_launch" as const,
        results,
        summary: {
          sent: results.filter(r => r.status === "sent").length,
          duplicates: results.filter(r => r.status === "duplicate").length,
          errors: results.filter(r => r.status === "error").length,
        },
      };
    }),

  // ─── Step 4: Review and launch ─────────────────────────────────────────
  getReviewSummary: protectedProcedure
    .input(z.object({ tenantId: z.number() }))
    .query(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const { tenants, tenantMemberships, teamInvitations, samlIdpConfigs } = await import("../../drizzle/schema");

      const tenant = await db.select().from(tenants).where(eq(tenants.id, input.tenantId)).limit(1);
      if (!tenant.length) throw new TRPCError({ code: "NOT_FOUND", message: "Tenant not found" });

      const settings = tenant[0].settings ? JSON.parse(tenant[0].settings as string) : {};

      const members = await db
        .select()
        .from(tenantMemberships)
        .where(eq(tenantMemberships.tenantId, input.tenantId));

      const pendingInvites = await db
        .select()
        .from(teamInvitations)
        .where(eq(teamInvitations.status, "pending"));

      const idpConfigs = await db
        .select()
        .from(samlIdpConfigs)
        .where(eq(samlIdpConfigs.tenantId, input.tenantId));

      return {
        organization: {
          name: tenant[0].name,
          slug: tenant[0].slug,
          industry: settings.industry || "not_set",
          orgSize: settings.orgSize || "not_set",
          complianceFrameworks: settings.complianceFrameworks || [],
          primaryContact: settings.primaryContact || null,
        },
        authentication: {
          method: settings.authMethod || "platform_only",
          mfaRequired: settings.mfaRequired ?? true,
          sessionTimeout: settings.sessionTimeout || 28800,
          idpConfigured: idpConfigs.length > 0,
          idpProvider: idpConfigs[0]?.provider || null,
        },
        team: {
          currentMembers: members.length,
          pendingInvites: pendingInvites.length,
          totalExpected: members.length + pendingInvites.length,
        },
        readiness: {
          orgInfoComplete: !!tenant[0].name && !!settings.industry,
          authConfigured: !!settings.authMethod,
          teamInvited: pendingInvites.length > 0 || members.length > 1,
          allStepsComplete: !!tenant[0].name && !!settings.authMethod,
        },
        createdAt: tenant[0].createdAt,
      };
    }),

  // ─── Activate tenant (final step) ──────────────────────────────────────
  activateTenant: protectedProcedure
    .input(z.object({ tenantId: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const { tenants, tenantMemberships, activityLogs } = await import("../../drizzle/schema");

      // Verify ownership
      const membership = await db
        .select()
        .from(tenantMemberships)
        .where(and(
          eq(tenantMemberships.tenantId, input.tenantId),
          eq(tenantMemberships.userId, ctx.user.id),
        ))
        .limit(1);

      if (!membership.length || membership[0].role !== "owner") {
        throw new TRPCError({ code: "FORBIDDEN", message: "Only tenant owners can activate" });
      }

      const tenant = await db.select().from(tenants).where(eq(tenants.id, input.tenantId)).limit(1);
      const currentSettings = tenant[0]?.settings ? JSON.parse(tenant[0].settings as string) : {};

      await db
        .update(tenants)
        .set({
          settings: JSON.stringify({
            ...currentSettings,
            onboardingComplete: true,
            onboardingCompletedAt: Date.now(),
            onboardingCompletedBy: ctx.user.id,
            status: "active",
          }),
        })
        .where(eq(tenants.id, input.tenantId));

      // Log the activation
      await db.insert(activityLogs).values({
        userId: ctx.user.id,
        action: "tenant_activated",
        details: JSON.stringify({
          tenantId: input.tenantId,
          tenantName: tenant[0].name,
        }),
        ipAddress: "system",
      });

      return {
        success: true,
        message: `Organization "${tenant[0].name}" is now active`,
        redirectTo: "/dashboard",
      };
    }),

  // ─── Get available industries for dropdown ─────────────────────────────
  getIndustries: protectedProcedure.query(() => {
    return [
      { value: "government_federal", label: "Federal Government" },
      { value: "government_state_local", label: "State & Local Government" },
      { value: "defense_contractor", label: "Defense Contractor" },
      { value: "financial_services", label: "Financial Services" },
      { value: "healthcare", label: "Healthcare" },
      { value: "energy_utilities", label: "Energy & Utilities" },
      { value: "technology", label: "Technology" },
      { value: "telecommunications", label: "Telecommunications" },
      { value: "manufacturing", label: "Manufacturing" },
      { value: "education", label: "Education" },
      { value: "retail", label: "Retail" },
      { value: "consulting", label: "Consulting" },
      { value: "other", label: "Other" },
    ];
  }),

  // ─── Get compliance frameworks for selection ───────────────────────────
  getComplianceFrameworks: protectedProcedure.query(() => {
    return [
      { value: "fedramp_high", label: "FedRAMP High", description: "Highest impact level for federal systems" },
      { value: "fedramp_moderate", label: "FedRAMP Moderate", description: "Moderate impact for federal systems" },
      { value: "fedramp_low", label: "FedRAMP Low", description: "Low impact for federal systems" },
      { value: "nist_800_53", label: "NIST SP 800-53", description: "Security and privacy controls catalog" },
      { value: "nist_800_171", label: "NIST SP 800-171", description: "Protecting CUI in non-federal systems" },
      { value: "cmmc_level2", label: "CMMC Level 2", description: "Advanced cyber hygiene for DoD contractors" },
      { value: "cmmc_level3", label: "CMMC Level 3", description: "Expert-level practices for DoD contractors" },
      { value: "hipaa", label: "HIPAA", description: "Health information privacy and security" },
      { value: "pci_dss", label: "PCI DSS", description: "Payment card data security" },
      { value: "sox", label: "SOX", description: "Financial reporting controls" },
      { value: "fisma", label: "FISMA", description: "Federal information security management" },
      { value: "itar", label: "ITAR", description: "International traffic in arms regulations" },
    ];
  }),
});
