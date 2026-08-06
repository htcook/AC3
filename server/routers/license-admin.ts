/**
 * License Admin Router
 * ────────────────────
 * Admin-only tRPC endpoints for license management, update publishing, and analytics.
 */

import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import {
  issueLicense,
  listLicenses,
  getLicenseByOrgId,
  revokeLicense,
  renewLicense,
  getLicenseAnalytics,
  getFullLicenseKey,
  logUsage,
} from "../lib/license-manager";
import {
  checkForUpdates,
  getChangelog,
  publishVersion,
  applyUpdate,
  getUpdateHistory,
  getCurrentVersion,
} from "../lib/update-manager";

// Admin guard
const adminProcedure = protectedProcedure.use(({ ctx, next }) => {
  if (ctx.user.role !== "admin") {
    throw new TRPCError({ code: "FORBIDDEN", message: "Admin access required" });
  }
  return next({ ctx });
});

export const licenseAdminRouter = router({
  // ─── License CRUD ───────────────────────────────────────────────────────

  issueLicense: adminProcedure
    .input(
      z.object({
        orgName: z.string().min(1).max(255),
        contactEmail: z.string().email().optional(),
        contactName: z.string().max(255).optional(),
        tier: z.enum(["starter", "professional", "enterprise"]),
        expiryDays: z.number().int().min(1).max(3650),
        maxSeats: z.number().int().min(1).optional(),
        maxScansPerPeriod: z.number().int().min(1).optional(),
        billingPeriodDays: z.number().int().min(1).optional(),
        gracePeriodDays: z.number().int().min(0).optional(),
        featureOverrides: z.record(z.boolean()).optional(),
        deploymentDomain: z.string().max(255).optional(),
        notes: z.string().max(2000).optional(),
      })
    )
    .mutation(async ({ input }) => {
      return issueLicense(input);
    }),

  listLicenses: adminProcedure
    .input(
      z
        .object({
          status: z.string().optional(),
          tier: z.string().optional(),
          limit: z.number().int().min(1).max(200).optional(),
          offset: z.number().int().min(0).optional(),
        })
        .optional()
    )
    .query(async ({ input }) => {
      return listLicenses(input ?? undefined);
    }),

  getLicense: adminProcedure
    .input(z.object({ orgId: z.string() }))
    .query(async ({ input }) => {
      const license = await getLicenseByOrgId(input.orgId);
      if (!license) throw new TRPCError({ code: "NOT_FOUND", message: "License not found" });
      return license;
    }),

  getFullLicenseKey: adminProcedure
    .input(z.object({ orgId: z.string() }))
    .query(async ({ input }) => {
      const key = await getFullLicenseKey(input.orgId);
      if (!key) throw new TRPCError({ code: "NOT_FOUND", message: "License not found" });
      return { licenseKey: key };
    }),

  revokeLicense: adminProcedure
    .input(
      z.object({
        orgId: z.string(),
        reason: z.string().min(1).max(1000),
      })
    )
    .mutation(async ({ input }) => {
      return revokeLicense(input.orgId, input.reason);
    }),

  renewLicense: adminProcedure
    .input(
      z.object({
        orgId: z.string(),
        additionalDays: z.number().int().min(1).max(3650),
      })
    )
    .mutation(async ({ input }) => {
      const result = await renewLicense(input.orgId, input.additionalDays);
      if (!result) throw new TRPCError({ code: "NOT_FOUND", message: "License not found" });
      return result;
    }),

  // ─── Analytics ──────────────────────────────────────────────────────────

  getAnalytics: adminProcedure.query(async () => {
    return getLicenseAnalytics();
  }),

  // ─── Update Management ────────────────────────────────────────────────

  getCurrentVersion: adminProcedure.query(() => {
    return { version: getCurrentVersion() };
  }),

  checkForUpdates: adminProcedure
    .input(
      z
        .object({
          currentVersion: z.string().optional(),
          channel: z.string().optional(),
        })
        .optional()
    )
    .query(async ({ input }) => {
      return checkForUpdates(input?.currentVersion, input?.channel);
    }),

  getChangelog: adminProcedure
    .input(
      z
        .object({
          channel: z.string().optional(),
          limit: z.number().int().min(1).max(100).optional(),
          sinceVersion: z.string().optional(),
        })
        .optional()
    )
    .query(async ({ input }) => {
      return getChangelog(input ?? undefined);
    }),

  publishVersion: adminProcedure
    .input(
      z.object({
        version: z.string().min(1),
        changelog: z.string().min(1),
        channel: z.string().optional(),
        migrationScript: z.string().optional(),
        minPreviousVersion: z.string().optional(),
        downloadUrl: z.string().url().optional(),
        checksumSha256: z.string().optional(),
        isBreaking: z.boolean().optional(),
        isRequired: z.boolean().optional(),
      })
    )
    .mutation(async ({ input }) => {
      await publishVersion(input);
      return { success: true };
    }),

  applyUpdate: adminProcedure
    .input(
      z.object({
        targetVersion: z.string(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const orgId = process.env.WL_ORG_ID ?? "self";
      return applyUpdate(orgId, input.targetVersion);
    }),

  getUpdateHistory: adminProcedure
    .input(z.object({ orgId: z.string().optional() }).optional())
    .query(async ({ input }) => {
      return getUpdateHistory(input?.orgId);
    }),
});
