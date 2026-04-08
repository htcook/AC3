/**
 * License Manager
 * ───────────────
 * Server-side CRUD for issued licenses, usage logging, and analytics.
 * Wraps the licensedOrganizations + licenseUsageLogs tables.
 */

import { getDb } from "../_core/db";
import { licensedOrganizations, licenseUsageLogs } from "../../drizzle/schema";
import { eq, desc, and, gte, lte, sql, count } from "drizzle-orm";
import { generateLicenseKey, type GenerateLicenseOptions } from "./licensing";
import crypto from "crypto";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface IssueLicenseInput {
  orgName: string;
  contactEmail?: string;
  contactName?: string;
  tier: "starter" | "professional" | "enterprise";
  expiryDays: number;
  maxSeats?: number;
  maxScansPerPeriod?: number;
  billingPeriodDays?: number;
  gracePeriodDays?: number;
  featureOverrides?: Record<string, boolean>;
  deploymentDomain?: string;
  notes?: string;
}

export interface LicenseRecord {
  id: number;
  orgId: string;
  orgName: string;
  contactEmail: string | null;
  contactName: string | null;
  tier: string;
  licenseKey: string;
  status: string;
  issuedAt: number;
  expiresAt: number;
  revokedAt: number | null;
  revokedReason: string | null;
  maxSeats: number;
  maxScansPerPeriod: number;
  billingPeriodDays: number;
  gracePeriodDays: number;
  featureOverrides: Record<string, boolean> | null;
  deploymentDomain: string | null;
  notes: string | null;
}

export interface LicenseAnalytics {
  totalLicenses: number;
  activeLicenses: number;
  expiredLicenses: number;
  revokedLicenses: number;
  tierDistribution: { tier: string; count: number }[];
  recentUsage: { date: string; scans: number; reports: number }[];
  topOrgs: { orgId: string; orgName: string; totalScans: number }[];
  expiringWithin30Days: number;
  totalRevenue: { starter: number; professional: number; enterprise: number };
}

// ─── Generate Unique Org ID ─────────────────────────────────────────────────

function generateOrgId(orgName: string): string {
  const slug = orgName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 30);
  const suffix = crypto.randomBytes(4).toString("hex");
  return `${slug}-${suffix}`;
}

function hashKey(key: string): string {
  return crypto.createHash("sha256").update(key).digest("hex").slice(0, 64);
}

// ─── Issue License ──────────────────────────────────────────────────────────

export async function issueLicense(input: IssueLicenseInput): Promise<LicenseRecord> {
  const db = await getDb();
  const orgId = generateOrgId(input.orgName);
  const now = Date.now();
  const expiresAt = now + input.expiryDays * 24 * 60 * 60 * 1000;

  const licenseKey = generateLicenseKey({
    org: orgId,
    orgName: input.orgName,
    tier: input.tier,
    features: input.featureOverrides as any,
    seats: input.maxSeats,
    scans: input.maxScansPerPeriod,
    expiryDays: input.expiryDays,
    billingPeriodDays: input.billingPeriodDays,
    gracePeriodDays: input.gracePeriodDays,
    deploymentId: `deploy-${orgId}`,
  });

  const keyHash = hashKey(licenseKey);

  await db.insert(licensedOrganizations).values({
    orgId,
    orgName: input.orgName,
    contactEmail: input.contactEmail ?? null,
    contactName: input.contactName ?? null,
    tier: input.tier,
    licenseKey,
    licenseKeyHash: keyHash,
    status: "active",
    issuedAt: now,
    expiresAt,
    maxSeats: input.maxSeats ?? (input.tier === "starter" ? 5 : input.tier === "professional" ? 25 : -1),
    maxScansPerPeriod: input.maxScansPerPeriod ?? (input.tier === "starter" ? 50 : input.tier === "professional" ? 500 : -1),
    billingPeriodDays: input.billingPeriodDays ?? 30,
    gracePeriodDays: input.gracePeriodDays ?? 7,
    featureOverrides: input.featureOverrides ?? null,
    deploymentDomain: input.deploymentDomain ?? null,
    notes: input.notes ?? null,
  });

  // Log the issuance
  await logUsage(orgId, "license_issued", "license", orgId, { tier: input.tier });

  return {
    id: 0, // Will be auto-assigned
    orgId,
    orgName: input.orgName,
    contactEmail: input.contactEmail ?? null,
    contactName: input.contactName ?? null,
    tier: input.tier,
    licenseKey,
    status: "active",
    issuedAt: now,
    expiresAt,
    revokedAt: null,
    revokedReason: null,
    maxSeats: input.maxSeats ?? (input.tier === "starter" ? 5 : input.tier === "professional" ? 25 : -1),
    maxScansPerPeriod: input.maxScansPerPeriod ?? (input.tier === "starter" ? 50 : input.tier === "professional" ? 500 : -1),
    billingPeriodDays: input.billingPeriodDays ?? 30,
    gracePeriodDays: input.gracePeriodDays ?? 7,
    featureOverrides: input.featureOverrides ?? null,
    deploymentDomain: input.deploymentDomain ?? null,
    notes: input.notes ?? null,
  };
}

// ─── List Licenses ──────────────────────────────────────────────────────────

export async function listLicenses(filters?: {
  status?: string;
  tier?: string;
  limit?: number;
  offset?: number;
}): Promise<{ licenses: any[]; total: number }> {
  const db = await getDb();
  const conditions: any[] = [];

  if (filters?.status) conditions.push(eq(licensedOrganizations.status, filters.status));
  if (filters?.tier) conditions.push(eq(licensedOrganizations.tier, filters.tier));

  const where = conditions.length > 0 ? and(...conditions) : undefined;

  const [rows, totalResult] = await Promise.all([
    db
      .select()
      .from(licensedOrganizations)
      .where(where)
      .orderBy(desc(licensedOrganizations.issuedAt))
      .limit(filters?.limit ?? 50)
      .offset(filters?.offset ?? 0),
    db
      .select({ count: count() })
      .from(licensedOrganizations)
      .where(where),
  ]);

  return {
    licenses: rows.map((r) => ({
      ...r,
      // Mask the license key for security — only show first/last 8 chars
      licenseKey: r.licenseKey
        ? `${r.licenseKey.slice(0, 20)}...${r.licenseKey.slice(-8)}`
        : null,
    })),
    total: totalResult[0]?.count ?? 0,
  };
}

// ─── Get License by Org ID ──────────────────────────────────────────────────

export async function getLicenseByOrgId(orgId: string) {
  const db = await getDb();
  const rows = await db
    .select()
    .from(licensedOrganizations)
    .where(eq(licensedOrganizations.orgId, orgId))
    .limit(1);
  return rows[0] ?? null;
}

// ─── Revoke License ─────────────────────────────────────────────────────────

export async function revokeLicense(orgId: string, reason: string): Promise<boolean> {
  const db = await getDb();
  const now = Date.now();

  const result = await db
    .update(licensedOrganizations)
    .set({
      status: "revoked",
      revokedAt: now,
      revokedReason: reason,
    })
    .where(eq(licensedOrganizations.orgId, orgId));

  await logUsage(orgId, "license_revoked", "license", orgId, { reason });
  return true;
}

// ─── Renew License ──────────────────────────────────────────────────────────

export async function renewLicense(orgId: string, additionalDays: number): Promise<LicenseRecord | null> {
  const db = await getDb();
  const existing = await getLicenseByOrgId(orgId);
  if (!existing) return null;

  const now = Date.now();
  const currentExpiry = existing.expiresAt;
  const baseDate = currentExpiry > now ? currentExpiry : now;
  const newExpiry = baseDate + additionalDays * 24 * 60 * 60 * 1000;

  // Generate new license key with updated expiry
  const newKey = generateLicenseKey({
    org: orgId,
    orgName: existing.orgName,
    tier: existing.tier as any,
    features: existing.featureOverrides as any,
    seats: existing.maxSeats,
    scans: existing.maxScansPerPeriod,
    expiryDays: Math.ceil((newExpiry - now) / (24 * 60 * 60 * 1000)),
    billingPeriodDays: existing.billingPeriodDays,
    gracePeriodDays: existing.gracePeriodDays,
    deploymentId: `deploy-${orgId}`,
  });

  await db
    .update(licensedOrganizations)
    .set({
      licenseKey: newKey,
      licenseKeyHash: hashKey(newKey),
      expiresAt: newExpiry,
      status: "active",
      revokedAt: null,
      revokedReason: null,
    })
    .where(eq(licensedOrganizations.orgId, orgId));

  await logUsage(orgId, "license_renewed", "license", orgId, { additionalDays, newExpiry });

  return { ...existing, licenseKey: newKey, expiresAt: newExpiry, status: "active" } as LicenseRecord;
}

// ─── Usage Logging ──────────────────────────────────────────────────────────

export async function logUsage(
  orgId: string,
  action: string,
  resourceType?: string,
  resourceId?: string,
  metadata?: Record<string, any>
): Promise<void> {
  const db = await getDb();
  await db.insert(licenseUsageLogs).values({
    orgId,
    action,
    resourceType: resourceType ?? null,
    resourceId: resourceId ?? null,
    metadata: metadata ?? null,
    timestamp: Date.now(),
  });
}

// ─── License Analytics ──────────────────────────────────────────────────────

export async function getLicenseAnalytics(): Promise<LicenseAnalytics> {
  const db = await getDb();
  const now = Date.now();
  const thirtyDaysFromNow = now + 30 * 24 * 60 * 60 * 1000;

  // Get all licenses
  const allLicenses = await db.select().from(licensedOrganizations);

  const totalLicenses = allLicenses.length;
  const activeLicenses = allLicenses.filter((l) => l.status === "active").length;
  const expiredLicenses = allLicenses.filter(
    (l) => l.status === "active" && l.expiresAt < now
  ).length;
  const revokedLicenses = allLicenses.filter((l) => l.status === "revoked").length;

  // Tier distribution
  const tierCounts: Record<string, number> = {};
  allLicenses.forEach((l) => {
    tierCounts[l.tier] = (tierCounts[l.tier] ?? 0) + 1;
  });
  const tierDistribution = Object.entries(tierCounts).map(([tier, count]) => ({
    tier,
    count,
  }));

  // Expiring within 30 days
  const expiringWithin30Days = allLicenses.filter(
    (l) => l.status === "active" && l.expiresAt > now && l.expiresAt <= thirtyDaysFromNow
  ).length;

  // Recent usage (last 7 days)
  const sevenDaysAgo = now - 7 * 24 * 60 * 60 * 1000;
  const recentLogs = await db
    .select()
    .from(licenseUsageLogs)
    .where(gte(licenseUsageLogs.timestamp, sevenDaysAgo))
    .orderBy(desc(licenseUsageLogs.timestamp))
    .limit(1000);

  // Group by date
  const usageByDate: Record<string, { scans: number; reports: number }> = {};
  recentLogs.forEach((log) => {
    const date = new Date(log.timestamp).toISOString().split("T")[0];
    if (!usageByDate[date]) usageByDate[date] = { scans: 0, reports: 0 };
    if (log.action === "scan") usageByDate[date].scans++;
    if (log.action === "report") usageByDate[date].reports++;
  });
  const recentUsage = Object.entries(usageByDate)
    .map(([date, data]) => ({ date, ...data }))
    .sort((a, b) => a.date.localeCompare(b.date));

  // Top orgs by scan count
  const orgScans: Record<string, { orgName: string; totalScans: number }> = {};
  recentLogs
    .filter((l) => l.action === "scan")
    .forEach((l) => {
      if (!orgScans[l.orgId]) {
        const org = allLicenses.find((o) => o.orgId === l.orgId);
        orgScans[l.orgId] = { orgName: org?.orgName ?? l.orgId, totalScans: 0 };
      }
      orgScans[l.orgId].totalScans++;
    });
  const topOrgs = Object.entries(orgScans)
    .map(([orgId, data]) => ({ orgId, ...data }))
    .sort((a, b) => b.totalScans - a.totalScans)
    .slice(0, 10);

  return {
    totalLicenses,
    activeLicenses,
    expiredLicenses,
    revokedLicenses,
    tierDistribution,
    recentUsage,
    topOrgs,
    expiringWithin30Days,
    totalRevenue: {
      starter: allLicenses.filter((l) => l.tier === "starter").length,
      professional: allLicenses.filter((l) => l.tier === "professional").length,
      enterprise: allLicenses.filter((l) => l.tier === "enterprise").length,
    },
  };
}

// ─── Get Full License Key (admin only) ──────────────────────────────────────

export async function getFullLicenseKey(orgId: string): Promise<string | null> {
  const db = await getDb();
  const rows = await db
    .select({ licenseKey: licensedOrganizations.licenseKey })
    .from(licensedOrganizations)
    .where(eq(licensedOrganizations.orgId, orgId))
    .limit(1);
  return rows[0]?.licenseKey ?? null;
}
