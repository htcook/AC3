/**
 * Update Manager
 * ──────────────
 * Handles version tracking, update checks, changelog management,
 * and migration execution for customer deployments.
 */

import { getDb } from "../db";
import { deploymentVersions, deploymentUpdateHistory } from "../../drizzle/schema";
import { eq, desc, and, gte, gt, sql } from "drizzle-orm";

// ─── Current Version ────────────────────────────────────────────────────────

const CURRENT_VERSION = process.env.AC3_VERSION ?? "2.4.0";
const UPDATE_CHANNEL = process.env.AC3_UPDATE_CHANNEL ?? "stable";

export function getCurrentVersion(): string {
  return CURRENT_VERSION;
}

// ─── Version Comparison ─────────────────────────────────────────────────────

function parseVersion(v: string): number[] {
  return v.replace(/^v/, "").split(".").map(Number);
}

function compareVersions(a: string, b: string): number {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] ?? 0;
    const nb = pb[i] ?? 0;
    if (na > nb) return 1;
    if (na < nb) return -1;
  }
  return 0;
}

// ─── Types ──────────────────────────────────────────────────────────────────

export interface VersionInfo {
  version: string;
  releaseDate: number;
  channel: string;
  changelog: string;
  isBreaking: boolean;
  isRequired: boolean;
  downloadUrl: string | null;
}

export interface UpdateCheckResult {
  currentVersion: string;
  latestVersion: string;
  updateAvailable: boolean;
  updates: VersionInfo[];
  hasBreakingChanges: boolean;
  hasRequiredUpdates: boolean;
}

export interface UpdateApplyResult {
  success: boolean;
  fromVersion: string;
  toVersion: string;
  migrationLog: string;
  error?: string;
}

// ─── Publish a New Version (Admin) ──────────────────────────────────────────

export async function publishVersion(input: {
  version: string;
  changelog: string;
  channel?: string;
  migrationScript?: string;
  minPreviousVersion?: string;
  downloadUrl?: string;
  checksumSha256?: string;
  isBreaking?: boolean;
  isRequired?: boolean;
}): Promise<void> {
  const db = await getDb();
  await db.insert(deploymentVersions).values({
    version: input.version,
    releaseDate: Date.now(),
    channel: input.channel ?? "stable",
    changelog: input.changelog,
    migrationScript: input.migrationScript ?? null,
    minPreviousVersion: input.minPreviousVersion ?? null,
    downloadUrl: input.downloadUrl ?? null,
    checksumSha256: input.checksumSha256 ?? null,
    isBreaking: input.isBreaking ? 1 : 0,
    isRequired: input.isRequired ? 1 : 0,
  });
}

// ─── Check for Updates ──────────────────────────────────────────────────────

export async function checkForUpdates(
  currentVersion?: string,
  channel?: string
): Promise<UpdateCheckResult> {
  const db = await getDb();
  const cv = currentVersion ?? CURRENT_VERSION;
  const ch = channel ?? UPDATE_CHANNEL;

  // Get all versions in this channel newer than current
  const allVersions = await db
    .select()
    .from(deploymentVersions)
    .where(eq(deploymentVersions.channel, ch))
    .orderBy(desc(deploymentVersions.releaseDate));

  const newerVersions = allVersions.filter(
    (v) => compareVersions(v.version, cv) > 0
  );

  const latestVersion =
    newerVersions.length > 0 ? newerVersions[0].version : cv;

  return {
    currentVersion: cv,
    latestVersion,
    updateAvailable: newerVersions.length > 0,
    updates: newerVersions.map((v) => ({
      version: v.version,
      releaseDate: v.releaseDate,
      channel: v.channel,
      changelog: v.changelog,
      isBreaking: v.isBreaking === 1,
      isRequired: v.isRequired === 1,
      downloadUrl: v.downloadUrl,
    })),
    hasBreakingChanges: newerVersions.some((v) => v.isBreaking === 1),
    hasRequiredUpdates: newerVersions.some((v) => v.isRequired === 1),
  };
}

// ─── Get Changelog ──────────────────────────────────────────────────────────

export async function getChangelog(options?: {
  channel?: string;
  limit?: number;
  sinceVersion?: string;
}): Promise<VersionInfo[]> {
  const db = await getDb();
  const ch = options?.channel ?? UPDATE_CHANNEL;

  const allVersions = await db
    .select()
    .from(deploymentVersions)
    .where(eq(deploymentVersions.channel, ch))
    .orderBy(desc(deploymentVersions.releaseDate))
    .limit(options?.limit ?? 20);

  let filtered = allVersions;
  if (options?.sinceVersion) {
    filtered = allVersions.filter(
      (v) => compareVersions(v.version, options.sinceVersion!) > 0
    );
  }

  return filtered.map((v) => ({
    version: v.version,
    releaseDate: v.releaseDate,
    channel: v.channel,
    changelog: v.changelog,
    isBreaking: v.isBreaking === 1,
    isRequired: v.isRequired === 1,
    downloadUrl: v.downloadUrl,
  }));
}

// ─── Apply Update ───────────────────────────────────────────────────────────

export async function applyUpdate(
  orgId: string,
  targetVersion: string
): Promise<UpdateApplyResult> {
  const db = await getDb();
  const fromVersion = CURRENT_VERSION;
  const now = Date.now();

  // Record the update attempt
  await db.insert(deploymentUpdateHistory).values({
    orgId,
    fromVersion,
    toVersion: targetVersion,
    status: "in_progress",
    startedAt: now,
  });

  const migrationLog: string[] = [];

  try {
    // Get all versions between current and target
    const allVersions = await db
      .select()
      .from(deploymentVersions)
      .where(eq(deploymentVersions.channel, UPDATE_CHANNEL))
      .orderBy(desc(deploymentVersions.releaseDate));

    const versionsToApply = allVersions
      .filter(
        (v) =>
          compareVersions(v.version, fromVersion) > 0 &&
          compareVersions(v.version, targetVersion) <= 0
      )
      .sort((a, b) => compareVersions(a.version, b.version));

    // Check minimum version requirement
    for (const v of versionsToApply) {
      if (
        v.minPreviousVersion &&
        compareVersions(fromVersion, v.minPreviousVersion) < 0
      ) {
        throw new Error(
          `Version ${v.version} requires at least version ${v.minPreviousVersion}. Current: ${fromVersion}`
        );
      }
    }

    // Apply migrations sequentially
    for (const v of versionsToApply) {
      migrationLog.push(`[${new Date().toISOString()}] Applying ${v.version}...`);

      if (v.migrationScript) {
        migrationLog.push(`  Running migration script for ${v.version}`);
        try {
          // Execute migration SQL directly
          const statements = v.migrationScript
            .split(";")
            .map((s) => s.trim())
            .filter((s) => s.length > 0);

          for (const stmt of statements) {
            await db.execute(sql`${stmt}`);
            migrationLog.push(`  ✓ Executed: ${stmt.slice(0, 80)}...`);
          }
        } catch (migErr: any) {
          migrationLog.push(`  ✗ Migration failed: ${migErr.message}`);
          throw migErr;
        }
      }

      migrationLog.push(`  ✓ ${v.version} applied successfully`);
    }

    // Mark update as complete
    await db
      .update(deploymentUpdateHistory)
      .set({
        status: "completed",
        completedAt: Date.now(),
        migrationLog: migrationLog.join("\n"),
      })
      .where(
        and(
          eq(deploymentUpdateHistory.orgId, orgId),
          eq(deploymentUpdateHistory.toVersion, targetVersion),
          eq(deploymentUpdateHistory.status, "in_progress")
        )
      );

    return {
      success: true,
      fromVersion,
      toVersion: targetVersion,
      migrationLog: migrationLog.join("\n"),
    };
  } catch (err: any) {
    // Mark update as failed
    migrationLog.push(`\n[ERROR] Update failed: ${err.message}`);

    await db
      .update(deploymentUpdateHistory)
      .set({
        status: "failed",
        completedAt: Date.now(),
        migrationLog: migrationLog.join("\n"),
        error: err.message,
      })
      .where(
        and(
          eq(deploymentUpdateHistory.orgId, orgId),
          eq(deploymentUpdateHistory.toVersion, targetVersion),
          eq(deploymentUpdateHistory.status, "in_progress")
        )
      );

    return {
      success: false,
      fromVersion,
      toVersion: targetVersion,
      migrationLog: migrationLog.join("\n"),
      error: err.message,
    };
  }
}

// ─── Get Update History ─────────────────────────────────────────────────────

export async function getUpdateHistory(orgId?: string) {
  const db = await getDb();
  const where = orgId ? eq(deploymentUpdateHistory.orgId, orgId) : undefined;

  return db
    .select()
    .from(deploymentUpdateHistory)
    .where(where)
    .orderBy(desc(deploymentUpdateHistory.startedAt))
    .limit(50);
}


