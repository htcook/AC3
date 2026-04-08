import * as db from "../db";
/**
 * Bug Bounty Platform Integration Router
 * Integrates HackerOne and Bugcrowd live feeds, correlates findings
 * with existing vulnerability intelligence and discovered assets.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb as _getDb } from "../db";
import {
  bugBountyPrograms,
  bugBountyFindings,
  bugBountyCorrelations,
  bugBountySyncLogs,
  bugBountyProgramScopes,
  bugBountyProgramWeaknesses,
  discoveredAssets,
  iocFeeds,
  userPlatformCredentials,
  engagements,
} from "../../drizzle/schema";
import { eq, desc, like, and, or, sql, inArray } from "drizzle-orm";
import crypto from "crypto";

async function getDbSafe() {
  const db = await _getDb();
  return db!;
}

// ─── Encryption helpers (mirror platform-credentials.ts) ───
const ENCRYPTION_KEY = process.env.JWT_SECRET
  ? crypto.createHash("sha256").update(process.env.JWT_SECRET).digest()
  : crypto.randomBytes(32);

function decrypt(encryptedText: string): string {
  const [ivHex, authTagHex, encrypted] = encryptedText.split(":");
  if (!ivHex || !authTagHex || !encrypted) throw new Error("Invalid encrypted format");
  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(authTagHex, "hex");
  const decipher = crypto.createDecipheriv("aes-256-gcm", ENCRYPTION_KEY, iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// ─── HackerOne API Client ───

const H1_BASE = "https://api.hackerone.com/v1/hackers";

async function h1Fetch(path: string, username?: string, token?: string) {
  const headers: Record<string, string> = {
    Accept: "application/json",
  };
  if (username && token) {
    headers.Authorization =
      "Basic " + Buffer.from(`${username}:${token}`).toString("base64");
  }
  const res = await fetch(`${H1_BASE}${path}`, { headers, signal: AbortSignal.timeout(15000) });
  if (!res.ok) {
    throw new Error(`HackerOne API ${res.status}: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Resolve HackerOne credentials from:
 * 1. User's stored platform credentials (encrypted in DB)
 * 2. Fallback to env vars HACKERONE_API_USERNAME / HACKERONE_API_KEY
 */
async function resolveH1Credentials(userId: number): Promise<{ username: string; token: string } | null> {
  const db = await getDbSafe();
  // Try user's stored credentials first
  const [cred] = await db
    .select()
    .from(userPlatformCredentials)
    .where(
      and(
        eq(userPlatformCredentials.userId, userId),
        eq(userPlatformCredentials.platform, "hackerone"),
        eq(userPlatformCredentials.isActive, 1)
      )
    )
    .limit(1);

  if (cred) {
    try {
      const apiKey = decrypt(cred.apiKeyEncrypted);
      return { username: cred.apiUsername || "", token: apiKey };
    } catch {
      // Decryption failed, fall through to env vars
    }
  }

  // Fallback to env vars
  const username = process.env.HACKERONE_API_USERNAME || process.env.HACKERONE_API_KEY?.split(":")[0];
  const token = process.env.HACKERONE_API_KEY?.includes(":") 
    ? process.env.HACKERONE_API_KEY.split(":").slice(1).join(":")
    : process.env.HACKERONE_API_KEY;
  if (username && token) {
    return { username, token };
  }

  return null;
}

// ─── Correlation Engine ───

interface CorrelationResult {
  findingId: number;
  correlationType: string;
  matchedEntityType: string;
  matchedEntityId: number;
  matchedEntityName: string;
  confidenceScore: number;
  details: Record<string, unknown>;
}

async function correlateFindings(findingIds?: number[]): Promise<CorrelationResult[]> {
  const db = await getDbSafe();
  const correlations: CorrelationResult[] = [];

  // Get findings to correlate
  let findings;
  if (findingIds && findingIds.length > 0) {
    findings = await db
      .select()
      .from(bugBountyFindings)
      .where(inArray(bugBountyFindings.id, findingIds));
  } else {
    findings = await db
      .select()
      .from(bugBountyFindings)
      .orderBy(desc(bugBountyFindings.createdAt))
      .limit(200);
  }

  // Get all discovered assets for matching
  const assets = await db.select().from(discoveredAssets).limit(5000);

  // Get IOC feeds (CVE-based) for matching
  const cveFeeds = await db
    .select()
    .from(iocFeeds)
    .where(eq(iocFeeds.feedType, "vulnerability"))
    .limit(5000);

  for (const finding of findings) {
    // 1. CVE Match: match finding CVE IDs against iocFeeds
    const cveIds = (finding.cveIds as string[] | null) || [];
    for (const cve of cveIds) {
      if (!cve) continue;
      for (const feed of cveFeeds) {
        if (feed.cveId && feed.cveId.toLowerCase() === cve.toLowerCase()) {
          correlations.push({
            findingId: finding.id,
            correlationType: "cve_match",
            matchedEntityType: "ioc_feed",
            matchedEntityId: feed.id,
            matchedEntityName: feed.cveId || cve,
            confidenceScore: 0.95,
            details: {
              matchField: "cveId",
              matchValue: cve,
              feedTitle: feed.title,
              feedSeverity: feed.severity,
            },
          });
        }
      }
    }

    // 2. Asset Match: match finding asset identifiers against discovered assets
    const assetId = finding.assetIdentifier;
    if (assetId) {
      for (const asset of assets) {
        const hostname = asset.hostname?.toLowerCase() || "";
        const assetUrl = (asset.url as string)?.toLowerCase() || "";
        const findingAsset = assetId.toLowerCase();

        // Domain/hostname match
        if (
          hostname &&
          (hostname === findingAsset ||
            hostname.endsWith("." + findingAsset) ||
            findingAsset.endsWith("." + hostname) ||
            findingAsset.includes(hostname))
        ) {
          correlations.push({
            findingId: finding.id,
            correlationType: "asset_match",
            matchedEntityType: "discovered_asset",
            matchedEntityId: asset.id,
            matchedEntityName: asset.hostname,
            confidenceScore:
              hostname === findingAsset ? 0.98 : 0.75,
            details: {
              matchField: "hostname",
              matchValue: findingAsset,
              assetType: asset.assetType,
              riskBand: asset.riskBand,
              hybridRiskScore: asset.hybridRiskScore,
            },
          });
        }

        // URL match
        if (assetUrl && findingAsset && assetUrl.includes(findingAsset)) {
          correlations.push({
            findingId: finding.id,
            correlationType: "asset_match",
            matchedEntityType: "discovered_asset",
            matchedEntityId: asset.id,
            matchedEntityName: asset.hostname,
            confidenceScore: 0.8,
            details: {
              matchField: "url",
              matchValue: findingAsset,
              assetUrl: asset.url,
            },
          });
        }
      }
    }

    // 3. CWE Match: match finding CWE against IOC feeds or asset posture findings
    if (finding.cweId) {
      for (const asset of assets) {
        const postureFindings = (asset.postureFindings as Array<{ cwe?: string; title?: string }>) || [];
        for (const pf of postureFindings) {
          if (pf.cwe && pf.cwe === finding.cweId) {
            correlations.push({
              findingId: finding.id,
              correlationType: "cwe_match",
              matchedEntityType: "discovered_asset",
              matchedEntityId: asset.id,
              matchedEntityName: `${asset.hostname} - ${pf.title || pf.cwe}`,
              confidenceScore: 0.7,
              details: {
                matchField: "cwe",
                matchValue: finding.cweId,
                postureTitle: pf.title,
              },
            });
          }
        }
      }
    }
  }

  return correlations;
}

// ─── Router ───

export const bugBountyRouter = router({
  // List programs with search and filtering
  listPrograms: protectedProcedure
    .input(
      z.object({
        platform: z.enum(["hackerone", "bugcrowd", "manual", "all"]).default("all"),
        search: z.string().optional(),
        state: z.string().optional(),
        limit: z.number().min(1).max(100).default(25),
        offset: z.number().min(0).default(0),
      })
    )
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions = [];
      if (input.platform !== "all") {
        conditions.push(eq(bugBountyPrograms.platform, input.platform));
      }
      if (input.search) {
        conditions.push(
          or(
            like(bugBountyPrograms.name, `%${input.search}%`),
            like(bugBountyPrograms.handle, `%${input.search}%`)
          )
        );
      }
      if (input.state) {
        conditions.push(eq(bugBountyPrograms.state, input.state));
      }
      const where = conditions.length > 0 ? and(...conditions) : undefined;
      const [programs, countResult] = await Promise.all([
        db
          .select()
          .from(bugBountyPrograms)
          .where(where)
          .orderBy(desc(bugBountyPrograms.updatedAt))
          .limit(input.limit)
          .offset(input.offset),
        db
          .select({ count: sql<number>`count(*)` })
          .from(bugBountyPrograms)
          .where(where),
      ]);
      return { programs, total: countResult[0]?.count || 0 };
    }),

  // List findings with search and filtering
  listFindings: protectedProcedure
    .input(
      z.object({
        platform: z.enum(["hackerone", "bugcrowd", "manual", "all"]).default("all"),
        severity: z.string().optional(),
        search: z.string().optional(),
        programId: z.number().optional(),
        limit: z.number().min(1).max(100).default(25),
        offset: z.number().min(0).default(0),
      })
    )
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions = [];
      if (input.platform !== "all") {
        conditions.push(eq(bugBountyFindings.platform, input.platform));
      }
      if (input.severity) {
        conditions.push(eq(bugBountyFindings.severityRating, input.severity));
      }
      if (input.search) {
        conditions.push(like(bugBountyFindings.title, `%${input.search}%`));
      }
      if (input.programId) {
        conditions.push(eq(bugBountyFindings.programId, input.programId));
      }
      const where = conditions.length > 0 ? and(...conditions) : undefined;
      const [findings, countResult] = await Promise.all([
        db
          .select()
          .from(bugBountyFindings)
          .where(where)
          .orderBy(desc(bugBountyFindings.disclosedAt))
          .limit(input.limit)
          .offset(input.offset),
        db
          .select({ count: sql<number>`count(*)` })
          .from(bugBountyFindings)
          .where(where),
      ]);
      return { findings, total: countResult[0]?.count || 0 };
    }),

  // List correlations
  listCorrelations: protectedProcedure
    .input(
      z.object({
        findingId: z.number().optional(),
        correlationType: z.string().optional(),
        minConfidence: z.number().min(0).max(1).default(0),
        limit: z.number().min(1).max(100).default(50),
        offset: z.number().min(0).default(0),
      })
    )
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions = [];
      if (input.findingId) {
        conditions.push(eq(bugBountyCorrelations.findingId, input.findingId));
      }
      if (input.correlationType) {
        conditions.push(eq(bugBountyCorrelations.correlationType, input.correlationType));
      }
      if (input.minConfidence > 0) {
        conditions.push(sql`${bugBountyCorrelations.confidenceScore} >= ${input.minConfidence}`);
      }
      const where = conditions.length > 0 ? and(...conditions) : undefined;
      const rows = await db
        .select()
        .from(bugBountyCorrelations)
        .where(where)
        .orderBy(desc(bugBountyCorrelations.confidenceScore))
        .limit(input.limit)
        .offset(input.offset);
      return rows;
    }),

  // ─── Enhanced HackerOne Sync: Hacktivity ───
  syncHackerOneHacktivity: protectedProcedure
    .input(
      z.object({
        queryString: z.string().default("severity_rating:critical OR severity_rating:high"),
        pages: z.number().min(1).max(10).default(3),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const db = await getDbSafe();
      const creds = await resolveH1Credentials(ctx.user.id);

      // Create sync log
      const [logResult] = await db.insert(bugBountySyncLogs).values({
        platform: "hackerone",
        syncType: "hacktivity",
        status: "running",
      });
      const logId = logResult.insertId;

      try {
        let totalSynced = 0;
        let totalUpdated = 0;

        for (let page = 1; page <= input.pages; page++) {
          const path = `/hacktivity?queryString=${encodeURIComponent(input.queryString)}&page[number]=${page}&page[size]=25`;
          const data = await h1Fetch(path, creds?.username, creds?.token);

          if (!data?.data?.length) break;

          for (const item of data.data) {
            const attrs = item.attributes || {};
            const reporter = item.relationships?.reporter?.data?.attributes;
            const program = item.relationships?.program?.data?.attributes;
            const aiSummary = item.relationships?.report_generated_content?.data?.attributes?.hacktivity_summary;

            // Upsert by external ID
            const existing = await db
              .select()
              .from(bugBountyFindings)
              .where(
                and(
                  eq(bugBountyFindings.platform, "hackerone"),
                  eq(bugBountyFindings.externalId, String(item.id))
                )
              )
              .limit(1);

            if (existing.length === 0) {
              await db.insert(bugBountyFindings).values({
                platform: "hackerone",
                externalId: String(item.id),
                title: attrs.title || "Untitled",
                severityRating: attrs.severity_rating || null,
                cveIds: attrs.cve_ids || null,
                cweId: attrs.cwe || null,
                substate: attrs.substate || null,
                reportUrl: attrs.url || null,
                disclosedAt: attrs.disclosed_at ? new Date(attrs.disclosed_at).toISOString().slice(0, 19).replace("T", " ") : null,
                submittedAt: attrs.submitted_at ? new Date(attrs.submitted_at).toISOString().slice(0, 19).replace("T", " ") : null,
                awardedAmount: attrs.total_awarded_amount || null,
                reporterUsername: reporter?.username || null,
                reporterReputation: reporter?.reputation || null,
                programHandle: program?.handle || null,
                programName: program?.name || null,
                assetIdentifier: attrs.asset_identifier || null,
                assetType: attrs.asset_type || null,
                votes: attrs.votes || 0,
                summary: aiSummary || null,
              });
              totalSynced++;
            } else {
              // Update existing with any new data (e.g., AI summary, votes)
              const updates: Record<string, any> = {};
              if (aiSummary && !existing[0].summary) updates.summary = aiSummary;
              if (attrs.votes && attrs.votes > (existing[0].votes || 0)) updates.votes = attrs.votes;
              if (attrs.total_awarded_amount && !existing[0].awardedAmount) updates.awardedAmount = attrs.total_awarded_amount;
              if (Object.keys(updates).length > 0) {
                await db.update(bugBountyFindings).set(updates).where(eq(bugBountyFindings.id, existing[0].id));
                totalUpdated++;
              }
            }
          }
        }

        // Update sync log
        await db
          .update(bugBountySyncLogs)
          .set({
            status: "completed",
            itemsSynced: totalSynced,
            completedAt: new Date(),
          })
          .where(eq(bugBountySyncLogs.id, Number(logId)));

        return { success: true, synced: totalSynced, updated: totalUpdated };
      } catch (err: any) {
        await db
          .update(bugBountySyncLogs)
          .set({
            status: "failed",
            errorMessage: err.message,
            completedAt: new Date(),
          })
          .where(eq(bugBountySyncLogs.id, Number(logId)));
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `HackerOne hacktivity sync failed: ${err.message}`,
        });
      }
    }),

  // ─── Enhanced HackerOne Sync: Programs ───
  syncHackerOnePrograms: protectedProcedure
    .input(
      z.object({
        pages: z.number().min(1).max(10).default(3),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const db = await getDbSafe();
      const creds = await resolveH1Credentials(ctx.user.id);

      const [logResult] = await db.insert(bugBountySyncLogs).values({
        platform: "hackerone",
        syncType: "programs",
        status: "running",
      });
      const logId = logResult.insertId;

      try {
        let totalSynced = 0;

        for (let page = 1; page <= input.pages; page++) {
          const path = `/programs?page[number]=${page}&page[size]=25`;
          const data = await h1Fetch(path, creds?.username, creds?.token);

          if (!data?.data?.length) break;

          for (const item of data.data) {
            const attrs = item.attributes || {};

            const existing = await db
              .select()
              .from(bugBountyPrograms)
              .where(
                and(
                  eq(bugBountyPrograms.platform, "hackerone"),
                  eq(bugBountyPrograms.handle, attrs.handle || String(item.id))
                )
              )
              .limit(1);

            if (existing.length === 0) {
              await db.insert(bugBountyPrograms).values({
                platform: "hackerone",
                handle: attrs.handle || String(item.id),
                name: attrs.name || attrs.handle || "Unknown",
                url: `https://hackerone.com/${attrs.handle}`,
                logoUrl: attrs.profile_picture || null,
                state: attrs.state || null,
                submissionState: attrs.submission_state || null,
                currency: attrs.currency || "USD",
                lastSyncedAt: new Date(),
              });
              totalSynced++;
            } else {
              await db
                .update(bugBountyPrograms)
                .set({
                  name: attrs.name || existing[0].name,
                  state: attrs.state || existing[0].state,
                  submissionState: attrs.submission_state || existing[0].submissionState,
                  lastSyncedAt: new Date(),
                })
                .where(eq(bugBountyPrograms.id, existing[0].id));
              totalSynced++;
            }
          }
        }

        await db
          .update(bugBountySyncLogs)
          .set({ status: "completed", itemsSynced: totalSynced, completedAt: new Date() })
          .where(eq(bugBountySyncLogs.id, Number(logId)));

        return { success: true, synced: totalSynced };
      } catch (err: any) {
        await db
          .update(bugBountySyncLogs)
          .set({ status: "failed", errorMessage: err.message, completedAt: new Date() })
          .where(eq(bugBountySyncLogs.id, Number(logId)));
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `HackerOne programs sync failed: ${err.message}`,
        });
      }
    }),

  // ─── NEW: Sync Structured Scopes for a program ───
  syncHackerOneScopes: protectedProcedure
    .input(
      z.object({
        programHandle: z.string().min(1),
        pages: z.number().min(1).max(10).default(5),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const db = await getDbSafe();
      const creds = await resolveH1Credentials(ctx.user.id);

      const [logResult] = await db.insert(bugBountySyncLogs).values({
        platform: "hackerone",
        syncType: "structured_scopes",
        status: "running",
      });
      const logId = logResult.insertId;

      try {
        let totalSynced = 0;

        for (let page = 1; page <= input.pages; page++) {
          const path = `/programs/${encodeURIComponent(input.programHandle)}/structured_scopes?page[number]=${page}&page[size]=25`;
          const data = await h1Fetch(path, creds?.username, creds?.token);

          if (!data?.data?.length) break;

          for (const item of data.data) {
            const attrs = item.attributes || {};

            // Check for existing scope by program + asset identifier
            const existing = await db
              .select()
              .from(bugBountyProgramScopes)
              .where(
                and(
                  eq(bugBountyProgramScopes.programHandle, input.programHandle),
                  eq(bugBountyProgramScopes.assetIdentifier, attrs.asset_identifier || ""),
                  eq(bugBountyProgramScopes.assetType, attrs.asset_type || "OTHER")
                )
              )
              .limit(1);

            if (existing.length === 0) {
              await db.insert(bugBountyProgramScopes).values({
                platform: "hackerone",
                programHandle: input.programHandle,
                externalId: String(item.id),
                assetType: attrs.asset_type || "OTHER",
                assetIdentifier: attrs.asset_identifier || "unknown",
                eligibleForBounty: attrs.eligible_for_bounty ? 1 : 0,
                eligibleForSubmission: attrs.eligible_for_submission !== false ? 1 : 0,
                maxSeverity: attrs.max_severity || null,
                confidentialityRequirement: attrs.confidentiality_requirement || null,
                integrityRequirement: attrs.integrity_requirement || null,
                availabilityRequirement: attrs.availability_requirement || null,
                instruction: attrs.instruction || null,
              });
              totalSynced++;
            } else {
              // Update existing
              await db
                .update(bugBountyProgramScopes)
                .set({
                  eligibleForBounty: attrs.eligible_for_bounty ? 1 : 0,
                  maxSeverity: attrs.max_severity || existing[0].maxSeverity,
                })
                .where(eq(bugBountyProgramScopes.id, existing[0].id));
            }
          }
        }

        await db
          .update(bugBountySyncLogs)
          .set({ status: "completed", itemsSynced: totalSynced, completedAt: new Date() })
          .where(eq(bugBountySyncLogs.id, Number(logId)));

        return { success: true, synced: totalSynced, programHandle: input.programHandle };
      } catch (err: any) {
        await db
          .update(bugBountySyncLogs)
          .set({ status: "failed", errorMessage: err.message, completedAt: new Date() })
          .where(eq(bugBountySyncLogs.id, Number(logId)));
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `HackerOne scopes sync failed for ${input.programHandle}: ${err.message}`,
        });
      }
    }),

  // ─── NEW: Sync Weaknesses for a program ───
  syncHackerOneWeaknesses: protectedProcedure
    .input(
      z.object({
        programHandle: z.string().min(1),
        pages: z.number().min(1).max(10).default(5),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const db = await getDbSafe();
      const creds = await resolveH1Credentials(ctx.user.id);

      const [logResult] = await db.insert(bugBountySyncLogs).values({
        platform: "hackerone",
        syncType: "weaknesses",
        status: "running",
      });
      const logId = logResult.insertId;

      try {
        let totalSynced = 0;

        for (let page = 1; page <= input.pages; page++) {
          const path = `/programs/${encodeURIComponent(input.programHandle)}/weaknesses?page[number]=${page}&page[size]=25`;
          const data = await h1Fetch(path, creds?.username, creds?.token);

          if (!data?.data?.length) break;

          for (const item of data.data) {
            const attrs = item.attributes || {};

            // Check for existing weakness by program + CWE ID
            const cweId = attrs.external_id || null;
            const existing = await db
              .select()
              .from(bugBountyProgramWeaknesses)
              .where(
                and(
                  eq(bugBountyProgramWeaknesses.programHandle, input.programHandle),
                  eq(bugBountyProgramWeaknesses.name, attrs.name || "")
                )
              )
              .limit(1);

            if (existing.length === 0) {
              await db.insert(bugBountyProgramWeaknesses).values({
                platform: "hackerone",
                programHandle: input.programHandle,
                externalId: String(item.id),
                cweId,
                name: attrs.name || "Unknown Weakness",
                description: attrs.description || null,
              });
              totalSynced++;
            }
          }
        }

        await db
          .update(bugBountySyncLogs)
          .set({ status: "completed", itemsSynced: totalSynced, completedAt: new Date() })
          .where(eq(bugBountySyncLogs.id, Number(logId)));

        return { success: true, synced: totalSynced, programHandle: input.programHandle };
      } catch (err: any) {
        await db
          .update(bugBountySyncLogs)
          .set({ status: "failed", errorMessage: err.message, completedAt: new Date() })
          .where(eq(bugBountySyncLogs.id, Number(logId)));
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `HackerOne weaknesses sync failed for ${input.programHandle}: ${err.message}`,
        });
      }
    }),

  // ─── NEW: Comprehensive Sync (all data types) ───
  syncAll: protectedProcedure
    .input(
      z.object({
        hacktivityPages: z.number().min(1).max(10).default(5),
        programPages: z.number().min(1).max(10).default(5),
        hacktivityQuery: z.string().default(""),
        syncScopes: z.boolean().default(true),
        syncWeaknesses: z.boolean().default(true),
        scopeProgramHandles: z.array(z.string()).optional(),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const db = await getDbSafe();
      const creds = await resolveH1Credentials(ctx.user.id);

      const [logResult] = await db.insert(bugBountySyncLogs).values({
        platform: "hackerone",
        syncType: "full_sync",
        status: "running",
      });
      const logId = logResult.insertId;

      const results = {
        hacktivity: { synced: 0, updated: 0 },
        programs: { synced: 0 },
        scopes: { synced: 0, programs: 0 },
        weaknesses: { synced: 0, programs: 0 },
        errors: [] as string[],
      };

      try {
        // 1. Sync hacktivity
        try {
          for (let page = 1; page <= input.hacktivityPages; page++) {
            const query = input.hacktivityQuery || "severity_rating:critical OR severity_rating:high";
            const path = `/hacktivity?queryString=${encodeURIComponent(query)}&page[number]=${page}&page[size]=25`;
            const data = await h1Fetch(path, creds?.username, creds?.token);
            if (!data?.data?.length) break;

            for (const item of data.data) {
              const attrs = item.attributes || {};
              const reporter = item.relationships?.reporter?.data?.attributes;
              const program = item.relationships?.program?.data?.attributes;
              const aiSummary = item.relationships?.report_generated_content?.data?.attributes?.hacktivity_summary;

              const existing = await db
                .select()
                .from(bugBountyFindings)
                .where(and(eq(bugBountyFindings.platform, "hackerone"), eq(bugBountyFindings.externalId, String(item.id))))
                .limit(1);

              if (existing.length === 0) {
                await db.insert(bugBountyFindings).values({
                  platform: "hackerone",
                  externalId: String(item.id),
                  title: attrs.title || "Untitled",
                  severityRating: attrs.severity_rating || null,
                  cveIds: attrs.cve_ids || null,
                  cweId: attrs.cwe || null,
                  substate: attrs.substate || null,
                  reportUrl: attrs.url || null,
                  disclosedAt: attrs.disclosed_at ? new Date(attrs.disclosed_at).toISOString().slice(0, 19).replace("T", " ") : null,
                  submittedAt: attrs.submitted_at ? new Date(attrs.submitted_at).toISOString().slice(0, 19).replace("T", " ") : null,
                  awardedAmount: attrs.total_awarded_amount || null,
                  reporterUsername: reporter?.username || null,
                  reporterReputation: reporter?.reputation || null,
                  programHandle: program?.handle || null,
                  programName: program?.name || null,
                  assetIdentifier: attrs.asset_identifier || null,
                  assetType: attrs.asset_type || null,
                  votes: attrs.votes || 0,
                  summary: aiSummary || null,
                });
                results.hacktivity.synced++;
              } else {
                const updates: Record<string, any> = {};
                if (aiSummary && !existing[0].summary) updates.summary = aiSummary;
                if (attrs.votes && attrs.votes > (existing[0].votes || 0)) updates.votes = attrs.votes;
                if (Object.keys(updates).length > 0) {
                  await db.update(bugBountyFindings).set(updates).where(eq(bugBountyFindings.id, existing[0].id));
                  results.hacktivity.updated++;
                }
              }
            }
          }
        } catch (err: any) {
          results.errors.push(`Hacktivity: ${err.message}`);
        }

        // 2. Sync programs
        try {
          for (let page = 1; page <= input.programPages; page++) {
            const path = `/programs?page[number]=${page}&page[size]=25`;
            const data = await h1Fetch(path, creds?.username, creds?.token);
            if (!data?.data?.length) break;

            for (const item of data.data) {
              const attrs = item.attributes || {};
              const existing = await db
                .select()
                .from(bugBountyPrograms)
                .where(and(eq(bugBountyPrograms.platform, "hackerone"), eq(bugBountyPrograms.handle, attrs.handle || String(item.id))))
                .limit(1);

              if (existing.length === 0) {
                await db.insert(bugBountyPrograms).values({
                  platform: "hackerone",
                  handle: attrs.handle || String(item.id),
                  name: attrs.name || attrs.handle || "Unknown",
                  url: `https://hackerone.com/${attrs.handle}`,
                  logoUrl: attrs.profile_picture || null,
                  state: attrs.state || null,
                  submissionState: attrs.submission_state || null,
                  currency: attrs.currency || "USD",
                  lastSyncedAt: new Date(),
                });
                results.programs.synced++;
              } else {
                await db.update(bugBountyPrograms).set({
                  name: attrs.name || existing[0].name,
                  state: attrs.state || existing[0].state,
                  lastSyncedAt: new Date(),
                }).where(eq(bugBountyPrograms.id, existing[0].id));
                results.programs.synced++;
              }
            }
          }
        } catch (err: any) {
          results.errors.push(`Programs: ${err.message}`);
        }

        // 3. Sync scopes for specified programs (or top synced programs)
        if (input.syncScopes) {
          const handles = input.scopeProgramHandles?.length
            ? input.scopeProgramHandles
            : (await db.select({ handle: bugBountyPrograms.handle }).from(bugBountyPrograms).where(eq(bugBountyPrograms.platform, "hackerone")).limit(10)).map(p => p.handle);

          for (const handle of handles) {
            try {
              for (let page = 1; page <= 3; page++) {
                const path = `/programs/${encodeURIComponent(handle)}/structured_scopes?page[number]=${page}&page[size]=25`;
                const data = await h1Fetch(path, creds?.username, creds?.token);
                if (!data?.data?.length) break;

                for (const item of data.data) {
                  const attrs = item.attributes || {};
                  const existing = await db
                    .select()
                    .from(bugBountyProgramScopes)
                    .where(and(
                      eq(bugBountyProgramScopes.programHandle, handle),
                      eq(bugBountyProgramScopes.assetIdentifier, attrs.asset_identifier || ""),
                      eq(bugBountyProgramScopes.assetType, attrs.asset_type || "OTHER")
                    ))
                    .limit(1);

                  if (existing.length === 0) {
                    await db.insert(bugBountyProgramScopes).values({
                      platform: "hackerone",
                      programHandle: handle,
                      externalId: String(item.id),
                      assetType: attrs.asset_type || "OTHER",
                      assetIdentifier: attrs.asset_identifier || "unknown",
                      eligibleForBounty: attrs.eligible_for_bounty ? 1 : 0,
                      eligibleForSubmission: attrs.eligible_for_submission !== false ? 1 : 0,
                      maxSeverity: attrs.max_severity || null,
                      confidentialityRequirement: attrs.confidentiality_requirement || null,
                      integrityRequirement: attrs.integrity_requirement || null,
                      availabilityRequirement: attrs.availability_requirement || null,
                      instruction: attrs.instruction || null,
                    });
                    results.scopes.synced++;
                  }
                }
              }
              results.scopes.programs++;
            } catch (err: any) {
              results.errors.push(`Scopes(${handle}): ${err.message}`);
            }
          }
        }

        // 4. Sync weaknesses for specified programs
        if (input.syncWeaknesses) {
          const handles = input.scopeProgramHandles?.length
            ? input.scopeProgramHandles
            : (await db.select({ handle: bugBountyPrograms.handle }).from(bugBountyPrograms).where(eq(bugBountyPrograms.platform, "hackerone")).limit(10)).map(p => p.handle);

          for (const handle of handles) {
            try {
              for (let page = 1; page <= 3; page++) {
                const path = `/programs/${encodeURIComponent(handle)}/weaknesses?page[number]=${page}&page[size]=25`;
                const data = await h1Fetch(path, creds?.username, creds?.token);
                if (!data?.data?.length) break;

                for (const item of data.data) {
                  const attrs = item.attributes || {};
                  const existing = await db
                    .select()
                    .from(bugBountyProgramWeaknesses)
                    .where(and(
                      eq(bugBountyProgramWeaknesses.programHandle, handle),
                      eq(bugBountyProgramWeaknesses.name, attrs.name || "")
                    ))
                    .limit(1);

                  if (existing.length === 0) {
                    await db.insert(bugBountyProgramWeaknesses).values({
                      platform: "hackerone",
                      programHandle: handle,
                      externalId: String(item.id),
                      cweId: attrs.external_id || null,
                      name: attrs.name || "Unknown Weakness",
                      description: attrs.description || null,
                    });
                    results.weaknesses.synced++;
                  }
                }
              }
              results.weaknesses.programs++;
            } catch (err: any) {
              results.errors.push(`Weaknesses(${handle}): ${err.message}`);
            }
          }
        }

        await db
          .update(bugBountySyncLogs)
          .set({
            status: results.errors.length > 0 ? "completed" : "completed",
            itemsSynced: results.hacktivity.synced + results.programs.synced + results.scopes.synced + results.weaknesses.synced,
            completedAt: new Date(),
            errorMessage: results.errors.length > 0 ? results.errors.join("; ") : null,
          })
          .where(eq(bugBountySyncLogs.id, Number(logId)));

        return { success: true, results };
      } catch (err: any) {
        await db
          .update(bugBountySyncLogs)
          .set({ status: "failed", errorMessage: err.message, completedAt: new Date() })
          .where(eq(bugBountySyncLogs.id, Number(logId)));
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Full sync failed: ${err.message}`,
        });
      }
    }),

  // ─── NEW: List program scopes ───
  listProgramScopes: protectedProcedure
    .input(
      z.object({
        programHandle: z.string().optional(),
        assetType: z.string().optional(),
        bountyOnly: z.boolean().default(false),
        limit: z.number().min(1).max(200).default(50),
        offset: z.number().min(0).default(0),
      })
    )
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions = [];
      if (input.programHandle) {
        conditions.push(eq(bugBountyProgramScopes.programHandle, input.programHandle));
      }
      if (input.assetType) {
        conditions.push(eq(bugBountyProgramScopes.assetType, input.assetType));
      }
      if (input.bountyOnly) {
        conditions.push(eq(bugBountyProgramScopes.eligibleForBounty, 1));
      }
      const where = conditions.length > 0 ? and(...conditions) : undefined;
      const [scopes, countResult] = await Promise.all([
        db.select().from(bugBountyProgramScopes).where(where).orderBy(desc(bugBountyProgramScopes.updatedAt)).limit(input.limit).offset(input.offset),
        db.select({ count: sql<number>`count(*)` }).from(bugBountyProgramScopes).where(where),
      ]);
      return { scopes, total: countResult[0]?.count || 0 };
    }),

  // ─── NEW: List program weaknesses ───
  listProgramWeaknesses: protectedProcedure
    .input(
      z.object({
        programHandle: z.string().optional(),
        cweId: z.string().optional(),
        limit: z.number().min(1).max(200).default(50),
        offset: z.number().min(0).default(0),
      })
    )
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions = [];
      if (input.programHandle) {
        conditions.push(eq(bugBountyProgramWeaknesses.programHandle, input.programHandle));
      }
      if (input.cweId) {
        conditions.push(eq(bugBountyProgramWeaknesses.cweId, input.cweId));
      }
      const where = conditions.length > 0 ? and(...conditions) : undefined;
      const [weaknesses, countResult] = await Promise.all([
        db.select().from(bugBountyProgramWeaknesses).where(where).orderBy(desc(bugBountyProgramWeaknesses.createdAt)).limit(input.limit).offset(input.offset),
        db.select({ count: sql<number>`count(*)` }).from(bugBountyProgramWeaknesses).where(where),
      ]);
      return { weaknesses, total: countResult[0]?.count || 0 };
    }),

  // ─── NEW: CWE Trending Analytics ───
  cweAnalytics: protectedProcedure
    .input(
      z.object({
        limit: z.number().min(1).max(50).default(20),
      })
    )
    .query(async ({ input }) => {
      const db = await getDbSafe();

      // CWE distribution from findings
      const cweDistribution = await db
        .select({
          cweId: bugBountyFindings.cweId,
          count: sql<number>`count(*)`,
          avgBounty: sql<number>`COALESCE(AVG(${bugBountyFindings.awardedAmount}), 0)`,
          maxBounty: sql<number>`COALESCE(MAX(${bugBountyFindings.awardedAmount}), 0)`,
        })
        .from(bugBountyFindings)
        .where(sql`${bugBountyFindings.cweId} IS NOT NULL AND ${bugBountyFindings.cweId} != ''`)
        .groupBy(bugBountyFindings.cweId)
        .orderBy(sql`count(*) DESC`)
        .limit(input.limit);

      // CWE distribution from program weaknesses
      const programCweDistribution = await db
        .select({
          cweId: bugBountyProgramWeaknesses.cweId,
          name: bugBountyProgramWeaknesses.name,
          programCount: sql<number>`COUNT(DISTINCT ${bugBountyProgramWeaknesses.programHandle})`,
        })
        .from(bugBountyProgramWeaknesses)
        .where(sql`${bugBountyProgramWeaknesses.cweId} IS NOT NULL`)
        .groupBy(bugBountyProgramWeaknesses.cweId, bugBountyProgramWeaknesses.name)
        .orderBy(sql`COUNT(DISTINCT ${bugBountyProgramWeaknesses.programHandle}) DESC`)
        .limit(input.limit);

      // Severity distribution
      const severityDistribution = await db
        .select({
          severity: bugBountyFindings.severityRating,
          count: sql<number>`count(*)`,
          totalBounty: sql<number>`COALESCE(SUM(${bugBountyFindings.awardedAmount}), 0)`,
        })
        .from(bugBountyFindings)
        .where(sql`${bugBountyFindings.severityRating} IS NOT NULL`)
        .groupBy(bugBountyFindings.severityRating);

      // Asset type distribution from scopes
      const assetTypeDistribution = await db
        .select({
          assetType: bugBountyProgramScopes.assetType,
          count: sql<number>`count(*)`,
          bountyEligible: sql<number>`SUM(CASE WHEN ${bugBountyProgramScopes.eligibleForBounty} = 1 THEN 1 ELSE 0 END)`,
        })
        .from(bugBountyProgramScopes)
        .groupBy(bugBountyProgramScopes.assetType)
        .orderBy(sql`count(*) DESC`);

      return {
        cweDistribution,
        programCweDistribution,
        severityDistribution,
        assetTypeDistribution,
      };
    }),

  // ─── NEW: Intelligence Summary (cross-module) ───
  intelligenceSummary: protectedProcedure.query(async () => {
    const db = await getDbSafe();

    const [findingCount] = await db.select({ count: sql<number>`count(*)` }).from(bugBountyFindings);
    const [programCount] = await db.select({ count: sql<number>`count(*)` }).from(bugBountyPrograms);
    const [scopeCount] = await db.select({ count: sql<number>`count(*)` }).from(bugBountyProgramScopes);
    const [weaknessCount] = await db.select({ count: sql<number>`count(*)` }).from(bugBountyProgramWeaknesses);
    const [correlationCount] = await db.select({ count: sql<number>`count(*)` }).from(bugBountyCorrelations);

    // Recent findings (last 30 days)
    const recentFindings = await db
      .select({ count: sql<number>`count(*)` })
      .from(bugBountyFindings)
      .where(sql`${bugBountyFindings.disclosedAt} >= DATE_SUB(NOW(), INTERVAL 30 DAY)`);

    // Top programs by finding count
    const topPrograms = await db
      .select({
        programHandle: bugBountyFindings.programHandle,
        programName: bugBountyFindings.programName,
        count: sql<number>`count(*)`,
        totalAwarded: sql<number>`COALESCE(SUM(${bugBountyFindings.awardedAmount}), 0)`,
        criticalCount: sql<number>`SUM(CASE WHEN ${bugBountyFindings.severityRating} = 'critical' THEN 1 ELSE 0 END)`,
        highCount: sql<number>`SUM(CASE WHEN ${bugBountyFindings.severityRating} = 'high' THEN 1 ELSE 0 END)`,
      })
      .from(bugBountyFindings)
      .where(sql`${bugBountyFindings.programHandle} IS NOT NULL`)
      .groupBy(bugBountyFindings.programHandle, bugBountyFindings.programName)
      .orderBy(sql`count(*) DESC`)
      .limit(10);

    // CVE coverage
    const cveFindings = await db
      .select({ count: sql<number>`count(*)` })
      .from(bugBountyFindings)
      .where(sql`JSON_LENGTH(${bugBountyFindings.cveIds}) > 0`);

    // Last sync
    const [lastSync] = await db
      .select()
      .from(bugBountySyncLogs)
      .orderBy(desc(bugBountySyncLogs.startedAt))
      .limit(1);

    return {
      totals: {
        findings: findingCount[0]?.count || 0,
        programs: programCount[0]?.count || 0,
        scopes: scopeCount[0]?.count || 0,
        weaknesses: weaknessCount[0]?.count || 0,
        correlations: correlationCount[0]?.count || 0,
        recentFindings: recentFindings[0]?.count || 0,
        findingsWithCVE: cveFindings[0]?.count || 0,
      },
      topPrograms,
      lastSync: lastSync || null,
    };
  }),

  // Add manual program
  addProgram: protectedProcedure
    .input(
      z.object({
        platform: z.enum(["hackerone", "bugcrowd", "manual"]),
        handle: z.string().min(1),
        name: z.string().min(1),
        url: z.string().optional(),
        state: z.string().optional(),
        minBounty: z.number().optional(),
        maxBounty: z.number().optional(),
        scopeAssets: z
          .array(z.object({ type: z.string(), identifier: z.string(), eligible: z.boolean().optional() }))
          .optional(),
      })
    )
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [result] = await db.insert(bugBountyPrograms).values({
        platform: input.platform,
        handle: input.handle,
        name: input.name,
        url: input.url || null,
        state: input.state || "open",
        minBounty: input.minBounty || null,
        maxBounty: input.maxBounty || null,
        scopeAssets: input.scopeAssets || null,
      });
      return { id: result.insertId };
    }),

  // Add manual finding
  addFinding: protectedProcedure
    .input(
      z.object({
        programId: z.number().optional(),
        platform: z.enum(["hackerone", "bugcrowd", "manual"]),
        title: z.string().min(1),
        severityRating: z.enum(["critical", "high", "medium", "low", "none"]).optional(),
        cveIds: z.array(z.string()).optional(),
        cweId: z.string().optional(),
        cweName: z.string().optional(),
        assetIdentifier: z.string().optional(),
        assetType: z.string().optional(),
        awardedAmount: z.number().optional(),
        summary: z.string().optional(),
        reportUrl: z.string().optional(),
      })
    )
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [result] = await db.insert(bugBountyFindings).values({
        programId: input.programId || null,
        platform: input.platform,
        title: input.title,
        severityRating: input.severityRating || null,
        cveIds: input.cveIds || null,
        cweId: input.cweId || null,
        cweName: input.cweName || null,
        assetIdentifier: input.assetIdentifier || null,
        assetType: input.assetType || null,
        awardedAmount: input.awardedAmount || null,
        summary: input.summary || null,
        reportUrl: input.reportUrl || null,
        disclosedAt: new Date(),
      });
      return { id: result.insertId };
    }),

  // Run correlation engine
  runCorrelation: protectedProcedure
    .input(
      z.object({
        findingIds: z.array(z.number()).optional(),
      })
    )
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const results = await correlateFindings(input.findingIds);

      // Persist correlations
      let inserted = 0;
      for (const corr of results) {
        // Check for duplicate
        const existing = await db
          .select()
          .from(bugBountyCorrelations)
          .where(
            and(
              eq(bugBountyCorrelations.findingId, corr.findingId),
              eq(bugBountyCorrelations.correlationType, corr.correlationType),
              eq(bugBountyCorrelations.matchedEntityId, corr.matchedEntityId)
            )
          )
          .limit(1);

        if (existing.length === 0) {
          await db.insert(bugBountyCorrelations).values({
            findingId: corr.findingId,
            correlationType: corr.correlationType,
            matchedEntityType: corr.matchedEntityType,
            matchedEntityId: corr.matchedEntityId,
            matchedEntityName: corr.matchedEntityName,
            confidenceScore: corr.confidenceScore,
            details: corr.details,
          });
          inserted++;
        }
      }

      return { total: results.length, newCorrelations: inserted };
    }),

  // Get sync history
  syncHistory: protectedProcedure
    .input(
      z.object({
        limit: z.number().min(1).max(50).default(20),
      })
    )
    .query(async ({ input }) => {
      const db = await getDbSafe();
      return db
        .select()
        .from(bugBountySyncLogs)
        .orderBy(desc(bugBountySyncLogs.startedAt))
        .limit(input.limit);
    }),

  // Dashboard stats
  stats: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    const [programCount] = await db
      .select({ count: sql<number>`count(*)` })
      .from(bugBountyPrograms);
    const [findingCount] = await db
      .select({ count: sql<number>`count(*)` })
      .from(bugBountyFindings);
    const [correlationCount] = await db
      .select({ count: sql<number>`count(*)` })
      .from(bugBountyCorrelations);

    // Severity breakdown
    const severityBreakdown = await db
      .select({
        severity: bugBountyFindings.severityRating,
        count: sql<number>`count(*)`,
      })
      .from(bugBountyFindings)
      .groupBy(bugBountyFindings.severityRating);

    // Platform breakdown
    const platformBreakdown = await db
      .select({
        platform: bugBountyFindings.platform,
        count: sql<number>`count(*)`,
      })
      .from(bugBountyFindings)
      .groupBy(bugBountyFindings.platform);

    // Top programs by findings
    const topPrograms = await db
      .select({
        programHandle: bugBountyFindings.programHandle,
        programName: bugBountyFindings.programName,
        count: sql<number>`count(*)`,
        totalAwarded: sql<number>`COALESCE(SUM(${bugBountyFindings.awardedAmount}), 0)`,
      })
      .from(bugBountyFindings)
      .groupBy(bugBountyFindings.programHandle, bugBountyFindings.programName)
      .orderBy(sql`count(*) DESC`)
      .limit(10);

    // Correlation type breakdown
    const correlationBreakdown = await db
      .select({
        type: bugBountyCorrelations.correlationType,
        count: sql<number>`count(*)`,
      })
      .from(bugBountyCorrelations)
      .groupBy(bugBountyCorrelations.correlationType);

    return {
      programs: programCount?.count || 0,
      findings: findingCount?.count || 0,
      correlations: correlationCount?.count || 0,
      severityBreakdown,
      platformBreakdown,
      topPrograms,
      correlationBreakdown,
    };
  }),

  // Delete a program
  deleteProgram: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.delete(bugBountyPrograms).where(eq(bugBountyPrograms.id, input.id));
      return { success: true };
    }),

  // Delete a finding
  deleteFinding: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      // Also delete associated correlations
      await db.delete(bugBountyCorrelations).where(eq(bugBountyCorrelations.findingId, input.id));
      await db.delete(bugBountyFindings).where(eq(bugBountyFindings.id, input.id));
      return { success: true };
    }),

  // ─── Bug Bounty Intelligence Service ───────────────────────────────────────

  // Enrich Domain Intel with HackerOne disclosed vulnerability data
  enrichDomain: protectedProcedure
    .input(z.object({ domain: z.string().min(1) }))
    .mutation(async ({ input }) => {
      const { enrichDomainIntel } = await import("../lib/bug-bounty-intelligence");
      return enrichDomainIntel(input.domain);
    }),

  // Enrich Threat Intelligence with CWE trends, severity distribution, exploit patterns
  enrichThreats: protectedProcedure
    .input(z.object({ timeRangeDays: z.number().min(7).max(365).default(90) }))
    .mutation(async ({ input }) => {
      const { enrichThreatIntelligence } = await import("../lib/bug-bounty-intelligence");
      return enrichThreatIntelligence(input.timeRangeDays);
    }),

  // Enrich Attack Vectors with bounty-validated attack surfaces
  enrichAttackVectors: protectedProcedure
    .mutation(async () => {
      const { enrichAttackVectors } = await import("../lib/bug-bounty-intelligence");
      return enrichAttackVectors();
    }),

  // Enrich OpSec with weakness categories and defensive priorities
  enrichOpSec: protectedProcedure
    .mutation(async () => {
      const { enrichOpSec } = await import("../lib/bug-bounty-intelligence");
      return enrichOpSec();
    }),

  // Generate full cross-module intelligence report
  fullIntelReport: protectedProcedure
    .input(z.object({ domain: z.string().optional() }))
    .mutation(async ({ input }) => {
      const { generateFullIntelligenceReport } = await import("../lib/bug-bounty-intelligence");
      return generateFullIntelligenceReport(input.domain);
    }),

  // ═══════════════════════════════════════════════════════════════════════
  // LLM TRAINING ENGINE
  // ═══════════════════════════════════════════════════════════════════════

  // Extract training samples from HackerOne disclosed findings
  extractH1Training: protectedProcedure
    .input(z.object({
      minBounty: z.number().default(0),
      minSeverity: z.string().optional(),
      limit: z.number().min(1).max(500).default(100),
    }).optional())
    .mutation(async ({ input }) => {
      const { extractFromHackerOneFindings } = await import("../lib/bounty-training-engine");
      return extractFromHackerOneFindings({
        minBounty: input?.minBounty || 0,
        minSeverity: input?.minSeverity,
        limit: input?.limit || 100,
      });
    }),

  // Extract training samples from AC3 engagement findings (Nuclei, ZAP, exploits, reports)
  extractEngagementTraining: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      limit: z.number().min(1).max(500).default(200),
    }).optional())
    .mutation(async ({ input }) => {
      const { extractFromEngagementFindings } = await import("../lib/bounty-training-engine");
      return extractFromEngagementFindings({
        engagementId: input?.engagementId,
        limit: input?.limit || 200,
      });
    }),

  // Enrich raw training samples with LLM-generated narratives and attack techniques
  enrichTraining: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(50).default(20),
      category: z.enum(["vuln_pattern", "exploit_chain", "report_template", "scope_recon", "cwe_analysis", "bounty_strategy", "novel_finding"]).optional(),
    }).optional())
    .mutation(async ({ input }) => {
      const { enrichTrainingSamples } = await import("../lib/bounty-training-engine");
      return enrichTrainingSamples({
        limit: input?.limit || 20,
        category: input?.category as any,
      });
    }),

  // Export training data as JSONL for fine-tuning
  exportTrainingJSONL: protectedProcedure
    .input(z.object({
      minQuality: z.number().min(0).max(1).default(0.3),
      categories: z.array(z.enum(["vuln_pattern", "exploit_chain", "report_template", "scope_recon", "cwe_analysis", "bounty_strategy", "novel_finding"])).optional(),
      enrichedOnly: z.boolean().default(false),
    }).optional())
    .mutation(async ({ input }) => {
      const { exportAsJSONL } = await import("../lib/bounty-training-engine");
      return exportAsJSONL({
        minQuality: input?.minQuality || 0.3,
        categories: input?.categories as any,
        enrichedOnly: input?.enrichedOnly || false,
      });
    }),

  // Get training pipeline stats
  trainingStats: protectedProcedure
    .query(async () => {
      const { getTrainingStats } = await import("../lib/bounty-training-engine");
      return getTrainingStats();
    }),

  // Get bounty ROI analytics (which CWEs/programs pay most)
  bountyROI: protectedProcedure
    .query(async () => {
      const { getBountyROIAnalytics } = await import("../lib/bounty-training-engine");
      return getBountyROIAnalytics();
    }),

  // ═══════════════════════════════════════════════════════════════════════
  // SCANFORGE BRIDGE — Disclosed Vulns → Detection Templates
  // ═══════════════════════════════════════════════════════════════════════

  // Generate ScanForge templates from all disclosed HackerOne findings
  generateScanForgeTemplates: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(100).default(25),
      minSeverity: z.string().optional(),
    }).optional())
    .mutation(async ({ input }) => {
      const { generateScanForgeTemplatesFromFindings } = await import("../lib/bounty-training-engine");
      return generateScanForgeTemplatesFromFindings({
        limit: input?.limit || 25,
        minSeverity: input?.minSeverity,
      });
    }),

  // Get ScanForge bridge stats
  scanForgeBridgeStats: protectedProcedure
    .query(async () => {
      const { getScanForgeBridgeStats } = await import("../lib/bounty-training-engine");
      return getScanForgeBridgeStats();
    }),

  // ─── Multi-Platform Sync ───

  // Sync a specific platform (Bugcrowd, Intigriti, YesWeHack, Open Bug Bounty, Immunefi)
  syncPlatform: protectedProcedure
    .input(
      z.object({
        platform: z.enum(["bugcrowd", "intigriti", "yeswehack", "open_bug_bounty", "immunefi"]),
        pages: z.number().min(1).max(10).default(3),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const { syncPlatform } = await import("../lib/bounty-platform-sync");
      return syncPlatform(ctx.user.id, input.platform, input.pages);
    }),

  // Sync all platforms with active credentials + public platforms
  syncAllPlatforms: protectedProcedure
    .input(
      z.object({
        pages: z.number().min(1).max(10).default(3),
      }).optional()
    )
    .mutation(async ({ ctx, input }) => {
      const { syncAllPlatforms } = await import("../lib/bounty-platform-sync");
      return syncAllPlatforms(ctx.user.id, input?.pages || 3);
    }),

  // ─── Automated Intel Pipeline ───

  // Manually trigger the full bug bounty intelligence pipeline
  runIntelPipeline: protectedProcedure
    .mutation(async () => {
      const { runBountyIntelPipeline } = await import("../lib/bounty-intel-scheduler");
      return runBountyIntelPipeline("manual");
    }),

  // ─── Engagement Builder (Create Engagement from Program) ───

  // Preview engagement plan from a synced program (LLM-powered)
  buildEngagementPreview: protectedProcedure
    .input(
      z.object({
        programId: z.number().optional(),
        programUrl: z.string().optional(),
        programName: z.string().optional(),
        platform: z.string().optional(),
      })
    )
    .mutation(async ({ input }) => {
      const { buildEngagementPreview } = await import("../lib/engagement-builder");
      return buildEngagementPreview(input);
    }),

  // Create engagement from a previewed plan
  createEngagementFromProgram: protectedProcedure
    .input(
      z.object({
        preview: z.any(), // EngagementPreview object from buildEngagementPreview
        customName: z.string().optional(),
        scanMode: z.enum(["strict_passive", "standard", "active"]).optional(),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const { createEngagementFromPreview } = await import("../lib/engagement-builder");
      return createEngagementFromPreview(input.preview, ctx.user.id, {
        customName: input.customName,
        scanMode: input.scanMode,
      });
    }),

  // ─── Burp Suite Integration ───

  // Verify Burp Suite connection
  verifyBurpConnection: protectedProcedure
    .input(
      z.object({
        edition: z.enum(["professional", "enterprise"]),
        baseUrl: z.string().min(1),
        apiKey: z.string().min(1),
      })
    )
    .mutation(async ({ input }) => {
      const { BurpSuiteConnector } = await import("../lib/burpsuite-connector");
      const connector = new BurpSuiteConnector(input);
      return connector.verify();
    }),

  // Import issues from a Burp Suite scan into findings
  importBurpIssues: protectedProcedure
    .input(
      z.object({
        credentialId: z.number(),
        scanId: z.string(),
        engagementHandle: z.string().optional(),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const db = await getDbSafe();
      const { BurpSuiteConnector, normalizeBurpIssues } = await import("../lib/burpsuite-connector");

      // Get the credential
      const [cred] = await db
        .select()
        .from(userPlatformCredentials)
        .where(and(eq(userPlatformCredentials.id, input.credentialId), eq(userPlatformCredentials.userId, ctx.user.id)))
        .limit(1);

      if (!cred) throw new TRPCError({ code: "NOT_FOUND", message: "Burp Suite credential not found" });

      const apiKey = decrypt(cred.apiKeyEncrypted);
      const edition = cred.platform === "burpsuite_enterprise" ? "enterprise" : "professional";
      const connector = new BurpSuiteConnector({
        edition,
        baseUrl: cred.baseUrl || "http://127.0.0.1:1337",
        apiKey,
      });

      const issues = await connector.getIssues(input.scanId);
      const normalized = normalizeBurpIssues(
        issues,
        input.engagementHandle || "burpsuite-import",
        edition
      );

      let imported = 0;
      for (const finding of normalized) {
        try {
          await db.insert(bugBountyFindings).values({
            platform: "burpsuite" as any,
            title: finding.title.substring(0, 1024),
            severityRating: finding.severityRating,
            summary: finding.summary,
            assetIdentifier: finding.assetIdentifier.substring(0, 512),
            assetType: finding.assetType,
            cweId: finding.cweId,
            cveIds: finding.cveIds,
            programHandle: finding.programHandle,
            programName: `Burp Suite ${edition === "enterprise" ? "Enterprise" : "Professional"} Import`,
            externalId: `burp-${input.scanId}-${finding.metadata.serialNumber || imported}`,
          });
          imported++;
        } catch {
          // Skip duplicates
        }
      }

      return { imported, total: issues.length, scanId: input.scanId };
    }),

  // Get Burp Suite scan status
  getBurpScanStatus: protectedProcedure
    .input(
      z.object({
        credentialId: z.number(),
        scanId: z.string(),
      })
    )
    .query(async ({ ctx, input }) => {
      const db = await getDbSafe();
      const { BurpSuiteConnector } = await import("../lib/burpsuite-connector");

      const [cred] = await db
        .select()
        .from(userPlatformCredentials)
        .where(and(eq(userPlatformCredentials.id, input.credentialId), eq(userPlatformCredentials.userId, ctx.user.id)))
        .limit(1);

      if (!cred) throw new TRPCError({ code: "NOT_FOUND", message: "Credential not found" });

      const apiKey = decrypt(cred.apiKeyEncrypted);
      const edition = cred.platform === "burpsuite_enterprise" ? "enterprise" : "professional";
      const connector = new BurpSuiteConnector({
        edition,
        baseUrl: cred.baseUrl || "http://127.0.0.1:1337",
        apiKey,
      });

      return connector.getScanStatus(input.scanId);
    }),

  // List Burp Suite Enterprise sites
  listBurpSites: protectedProcedure
    .input(z.object({ credentialId: z.number() }))
    .query(async ({ ctx, input }) => {
      const db = await getDbSafe();
      const { BurpSuiteConnector } = await import("../lib/burpsuite-connector");

      const [cred] = await db
        .select()
        .from(userPlatformCredentials)
        .where(and(eq(userPlatformCredentials.id, input.credentialId), eq(userPlatformCredentials.userId, ctx.user.id)))
        .limit(1);

      if (!cred) throw new TRPCError({ code: "NOT_FOUND", message: "Credential not found" });
      if (cred.platform !== "burpsuite_enterprise") {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Site listing is only available for Burp Suite Enterprise/DAST" });
      }

      const apiKey = decrypt(cred.apiKeyEncrypted);
      const connector = new BurpSuiteConnector({
        edition: "enterprise",
        baseUrl: cred.baseUrl || "",
        apiKey,
      });

      return connector.listSitesEnterprise();
    }),

  // ─── Burp Suite Auto-Scan Endpoints ───

  // Launch a Burp Suite auto-scan for an engagement
  launchBurpAutoScan: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      credentialId: z.number(),
      scanConfigName: z.string().optional(),
      appLogin: z.object({
        username: z.string(),
        password: z.string(),
        loginUrl: z.string().optional(),
      }).optional(),
    }))
    .mutation(async ({ ctx, input }) => {
      const db = await getDbSafe();
      const { launchBurpAutoScan, extractScopeUrls } = await import("../lib/burp-auto-scan");

      // Get engagement
      const [engagement] = await db
        .select()
        .from(engagements)
        .where(eq(engagements.id, input.engagementId))
        .limit(1);
      if (!engagement) throw new TRPCError({ code: "NOT_FOUND", message: "Engagement not found" });

      // Get credential
      const [cred] = await db
        .select()
        .from(userPlatformCredentials)
        .where(and(eq(userPlatformCredentials.id, input.credentialId), eq(userPlatformCredentials.userId, ctx.user.id)))
        .limit(1);
      if (!cred) throw new TRPCError({ code: "NOT_FOUND", message: "Burp Suite credential not found" });

      const apiKey = decrypt(cred.apiKeyEncrypted);
      const edition = cred.platform === "burpsuite_enterprise" ? "enterprise" : "professional";

      // Extract scope URLs from engagement
      const scopeUrls = extractScopeUrls(engagement);
      if (scopeUrls.length === 0) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "No web URLs found in engagement scope. Add HTTP/HTTPS targets to the engagement scope first." });
      }

      const state = await launchBurpAutoScan({
        engagementId: input.engagementId,
        engagementHandle: (engagement as any).handle || engagement.name || `eng-${input.engagementId}`,
        userId: ctx.user.id,
        targetUrls: scopeUrls,
        credentialId: input.credentialId,
        burpConfig: {
          edition: edition as any,
          baseUrl: cred.baseUrl || "http://127.0.0.1:1337",
          apiKey,
        },
        scanConfigName: input.scanConfigName,
        appLogin: input.appLogin,
        scanMode: (engagement as any).scanMode || "standard",
      });

      return {
        scanId: state.scanId,
        status: state.status,
        targetUrls: state.targetUrls,
        edition: state.edition,
      };
    }),

  // Get Burp auto-scan progress for an engagement
  getBurpAutoScanProgress: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      credentialId: z.number().optional(),
    }))
    .query(async ({ input }) => {
      const { getEngagementBurpScans, getBurpAutoScanState } = await import("../lib/burp-auto-scan");

      if (input.credentialId) {
        const state = getBurpAutoScanState(input.engagementId, input.credentialId);
        return { scans: state ? [state] : [] };
      }

      return { scans: getEngagementBurpScans(input.engagementId) };
    }),

  // Cancel a Burp auto-scan
  cancelBurpAutoScan: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      credentialId: z.number(),
    }))
    .mutation(async ({ input }) => {
      const { cancelBurpAutoScan } = await import("../lib/burp-auto-scan");
      const cancelled = await cancelBurpAutoScan(input.engagementId, input.credentialId);
      return { cancelled };
    }),

  // Get Burp auto-scan stats
  getBurpAutoScanStats: protectedProcedure
    .query(async () => {
      const { getBurpAutoScanStats } = await import("../lib/burp-auto-scan");
      return getBurpAutoScanStats();
    }),
});
