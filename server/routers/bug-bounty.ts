/**
 * Bug Bounty Platform Integration Router
 * Integrates HackerOne and Bugcrowd live feeds, correlates findings
 * with existing vulnerability intelligence and discovered assets.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { ENV } from "../_core/env";
import { getDb as _getDb } from "../db";
import {
  bugBountyPrograms,
  bugBountyFindings,
  bugBountyCorrelations,
  bugBountySyncLogs,
  discoveredAssets,
  iocFeeds,
  domainIntelScans,
} from "../../drizzle/schema";
import { eq, desc, like, and, or, sql, inArray } from "drizzle-orm";

async function getDbSafe() {
  const db = await _getDb();
  return db!;
}

// ─── HackerOne API Client ───

const H1_BASE = "https://api.hackerone.com/v1/hackers";

async function h1Fetch(path: string) {
  const username = ENV.HACKERONE_API_USERNAME;
  const token = ENV.HACKERONE_API_TOKEN;
  const headers: Record<string, string> = {
    Accept: "application/json",
  };
  if (username && token) {
    headers.Authorization =
      "Basic " + Buffer.from(`${username}:${token}`).toString("base64");
  }
  const res = await fetch(`${H1_BASE}${path}`, {
    headers,
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(
      `HackerOne API ${res.status}: ${res.statusText}${body ? ` — ${body.slice(0, 200)}` : ""}`
    );
  }
  return res.json();
}

// ─── Bugcrowd API Client ───

const BC_BASE = "https://api.bugcrowd.com";

async function bcFetch(path: string) {
  const token = ENV.BUGCROWD_API_TOKEN;
  if (!token) {
    throw new Error(
      "Bugcrowd API token not configured. Set BUGCROWD_API_TOKEN in secrets."
    );
  }
  const headers: Record<string, string> = {
    Accept: "application/vnd.bugcrowd+json",
    Authorization: `Token ${token}`,
  };
  const res = await fetch(`${BC_BASE}${path}`, {
    headers,
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(
      `Bugcrowd API ${res.status}: ${res.statusText}${body ? ` — ${body.slice(0, 200)}` : ""}`
    );
  }
  return res.json();
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

async function correlateFindings(
  findingIds?: number[]
): Promise<CorrelationResult[]> {
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
            confidenceScore: hostname === findingAsset ? 0.98 : 0.75,
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

    // 3. CWE Match: match finding CWE against asset posture findings
    if (finding.cweId) {
      for (const asset of assets) {
        const postureFindings =
          (asset.postureFindings as Array<{ cwe?: string; title?: string }>) ||
          [];
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
  // Check API credential status
  credentialStatus: protectedProcedure.query(async () => {
    return {
      hackerOne: {
        configured: !!(ENV.HACKERONE_API_USERNAME && ENV.HACKERONE_API_TOKEN),
        username: ENV.HACKERONE_API_USERNAME
          ? ENV.HACKERONE_API_USERNAME.slice(0, 3) + "***"
          : null,
      },
      bugcrowd: {
        configured: !!ENV.BUGCROWD_API_TOKEN,
      },
    };
  }),

  // List programs with search and filtering
  listPrograms: protectedProcedure
    .input(
      z.object({
        platform: z
          .enum(["hackerone", "bugcrowd", "manual", "all"])
          .default("all"),
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
        platform: z
          .enum(["hackerone", "bugcrowd", "manual", "all"])
          .default("all"),
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
        conditions.push(
          eq(bugBountyCorrelations.findingId, input.findingId)
        );
      }
      if (input.correlationType) {
        conditions.push(
          eq(bugBountyCorrelations.correlationType, input.correlationType)
        );
      }
      if (input.minConfidence > 0) {
        conditions.push(
          sql`${bugBountyCorrelations.confidenceScore} >= ${input.minConfidence}`
        );
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

  // ─── HackerOne Sync ───

  syncHackerOneHacktivity: protectedProcedure
    .input(
      z.object({
        queryString: z
          .string()
          .default("severity_rating:critical OR severity_rating:high"),
        pages: z.number().min(1).max(10).default(3),
      })
    )
    .mutation(async ({ input }) => {
      if (!ENV.HACKERONE_API_USERNAME || !ENV.HACKERONE_API_TOKEN) {
        throw new TRPCError({
          code: "PRECONDITION_FAILED",
          message:
            "HackerOne API credentials not configured. Add HACKERONE_API_USERNAME and HACKERONE_API_TOKEN in Settings > Secrets.",
        });
      }

      const db = await getDbSafe();
      const [logResult] = await db.insert(bugBountySyncLogs).values({
        platform: "hackerone",
        syncType: "hacktivity",
        status: "running",
      });
      const logId = logResult.insertId;

      try {
        let totalSynced = 0;

        for (let page = 1; page <= input.pages; page++) {
          const path = `/hacktivity?queryString=${encodeURIComponent(input.queryString)}&page[number]=${page}&page[size]=25`;
          const data = await h1Fetch(path);

          if (!data?.data?.length) break;

          for (const item of data.data) {
            const attrs = item.attributes || {};
            const reporter =
              item.relationships?.reporter?.data?.attributes;
            const program =
              item.relationships?.program?.data?.attributes;

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
                disclosedAt: attrs.disclosed_at
                  ? new Date(attrs.disclosed_at)
                  : null,
                awardedAmount: attrs.total_awarded_amount || null,
                reporterUsername: reporter?.username || null,
                reporterReputation: reporter?.reputation || null,
                programHandle: program?.handle || null,
                programName: program?.name || null,
                votes: attrs.votes || 0,
              });
              totalSynced++;
            }
          }
        }

        await db
          .update(bugBountySyncLogs)
          .set({
            status: "completed",
            itemsSynced: totalSynced,
            completedAt: new Date(),
          })
          .where(eq(bugBountySyncLogs.id, Number(logId)));

        return { success: true, synced: totalSynced };
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
          message: `HackerOne sync failed: ${err.message}`,
        });
      }
    }),

  syncHackerOnePrograms: protectedProcedure
    .input(
      z.object({
        pages: z.number().min(1).max(10).default(3),
      })
    )
    .mutation(async ({ input }) => {
      if (!ENV.HACKERONE_API_USERNAME || !ENV.HACKERONE_API_TOKEN) {
        throw new TRPCError({
          code: "PRECONDITION_FAILED",
          message:
            "HackerOne API credentials not configured. Add HACKERONE_API_USERNAME and HACKERONE_API_TOKEN in Settings > Secrets.",
        });
      }

      const db = await getDbSafe();
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
          const data = await h1Fetch(path);

          if (!data?.data?.length) break;

          for (const item of data.data) {
            const attrs = item.attributes || {};

            const existing = await db
              .select()
              .from(bugBountyPrograms)
              .where(
                and(
                  eq(bugBountyPrograms.platform, "hackerone"),
                  eq(
                    bugBountyPrograms.handle,
                    attrs.handle || String(item.id)
                  )
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
                  submissionState:
                    attrs.submission_state || existing[0].submissionState,
                  lastSyncedAt: new Date(),
                })
                .where(eq(bugBountyPrograms.id, existing[0].id));
              totalSynced++;
            }
          }
        }

        await db
          .update(bugBountySyncLogs)
          .set({
            status: "completed",
            itemsSynced: totalSynced,
            completedAt: new Date(),
          })
          .where(eq(bugBountySyncLogs.id, Number(logId)));

        return { success: true, synced: totalSynced };
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
          message: `HackerOne programs sync failed: ${err.message}`,
        });
      }
    }),

  // ─── Bugcrowd Sync ───

  syncBugcrowdPrograms: protectedProcedure
    .input(
      z.object({
        pages: z.number().min(1).max(10).default(3),
      })
    )
    .mutation(async ({ input }) => {
      if (!ENV.BUGCROWD_API_TOKEN) {
        throw new TRPCError({
          code: "PRECONDITION_FAILED",
          message:
            "Bugcrowd API token not configured. Add BUGCROWD_API_TOKEN in Settings > Secrets.",
        });
      }

      const db = await getDbSafe();
      const [logResult] = await db.insert(bugBountySyncLogs).values({
        platform: "bugcrowd",
        syncType: "programs",
        status: "running",
      });
      const logId = logResult.insertId;

      try {
        let totalSynced = 0;
        let nextUrl: string | null = `/programs?page[limit]=25`;

        for (let page = 0; page < input.pages && nextUrl; page++) {
          const data = await bcFetch(nextUrl);
          const items = data?.data || [];

          for (const item of items) {
            const attrs = item.attributes || {};
            const handle = attrs.code || item.id;

            const existing = await db
              .select()
              .from(bugBountyPrograms)
              .where(
                and(
                  eq(bugBountyPrograms.platform, "bugcrowd"),
                  eq(bugBountyPrograms.handle, handle)
                )
              )
              .limit(1);

            if (existing.length === 0) {
              await db.insert(bugBountyPrograms).values({
                platform: "bugcrowd",
                handle,
                name: attrs.name || handle,
                url: attrs.program_url || `https://bugcrowd.com/${handle}`,
                logoUrl: attrs.logo || null,
                state: attrs.status || null,
                submissionState: attrs.submission_state || null,
                currency: "USD",
                lastSyncedAt: new Date(),
              });
              totalSynced++;
            } else {
              await db
                .update(bugBountyPrograms)
                .set({
                  name: attrs.name || existing[0].name,
                  state: attrs.status || existing[0].state,
                  lastSyncedAt: new Date(),
                })
                .where(eq(bugBountyPrograms.id, existing[0].id));
              totalSynced++;
            }
          }

          // Pagination via JSON API links
          nextUrl = data?.links?.next || null;
        }

        await db
          .update(bugBountySyncLogs)
          .set({
            status: "completed",
            itemsSynced: totalSynced,
            completedAt: new Date(),
          })
          .where(eq(bugBountySyncLogs.id, Number(logId)));

        return { success: true, synced: totalSynced };
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
          message: `Bugcrowd programs sync failed: ${err.message}`,
        });
      }
    }),

  syncBugcrowdSubmissions: protectedProcedure
    .input(
      z.object({
        pages: z.number().min(1).max(10).default(3),
      })
    )
    .mutation(async ({ input }) => {
      if (!ENV.BUGCROWD_API_TOKEN) {
        throw new TRPCError({
          code: "PRECONDITION_FAILED",
          message:
            "Bugcrowd API token not configured. Add BUGCROWD_API_TOKEN in Settings > Secrets.",
        });
      }

      const db = await getDbSafe();
      const [logResult] = await db.insert(bugBountySyncLogs).values({
        platform: "bugcrowd",
        syncType: "submissions",
        status: "running",
      });
      const logId = logResult.insertId;

      try {
        let totalSynced = 0;
        let nextUrl: string | null = `/submissions?page[limit]=25&filter[state]=accepted&filter[disclosed]=true&sort=-submitted_at`;

        for (let page = 0; page < input.pages && nextUrl; page++) {
          const data = await bcFetch(nextUrl);
          const items = data?.data || [];

          for (const item of items) {
            const attrs = item.attributes || {};
            const externalId = item.id;

            const existing = await db
              .select()
              .from(bugBountyFindings)
              .where(
                and(
                  eq(bugBountyFindings.platform, "bugcrowd"),
                  eq(bugBountyFindings.externalId, String(externalId))
                )
              )
              .limit(1);

            if (existing.length === 0) {
              // Map Bugcrowd priority to severity
              const priorityMap: Record<number, string> = {
                1: "critical",
                2: "high",
                3: "medium",
                4: "low",
                5: "none",
              };
              const severity =
                priorityMap[attrs.priority] || attrs.severity || null;

              await db.insert(bugBountyFindings).values({
                platform: "bugcrowd",
                externalId: String(externalId),
                title: attrs.title || "Untitled Submission",
                severityRating: severity,
                cveIds: attrs.cve_ids || null,
                cweId: attrs.cwe || null,
                substate: attrs.state || null,
                reportUrl: attrs.bug_url || null,
                disclosedAt: attrs.disclosed_at
                  ? new Date(attrs.disclosed_at)
                  : attrs.submitted_at
                    ? new Date(attrs.submitted_at)
                    : null,
                awardedAmount: attrs.amount || null,
                reporterUsername: attrs.researcher?.username || null,
                programHandle: attrs.program?.code || null,
                programName: attrs.program?.name || null,
                assetIdentifier: attrs.target?.name || null,
                assetType: attrs.target?.category || null,
                votes: 0,
              });
              totalSynced++;
            }
          }

          nextUrl = data?.links?.next || null;
        }

        await db
          .update(bugBountySyncLogs)
          .set({
            status: "completed",
            itemsSynced: totalSynced,
            completedAt: new Date(),
          })
          .where(eq(bugBountySyncLogs.id, Number(logId)));

        return { success: true, synced: totalSynced };
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
          message: `Bugcrowd submissions sync failed: ${err.message}`,
        });
      }
    }),

  // ─── Domain-to-Program Matching ───
  // Matches scanned domains against bug bounty program scope assets
  matchDomainsToPrograms: protectedProcedure.mutation(async () => {
    const db = await getDbSafe();

    // Get all scanned domains
    const scans = await db
      .select({ id: domainIntelScans.id, domain: domainIntelScans.primaryDomain })
      .from(domainIntelScans);

    // Get all programs with scope assets
    const programs = await db.select().from(bugBountyPrograms);

    const matches: Array<{
      domain: string;
      programName: string;
      programHandle: string;
      platform: string;
      matchType: string;
    }> = [];

    for (const scan of scans) {
      const domain = scan.domain?.toLowerCase();
      if (!domain) continue;

      for (const program of programs) {
        const scopeAssets =
          (program.scopeAssets as Array<{
            type?: string;
            identifier?: string;
            eligible?: boolean;
          }>) || [];

        // Check scope assets
        for (const asset of scopeAssets) {
          const id = asset.identifier?.toLowerCase() || "";
          if (!id) continue;

          if (
            domain === id ||
            domain.endsWith("." + id) ||
            id.endsWith("." + domain) ||
            id.includes(domain) ||
            domain.includes(id)
          ) {
            matches.push({
              domain,
              programName: program.name,
              programHandle: program.handle,
              platform: program.platform,
              matchType: "scope_asset",
            });
          }
        }

        // Also check program handle/name against domain
        const handle = program.handle?.toLowerCase() || "";
        const name = program.name?.toLowerCase() || "";
        if (
          handle &&
          (domain.includes(handle) || handle.includes(domain.split(".")[0]))
        ) {
          matches.push({
            domain,
            programName: program.name,
            programHandle: program.handle,
            platform: program.platform,
            matchType: "handle_match",
          });
        }
      }
    }

    // Deduplicate
    const seen = new Set<string>();
    const unique = matches.filter((m) => {
      const key = `${m.domain}:${m.programHandle}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    return { matches: unique, total: unique.length };
  }),

  // ─── Manual CRUD ───

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
          .array(
            z.object({
              type: z.string(),
              identifier: z.string(),
              eligible: z.boolean().optional(),
            })
          )
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

  addFinding: protectedProcedure
    .input(
      z.object({
        programId: z.number().optional(),
        platform: z.enum(["hackerone", "bugcrowd", "manual"]),
        title: z.string().min(1),
        severityRating: z
          .enum(["critical", "high", "medium", "low", "none"])
          .optional(),
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

      let inserted = 0;
      for (const corr of results) {
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

    const severityBreakdown = await db
      .select({
        severity: bugBountyFindings.severityRating,
        count: sql<number>`count(*)`,
      })
      .from(bugBountyFindings)
      .groupBy(bugBountyFindings.severityRating);

    const platformBreakdown = await db
      .select({
        platform: bugBountyFindings.platform,
        count: sql<number>`count(*)`,
      })
      .from(bugBountyFindings)
      .groupBy(bugBountyFindings.platform);

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
      await db
        .delete(bugBountyPrograms)
        .where(eq(bugBountyPrograms.id, input.id));
      return { success: true };
    }),

  // Delete a finding
  deleteFinding: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db
        .delete(bugBountyCorrelations)
        .where(eq(bugBountyCorrelations.findingId, input.id));
      await db
        .delete(bugBountyFindings)
        .where(eq(bugBountyFindings.id, input.id));
      return { success: true };
    }),
});
