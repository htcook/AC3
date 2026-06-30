import * as db from "../db";
/**
 * Bug Bounty Platform Integration Router
 * Integrates HackerOne and Bugcrowd live feeds, correlates findings
 * with existing vulnerability intelligence and discovered assets.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { assertEngagementAccess } from "../lib/engagement-access-guard";
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
 * Unified H1 credential resolution — delegates to credential-service.ts
 * which handles: DB per-user lookup → env var fallback.
 * This ensures all BB platform credential fixes apply universally to all users.
 */
async function resolveH1Credentials(userId: number): Promise<{ username: string; token: string } | null> {
  try {
    const { getH1CredentialsForUser } = await import('../lib/credential-service.js');
    const creds = await getH1CredentialsForUser(userId);
    if (creds) {
      return { username: creds.username, token: creds.apiKey };
    }
  } catch (err: any) {
    console.warn('[BugBounty] credential-service lookup failed:', err.message);
  }
  // No direct env fallback — credential-service already handles DB → env with validation
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

// ─── Lab Asset Auto-Registration ───

/**
 * Auto-register the deployed test lab as an engagement target asset.
 * Also removes out-of-scope *.nextcloud.com domain assets from the ops state.
 * Called automatically after successful test lab deployment.
 */
async function autoRegisterLabAsset(
  engagementId: number,
  labUrl: string,
  scanServerHost: string
): Promise<{ registered: boolean; removedOutOfScope: string[] }> {
  const db = await getDbSafe();
  const removedOutOfScope: string[] = [];

  // 1. Update engagement targetDomain and targetIpRange
  let host: string;
  try {
    const url = new URL(labUrl);
    host = url.hostname;
  } catch {
    host = labUrl.replace(/https?:\/\//, '').split(':')[0];
  }

  await db.update(engagements)
    .set({
      targetDomain: host,
      targetIpRange: scanServerHost,
      notes: [
        `Test Lab URL: ${labUrl}`,
        `Scan Server: ${scanServerHost}`,
        `Deployed via AC3 Nextcloud Test Lab`,
        `Auto-registered: ${new Date().toISOString()}`,
        `Note: *.nextcloud.com domains removed (out-of-scope per HackerOne program rules)`,
      ].join('\n'),
    })
    .where(eq(engagements.id, engagementId));

  // 2. Update ops state snapshot: add lab asset, remove out-of-scope nextcloud.com assets
  const { engagementOpsSnapshots } = await import("../../drizzle/schema");
  const [snapshot] = await db.select()
    .from(engagementOpsSnapshots)
    .where(eq(engagementOpsSnapshots.engagementId, engagementId))
    .limit(1);

  if (snapshot) {
    const state = snapshot.stateJson as any;
    const assets = Array.isArray(state.assets) ? state.assets : [];

    // Remove out-of-scope nextcloud.com domain assets
    const filteredAssets = assets.filter((a: any) => {
      const hostname = (a.hostname || '').toLowerCase();
      if (
        hostname === 'nextcloud.com' ||
        hostname.endsWith('.nextcloud.com')
      ) {
        removedOutOfScope.push(hostname);
        return false;
      }
      return true;
    });

    // Check if lab asset already exists
    const labAssetExists = filteredAssets.some(
      (a: any) => (a.hostname || '').includes(scanServerHost)
    );

    if (!labAssetExists) {
      // Add the test lab as a new target asset with all known scan server ports
      filteredAssets.push({
        hostname: `${scanServerHost}:8443`,
        type: 'web_app',
        status: 'discovered',
        ports: [
          { port: 22, service: 'ssh', version: 'OpenSSH' },
          { port: 80, service: 'http', version: 'nginx/1.18.0' },
          { port: 443, service: 'https', version: 'nginx/1.18.0' },
          { port: 4000, service: 'http', version: 'Node.js/Express' },
          { port: 8090, service: 'http-alt', version: '' },
          { port: 8443, service: 'https', version: 'Nextcloud Test Lab' },
          { port: 8444, service: 'https', version: 'phpLDAPadmin' },
          { port: 8445, service: 'https', version: 'Keycloak SSO' },
          { port: 8447, service: 'https', version: 'MinIO Console' },
          { port: 8448, service: 'http', version: 'Mailhog SMTP UI' },
        ],
        vulns: [],
        exploitAttempts: [],
        toolResults: [],
        pendingVulns: [],
        confirmedCredentials: [],
        passiveRecon: {
          technologies: ['Nextcloud', 'PHP', 'MariaDB', 'Redis', 'Collabora', 'OpenLDAP', 'Keycloak', 'MinIO', 'ClamAV'],
          cloudProvider: 'DigitalOcean',
          subdomains: [],
          ipAddresses: [scanServerHost],
          certificates: [],
          historicalUrls: [],
          riskSignals: [],
          services: [],
          sources: ['AC3 Test Lab Deployer'],
          rawObservationCount: 0,
        },
        notes: `AC3 Nextcloud Bug Bounty Test Lab - auto-registered on deploy. Lab URL: ${labUrl}`,
        inScope: true,
        labDeployed: true,
      });
    }

    // ═══ UPDATE RoE SCOPE GUARD ═══
    // Ensure the lab IP/hostname is in the authorized scope so it won't be excluded
    // during active scan plan generation or vuln_detection phase
    if (!state.roeScopeGuard) {
      state.roeScopeGuard = {
        authorizedDomains: [host],
        authorizedIps: [scanServerHost],
        roeStatus: 'signed',
      };
    } else {
      // Add the lab hostname (IP:port format) to authorizedDomains if not already present
      const labHostPort = `${scanServerHost}:8443`;
      if (!state.roeScopeGuard.authorizedDomains) state.roeScopeGuard.authorizedDomains = [];
      if (!state.roeScopeGuard.authorizedIps) state.roeScopeGuard.authorizedIps = [];

      if (!state.roeScopeGuard.authorizedDomains.includes(host)) {
        state.roeScopeGuard.authorizedDomains.push(host);
      }
      if (!state.roeScopeGuard.authorizedDomains.includes(labHostPort)) {
        state.roeScopeGuard.authorizedDomains.push(labHostPort);
      }
      if (!state.roeScopeGuard.authorizedIps.includes(scanServerHost)) {
        state.roeScopeGuard.authorizedIps.push(scanServerHost);
      }

      // Remove out-of-scope nextcloud.com domains from authorized list
      state.roeScopeGuard.authorizedDomains = state.roeScopeGuard.authorizedDomains.filter(
        (d: string) => !d.toLowerCase().endsWith('.nextcloud.com') && d.toLowerCase() !== 'nextcloud.com'
      );
    }

    // Save updated state
    state.assets = filteredAssets;
    await db.update(engagementOpsSnapshots)
      .set({
        stateJson: state,
        assetCount: filteredAssets.length,
      })
      .where(eq(engagementOpsSnapshots.engagementId, engagementId));
  }

  // 3. Log timeline event
  const { engagementTimelineEvents } = await import("../../drizzle/schema");
  await db.insert(engagementTimelineEvents).values({
    engagementId,
    eventType: 'note_added',
    phase: 'recon',
    title: 'Test Lab Auto-Registered as Target',
    description: [
      `Lab deployed at ${labUrl} — auto-added as in-scope target asset.`,
      removedOutOfScope.length > 0
        ? `Removed ${removedOutOfScope.length} out-of-scope domain(s): ${removedOutOfScope.join(', ')} (HackerOne program requires local testing only).`
        : '',
    ].filter(Boolean).join(' '),
    metadata: JSON.stringify({
      labUrl,
      scanServerHost,
      removedOutOfScope,
      action: 'auto_register_lab_asset',
    }),
    timestamp: Date.now(),
  });

  console.log(`[LabAssetRegister] Registered ${labUrl} for engagement #${engagementId}. Removed ${removedOutOfScope.length} out-of-scope domains.`);
  return { registered: true, removedOutOfScope };
}

/**
 * Remove out-of-scope *.nextcloud.com assets from an engagement's ops state.
 * Can be called independently (not just during deploy).
 */
async function removeOutOfScopeNextcloudAssets(
  engagementId: number
): Promise<{ removed: string[]; remainingCount: number }> {
  const db = await getDbSafe();
  const removed: string[] = [];

  const { engagementOpsSnapshots } = await import("../../drizzle/schema");
  const [snapshot] = await db.select()
    .from(engagementOpsSnapshots)
    .where(eq(engagementOpsSnapshots.engagementId, engagementId))
    .limit(1);

  if (!snapshot) return { removed: [], remainingCount: 0 };

  const state = snapshot.stateJson as any;
  const assets = Array.isArray(state.assets) ? state.assets : [];

  const filteredAssets = assets.filter((a: any) => {
    const hostname = (a.hostname || '').toLowerCase();
    if (
      hostname === 'nextcloud.com' ||
      hostname.endsWith('.nextcloud.com')
    ) {
      removed.push(hostname);
      return false;
    }
    return true;
  });

  if (removed.length > 0) {
    state.assets = filteredAssets;
    await db.update(engagementOpsSnapshots)
      .set({
        stateJson: state,
        assetCount: filteredAssets.length,
      })
      .where(eq(engagementOpsSnapshots.engagementId, engagementId));

    // Log timeline event
    const { engagementTimelineEvents } = await import("../../drizzle/schema");
    await db.insert(engagementTimelineEvents).values({
      engagementId,
      eventType: 'note_added',
      phase: 'recon',
      title: 'Out-of-Scope Assets Removed',
      description: `Removed ${removed.length} out-of-scope domain(s): ${removed.join(', ')}. HackerOne Nextcloud program requires all testing on self-hosted instances only — *.nextcloud.com domains are NOT bounty-eligible.`,
      metadata: JSON.stringify({ removed, action: 'remove_out_of_scope' }),
      timestamp: Date.now(),
    });
  }

  return { removed, remainingCount: filteredAssets.length };
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
        baseUrl: cred.baseUrl || `http://${process.env.SCAN_SERVER_HOST || '127.0.0.1'}:1337`,
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
        baseUrl: cred.baseUrl || `http://${process.env.SCAN_SERVER_HOST || '127.0.0.1'}:1337`,
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
          baseUrl: cred.baseUrl || `http://${process.env.SCAN_SERVER_HOST || '127.0.0.1'}:1337`,
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

  // Get Burp auto-scan progress for an engagement (in-memory active + DB history)
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

  // Get Burp scan history from DB (persisted records that survive restarts)
  getBurpScanHistory: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
    }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const { getEngagementBurpScanHistory } = await import("../lib/burp-auto-scan");
      return { history: await getEngagementBurpScanHistory(input.engagementId) };
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

  // Get Burp auto-scan stats (combined in-memory + DB)
  getBurpAutoScanStats: protectedProcedure
    .query(async () => {
      const { getBurpAutoScanStatsWithHistory } = await import("../lib/burp-auto-scan");
      return getBurpAutoScanStatsWithHistory();
    }),

  // ═══════════════════════════════════════════════════════════════════════
  // Nextcloud Test Lab Management
  // ═══════════════════════════════════════════════════════════════════════

  getTestLabConfig: protectedProcedure
    .input(z.object({
      nextcloudVersion: z.string().optional(),
      hostPort: z.number().optional(),
      enableCollabora: z.boolean().optional(),
      enableClamAV: z.boolean().optional(),
      enableLDAP: z.boolean().optional(),
      enableKeycloak: z.boolean().optional(),
      enableElasticsearch: z.boolean().optional(),
      enableMinIO: z.boolean().optional(),
      enableMailhog: z.boolean().optional(),
      enableCoturn: z.boolean().optional(),
      scanServerHost: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      const {
        generateDockerCompose,
        generateAppInstallScript,
        generateUserProvisioningScript,
        generateLdapSeedScript,
        generateConfigScript,
        generateFullDeployScript,
        generateStatusScript,
        generateTeardownScript,
        getTestLabInfo,
        DEFAULT_LAB_CONFIG,
        BOUNTY_ELIGIBLE_APPS,
        NEXTCLOUD_VERSIONS,
      } = await import("../lib/nextcloud-test-lab");

      const config = {
        ...DEFAULT_LAB_CONFIG,
        ...(input?.nextcloudVersion && { nextcloudVersion: input.nextcloudVersion }),
        ...(input?.hostPort && { hostPort: input.hostPort }),
        ...(input?.enableCollabora !== undefined && { enableCollabora: input.enableCollabora }),
        ...(input?.enableClamAV !== undefined && { enableClamAV: input.enableClamAV }),
        ...(input?.enableLDAP !== undefined && { enableLDAP: input.enableLDAP }),
        ...(input?.enableKeycloak !== undefined && { enableKeycloak: input.enableKeycloak }),
        ...(input?.enableElasticsearch !== undefined && { enableElasticsearch: input.enableElasticsearch }),
        ...(input?.enableMinIO !== undefined && { enableMinIO: input.enableMinIO }),
        ...(input?.enableMailhog !== undefined && { enableMailhog: input.enableMailhog }),
        ...(input?.enableCoturn !== undefined && { enableCoturn: input.enableCoturn }),
        // Use input scanServerHost, or fall back to SCAN_SERVER_HOST env var
        scanServerHost: input?.scanServerHost || process.env.SCAN_SERVER_HOST || DEFAULT_LAB_CONFIG.scanServerHost || '',
      };

      return {
        dockerCompose: generateDockerCompose(config),
        installAppsScript: generateAppInstallScript(config),
        provisionUsersScript: generateUserProvisioningScript(config),
        ldapSeedScript: generateLdapSeedScript(config),
        configureScript: generateConfigScript(config),
        fullDeployScript: generateFullDeployScript(config),
        statusScript: generateStatusScript(config),
        teardownScript: generateTeardownScript(config),
        labInfo: getTestLabInfo(config),
        config,
        supportedVersions: NEXTCLOUD_VERSIONS.supported,
        bountyEligibleApps: BOUNTY_ELIGIBLE_APPS.map(a => ({
          name: a.name,
          repo: a.repo,
          tier: a.tier,
          description: a.description,
        })),
        appCount: BOUNTY_ELIGIBLE_APPS.filter(a => !('builtIn' in a && a.builtIn)).length,
      };
    }),

  downloadTestLabFiles: protectedProcedure
    .input(z.object({
      scanServerHost: z.string().optional(),
      nextcloudVersion: z.string().optional(),
      hostPort: z.number().optional(),
    }).optional())
    .mutation(async ({ input }) => {
      const {
        generateDockerCompose,
        generateAppInstallScript,
        generateUserProvisioningScript,
        generateLdapSeedScript,
        generateConfigScript,
        generateFullDeployScript,
        generateStatusScript,
        generateTeardownScript,
        DEFAULT_LAB_CONFIG,
      } = await import("../lib/nextcloud-test-lab");

      const config = {
        ...DEFAULT_LAB_CONFIG,
        ...(input?.scanServerHost && { scanServerHost: input.scanServerHost }),
        ...(input?.nextcloudVersion && { nextcloudVersion: input.nextcloudVersion }),
        ...(input?.hostPort && { hostPort: input.hostPort }),
      };

      return {
        files: [
          { name: 'docker-compose.yml', content: generateDockerCompose(config) },
          { name: 'deploy.sh', content: generateFullDeployScript(config) },
          { name: 'install-apps.sh', content: generateAppInstallScript(config) },
          { name: 'provision-users.sh', content: generateUserProvisioningScript(config) },
          { name: 'seed-ldap-users.sh', content: generateLdapSeedScript(config) },
          { name: 'configure.sh', content: generateConfigScript(config) },
          { name: 'status.sh', content: generateStatusScript(config) },
          { name: 'teardown.sh', content: generateTeardownScript(config) },
        ],
      };
    }),

  updateEngagementTestTarget: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      testLabUrl: z.string(),
      scanServerHost: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();

      // Extract host from URL
      let host: string;
      try {
        const url = new URL(input.testLabUrl);
        host = url.hostname;
      } catch {
        host = input.testLabUrl.replace(/https?:\/\//, '').split(':')[0];
      }

      await db.update(engagements)
        .set({
          targetDomain: host,
          notes: `Test Lab URL: ${input.testLabUrl}\nScan Server: ${input.scanServerHost || host}\nUpdated: ${new Date().toISOString()}`,
        })
        .where(eq(engagements.id, input.engagementId));

      // Log timeline event
      const { engagementTimelineEvents } = await import("../../drizzle/schema");
      await db.insert(engagementTimelineEvents).values({
        engagementId: input.engagementId,
        eventType: 'note_added',
        phase: 'recon',
        title: 'Test Lab Target Updated',
        description: `Engagement target updated to local test lab: ${input.testLabUrl}`,
        metadata: JSON.stringify({
          testLabUrl: input.testLabUrl,
          scanServerHost: input.scanServerHost,
        }),
        timestamp: Date.now(),
      });

      return { success: true, targetDomain: host };
    }),

  // ─── Test Lab Deployer ───────────────────────────────────────────────────

  deployTestLab: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      remoteDir: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { deployTestLab } = await import("../lib/test-lab-deployer");
      const { DEFAULT_LAB_CONFIG } = await import("../lib/nextcloud-test-lab");
      const state = await deployTestLab(input.engagementId, DEFAULT_LAB_CONFIG, {
        remoteDir: input.remoteDir,
      });

      // ─── Auto-register lab as engagement asset on successful deploy ───
      if (state.status === "running" && state.labUrl) {
        try {
          await autoRegisterLabAsset(input.engagementId, state.labUrl, state.scanServerHost);
        } catch (err: any) {
          console.error(`[DeployTestLab] Auto-register failed:`, err.message);
        }
      }

      return {
        id: state.id,
        status: state.status,
        labUrl: state.labUrl,
        error: state.error,
        logs: state.logs.slice(-20),
      };
    }),

  getLabDeploymentStatus: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getLatestDeployment, getEngagementDeployments } = await import("../lib/test-lab-deployer");
      const latest = getLatestDeployment(input.engagementId);
      const all = getEngagementDeployments(input.engagementId);
      return {
        latest: latest ? {
          id: latest.id,
          status: latest.status,
          labUrl: latest.labUrl,
          scanServerHost: latest.scanServerHost,
          startedAt: latest.startedAt,
          completedAt: latest.completedAt,
          error: latest.error,
          logCount: latest.logs.length,
        } : null,
        totalDeployments: all.length,
      };
    }),

  getDeploymentLogs: protectedProcedure
    .input(z.object({
      deploymentId: z.string(),
      since: z.number().optional(),
    }))
    .query(async ({ input }) => {
      const { getDeploymentLogs } = await import("../lib/test-lab-deployer");
      return getDeploymentLogs(input.deploymentId, input.since);
    }),

  destroyTestLab: protectedProcedure
    .input(z.object({ deploymentId: z.string() }))
    .mutation(async ({ input }) => {
      const { destroyTestLab } = await import("../lib/test-lab-deployer");
      const result = await destroyTestLab(input.deploymentId);
      return result ? { success: true, status: result.status } : { success: false, status: "not_found" };
    }),

  // ─── Lab Asset Management ─────────────────────────────────────────────────

  removeOutOfScopeAssets: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .mutation(async ({ input }) => {
      return removeOutOfScopeNextcloudAssets(input.engagementId);
    }),

  registerLabAsset: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      labUrl: z.string(),
      scanServerHost: z.string(),
    }))
    .mutation(async ({ input }) => {
      return autoRegisterLabAsset(input.engagementId, input.labUrl, input.scanServerHost);
    }),

  // ─── Burp ↔ Test Lab Bridge ──────────────────────────────────────────────

  getLabScanProfiles: protectedProcedure
    .input(z.object({ engagementId: z.number().optional() }))
    .query(async () => {
      const { listScanProfiles, getPlaybookStats: getBridgeStats } = await import("../lib/burp-testlab-bridge");
      const profiles = listScanProfiles();
      return profiles.map(p => ({
        name: p.name,
        description: p.description,
        targetUrls: p.targetUrls,
        scanMode: p.scanMode,
        attackTechniques: p.attackTechniques,
        targetCwes: p.targetCwes,
        priority: p.priority,
      }));
    }),

  preflightLabScan: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { preflightCheck } = await import("../lib/burp-testlab-bridge");
      return preflightCheck(input.engagementId);
    }),

  launchLabProfileScan: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      engagementHandle: z.string(),
      credentialId: z.number(),
      profileName: z.string(),
      burpType: z.enum(["pro", "enterprise"]),
    }))
    .mutation(async ({ ctx, input }) => {
      const { launchProfileScan } = await import("../lib/burp-testlab-bridge");
      const db = await getDbSafe();
      const [cred] = await db.select().from(userPlatformCredentials)
        .where(eq(userPlatformCredentials.id, input.credentialId));
      if (!cred) throw new TRPCError({ code: "NOT_FOUND", message: "Burp credential not found" });
      const apiKey = decrypt(cred.apiKeyEncrypted);
      return launchProfileScan(
        input.engagementId,
        input.engagementHandle,
        ctx.user.id,
        input.credentialId,
        { baseUrl: cred.baseUrl || `http://${process.env.SCAN_SERVER_HOST || '127.0.0.1'}:1337`, apiKey, type: input.burpType },
        input.profileName,
      );
    }),

  launchFullLabScan: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      engagementHandle: z.string(),
      credentialId: z.number(),
      burpType: z.enum(["pro", "enterprise"]),
    }))
    .mutation(async ({ ctx, input }) => {
      const { launchFullLabScan } = await import("../lib/burp-testlab-bridge");
      const db = await getDbSafe();
      const [cred] = await db.select().from(userPlatformCredentials)
        .where(eq(userPlatformCredentials.id, input.credentialId));
      if (!cred) throw new TRPCError({ code: "NOT_FOUND", message: "Burp credential not found" });
      const apiKey = decrypt(cred.apiKeyEncrypted);
      return launchFullLabScan(
        input.engagementId,
        input.engagementHandle,
        ctx.user.id,
        input.credentialId,
        { baseUrl: cred.baseUrl || `http://${process.env.SCAN_SERVER_HOST || '127.0.0.1'}:1337`, apiKey, type: input.burpType },
      );
    }),

  // ─── Attack Playbook ─────────────────────────────────────────────────────

  getAttackPlaybook: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      targetHost: z.string().optional(),
    }))
    .query(async ({ input }) => {
      const { generateAttackPlaybook, generatePlaybookForEngagement } = await import("../lib/nextcloud-attack-playbook");
      if (input.engagementId) {
        const db = await getDbSafe();
        const [eng] = await db.select().from(engagements).where(eq(engagements.id, input.engagementId));
        if (eng) {
          return generatePlaybookForEngagement({
            targetDomain: eng.targetDomain || undefined,
            scope: eng.scope || undefined,
            notes: eng.notes || undefined,
          });
        }
      }
      return generateAttackPlaybook(input.targetHost || "localhost:8443");
    }),

  getPlaybookStats: protectedProcedure
    .query(async () => {
      const { getPlaybookStats } = await import("../lib/nextcloud-attack-playbook");
      return getPlaybookStats();
    }),

  getPlaybookPhase: protectedProcedure
    .input(z.object({ phaseId: z.string() }))
    .query(async ({ input }) => {
      const { getPhase } = await import("../lib/nextcloud-attack-playbook");
      const phase = getPhase(input.phaseId);
      if (!phase) throw new TRPCError({ code: "NOT_FOUND", message: "Phase not found" });
      return phase;
    }),

  getAutomatedTestCases: protectedProcedure
    .query(async () => {
      const { getAutomatedTestCases } = await import("../lib/nextcloud-attack-playbook");
      return getAutomatedTestCases();
    }),

  getAllAttackTechniques: protectedProcedure
    .query(async () => {
      const { getAllAttackTechniques } = await import("../lib/nextcloud-attack-playbook");
      return getAllAttackTechniques();
    }),

  // ─── ZAP → Burp Cross-Tool Pipeline ───

  runZapToBurpPipeline: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      engagementHandle: z.string(),
      zapScanId: z.number().optional(),
      burpCredentialId: z.number().optional(),
      targetUrls: z.array(z.string()).optional(),
    }))
    .mutation(async ({ ctx, input }) => {
      const { runZapToBurpPipeline } = await import("../lib/zap-burp-pipeline");
      return runZapToBurpPipeline({
        engagementId: input.engagementId,
        userId: String(ctx.user.id),
        engagementHandle: input.engagementHandle,
        zapScanId: input.zapScanId,
        burpCredentialId: input.burpCredentialId,
        targetUrls: input.targetUrls,
      });
    }),

  getZapBurpCoverage: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getCrossToolCoverage } = await import("../lib/zap-burp-pipeline");
      return getCrossToolCoverage(input.engagementId);
    }),

  getZapDiscoveredUrls: protectedProcedure
    .input(z.object({ zapScanId: z.number() }))
    .query(async ({ input }) => {
      const { extractZapDiscoveredUrls } = await import("../lib/zap-burp-pipeline");
      return extractZapDiscoveredUrls(input.zapScanId);
    }),

  correlateZapBurpFindings: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      zapScanId: z.number(),
    }))
    .query(async ({ input }) => {
      const { correlateFindings } = await import("../lib/zap-burp-pipeline");
      return correlateFindings(input.engagementId, input.zapScanId);
    }),

  // ─── Severity Escalation ───

  /** Run severity escalation on an engagement's cross-tool findings */
  runSeverityEscalation: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      zapScanId: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const { runSeverityEscalation } = await import("../lib/zap-burp-pipeline");
      return runSeverityEscalation(input.engagementId, input.zapScanId);
    }),

  /** Get the latest escalation status for an engagement (read-only, no re-run) */
  getEscalationStatus: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getEscalationStatus } = await import("../lib/zap-burp-pipeline");
      return getEscalationStatus(input.engagementId);
    }),

  /** Manual severity override for a specific finding */
  overrideFindingSeverity: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      findingId: z.string(),
      newSeverity: z.enum(["info", "low", "medium", "high", "critical"]),
      reason: z.string().min(1).max(500),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const { engagementTimelineEvents } = await import("../../drizzle/schema");

      // Record the manual override in the timeline
      await db.insert(engagementTimelineEvents).values({
        engagementId: input.engagementId,
        phase: "vulnerability_analysis",
        eventType: "severity_override",
        severity: input.newSeverity,
        title: `Manual severity override: ${input.findingId} → ${input.newSeverity}`,
        description: `User ${ctx.user.name || ctx.user.openId} overrode severity to ${input.newSeverity}. Reason: ${input.reason}`,
        metadata: JSON.stringify({
          findingId: input.findingId,
          newSeverity: input.newSeverity,
          reason: input.reason,
          overriddenBy: ctx.user.openId,
        }),
        sourceModule: "manual_override",
        timestamp: Date.now(),
      });

      // Update the ops state if possible
      try {
        const dbModule = await import("../db");
        const opsSnapshot = await dbModule.loadOpsSnapshot(input.engagementId);
        if (opsSnapshot?.stateJson) {
          let state: any;
          try { state = typeof opsSnapshot.stateJson === "string" ? JSON.parse(opsSnapshot.stateJson) : opsSnapshot.stateJson; } catch { state = null; }
          if (state?.assets) {
            let updated = false;
            for (const asset of state.assets) {
              if (!asset.vulns) continue;
              for (const vuln of asset.vulns) {
                if (vuln.title?.includes(input.findingId) || vuln.id === input.findingId) {
                  vuln.severity = input.newSeverity;
                  vuln.evidenceDetail = `${vuln.evidenceDetail || ""} [Manual override by ${ctx.user.name}: ${input.reason}]`.trim();
                  updated = true;
                }
              }
            }
            if (updated) {
              await dbModule.saveOpsSnapshot(input.engagementId, state);
            }
          }
        }
      } catch (e: any) {
        console.warn(`[SeverityOverride] Ops state update failed: ${e.message}`);
      }

      return { success: true, findingId: input.findingId, newSeverity: input.newSeverity };
    }),

  // ─── BB RoE Enforcement Procedures ───────────────────────────────────────

  /** Get the operator briefing for a BB engagement's program */
  getOperatorBriefing: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { generateOperatorBriefing, getProgramRoE } = await import('../lib/bb-roe-enforcement');
      const db = await getDbSafe();
      const [eng] = await db.select().from(engagements).where(eq(engagements.id, input.engagementId)).limit(1);
      if (!eng) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement not found' });
      if (eng.engagementType !== 'bug_bounty') return null;

      // Try to get program handle from roeScope JSON
      let programHandle: string | null = null;
      try {
        const roeData = JSON.parse(eng.roeScope || '{}');
        programHandle = roeData.bbRoeConfig?.programHandle || roeData.programHandle || null;
      } catch {}

      // Fallback: try to match from engagement name or target domain
      if (!programHandle) {
        const name = (eng.name || '').toLowerCase();
        if (name.includes('priceline')) programHandle = 'priceline';
        else if (name.includes('nextcloud')) programHandle = 'nextcloud';
        else if (name.includes('wordpress')) programHandle = 'wordpress';
        else if (name.includes('node')) programHandle = 'nodejs';
      }

      if (!programHandle) return null;

      const briefing = generateOperatorBriefing(programHandle);
      const fullRoe = getProgramRoE(programHandle);

      return {
        briefing,
        programHandle,
        subTargetRules: fullRoe?.acceptableFindings.subTargetRules || [],
        rateLimiting: fullRoe?.testingRestrictions.rateLimiting || null,
        automatedScannersAllowed: fullRoe?.testingRestrictions.automatedScannersAllowed ?? true,
        dataHandling: fullRoe?.testingRestrictions.dataHandling || [],
      };
    }),

  /** Import RoE from a program URL using LLM to parse the policy page */
  importRoeFromUrl: protectedProcedure
    .input(z.object({
      programUrl: z.string().url(),
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const { invokeLLM } = await import('../_core/llm');
      const { registerProgramRoE } = await import('../lib/bb-roe-enforcement');

      // Fetch the program policy page
      let policyHtml = '';
      try {
        const resp = await fetch(input.programUrl, {
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; AC3-RoE-Parser/1.0)' },
        });
        policyHtml = await resp.text();
      } catch (e: any) {
        throw new TRPCError({ code: 'BAD_REQUEST', message: `Failed to fetch program page: ${e.message}` });
      }

      // Strip HTML tags for cleaner LLM input (keep text content)
      const textContent = policyHtml
        .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
        .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
        .replace(/<[^>]+>/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 15000); // Limit to 15k chars for LLM context

      // Use LLM to parse the policy into structured RoE config
      const response = await invokeLLM({
        messages: [
          {
            role: 'system',
            content: `You are a bug bounty Rules of Engagement parser. Extract structured program rules from the policy text provided. Return a JSON object with the following structure:
{
  "programHandle": "lowercase-program-name",
  "platform": "hackerone|bugcrowd|other",
  "identification": {
    "customHeaders": { "header-name": "value-template" },
    "emailAlias": "@domain.com suffix or null",
    "includeIpInReport": boolean,
    "platformUsername": null
  },
  "testingRestrictions": {
    "prohibitedActions": [{ "action": "description", "category": "dos|availability_impact|inventory_manipulation|data_access|social_engineering|automated_scanning|fuzzing|account_manipulation|target_exclusion|data_exfiltration|ai_service_usage|noise|other", "enforcement": "hard|soft" }],
    "excludedTargets": ["domain-or-pattern"],
    "excludedEndpoints": [{ "pattern": "url-pattern", "reason": "why", "matchType": "contains|prefix|exact|regex" }],
    "rateLimiting": { "maxRequestsPerSecond": number|null, "maxConcurrentScans": number|null },
    "automatedScannersAllowed": boolean,
    "scannerRestrictions": "description or null",
    "dataHandling": [{ "dataType": "type", "rule": "rule", "enforcement": "hard|soft" }]
  },
  "acceptableFindings": {
    "eligibleCategories": [{ "category": "CWE or name", "description": "what's acceptable", "examples": ["example"] }],
    "subTargetRules": [{ "targetName": "name", "assets": ["asset"], "acceptableCategories": [...] }]
  },
  "ineligibleFindings": {
    "h1CoreIneligible": boolean,
    "programSpecificIneligible": [{ "pattern": "regex-pattern", "matchType": "regex|title_contains|category_equals", "reason": "why" }]
  },
  "submissionRequirements": {
    "acceptsAutomatedScannerOutput": boolean,
    "requiresDetailedPoC": boolean,
    "cleanupRequired": [{ "action": "what", "timing": "immediate|after_test|after_engagement" }],
    "reportFormat": "format description or null"
  }
}

Be thorough. Extract EVERY rule mentioned in the policy. For prohibited actions, use "hard" enforcement for absolute prohibitions and "soft" for recommendations. Include all scope exclusions, data handling rules, and submission requirements.`
          },
          {
            role: 'user',
            content: `Parse this bug bounty program policy into structured RoE config:\n\n${textContent}`
          }
        ],
        response_format: {
          type: 'json_schema',
          json_schema: {
            name: 'bb_roe_config',
            strict: false,
            schema: {
              type: 'object',
              properties: {
                programHandle: { type: 'string' },
                platform: { type: 'string' },
                identification: { type: 'object' },
                testingRestrictions: { type: 'object' },
                acceptableFindings: { type: 'object' },
                ineligibleFindings: { type: 'object' },
                submissionRequirements: { type: 'object' },
              },
              required: ['programHandle', 'platform', 'testingRestrictions'],
            },
          },
        },
      });

      let parsedConfig: any;
      try {
        parsedConfig = JSON.parse(response.choices[0].message.content || '{}');
      } catch {
        throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Failed to parse LLM response into structured RoE config' });
      }

      // Build the full BugBountyProgramRoE object
      const roeConfig = {
        programHandle: parsedConfig.programHandle || 'unknown',
        platform: parsedConfig.platform || 'hackerone',
        policyUrl: input.programUrl,
        lastParsedAt: Date.now(),
        identification: {
          customHeaders: parsedConfig.identification?.customHeaders || {},
          emailAlias: parsedConfig.identification?.emailAlias || undefined,
          includeIpInReport: parsedConfig.identification?.includeIpInReport ?? false,
          platformUsername: parsedConfig.identification?.platformUsername || undefined,
        },
        testingRestrictions: {
          prohibitedActions: (parsedConfig.testingRestrictions?.prohibitedActions || []).map((a: any) => ({
            action: a.action || '',
            category: a.category || 'other',
            targets: a.targets || [],
            enforcement: a.enforcement || 'hard',
          })),
          excludedTargets: parsedConfig.testingRestrictions?.excludedTargets || [],
          excludedEndpoints: (parsedConfig.testingRestrictions?.excludedEndpoints || []).map((e: any) => ({
            pattern: e.pattern || '',
            reason: e.reason || '',
            matchType: e.matchType || 'contains',
          })),
          rateLimiting: parsedConfig.testingRestrictions?.rateLimiting || undefined,
          automatedScannersAllowed: parsedConfig.testingRestrictions?.automatedScannersAllowed ?? true,
          scannerRestrictions: parsedConfig.testingRestrictions?.scannerRestrictions || undefined,
          dataHandling: (parsedConfig.testingRestrictions?.dataHandling || []).map((d: any) => ({
            dataType: d.dataType || '',
            rule: d.rule || '',
            enforcement: d.enforcement || 'soft',
          })),
        },
        acceptableFindings: {
          eligibleCategories: (parsedConfig.acceptableFindings?.eligibleCategories || []).map((c: any) => ({
            category: c.category || '',
            description: c.description || '',
            examples: c.examples || [],
          })),
          subTargetRules: (parsedConfig.acceptableFindings?.subTargetRules || []).map((s: any) => ({
            targetName: s.targetName || '',
            assets: s.assets || [],
            acceptableCategories: (s.acceptableCategories || []).map((c: any) => ({
              category: c.category || '',
              description: c.description || '',
              examples: c.examples || [],
            })),
          })),
        },
        ineligibleFindings: {
          h1CoreIneligible: parsedConfig.ineligibleFindings?.h1CoreIneligible ?? true,
          programSpecificIneligible: (parsedConfig.ineligibleFindings?.programSpecificIneligible || []).map((p: any) => ({
            pattern: p.pattern || '',
            matchType: p.matchType || 'regex',
            reason: p.reason || '',
          })),
        },
        submissionRequirements: {
          acceptsAutomatedScannerOutput: parsedConfig.submissionRequirements?.acceptsAutomatedScannerOutput ?? false,
          requiresDetailedPoC: parsedConfig.submissionRequirements?.requiresDetailedPoC ?? true,
          cleanupRequired: (parsedConfig.submissionRequirements?.cleanupRequired || []).map((c: any) => ({
            action: c.action || '',
            timing: c.timing || 'after_test',
          })),
          reportFormat: parsedConfig.submissionRequirements?.reportFormat || undefined,
        },
      };

      // Register in memory
      registerProgramRoE(roeConfig as any);

      // If engagementId provided, update the engagement's roeScope with the BB config
      if (input.engagementId) {
        const db = await getDbSafe();
        const [eng] = await db.select().from(engagements).where(eq(engagements.id, input.engagementId)).limit(1);
        if (eng) {
          let existingRoe: any = {};
          try { existingRoe = JSON.parse(eng.roeScope || '{}'); } catch {}
          existingRoe.bbRoeConfig = {
            programHandle: roeConfig.programHandle,
            importedAt: Date.now(),
            policyUrl: input.programUrl,
          };
          await db.update(engagements)
            .set({ roeScope: JSON.stringify(existingRoe) })
            .where(eq(engagements.id, input.engagementId));
        }
      }

      // Generate the operator briefing from the newly registered config
      const { generateOperatorBriefing } = await import('../lib/bb-roe-enforcement');
      const briefing = generateOperatorBriefing(roeConfig.programHandle);

      return {
        success: true,
        programHandle: roeConfig.programHandle,
        roeConfig,
        briefing,
        rulesCount: {
          prohibitedActions: roeConfig.testingRestrictions.prohibitedActions.length,
          excludedTargets: roeConfig.testingRestrictions.excludedTargets.length,
          eligibleCategories: roeConfig.acceptableFindings.eligibleCategories.length,
          ineligiblePatterns: roeConfig.ineligibleFindings.programSpecificIneligible.length,
          cleanupActions: roeConfig.submissionRequirements.cleanupRequired.length,
        },
      };
    }),

  /** Get all registered program RoE configs */
  listProgramRoEs: protectedProcedure
    .query(async () => {
      const { getAllProgramRoEs, generateOperatorBriefing } = await import('../lib/bb-roe-enforcement');
      const allRoes = getAllProgramRoEs();
      return allRoes.map(roe => ({
        programHandle: roe.programHandle,
        platform: roe.platform,
        policyUrl: roe.policyUrl,
        lastParsedAt: roe.lastParsedAt,
        briefing: generateOperatorBriefing(roe.programHandle),
        stats: {
          prohibitedActions: roe.testingRestrictions.prohibitedActions.length,
          excludedTargets: roe.testingRestrictions.excludedTargets.length,
          eligibleCategories: roe.acceptableFindings.eligibleCategories.length,
          subTargets: roe.acceptableFindings.subTargetRules.length,
        },
      }));
    }),
});
