/**
 * Evidence Integrity Router
 *
 * tRPC procedures for chain-of-custody controls, hallucination guardrails,
 * and evidence integrity verification.
 *
 * Endpoints:
 *   - validateEvidence: Run full guardrail check on evidence content
 *   - verifyChain: Validate the integrity chain for an engagement
 *   - createAnchor: Create a Merkle root anchor for an engagement's evidence chain
 *   - verifyAnchor: Verify an existing anchor against current chain state
 *   - getChainStatus: Get chain statistics for an engagement
 *   - getGuardrailAudit: Query the guardrail audit log
 *   - getIntegrityAnchors: List integrity anchors for an engagement
 *   - bulkValidate: Validate multiple evidence items in batch
 */

import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb as _getDb } from "../db";
import {
  evidenceGuardrailAudit,
  evidenceIntegrityAnchors,
  evidenceItems,
  evidenceChainOfCustody,
} from "../../drizzle/schema";
import { eq, desc, and, sql } from "drizzle-orm";
import {
  sha256,
  validateProvenance,
  checkHallucination,
  validateChain,
  createAnchor,
  verifyAnchor,
  getChain,
  getChainStats,
  createIntegrityEnvelope,
  buildProvenance,
  evidenceGate,
  type EvidenceSourceTool,
} from "../lib/evidence-integrity-guardrails";
import {
  validateLLMEvidence,
  validateReportFinding,
  validateVulnVerification,
  validateAttackPlan,
  type GuardrailContext,
} from "../lib/llm-evidence-guardrail";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
  return db;
}

export const evidenceIntegrityRouter = router({
  // ─── Validate evidence content against ground truth ───
  validateEvidence: protectedProcedure
    .input(z.object({
      engagementId: z.string(),
      content: z.string(),
      specialist: z.string().default("generic"),
      sourceTool: z.string().default("llm_analysis"),
      groundTruth: z.record(z.string()).optional(),
      knownAssets: z.array(z.object({
        hostname: z.string(),
        ip: z.string(),
        ports: z.array(z.number()).optional(),
      })).optional(),
      knownCves: z.array(z.string()).optional(),
      strictness: z.enum(["strict", "moderate", "lenient"]).default("moderate"),
    }))
    .mutation(async ({ input }) => {
      const context: GuardrailContext = {
        specialist: input.specialist,
        engagementId: input.engagementId,
        toolOutputs: input.groundTruth || {},
        knownAssets: input.knownAssets,
        knownCves: input.knownCves,
        strictness: input.strictness,
      };

      const result = validateLLMEvidence(input.content, context);

      // Log to audit table
      const db = await getDbSafe();
      await db.insert(evidenceGuardrailAudit).values({
        engagementId: input.engagementId,
        evidenceId: result.envelopeId,
        specialist: input.specialist,
        checkType: "hallucination",
        passed: result.passed ? 1 : 0,
        score: Math.round(result.hallucinationCheck.score * 100),
        recommendation: result.recommendation,
        groundedClaimsCount: result.hallucinationCheck.groundedClaims.length,
        ungroundedClaimsCount: result.hallucinationCheck.ungroundedClaims.length,
        criticalIssues: result.hallucinationCheck.ungroundedClaims.filter(c => c.severity === "critical").length,
        wasSanitized: result.wasSanitized ? 1 : 0,
        details: JSON.stringify({
          groundedClaims: result.hallucinationCheck.groundedClaims,
          ungroundedClaims: result.hallucinationCheck.ungroundedClaims,
          warnings: result.warnings,
          errors: result.errors,
        }),
        contentHash: result.contentHash,
      });

      return {
        passed: result.passed,
        score: result.hallucinationCheck.score,
        recommendation: result.recommendation,
        wasSanitized: result.wasSanitized,
        sanitizedContent: result.wasSanitized ? result.content : null,
        groundedClaims: result.hallucinationCheck.groundedClaims.length,
        ungroundedClaims: result.hallucinationCheck.ungroundedClaims.length,
        criticalIssues: result.hallucinationCheck.ungroundedClaims.filter(c => c.severity === "critical").length,
        details: {
          grounded: result.hallucinationCheck.groundedClaims,
          ungrounded: result.hallucinationCheck.ungroundedClaims,
          warnings: result.warnings,
          errors: result.errors,
        },
        contentHash: result.contentHash,
        envelopeId: result.envelopeId,
      };
    }),

  // ─── Verify the integrity chain for an engagement ───
  verifyChain: protectedProcedure
    .input(z.object({
      engagementId: z.string(),
    }))
    .query(async ({ input }) => {
      const chainResult = validateChain(input.engagementId);

      // Also check DB-stored chain of custody records
      const db = await getDbSafe();
      const dbRecords = await db.select({
        count: sql<number>`count(*)`,
        distinctEvidence: sql<number>`count(distinct ${evidenceChainOfCustody.evidenceId})`,
      }).from(evidenceChainOfCustody);

      return {
        ...chainResult,
        dbCustodyRecords: Number(dbRecords[0]?.count ?? 0),
        dbDistinctEvidence: Number(dbRecords[0]?.distinctEvidence ?? 0),
      };
    }),

  // ─── Create a Merkle root anchor ───
  createAnchor: protectedProcedure
    .input(z.object({
      engagementId: z.string(),
      notes: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const anchor = createAnchor(input.engagementId);
      if (!anchor) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "Cannot create anchor: chain is empty or invalid",
        });
      }

      // Persist to database
      const db = await getDbSafe();

      // Supersede any existing active anchors
      await db.update(evidenceIntegrityAnchors)
        .set({ status: "superseded" })
        .where(and(
          eq(evidenceIntegrityAnchors.engagementId, input.engagementId),
          eq(evidenceIntegrityAnchors.status, "active"),
        ));

      await db.insert(evidenceIntegrityAnchors).values({
        engagementId: input.engagementId,
        merkleRoot: anchor.merkleRoot,
        hmacSignature: anchor.hmacSignature,
        chainLength: anchor.chainLength,
        anchoredBy: ctx.user?.name || "system",
        notes: input.notes,
      });

      return {
        merkleRoot: anchor.merkleRoot,
        chainLength: anchor.chainLength,
        anchoredAt: anchor.anchoredAt,
        status: "active",
      };
    }),

  // ─── Verify an existing anchor ───
  verifyAnchor: protectedProcedure
    .input(z.object({
      engagementId: z.string(),
    }))
    .query(async ({ input }) => {
      const db = await getDbSafe();

      // Get the latest active anchor
      const [anchor] = await db.select()
        .from(evidenceIntegrityAnchors)
        .where(and(
          eq(evidenceIntegrityAnchors.engagementId, input.engagementId),
          eq(evidenceIntegrityAnchors.status, "active"),
        ))
        .orderBy(desc(evidenceIntegrityAnchors.anchoredAt))
        .limit(1);

      if (!anchor) {
        return {
          hasAnchor: false,
          valid: null,
          error: "No active anchor found for this engagement",
        };
      }

      const result = verifyAnchor(input.engagementId, {
        merkleRoot: anchor.merkleRoot,
        hmacSignature: anchor.hmacSignature,
      });

      return {
        hasAnchor: true,
        valid: result.valid,
        error: result.error,
        anchor: {
          merkleRoot: anchor.merkleRoot,
          chainLength: anchor.chainLength,
          anchoredAt: anchor.anchoredAt,
          anchoredBy: anchor.anchoredBy,
        },
      };
    }),

  // ─── Get chain statistics ───
  chainStats: protectedProcedure.query(async () => {
    const stats = getChainStats();

    // Also get DB stats
    const db = await getDbSafe();
    const [dbStats] = await db.select({
      totalItems: sql<number>`count(*)`,
      withHash: sql<number>`sum(case when ${evidenceItems.sha256Hash} is not null then 1 else 0 end)`,
      withoutHash: sql<number>`sum(case when ${evidenceItems.sha256Hash} is null then 1 else 0 end)`,
    }).from(evidenceItems);

    const [auditStats] = await db.select({
      totalChecks: sql<number>`count(*)`,
      passed: sql<number>`sum(case when ${evidenceGuardrailAudit.passed} = 1 then 1 else 0 end)`,
      failed: sql<number>`sum(case when ${evidenceGuardrailAudit.passed} = 0 then 1 else 0 end)`,
      quarantined: sql<number>`sum(case when ${evidenceGuardrailAudit.recommendation} = 'quarantine' then 1 else 0 end)`,
    }).from(evidenceGuardrailAudit);

    return {
      inMemory: stats,
      database: {
        totalEvidenceItems: Number(dbStats?.totalItems ?? 0),
        withIntegrityHash: Number(dbStats?.withHash ?? 0),
        withoutIntegrityHash: Number(dbStats?.withoutHash ?? 0),
      },
      guardrailAudit: {
        totalChecks: Number(auditStats?.totalChecks ?? 0),
        passed: Number(auditStats?.passed ?? 0),
        failed: Number(auditStats?.failed ?? 0),
        quarantined: Number(auditStats?.quarantined ?? 0),
      },
    };
  }),

  // ─── Get guardrail audit log ───
  auditLog: protectedProcedure
    .input(z.object({
      engagementId: z.string().optional(),
      specialist: z.string().optional(),
      recommendation: z.enum(["accept", "review", "reject", "quarantine"]).optional(),
      limit: z.number().min(1).max(200).default(50),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const filters: any[] = [];

      if (input?.engagementId) {
        filters.push(eq(evidenceGuardrailAudit.engagementId, input.engagementId));
      }
      if (input?.specialist) {
        filters.push(eq(evidenceGuardrailAudit.specialist, input.specialist));
      }
      if (input?.recommendation) {
        filters.push(eq(evidenceGuardrailAudit.recommendation, input.recommendation));
      }

      const where = filters.length > 0 ? and(...filters) : undefined;

      const [items, countResult] = await Promise.all([
        db.select().from(evidenceGuardrailAudit)
          .where(where)
          .orderBy(desc(evidenceGuardrailAudit.createdAt))
          .limit(input?.limit ?? 50)
          .offset(input?.offset ?? 0),
        db.select({ count: sql<number>`count(*)` }).from(evidenceGuardrailAudit).where(where),
      ]);

      return {
        items: items.map(item => ({
          ...item,
          details: typeof item.details === "string" ? JSON.parse(item.details) : item.details,
        })),
        total: Number(countResult[0]?.count ?? 0),
      };
    }),

  // ─── List integrity anchors for an engagement ───
  anchors: protectedProcedure
    .input(z.object({
      engagementId: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const filters: any[] = [];
      if (input?.engagementId) {
        filters.push(eq(evidenceIntegrityAnchors.engagementId, input.engagementId));
      }
      const where = filters.length > 0 ? and(...filters) : undefined;

      const items = await db.select().from(evidenceIntegrityAnchors)
        .where(where)
        .orderBy(desc(evidenceIntegrityAnchors.anchoredAt))
        .limit(50);

      return items;
    }),

  // ─── Compute hash for evidence content (utility) ───
  computeHash: protectedProcedure
    .input(z.object({
      content: z.string(),
    }))
    .mutation(async ({ input }) => {
      return {
        sha256: sha256(input.content),
        size: Buffer.byteLength(input.content, "utf-8"),
      };
    }),

  // ─── Validate provenance of evidence ───
  validateProvenance: protectedProcedure
    .input(z.object({
      content: z.string(),
      sourceTool: z.string(),
      collectorHost: z.string().default("ac3-platform"),
      toolOutputTimestamp: z.string(),
      targetHost: z.string(),
      sourceIp: z.string().default("unknown"),
      destinationIp: z.string().default("unknown"),
    }))
    .mutation(async ({ input }) => {
      const provenance = buildProvenance({
        tool: input.sourceTool as EvidenceSourceTool,
        collectorHost: input.collectorHost,
        rawOutput: input.content,
        targetHost: input.targetHost,
        sourceIp: input.sourceIp,
        destinationIp: input.destinationIp,
      });
      provenance.toolOutputTimestamp = input.toolOutputTimestamp;

      const result = validateProvenance(input.content, provenance);

      return {
        valid: result.valid,
        toolSignatureMatch: result.toolSignatureMatch,
        timestampConsistent: result.timestampConsistent,
        networkContextValid: result.networkContextValid,
        contentFormatValid: result.contentFormatValid,
        errors: result.errors,
        warnings: result.warnings,
      };
    }),

  // ─── Bulk validate evidence items from DB ───
  bulkValidate: protectedProcedure
    .input(z.object({
      engagementId: z.string(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();

      // Get all evidence items for this engagement
      const items = await db.select().from(evidenceItems)
        .where(eq(evidenceItems.engagementId, input.engagementId));

      const results = {
        total: items.length,
        withHash: 0,
        withoutHash: 0,
        verified: 0,
        tampered: 0,
        errors: [] as string[],
      };

      for (const item of items) {
        if (item.sha256Hash) {
          results.withHash++;
          // We can't re-verify content hash without the original content
          // but we can verify the hash exists and is well-formed
          if (/^[a-f0-9]{64}$/.test(item.sha256Hash)) {
            results.verified++;
          } else {
            results.tampered++;
            results.errors.push(`${item.evidenceId}: Invalid hash format`);
          }
        } else {
          results.withoutHash++;
        }
      }

      return results;
    }),
});
