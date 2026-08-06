/**
 * Evidence Export router — AC3 side of the AC3 ⇄ SSP Generator contract.
 *
 * Emits an engagement's control-tagged findings (Payload A) and hash-chained
 * evidence (Payload B) in the shape the compliance service's POST /findings/import
 * consumes. See COMBINED_PLATFORM_DESIGN §5 and evidence-integration.openapi.yaml.
 *
 * Idempotent: source_finding_id / source_evidence_id are stable, so repeated
 * exports of the same engagement yield identical id sets.
 *
 * NOTE: this is the tRPC form. A thin REST adapter (GET /api/v1/evidence-export)
 * that calls this same builder is a small wrapper to add when wiring the
 * external compliance service (Phase 2).
 */
import { z } from "zod";
import { eq } from "drizzle-orm";
import { router, protectedProcedure } from "../_core/trpc";
import { getEngagementFindings, getDbRequired } from "../db";
import { ksiEvidence } from "../../drizzle/schema";
import { assertEngagementAccess } from "../lib/engagement-access-guard";
import { buildFindingPayload, buildEvidencePayload } from "../lib/finding-control-tagger";

export const evidenceExportRouter = router({
  /** Export findings + evidence for one engagement, optionally since a timestamp. */
  forEngagement: protectedProcedure
    .input(
      z.object({
        engagementId: z.number().int().positive(),
        since: z.string().datetime().optional(),
      })
    )
    .query(async ({ input, ctx }) => {
      const db = await getDbRequired();
      // Tenant / authorization guard — never export another owner's engagement.
      await assertEngagementAccess(db, input.engagementId, ctx.user);

      const findingRows = await getEngagementFindings(input.engagementId);
      const evidenceRows = await db
        .select()
        .from(ksiEvidence)
        .where(eq(ksiEvidence.engagementId, String(input.engagementId)));

      let findings = findingRows.map((f) => buildFindingPayload(f, input.engagementId));
      let evidence = evidenceRows.map((e) => buildEvidencePayload(e));

      if (input.since) {
        const cutoff = Date.parse(input.since);
        if (Number.isFinite(cutoff)) {
          const after = (iso: string | null) => (iso ? Date.parse(iso) >= cutoff : true);
          findings = findings.filter((f) => after(f.detected_at));
          evidence = evidence.filter((e) => after(e.provenance.timestamp));
        }
      }

      return {
        engagementId: input.engagementId,
        generatedAt: new Date().toISOString(),
        findings,
        evidence,
      };
    }),
});
