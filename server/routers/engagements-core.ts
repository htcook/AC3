import { TRPCError } from "@trpc/server";
import { protectedProcedure, router, adminProcedure} from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";
import { ENV } from "../_core/env";
import { and, eq, inArray, max, min, not, or } from "drizzle-orm";
import * as schema from "../../drizzle/schema";
import { assertEngagementAccess } from "../lib/engagement-access-guard";


export const engagementsRouter = router({
    list: protectedProcedure.query(async ({ ctx }) => {
      return db.getEngagements(ctx.user);
    }),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input, ctx }) => {
        return db.getEngagementById(input.id, ctx.user);
      }),

    create: protectedProcedure
      .input(z.object({
        name: z.string().min(1),
        customerName: z.string().min(1),
        description: z.string().optional(),
        engagementType: z.enum(['red_team', 'phishing', 'pentest', 'purple_team', 'tabletop']).default('red_team'),
        status: z.enum(['planning', 'active', 'paused', 'completed', 'archived']).default('planning'),
        startDate: z.date().optional(),
        endDate: z.date().optional(),
        targetDomain: z.string().optional(),
        targetIpRange: z.string().optional(),
        phishingDomain: z.string().optional(),
        calderaOperationId: z.string().optional(),
        calderaAdversaryId: z.string().optional(),
        gophishCampaignId: z.number().optional(),
        notes: z.string().optional(),
        roeDocumentId: z.number().optional(),
        fedrampImpactLevel: z.enum(['none', 'low', 'moderate', 'high']).default('none'),
      }))
      .mutation(async ({ input, ctx }) => {
        // Validate: at least one target domain or IP range is required
        if (!input.targetDomain && !input.targetIpRange) {
          throw new TRPCError({
            code: 'BAD_REQUEST',
            message: 'At least one target domain or IP range is required to create an engagement.',
          });
        }

        const id = await db.createEngagement({
          ...input,
          createdBy: ctx.user.id,
        });

        // Auto-create RoE document if none linked
        let roeDocId = input.roeDocumentId ?? null;
        if (!roeDocId) {
          const { roeDocuments } = await import('../../drizzle/schema');
          const { getDb } = await import('../db');
          const dbConn = await getDb();
          if (dbConn) {
            // Build initial scope from engagement targets
            const inScopeDomains: Array<{ domain: string; includeSubdomains: boolean; description: string }> = [];
            const inScopeIpRanges: Array<{ cidr: string; description: string }> = [];

            if (input.targetDomain) {
              // Support comma-separated domains
              const domains = input.targetDomain.split(/[,;\s]+/).map(d => d.trim()).filter(Boolean);
              for (const domain of domains) {
                inScopeDomains.push({
                  domain,
                  includeSubdomains: true,
                  description: `Primary target domain from engagement builder`,
                });
              }
            }
            if (input.targetIpRange) {
              // Support comma-separated IP ranges
              const ranges = input.targetIpRange.split(/[,;\s]+/).map(r => r.trim()).filter(Boolean);
              for (const range of ranges) {
                inScopeIpRanges.push({
                  cidr: range.includes('/') ? range : `${range}/32`,
                  description: `Target IP range from engagement builder`,
                });
              }
            }

            const [roeResult] = await dbConn.insert(roeDocuments).values({
              title: `RoE — ${input.name}`,
              engagementId: id,
              organizationName: input.customerName,
              testingFirmName: 'AC3 — AceofCloud',
              status: 'draft',
              inScopeDomains: inScopeDomains.length > 0 ? inScopeDomains : undefined,
              inScopeIpRanges: inScopeIpRanges.length > 0 ? inScopeIpRanges : undefined,
              testingDays: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'],
              testTimezone: 'America/New_York',
              createdBy: ctx.user.id,
              lastModifiedBy: ctx.user.id,
              purpose: `Rules of Engagement for ${input.name} — ${input.customerName}. Auto-generated during engagement creation. Please review and complete all sections before activating the engagement.`,
            } as any);
            roeDocId = roeResult.insertId;

            // Link the RoE document back to the engagement
            const { engagements } = await import('../../drizzle/schema');
            const { eq } = await import('drizzle-orm');
            await dbConn.update(engagements)
              .set({ roeDocumentId: roeDocId, roeStatus: 'pending' })
              .where(eq(engagements.id, id));
          }
        }

        // Also seed the engagement's roeScope JSON from targetDomain/targetIpRange
        // so the scope guard can enforce even before the RoE document is fully completed
        if (input.targetDomain || input.targetIpRange) {
          const roeScope: any = {};
          if (input.targetDomain) {
            const domains = input.targetDomain.split(/[,;\s]+/).map(d => d.trim()).filter(Boolean);
            roeScope.inScopeDomains = domains.map(d => ({
              domain: d,
              includeSubdomains: true,
              description: 'From engagement builder',
            }));
          }
          if (input.targetIpRange) {
            const ranges = input.targetIpRange.split(/[,;\s]+/).map(r => r.trim()).filter(Boolean);
            roeScope.inScopeIpRanges = ranges.map(r => ({
              cidr: r.includes('/') ? r : `${r}/32`,
              description: 'From engagement builder',
            }));
          }
          const { engagements } = await import('../../drizzle/schema');
          const { eq } = await import('drizzle-orm');
          const { getDb } = await import('../db');
          const dbConn = await getDb();
          if (dbConn) {
            await dbConn.update(engagements)
              .set({ roeScope })
              .where(eq(engagements.id, id));
          }
        }

        // ── Auto-Create Cyber C2 Operation/Campaign ──────────────────────────
        // Every engagement gets a Cyber C2 operation by default.
        // Preflight check ensures the server is reachable before attempting.
        let calderaOpId: string | null = input.calderaOperationId || null;
        let calderaError: string | null = null;

        if (!calderaOpId) {
          try {
            const { validateCalderaConnection } = await import('../lib/caldera-preflight');
            const preflight = await validateCalderaConnection({ timeout: 8000 });
            console.log(`[EngagementCreate] Caldera preflight OK: ${preflight.ip}:${preflight.port} (${preflight.latencyMs}ms)`);

            // Create a new Cyber C2 operation for this engagement
            const opName = `${input.name} — ${input.customerName} [#${id}]`;
            const calderaBaseUrl = preflight.baseUrl;
            const calderaApiKey = (await import('../_core/env')).ENV.calderaApiKey;

            // First, get or create a default adversary profile
            let adversaryId = input.calderaAdversaryId || null;
            if (!adversaryId) {
              // Use the default "red" adversary or create one
              try {
                const advResponse = await fetch(`${calderaBaseUrl}/api/v2/adversaries`, {
                  headers: { KEY: calderaApiKey },
                  signal: AbortSignal.timeout(5000),
                });
                if (advResponse.ok) {
                  const adversaries = await advResponse.json();
                  // Prefer an adversary named after the engagement type, or fall back to first available
                  const typeMatch = adversaries.find((a: any) =>
                    a.name?.toLowerCase().includes(input.engagementType.replace('_', ' '))
                  );
                  adversaryId = typeMatch?.adversary_id || adversaries[0]?.adversary_id || null;
                }
              } catch {
                // Non-fatal — create operation without specific adversary
              }
            }

            // Create the operation
            const opPayload: Record<string, any> = {
              name: opName,
              group: 'red',
              state: 'paused', // Start paused — operator activates when ready
              auto_close: false,
              jitter: '2/8',
              visibility: 51,
            };
            if (adversaryId) {
              opPayload.adversary = { adversary_id: adversaryId };
            }

            const opResponse = await fetch(`${calderaBaseUrl}/api/v2/operations`, {
              method: 'POST',
              headers: {
                KEY: calderaApiKey,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify(opPayload),
              signal: AbortSignal.timeout(10000),
            });

            if (opResponse.ok) {
              const opData = await opResponse.json();
              calderaOpId = opData.id || opData.operation_id || null;
              console.log(`[EngagementCreate] Cyber C2 operation created: ${calderaOpId} for engagement #${id}`);

              // Link the operation back to the engagement
              if (calderaOpId) {
                const { engagements: engTable } = await import('../../drizzle/schema');
                const { eq: eqOp } = await import('drizzle-orm');
                const { getDb: getDbOp } = await import('../db');
                const dbOp = await getDbOp();
                if (dbOp) {
                  await dbOp.update(engTable)
                    .set({
                      calderaOperationId: calderaOpId,
                      ...(adversaryId ? { calderaAdversaryId: adversaryId } : {}),
                    })
                    .where(eqOp(engTable.id, id));
                }
              }
            } else {
              calderaError = `Cyber C2 operation creation failed: HTTP ${opResponse.status}`;
              console.warn(`[EngagementCreate] ${calderaError}`);
            }
          } catch (calErr: any) {
            calderaError = calErr.message || 'Caldera campaign auto-creation failed';
            console.warn(`[EngagementCreate] Caldera auto-campaign failed (non-fatal): ${calderaError}`);
          }
        }

        await db.logActivity({
          userId: ctx.user.id,
          action: 'engagement_created',
          details: `Created engagement: ${input.name} for ${input.customerName}${roeDocId ? ` (RoE #${roeDocId} auto-created)` : ''}${calderaOpId ? ` (Caldera op: ${calderaOpId})` : ''}`,
        });
        return {
          id,
          roeDocumentId: roeDocId,
          calderaOperationId: calderaOpId,
          calderaError,
        };
      }),

    update: protectedProcedure
      .input(z.object({
        id: z.number(),
        name: z.string().min(1).optional(),
        customerName: z.string().min(1).optional(),
        description: z.string().optional(),
        engagementType: z.enum(['red_team', 'phishing', 'pentest', 'purple_team', 'tabletop']).optional(),
        status: z.enum(['planning', 'active', 'paused', 'completed', 'archived']).optional(),
        startDate: z.date().optional(),
        endDate: z.date().optional(),
        targetDomain: z.string().optional(),
        targetIpRange: z.string().optional(),
        phishingDomain: z.string().optional(),
        calderaOperationId: z.string().optional(),
        calderaAdversaryId: z.string().optional(),
        gophishCampaignId: z.number().optional(),
        notes: z.string().optional(),
        roeDocumentId: z.number().nullable().optional(),
        fedrampImpactLevel: z.enum(['none', 'low', 'moderate', 'high']).optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { id, ...updates } = input;
        // Verify the user has access to this engagement before updating
        const dbConn = await db.getDb();
        if (dbConn) await assertEngagementAccess(dbConn, id, ctx.user);
        await db.updateEngagement(id, updates);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'engagement_updated',
          details: `Updated engagement ID: ${id}`,
        });
        return { success: true };
      }),

    delete: adminProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input, ctx }) => {
        await db.deleteEngagement(input.id);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'engagement_deleted',
          details: `Deleted engagement ID: ${input.id}`,
        });
        return { success: true };
      }),

    bulkDelete: adminProcedure
      .input(z.object({ ids: z.array(z.number()).min(1).max(500) }))
      .mutation(async ({ input, ctx }) => {
        const result = await db.bulkDeleteEngagements(input.ids);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'engagements_bulk_deleted',
          details: `Bulk deleted ${input.ids.length} engagements`,
        });
        return { success: true, deleted: result?.deleted ?? 0 };
      }),

    // ── Engagement Templates ──────────────────────────────────────────────
    listTemplates: protectedProcedure.query(async () => {
      const { ENGAGEMENT_TEMPLATES } = await import('../lib/engagement-templates');
      return ENGAGEMENT_TEMPLATES.map(t => ({
        id: t.id,
        name: t.name,
        shortName: t.shortName,
        description: t.description,
        icon: t.icon,
        category: t.category,
        engagementType: t.engagementType,
        estimatedDuration: t.estimatedDuration,
        teamSize: t.teamSize,
        difficulty: t.difficulty,
        tags: t.tags,
      }));
    }),

    getTemplate: protectedProcedure
      .input(z.object({ id: z.string() }))
      .query(async ({ input }) => {
        const { getTemplateById } = await import('../lib/engagement-templates');
        const template = getTemplateById(input.id);
        if (!template) throw new TRPCError({ code: 'NOT_FOUND', message: 'Template not found' });
        return template;
      }),

    createFromTemplate: protectedProcedure
      .input(z.object({
        templateId: z.string(),
        name: z.string().min(1),
        customerName: z.string().min(1),
        targetDomain: z.string().optional(),
        targetIpRange: z.string().optional(),
        phishingDomain: z.string().optional(),
        notes: z.string().optional(),
        fedrampImpactLevel: z.enum(['none', 'low', 'moderate', 'high']).default('none'),
      }))
      .mutation(async ({ input, ctx }) => {
        const { getTemplateById } = await import('../lib/engagement-templates');
        const template = getTemplateById(input.templateId);
        if (!template) throw new TRPCError({ code: 'NOT_FOUND', message: 'Template not found' });

        // Validate: at least one target domain or IP range (unless tabletop)
        if (template.engagementType !== 'tabletop' && !input.targetDomain && !input.targetIpRange) {
          throw new TRPCError({
            code: 'BAD_REQUEST',
            message: 'At least one target domain or IP range is required.',
          });
        }

        // Create engagement with template defaults
        const id = await db.createEngagement({
          name: input.name,
          customerName: input.customerName,
          description: template.defaultDescription,
          engagementType: template.engagementType,
          status: 'planning',
          targetDomain: input.targetDomain || '',
          targetIpRange: input.targetIpRange || '',
          phishingDomain: input.phishingDomain || '',
          notes: `${template.defaultNotes}${input.notes ? `\n\n--- Operator Notes ---\n${input.notes}` : ''}`,
          createdBy: ctx.user.id,
        });

        // Auto-create RoE with template defaults
        let roeDocId: number | null = null;
        try {
          const { roeDocuments } = await import('../../drizzle/schema');
          const { getDb } = await import('../db');
          const dbConn = await getDb();
          if (dbConn) {
            const inScopeDomains: Array<{ domain: string; includeSubdomains: boolean; description: string }> = [];
            const inScopeIpRanges: Array<{ cidr: string; description: string }> = [];

            if (input.targetDomain) {
              const domains = input.targetDomain.split(/[,;\s]+/).map(d => d.trim()).filter(Boolean);
              for (const domain of domains) {
                inScopeDomains.push({ domain, includeSubdomains: true, description: 'From engagement template' });
              }
            }
            if (input.targetIpRange) {
              const ranges = input.targetIpRange.split(/[,;\s]+/).map(r => r.trim()).filter(Boolean);
              for (const range of ranges) {
                inScopeIpRanges.push({ cidr: range.includes('/') ? range : `${range}/32`, description: 'From engagement template' });
              }
            }

            const [roeResult] = await dbConn.insert(roeDocuments).values({
              title: `RoE — ${input.name}`,
              engagementId: id,
              organizationName: input.customerName,
              testingFirmName: 'AC3 — AceofCloud',
              status: 'draft',
              purpose: template.roeDefaults.purpose,
              inScopeDomains: inScopeDomains.length > 0 ? inScopeDomains : undefined,
              inScopeIpRanges: inScopeIpRanges.length > 0 ? inScopeIpRanges : undefined,
              testingDays: template.roeDefaults.testingDays,
              testTimezone: template.roeDefaults.testTimezone,
              createdBy: ctx.user.id,
              lastModifiedBy: ctx.user.id,
            } as any);
            roeDocId = roeResult.insertId;

            // Link RoE to engagement
            const { engagements } = await import('../../drizzle/schema');
            const { eq } = await import('drizzle-orm');
            await dbConn.update(engagements)
              .set({ roeDocumentId: roeDocId, roeStatus: 'pending' })
              .where(eq(engagements.id, id));
          }
        } catch (e) {
          console.warn('[createFromTemplate] RoE auto-creation failed:', e);
        }

        // Seed roeScope JSON
        if (input.targetDomain || input.targetIpRange) {
          try {
            const roeScope: any = {};
            if (input.targetDomain) {
              const domains = input.targetDomain.split(/[,;\s]+/).map(d => d.trim()).filter(Boolean);
              roeScope.inScopeDomains = domains.map(d => ({ domain: d, includeSubdomains: true, description: 'From template' }));
            }
            if (input.targetIpRange) {
              const ranges = input.targetIpRange.split(/[,;\s]+/).map(r => r.trim()).filter(Boolean);
              roeScope.inScopeIpRanges = ranges.map(r => ({ cidr: r.includes('/') ? r : `${r}/32`, description: 'From template' }));
            }
            const { engagements } = await import('../../drizzle/schema');
            const { eq } = await import('drizzle-orm');
            const { getDb } = await import('../db');
            const dbConn = await getDb();
            if (dbConn) {
              await dbConn.update(engagements).set({ roeScope }).where(eq(engagements.id, id));
            }
          } catch (e) {
            console.warn('[createFromTemplate] roeScope seed failed:', e);
          }
        }

        // Auto-create Cyber C2 operation (same as regular create)
        let calderaOpId: string | null = null;
        try {
          const { validateCalderaConnection } = await import('../lib/caldera-preflight');
          const preflight = await validateCalderaConnection({ timeout: 8000 });
          const opName = `${input.name} — ${input.customerName} [#${id}]`;
          const calderaApiKey = (await import('../_core/env')).ENV.calderaApiKey;
          const opPayload: Record<string, any> = {
            name: opName, group: 'red', state: 'paused', auto_close: false, jitter: '2/8', visibility: 51,
          };
          const opResponse = await fetch(`${preflight.baseUrl}/api/v2/operations`, {
            method: 'POST',
            headers: { KEY: calderaApiKey, 'Content-Type': 'application/json' },
            body: JSON.stringify(opPayload),
            signal: AbortSignal.timeout(10000),
          });
          if (opResponse.ok) {
            const opData = await opResponse.json();
            calderaOpId = opData.id || opData.operation_id || null;
            if (calderaOpId) {
              const { engagements: engTable } = await import('../../drizzle/schema');
              const { eq: eqOp } = await import('drizzle-orm');
              const { getDb: getDbOp } = await import('../db');
              const dbOp = await getDbOp();
              if (dbOp) {
                await dbOp.update(engTable).set({ calderaOperationId: calderaOpId }).where(eqOp(engTable.id, id));
              }
            }
          }
        } catch (e) {
          console.warn('[createFromTemplate] Caldera auto-creation failed (non-fatal):', e);
        }

        await db.logActivity({
          userId: ctx.user.id,
          action: 'engagement_created_from_template',
          details: `Created engagement from template "${template.name}": ${input.name} for ${input.customerName}`,
        });

        return {
          id,
          templateId: template.id,
          roeDocumentId: roeDocId,
          calderaOperationId: calderaOpId,
          scanConfig: template.scanConfig,
          phaseConfig: template.phaseConfig,
        };
      }),

    /**
     * Reset an engagement for a fresh rerun.
     * Clears ops snapshots, scan results, timeline events, and test plans.
     * Resets status to 'planning'.
     */
    resetEngagement: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const engagement = await db.getEngagementById(input.id, ctx.user);
        if (!engagement) {
          throw new TRPCError({ code: 'NOT_FOUND', message: `Engagement #${input.id} not found or access denied` });
        }

        const dbConn = await db.getDb();
        if (!dbConn) {
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Database unavailable' });
        }

        const cleared: Record<string, number> = {};

        // 1. Delete ops snapshot
        try {
          const r = await dbConn.delete(schema.engagementOpsSnapshots)
            .where(eq(schema.engagementOpsSnapshots.engagementId, input.id));
          cleared.opsSnapshots = r[0]?.affectedRows ?? 0;
        } catch { cleared.opsSnapshots = 0; }

        // 2. Delete scan results
        try {
          const r = await dbConn.delete(schema.scanResults)
            .where(eq(schema.scanResults.engagementId, input.id));
          cleared.scanResults = r[0]?.affectedRows ?? 0;
        } catch { cleared.scanResults = 0; }

        // 3. Delete timeline events
        try {
          const r = await dbConn.delete(schema.engagementTimelineEvents)
            .where(eq(schema.engagementTimelineEvents.engagementId, input.id));
          cleared.timelineEvents = r[0]?.affectedRows ?? 0;
        } catch { cleared.timelineEvents = 0; }

        // 4. Delete test plans
        try {
          const r = await dbConn.delete(schema.testPlans)
            .where(eq(schema.testPlans.engagementId, input.id));
          cleared.testPlans = r[0]?.affectedRows ?? 0;
        } catch { cleared.testPlans = 0; }

        // 5. Reset engagement status to planning
        await dbConn.update(schema.engagements)
          .set({ status: 'planning' })
          .where(eq(schema.engagements.id, input.id));

        // 6. Stop any in-memory orchestrator state
        try {
          const { stopEngagement } = await import('../lib/engagement-orchestrator');
          stopEngagement(input.id);
        } catch { /* not running */ }

        await db.logActivity({
          userId: ctx.user.id,
          action: 'engagement_reset',
          details: `Reset engagement #${input.id} (${engagement.name}) for fresh rerun. Cleared: ${JSON.stringify(cleared)}`,
        });

        return { success: true, engagementId: input.id, cleared };
      }),

    /**
     * Bulk reset multiple engagements at once.
     */
    bulkResetEngagements: protectedProcedure
      .input(z.object({ ids: z.array(z.number()).min(1) }))
      .mutation(async ({ input, ctx }) => {
        const results: Array<{ id: number; cleared: Record<string, number> }> = [];

        const dbConn = await db.getDb();
        if (!dbConn) {
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Database unavailable' });
        }

        for (const id of input.ids) {
          const cleared: Record<string, number> = {};

          try {
            const r1 = await dbConn.delete(schema.engagementOpsSnapshots)
              .where(eq(schema.engagementOpsSnapshots.engagementId, id));
            cleared.opsSnapshots = r1[0]?.affectedRows ?? 0;
          } catch { cleared.opsSnapshots = 0; }

          try {
            const r2 = await dbConn.delete(schema.scanResults)
              .where(eq(schema.scanResults.engagementId, id));
            cleared.scanResults = r2[0]?.affectedRows ?? 0;
          } catch { cleared.scanResults = 0; }

          try {
            const r3 = await dbConn.delete(schema.engagementTimelineEvents)
              .where(eq(schema.engagementTimelineEvents.engagementId, id));
            cleared.timelineEvents = r3[0]?.affectedRows ?? 0;
          } catch { cleared.timelineEvents = 0; }

          try {
            const r4 = await dbConn.delete(schema.testPlans)
              .where(eq(schema.testPlans.engagementId, id));
            cleared.testPlans = r4[0]?.affectedRows ?? 0;
          } catch { cleared.testPlans = 0; }

          await dbConn.update(schema.engagements)
            .set({ status: 'planning' })
            .where(eq(schema.engagements.id, id));

          try {
            const { stopEngagement } = await import('../lib/engagement-orchestrator');
            stopEngagement(id);
          } catch { /* not running */ }

          results.push({ id, cleared });
        }

        await db.logActivity({
          userId: ctx.user.id,
          action: 'engagement_bulk_reset',
          details: `Bulk reset ${input.ids.length} engagement(s): ${input.ids.join(', ')}`,
        });

        return { success: true, results };
      }),
  });
