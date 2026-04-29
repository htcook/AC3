import { TRPCError } from "@trpc/server";
import { protectedProcedure, router, adminProcedure} from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";
import { ENV } from "../_core/env";
import { and, eq, inArray, max, min, not, or } from "drizzle-orm";
import * as schema from "../../drizzle/schema";
import { assertEngagementAccess } from "../lib/engagement-access-guard";
import { validateEngagementTargets, getSafetyWarning } from "../../shared/domain-safety-whitelist";


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

        // ═══ DOMAIN SAFETY WHITELIST CHECK ═══
        // Validate targets against approved test lab whitelist.
        // Non-whitelisted domains get a warning stored in the engagement notes
        // and will be restricted to passive-only operations unless admin overrides.
        const domainValidation = validateEngagementTargets(input.targetDomain, input.targetIpRange);
        const safetyWarning = getSafetyWarning(domainValidation);
        let notes = input.notes || '';
        if (safetyWarning) {
          notes = `[SAFETY] ${safetyWarning}\n\n${notes}`.trim();
          console.warn(`[EngCreate] Non-whitelisted targets in new engagement: ${domainValidation.nonWhitelistedTargets.join(', ')}`);
        }

        const id = await db.createEngagement({
          ...input,
          notes,
          createdBy: ctx.user.id,
          // Store whitelist validation result for downstream guardrails
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
        activeScanOverride: z.number().min(0).max(1).optional(),
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

    /**
     * Toggle the active scan override for an engagement.
     * This allows non-whitelisted targets to be actively scanned.
     * Admin-only: requires signed RoE authorization.
     */
    toggleActiveScanOverride: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        enabled: z.boolean(),
        justification: z.string().min(1, 'Justification is required for active scan override'),
      }))
      .mutation(async ({ input, ctx }) => {
        const dbConn = await db.getDb();
        if (dbConn) await assertEngagementAccess(dbConn, input.engagementId, ctx.user);
        await db.updateEngagement(input.engagementId, {
          activeScanOverride: input.enabled ? 1 : 0,
        });
        await db.logActivity({
          userId: ctx.user.id,
          action: input.enabled ? 'active_scan_override_enabled' : 'active_scan_override_disabled',
          details: `${input.enabled ? 'Enabled' : 'Disabled'} active scan override on engagement #${input.engagementId}. Justification: ${input.justification}`,
        });
        // Log as engagement timeline event
        const dbInstance = await db.getDb();
        if (dbInstance) {
          await dbInstance.insert(schema.engagementTimelineEvents).values({
            engagementId: input.engagementId,
            eventType: 'safety_override',
            title: input.enabled
              ? '\u26a0\ufe0f Active Scan Override Enabled'
              : '\ud83d\udee1\ufe0f Active Scan Override Disabled',
            description: `${ctx.user.name || ctx.user.email} ${input.enabled ? 'enabled' : 'disabled'} active scan override. Justification: ${input.justification}`,
            phase: 'scoping',
            severity: input.enabled ? 'high' : 'info',
            metadata: JSON.stringify({
              userId: ctx.user.id,
              userName: ctx.user.name,
              enabled: input.enabled,
              justification: input.justification,
              timestamp: new Date().toISOString(),
            }),
            createdAt: new Date(),
          });
        }
        return {
          success: true,
          enabled: input.enabled,
          message: input.enabled
            ? 'Active scan override enabled. Full pipeline authorized for all targets.'
            : 'Active scan override disabled. Non-whitelisted targets restricted to passive only.',
        };
      }),

    /**
     * Get per-target approval statuses for an engagement.
     */
    getTargetApprovals: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input, ctx }) => {
        const dbConn = await db.getDb();
        if (!dbConn) return [];
        await assertEngagementAccess(dbConn, input.engagementId, ctx.user);
        const rows = await dbConn.select().from(schema.engagementApprovedTargets)
          .where(eq(schema.engagementApprovedTargets.engagementId, input.engagementId));
        return rows;
      }),

    /**
     * Set per-target approval status (approve/reject individual targets).
     * When all non-whitelisted targets are approved, automatically enables activeScanOverride.
     */
    setTargetApproval: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        targets: z.array(z.object({
          target: z.string(),
          hostname: z.string(),
          status: z.enum(['approved', 'rejected', 'pending']),
          justification: z.string().optional(),
        })),
        globalJustification: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const dbConn = await db.getDb();
        if (!dbConn) throw new Error('Database unavailable');
        await assertEngagementAccess(dbConn, input.engagementId, ctx.user);

        const results: Array<{ target: string; status: string }> = [];

        for (const t of input.targets) {
          // Upsert: check if target already exists
          const existing = await dbConn.select().from(schema.engagementApprovedTargets)
            .where(and(
              eq(schema.engagementApprovedTargets.engagementId, input.engagementId),
              eq(schema.engagementApprovedTargets.hostname, t.hostname),
            ));

          const justification = t.justification || input.globalJustification || '';

          if (existing.length > 0) {
            await dbConn.update(schema.engagementApprovedTargets)
              .set({
                status: t.status,
                approvedBy: ctx.user.id,
                approvedByName: ctx.user.name || ctx.user.email,
                justification,
              })
              .where(eq(schema.engagementApprovedTargets.id, existing[0].id));
          } else {
            await dbConn.insert(schema.engagementApprovedTargets).values({
              engagementId: input.engagementId,
              target: t.target,
              hostname: t.hostname,
              status: t.status,
              approvedBy: ctx.user.id,
              approvedByName: ctx.user.name || ctx.user.email,
              justification,
            });
          }
          results.push({ target: t.hostname, status: t.status });
        }

        // Check if all non-whitelisted targets are now approved
        const allApprovals = await dbConn.select().from(schema.engagementApprovedTargets)
          .where(eq(schema.engagementApprovedTargets.engagementId, input.engagementId));
        const allApproved = allApprovals.length > 0 && allApprovals.every(a => a.status === 'approved');

        // Auto-enable activeScanOverride if all targets approved
        if (allApproved) {
          await db.updateEngagement(input.engagementId, { activeScanOverride: 1 });
        }

        // Log timeline event
        const approvedCount = results.filter(r => r.status === 'approved').length;
        const rejectedCount = results.filter(r => r.status === 'rejected').length;
        await dbConn.insert(schema.engagementTimelineEvents).values({
          engagementId: input.engagementId,
          eventType: 'target_approval',
          title: `Target Approval: ${approvedCount} approved, ${rejectedCount} rejected`,
          description: `${ctx.user.name || ctx.user.email} reviewed ${results.length} target(s). ${allApproved ? 'All targets approved — active scan override auto-enabled.' : ''}`,
          phase: 'scoping',
          severity: 'info',
          metadata: JSON.stringify({
            userId: ctx.user.id,
            userName: ctx.user.name,
            results,
            allApproved,
            globalJustification: input.globalJustification,
            timestamp: new Date().toISOString(),
          }),
          createdAt: new Date(),
        });

        await db.logActivity({
          userId: ctx.user.id,
          action: 'target_approval_updated',
          details: `Reviewed ${results.length} targets on engagement #${input.engagementId}: ${approvedCount} approved, ${rejectedCount} rejected`,
        });

        return {
          success: true,
          results,
          allApproved,
          message: allApproved
            ? `All ${results.length} targets approved. Active scan override auto-enabled.`
            : `${approvedCount} target(s) approved, ${rejectedCount} rejected. ${allApprovals.filter(a => a.status === 'pending').length} still pending.`,
        };
      }),

    /**
     * Bulk approve all non-whitelisted targets for an engagement.
     */
    bulkApproveTargets: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        targets: z.array(z.object({
          target: z.string(),
          hostname: z.string(),
        })),
        justification: z.string().min(1, 'Justification is required'),
        roeReference: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const dbConn = await db.getDb();
        if (!dbConn) throw new Error('Database unavailable');
        await assertEngagementAccess(dbConn, input.engagementId, ctx.user);

        // Upsert all targets as approved
        for (const t of input.targets) {
          const existing = await dbConn.select().from(schema.engagementApprovedTargets)
            .where(and(
              eq(schema.engagementApprovedTargets.engagementId, input.engagementId),
              eq(schema.engagementApprovedTargets.hostname, t.hostname),
            ));

          if (existing.length > 0) {
            await dbConn.update(schema.engagementApprovedTargets)
              .set({
                status: 'approved',
                approvedBy: ctx.user.id,
                approvedByName: ctx.user.name || ctx.user.email,
                justification: input.justification,
                roeReference: input.roeReference || null,
              })
              .where(eq(schema.engagementApprovedTargets.id, existing[0].id));
          } else {
            await dbConn.insert(schema.engagementApprovedTargets).values({
              engagementId: input.engagementId,
              target: t.target,
              hostname: t.hostname,
              status: 'approved',
              approvedBy: ctx.user.id,
              approvedByName: ctx.user.name || ctx.user.email,
              justification: input.justification,
              roeReference: input.roeReference || null,
            });
          }
        }

        // Enable activeScanOverride
        await db.updateEngagement(input.engagementId, { activeScanOverride: 1 });

        // Log timeline event
        await dbConn.insert(schema.engagementTimelineEvents).values({
          engagementId: input.engagementId,
          eventType: 'target_approval',
          title: `Bulk Approved: ${input.targets.length} targets`,
          description: `${ctx.user.name || ctx.user.email} bulk-approved all ${input.targets.length} non-whitelisted targets. Active scan override enabled. Justification: ${input.justification}`,
          phase: 'scoping',
          severity: 'high',
          metadata: JSON.stringify({
            userId: ctx.user.id,
            userName: ctx.user.name,
            targets: input.targets.map(t => t.hostname),
            justification: input.justification,
            roeReference: input.roeReference,
            timestamp: new Date().toISOString(),
          }),
          createdAt: new Date(),
        });

        await db.logActivity({
          userId: ctx.user.id,
          action: 'targets_bulk_approved',
          details: `Bulk approved ${input.targets.length} targets on engagement #${input.engagementId}`,
        });

        return {
          success: true,
          approvedCount: input.targets.length,
          message: `All ${input.targets.length} targets approved. Active scan override enabled.`,
        };
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
