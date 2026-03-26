import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";
import { invokeLLM } from "../_core/llm";
import { and, desc, eq, like, not, or, sql } from "drizzle-orm";
import * as schema from "../../drizzle/schema";

export const engagementPipelineRouter = router({
    // Create a new automated pipeline
    create: protectedProcedure
      .input(z.object({
        name: z.string(),
        targetDomains: z.array(z.string()),
        clientType: z.string(),
        orgProfile: z.any().optional(),
        autoCreateCaldera: z.boolean().optional(),
        autoCreateGophish: z.boolean().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const id = await db.createEngagementPipeline({
          userId: ctx.user?.id || 0,
          name: input.name,
          status: 'pending',
          targetDomains: input.targetDomains,
          clientType: input.clientType,
          orgProfile: input.orgProfile,
          totalSteps: 6,
          currentStep: 0,
          stepLog: [
            { step: 1, name: 'Domain Intel Scan', status: 'pending', timestamp: Date.now() },
            { step: 2, name: 'Risk Assessment', status: 'pending', timestamp: Date.now() },
            { step: 3, name: 'Campaign Recommendations', status: 'pending', timestamp: Date.now() },
            { step: 4, name: 'Create Cyber C2 Operation', status: 'pending', timestamp: Date.now() },
            { step: 5, name: 'Create GoPhish Campaign', status: 'pending', timestamp: Date.now() },
            { step: 6, name: 'Create Engagement', status: 'pending', timestamp: Date.now() },
          ],
        });
        return { id };
      }),

    // Execute the pipeline (runs all steps)
    execute: protectedProcedure
      .input(z.object({ pipelineId: z.number() }))
      .mutation(async ({ input }) => {
        const pipeline = await db.getEngagementPipeline(input.pipelineId);
        if (!pipeline) throw new TRPCError({ code: 'NOT_FOUND' });

        await db.updateEngagementPipeline(input.pipelineId, { status: 'running' });

        const stepLog = (pipeline.stepLog as any[]) || [];
        const riskSummary: Record<string, any> = {};

        // Import WebSocket event emitters for real-time updates
        const { emitPipelineStep, emitReconComplete, emitSystemNotification } = await import('../lib/ws-event-hub');

        try {
          // Step 1: Domain Intel Scan
          stepLog[0] = { ...stepLog[0], status: 'running', timestamp: Date.now() };
          await db.updateEngagementPipeline(input.pipelineId, { currentStep: 1, stepLog });
          emitPipelineStep({ pipelineId: input.pipelineId, step: 1, stepName: 'Domain Intel Scan', status: 'running' });

          const { runDomainIntelPipeline } = await import('../domainIntel');
          const domains = pipeline.targetDomains as string[];
          const orgProfile = (pipeline.orgProfile as any) || {};
          const scanResult = await runDomainIntelPipeline({
            customerName: pipeline.name || 'Auto',
            primaryDomain: domains[0] || '',
            additionalDomains: domains.slice(1),
            sector: orgProfile.sector || 'technology',
            clientType: pipeline.clientType || 'enterprise',
            criticalFunctions: orgProfile.criticalFunctions || [],
            complianceFlags: orgProfile.complianceFlags || [],
          });
          riskSummary.domainIntel = { totalAssets: scanResult.totalAssets, totalFindings: scanResult.totalFindings };
          stepLog[0] = { ...stepLog[0], status: 'complete', timestamp: Date.now() };
          emitPipelineStep({ pipelineId: input.pipelineId, step: 1, stepName: 'Domain Intel Scan', status: 'complete' });
          emitReconComplete({ scanId: 0, domain: domains[0] || '', findings: scanResult.totalFindings || 0 });

          // Step 2: Risk Assessment
          stepLog[1] = { ...stepLog[1], status: 'running', timestamp: Date.now() };
          await db.updateEngagementPipeline(input.pipelineId, { currentStep: 2, stepLog });
          emitPipelineStep({ pipelineId: input.pipelineId, step: 2, stepName: 'Risk Assessment', status: 'running' });
          riskSummary.riskAssessment = {
            overallRisk: scanResult.overallRiskBand || 'medium',
            overallScore: scanResult.overallRiskScore,
            topAssets: (scanResult.assets || []).slice(0, 10).map((a: any) => ({ name: a.hostname, risk: a.hybridRiskScore })),
          };
          stepLog[1] = { ...stepLog[1], status: 'complete', timestamp: Date.now() };
          emitPipelineStep({ pipelineId: input.pipelineId, step: 2, stepName: 'Risk Assessment', status: 'complete' });

          // Step 3: Campaign Recommendations
          stepLog[2] = { ...stepLog[2], status: 'running', timestamp: Date.now() };
          await db.updateEngagementPipeline(input.pipelineId, { currentStep: 3, stepLog, riskSummary });
          emitPipelineStep({ pipelineId: input.pipelineId, step: 3, stepName: 'Campaign Recommendations', status: 'running' });
          riskSummary.campaignRecommendations = scanResult.campaignRecommendations || [];
          stepLog[2] = { ...stepLog[2], status: 'complete', timestamp: Date.now() };
          emitPipelineStep({ pipelineId: input.pipelineId, step: 3, stepName: 'Campaign Recommendations', status: 'complete' });

          // Step 4: Create Cyber C2 Operation (ready state)
          stepLog[3] = { ...stepLog[3], status: 'running', timestamp: Date.now() };
          await db.updateEngagementPipeline(input.pipelineId, { currentStep: 4, stepLog });
          emitPipelineStep({ pipelineId: input.pipelineId, step: 4, stepName: 'Create Cyber C2 Operation', status: 'running' });
          riskSummary.calderaOperation = {
            status: 'ready',
            recommendedAbilities: (scanResult.campaignRecommendations || []).flatMap((c: any) => c.calderaAbilities || []),
          };
          stepLog[3] = { ...stepLog[3], status: 'complete', timestamp: Date.now() };
          emitPipelineStep({ pipelineId: input.pipelineId, step: 4, stepName: 'Create Cyber C2 Operation', status: 'complete' });

          // Step 5: Auto-Materialize Phishing Drafts from scan recommendations
          stepLog[4] = { ...stepLog[4], status: 'running', timestamp: Date.now() };
          await db.updateEngagementPipeline(input.pipelineId, { currentStep: 5, stepLog });
          emitPipelineStep({ pipelineId: input.pipelineId, step: 5, stepName: 'Create GoPhish Campaign', status: 'running' });

          // First, we need a domain intel scan record. The pipeline ran runDomainIntelPipeline
          // directly, so we need to find or create the scan record.
          const { domainIntelScans, phishingDrafts } = await import('../../drizzle/schema');
          const { eq: eqOp, desc: descOp, and: andOp, sql: sqlOp } = await import('drizzle-orm');
          const drizzleDb = await (await import('../db')).getDb();
          if (!drizzleDb) throw new Error('Database not available');

          // Find the most recent completed scan for this domain
          const [latestScan] = await drizzleDb.select().from(domainIntelScans)
            .where(andOp(
              eqOp(domainIntelScans.primaryDomain, domains[0] || ''),
              eqOp(domainIntelScans.status, 'completed')
            ))
            .orderBy(descOp(domainIntelScans.createdAt))
            .limit(1);

          const materializedDraftIds: number[] = [];
          const campaignRecs = scanResult.campaignRecommendations || [];

          if (latestScan && campaignRecs.length > 0) {
            const { invokeLLM } = await import('../_core/llm');
            const { matchPhishingExploits, enhanceLandingPage, PHISHING_EXPLOITS } = await import('../lib/phishing-exploits');
            const pipelineOut = latestScan.pipelineOutput as any;
            const actorMatches = pipelineOut?.threatActorMatches;
            const topActor = actorMatches?.topMatches?.[0];

            // Match phishing exploits based on scan intelligence
            const technologies = (pipelineOut?.discoveredAssets || []).flatMap((a: any) => Object.keys(a.technologyVersions || {}));
            const hasWebmail = technologies.some((t: string) => /exchange|owa|outlook|webmail|zimbra/i.test(t));
            const usesMfa = true; // Assume MFA for modern orgs
            const usesSSO = technologies.some((t: string) => /azure|okta|saml|oauth|adfs/i.test(t));
            const idpProvider = technologies.some((t: string) => /azure|microsoft|office365/i.test(t)) ? 'microsoft' :
              technologies.some((t: string) => /google|gsuite|workspace/i.test(t)) ? 'google' :
              technologies.some((t: string) => /okta/i.test(t)) ? 'okta' : undefined;
            const confirmedCves = (pipelineOut?.postureFindings || []).filter((f: any) => f.corroborationTier === 'confirmed').map((f: any) => f.cveId).filter(Boolean);

            const matchedExploits = matchPhishingExploits({
              sector: latestScan.sector || 'technology',
              technologies,
              hasWebmail,
              usesMfa,
              usesSSO,
              idpProvider,
              confirmedCves,
            });
            console.log(`[Pipeline] Matched ${matchedExploits.length} phishing exploits for campaign enhancement`);

            // Auto-materialize up to 3 top-priority recommendations using LLM
            const topRecs = campaignRecs.slice(0, 3);
            for (let i = 0; i < topRecs.length; i++) {
              try {
                // Check if already materialized
                const existing = await drizzleDb.select().from(phishingDrafts)
                  .where(andOp(
                    eqOp(phishingDrafts.scanId, latestScan.id),
                    sqlOp`${phishingDrafts.campaignRecommendationIndex} = ${i}`
                  ));
                if (existing.length > 0) {
                  materializedDraftIds.push(existing[0].id);
                  continue;
                }

                const rec = topRecs[i];
                const campaignName = rec.name || `${domains[0]} - ${rec.type || 'phishing'} Campaign`;
                const templateName = `[AC3] ${campaignName} - Template`;
                const landingPageName = `[AC3] ${campaignName} - Landing Page`;
                const targetGroupName = `[AC3] ${campaignName} - Targets`;

                // LLM-powered materialization
                let generatedContent: any = {};
                try {
                  const materializePrompt = `You are a red team phishing campaign designer for AceofCloud (AC3 platform).
Given the following domain intelligence and campaign recommendation, generate a complete phishing campaign package.

TARGET DOMAIN: ${domains[0]}
SECTOR: ${latestScan.sector || 'unknown'}
CAMPAIGN NAME: ${campaignName}
CAMPAIGN TYPE: ${rec.type}
PRIORITY: ${rec.priority}
DESCRIPTION: ${rec.description}
TARGET ASSETS: ${JSON.stringify(rec.targetAssets || [])}
ATTACK CHAIN: ${JSON.stringify(rec.attackChain || [])}
MITRE TACTICS: ${JSON.stringify(rec.mitreTactics || [])}
MATCHED THREAT ACTOR: ${topActor ? `${topActor.actorName} (confidence: ${topActor.confidence}%)` : 'None'}
GOPHISH TEMPLATE SUGGESTIONS: ${JSON.stringify(rec.gophishTemplates || [])}

MATCHED PHISHING EXPLOITS (use these techniques to enhance the campaign):
${matchedExploits.slice(0, 5).map((m: any) => `- ${m.exploit.name} (${m.exploit.category}, ${m.exploit.mitreId}): ${m.exploit.description.slice(0, 150)}... [Relevance: ${m.relevanceScore}%]`).join('\n')}

Generate a JSON object with these fields:
{
  "templateSubject": "Realistic email subject line",
  "templateHtml": "Full HTML email body with GoPhish variables: {{.FirstName}}, {{.LastName}}, {{.Email}}, {{.TrackingURL}}, {{.URL}}, {{.From}}. Must look like a legitimate business email. Include proper HTML structure with inline CSS. Incorporate evasion techniques from matched exploits where applicable (e.g., QR codes, zero-width chars, redirect chain URL patterns).",
  "templateText": "Plain text version of the email",
  "landingPageHtml": "HTML for a credential capture landing page. Use the most relevant matched exploit technique (e.g., BITB SSO popup for SSO targets, progressive MFA capture for MFA targets, ClickFix for payload delivery). Include form fields that POST credentials. Make it look like the target's real login page.",
  "landingPageRedirectUrl": "https://${domains[0]}",
  "smtpProfileName": "AC3 - ${domains[0]} Profile"
}

Make the phishing content highly realistic and tailored to the target domain and sector. Use professional language and branding cues from the target organization. Leverage the matched phishing exploit techniques to maximize effectiveness.`;

                  const llmResponse = await invokeLLM({ 
                    _caller: "engagement-pipeline",
                    messages: [
                      { role: 'system', content: 'You are a red team phishing content generator. Output only valid JSON.' },
                      { role: 'user', content: materializePrompt },
                    ],
                    response_format: {
                      type: 'json_schema',
                      json_schema: {
                        name: 'phishing_draft',
                        strict: true,
                        schema: {
                          type: 'object',
                          properties: {
                            templateSubject: { type: 'string', description: 'Email subject line' },
                            templateHtml: { type: 'string', description: 'Full HTML email body' },
                            templateText: { type: 'string', description: 'Plain text email' },
                            landingPageHtml: { type: 'string', description: 'Landing page HTML' },
                            landingPageRedirectUrl: { type: 'string', description: 'Redirect URL after capture' },
                            smtpProfileName: { type: 'string', description: 'SMTP profile name' },
                          },
                          required: ['templateSubject', 'templateHtml', 'templateText', 'landingPageHtml', 'landingPageRedirectUrl', 'smtpProfileName'],
                          additionalProperties: false,
                        },
                      },
                    },
                  });
                  const rawContent = llmResponse?.choices?.[0]?.message?.content;
                  if (rawContent && typeof rawContent === 'string') {
                    generatedContent = JSON.parse(rawContent);
                  }
                  console.log(`[Pipeline] LLM materialized recommendation ${i}: ${campaignName}`);

                  // Enhance landing page with injectable exploit code
                  if (generatedContent.landingPageHtml && matchedExploits.length > 0) {
                    const topExploitIds = matchedExploits
                      .filter((m: any) => m.exploit.target === 'landing_page' || m.exploit.target === 'both')
                      .slice(0, 3)
                      .map((m: any) => m.exploit.id);
                    if (topExploitIds.length > 0) {
                      generatedContent.exploitEnhancedLandingPage = enhanceLandingPage(generatedContent.landingPageHtml, topExploitIds);
                      generatedContent.phishingExploits = matchedExploits.slice(0, 8).map((m: any) => ({
                        id: m.exploit.id,
                        name: m.exploit.name,
                        category: m.exploit.category,
                        mitreId: m.exploit.mitreId,
                        relevanceScore: m.relevanceScore,
                        matchReason: m.matchReason,
                        enablesRemoteAccess: m.exploit.enablesRemoteAccess,
                      }));
                      console.log(`[Pipeline] Enhanced landing page with ${topExploitIds.length} exploit injections`);
                    }
                  }
                } catch (llmErr: any) {
                  console.warn(`[Pipeline] LLM materialization failed for rec ${i}, using fallback:`, llmErr.message);
                  // Fallback to basic template
                  generatedContent = {
                    templateSubject: rec.gophishTemplates?.[0]?.subject || `Important: Action Required - ${domains[0]}`,
                    templateHtml: `<html><body><p>Dear {{.FirstName}},</p><p>Please review the attached document regarding your ${domains[0]} account.</p><p><a href="{{.URL}}">Click here to review</a></p><p>Best regards,<br>IT Security Team</p></body></html>`,
                    templateText: `Dear {{.FirstName}},\n\nPlease review the document regarding your ${domains[0]} account.\n\n{{.URL}}\n\nBest regards,\nIT Security Team`,
                    landingPageHtml: `<html><body><h2>${domains[0]} - Login</h2><form method="POST"><input name="email" placeholder="Email" /><input name="password" type="password" placeholder="Password" /><button type="submit">Sign In</button></form></body></html>`,
                    landingPageRedirectUrl: `https://${domains[0]}`,
                    smtpProfileName: `AC3 - ${domains[0]} Profile`,
                  };
                }

                // Dedup guard: skip if a draft already exists for this scan + recommendation index
                const [existingDraft] = await drizzleDb.select({ id: phishingDrafts.id })
                  .from(phishingDrafts)
                  .where(and(
                    eq(phishingDrafts.scanId, latestScan.id),
                    eq(phishingDrafts.campaignRecommendationIndex, i)
                  ))
                  .limit(1);
                if (existingDraft) {
                  console.log(`[Pipeline Dedup] Draft already exists for scan ${latestScan.id} rec ${i}: id=${existingDraft.id}`);
                  materializedDraftIds.push(existingDraft.id);
                  continue;
                }

                const [draftResult] = await drizzleDb.insert(phishingDrafts).values({
                  scanId: latestScan.id,
                  campaignRecommendationIndex: i,
                  status: 'draft',
                  campaignName,
                  campaignType: rec.type || 'phishing',
                  priority: rec.priority || 'medium',
                  targetDomain: domains[0],
                  targetSector: latestScan.sector || null,
                  templateName,
                  templateSubject: generatedContent.templateSubject,
                  templateHtml: generatedContent.templateHtml,
                  templateText: generatedContent.templateText,
                  landingPageName,
                  landingPageHtml: generatedContent.landingPageHtml,
                  landingPageRedirectUrl: generatedContent.landingPageRedirectUrl,
                  captureCredentials: true,
                  capturePasswords: false,
                  targetGroupName,
                  targetEmails: null,
                  smtpProfileName: generatedContent.smtpProfileName,
                  attackChain: rec.attackChain || null,
                  calderaAbilities: rec.calderaAbilities || null,
                  threatActorId: topActor?.actorId || null,
                  threatActorName: topActor?.actorName || null,
                  matchRationale: topActor
                    ? `Matched with ${topActor.confidence}% confidence. LLM-materialized by engagement pipeline.`
                    : 'LLM-materialized by engagement pipeline',
                  phishingExploits: generatedContent.phishingExploits || null,
                  exploitEnhancedLandingPage: generatedContent.exploitEnhancedLandingPage || null,
                  createdBy: null,
                }).$returningId();
                materializedDraftIds.push(draftResult.id);
                console.log(`[Pipeline] Auto-materialized draft ${draftResult.id} for recommendation ${i}: ${campaignName}`);
              } catch (matErr: any) {
                console.error(`[Pipeline] Failed to materialize recommendation ${i}:`, matErr.message);
              }
            }
          }

          riskSummary.gophishCampaign = {
            status: materializedDraftIds.length > 0 ? 'materialized' : 'ready',
            materializedDraftIds,
            totalRecommendations: campaignRecs.length,
            materializedCount: materializedDraftIds.length,
            recommendedTemplates: campaignRecs.flatMap((c: any) => c.gophishTemplates || []),
          };
          stepLog[4] = { ...stepLog[4], status: 'complete', timestamp: Date.now() };
          emitPipelineStep({ pipelineId: input.pipelineId, step: 5, stepName: 'Create GoPhish Campaign', status: 'complete' });

          // Step 5b: Auto-identify typosquat domains when phishing is in-scope
          try {
            const { domainRecon, roeDocuments: roeTable, engagements: engTable } = await import('../../drizzle/schema');

            // Check if phishing is an in-scope item:
            // 1. Engagement type is 'phishing'
            // 2. RoE testingTypes/attackVectors include phishing or social_engineering
            // 3. socialEngineeringAllowed is set
            let phishingInScope = false;
            let phishingScopeReason = '';

            // Check engagement type
            if (riskSummary?.engagement?.id) {
              const [eng] = await drizzleDb.select().from(engTable)
                .where(eqOp(engTable.id, riskSummary.engagement.id))
                .limit(1);
              if (eng?.engagementType === 'phishing') {
                phishingInScope = true;
                phishingScopeReason = 'Engagement type is phishing';
              }
            }

            // Check RoE for phishing/social engineering scope
            if (!phishingInScope) {
              const roeResults = await drizzleDb.select().from(roeTable)
                .orderBy(descOp(roeTable.createdAt))
                .limit(5);
              for (const roe of roeResults) {
                const testingTypes = Array.isArray(roe.testingTypes) ? roe.testingTypes : JSON.parse((roe.testingTypes as string) || '[]');
                const attackVecs = Array.isArray(roe.attackVectors) ? roe.attackVectors : JSON.parse((roe.attackVectors as string) || '[]');
                const hasPhishingType = testingTypes.some((t: string) => /phish|social/i.test(t));
                const hasPhishingVector = attackVecs.some((v: string) => /phish|social|credential_harvest/i.test(v));
                if (hasPhishingType || hasPhishingVector || roe.socialEngineeringAllowed) {
                  phishingInScope = true;
                  phishingScopeReason = `RoE #${roe.id}: ${hasPhishingType ? 'phishing testing type' : hasPhishingVector ? 'phishing attack vector' : 'social engineering allowed'}`;
                  break;
                }
              }
            }

            // Also check pipeline clientType / orgProfile for phishing indicators
            if (!phishingInScope && pipeline.clientType) {
              const ct = (pipeline.clientType || '').toLowerCase();
              if (ct.includes('phish') || ct.includes('social')) {
                phishingInScope = true;
                phishingScopeReason = `Pipeline client type indicates phishing: ${pipeline.clientType}`;
              }
            }

            // Check spoofability as a secondary trigger (original logic)
            const [latestRecon] = await drizzleDb.select().from(domainRecon)
              .where(eqOp(domainRecon.domain, domains[0] || ''))
              .orderBy(descOp(domainRecon.createdAt))
              .limit(1);

            const notSpoofable = latestRecon && !latestRecon.spoofable && (latestRecon.spoofScore ?? 0) < 50;
            if (notSpoofable && !phishingInScope) {
              phishingInScope = true;
              phishingScopeReason = `Target has strong email security (spoof score: ${latestRecon.spoofScore}/100) — typosquat recommended`;
            }

            if (phishingInScope) {
              const { generateTyposquatVariants } = await import('../lib/typosquat');
              const typosquatResult = await generateTyposquatVariants(domains[0], {
                checkAvailability: true,
                maxVariants: 15,
                includeAllTechniques: true,
              });

              riskSummary.typosquatRecommendation = {
                needed: true,
                reason: phishingScopeReason,
                spoofable: latestRecon?.spoofable ?? null,
                spoofScore: latestRecon?.spoofScore ?? null,
                variants: typosquatResult.recommendedVariants.slice(0, 10).map((v: any) => ({
                  domain: v.domain,
                  technique: v.technique,
                  effectiveness: v.effectiveness,
                  available: v.available,
                })),
                totalGenerated: typosquatResult.recommendedVariants.length,
              };
              console.log(`[Pipeline] Phishing in scope (${phishingScopeReason}). Generated ${typosquatResult.recommendedVariants.length} typosquat recommendations.`);
            } else {
              riskSummary.typosquatRecommendation = {
                needed: false,
                reason: 'Phishing not in scope and target domain is spoofable — typosquat not needed.',
              };
            }
          } catch (typoErr: any) {
            console.error('[Pipeline] Typosquat recommendation failed:', typoErr.message);
            riskSummary.typosquatRecommendation = { needed: false, reason: 'Check failed', error: typoErr.message };
          }

          // Step 6: Create Engagement
          stepLog[5] = { ...stepLog[5], status: 'running', timestamp: Date.now() };
          await db.updateEngagementPipeline(input.pipelineId, { currentStep: 6, stepLog });
          emitPipelineStep({ pipelineId: input.pipelineId, step: 6, stepName: 'Create Engagement', status: 'running' });
          const engagementId = await db.createEngagement({
            name: pipeline.name || 'Auto-Generated Engagement',
            customerName: domains[0] || 'Auto',
            engagementType: 'purple_team',
            status: 'planning',
            targetDomain: domains[0],
            description: `Auto-generated from pipeline. Domains: ${(pipeline.targetDomains as string[]).join(', ')}`,
          });
          riskSummary.engagement = { id: engagementId };
          stepLog[5] = { ...stepLog[5], status: 'complete', timestamp: Date.now() };
          emitPipelineStep({ pipelineId: input.pipelineId, step: 6, stepName: 'Create Engagement', status: 'complete' });

          await db.updateEngagementPipeline(input.pipelineId, {
            status: 'completed',
            stepLog,
            riskSummary,
            engagementId: Number(engagementId),
            completedAt: new Date(),
          });

          // Emit pipeline finished event
          emitPipelineStep({ pipelineId: input.pipelineId, step: -1, stepName: 'Pipeline Complete', status: 'complete', engagementId: Number(engagementId) });
          emitSystemNotification({ title: 'Engagement Pipeline Complete', message: `Pipeline "${pipeline.name}" completed successfully. Engagement #${engagementId} created.`, severity: 'info' });

          return { success: true, engagementId: Number(engagementId), riskSummary };
        } catch (err: any) {
          const failedStep = stepLog.findIndex((s: any) => s.status === 'running');
          if (failedStep >= 0) stepLog[failedStep] = { ...stepLog[failedStep], status: 'failed', timestamp: Date.now() };
          await db.updateEngagementPipeline(input.pipelineId, {
            status: 'failed',
            stepLog,
            errorMessage: err.message,
          });
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: err.message });
        }
      }),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return db.getEngagementPipeline(input.id);
      }),

    list: protectedProcedure.query(async () => {
      return db.listEngagementPipelines();
    }),
  });
