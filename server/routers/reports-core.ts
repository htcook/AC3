import { doStoragePut, doStorageGetContent } from "../do-storage";
import { fetchGophish as _fetchGophish } from "../lib/gophish-client";

/** Positional-args wrapper for backward compatibility */
function fetchGophishAPI(endpoint: string, method: string = 'GET', data?: any) {
  return _fetchGophish(endpoint, { method, data });
}
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";
import { ENV } from "../_core/env";
import { invokeLLM } from "../_core/llm";
import { captureCalderaEvidence } from "../lib/caldera-evidence-collector";
import { assertEngagementAccess } from "../lib/engagement-access-guard";

/**
 * Collect Caldera evidence snapshot for report generation.
 * Attempts to find the most recent operation related to the engagement
 * and captures agents, operation timeline, and adversary profile data
 * with source/destination IPs and timestamps.
 */
async function collectCalderaEvidenceForReport(engagement: any) {
  try {
    const calderaUrl = ENV.calderaBaseUrl;
    const calderaKey = ENV.calderaApiKey;
    if (!calderaUrl || !calderaKey) return undefined;

    // Find the most recent operation related to this engagement
    const opsResp = await fetch(calderaUrl + '/api/v2/operations', {
      headers: { 'KEY': calderaKey },
    });
    if (!opsResp.ok) return undefined;
    const allOps = await opsResp.json();
    if (!Array.isArray(allOps) || allOps.length === 0) return undefined;

    // Match by engagement name/ID in operation name, or take the most recent
    const engName = (engagement.name || engagement.customerName || '').toLowerCase();
    const engId = engagement.id;
    const matchedOp = allOps.find((op: any) =>
      op.name?.toLowerCase().includes(engName) ||
      op.name?.includes(`Eng${engId}`) ||
      op.name?.includes(`eng${engId}`)
    ) || allOps[allOps.length - 1];

    const operationId = matchedOp ? String(matchedOp.id) : undefined;
    const adversaryId = matchedOp?.adversary?.adversary_id || undefined;

    const snapshot = await captureCalderaEvidence({
      engagementId: engId,
      engagementName: engagement.name || `Engagement-${engId}`,
      operationId,
      adversaryId,
      targets: [], // Will be populated from agents
    });

    return snapshot || undefined;
  } catch (e) {
    console.log('[ReportsCore] Caldera evidence collection failed (non-fatal):', (e as any).message);
    return undefined;
  }
}
import { and, desc, eq, min, not } from "drizzle-orm";
import * as schema from "../../drizzle/schema";

export const reportsRouter = router({
    generate: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        reportType: z.enum(['executive_summary', 'technical_detail', 'compliance', 'phishing_results', 'osint_assessment', 'full_engagement', 'purple_team', 'red_team_assessment', 'detection_gap_analysis', 'pentest_assessment']),
        clientType: z.enum(['msp', 'enterprise', 'saas', 'paas', 'iaas', 'mixed_hosting', 'other']).default('enterprise'),
        title: z.string().min(1),
        preparedFor: z.string().nullish(),
        preparedBy: z.string().nullish(),
        includeSections: z.array(z.string()).optional(),
        brandingColor: z.string().nullish(),
      }))
      .mutation(async ({ input, ctx }) => {
        // Create report record
        const reportId = await db.createEngagementReport({
          engagementId: input.engagementId,
          reportType: input.reportType,
          clientType: input.clientType,
          title: input.title,
          preparedFor: input.preparedFor ?? null,
          preparedBy: input.preparedBy ?? ctx.user.name ?? 'C3 Platform',
          includeSections: input.includeSections || [],
          brandingColor: input.brandingColor ?? '#dc2626',
          status: 'generating',
          createdBy: ctx.user.id,
        });

        // Gather all engagement data
        const engagement = await db.getEngagementById(input.engagementId, ctx.user);
        if (!engagement) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement not found' });

        const reconData = await db.getDomainReconByEngagement(input.engagementId);
        const typosquats = await db.getTyposquatsByEngagement(input.engagementId);
        const findings = await db.getOsintFindingsByEngagement(input.engagementId);
        const campaignLinks = await db.getCampaignsByEngagement(input.engagementId);

        // Fetch GoPhish campaign results for linked campaigns
        let campaignResults: any[] = [];
        const gophishBaseUrl = ENV.gophishBaseUrl;
        const gophishApiKey = ENV.gophishApiKey;
        if (gophishBaseUrl && gophishApiKey) {
          for (const link of campaignLinks) {
            try {
              const resp = await fetch(`${gophishBaseUrl}/api/campaigns/${link.gophishCampaignId}/results`, {
                headers: { 'Authorization': gophishApiKey },
                ...(gophishBaseUrl.startsWith('https') ? { agent: new (await import('https')).Agent({ rejectUnauthorized: false }) } : {}),
              } as any);
              if (resp.ok) {
                const data = await resp.json();
                campaignResults.push({ ...data, campaignName: link.gophishCampaignName });
              }
            } catch (e) { /* skip failed fetches */ }
          }
        }

        // Fetch Domain Intel scan results for this engagement
        let domainIntelData: any[] = [];
        try {
          domainIntelData = await db.getDomainIntelScansByEngagement(input.engagementId);
        } catch (e) { /* skip if not available */ }

        // Extract threat actor matches from Domain Intel results
        let threatActorMatches: any[] = [];
        for (const scan of domainIntelData) {
          const result = scan.result as any;
          if (result?.threatActorMatches) {
            threatActorMatches = result.threatActorMatches;
            break;
          }
        }

        // Fetch Cyber C2 operation results
        let calderaOpsData: any[] = [];
        try {
          const calderaUrl = ENV.calderaBaseUrl;
          const calderaKey = ENV.calderaApiKey;
          if (calderaUrl && calderaKey) {
            const opsResp = await fetch(calderaUrl + '/api/v2/operations', {
              headers: { 'KEY': calderaKey },
            });
            if (opsResp.ok) {
              const allOps = await opsResp.json();
              // Filter for operations related to this engagement
              calderaOpsData = Array.isArray(allOps) ? allOps.filter((op: any) =>
                op.name?.toLowerCase().includes(engagement.customerName?.toLowerCase() || '') ||
                op.name?.toLowerCase().includes(engagement.targetDomain?.toLowerCase() || '')
              ).slice(0, 5) : [];
            }
          }
        } catch (e) { /* skip */ }

        // Get TTP knowledge for matched techniques
        let ttpInsights: any[] = [];
        try {
          const matchedTechniques = threatActorMatches.flatMap((a: any) => (a.techniques || []).map((t: any) => t.id)).filter(Boolean);
          const uniqueTechs = Array.from(new Set(matchedTechniques)).slice(0, 20);
          for (const techId of uniqueTechs) {
            const knowledge = await db.getTtpKnowledge(techId);
            if (knowledge) {
              ttpInsights.push({
                id: techId,
                name: knowledge.techniqueName,
                detectionRules: knowledge.detectionRules ? Object.keys(knowledge.detectionRules as any).length : 0,
                tools: Array.isArray(knowledge.toolsUsed) ? (knowledge.toolsUsed as any[]).length : 0,
              });
            }
          }
        } catch (e) { /* skip */ }

        // Fetch ROE status and audit log for Compliance & Authorization section
        let roeData: any = null;
        let auditLogEntries: any[] = [];
        try {
          const { engagements: engTable, offensiveAuditLog } = await import('../../drizzle/schema');
          const { eq: eqOp, desc: descOp } = await import('drizzle-orm');
          const { getDb: getDbConn } = await import('../db');
          const dbConn = await getDbConn();
          if (dbConn) {
            const [engRoe] = await dbConn.select({
              roeStatus: engTable.roeStatus,
              roeSignedDate: engTable.roeSignedDate,
              roeExpiryDate: engTable.roeExpiryDate,
              roeDocumentUrl: engTable.roeDocumentUrl,
              roeScope: engTable.roeScope,
              roeSignerName: engTable.roeSignerName,
              roeSignerEmail: engTable.roeSignerEmail,
            }).from(engTable).where(eqOp(engTable.id, input.engagementId)).limit(1);
            roeData = engRoe || null;

            auditLogEntries = await dbConn.select().from(offensiveAuditLog)
              .where(eqOp(offensiveAuditLog.engagementId, input.engagementId))
              .orderBy(descOp(offensiveAuditLog.createdAt))
              .limit(200);
          }        } catch (e) { console.error('ROE/audit fetch for report failed:', e); }

        // ─── Fetch credential exposure data from breach harvesting ───
        let credentialExposureContext = '';
        try {
          const { getEngagementCredentials } = await import('../lib/credential-harvester');
          const credData = await getEngagementCredentials(input.engagementId);
          if (credData.stats.total > 0) {
            const s = credData.stats;
            credentialExposureContext = `\n\n## CREDENTIAL EXPOSURE ASSESSMENT\n\n`;
            credentialExposureContext += `Total Breach-Sourced Credentials: ${s.total}\n`;
            credentialExposureContext += `Credentials with Plaintext Passwords: ${s.withPasswords}\n`;
            credentialExposureContext += `Credentials with Password Hashes: ${s.withHashes}\n`;
            credentialExposureContext += `Credentials Tested via Spray: ${s.tested}\n`;
            credentialExposureContext += `Successful Credential Sprays: ${s.successful}\n`;
            credentialExposureContext += `Sources: ${Object.entries(s.bySource).map(([src, cnt]) => `${src} (${cnt})`).join(', ')}\n\n`;
            // Include sample credentials (redacted passwords) for context
            const samples = credData.credentials.slice(0, 25);
            credentialExposureContext += `Sample Credentials (${Math.min(25, credData.credentials.length)} of ${credData.credentials.length}):\n`;
            for (const c of samples) {
              credentialExposureContext += `- ${c.email || c.username} | Source: ${c.source}${c.breachName ? ` (${c.breachName})` : ''} | Confidence: ${c.confidence} | Tested: ${c.isUsed ? 'Yes' : 'No'}${c.usedResult ? ` (${c.usedResult})` : ''}\n`;
            }
            if (credData.credentials.length > 25) {
              credentialExposureContext += `... and ${credData.credentials.length - 25} more credentials\n`;
            }
            credentialExposureContext += `\nIMPORTANT: You MUST include a "Credential Exposure Assessment" section in the report that:\n1. Summarizes the total breach-sourced credentials found and their sources\n2. Highlights the number of plaintext passwords vs hashed passwords\n3. Reports credential spray testing results (tested count, success rate)\n4. Assesses the organizational risk from credential reuse\n5. Provides remediation recommendations (password resets, MFA enforcement, credential monitoring)\n`;
            if (s.successful > 0) {
              credentialExposureContext += `\nCRITICAL: ${s.successful} credential(s) were CONFIRMED VALID via spray testing. This represents an active compromise risk and MUST be highlighted as a critical finding with immediate remediation required.\n`;
            }
          }
        } catch (credErr: any) {
          console.error('[Report] Failed to fetch credential exposure data:', credErr.message);
        }

        // Fetch engagement ops datatus from scan results when not explicitly set
        function deriveAssetStatus(asset: any): string {
          const hasExploits = (asset.exploitAttempts || []).some((ea: any) => ea.success);
          if (hasExploits) return 'compromised';
          const hasVulns = (asset.vulns || []).length > 0;
          const hasToolResults = (asset.toolResults || []).length > 0;
          if (hasVulns) return 'vulnerable';
          if (hasToolResults) return 'scanned';
          const hasPorts = (asset.knownPorts || []).length > 0 || (asset.ports || []).length > 0;
          if (hasPorts) return 'enumerated';
          return 'discovered';
        }

        // Fetch engagement ops data for discovery/tool evidence sections
        let opsDataContext = 'No active scan data available for this engagement.';
        try {
          const { getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
          const opsState = await getOpsStateWithRecovery(input.engagementId);
          if (opsState?.assets?.length) {
            const assets = opsState.assets;
            const totalToolRuns = assets.reduce((s, a) => s + (a.toolResults?.length || 0), 0);
            const totalFindings = assets.reduce((s, a) => s + (a.toolResults || []).reduce((s2, tr) => s2 + (tr.findings?.length || 0), 0), 0);
            let ctx = `Assets Discovered: ${assets.length} | Tool Runs: ${totalToolRuns} | Total Findings: ${totalFindings}\n\n`;
            for (const a of assets.slice(0, 20)) {
              ctx += `### ${a.hostname} (${a.ip || 'unknown'}) - Status: ${a.status}\n`;
              if (a.knownPorts?.length) ctx += `Ports: ${a.knownPorts.map((p: any) => typeof p === 'number' ? p : `${p.port}/${p.service || '?'}`).join(', ')}\n`;
              if (a.passiveRecon?.technologies?.length) ctx += `Technologies: ${a.passiveRecon.technologies.join(', ')}\n`;
              if (a.passiveRecon?.riskSignals?.length) ctx += `Risk Signals: ${a.passiveRecon.riskSignals.join(' | ')}\n`;
              if (a.passiveRecon?.certificates?.length) ctx += `Certificates: ${a.passiveRecon.certificates.map((c: any) => `${c.issuer || 'unknown'} (valid to: ${c.validTo || '?'})`).join(', ')}\n`;
              for (const tr of (a.toolResults || []).slice(0, 5)) {
                ctx += `  Tool: ${tr.tool} | Exit: ${tr.exitCode} | Duration: ${tr.duration || '?'}\n`;
                if (tr.command) ctx += `  Command: ${tr.command}\n`;
                if (tr.findings?.length) ctx += `  Findings: ${tr.findings.slice(0, 5).join('; ')}${tr.findings.length > 5 ? ` (+${tr.findings.length - 5} more)` : ''}\n`;
              }
              ctx += '\n';
            }
            if (assets.length > 20) ctx += `... and ${assets.length - 20} more assets\n`;
            opsDataContext = ctx;
          }

          // ─── Fallback: enrich opsDataContext from scan_results table ───
          if (opsDataContext === 'No active scan data available for this engagement.') {
            try {
              const dbScanResults = await db.getScanResultsByEngagement(input.engagementId);
              if (dbScanResults.length > 0) {
                const scanSummary = await db.getScanResultsSummary(input.engagementId);
                const totalDbFindings = dbScanResults.reduce((s, r) => s + (r.findingCount || 0), 0);
                const uniqueTargets = [...new Set(dbScanResults.map(r => r.target))];
                let ctx = `[Data recovered from scan_results database]\nTargets Scanned: ${uniqueTargets.length} | Tool Runs: ${dbScanResults.length} | Total Findings: ${totalDbFindings}\n\n`;
                ctx += `Tool Summary:\n`;
                for (const ts of scanSummary) {
                  ctx += `  ${ts.tool}: ${ts.count} runs, ${ts.totalFindings} findings, avg ${Math.round(Number(ts.avgDurationMs))}ms\n`;
                }
                ctx += '\n';
                // Group by target
                const byTarget = new Map<string, typeof dbScanResults>();
                for (const sr of dbScanResults) {
                  if (!byTarget.has(sr.target)) byTarget.set(sr.target, []);
                  byTarget.get(sr.target)!.push(sr);
                }
                for (const [target, results] of [...byTarget.entries()].slice(0, 20)) {
                  ctx += `### ${target}\n`;
                  for (const sr of results.slice(0, 8)) {
                    ctx += `  Tool: ${sr.tool} | Exit: ${sr.exitCode ?? '?'} | Findings: ${sr.findingCount || 0} | Duration: ${sr.durationMs ? sr.durationMs + 'ms' : '?'}\n`;
                    if (sr.command) ctx += `  Command: ${sr.command}\n`;
                    const findings = Array.isArray(sr.findings) ? sr.findings : [];
                    if (findings.length > 0) {
                      const findingStrs = findings.slice(0, 5).map((f: any) =>
                        typeof f === 'object' ? (f.title || f.name || f.vulnerability || JSON.stringify(f).substring(0, 100)) : String(f).substring(0, 100)
                      );
                      ctx += `  Findings: ${findingStrs.join('; ')}${findings.length > 5 ? ` (+${findings.length - 5} more)` : ''}\n`;
                    }
                  }
                  ctx += '\n';
                }
                opsDataContext = ctx;
                console.log(`[Report] Recovered ops context from ${dbScanResults.length} scan_results rows for ${uniqueTargets.length} targets`);
              }
            } catch (scanFallbackErr) {
              console.error('[Report] Legacy scan_results fallback failed:', scanFallbackErr);
            }
          }
        } catch (e) { console.error('Failed to fetch ops data for report:', e); }

        // ─── Pentest Assessment Pipeline (new structured report) ───
        if (input.reportType === 'pentest_assessment' || input.reportType === 'full_engagement') {
          try {
            const { runPentestReportPipeline } = await import('../lib/pentest-report-pipeline');
            const { getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
            const opsState = await getOpsStateWithRecovery(input.engagementId);

            // Map ops state assets to pipeline format
            let pipelineAssets = (opsState?.assets || []).map((a: any) => ({
              hostname: a.hostname || 'unknown',
              ip: a.ip || '',
              status: a.status || deriveAssetStatus(a),
              knownPorts: (a.knownPorts || []).map((p: any) => typeof p === 'number' ? { port: p } : p),
              technologies: a.passiveRecon?.technologies || [],
              riskSignals: a.passiveRecon?.riskSignals || [],
              certificates: a.passiveRecon?.certificates || [],
              vulns: (a.vulns || []).map((v: any) => ({
                title: v.title || v.name || 'Unknown',
                severity: v.severity || 'medium',
                cve: v.cve || v.cveId,
                description: v.description,
                source: v.source,
                corroborationTier: v.corroborationTier,
                evidenceDetail: v.evidenceDetail,
                evidence: v.evidence || undefined,
                attack: v.attack || undefined,
                method: v.method || undefined,
                param: v.param || undefined,
                url: v.url || undefined,
              })),
              toolResults: (a.toolResults || []).map((tr: any) => ({
                tool: tr.tool || 'scanner',
                command: tr.command,
                exitCode: tr.exitCode,
                duration: tr.duration,
                durationMs: tr.durationMs || tr.duration,
                findings: tr.findings || [],
                findingCount: tr.findings?.length || tr.findingCount || 0,
                rawOutput: tr.outputPreview || tr.rawOutput || '',
                executedAt: tr.executedAt || tr.timestamp,
                phase: tr.phase || (tr.tool === 'nuclei' ? 'scanning' : tr.tool === 'httpx' ? 'discovery' : tr.tool === 'naabu' || tr.tool === 'masscan' ? 'enumeration' : 'reconnaissance'),
              })),
              exploitAttempts: (a.exploitAttempts || []).map((ea: any) => ({
                module: ea.module || ea.exploitModule || ea.exploitSource || 'manual',
                success: !!ea.success,
                cve: ea.cve,
                service: ea.service,
                port: ea.port,
                confidence: ea.confidence,
                reasoning: ea.reasoning,
                timestamp: ea.timestamp,
                error: ea.error,
                output: ea.output || ea.rawOutput || '',
                technique: ea.technique || '',
                payload: ea.payload || '',
              })),
            }));

            // ─── Fallback: enrich from scan_results table when ops state has gaps ───
            // This ensures reports capture data even after server restarts when
            // in-memory state was lost and the DB snapshot may be stale.
            try {
              const dbScanResults = await db.getScanResultsByEngagement(input.engagementId);
              if (dbScanResults.length > 0) {
                // If ops state had no assets at all, build synthetic assets from scan_results
                if (pipelineAssets.length === 0) {
                  const assetMap = new Map<string, any>();
                  for (const sr of dbScanResults) {
                    const target = sr.target || 'unknown';
                    if (!assetMap.has(target)) {
                      assetMap.set(target, {
                        hostname: target,
                        ip: target,
                        status: 'scanned',
                        knownPorts: [],
                        technologies: [],
                        riskSignals: [],
                        certificates: [],
                        vulns: [],
                        toolResults: [],
                        exploitAttempts: [],
                      });
                    }
                    const asset = assetMap.get(target)!;
                    // Add tool result
                    asset.toolResults.push({
                      tool: sr.tool || 'unknown',
                      command: sr.command || '',
                      exitCode: sr.exitCode ?? -1,
                      duration: sr.durationMs ? `${sr.durationMs}ms` : undefined,
                      findings: Array.isArray(sr.findings) ? (sr.findings as string[]) : [],
                      rawOutput: sr.rawOutput ? (sr.rawOutput as string).substring(0, 2000) : undefined,
                    });
                    // Extract vulns from findings JSON
                    const findings = Array.isArray(sr.findings) ? sr.findings : [];
                    for (const f of findings as any[]) {
                      if (typeof f === 'object' && f !== null && (f.title || f.name || f.vulnerability)) {
                        asset.vulns.push({
                          title: f.title || f.name || f.vulnerability || 'Unknown Finding',
                          severity: f.severity || 'medium',
                          cve: f.cve || f.cveId || undefined,
                          description: f.description || f.detail || undefined,
                          source: sr.tool,
                          corroborationTier: f.corroborationTier || undefined,
                          evidenceDetail: f.evidence || f.evidenceDetail || undefined,
                          evidence: f.evidence || undefined,
                          attack: f.attack || undefined,
                          method: f.method || undefined,
                          param: f.param || undefined,
                          url: f.url || undefined,
                        });
                      } else if (typeof f === 'string' && f.length > 5) {
                        asset.vulns.push({
                          title: f.substring(0, 200),
                          severity: 'medium',
                          source: sr.tool,
                        });
                      }
                    }
                  }
                  pipelineAssets = Array.from(assetMap.values());
                  console.log(`[Report] Built ${pipelineAssets.length} synthetic assets from ${dbScanResults.length} scan_results rows`);
                } else {
                  // Ops state had assets but may be missing tool results — merge scan_results
                  for (const sr of dbScanResults) {
                    const matchingAsset = pipelineAssets.find(
                      a => a.hostname === sr.target || a.ip === sr.target
                    );
                    if (matchingAsset) {
                      const alreadyHasTool = matchingAsset.toolResults.some(
                        (tr: any) => tr.tool === sr.tool
                      );
                      if (!alreadyHasTool) {
                        matchingAsset.toolResults.push({
                          tool: sr.tool || 'unknown',
                          command: sr.command || '',
                          exitCode: sr.exitCode ?? -1,
                          duration: sr.durationMs ? `${sr.durationMs}ms` : undefined,
                          findings: Array.isArray(sr.findings) ? (sr.findings as string[]) : [],
                          rawOutput: sr.rawOutput ? (sr.rawOutput as string).substring(0, 2000) : undefined,
                        });
                      }
                    }
                  }
                }
              }
            } catch (scanFallbackErr) {
              console.error('[Report] scan_results fallback failed:', scanFallbackErr);
            }

            // Extract provenance records from active scan plan (stored on opsState during Phase 2.5)
            let provenanceRecords: Array<{
              passiveObservationId: string;
              passiveSignal: string;
              activeTool: string;
              target: string;
              rationale: string;
            }> | undefined;
            let activeScanPlanMeta: {
              totalTargets: number;
              estimatedScanDuration: string;
              riskCoverage: number;
              excludedByRoE: Array<{ hostname: string; reason: string }>;
            } | undefined;

            if (opsState && (opsState as any).activeScanPlan) {
              const plan = (opsState as any).activeScanPlan;
              if (Array.isArray(plan.provenance) && plan.provenance.length > 0) {
                provenanceRecords = plan.provenance.map((p: any) => ({
                  passiveObservationId: p.passiveObservationId || 'unknown',
                  passiveSignal: p.passiveSignal || 'unknown',
                  activeTool: p.activeTool || 'unknown',
                  target: p.target || 'unknown',
                  rationale: p.rationale || '',
                }));
              }
              activeScanPlanMeta = {
                totalTargets: plan.totalTargets || 0,
                estimatedScanDuration: plan.stats?.estimatedScanDuration || 'N/A',
                riskCoverage: plan.stats?.riskCoverage || 0,
                excludedByRoE: plan.excludedByRoE || [],
              };
            }

            // ─── Fetch exploitation evidence from DB for report ───
            let exploitationEvidence: any[] = [];
            try {
              const dbEvidence = await db.getExploitationAttempts(input.engagementId);
              if (dbEvidence.length > 0) {
                exploitationEvidence = dbEvidence.map(e => {
                  // Resolve true exploit status: if shell was obtained or meaningful access achieved,
                  // the exploit succeeded regardless of ea_status (which may reflect runner cleanup errors)
                  const rawStatus = e.eaStatus || 'attempted';
                  const shellGot = !!e.shellObtained;
                  const hasAccess = e.eaAccessLevel && e.eaAccessLevel !== 'none';
                  const resolvedStatus = (shellGot || hasAccess) ? 'succeeded' : rawStatus;

                  return {
                    id: e.id,
                    targetHost: e.targetHost,
                    targetPort: e.targetPort,
                    targetService: e.targetService,
                    vulnerabilityId: e.vulnerabilityId,
                    vulnerabilityCve: e.vulnerabilityCve,
                    exploitSource: e.exploitSource,
                    exploitModule: e.exploitModule,
                    status: resolvedStatus,
                    resultType: e.resultType,
                    resultOutput: e.resultOutput,
                    shellObtained: e.shellObtained,
                    accessLevel: e.eaAccessLevel,
                    evidence: e.eaEvidence,
                    attackTechnique: e.eaAttackTechnique,
                    matchConfidence: e.matchConfidence,
                    opsecRisk: e.opsecRisk,
                    durationMs: e.durationMs,
                    attemptedAt: e.eaAttemptedAt,
                    completedAt: e.eaCompletedAt,
                    screenshotUrls: e.screenshotUrls ? (typeof e.screenshotUrls === 'string' ? JSON.parse(e.screenshotUrls) : e.screenshotUrls) : [],
                  };
                });
                console.log(`[Report] Loaded ${exploitationEvidence.length} exploitation evidence records from DB`);
              }
            } catch (evidenceErr: any) {
              console.error('[Report] Failed to load exploitation evidence:', evidenceErr.message);
            }

            const pipelineResult = await runPentestReportPipeline({
              engagement: {
                id: engagement.id,
                name: engagement.name,
                customerName: engagement.customerName,
                engagementType: engagement.engagementType || 'External Penetration Test',
                targetDomain: engagement.targetDomain,
                targetIpRange: engagement.targetIpRange,
                status: engagement.status,
                startDate: engagement.startDate ? new Date(engagement.startDate).getTime() : null,
                endDate: engagement.endDate ? new Date(engagement.endDate).getTime() : null,
              },
              preparedFor: input.preparedFor || engagement.customerName,
              preparedBy: input.preparedBy || ctx.user.name || 'Ace of Cloud LLC',
              clientType: input.clientType,
              assets: pipelineAssets,
              reconData,
              typosquats,
              osintFindings: findings,
              domainIntelData,
              threatActorMatches,
              calderaOpsData,
              ttpInsights,
              campaignResults,
              roeData,
              auditLogEntries,
              provenanceRecords,
              activeScanPlan: activeScanPlanMeta,
              calderaEvidenceSnapshot: await collectCalderaEvidenceForReport(engagement),
              exploitationEvidence,
              manualFindings: opsState?.manualFindings || [],
              usedConnectors: (() => {
                // Extract connector names from domain intel scan results for compliance attribution
                const connectors = new Set<string>();
                for (const scan of domainIntelData) {
                  const po = scan.pipelineOutput as any;
                  if (po?.connectorResults) {
                    for (const cr of po.connectorResults) {
                      if (cr?.connector) connectors.add(cr.connector);
                    }
                  }
                  // Also check passiveRecon observations
                  if (po?.passiveRecon?.observations) {
                    for (const obs of po.passiveRecon.observations) {
                      if (obs?.tags) {
                        for (const tag of obs.tags) {
                          if (typeof tag === 'string' && !tag.includes(' ')) connectors.add(tag);
                        }
                      }
                    }
                  }
                }
                return connectors.size > 0 ? Array.from(connectors) : undefined;
              })(),
              credentialExposure: await (async () => {
                try {
                  const { getEngagementCredentials } = await import('../lib/credential-harvester');
                  const credData = await getEngagementCredentials(input.engagementId);
                  if (credData.stats.total > 0) {
                    return {
                      ...credData.stats,
                      sampleCredentials: credData.credentials.slice(0, 25).map(c => ({
                        email: c.email,
                        username: c.username,
                        source: c.source,
                        breachName: c.breachName,
                        confidence: c.confidence,
                        isUsed: c.isUsed,
                        usedResult: c.usedResult,
                      })),
                    };
                  }
                } catch (e) { console.error('[Report] Credential exposure fetch failed:', (e as any).message); }
                return undefined;
              })(),
            });

            // ── AC3 Lint Quality Gate ──
            let lintResult: any = null;
            try {
              const { lintReport, formatLintIssues } = await import('../lib/ac3-lint-bridge');
              // Build the lint input dict from pipeline data
              const lintInput: Record<string, unknown> = {
                report_type: 'pentest',
                metadata: {
                  engagement_id: input.engagementId,
                  target: pipelineResult.reportMetrics?.targetDomain || engagement.targetDomain,
                },
                counts: pipelineResult.reportMetrics ? {
                  total_assets: pipelineResult.reportMetrics.totalAssets,
                  confirmed_findings: pipelineResult.reportMetrics.totalFindings,
                } : undefined,
                rendered_text: {
                  full_report: pipelineResult.markdown.slice(0, 50000), // First 50k chars for narrative checks
                },
              };
              lintResult = await lintReport(lintInput);
              if (!lintResult.passed) {
                console.warn(`[AC3 Lint] Report FAILED quality gate: ${lintResult.summary.errors} errors, ${lintResult.summary.warnings} warnings`);
                console.warn(formatLintIssues(lintResult));
              } else {
                console.log(`[AC3 Lint] Report PASSED quality gate (${lintResult.checks_run} checks, ${lintResult.summary.warnings} warnings)`);
              }
            } catch (lintErr: any) {
              // Non-fatal: don't block report delivery if linter fails
              console.error('[AC3 Lint] Linter execution failed (non-blocking):', lintErr.message);
            }

            // Store as S3 file
            try {
              const reportKey = `reports/${input.engagementId}/${reportId}-pentest-${Date.now()}.md`;
              const { url } = await doStoragePut(reportKey, pipelineResult.markdown, 'text/markdown');

              await db.updateReport(reportId, {
                status: 'completed',
                reportUrl: url,
                reportKey,
                generatedAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
              });

              // ── Evidence Integrity: Create Merkle root anchor at report finalization ──
              try {
                const { createMerkleRootAnchor, flushChainToDb } = await import('../lib/evidence-integrity-guardrails');
                // Flush any in-memory chain envelopes to DB first
                await flushChainToDb(String(input.engagementId));
                // Create the cryptographic seal
                const anchor = await createMerkleRootAnchor(
                  String(input.engagementId),
                  `Report finalization anchor — Report ID: ${reportId}, generated by ${ctx.user?.name || 'system'}`,
                  ctx.user?.name || 'AC3 Report Pipeline',
                );
                if (anchor) {
                  console.log(`[Evidence Integrity] Merkle root anchor created for engagement ${input.engagementId}: ${anchor.merkleRoot.slice(0, 16)}... (chain length: ${anchor.chainLength})`);
                } else {
                  console.warn(`[Evidence Integrity] No evidence chain found for engagement ${input.engagementId} — anchor not created`);
                }
              } catch (anchorErr: any) {
                // Non-fatal: don't block report delivery if anchor creation fails
                console.error(`[Evidence Integrity] Anchor creation failed for engagement ${input.engagementId}:`, anchorErr.message);
              }

              return { id: reportId, url, content: pipelineResult.markdown, lintResult };
            } catch (storageErr) {
              await db.updateReport(reportId, {
                status: 'completed',
                generatedAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
              });
              return { id: reportId, url: null, content: pipelineResult.markdown, lintResult };
            }
          } catch (err: any) {
            console.error('Pentest pipeline failed:', err);
            await db.updateReport(reportId, { status: 'failed' });
            throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Pentest report pipeline failed: ' + err.message });
          }
        }

        // ─── Legacy single-prompt report generation ───
        const { invokeLLM } = await import('../_core/llm');
        const { buildSectionOutline, getReportBlueprint } = await import('../lib/report-section-blueprints');

        const clientTypeLabels: Record<string, string> = {
          msp: 'Managed Service Provider (MSP)',
          enterprise: 'Enterprise Organization',
          saas: 'SaaS Provider',
          paas: 'PaaS Provider',
          iaas: 'IaaS Provider',
          mixed_hosting: 'Mixed Hosting Provider',
          other: 'Organization',
        };

        // ─── Map report types to assessment blueprint types ───
        const reportTypeToBlueprint: Record<string, string> = {
          executive_summary: 'penetration_test',
          technical_detail: 'penetration_test',
          compliance: 'penetration_test',
          phishing_results: 'phishing_campaign',
          osint_assessment: 'vulnerability_assessment',
          full_engagement: 'hybrid',
          purple_team: 'purple_team',
          red_team_assessment: 'red_team',
          detection_gap_analysis: 'purple_team',
        };

        // Also map from engagement type if available
        const engTypeToBlueprint: Record<string, string> = {
          red_team: 'red_team',
          phishing: 'phishing_campaign',
          pentest: 'penetration_test',
          purple_team: 'purple_team',
          tabletop: 'tabletop_exercise',
        };

        // Determine the best blueprint: prefer engagement type, fallback to report type mapping
        const engType = (engagement.engagementType || '').toLowerCase().replace(/[\s-]/g, '_');
        const blueprintType = engTypeToBlueprint[engType] || reportTypeToBlueprint[input.reportType] || 'penetration_test';
        const blueprint = getReportBlueprint(blueprintType);
        const sectionOutline = buildSectionOutline(blueprintType);

        // ─── Auto-escalate risk when successful exploits exist ───
        // GUARDRAIL: Only escalate risk based on CONFIRMED successful exploits from the database,
        // not from in-memory ops state which may be stale or inaccurate.
        let riskEscalation = '';
        try {
          const dbExploitAttempts = await db.getExploitationAttempts(input.engagementId);
          const confirmedSuccessful = dbExploitAttempts.filter(e => e.status === 'succeeded');
          const hasC2Agents = false; // Only set true if we have DB-confirmed C2 agent evidence
          try {
            const { getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
            const opsState = await getOpsStateWithRecovery(input.engagementId);
            if (opsState && ((opsState as any).stats?.c2Agents || 0) > 0) {
              // C2 agents are confirmed by Caldera API, not LLM-generated
              // hasC2Agents = true; // Uncomment when Caldera evidence is verified
            }
          } catch { /* non-fatal */ }
          if (confirmedSuccessful.length > 0 || hasC2Agents) {
            riskEscalation = `\n\nCRITICAL RISK ESCALATION: This engagement achieved ${confirmedSuccessful.length} CONFIRMED SUCCESSFUL EXPLOITATION(S) verified in the database. The overall risk rating MUST be HIGH or CRITICAL. Include a dedicated "Exploitation Evidence" section with:\n- CVSS v3.1 score and full vector string with per-metric justification\n- Exploitation timeline with precise timestamps\n- Session evidence (shell access, commands executed)\n- Risk rating justification table (exploitability, impact, regulatory, detection gaps)`;
          } else if (dbExploitAttempts.length > 0) {
            riskEscalation = `\n\nEXPLOITATION STATUS: ${dbExploitAttempts.length} exploitation attempts were made but ALL FAILED. Do NOT claim successful exploitation. Report the failed attempts honestly and focus on the theoretical risk of the identified vulnerabilities.`;
          }
        } catch (e) { /* non-fatal */ }

        // ─── Fetch exploitation evidence from DB for legacy report ───
        let legacyExploitEvidence = '';
        try {
          const dbEvidence = await db.getExploitationAttempts(input.engagementId);
          if (dbEvidence.length > 0) {
            const succeeded = dbEvidence.filter(e => e.status === 'succeeded');
            const failed = dbEvidence.filter(e => e.status === 'failed');
            const blocked = dbEvidence.filter(e => e.status === 'blocked');
            legacyExploitEvidence = `\n\n## EXPLOITATION EVIDENCE (${dbEvidence.length} attempts — ${succeeded.length} succeeded, ${failed.length} failed, ${blocked.length} blocked)\n`;
            legacyExploitEvidence += dbEvidence.slice(0, 20).map(e => {
              let line = `- [${(e.status || 'unknown').toUpperCase()}] ${e.exploitModule || e.exploitSource} → ${e.targetHost}:${e.targetPort || 'N/A'}`;
              if (e.vulnerabilityCve) line += ` (${e.vulnerabilityCve})`;
              if (e.accessLevel) line += ` | Access: ${e.accessLevel}`;
              if (e.resultType) line += ` | Result: ${e.resultType}`;
              if (e.attackTechnique) line += ` | Technique: ${e.attackTechnique}`;
              if (e.durationMs) line += ` | Duration: ${e.durationMs}ms`;
              if (e.resultOutput) line += `\n  Output: ${e.resultOutput.substring(0, 300)}`;
              if (e.evidence) {
                const evi = typeof e.evidence === 'string' ? (() => { try { return JSON.parse(e.evidence as string); } catch { return null; } })() : e.evidence;
                if (evi?.proofLines?.length > 0) line += `\n  Proof: ${evi.proofLines.slice(0, 3).join(' | ')}`;
                if (evi?.httpResponse?.statusCode) line += `\n  HTTP: ${evi.httpResponse.statusCode} ${evi.httpResponse.url || ''}`;
              }
              return line;
            }).join('\n');
            if (succeeded.length > 0) {
              legacyExploitEvidence += `\n\nIMPORTANT: You MUST include an "Exploitation Evidence" section in the report that presents each successful exploit with its proof-of-concept output, HTTP response data, access classification, and timestamps. Failed and blocked attempts should be summarized in a table.`;
            } else {
              legacyExploitEvidence += `\n\nCRITICAL: ALL ${dbEvidence.length} exploitation attempts FAILED. Zero exploits succeeded. You MUST NOT claim any exploit was successful. You MUST NOT fabricate shell access, command execution, credential dumps, or any post-exploitation activity. The report MUST clearly state that exploitation testing was attempted but did not result in confirmed compromise. Describe the failed attempts honestly and discuss what defensive controls prevented exploitation.`;
            }
            console.log(`[Report/Legacy] Loaded ${dbEvidence.length} exploitation evidence records`);
          }
        } catch (evidenceErr: any) {
          console.error('[Report/Legacy] Failed to load exploitation evidence:', evidenceErr.message);
        }

        const reportPrompt = `Generate a ${blueprint.displayName} for a ${clientTypeLabels[input.clientType] || 'client'}. Target audience: ${blueprint.audience}. Applicable frameworks: ${blueprint.defaultFrameworks.join(', ')}.`;

        try {
          const response = await invokeLLM({ _caller: "reports-core", _priority: 'bulk',
            messages: [
              {
                role: 'system',
                content: `You are a senior cybersecurity assessment reporting engine designed to produce professional reports suitable for enterprise clients and government compliance frameworks including FedRAMP, NIST 800-53, SOC2, PCI-DSS, and HIPAA.

Your task is to convert raw security testing data, reconnaissance outputs, and vulnerability signals into a fully structured ${blueprint.displayName} for a ${clientTypeLabels[input.clientType] || 'client'} suitable for ${blueprint.audience}.

The report must follow professional standards used by top consulting firms (Mandiant, NCC Group, Bishop Fox, CrowdStrike).

${sectionOutline}

EVIDENCE-GROUNDING RULES (MANDATORY — VIOLATION IS PROFESSIONAL FRAUD):
- You MUST ONLY report exploitation outcomes that are explicitly provided in the EXPLOITATION EVIDENCE section below.
- If an exploit is marked as FAILED, you MUST report it as failed. Do NOT claim it succeeded.
- If zero exploits succeeded, the report MUST clearly state that no exploitation was achieved during this engagement.
- Do NOT invent, fabricate, or hallucinate any exploitation results, shell sessions, credential dumps, lateral movement, data exfiltration, or post-exploitation activity.
- Use conditional language ("could potentially", "would allow", "if exploited") when discussing theoretical impact of unpatched vulnerabilities.
- When all exploits failed, focus on: vulnerabilities identified, theoretical risk if left unpatched, and defensive controls that prevented exploitation.
- This is a legal document provided to paying clients. Fabricating successful exploitation constitutes professional fraud and liability.

FORMATTING REQUIREMENTS:
- Use structured Markdown tables for all tabular data
- Use Mermaid diagrams for attack chains, kill chains, and process flows where appropriate
- Every vulnerability finding MUST include:
  * CVSS v3.1 score and full vector string (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
  * Per-metric CVSS justification table
  * MITRE ATT&CK technique mapping (T-number and tactic)
  * NIST 800-53 control mapping
  * OWASP Top 10:2025 category
  * Supporting evidence artifacts (numbered E-1, E-2, etc.)
  * Risk rating with justification
  * Remediation recommendation with priority
- Every successful exploitation MUST include:
  * Exploitation timeline with precise timestamps
  * Session evidence (shell access, commands, output)
  * C2 agent deployment proof if applicable
  * Approval gate audit trail
  * Risk rating justification table
- Include a Risk Matrix table mapping likelihood vs impact
- Include a Remediation Roadmap with prioritized action items and timelines

Output format: Markdown compatible with PDF export.
Brand the report as produced by Ace of Cloud LLC (aceofcloud.com). Report Author: Harrison Cook.${riskEscalation}`,
              },
              {
                role: 'user',
                content: `Generate the report with the following context:

Report Title: ${input.title}
Prepared For: ${input.preparedFor || engagement.customerName}
Prepared By: ${input.preparedBy || ctx.user.name || 'C3 Platform'}
Client Type: ${clientTypeLabels[input.clientType]}
Engagement: ${engagement.name} (${engagement.engagementType})
Customer: ${engagement.customerName}
Target Domain: ${engagement.targetDomain || 'N/A'}
Status: ${engagement.status}
Date Range: ${engagement.startDate ? new Date(engagement.startDate).toLocaleDateString() : 'N/A'} - ${engagement.endDate ? new Date(engagement.endDate).toLocaleDateString() : 'Ongoing'}

OSINT Recon Data (${reconData.length} scans):
${JSON.stringify(reconData.slice(0, 3).map(r => ({
  domain: r.domain,
  spoofScore: r.spoofScore,
  spoofable: r.spoofable,
  spf: r.spfRecord ? 'Present' : 'Missing',
  dmarc: r.dmarcRecord ? 'Present' : 'Missing',
  subdomains: Array.isArray(r.subdomains) ? (r.subdomains as any[]).length : 0,
})), null, 2)}

Typosquat Domains Found: ${typosquats.length}
${typosquats.slice(0, 10).map(t => `- ${t.permutedDomain} (${t.permutationType}, registered: ${t.isRegistered})`).join('\n')}

OSINT Findings (${findings.length} total):
${findings.slice(0, 15).map(f => `- [${f.severity}] ${f.title}: ${f.description?.substring(0, 100)}`).join('\n')}

Phishing Campaign Results (${campaignResults.length} campaigns):
${JSON.stringify(campaignResults.map(c => ({
  name: c.campaignName,
  totalTargets: c.results?.length || 0,
  sent: c.results?.filter((r: any) => r.status === 'Email Sent').length || 0,
  opened: c.results?.filter((r: any) => r.status === 'Email Opened').length || 0,
  clicked: c.results?.filter((r: any) => r.status === 'Clicked Link').length || 0,
  submitted: c.results?.filter((r: any) => r.status === 'Submitted Data').length || 0,
})), null, 2)}

Domain Intel Scan Results (${domainIntelData.length} scans):
${domainIntelData.slice(0, 3).map(s => {
  const r = s.result as any;
  const po = s.pipelineOutput as any;
  return JSON.stringify({
    domain: s.domain,
    riskScore: r?.riskScore,
    assetsDiscovered: r?.assets?.length || 0,
    postureFindings: r?.posture?.length || 0,
    campaignRecommendations: (r?.campaigns || []).map((c: any) => ({ name: c.name, priority: c.priority })),
    domainHealth: po?.domainHealth ? {
      overallScore: po.domainHealth.overallScore,
      overallGrade: po.domainHealth.overallGrade,
      blacklistGrade: po.domainHealth.categories?.blacklist?.grade,
      mailServerGrade: po.domainHealth.categories?.mailServer?.grade,
      dnsHealthGrade: po.domainHealth.categories?.dnsHealth?.grade,
      connectivityGrade: po.domainHealth.categories?.connectivity?.grade,
      issueCount: po.domainHealth.issues?.length || 0,
      criticalIssues: (po.domainHealth.issues || []).filter((i: any) => i.severity === 'critical').map((i: any) => i.message),
      warningIssues: (po.domainHealth.issues || []).filter((i: any) => i.severity === 'warning').map((i: any) => i.message).slice(0, 5),
    } : undefined,
  });
}).join('\n')}

IMPORTANT: If domain health data is available, include a "Domain Health Assessment" section covering blacklist status, mail server configuration, DNS health, and connectivity. Highlight any critical or warning issues that could impact the organization's security posture or email deliverability.

Matched Threat Actors (${threatActorMatches.length} actors targeting this organization):
${threatActorMatches.slice(0, 10).map((a: any) => "- " + a.name + " (" + a.origin + ") - Score: " + a.matchScore + "/100 - Techniques: " + (a.techniques?.length || 0)).join('\n')}

Cyber C2 Operation Results (${calderaOpsData.length} operations):
${calderaOpsData.map((op: any) => JSON.stringify({
  name: op.name,
  state: op.state,
  adversary: op.adversary?.name,
  chainLength: op.chain?.length || 0,
  successfulSteps: op.chain?.filter((c: any) => c.status === 0).length || 0,
  failedSteps: op.chain?.filter((c: any) => c.status !== 0 && c.status !== -3).length || 0,
})).join('\n')}

TTP Knowledge Base Insights (${ttpInsights.length} techniques analyzed):
${ttpInsights.map(t => "- " + t.id + " " + t.name + " (" + t.detectionRules + " detection rule types, " + t.tools + " tools)").join('\n')}

IMPORTANT: Include a Detection Gap Analysis section that identifies which techniques were successfully executed vs blocked. Include specific remediation recommendations for each gap. Map findings to MITRE ATT&CK framework. Include a risk matrix table.

## COMPLIANCE & AUTHORIZATION DATA

ROE Status: ${roeData?.roeStatus || 'none'}
ROE Signed Date: ${roeData?.roeSignedDate ? new Date(roeData.roeSignedDate).toLocaleDateString() : 'N/A'}
ROE Expiry Date: ${roeData?.roeExpiryDate ? new Date(roeData.roeExpiryDate).toLocaleDateString() : 'N/A'}
ROE Signer: ${roeData?.roeSignerName || 'N/A'} (${roeData?.roeSignerEmail || 'N/A'})
ROE Document: ${roeData?.roeDocumentUrl ? 'Uploaded' : 'Not uploaded'}
ROE Scope: ${roeData?.roeScope ? JSON.stringify(roeData.roeScope) : 'Not defined'}

Offensive Audit Log (${auditLogEntries.length} entries):
${auditLogEntries.slice(0, 50).map((e: any) => `- [${new Date(e.createdAt).toISOString()}] ${e.operatorName || e.operatorId} | ${e.actionType} | ${e.riskTier} tier | Target: ${e.target} | Module: ${e.moduleOrTool || 'N/A'} | Result: ${e.resultStatus} | ROE: ${e.roeStatus || 'N/A'}`).join('\n')}
${auditLogEntries.length > 50 ? `... and ${auditLogEntries.length - 50} more entries` : ''}

## ENGAGEMENT OPS DATA (Active Scanning & Discovery)
${opsDataContext}

IMPORTANT: You MUST include a "Discovery & Reconnaissance" section that covers all asset discovery results, port/service findings from ScanForge/httpx, passive recon data, and technology stack analysis. Include a per-asset summary table with ports, services, technologies, and risk signals.

IMPORTANT: You MUST include a "Tool Execution Evidence" section that documents all security tools executed, their commands, exit codes, and key findings. This provides the forensic evidence chain.
${credentialExposureContext}
${legacyExploitEvidence}
IMPORTANT: You MUST include a "Compliance & Authorization" section in the report that:
1. States the ROE status, signed date, expiry date, and signer information
2. Confirms whether all offensive actions were conducted under valid ROE
3. Lists a summary table of offensive actions from the audit log (action type, risk tier, target, result, timestamp)
4. Notes any actions that were blocked due to missing/expired ROE
5. Includes the authorized scope (domains, IP ranges, exclusions) from the ROE

Instructions: ${reportPrompt}`,
              },
            ],
          });

          const reportContent = (response?.choices?.[0]?.message?.content as string) || 'Report generation failed.';

          // Store as S3 file
          try {
            const reportKey = `reports/${input.engagementId}/${reportId}-${Date.now()}.md`;
            const { url } = await doStoragePut(reportKey, reportContent, 'text/markdown');

            await db.updateReport(reportId, {
              status: 'completed',
              reportUrl: url,
              reportKey,
              generatedAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
            });

            // ── Evidence Integrity: Create Merkle root anchor at legacy report finalization ──
            try {
              const { createMerkleRootAnchor, flushChainToDb } = await import('../lib/evidence-integrity-guardrails');
              await flushChainToDb(String(input.engagementId));
              const anchor = await createMerkleRootAnchor(
                String(input.engagementId),
                `Legacy report anchor — Report ID: ${reportId}`,
                ctx.user?.name || 'AC3 Report Pipeline',
              );
              if (anchor) {
                console.log(`[Evidence Integrity] Merkle root anchor created for engagement ${input.engagementId}: ${anchor.merkleRoot.slice(0, 16)}...`);
              }
            } catch (anchorErr: any) {
              console.error(`[Evidence Integrity] Anchor creation failed:`, anchorErr.message);
            }

            return { id: reportId, url, content: reportContent };
          } catch (storageErr) {
            // If S3 fails, still return the content
            await db.updateReport(reportId, {
              status: 'completed',
              generatedAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
            });
            return { id: reportId, url: null, content: reportContent };
          }
        } catch (err: any) {
          await db.updateReport(reportId, { status: 'failed' });
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Report generation failed: ' + err.message });
        }
      }),

    list: protectedProcedure
      .input(z.object({ engagementId: z.number().optional() }).optional())
      .query(async ({ input }) => {
        if (input?.engagementId) {
          return db.getEngagementReports(input.engagementId);
        }
        return db.getAllReports();
      }),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        const report = await db.getReportById(input.id);
        if (!report) throw new TRPCError({ code: 'NOT_FOUND', message: 'Report not found' });
        return report;
      }),

    delete: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        const report = await db.getReportById(input.id);
        if (!report) throw new TRPCError({ code: 'NOT_FOUND', message: 'Report not found' });
        await db.deleteReport(input.id);
        return { success: true };
      }),

    exportHtml: protectedProcedure
      .input(z.object({ reportId: z.number() }))
      .mutation(async ({ input }) => {
        const report = await db.getReportById(input.reportId);
        if (!report) throw new TRPCError({ code: 'NOT_FOUND', message: 'Report not found' });

        // Fetch the markdown content from S3 URL or stored content
        let markdownContent = '';
        if (report.reportUrl) {
          try {
            const resp = await fetch(report.reportUrl);
            if (resp.ok) markdownContent = await resp.text();
          } catch (e) { /* fallback below */ }
        }
        if (!markdownContent) {
          throw new TRPCError({ code: 'NOT_FOUND', message: 'Report content not available' });
        }

        // Convert markdown to HTML using marked
        const { marked } = await import('marked');
        const bodyHtml = await marked.parse(markdownContent, {
          gfm: true,
          breaks: true,
        });

        // Wrap in branded Ace of Cloud template
        const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

        // Determine assessment type display name from blueprint
        let assessmentTypeDisplay = 'Security Assessment';
        try {
          const { getReportBlueprint } = await import('../lib/report-section-blueprints');
          // Try to get engagement for type info
          const eng = await db.getEngagementById((report as any).engagementId);
          const engType = (eng?.engagementType || (report as any).reportType || 'pentest').toLowerCase().replace(/[\s-]/g, '_');
          assessmentTypeDisplay = getReportBlueprint(engType).displayName;
        } catch { assessmentTypeDisplay = ((report as any).reportType || 'security_assessment').replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase()); }

        const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>${report.title || 'Pentest Assessment Report'}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Inter', Helvetica, Arial, sans-serif; color: #1a1a1a; line-height: 1.7; background: #fff; }
  .page { max-width: 850px; margin: 0 auto; padding: 48px 56px; }
  .header { padding-bottom: 28px; margin-bottom: 36px; border-bottom: 1px solid #cccccc; }
  .report-title { font-size: 28px; font-weight: 700; color: #1a1a1a; margin-bottom: 16px; }
  .report-meta { font-size: 12px; color: #666666; line-height: 1.8; }
  .report-meta div { margin-bottom: 2px; }
  .classification-line { font-weight: 700; font-size: 13px; margin-top: 12px; }
  .content h1 { font-size: 22px; font-weight: 700; color: #1a1a1a; margin: 32px 0 16px 0; }
  .content h2 { font-size: 18px; font-weight: 700; color: #1a1a1a; margin: 24px 0 12px 0; }
  .content h3 { font-size: 15px; font-weight: 600; color: #333333; margin: 20px 0 10px 0; }
  .content h4 { font-size: 13px; font-weight: 600; color: #444444; margin: 16px 0 8px 0; }
  .content p { font-size: 13px; margin-bottom: 10px; }
  .content ul, .content ol { font-size: 13px; padding-left: 24px; margin-bottom: 12px; }
  .content li { margin-bottom: 4px; }
  .content table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 12px; }
  .content th { background: #d9d9d9; color: #1a1a1a; padding: 8px 12px; text-align: left; font-weight: 600; font-size: 11px; border: 1px solid #999999; }
  .content td { padding: 8px 12px; border: 1px solid #cccccc; }
  .content blockquote { border-left: 3px solid #999999; padding: 12px 16px; margin: 12px 0; background: #f5f5f5; font-size: 13px; color: #333333; }
  .content code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-size: 12px; color: #333333; }
  .content pre { background: #2a2a2a; color: #e0e0e0; padding: 16px; border-radius: 4px; overflow-x: auto; margin: 12px 0; font-size: 12px; }
  .content pre code { background: none; padding: 0; color: inherit; }
  .content hr { border: none; border-top: 1px solid #cccccc; margin: 24px 0; }
  .content strong { color: #1a1a1a; }
  .footer { border-top: 1px solid #cccccc; padding-top: 16px; margin-top: 40px; font-size: 11px; color: #666666; display: flex; justify-content: space-between; }
  @media print {
    .page { padding: 24px; max-width: 100%; }
    .content h1 { page-break-before: always; }
    .content h1:first-child { page-break-before: avoid; }
    .content table { page-break-inside: avoid; }
    .no-print { display: none; }
  }
</style>
</head>
<body>
<div class="page">
  <div class="header">
    <div class="report-title">${report.title || 'Penetration Test Assessment Report'}</div>
    <div class="report-meta">
      <div>Client: ${report.preparedFor || 'Client'}</div>
      <div>Prepared by: ${report.preparedBy || 'Ace of Cloud LLC'}</div>
      <div>Assessment Type: ${assessmentTypeDisplay}</div>
      <div>Report Date: ${dateStr}</div>
    </div>
    <div class="classification-line">CONFIDENTIAL \u2013 Security Assessment Report</div>
  </div>
  <div class="content">${bodyHtml}</div>
  <div class="footer">
    <div>Ace of Cloud LLC \u2014 aceofcloud.com</div>
    <div>CONFIDENTIAL \u2014 ${dateStr}</div>
  </div>
</div>
<script class="no-print">
  // Auto-trigger print dialog for PDF export
  window.addEventListener('load', function() {
    setTimeout(function() { window.print(); }, 600);
  });
</script>
</body>
</html>`;

        // Store the HTML version to S3
        try {
          const htmlKey = `reports/${report.engagementId}/${input.reportId}-branded-${Date.now()}.html`;
          const { url } = await doStoragePut(htmlKey, html, 'text/html');
          return { html, url };
        } catch (e) {
          return { html, url: null };
        }
      }),

    /** Export report as a real downloadable PDF stored in S3 */
    exportPdf: protectedProcedure
      .input(z.object({ reportId: z.number() }))
      .mutation(async ({ input }) => {
        const report = await db.getReportById(input.reportId);
        if (!report) throw new TRPCError({ code: 'NOT_FOUND', message: 'Report not found' });

        // Fetch the markdown content: prefer S3 SDK (handles presigned URL expiry), fallback to URL fetch
        let markdownContent = '';
        // Method 1: Direct S3 download via reportKey (never expires)
        if (!markdownContent && (report as any).reportKey) {
          try {
            const result = await doStorageGetContent((report as any).reportKey);
            if (result) markdownContent = result.data.toString('utf-8');
          } catch (e) {
            console.warn('[Report/PDF] S3 direct download failed, trying URL:', (e as any).message);
          }
        }
        // Method 2: Fetch from stored URL with retry (works for public buckets)
        if (!markdownContent && report.reportUrl) {
          for (let attempt = 0; attempt < 3; attempt++) {
            try {
              const resp = await fetch(report.reportUrl, { signal: AbortSignal.timeout(30000) });
              if (resp.ok) { markdownContent = await resp.text(); break; }
              if (resp.status === 403) {
                console.warn('[Report/PDF] URL returned 403 (likely expired presigned URL)');
                break; // Don't retry 403s
              }
            } catch (e) {
              if (attempt === 2) console.error('[Report/PDF] Failed to fetch markdown after 3 attempts:', (e as any).message);
              await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
            }
          }
        }
        if (!markdownContent) {
          throw new TRPCError({ code: 'NOT_FOUND', message: 'Report content not available. The stored URL may have expired \u2014 please regenerate the report.' });
        }

        // Convert markdown to HTML using marked
        const { marked } = await import('marked');
        const bodyHtml = await marked.parse(markdownContent, { gfm: true, breaks: true });

        const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

        let assessmentTypeDisplay = 'Security Assessment';
        try {
          const { getReportBlueprint } = await import('../lib/report-section-blueprints');
          const eng = await db.getEngagementById((report as any).engagementId);
          const engType = (eng?.engagementType || (report as any).reportType || 'pentest').toLowerCase().replace(/[\s-]/g, '_');
          assessmentTypeDisplay = getReportBlueprint(engType).displayName;
        } catch { assessmentTypeDisplay = ((report as any).reportType || 'security_assessment').replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase()); }

        // Build clean HTML for PDF conversion (no print script)
        const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>${report.title || 'Security Assessment Report'}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: Helvetica, Arial, sans-serif; color: #1a1a1a; line-height: 1.7; background: #fff; }
  .page { max-width: 850px; margin: 0 auto; padding: 48px 56px; }
  .header { padding-bottom: 28px; margin-bottom: 36px; border-bottom: 1px solid #cccccc; }
  .report-title { font-size: 28px; font-weight: 700; color: #1a1a1a; margin-bottom: 16px; }
  .report-meta { font-size: 12px; color: #666666; line-height: 1.8; }
  .report-meta div { margin-bottom: 2px; }
  .classification-line { font-weight: 700; font-size: 13px; margin-top: 12px; }
  .content h1 { font-size: 22px; font-weight: 700; color: #1a1a1a; margin: 32px 0 16px 0; }
  .content h2 { font-size: 18px; font-weight: 700; color: #1a1a1a; margin: 24px 0 12px 0; }
  .content h3 { font-size: 15px; font-weight: 600; color: #333333; margin: 20px 0 10px 0; }
  .content h4 { font-size: 13px; font-weight: 600; color: #444444; margin: 16px 0 8px 0; }
  .content p { font-size: 13px; margin-bottom: 10px; }
  .content ul, .content ol { font-size: 13px; padding-left: 24px; margin-bottom: 12px; }
  .content li { margin-bottom: 4px; }
  .content table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 12px; }
  .content th { background: #d9d9d9; color: #1a1a1a; padding: 8px 12px; text-align: left; font-weight: 600; font-size: 11px; border: 1px solid #999999; }
  .content td { padding: 8px 12px; border: 1px solid #cccccc; }
  .content blockquote { border-left: 3px solid #999999; padding: 12px 16px; margin: 12px 0; background: #f5f5f5; font-size: 13px; color: #333333; }
  .content code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-size: 12px; color: #333333; }
  .content pre { background: #2a2a2a; color: #e0e0e0; padding: 16px; border-radius: 4px; overflow-x: auto; margin: 12px 0; font-size: 12px; }
  .content pre code { background: none; padding: 0; color: inherit; }
  .content hr { border: none; border-top: 1px solid #cccccc; margin: 24px 0; }
  .content strong { color: #1a1a1a; }
  .footer { border-top: 1px solid #cccccc; padding-top: 16px; margin-top: 40px; font-size: 11px; color: #666666; display: flex; justify-content: space-between; }
</style>
</head>
<body>
<div class="page">
  <div class="header">
    <div class="report-title">${report.title || 'Security Assessment Report'}</div>
    <div class="report-meta">
      <div>Client: ${report.preparedFor || 'Client'}</div>
      <div>Prepared by: ${report.preparedBy || 'Ace of Cloud LLC'}</div>
      <div>Assessment Type: ${assessmentTypeDisplay}</div>
      <div>Report Date: ${dateStr}</div>
    </div>
    <div class="classification-line">CONFIDENTIAL \u2013 Security Assessment Report</div>
  </div>
  <div class="content">${bodyHtml}</div>
  <div class="footer">
    <div>Ace of Cloud LLC \u2014 aceofcloud.com</div>
    <div>CONFIDENTIAL \u2014 ${dateStr}</div>
  </div>
</div>
</body>
</html>`;

        // Generate real PDF using puppeteer-core with system Chromium
        try {
          let pdfBuffer: Buffer;
          // Resolve chromium path: env var > common paths
          const chromiumPath = process.env.PUPPETEER_EXECUTABLE_PATH
            || (await (async () => {
              const { existsSync } = await import('fs');
              for (const p of ['/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome']) {
                if (existsSync(p)) return p;
              }
              return null;
            })());

          if (!chromiumPath) {
            console.error('[Report/PDF] No Chromium binary found — uploading styled HTML instead');
            const htmlKey = `reports/${report.engagementId}/${input.reportId}-report-${Date.now()}.html`;
            const { url } = await doStoragePut(htmlKey, html, 'text/html');
            return { url, filename: `${(report.title || 'report').replace(/[^a-zA-Z0-9]/g, '_')}.html`, format: 'html' };
          }

          try {
            const puppeteer = await import('puppeteer-core');
            const browser = await puppeteer.default.launch({
              executablePath: chromiumPath,
              headless: true,
              args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--disable-software-rasterizer',
                '--single-process',
              ],
            });
            const page = await browser.newPage();
            // Use domcontentloaded for large reports to avoid networkidle0 timeout
            await page.setContent(html, { waitUntil: 'domcontentloaded', timeout: 60000 });
            // Wait a bit for styles to apply
            await new Promise(r => setTimeout(r, 1000));
            const pdfUint8 = await page.pdf({
              format: 'A4',
              printBackground: true,
              margin: { top: '20mm', bottom: '20mm', left: '15mm', right: '15mm' },
              displayHeaderFooter: true,
              headerTemplate: '<div style="font-size:8px;width:100%;text-align:center;color:#999;">CONFIDENTIAL — Security Assessment Report</div>',
              footerTemplate: '<div style="font-size:8px;width:100%;text-align:center;color:#999;">Ace of Cloud LLC — Page <span class="pageNumber"></span> of <span class="totalPages"></span></div>',
              timeout: 120000,
            });
            pdfBuffer = Buffer.from(pdfUint8);
            await browser.close();
          } catch (puppeteerErr: any) {
            console.error('[Report/PDF] Puppeteer PDF generation failed:', puppeteerErr.message);
            // Fallback: upload styled HTML
            const htmlKey = `reports/${report.engagementId}/${input.reportId}-report-${Date.now()}.html`;
            const { url } = await doStoragePut(htmlKey, html, 'text/html');
            return { url, filename: `${(report.title || 'report').replace(/[^a-zA-Z0-9]/g, '_')}.html`, format: 'html' };
          }
          const pdfKey = `reports/${report.engagementId}/${input.reportId}-report-${Date.now()}.pdf`;
          const { url } = await doStoragePut(pdfKey, pdfBuffer, 'application/pdf');
          return { url, filename: `${(report.title || 'report').replace(/[^a-zA-Z0-9]/g, '_')}.pdf`, format: 'pdf' };
        } catch (e: any) {
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Failed to generate PDF: ' + e.message });
        }
      }),

    /** Generate and return a DOCX report from the full markdown pipeline output */
    exportDocx: protectedProcedure
      .input(z.object({ reportId: z.number() }))
      .mutation(async ({ input }) => {
        const report = await db.getReportById(input.reportId);
        if (!report) throw new TRPCError({ code: 'NOT_FOUND', message: 'Report not found' });

        // Fetch the markdown content: prefer S3 SDK (handles presigned URL expiry), fallback to URL fetch
        let markdownContent = '';
        // Method 1: Direct S3 download via reportKey (never expires)
        if (!markdownContent && (report as any).reportKey) {
          try {
            const result = await doStorageGetContent((report as any).reportKey);
            if (result) markdownContent = result.data.toString('utf-8');
          } catch (e) {
            console.warn('[Report/DOCX] S3 direct download failed, trying URL:', (e as any).message);
          }
        }
        // Method 2: Fetch from stored URL with retry (works for public buckets)
        if (!markdownContent && report.reportUrl) {
          for (let attempt = 0; attempt < 3; attempt++) {
            try {
              const resp = await fetch(report.reportUrl, { signal: AbortSignal.timeout(30000) });
              if (resp.ok) { markdownContent = await resp.text(); break; }
              if (resp.status === 403) {
                console.warn('[Report/DOCX] URL returned 403 (likely expired presigned URL)');
                break;
              }
            } catch (e) {
              if (attempt === 2) console.error('[Report/DOCX] Failed to fetch markdown after 3 attempts:', (e as any).message);
              await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
            }
          }
        }
        if (!markdownContent) {
          throw new TRPCError({ code: 'NOT_FOUND', message: 'Report content not available. The stored URL may have expired \u2014 please regenerate the report.' });
        }

        const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

        let assessmentTypeDisplay = 'Penetration Test';
        try {
          const { getReportBlueprint } = await import('../lib/report-section-blueprints');
          const eng = await db.getEngagementById((report as any).engagementId);
          const engType = (eng?.engagementType || (report as any).reportType || 'pentest').toLowerCase().replace(/[\s-]/g, '_');
          assessmentTypeDisplay = getReportBlueprint(engType).displayName;
        } catch {
          assessmentTypeDisplay = ((report as any).reportType || 'penetration_test').replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase());
        }

        // Convert markdown to DOCX using our converter with error handling
        try {
          const { markdownToDocx } = await import('../lib/markdown-to-docx');
          const docxBuffer = await markdownToDocx(markdownContent, {
            title: report.title || 'Security Assessment Report',
            preparedFor: report.preparedFor || 'Client',
            preparedBy: report.preparedBy || 'Ace of Cloud LLC',
            assessmentType: assessmentTypeDisplay,
            reportDate: dateStr,
            reportId: String(input.reportId),
          });

          // Upload to S3
          const docxKey = `reports/${(report as any).engagementId}/${input.reportId}-report-${Date.now()}.docx`;
          const { url } = await doStoragePut(docxKey, docxBuffer, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');

          return { url, filename: `${(report.title || 'report').replace(/[^a-zA-Z0-9]/g, '_')}.docx` };
        } catch (docxErr: any) {
          console.error('[Report/DOCX] DOCX generation failed:', docxErr.message, docxErr.stack?.slice(0, 500));
          throw new TRPCError({
            code: 'INTERNAL_SERVER_ERROR',
            message: `DOCX generation failed: ${docxErr.message}. Report has ${markdownContent.length} chars — if this is a large report, please try again or export as PDF instead.`,
          });
        }
      }),

    /** Get raw markdown content for client-side PDF generation */
    getReportMarkdown: protectedProcedure
      .input(z.object({ reportId: z.number() }))
      .query(async ({ input }) => {
        const report = await db.getReportById(input.reportId);
        if (!report) throw new TRPCError({ code: 'NOT_FOUND', message: 'Report not found' });
        let markdownContent = '';
        // Method 1: Direct S3 download via reportKey (never expires)
        if ((report as any).reportKey) {
          try {
            const result = await doStorageGetContent((report as any).reportKey);
            if (result) markdownContent = result.data.toString('utf-8');
          } catch (e) {
            console.warn('[Report/Markdown] S3 direct download failed:', (e as any).message);
          }
        }
        // Method 2: Fetch from stored URL
        if (!markdownContent && report.reportUrl) {
          try {
            const resp = await fetch(report.reportUrl, { signal: AbortSignal.timeout(30000) });
            if (resp.ok) markdownContent = await resp.text();
          } catch (e) {
            console.warn('[Report/Markdown] URL fetch failed:', (e as any).message);
          }
        }
        if (!markdownContent) {
          throw new TRPCError({ code: 'NOT_FOUND', message: 'Report content not available. Please regenerate the report.' });
        }
        return {
          markdown: markdownContent,
          title: report.title || 'Security Assessment Report',
          preparedFor: (report as any).preparedFor || 'Client',
          preparedBy: (report as any).preparedBy || 'Ace of Cloud LLC',
          reportType: (report as any).reportType || 'pentest_assessment',
          generatedAt: (report as any).generatedAt || new Date().toISOString(),
        };
      }),
  });
export const templateGeneratorRouter = router({
    // Generate phishing email template based on threat actor IOCs and TTPs
    generateFromThreatActor: protectedProcedure
      .input(z.object({
        threatActorId: z.string(),
        threatActorName: z.string(),
        targetOrg: z.string().optional(),
        targetSector: z.string().optional(),
        phishingType: z.enum(['credential_harvest', 'malware_delivery', 'callback_phishing', 'business_email_compromise', 'mfa_fatigue']),
        sophistication: z.enum(['basic', 'intermediate', 'advanced']),
        iocs: z.array(z.object({
          type: z.string(),
          value: z.string(),
          description: z.string(),
        })).optional(),
        techniques: z.array(z.object({
          id: z.string(),
          name: z.string(),
          tactic: z.string(),
        })).optional(),
      }))
      .mutation(async ({ input }) => {
        const { invokeLLM } = await import('../_core/llm');

        const iocContext = input.iocs?.map(ioc => `- ${ioc.type}: ${ioc.value} (${ioc.description})`).join('\n') || 'No specific IOCs provided';
        const ttpContext = input.techniques?.map(t => `- ${t.id} ${t.name} (${t.tactic})`).join('\n') || 'No specific TTPs provided';

        const prompt = `You are a red team phishing template designer. Generate a realistic phishing email template and landing page HTML based on the following threat intelligence:

Threat Actor: ${input.threatActorName}
Target Organization: ${input.targetOrg || 'Generic enterprise'}
Target Sector: ${input.targetSector || 'Technology'}
Phishing Type: ${input.phishingType}
Sophistication Level: ${input.sophistication}

Known IOCs:
${iocContext}

Known TTPs:
${ttpContext}

Generate a JSON response with these exact fields:
{
  "emailTemplate": {
    "name": "Template name including threat actor reference",
    "subject": "Realistic email subject line",
    "senderName": "Realistic sender display name",
    "senderDomain": "Suggested sender domain",
    "html": "Full HTML email body with {{.FirstName}}, {{.URL}} GoPhish variables",
    "text": "Plain text version",
    "pretext": "Brief description of the social engineering angle"
  },
  "landingPage": {
    "name": "Landing page name",
    "html": "Full HTML landing page with credential capture form",
    "redirectUrl": "URL to redirect after credential capture"
  },
  "indicators": {
    "subjectKeywords": ["list of suspicious keywords in subject"],
    "bodyRedFlags": ["list of red flags users should spot"],
    "technicalIndicators": ["list of technical indicators"]
  },
  "trainingNotes": "Brief notes for security awareness training about this phishing type"
}

Make the email realistic and based on actual ${input.threatActorName} phishing campaigns. Include proper HTML formatting, logos, and branding that matches the phishing type. The landing page should capture credentials realistically. Use GoPhish template variables: {{.FirstName}}, {{.LastName}}, {{.Email}}, {{.URL}}, {{.TrackingURL}}, {{.From}}.`;

        try {
          const response = await invokeLLM({ _caller: "reports-core", _priority: 'bulk',
            messages: [
              { role: 'system', content: 'You are an expert red team phishing template designer. Always respond with valid JSON only, no markdown code blocks.' },
              { role: 'user', content: prompt },
            ],
            response_format: {
              type: 'json_schema',
              json_schema: {
                name: 'phishing_template',
                strict: true,
                schema: {
                  type: 'object',
                  properties: {
                    emailTemplate: {
                      type: 'object',
                      properties: {
                        name: { type: 'string' },
                        subject: { type: 'string' },
                        senderName: { type: 'string' },
                        senderDomain: { type: 'string' },
                        html: { type: 'string' },
                        text: { type: 'string' },
                        pretext: { type: 'string' },
                      },
                      required: ['name', 'subject', 'senderName', 'senderDomain', 'html', 'text', 'pretext'],
                      additionalProperties: false,
                    },
                    landingPage: {
                      type: 'object',
                      properties: {
                        name: { type: 'string' },
                        html: { type: 'string' },
                        redirectUrl: { type: 'string' },
                      },
                      required: ['name', 'html', 'redirectUrl'],
                      additionalProperties: false,
                    },
                    indicators: {
                      type: 'object',
                      properties: {
                        subjectKeywords: { type: 'array', items: { type: 'string' } },
                        bodyRedFlags: { type: 'array', items: { type: 'string' } },
                        technicalIndicators: { type: 'array', items: { type: 'string' } },
                      },
                      required: ['subjectKeywords', 'bodyRedFlags', 'technicalIndicators'],
                      additionalProperties: false,
                    },
                    trainingNotes: { type: 'string' },
                  },
                  required: ['emailTemplate', 'landingPage', 'indicators', 'trainingNotes'],
                  additionalProperties: false,
                },
              },
            },
          });

          const content = response.choices?.[0]?.message?.content;
          if (!content) throw new Error('No response from LLM');
          const parsed = JSON.parse(content as string);
          return { success: true, ...parsed };
        } catch (err: any) {
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: `Template generation failed: ${err.message}` });
        }
      }),

    // Deploy generated template directly to GoPhish
    deployToGophish: protectedProcedure
      .input(z.object({
        template: z.object({
          name: z.string(),
          subject: z.string(),
          html: z.string(),
          text: z.string().optional(),
        }),
        landingPage: z.object({
          name: z.string(),
          html: z.string(),
          capture_credentials: z.boolean().optional(),
          capture_passwords: z.boolean().optional(),
          redirect_url: z.string().optional(),
        }).optional(),
      }))
      .mutation(async ({ input }) => {
        const results: { template?: any; landingPage?: any; errors: string[] } = { errors: [] };

        // Deploy email template
        try {
          const templateResult = await fetchGophishAPI('/api/templates/', 'POST', input.template);
          if (templateResult?.id) {
            results.template = { id: templateResult.id, name: input.template.name, success: true };
          } else {
            results.errors.push('Failed to create email template');
          }
        } catch (err: any) {
          results.errors.push(`Template error: ${err.message}`);
        }

        // Deploy landing page if provided
        if (input.landingPage) {
          try {
            const pageResult = await fetchGophishAPI('/api/pages/', 'POST', {
              ...input.landingPage,
              capture_credentials: input.landingPage.capture_credentials ?? true,
              capture_passwords: input.landingPage.capture_passwords ?? true,
            });
            if (pageResult?.id) {
              results.landingPage = { id: pageResult.id, name: input.landingPage.name, success: true };
            } else {
              results.errors.push('Failed to create landing page');
            }
          } catch (err: any) {
            results.errors.push(`Landing page error: ${err.message}`);
          }
        }

           return results;
      }),
  });
