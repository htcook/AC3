import { storagePut } from "../storage";
import { fetchGophishAPI } from "../lib/api-helpers";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";
import { ENV } from "../_core/env";
import { invokeLLM } from "../_core/llm";
import { and, desc, eq, min, not } from "drizzle-orm";
import * as schema from "../../drizzle/schema";

export const reportsRouter = router({
    generate: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        reportType: z.enum(['executive_summary', 'technical_detail', 'compliance', 'phishing_results', 'osint_assessment', 'full_engagement', 'purple_team', 'red_team_assessment', 'detection_gap_analysis', 'pentest_assessment']),
        clientType: z.enum(['msp', 'enterprise', 'saas', 'paas', 'iaas', 'mixed_hosting', 'other']).default('enterprise'),
        title: z.string().min(1),
        preparedFor: z.string().optional(),
        preparedBy: z.string().optional(),
        includeSections: z.array(z.string()).optional(),
        brandingColor: z.string().optional(),
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
        const engagement = await db.getEngagementById(input.engagementId);
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

        // Fetch Caldera operation results
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
          }
        } catch (e) { console.error('ROE/audit fetch for report failed:', e); }

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
        if (input.reportType === 'pentest_assessment') {
          try {
            const { runPentestReportPipeline } = await import('../lib/pentest-report-pipeline');
            const { getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
            const opsState = await getOpsStateWithRecovery(input.engagementId);

            // Map ops state assets to pipeline format
            let pipelineAssets = (opsState?.assets || []).map((a: any) => ({
              hostname: a.hostname || 'unknown',
              ip: a.ip || '',
              status: a.status || 'unknown',
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
              })),
              toolResults: (a.toolResults || []).map((tr: any) => ({
                tool: tr.tool || 'unknown',
                command: tr.command,
                exitCode: tr.exitCode,
                duration: tr.duration,
                findings: tr.findings || [],
                rawOutput: tr.rawOutput,
              })),
              exploitAttempts: (a.exploitAttempts || []).map((ea: any) => ({
                module: ea.module || 'unknown',
                success: !!ea.success,
                cve: ea.cve,
                service: ea.service,
                port: ea.port,
                confidence: ea.confidence,
                reasoning: ea.reasoning,
                timestamp: ea.timestamp,
                error: ea.error,
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
            });

            // Store as S3 file
            try {
              const { storagePut } = await import('../storage');
              const reportKey = `reports/${input.engagementId}/${reportId}-pentest-${Date.now()}.md`;
              const { url } = await storagePut(reportKey, pipelineResult.markdown, 'text/markdown');

              await db.updateReport(reportId, {
                status: 'completed',
                reportUrl: url,
                reportKey,
                generatedAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
              });

              return { id: reportId, url, content: pipelineResult.markdown };
            } catch (storageErr) {
              await db.updateReport(reportId, {
                status: 'completed',
                generatedAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
              });
              return { id: reportId, url: null, content: pipelineResult.markdown };
            }
          } catch (err: any) {
            console.error('Pentest pipeline failed:', err);
            await db.updateReport(reportId, { status: 'failed' });
            throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Pentest report pipeline failed: ' + err.message });
          }
        }

        // ─── Legacy single-prompt report generation ───
        const { invokeLLM } = await import('../_core/llm');

        const clientTypeLabels: Record<string, string> = {
          msp: 'Managed Service Provider (MSP)',
          enterprise: 'Enterprise Organization',
          saas: 'SaaS Provider',
          paas: 'PaaS Provider',
          iaas: 'IaaS Provider',
          mixed_hosting: 'Mixed Hosting Provider',
          other: 'Organization',
        };

        const sectionPrompts: Record<string, string> = {
          executive_summary: 'Write a concise executive summary suitable for C-level stakeholders. Focus on business risk, key findings, and recommended actions.',
          technical_detail: 'Write a detailed technical report covering all findings, attack paths, vulnerabilities, and remediation steps with specific technical guidance.',
          compliance: 'Write a compliance-focused report mapping findings to relevant frameworks (NIST CSF, ISO 27001, SOC 2, HIPAA, PCI DSS). Include gap analysis.',
          phishing_results: 'Write a phishing campaign results report with click rates, credential capture rates, user behavior analysis, and awareness training recommendations.',
          osint_assessment: 'Write an OSINT assessment report covering domain security posture, email authentication, typosquat risks, and external attack surface findings.',
          full_engagement: 'Write a comprehensive engagement report covering all aspects: executive summary, OSINT findings, phishing results, technical findings, and recommendations.',
          purple_team: 'Write a Purple Team exercise report covering adversary emulation results, detection coverage analysis, technique-by-technique breakdown of what was detected vs missed, SOC performance metrics, and specific detection engineering recommendations. Include a MITRE ATT&CK heatmap summary.',
          red_team_assessment: 'Write a Red Team assessment report covering attack paths, initial access methods, lateral movement, privilege escalation, persistence mechanisms, and data exfiltration attempts. Include a kill chain analysis and specific remediation steps for each finding.',
          detection_gap_analysis: 'Write a Detection Gap Analysis report that maps every tested MITRE ATT&CK technique to its detection status (detected/partially detected/missed). Include specific Sigma rules, YARA rules, and SIEM queries that should be implemented to close each gap. Prioritize gaps by risk severity.',
        };

        const reportPrompt = sectionPrompts[input.reportType] || sectionPrompts.full_engagement;

        try {
          const response = await invokeLLM({ _priority: 'bulk',
            messages: [
              {
                role: 'system',
                content: `You are a senior cybersecurity consultant at Ace of Cloud LLC generating a professional ${input.reportType.replace(/_/g, ' ')} report for a ${clientTypeLabels[input.clientType] || 'client'} using the Ace C3 (Cyber Campaign Command) platform. Use formal, professional language. Include specific data points from the provided engagement data including Domain Intelligence scan results, matched threat actors, Caldera adversary emulation results, and TTP knowledge base insights. Format the report in Markdown with clear sections, tables where appropriate, and actionable recommendations. Include a Detection Gap Analysis section mapping successful vs blocked techniques to MITRE ATT&CK. Include a Risk Matrix table. The report should be thorough, data-driven, and actionable. Do NOT include customer-identifiable information in template sections - only in the final report header. Brand the report as produced by Ace of Cloud LLC (aceofcloud.com).`,
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
  return JSON.stringify({
    domain: s.domain,
    riskScore: r?.riskScore,
    assetsDiscovered: r?.assets?.length || 0,
    postureFindings: r?.posture?.length || 0,
    campaignRecommendations: (r?.campaigns || []).map((c: any) => ({ name: c.name, priority: c.priority })),
  });
}).join('\n')}

Matched Threat Actors (${threatActorMatches.length} actors targeting this organization):
${threatActorMatches.slice(0, 10).map((a: any) => "- " + a.name + " (" + a.origin + ") - Score: " + a.matchScore + "/100 - Techniques: " + (a.techniques?.length || 0)).join('\n')}

Caldera Operation Results (${calderaOpsData.length} operations):
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

IMPORTANT: You MUST include a "Discovery & Reconnaissance" section that covers all asset discovery results, port/service findings from naabu/nmap/httpx, passive recon data, and technology stack analysis. Include a per-asset summary table with ports, services, technologies, and risk signals.

IMPORTANT: You MUST include a "Tool Execution Evidence" section that documents all security tools executed, their commands, exit codes, and key findings. This provides the forensic evidence chain.

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
            const { storagePut } = await import('../storage');
            const reportKey = `reports/${input.engagementId}/${reportId}-${Date.now()}.md`;
            const { url } = await storagePut(reportKey, reportContent, 'text/markdown');

            await db.updateReport(reportId, {
              status: 'completed',
              reportUrl: url,
              reportKey,
              generatedAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
            });

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
        const BRAND_LOGO_URL = 'https://d2xsxph8kpxj0f.cloudfront.net/310419663028432609/VmWWcXQYZJYuALRdNNvsC2/ace_of_cloud_logo_8934407a.jpeg';
        const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

        const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>${report.title || 'Pentest Assessment Report'}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; color: #1e293b; line-height: 1.7; background: #fff; }
  .page { max-width: 900px; margin: 0 auto; padding: 40px 48px; }
  .header { border-bottom: 3px solid #14b8a6; padding-bottom: 24px; margin-bottom: 32px; }
  .header-top { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; }
  .brand { display: flex; align-items: center; gap: 12px; }
  .brand-logo { width: 48px; height: 48px; border-radius: 8px; overflow: hidden; }
  .brand-logo img { width: 100%; height: 100%; object-fit: contain; }
  .brand-name { font-size: 20px; font-weight: 700; color: #213555; }
  .brand-sub { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; }
  .classification { background: #213555; color: #fff; padding: 4px 12px; border-radius: 4px; font-size: 10px; font-weight: 600; letter-spacing: 1px; text-transform: uppercase; }
  .report-title { font-size: 26px; font-weight: 700; color: #213555; margin-bottom: 4px; }
  .report-meta { display: flex; gap: 24px; margin-top: 8px; font-size: 12px; color: #64748b; }
  .content h1 { font-size: 22px; font-weight: 700; color: #213555; border-left: 4px solid #14b8a6; padding-left: 12px; margin: 32px 0 16px 0; }
  .content h2 { font-size: 18px; font-weight: 700; color: #213555; margin: 24px 0 12px 0; }
  .content h3 { font-size: 15px; font-weight: 600; color: #334155; margin: 20px 0 10px 0; }
  .content h4 { font-size: 13px; font-weight: 600; color: #475569; margin: 16px 0 8px 0; }
  .content p { font-size: 13px; margin-bottom: 10px; }
  .content ul, .content ol { font-size: 13px; padding-left: 24px; margin-bottom: 12px; }
  .content li { margin-bottom: 4px; }
  .content table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 12px; }
  .content th { background: #213555; color: #fff; padding: 8px 12px; text-align: left; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
  .content td { padding: 8px 12px; border-bottom: 1px solid #e2e8f0; }
  .content tr:nth-child(even) { background: #f8fafc; }
  .content blockquote { border-left: 4px solid #14b8a6; padding: 12px 16px; margin: 12px 0; background: #f0fdfa; font-size: 13px; color: #0f766e; }
  .content code { background: #f1f5f9; padding: 2px 6px; border-radius: 3px; font-size: 12px; color: #334155; }
  .content pre { background: #1e293b; color: #e2e8f0; padding: 16px; border-radius: 8px; overflow-x: auto; margin: 12px 0; font-size: 12px; }
  .content pre code { background: none; padding: 0; color: inherit; }
  .content hr { border: none; border-top: 2px solid #e2e8f0; margin: 24px 0; }
  .content strong { color: #1e293b; }
  .footer { border-top: 2px solid #e2e8f0; padding-top: 16px; margin-top: 40px; font-size: 11px; color: #64748b; display: flex; justify-content: space-between; }
  @media print {
    .page { padding: 20px; max-width: 100%; }
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
    <div class="header-top">
      <div class="brand">
        <div class="brand-logo"><img src="${BRAND_LOGO_URL}" alt="Ace of Cloud" /></div>
        <div>
          <div class="brand-name">Ace of Cloud</div>
          <div class="brand-sub">Ace C3 — Cyber Campaign Command</div>
        </div>
      </div>
      <div class="classification">CONFIDENTIAL</div>
    </div>
    <div class="report-title">${report.title || 'Penetration Test Assessment Report'}</div>
    <div class="report-meta">
      <span>Prepared for: ${report.preparedFor || 'Client'}</span>
      <span>Prepared by: ${report.preparedBy || 'Ace of Cloud LLC'}</span>
      <span>Date: ${dateStr}</span>
    </div>
  </div>
  <div class="content">${bodyHtml}</div>
  <div class="footer">
    <div>Ace of Cloud LLC — Ace C3 Platform | aceofcloud.com</div>
    <div>CONFIDENTIAL — ${dateStr}</div>
  </div>
</div>
<script class="no-print">
  // Auto-trigger print dialog for PDF export
  // window.print();
</script>
</body>
</html>`;

        // Store the HTML version to S3
        try {
          const { storagePut } = await import('../storage');
          const htmlKey = `reports/${report.engagementId}/${input.reportId}-branded-${Date.now()}.html`;
          const { url } = await storagePut(htmlKey, html, 'text/html');
          return { html, url };
        } catch (e) {
          return { html, url: null };
        }
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
          const response = await invokeLLM({ _priority: 'bulk',
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
