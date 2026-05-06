/**
 * Engagement Auto-Report Generation
 *
 * Extracted from engagement-orchestrator.ts to reduce complexity (~400 lines).
 * Automatically creates a pentest report at engagement completion:
 *
 * 1. Creates a report record in the database
 * 2. Imports findings from the ops snapshot state (vulnAnalysis + asset vulns + ZAP)
 * 3. Generates LLM-powered narratives with remediation for each finding
 * 4. Generates an executive summary with risk rating
 * 5. Attaches intelligence gaps from the engagement and DI scan
 */

import { randomUUID } from "crypto";
import { invokeLLM } from "../_core/llm";
import { classifyVendor, type RiskResponsibility } from "../../shared/managed-provider-filter";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AutoReportState {
  engagementId: string;
  assets: Array<{
    hostname?: string;
    ip?: string;
    vulns?: Array<{
      title?: string;
      cve?: string;
      severity?: string;
      cvss?: number;
      description?: string;
      source?: string;
      rawEvidence?: string;
      evidenceChain?: string[];
      evidenceDetail?: string;
      corroborationTier?: string;
      tool?: string;
    }>;
    zapFindings?: Array<{
      alert?: string;
      risk?: string;
      url?: string;
      description?: string;
      other?: string;
      solution?: string;
    }>;
    toolResults?: Array<{
      tool: string;
      command?: string;
      findingCount: number;
      outputPreview?: string;
      rawOutput?: string;
    }>;
  }>;
  vulnAnalysis?: Array<{
    title?: string;
    finding?: any;
    analysis?: any;
    attackTechniques?: string[];
    controls?: string[];
  }>;
  stats: {
    vulnsFound: number;
    exploitsAttempted: number;
    exploitsSucceeded: number;
    sessionsOpened: number;
  };
  startedAt?: number;
  completedAt?: number;
  metadata?: Record<string, any>;
}

export interface AutoReportEngagement {
  name: string;
  customerName?: string;
}

export interface AutoReportCallbacks {
  addLog: (entry: { phase: string; type: string; title: string; detail: string; data?: any }) => void;
  broadcastUpdate: (update: { type: string }) => void;
}

export interface AutoReportResult {
  success: boolean;
  reportId?: string;
  findingsCount?: number;
  error?: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function mapSev(sev: string | null | undefined, score?: number): string {
  if (sev) {
    const m: Record<string, string> = { critical: 'critical', high: 'high', medium: 'moderate', low: 'low', info: 'informational' };
    return m[sev] || 'moderate';
  }
  if (score !== undefined) {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'moderate';
    if (score >= 2) return 'low';
    return 'informational';
  }
  return 'moderate';
}

// ─── Main Function ────────────────────────────────────────────────────────────

/**
 * Generate an auto-report from the engagement state.
 * Dynamically imports database dependencies to avoid circular imports.
 */
export async function generateAutoReport(
  state: AutoReportState,
  engagement: AutoReportEngagement,
  callbacks: AutoReportCallbacks
): Promise<AutoReportResult> {
  callbacks.addLog({
    phase: 'completed', type: 'info',
    title: '📝 Auto-Report: Generating pentest report...',
    detail: 'Creating report, importing findings from ops snapshot, generating narratives with remediation recommendations',
  });
  callbacks.broadcastUpdate({ type: 'log_update' });

  const { ac3Reports: reportsTable, ac3ReportFindings: findingsTable } = await import('../../drizzle/schema');
  const { getDbRequired: getDbReq } = await import('../db');
  const { eq: eqOp } = await import('drizzle-orm');
  const reportDb = await getDbReq();

  // 1. Create the report
  const reportId = `rpt-${randomUUID().slice(0, 12)}`;
  const reportName = `${engagement.name} — Auto-Generated Report`;
  const now = Date.now();

  await reportDb.insert(reportsTable).values({
    rptReportId: reportId,
    rptName: reportName,
    rptStatus: 'generating',
    complianceFramework: 'nist_800_53_r5',
    rptClientName: engagement.customerName || null,
    rptSystemName: engagement.name,
    rptAssessmentType: 'penetration_test',
    rptVersion: '1.0',
    rptScopeDomains: state.assets.map((a) => a.hostname).filter(Boolean) as string[],
    rptScopeAssets: state.assets.map((a) => a.hostname || a.ip).filter(Boolean) as string[],
    rptApprovedVectors: [],
    rptOutOfScope: [],
    rptCreatedBy: 'auto-pipeline',
    rptCreatedAt: now,
    rptUpdatedAt: now,
    rptWindowStart: state.startedAt || now,
    rptWindowEnd: state.completedAt || now,
  });

  // 2. Import findings from the ops snapshot state
  const vulnAnalysis = state.vulnAnalysis || [];
  const rptAssets = state.assets || [];
  let importedCount = 0;

  for (const vuln of vulnAnalysis) {
    try {
      const finding = vuln.finding || {};
      const analysis = vuln.analysis || {};
      const severity = mapSev(finding.severity, analysis.riskScore);
      const findingId = `FND-${randomUUID().slice(0, 8).toUpperCase()}`;

      // Build rich evidence array from all available sources
      const evidence: any[] = Array.isArray(finding.evidence) ? [...finding.evidence] : [];
      if (analysis.poc) {
        evidence.push({ type: 'poc', reference: `PoC for ${finding.title || vuln.title}`, description: (typeof analysis.poc === 'string' ? analysis.poc : JSON.stringify(analysis.poc)).slice(0, 500) });
      }
      if (finding.rawOutput) {
        evidence.push({ type: 'scanner_output', reference: `Scanner output: ${finding.tool || 'tool'} on ${finding.asset || ''}`, raw: finding.rawOutput.slice(0, 2000), description: `Tool: ${finding.tool || 'unknown'}. Raw scanner output.` });
      }
      const origVuln = rptAssets.flatMap((a) => a.vulns || []).find((v) =>
        v.title === finding.title && (v.cve === finding.cve || !finding.cve)
      );
      if (origVuln?.rawEvidence) {
        evidence.push({ type: 'raw_evidence', reference: `Raw evidence: ${origVuln.source || origVuln.tool || 'scanner'}`, raw: String(origVuln.rawEvidence).slice(0, 2000), description: `Source: ${origVuln.source || origVuln.tool || 'scanner'}. Corroboration: ${origVuln.corroborationTier || 'unverified'}.` });
      }
      if (origVuln?.evidenceChain?.length) {
        evidence.push({ type: 'evidence_chain', reference: `Evidence chain for ${finding.title || vuln.title}`, description: origVuln.evidenceChain.join(' → ') });
      }
      if (origVuln?.evidenceDetail) {
        evidence.push({ type: 'evidence_detail', reference: `Evidence detail`, description: origVuln.evidenceDetail.slice(0, 1000) });
      }
      if (finding.asset) {
        const matchingAsset = rptAssets.find((a) => (a.hostname || a.ip) === finding.asset);
        if (matchingAsset?.toolResults?.length) {
          const relevantTools = (matchingAsset.toolResults as any[]).filter((tr: any) => tr.findingCount > 0 && tr.outputPreview).slice(0, 2);
          for (const tr of relevantTools) {
            evidence.push({ type: 'tool_output', reference: `${tr.tool} scan on ${finding.asset}`, raw: (tr.rawOutput || tr.outputPreview || '').slice(0, 1500), description: `Command: ${(tr.command || '').slice(0, 200)}. Findings: ${tr.findingCount}.` });
          }
        }
      }
      if (evidence.length === 0 && analysis.technicalAnalysis) {
        evidence.push({ type: 'analysis', reference: `Analysis for ${finding.title || vuln.title}`, description: analysis.technicalAnalysis.slice(0, 1000) });
      }

      // Classify risk ownership based on the asset hostname
      const assetHostname = finding.asset || '';
      const vendorClass = classifyVendor({ hostname: assetHostname });
      const riskOwner: 'customer' | 'vendor' | 'shared' = vendorClass.riskResponsibility === 'vendor_responsibility' ? 'vendor'
        : vendorClass.riskResponsibility === 'shared_responsibility' ? 'shared' : 'customer';

      await reportDb.insert(findingsTable).values({
        rfFindingId: findingId,
        rfReportId: reportId,
        rfTitle: finding.title || vuln.title || 'Untitled Finding',
        rfSeverity: severity as any,
        rfSummary: analysis.technicalAnalysis || finding.description || '',
        rfEvidence: JSON.stringify(evidence),
        rfAssets: JSON.stringify([finding.asset || '']),
        rfAttackTechniques: JSON.stringify(vuln.attackTechniques || []),
        rfControls: JSON.stringify(vuln.controls || []),
        rfNarrativeStatus: 'pending',
        rfSortOrder: importedCount,
        rfRiskOwner: riskOwner,
        rfVendorName: vendorClass.vendor?.name || null,
        rfCreatedAt: now,
        rfUpdatedAt: now,
      });
      importedCount++;
    } catch (fErr: any) {
      console.warn(`[AutoReport] Failed to import finding: ${fErr.message}`);
    }
  }

  // Also import from asset vulns if vulnAnalysis is empty
  if (importedCount === 0) {
    for (const rptAsset of rptAssets) {
      for (const v of (rptAsset.vulns || [])) {
        try {
          const findingId = `FND-${randomUUID().slice(0, 8).toUpperCase()}`;
          // Classify risk ownership for this asset
          const assetHost = rptAsset.hostname || rptAsset.ip || '';
          const vc = classifyVendor({ hostname: assetHost });
          const owner: 'customer' | 'vendor' | 'shared' = vc.riskResponsibility === 'vendor_responsibility' ? 'vendor'
            : vc.riskResponsibility === 'shared_responsibility' ? 'shared' : 'customer';

          await reportDb.insert(findingsTable).values({
            rfFindingId: findingId,
            rfReportId: reportId,
            rfTitle: v.title || v.cve || 'Untitled Vulnerability',
            rfSeverity: mapSev(v.severity, v.cvss) as any,
            rfSummary: v.description || `${v.title} found on ${rptAsset.hostname}`,
            rfEvidence: JSON.stringify([
              { type: 'raw_evidence', reference: `${v.source || 'scanner'} on ${rptAsset.hostname || rptAsset.ip}`, raw: v.rawEvidence ? String(v.rawEvidence).slice(0, 2000) : undefined, description: v.description || v.title },
              ...(v.evidenceChain?.length ? [{ type: 'evidence_chain', reference: `Evidence chain`, description: v.evidenceChain.join(' → ') }] : []),
              ...(v.evidenceDetail ? [{ type: 'evidence_detail', reference: `Evidence detail`, description: v.evidenceDetail.slice(0, 1000) }] : []),
            ].filter((e: any) => e.description || e.raw)),
            rfAssets: JSON.stringify([rptAsset.hostname || rptAsset.ip]),
            rfAttackTechniques: JSON.stringify([]),
            rfControls: JSON.stringify([]),
            rfNarrativeStatus: 'pending',
            rfSortOrder: importedCount,
            rfRiskOwner: owner,
            rfVendorName: vc.vendor?.name || null,
            rfCreatedAt: now,
            rfUpdatedAt: now,
          });
          importedCount++;
        } catch (fErr: any) {
          console.warn(`[AutoReport] Failed to import vuln: ${fErr.message}`);
        }
      }
      for (const zf of (rptAsset.zapFindings || [])) {
        try {
          const findingId = `FND-${randomUUID().slice(0, 8).toUpperCase()}`;
          // ZAP findings inherit the asset's vendor classification
          await reportDb.insert(findingsTable).values({
            rfFindingId: findingId,
            rfReportId: reportId,
            rfTitle: zf.alert || 'ZAP Finding',
            rfSeverity: mapSev(zf.risk, undefined) as any,
            rfSummary: zf.description || zf.alert || '',
            rfEvidence: JSON.stringify([{ tool: 'zap', url: zf.url, output: zf.other || zf.solution }]),
            rfAssets: JSON.stringify([rptAsset.hostname || rptAsset.ip]),
            rfAttackTechniques: JSON.stringify([]),
            rfControls: JSON.stringify([]),
            rfNarrativeStatus: 'pending',
            rfSortOrder: importedCount,
            rfRiskOwner: owner,
            rfVendorName: vc.vendor?.name || null,
            rfCreatedAt: now,
            rfUpdatedAt: now,
          });
          importedCount++;
        } catch (fErr: any) {
          console.warn(`[AutoReport] Failed to import ZAP finding: ${fErr.message}`);
        }
      }
    }
  }

  callbacks.addLog({
    phase: 'completed', type: 'info',
    title: `📝 Auto-Report: Imported ${importedCount} findings`,
    detail: `Report ${reportId} created with ${importedCount} findings from ${vulnAnalysis.length} vuln analyses and ${rptAssets.length} assets`,
  });
  callbacks.broadcastUpdate({ type: 'log_update' });

  // 3. Generate narratives with remediation recommendations for each finding
  if (importedCount > 0) {
    const pendingFindings = await reportDb.select().from(findingsTable)
      .where(eqOp(findingsTable.rfReportId, reportId));

    let narrativesGenerated = 0;
    for (const f of pendingFindings) {
      try {
        const narrativeResp = await invokeLLM({
          _caller: 'auto-report.generateNarrative',
          messages: [
            {
              role: 'system',
              content: 'You are a senior penetration tester writing a professional security assessment report following NIST 800-53 Rev 5 standards. Write clear, actionable findings with specific remediation steps. Do not include customer-specific identifiable information in the template — keep it generalizable.',
            },
            {
              role: 'user',
              content: `Generate a professional finding narrative for this vulnerability:\n\nTitle: ${f.rfTitle}\nSeverity: ${f.rfSeverity}\nSummary: ${f.rfSummary || 'N/A'}\nAssets: ${f.rfAssets || 'N/A'}\nEvidence: ${typeof f.rfEvidence === 'string' ? (f.rfEvidence as string).slice(0, 500) : JSON.stringify(f.rfEvidence).slice(0, 500)}\n\nProvide:\n1. A clear, professional title\n2. A concise summary (2-3 sentences)\n3. Business impact assessment\n4. Technical details of the vulnerability\n5. Specific, actionable remediation steps with priority`,
            },
          ],
          response_format: {
            type: 'json_schema',
            json_schema: {
              name: 'finding_narrative',
              strict: true,
              schema: {
                type: 'object',
                properties: {
                  title: { type: 'string' },
                  summary: { type: 'string' },
                  business_impact: { type: 'string' },
                  technical_details: { type: 'string' },
                  remediation: { type: 'string' },
                },
                required: ['title', 'summary', 'business_impact', 'technical_details', 'remediation'],
                additionalProperties: false,
              },
            },
          },
        });

        const content = narrativeResp.choices?.[0]?.message?.content;
        if (content && typeof content === 'string') {
          const narrative = JSON.parse(content);
          await reportDb.update(findingsTable).set({
            rfTitle: narrative.title,
            rfSummary: narrative.summary,
            rfBusinessImpact: narrative.business_impact,
            rfTechnicalDetails: narrative.technical_details,
            rfRemediation: narrative.remediation,
            rfNarrativeStatus: 'drafted',
            rfUpdatedAt: Date.now(),
          }).where(eqOp(findingsTable.rfFindingId, f.rfFindingId));
          narrativesGenerated++;
        }
      } catch (nErr: any) {
        console.warn(`[AutoReport] Narrative generation failed for ${f.rfFindingId}: ${nErr.message}`);
      }
    }

    callbacks.addLog({
      phase: 'completed', type: 'info',
      title: `📝 Auto-Report: Generated ${narrativesGenerated}/${importedCount} narratives with remediation`,
      detail: 'Each finding now includes business impact, technical details, and specific remediation steps',
    });
    callbacks.broadcastUpdate({ type: 'log_update' });
  }

  // 4. Generate executive summary
  if (importedCount > 0) {
    try {
      const allRptFindings = await reportDb.select().from(findingsTable)
        .where(eqOp(findingsTable.rfReportId, reportId));
      const [reportRow] = await reportDb.select().from(reportsTable)
        .where(eqOp(reportsTable.rptReportId, reportId));

      const sevCounts: Record<string, number> = {};
      const ownerCounts: Record<string, number> = { customer: 0, vendor: 0, shared: 0 };
      for (const f of allRptFindings) {
        sevCounts[f.rfSeverity || 'moderate'] = (sevCounts[f.rfSeverity || 'moderate'] || 0) + 1;
        ownerCounts[f.rfRiskOwner || 'customer'] = (ownerCounts[f.rfRiskOwner || 'customer'] || 0) + 1;
      }

      const execResp = await invokeLLM({
        _caller: 'auto-report.generateExecSummary',
        messages: [
          {
            role: 'system',
            content: 'You are a senior penetration tester writing an executive summary for a security assessment report. Be concise, professional, and actionable. Clearly distinguish between findings that are the customer\'s responsibility vs. those attributed to third-party vendors. Do not include customer-specific identifiable information.',
          },
          {
            role: 'user',
            content: `Generate an executive summary for this penetration test report:\n\nAssessment: ${reportRow?.rptName || engagement.name}\nTarget: ${state.assets.map((a) => a.hostname).join(', ')}\nFindings: ${allRptFindings.length} total (${sevCounts.critical || 0} critical, ${sevCounts.high || 0} high, ${sevCounts.moderate || 0} moderate, ${sevCounts.low || 0} low, ${sevCounts.informational || 0} informational)\nRisk Ownership: ${ownerCounts.customer} customer-owned, ${ownerCounts.vendor} vendor-managed, ${ownerCounts.shared} shared responsibility\nExploits: ${state.stats.exploitsSucceeded}/${state.stats.exploitsAttempted} successful\nSessions: ${state.stats.sessionsOpened} opened\n\nTop findings:\n${allRptFindings.slice(0, 10).map((f: any) => `- [${f.rfSeverity}] [${f.rfRiskOwner || 'customer'}] ${f.rfTitle}`).join('\n')}\n\nProvide:\n1. Risk statement (clearly separate customer vs vendor risk)\n2. Overall risk rating (critical/high/moderate/low) — based on CUSTOMER-owned findings only\n3. Key strengths observed\n4. Key gaps identified\n5. Executive narrative (2-3 paragraphs, noting vendor dependency risks separately)`,
          },
        ],
        response_format: {
          type: 'json_schema',
          json_schema: {
            name: 'executive_summary',
            strict: true,
            schema: {
              type: 'object',
              properties: {
                risk_statement: { type: 'string' },
                overall_rating: { type: 'string' },
                key_strengths: { type: 'array', items: { type: 'string' } },
                key_gaps: { type: 'array', items: { type: 'string' } },
                narrative: { type: 'string' },
              },
              required: ['risk_statement', 'overall_rating', 'key_strengths', 'key_gaps', 'narrative'],
              additionalProperties: false,
            },
          },
        },
      });

      const execContent = execResp.choices?.[0]?.message?.content;
      if (execContent && typeof execContent === 'string') {
        const summary = JSON.parse(execContent);
        const validRatings = ['critical', 'high', 'moderate', 'low', 'informational'];
        const normalizedRating = validRatings.includes(summary.overall_rating?.toLowerCase())
          ? summary.overall_rating.toLowerCase()
          : 'moderate';

        await reportDb.update(reportsTable).set({
          rptExecRiskStatement: summary.risk_statement,
          rptExecRating: normalizedRating as any,
          rptExecStrengths: summary.key_strengths,
          rptExecGaps: summary.key_gaps,
          rptExecNarrative: summary.narrative,
          rptStatus: 'draft',
          rptUpdatedAt: Date.now(),
        }).where(eqOp(reportsTable.rptReportId, reportId));

        callbacks.addLog({
          phase: 'completed', type: 'info',
          title: `📝 Auto-Report: Executive summary generated — Overall Risk: ${normalizedRating.toUpperCase()}`,
          detail: summary.risk_statement.slice(0, 200),
        });
      }
    } catch (execErr: any) {
      console.warn(`[AutoReport] Exec summary generation failed: ${execErr.message}`);
    }
  }

  // Store report ID in state metadata for UI access
  if (!state.metadata) state.metadata = {} as any;
  state.metadata!.autoReportId = reportId;
  state.metadata!.autoReportFindings = importedCount;

  // 5. Attach intelligence gaps to the report
  let gapsSummary = '';
  try {
    const { listGaps, formatGapsForReport } = await import('./intelligence-gaps');
    const engGaps = state.engagementId
      ? await listGaps({ engagementId: state.engagementId as any, limit: 500 })
      : [];
    const scanId = state.metadata?.diScanId;
    const scanGaps = scanId
      ? await listGaps({ scanId, limit: 500 })
      : [];
    const seen = new Set<string>();
    const allGaps = [];
    for (const g of [...engGaps, ...scanGaps]) {
      const key = `${g.category}:${g.title}`;
      if (!seen.has(key)) { seen.add(key); allGaps.push(g); }
    }
    if (allGaps.length > 0) {
      const gapReport = formatGapsForReport(allGaps);
      await reportDb.update(reportsTable).set({
        rptIntelligenceGaps: gapReport,
        rptUpdatedAt: Date.now(),
      }).where(eqOp(reportsTable.rptReportId, reportId));
      gapsSummary = ` Intelligence gaps: ${allGaps.length} (${gapReport.totalOpen} open).`;
      callbacks.addLog({
        phase: 'completed', type: 'info',
        title: `🔍 Intelligence Gaps: ${allGaps.length} gaps attached to report`,
        detail: gapReport.summary,
      });
    }
  } catch (gapErr: any) {
    console.warn(`[AutoReport] Intelligence gaps attachment failed (non-fatal): ${gapErr.message}`);
  }

  callbacks.addLog({
    phase: 'completed', type: 'phase_complete',
    title: `📝 Auto-Report Complete: ${reportId}`,
    detail: `Report "${reportName}" created with ${importedCount} findings, narratives with remediation, and executive summary.${gapsSummary} View in Reports tab.`,
    data: { reportId, findingsCount: importedCount },
  });
  callbacks.broadcastUpdate({ type: 'log_update' });

  return { success: true, reportId, findingsCount: importedCount };
}
