import {
  init_managed_provider_filter
} from "./chunk-T6LEVQYF.js";
import {
  classifyVendor
} from "./chunk-E64FO4YW.js";
import {
  init_llm,
  invokeLLM
} from "./chunk-NS7EEW5R.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-NRYVRXXR.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/engagement-auto-report.ts
import { randomUUID } from "crypto";
function mapSev(sev, score) {
  if (sev) {
    const m = { critical: "critical", high: "high", medium: "moderate", low: "low", info: "informational" };
    return m[sev] || "moderate";
  }
  if (score !== void 0) {
    if (score >= 9) return "critical";
    if (score >= 7) return "high";
    if (score >= 4) return "moderate";
    if (score >= 2) return "low";
    return "informational";
  }
  return "moderate";
}
async function generateAutoReport(state, engagement, callbacks) {
  callbacks.addLog({
    phase: "completed",
    type: "info",
    title: "\u{1F4DD} Auto-Report: Generating pentest report...",
    detail: "Creating report, importing findings from ops snapshot, generating narratives with remediation recommendations"
  });
  callbacks.broadcastUpdate({ type: "log_update" });
  const { ac3Reports: reportsTable, ac3ReportFindings: findingsTable } = await import("./schema-AEHUE7AH.js");
  const { getDbRequired: getDbReq } = await import("./db-EEYUM2OC.js");
  const { eq: eqOp } = await import("drizzle-orm");
  const reportDb = await getDbReq();
  const reportId = `rpt-${randomUUID().slice(0, 12)}`;
  const reportName = `${engagement.name} \u2014 Auto-Generated Report`;
  const now = Date.now();
  await reportDb.insert(reportsTable).values({
    rptReportId: reportId,
    rptName: reportName,
    rptStatus: "generating",
    complianceFramework: "nist_800_53_r5",
    rptClientName: engagement.customerName || null,
    rptSystemName: engagement.name,
    rptAssessmentType: "penetration_test",
    rptVersion: "1.0",
    rptScopeDomains: state.assets.map((a) => a.hostname).filter(Boolean),
    rptScopeAssets: state.assets.map((a) => a.hostname || a.ip).filter(Boolean),
    rptApprovedVectors: [],
    rptOutOfScope: [],
    rptCreatedBy: "auto-pipeline",
    rptCreatedAt: now,
    rptUpdatedAt: now,
    rptWindowStart: state.startedAt || now,
    rptWindowEnd: state.completedAt || now
  });
  const vulnAnalysis = state.vulnAnalysis || [];
  const rptAssets = state.assets || [];
  let importedCount = 0;
  for (const vuln of vulnAnalysis) {
    try {
      const finding = vuln.finding || {};
      const analysis = vuln.analysis || {};
      const severity = mapSev(finding.severity, analysis.riskScore);
      const findingId = `FND-${randomUUID().slice(0, 8).toUpperCase()}`;
      const evidence = Array.isArray(finding.evidence) ? [...finding.evidence] : [];
      if (analysis.poc) {
        evidence.push({ type: "poc", reference: `PoC for ${finding.title || vuln.title}`, description: (typeof analysis.poc === "string" ? analysis.poc : JSON.stringify(analysis.poc)).slice(0, 500) });
      }
      if (finding.rawOutput) {
        evidence.push({ type: "scanner_output", reference: `Scanner output: ${finding.tool || "tool"} on ${finding.asset || ""}`, raw: finding.rawOutput.slice(0, 2e3), description: `Tool: ${finding.tool || "unknown"}. Raw scanner output.` });
      }
      const origVuln = rptAssets.flatMap((a) => a.vulns || []).find(
        (v) => v.title === finding.title && (v.cve === finding.cve || !finding.cve)
      );
      if (origVuln?.rawEvidence) {
        evidence.push({ type: "raw_evidence", reference: `Raw evidence: ${origVuln.source || origVuln.tool || "scanner"}`, raw: String(origVuln.rawEvidence).slice(0, 2e3), description: `Source: ${origVuln.source || origVuln.tool || "scanner"}. Corroboration: ${origVuln.corroborationTier || "unverified"}.` });
      }
      if (origVuln?.evidenceChain?.length) {
        evidence.push({ type: "evidence_chain", reference: `Evidence chain for ${finding.title || vuln.title}`, description: origVuln.evidenceChain.join(" \u2192 ") });
      }
      if (origVuln?.evidenceDetail) {
        evidence.push({ type: "evidence_detail", reference: `Evidence detail`, description: origVuln.evidenceDetail.slice(0, 1e3) });
      }
      if (finding.asset) {
        const matchingAsset = rptAssets.find((a) => (a.hostname || a.ip) === finding.asset);
        if (matchingAsset?.toolResults?.length) {
          const relevantTools = matchingAsset.toolResults.filter((tr) => tr.findingCount > 0 && tr.outputPreview).slice(0, 2);
          for (const tr of relevantTools) {
            evidence.push({ type: "tool_output", reference: `${tr.tool} scan on ${finding.asset}`, raw: (tr.rawOutput || tr.outputPreview || "").slice(0, 1500), description: `Command: ${(tr.command || "").slice(0, 200)}. Findings: ${tr.findingCount}.` });
          }
        }
      }
      if (evidence.length === 0 && analysis.technicalAnalysis) {
        evidence.push({ type: "analysis", reference: `Analysis for ${finding.title || vuln.title}`, description: analysis.technicalAnalysis.slice(0, 1e3) });
      }
      const assetHostname = finding.asset || "";
      const vendorClass = classifyVendor({ hostname: assetHostname });
      const riskOwner = vendorClass.riskResponsibility === "vendor_responsibility" ? "vendor" : vendorClass.riskResponsibility === "shared_responsibility" ? "shared" : "customer";
      await reportDb.insert(findingsTable).values({
        rfFindingId: findingId,
        rfReportId: reportId,
        rfTitle: finding.title || vuln.title || "Untitled Finding",
        rfSeverity: severity,
        rfSummary: analysis.technicalAnalysis || finding.description || "",
        rfEvidence: JSON.stringify(evidence),
        rfAssets: JSON.stringify([finding.asset || ""]),
        rfAttackTechniques: JSON.stringify(vuln.attackTechniques || []),
        rfControls: JSON.stringify(vuln.controls || []),
        rfNarrativeStatus: "pending",
        rfSortOrder: importedCount,
        rfRiskOwner: riskOwner,
        rfVendorName: vendorClass.vendor?.name || null,
        rfCreatedAt: now,
        rfUpdatedAt: now
      });
      importedCount++;
    } catch (fErr) {
      console.warn(`[AutoReport] Failed to import finding: ${fErr.message}`);
    }
  }
  if (importedCount === 0) {
    for (const rptAsset of rptAssets) {
      for (const v of rptAsset.vulns || []) {
        try {
          const findingId = `FND-${randomUUID().slice(0, 8).toUpperCase()}`;
          const assetHost = rptAsset.hostname || rptAsset.ip || "";
          const vc2 = classifyVendor({ hostname: assetHost });
          const owner2 = vc2.riskResponsibility === "vendor_responsibility" ? "vendor" : vc2.riskResponsibility === "shared_responsibility" ? "shared" : "customer";
          await reportDb.insert(findingsTable).values({
            rfFindingId: findingId,
            rfReportId: reportId,
            rfTitle: v.title || v.cve || "Untitled Vulnerability",
            rfSeverity: mapSev(v.severity, v.cvss),
            rfSummary: v.description || `${v.title} found on ${rptAsset.hostname}`,
            rfEvidence: JSON.stringify([
              { type: "raw_evidence", reference: `${v.source || "scanner"} on ${rptAsset.hostname || rptAsset.ip}`, raw: v.rawEvidence ? String(v.rawEvidence).slice(0, 2e3) : void 0, description: v.description || v.title },
              ...v.evidenceChain?.length ? [{ type: "evidence_chain", reference: `Evidence chain`, description: v.evidenceChain.join(" \u2192 ") }] : [],
              ...v.evidenceDetail ? [{ type: "evidence_detail", reference: `Evidence detail`, description: v.evidenceDetail.slice(0, 1e3) }] : []
            ].filter((e) => e.description || e.raw)),
            rfAssets: JSON.stringify([rptAsset.hostname || rptAsset.ip]),
            rfAttackTechniques: JSON.stringify([]),
            rfControls: JSON.stringify([]),
            rfNarrativeStatus: "pending",
            rfSortOrder: importedCount,
            rfRiskOwner: owner2,
            rfVendorName: vc2.vendor?.name || null,
            rfCreatedAt: now,
            rfUpdatedAt: now
          });
          importedCount++;
        } catch (fErr) {
          console.warn(`[AutoReport] Failed to import vuln: ${fErr.message}`);
        }
      }
      for (const zf of rptAsset.zapFindings || []) {
        try {
          const findingId = `FND-${randomUUID().slice(0, 8).toUpperCase()}`;
          await reportDb.insert(findingsTable).values({
            rfFindingId: findingId,
            rfReportId: reportId,
            rfTitle: zf.alert || "ZAP Finding",
            rfSeverity: mapSev(zf.risk, void 0),
            rfSummary: zf.description || zf.alert || "",
            rfEvidence: JSON.stringify([{ tool: "zap", url: zf.url, output: zf.other || zf.solution }]),
            rfAssets: JSON.stringify([rptAsset.hostname || rptAsset.ip]),
            rfAttackTechniques: JSON.stringify([]),
            rfControls: JSON.stringify([]),
            rfNarrativeStatus: "pending",
            rfSortOrder: importedCount,
            rfRiskOwner: owner,
            rfVendorName: vc.vendor?.name || null,
            rfCreatedAt: now,
            rfUpdatedAt: now
          });
          importedCount++;
        } catch (fErr) {
          console.warn(`[AutoReport] Failed to import ZAP finding: ${fErr.message}`);
        }
      }
    }
  }
  callbacks.addLog({
    phase: "completed",
    type: "info",
    title: `\u{1F4DD} Auto-Report: Imported ${importedCount} findings`,
    detail: `Report ${reportId} created with ${importedCount} findings from ${vulnAnalysis.length} vuln analyses and ${rptAssets.length} assets`
  });
  callbacks.broadcastUpdate({ type: "log_update" });
  if (importedCount > 0) {
    const pendingFindings = await reportDb.select().from(findingsTable).where(eqOp(findingsTable.rfReportId, reportId));
    let narrativesGenerated = 0;
    for (const f of pendingFindings) {
      try {
        const narrativeResp = await invokeLLM({
          _caller: "auto-report.generateNarrative",
          messages: [
            {
              role: "system",
              content: "You are a senior penetration tester writing a professional security assessment report following NIST 800-53 Rev 5 standards. Write clear, actionable findings with specific remediation steps. Do not include customer-specific identifiable information in the template \u2014 keep it generalizable."
            },
            {
              role: "user",
              content: `Generate a professional finding narrative for this vulnerability:

Title: ${f.rfTitle}
Severity: ${f.rfSeverity}
Summary: ${f.rfSummary || "N/A"}
Assets: ${f.rfAssets || "N/A"}
Evidence: ${typeof f.rfEvidence === "string" ? f.rfEvidence.slice(0, 500) : JSON.stringify(f.rfEvidence).slice(0, 500)}

Provide:
1. A clear, professional title
2. A concise summary (2-3 sentences)
3. Business impact assessment
4. Technical details of the vulnerability
5. Specific, actionable remediation steps with priority`
            }
          ],
          response_format: {
            type: "json_schema",
            json_schema: {
              name: "finding_narrative",
              strict: true,
              schema: {
                type: "object",
                properties: {
                  title: { type: "string" },
                  summary: { type: "string" },
                  business_impact: { type: "string" },
                  technical_details: { type: "string" },
                  remediation: { type: "string" }
                },
                required: ["title", "summary", "business_impact", "technical_details", "remediation"],
                additionalProperties: false
              }
            }
          }
        });
        const content = narrativeResp.choices?.[0]?.message?.content;
        if (content && typeof content === "string") {
          const narrative = JSON.parse(content);
          await reportDb.update(findingsTable).set({
            rfTitle: narrative.title,
            rfSummary: narrative.summary,
            rfBusinessImpact: narrative.business_impact,
            rfTechnicalDetails: narrative.technical_details,
            rfRemediation: narrative.remediation,
            rfNarrativeStatus: "drafted",
            rfUpdatedAt: Date.now()
          }).where(eqOp(findingsTable.rfFindingId, f.rfFindingId));
          narrativesGenerated++;
        }
      } catch (nErr) {
        console.warn(`[AutoReport] Narrative generation failed for ${f.rfFindingId}: ${nErr.message}`);
      }
    }
    callbacks.addLog({
      phase: "completed",
      type: "info",
      title: `\u{1F4DD} Auto-Report: Generated ${narrativesGenerated}/${importedCount} narratives with remediation`,
      detail: "Each finding now includes business impact, technical details, and specific remediation steps"
    });
    callbacks.broadcastUpdate({ type: "log_update" });
  }
  if (importedCount > 0) {
    try {
      const allRptFindings = await reportDb.select().from(findingsTable).where(eqOp(findingsTable.rfReportId, reportId));
      const [reportRow] = await reportDb.select().from(reportsTable).where(eqOp(reportsTable.rptReportId, reportId));
      const sevCounts = {};
      const ownerCounts = { customer: 0, vendor: 0, shared: 0 };
      for (const f of allRptFindings) {
        sevCounts[f.rfSeverity || "moderate"] = (sevCounts[f.rfSeverity || "moderate"] || 0) + 1;
        ownerCounts[f.rfRiskOwner || "customer"] = (ownerCounts[f.rfRiskOwner || "customer"] || 0) + 1;
      }
      const execResp = await invokeLLM({
        _caller: "auto-report.generateExecSummary",
        messages: [
          {
            role: "system",
            content: "You are a senior penetration tester writing an executive summary for a security assessment report. Be concise, professional, and actionable. Clearly distinguish between findings that are the customer's responsibility vs. those attributed to third-party vendors. Do not include customer-specific identifiable information."
          },
          {
            role: "user",
            content: `Generate an executive summary for this penetration test report:

Assessment: ${reportRow?.rptName || engagement.name}
Target: ${state.assets.map((a) => a.hostname).join(", ")}
Findings: ${allRptFindings.length} total (${sevCounts.critical || 0} critical, ${sevCounts.high || 0} high, ${sevCounts.moderate || 0} moderate, ${sevCounts.low || 0} low, ${sevCounts.informational || 0} informational)
Risk Ownership: ${ownerCounts.customer} customer-owned, ${ownerCounts.vendor} vendor-managed, ${ownerCounts.shared} shared responsibility
Exploits: ${state.stats.exploitsSucceeded}/${state.stats.exploitsAttempted} successful
Sessions: ${state.stats.sessionsOpened} opened

Top findings:
${allRptFindings.slice(0, 10).map((f) => `- [${f.rfSeverity}] [${f.rfRiskOwner || "customer"}] ${f.rfTitle}`).join("\n")}

Provide:
1. Risk statement (clearly separate customer vs vendor risk)
2. Overall risk rating (critical/high/moderate/low) \u2014 based on CUSTOMER-owned findings only
3. Key strengths observed
4. Key gaps identified
5. Executive narrative (2-3 paragraphs, noting vendor dependency risks separately)`
          }
        ],
        response_format: {
          type: "json_schema",
          json_schema: {
            name: "executive_summary",
            strict: true,
            schema: {
              type: "object",
              properties: {
                risk_statement: { type: "string" },
                overall_rating: { type: "string" },
                key_strengths: { type: "array", items: { type: "string" } },
                key_gaps: { type: "array", items: { type: "string" } },
                narrative: { type: "string" }
              },
              required: ["risk_statement", "overall_rating", "key_strengths", "key_gaps", "narrative"],
              additionalProperties: false
            }
          }
        }
      });
      const execContent = execResp.choices?.[0]?.message?.content;
      if (execContent && typeof execContent === "string") {
        const summary = JSON.parse(execContent);
        const validRatings = ["critical", "high", "moderate", "low", "informational"];
        const normalizedRating = validRatings.includes(summary.overall_rating?.toLowerCase()) ? summary.overall_rating.toLowerCase() : "moderate";
        await reportDb.update(reportsTable).set({
          rptExecRiskStatement: summary.risk_statement,
          rptExecRating: normalizedRating,
          rptExecStrengths: summary.key_strengths,
          rptExecGaps: summary.key_gaps,
          rptExecNarrative: summary.narrative,
          rptStatus: "draft",
          rptUpdatedAt: Date.now()
        }).where(eqOp(reportsTable.rptReportId, reportId));
        callbacks.addLog({
          phase: "completed",
          type: "info",
          title: `\u{1F4DD} Auto-Report: Executive summary generated \u2014 Overall Risk: ${normalizedRating.toUpperCase()}`,
          detail: summary.risk_statement.slice(0, 200)
        });
      }
    } catch (execErr) {
      console.warn(`[AutoReport] Exec summary generation failed: ${execErr.message}`);
    }
  }
  if (!state.metadata) state.metadata = {};
  state.metadata.autoReportId = reportId;
  state.metadata.autoReportFindings = importedCount;
  let gapsSummary = "";
  try {
    const { listGaps, formatGapsForReport } = await import("./intelligence-gaps-TBRUK2YI.js");
    const engGaps = state.engagementId ? await listGaps({ engagementId: state.engagementId, limit: 500 }) : [];
    const scanId = state.metadata?.diScanId;
    const scanGaps = scanId ? await listGaps({ scanId, limit: 500 }) : [];
    const seen = /* @__PURE__ */ new Set();
    const allGaps = [];
    for (const g of [...engGaps, ...scanGaps]) {
      const key = `${g.category}:${g.title}`;
      if (!seen.has(key)) {
        seen.add(key);
        allGaps.push(g);
      }
    }
    if (allGaps.length > 0) {
      const gapReport = formatGapsForReport(allGaps);
      await reportDb.update(reportsTable).set({
        rptIntelligenceGaps: gapReport,
        rptUpdatedAt: Date.now()
      }).where(eqOp(reportsTable.rptReportId, reportId));
      gapsSummary = ` Intelligence gaps: ${allGaps.length} (${gapReport.totalOpen} open).`;
      callbacks.addLog({
        phase: "completed",
        type: "info",
        title: `\u{1F50D} Intelligence Gaps: ${allGaps.length} gaps attached to report`,
        detail: gapReport.summary
      });
    }
  } catch (gapErr) {
    console.warn(`[AutoReport] Intelligence gaps attachment failed (non-fatal): ${gapErr.message}`);
  }
  callbacks.addLog({
    phase: "completed",
    type: "phase_complete",
    title: `\u{1F4DD} Auto-Report Complete: ${reportId}`,
    detail: `Report "${reportName}" created with ${importedCount} findings, narratives with remediation, and executive summary.${gapsSummary} View in Reports tab.`,
    data: { reportId, findingsCount: importedCount }
  });
  callbacks.broadcastUpdate({ type: "log_update" });
  return { success: true, reportId, findingsCount: importedCount };
}
var init_engagement_auto_report = __esm({
  "server/lib/engagement-auto-report.ts"() {
    init_llm();
    init_managed_provider_filter();
  }
});
init_engagement_auto_report();
export {
  generateAutoReport
};
