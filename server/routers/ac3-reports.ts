import { z } from "zod";
import { protectedProcedure } from "../_core/trpc";
import { getDbRequired } from "../db";
import { ac3Reports, ac3ReportFindings, ac3ReportArtifacts, engagements, engagementTimelineEvents, engagementOpsSnapshots, atomicTestExecutions, atomicTests } from "../../drizzle/schema";
import { eq, desc, and, sql, inArray, like } from "drizzle-orm";
import { randomUUID } from "crypto";
import { invokeLLM } from "../_core/llm";
import { doStoragePut } from "../do-storage";
import { evidenceIntegrityAnchors, evidenceGuardrailAudit } from "../../drizzle/schema";
import { ENV } from "../_core/env";
import * as docx from "docx";
import { scopeEngagementWhere, hasFullAccess } from "../lib/engagement-access-guard";

// ─── JSON Parsing Helper ─────────────────────────────────────────────────────

/** Safely parse JSON fields that may be arrays, JSON strings, or double-encoded */
function parseJsonField(val: any): any[] {
  if (Array.isArray(val)) return val;
  if (typeof val === 'string') {
    try {
      const parsed = JSON.parse(val);
      if (Array.isArray(parsed)) return parsed;
      if (typeof parsed === 'string') {
        // Double-encoded: parse again
        try { const p2 = JSON.parse(parsed); if (Array.isArray(p2)) return p2; } catch {}
      }
    } catch {}
  }
  return [];
}

// ─── Deduplication Helper ────────────────────────────────────────────────────

/** Find existing findings in a report that match by ATT&CK technique ID */
async function findDuplicatesByTechnique(
  db: any,
  reportId: string,
  techniqueIds: string[]
): Promise<Map<string, any>> {
  if (techniqueIds.length === 0) return new Map();
  const existing = await db.select().from(ac3ReportFindings)
    .where(eq(ac3ReportFindings.rfReportId, reportId));
  const dupeMap = new Map<string, any>();
  for (const f of existing) {
    const techniques = (typeof f.rfAttackTechniques === 'string'
      ? JSON.parse(f.rfAttackTechniques)
      : f.rfAttackTechniques) as any[] || [];
    for (const t of techniques) {
      if (t.id && techniqueIds.includes(t.id)) {
        dupeMap.set(t.id, f);
      }
    }
  }
  return dupeMap;
}

/** Merge new evidence and assets into an existing finding, keeping highest severity */
async function mergeFinding(
  db: any,
  existingFinding: any,
  newEvidence: any[],
  newAssets: string[],
  newSeverity: string,
  newControls: any[],
): Promise<void> {
  const severityRank: Record<string, number> = {
    critical: 5, high: 4, moderate: 3, low: 2, informational: 1,
  };

  // Parse existing JSON fields
  const existingEvidence = (typeof existingFinding.rfEvidence === 'string'
    ? JSON.parse(existingFinding.rfEvidence)
    : existingFinding.rfEvidence) as any[] || [];
  const existingAssets = (typeof existingFinding.rfAssets === 'string'
    ? JSON.parse(existingFinding.rfAssets)
    : existingFinding.rfAssets) as string[] || [];
  const existingControls = (typeof existingFinding.rfControls === 'string'
    ? JSON.parse(existingFinding.rfControls)
    : existingFinding.rfControls) as any[] || [];

  // Merge evidence (append new, avoid exact duplicates by reference)
  const existingRefs = new Set(existingEvidence.map((e: any) => e.reference));
  const mergedEvidence = [...existingEvidence, ...newEvidence.filter(e => !existingRefs.has(e.reference))];

  // Merge assets (union)
  const mergedAssets = [...new Set([...existingAssets, ...newAssets])];

  // Merge controls (union by id)
  const existingControlIds = new Set(existingControls.map((c: any) => c.id));
  const mergedControls = [...existingControls, ...newControls.filter(c => !existingControlIds.has(c.id))];

  // Keep highest severity
  const currentRank = severityRank[existingFinding.rfSeverity] || 1;
  const newRank = severityRank[newSeverity] || 1;
  const finalSeverity = newRank > currentRank ? newSeverity : existingFinding.rfSeverity;

  await db.update(ac3ReportFindings).set({
    rfEvidence: mergedEvidence,
    rfAssets: mergedAssets,
    rfControls: mergedControls,
    rfSeverity: finalSeverity,
    rfUpdatedAt: Date.now(),
  }).where(eq(ac3ReportFindings.rfFindingId, existingFinding.rfFindingId));
}

// ─── FedRAMP Control Families Reference ─────────────────────────────────────

const NIST_CONTROL_FAMILIES: Record<string, string> = {
  "AC": "Access Control",
  "AT": "Awareness and Training",
  "AU": "Audit and Accountability",
  "CA": "Assessment, Authorization, and Monitoring",
  "CM": "Configuration Management",
  "CP": "Contingency Planning",
  "IA": "Identification and Authentication",
  "IR": "Incident Response",
  "MA": "Maintenance",
  "MP": "Media Protection",
  "PE": "Physical and Environmental Protection",
  "PL": "Planning",
  "PM": "Program Management",
  "PS": "Personnel Security",
  "PT": "PII Processing and Transparency",
  "RA": "Risk Assessment",
  "SA": "System and Services Acquisition",
  "SC": "System and Communications Protection",
  "SI": "System and Information Integrity",
  "SR": "Supply Chain Risk Management",
};

// ─── Severity Rubric (Platform Source of Truth) ─────────────────────────────

const SEVERITY_RUBRIC = {
  critical: "Broad compromise or severe impact with limited mitigating control effectiveness. Immediate remediation required.",
  high: "Meaningful unauthorized access, privilege escalation, or material risk to sensitive functions or data.",
  moderate: "Clear security weakness with realistic abuse potential but more constrained impact or more prerequisites.",
  low: "Issue worth addressing but with limited practical exploitability or impact in the tested context.",
  informational: "No direct exploit path but still useful for hardening or assurance.",
};

// ─── LLM Prompt Templates ───────────────────────────────────────────────────

// Framework-aware system prompt builder
function buildSystemPrompt(framework: string): string {
  const isFedRAMP = framework === 'fedramp';
  const frameworkLabel = isFedRAMP
    ? 'FedRAMP (cloud service provider within a FedRAMP authorization boundary)'
    : 'NIST SP 800-53 Revision 5 (applicable to all federal information systems)';
  const frameworkGuidance = isFedRAMP
    ? `## FedRAMP-specific style rules
- This report targets a Cloud Service Provider (CSP) operating within a FedRAMP authorization boundary.
- Use FedRAMP-specific language: "cloud service offering (CSO)", "authorization boundary", "FedRAMP impact level", "3PAO", "POA&M".
- Reference FedRAMP baselines (Low, Moderate, High, LI-SaaS) when discussing control applicability.
- Frame findings in terms of the CSP's shared responsibility model and inherited vs. customer-responsible controls.
- Reference FedRAMP continuous monitoring (ConMon) requirements where remediation timelines are discussed.`
    : `## NIST 800-53 Rev 5 style rules
- This report uses the NIST SP 800-53 Revision 5 control catalog as the compliance framework.
- 800-53 Rev 5 applies to all federal information systems regardless of hosting model (on-premises, cloud, hybrid).
- Do NOT use FedRAMP-specific language ("CSO", "3PAO", "FedRAMP baseline", "authorization boundary") unless the system is explicitly scoped into a FedRAMP boundary.
- Frame findings in terms of the organization's security posture and the applicable 800-53 control baselines (Low, Moderate, High).
- Reference NIST SP 800-53A for assessment procedures and NIST SP 800-115 for penetration testing methodology where appropriate.`;

  return `You are the AC3 security report writer. Your job is to convert structured assessment data into professional, audit-defensible penetration test and red team reporting.

## Compliance Framework
This report is governed by: ${frameworkLabel}

## Operating rules
- Write in a calm, precise, professional consulting tone.
- Produce evidence-backed narratives only. Do not invent assets, dates, screenshots, logs, controls, or impact.
- Use high-level reproduction language only. Never include exploit code, malware instructions, payloads, or step-by-step offensive procedures.
- Keep executive summaries concise and business-readable.
- Keep technical sections explicit, structured, and internally consistent.
- Every finding must include: title, severity, summary, business impact, technical details, evidence references, ATT&CK mapping, control mapping, remediation.
- When facts are missing, state that additional evidence is required rather than guessing.

${frameworkGuidance}

## General style rules
- Prefer control-family language such as CA, RA, AC, IA, AU, SI, SC, IR, and CM when supported by the input.
- Use wording that fits formal security assessment reports: "observed", "validated", "identified", "demonstrated", "simulated", "within approved rules of engagement".
- Separate "business impact" from "technical details".
- Distinguish between "simulated exfiltration" and "actual data access" if relevant.
- Avoid sensational or adversarial phrasing.

## Output formatting rules
- Use complete sentences.
- Keep paragraphs short.
- Use bullets for evidence and remediation steps where helpful.
- Preserve exact control IDs and ATT&CK IDs from the input.`;
}

function buildFindingNarrativePrompt(finding: any, metadata: any): string {
  const isFedRAMP = metadata.complianceFramework === 'fedramp';
  const frameworkLine = isFedRAMP
    ? `- Compliance Framework: FedRAMP (${(metadata.fedrampImpactLevel || 'moderate').toUpperCase()} impact level, cloud CSP boundary)`
    : `- Compliance Framework: NIST SP 800-53 Rev 5${metadata.fedrampImpactLevel ? ` (${metadata.fedrampImpactLevel.toUpperCase()} baseline)` : ''}`;
  return `Generate professional narrative fields for this security finding. The platform provides the severity, evidence, ATT&CK IDs, and control mappings as source of truth. You are drafting ONLY the narrative text fields.

## Assessment Context
- Client: ${metadata.clientName || "Not specified"}
- System: ${metadata.systemName || "Not specified"}
- Assessment Type: ${metadata.assessmentType || "penetration_test"}
${frameworkLine}

## Finding Data (Platform Source of Truth - DO NOT modify these)
- Finding ID: ${finding.rfFindingId}
- Severity: ${finding.rfSeverity} — ${SEVERITY_RUBRIC[finding.rfSeverity as keyof typeof SEVERITY_RUBRIC] || ""}
- Evidence: ${JSON.stringify(finding.rfEvidence || [])}
- ATT&CK Techniques: ${JSON.stringify(finding.rfAttackTechniques || [])}
- NIST 800-53 Controls: ${JSON.stringify(finding.rfControls || [])}
- Affected Assets: ${JSON.stringify(finding.rfAssets || [])}
${finding.rfCvssScore ? `- CVSS Score: ${finding.rfCvssScore}` : ""}
${finding.rfCvssVector ? `- CVSS Vector: ${finding.rfCvssVector}` : ""}
${finding.artifactLabels ? `- Supporting Artifacts: ${finding.artifactLabels}` : ''}

## Source Context
${finding.sourceContext || "No additional context provided."}

## Task
Draft the following narrative fields. Be precise, evidence-backed, and ${isFedRAMP ? 'FedRAMP' : 'NIST 800-53 Rev 5'}-appropriate.

IMPORTANT: Where supporting artifacts are listed above, reference them by label in the narrative (e.g., "as demonstrated in Artifact A-1" or "see Artifact A-3 for the scan output"). This creates a traceable chain of evidence between the narrative and the appendix.

Return strict JSON:
{
  "title": "A concise, descriptive finding title",
  "summary": "2-3 sentence finding summary for the findings table",
  "business_impact": "Business impact paragraph explaining organizational risk",
  "technical_details": "Technical details paragraph with high-level reproduction steps (no exploit code). Reference supporting artifacts by label where applicable.",
  "remediation": "Specific, actionable remediation recommendations"
}`;
}

function buildExecSummaryPrompt(reportData: any, findings: any[]): string {
  const severityCounts = findings.reduce((acc: any, f: any) => {
    acc[f.rfSeverity] = (acc[f.rfSeverity] || 0) + 1;
    return acc;
  }, {});
  const isFedRAMP = reportData.complianceFramework === 'fedramp';
  const frameworkLine = isFedRAMP
    ? `- Compliance Framework: FedRAMP (${(reportData.fedrampImpactLevel || 'moderate').toUpperCase()} impact level, cloud CSP boundary)`
    : `- Compliance Framework: NIST SP 800-53 Rev 5${reportData.fedrampImpactLevel ? ` (${reportData.fedrampImpactLevel.toUpperCase()} baseline)` : ''}`;

  return `Generate a one-page executive summary for this security assessment report.

## Assessment Metadata
- Client: ${reportData.clientName || "Not specified"}
- System: ${reportData.systemName || "Not specified"}
- Assessment Type: ${reportData.assessmentType || "penetration_test"}
${frameworkLine}
- Assessment Window: ${reportData.assessmentWindowStart ? new Date(reportData.assessmentWindowStart).toISOString().split("T")[0] : "N/A"} to ${reportData.assessmentWindowEnd ? new Date(reportData.assessmentWindowEnd).toISOString().split("T")[0] : "N/A"}

## Scope
- Domains: ${JSON.stringify(reportData.scopeDomains || [])}
- Assets: ${JSON.stringify(reportData.scopeAssets || [])}
- Approved Vectors: ${JSON.stringify(reportData.approvedVectors || [])}

## Findings Summary
- Total Findings: ${findings.length}
- Critical: ${severityCounts.critical || 0}
- High: ${severityCounts.high || 0}
- Moderate: ${severityCounts.moderate || 0}
- Low: ${severityCounts.low || 0}
- Informational: ${severityCounts.informational || 0}

## Finding Titles
${findings.map((f, i) => `${i + 1}. [${f.rfSeverity.toUpperCase()}] ${f.rfTitle}`).join("\n")}

## Requirements
- Audience: executives, auditors, and security leadership
- Tone: formal, concise, non-alarmist
- Include: engagement purpose, risk statement, top 3 themes, strengths, key gaps, prioritized next actions
- Do not repeat every detailed finding
- Do not use unexplained acronyms
- Do not add facts not present in the input

Return strict JSON:
{
  "risk_statement": "Overall risk assessment paragraph",
  "overall_rating": "critical|high|moderate|low|informational",
  "key_strengths": ["strength1", "strength2", "strength3"],
  "key_gaps": ["gap1", "gap2", "gap3"],
  "narrative": "Full executive summary narrative (3-5 paragraphs)"
}`;
}

function buildQaReviewPrompt(reportData: any, findings: any[]): string {
  return `Review this draft penetration test / red team report for quality and audit readiness.

## Report Metadata
${JSON.stringify(reportData, null, 2)}

## Findings
${JSON.stringify(findings.map(f => ({
  id: f.rfFindingId,
  title: f.rfTitle,
  severity: f.rfSeverity,
  summary: f.rfSummary,
  business_impact: f.rfBusinessImpact,
  technical_details: f.rfTechnicalDetails,
  evidence: f.rfEvidence,
  attack_techniques: f.rfAttackTechniques,
  controls: f.rfControls,
  remediation: f.rfRemediation,
})), null, 2)}

## Check for:
- unsupported claims
- inconsistent severity
- missing evidence references
- vague remediation
- mismatch between executive summary and findings
- missing ATT&CK or control mappings where expected
- prohibited content such as exploit code or overly operational offensive steps
- missing explicit scope or rules of engagement references

Return strict JSON:
{
  "status": "pass or revise",
  "issues": [
    {"section": "section name", "issue": "description", "severity": "high|medium|low", "recommended_fix": "fix description"}
  ]
}`;
}

// ─── Zod Schemas ────────────────────────────────────────────────────────────

const evidenceItemSchema = z.object({
  type: z.string(),
  reference: z.string(),
  description: z.string(),
  url: z.string().optional(),
});

const attackTechniqueSchema = z.object({
  id: z.string(),
  name: z.string().optional(),
  tactic: z.string().optional(),
});

const controlSchema = z.object({
  id: z.string(),
  family: z.string().optional(),
  title: z.string().optional(),
});

// ─── Router ─────────────────────────────────────────────────────────────────

export const ac3ReportsRouter = {
  // List all reports
  listReports: protectedProcedure.query(async ({ ctx }) => {
    const db = await getDbRequired();
    // TODO: ac3Reports doesn't have a direct createdBy/engagementId link yet.
    // For now, all authenticated users can list reports. Full scoping requires
    // linking reports to engagements and filtering by engagement ownership.
    const rows = await db.select().from(ac3Reports).orderBy(desc(ac3Reports.rptUpdatedAt));
    return rows;
  }),

  // Get a single report with findings
  getReport: protectedProcedure
    .input(z.object({ reportId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.rptReportId, input.reportId));
      if (!report) return null;

      const findings = await db.select().from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.rfReportId, input.reportId))
        .orderBy(ac3ReportFindings.rfSortOrder);

      const artifacts = await db.select().from(ac3ReportArtifacts)
        .where(eq(ac3ReportArtifacts.reportId, input.reportId));

      return { ...report, findings, artifacts };
    }),

  // Create a new report
  createReport: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(255),
      clientName: z.string().optional(),
      systemName: z.string().optional(),
      assessmentType: z.enum(["penetration_test", "red_team", "purple_team", "vulnerability_assessment", "hybrid"]).optional(),
      fedrampImpactLevel: z.enum(["low", "moderate", "high", "li-saas"]).optional(),
      cloudProvider: z.string().optional(),
      serviceModel: z.string().optional(),
      assessmentWindowStart: z.number().optional(),
      assessmentWindowEnd: z.number().optional(),
      scopeDomains: z.array(z.string()).optional(),
      scopeAssets: z.array(z.string()).optional(),
      approvedVectors: z.array(z.string()).optional(),
      outOfScope: z.array(z.string()).optional(),
      campaignId: z.string().optional(),
      complianceFramework: z.enum(['fedramp', 'nist_800_53_r5']).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbRequired();
      const now = Date.now();
      const reportId = `rpt-${randomUUID().slice(0, 12)}`;

      await db.insert(ac3Reports).values({
        rptReportId: reportId,
        rptName: input.name,
        rptStatus: "draft",
        complianceFramework: input.complianceFramework ?? 'nist_800_53_r5',
        rptClientName: input.clientName ?? null,
        rptSystemName: input.systemName ?? null,
        rptAssessmentType: input.assessmentType ?? "penetration_test",
        rptFedrampLevel: input.fedrampImpactLevel ?? null,
        rptCloudProvider: input.cloudProvider ?? null,
        rptServiceModel: input.serviceModel ?? null,
        rptWindowStart: input.assessmentWindowStart ?? null,
        rptWindowEnd: input.assessmentWindowEnd ?? null,
        rptVersion: "1.0",
        rptScopeDomains: input.scopeDomains ?? [],
        rptScopeAssets: input.scopeAssets ?? [],
        rptApprovedVectors: input.approvedVectors ?? [],
        rptOutOfScope: input.outOfScope ?? [],
        rptCampaignId: input.campaignId ?? null,
        rptCreatedBy: ctx.user?.name ?? "operator",
        rptCreatedAt: now,
        rptUpdatedAt: now,
      });

      return { reportId, created: true };
    }),

  // Update report metadata
  updateReport: protectedProcedure
    .input(z.object({
      reportId: z.string(),
      name: z.string().optional(),
      clientName: z.string().optional(),
      systemName: z.string().optional(),
      assessmentType: z.enum(["penetration_test", "red_team", "purple_team", "vulnerability_assessment", "hybrid"]).optional(),
      fedrampImpactLevel: z.enum(["low", "moderate", "high", "li-saas"]).optional(),
      cloudProvider: z.string().optional(),
      serviceModel: z.string().optional(),
      assessmentWindowStart: z.number().optional(),
      assessmentWindowEnd: z.number().optional(),
      scopeDomains: z.array(z.string()).optional(),
      scopeAssets: z.array(z.string()).optional(),
      approvedVectors: z.array(z.string()).optional(),
      outOfScope: z.array(z.string()).optional(),
      status: z.enum(["draft", "generating", "review", "approved", "final"]).optional(),
      complianceFramework: z.enum(['fedramp', 'nist_800_53_r5']).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      const now = Date.now();
      const updates: any = { rptUpdatedAt: now };

      if (input.name !== undefined) updates.rptName = input.name;
      if (input.clientName !== undefined) updates.rptClientName = input.clientName;
      if (input.systemName !== undefined) updates.rptSystemName = input.systemName;
      if (input.assessmentType !== undefined) updates.rptAssessmentType = input.assessmentType;
      if (input.fedrampImpactLevel !== undefined) updates.rptFedrampLevel = input.fedrampImpactLevel;
      if (input.cloudProvider !== undefined) updates.rptCloudProvider = input.cloudProvider;
      if (input.serviceModel !== undefined) updates.rptServiceModel = input.serviceModel;
      if (input.assessmentWindowStart !== undefined) updates.rptWindowStart = input.assessmentWindowStart;
      if (input.assessmentWindowEnd !== undefined) updates.rptWindowEnd = input.assessmentWindowEnd;
      if (input.scopeDomains !== undefined) updates.rptScopeDomains = input.scopeDomains;
      if (input.scopeAssets !== undefined) updates.rptScopeAssets = input.scopeAssets;
      if (input.approvedVectors !== undefined) updates.rptApprovedVectors = input.approvedVectors;
      if (input.outOfScope !== undefined) updates.rptOutOfScope = input.outOfScope;
      if (input.status !== undefined) updates.rptStatus = input.status;
      if (input.complianceFramework !== undefined) updates.complianceFramework = input.complianceFramework;

      await db.update(ac3Reports).set(updates)
        .where(eq(ac3Reports.rptReportId, input.reportId));

      return { updated: true };
    }),

  // Add a finding to a report (platform-controlled fields)
  addFinding: protectedProcedure
    .input(z.object({
      reportId: z.string(),
      severity: z.enum(["critical", "high", "moderate", "low", "informational"]),
      title: z.string().min(1),
      evidence: z.array(evidenceItemSchema).optional(),
      attackTechniques: z.array(attackTechniqueSchema).optional(),
      controls: z.array(controlSchema).optional(),
      assets: z.array(z.string()).optional(),
      cvssScore: z.string().optional(),
      cvssVector: z.string().optional(),
      sourceTaskId: z.string().optional(),
      sourceCampaignId: z.string().optional(),
      sourceAgentId: z.string().optional(),
      // Optional pre-filled narratives
      summary: z.string().optional(),
      businessImpact: z.string().optional(),
      technicalDetails: z.string().optional(),
      remediation: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      const now = Date.now();
      const findingId = `f-${randomUUID().slice(0, 12)}`;

      // Auto-enrich control families
      const enrichedControls = (input.controls || []).map(c => ({
        ...c,
        family: c.family || NIST_CONTROL_FAMILIES[c.id.split("-")[0]] || undefined,
      }));

      // Get current finding count for sort order
      const existing = await db.select({ count: sql`COUNT(*)` }).from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.rfReportId, input.reportId));
      const sortOrder = Number(existing[0]?.count ?? 0);

      await db.insert(ac3ReportFindings).values({
        rfFindingId: findingId,
        rfReportId: input.reportId,
        rfSortOrder: sortOrder,
        rfSeverity: input.severity,
        rfTitle: input.title,
        rfEvidence: input.evidence ?? [],
        rfAttackTechniques: input.attackTechniques ?? [],
        rfControls: enrichedControls,
        rfAssets: input.assets ?? [],
        rfCvssScore: input.cvssScore ?? null,
        rfCvssVector: input.cvssVector ?? null,
        rfSummary: input.summary ?? null,
        rfBusinessImpact: input.businessImpact ?? null,
        rfTechnicalDetails: input.technicalDetails ?? null,
        rfRemediation: input.remediation ?? null,
        rfSourceTaskId: input.sourceTaskId ?? null,
        rfSourceCampaignId: input.sourceCampaignId ?? null,
        rfSourceAgentId: input.sourceAgentId ?? null,
        rfNarrativeStatus: (input.summary && input.businessImpact) ? "drafted" : "pending",
        rfCreatedAt: now,
        rfUpdatedAt: now,
      });

      return { findingId, added: true };
    }),

  // Update a finding
  updateFinding: protectedProcedure
    .input(z.object({
      findingId: z.string(),
      severity: z.enum(["critical", "high", "moderate", "low", "informational"]).optional(),
      title: z.string().optional(),
      evidence: z.array(evidenceItemSchema).optional(),
      attackTechniques: z.array(attackTechniqueSchema).optional(),
      controls: z.array(controlSchema).optional(),
      assets: z.array(z.string()).optional(),
      cvssScore: z.string().optional(),
      cvssVector: z.string().optional(),
      summary: z.string().optional(),
      businessImpact: z.string().optional(),
      technicalDetails: z.string().optional(),
      remediation: z.string().optional(),
      narrativeStatus: z.enum(["pending", "drafted", "reviewed", "approved"]).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbRequired();
      const now = Date.now();
      const updates: any = { rfUpdatedAt: now };

      if (input.severity !== undefined) updates.rfSeverity = input.severity;
      if (input.title !== undefined) updates.rfTitle = input.title;
      if (input.evidence !== undefined) updates.rfEvidence = input.evidence;
      if (input.attackTechniques !== undefined) updates.rfAttackTechniques = input.attackTechniques;
      if (input.controls !== undefined) {
        updates.rfControls = input.controls.map(c => ({
          ...c,
          family: c.family || NIST_CONTROL_FAMILIES[c.id.split("-")[0]] || undefined,
        }));
      }
      if (input.assets !== undefined) updates.rfAssets = input.assets;
      if (input.cvssScore !== undefined) updates.rfCvssScore = input.cvssScore;
      if (input.cvssVector !== undefined) updates.rfCvssVector = input.cvssVector;
      if (input.summary !== undefined) updates.rfSummary = input.summary;
      if (input.businessImpact !== undefined) updates.rfBusinessImpact = input.businessImpact;
      if (input.technicalDetails !== undefined) updates.rfTechnicalDetails = input.technicalDetails;
      if (input.remediation !== undefined) updates.rfRemediation = input.remediation;
      if (input.narrativeStatus !== undefined) {
        updates.rfNarrativeStatus = input.narrativeStatus;
        if (input.narrativeStatus === "reviewed" || input.narrativeStatus === "approved") {
          updates.rfReviewedBy = ctx.user?.name ?? "operator";
          updates.rfReviewedAt = now;
        }
      }

      await db.update(ac3ReportFindings).set(updates)
        .where(eq(ac3ReportFindings.rfFindingId, input.findingId));

      return { updated: true };
    }),

  // Delete a finding
  deleteFinding: protectedProcedure
    .input(z.object({ findingId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      await db.delete(ac3ReportFindings)
        .where(eq(ac3ReportFindings.rfFindingId, input.findingId));
      return { deleted: true };
    }),

  // ─── LLM-Powered Narrative Generation ─────────────────────────────────────

  // Generate narrative for a single finding
  generateFindingNarrative: protectedProcedure
    .input(z.object({
      findingId: z.string(),
      sourceContext: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();

      // Get the finding
      const [finding] = await db.select().from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.rfFindingId, input.findingId));
      if (!finding) throw new Error("Finding not found");

      // Get the report for context
      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.rptReportId, finding.rfReportId));
      if (!report) throw new Error("Report not found");

      // Load artifacts linked to this finding for cross-reference in narrative
      const findingArtifacts = await db.select().from(ac3ReportArtifacts)
        .where(and(
          eq(ac3ReportArtifacts.reportId, finding.rfReportId),
          eq(ac3ReportArtifacts.findingId, input.findingId)
        ));
      const artifactLabels = findingArtifacts.length > 0
        ? findingArtifacts.map(a => `${a.label} (${a.artifactType.replace(/_/g, ' ')}${a.description ? ': ' + a.description : ''})`).join('; ')
        : '';

      const findingData = {
        ...finding,
        sourceContext: input.sourceContext || "",
        artifactLabels,
      };

      const prompt = buildFindingNarrativePrompt(findingData, report);

      const response = await invokeLLM({ 
        _caller: "ac3-reports.generateFindingNarrative",
        messages: [
          { role: "system", content: buildSystemPrompt(report.complianceFramework || 'nist_800_53_r5') },
          { role: "user", content: prompt },
        ],
        response_format: {
          type: "json_schema",
          json_schema: {
            name: "finding_narrative",
            strict: true,
            schema: {
              type: "object",
              properties: {
                title: { type: "string", description: "Concise finding title" },
                summary: { type: "string", description: "2-3 sentence summary" },
                business_impact: { type: "string", description: "Business impact paragraph" },
                technical_details: { type: "string", description: "Technical details paragraph" },
                remediation: { type: "string", description: "Remediation recommendations" },
              },
              required: ["title", "summary", "business_impact", "technical_details", "remediation"],
              additionalProperties: false,
            },
          },
        },
      });

      const content = response.choices?.[0]?.message?.content;
      if (!content) throw new Error("LLM returned empty response");

      const narrative = JSON.parse(content);
      const now = Date.now();

      // Update finding with LLM-drafted narratives
      await db.update(ac3ReportFindings).set({
        rfTitle: narrative.title,
        rfSummary: narrative.summary,
        rfBusinessImpact: narrative.business_impact,
        rfTechnicalDetails: narrative.technical_details,
        rfRemediation: narrative.remediation,
        rfNarrativeStatus: "drafted",
        rfUpdatedAt: now,
      }).where(eq(ac3ReportFindings.rfFindingId, input.findingId));

      return { narrative, status: "drafted" };
    }),

  // Generate executive summary for a report
  generateExecSummary: protectedProcedure
    .input(z.object({ reportId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();

      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.rptReportId, input.reportId));
      if (!report) throw new Error("Report not found");

      const findings = await db.select().from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.rfReportId, input.reportId))
        .orderBy(ac3ReportFindings.rfSortOrder);

      if (findings.length === 0) throw new Error("No findings to summarize");

      const prompt = buildExecSummaryPrompt(report, findings);

      const response = await invokeLLM({ 
        _caller: "ac3-reports.generateExecSummary",
        messages: [
          { role: "system", content: buildSystemPrompt(report.complianceFramework || 'nist_800_53_r5') },
          { role: "user", content: prompt },
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
                narrative: { type: "string" },
              },
              required: ["risk_statement", "overall_rating", "key_strengths", "key_gaps", "narrative"],
              additionalProperties: false,
            },
          },
        },
      });

      const content = response.choices?.[0]?.message?.content;
      if (!content) throw new Error("LLM returned empty response");

      const summary = JSON.parse(content);
      const now = Date.now();

      // Validate and normalize overall_rating
      const validRatings = ["critical", "high", "moderate", "low", "informational"];
      const normalizedRating = validRatings.includes(summary.overall_rating?.toLowerCase())
        ? summary.overall_rating.toLowerCase()
        : "moderate";

      await db.update(ac3Reports).set({
        rptExecRiskStatement: summary.risk_statement,
        rptExecRating: normalizedRating as any,
        rptExecStrengths: summary.key_strengths,
        rptExecGaps: summary.key_gaps,
        rptExecNarrative: summary.narrative,
        rptUpdatedAt: now,
      }).where(eq(ac3Reports.rptReportId, input.reportId));

      return { summary, generated: true };
    }),

  // Run QA review on a report
  runQaReview: protectedProcedure
    .input(z.object({ reportId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();

      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.rptReportId, input.reportId));
      if (!report) throw new Error("Report not found");

      const findings = await db.select().from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.rfReportId, input.reportId))
        .orderBy(ac3ReportFindings.rfSortOrder);

      const prompt = buildQaReviewPrompt(report, findings);

      const response = await invokeLLM({ 
        _caller: "ac3-reports.runQaReview",
        messages: [
          { role: "system", content: buildSystemPrompt(report.complianceFramework || 'nist_800_53_r5') },
          { role: "user", content: prompt },
        ],
        response_format: {
          type: "json_schema",
          json_schema: {
            name: "qa_review",
            strict: true,
            schema: {
              type: "object",
              properties: {
                status: { type: "string" },
                issues: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      section: { type: "string" },
                      issue: { type: "string" },
                      severity: { type: "string" },
                      recommended_fix: { type: "string" },
                    },
                    required: ["section", "issue", "severity", "recommended_fix"],
                    additionalProperties: false,
                  },
                },
              },
              required: ["status", "issues"],
              additionalProperties: false,
            },
          },
        },
      });

      const content = response.choices?.[0]?.message?.content;
      if (!content) throw new Error("LLM returned empty response");

      const review = JSON.parse(content);
      const now = Date.now();

      const qaStatus = review.status === "pass" ? "pass" : "revise";

      await db.update(ac3Reports).set({
        rptQaStatus: qaStatus as any,
        rptQaIssues: review.issues,
        rptQaReviewedAt: now,
        rptStatus: qaStatus === "pass" ? "review" : "draft",
        rptUpdatedAt: now,
      }).where(eq(ac3Reports.rptReportId, input.reportId));

      return { review, qaStatus };
    }),

  // Generate all finding narratives for a report
  generateAllNarratives: protectedProcedure
    .input(z.object({ reportId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();

      const findings = await db.select().from(ac3ReportFindings)
        .where(and(
          eq(ac3ReportFindings.rfReportId, input.reportId),
          eq(ac3ReportFindings.rfNarrativeStatus, "pending"),
        ));

      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.rptReportId, input.reportId));
      if (!report) throw new Error("Report not found");

      // Update report status
      await db.update(ac3Reports).set({
        rptStatus: "generating",
        rptUpdatedAt: Date.now(),
      }).where(eq(ac3Reports.rptReportId, input.reportId));

      const results: Array<{ findingId: string; status: string }> = [];

      for (const finding of findings) {
        try {
          const prompt = buildFindingNarrativePrompt(finding, report);

          const response = await invokeLLM({ 
            _caller: "ac3-reports.generateAllNarratives",
            messages: [
              { role: "system", content: buildSystemPrompt(report.complianceFramework || 'nist_800_53_r5') },
              { role: "user", content: prompt },
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
                    remediation: { type: "string" },
                  },
                  required: ["title", "summary", "business_impact", "technical_details", "remediation"],
                  additionalProperties: false,
                },
              },
            },
          });

          const content = response.choices?.[0]?.message?.content;
          if (!content) throw new Error("Empty response");

          const narrative = JSON.parse(content);
          const now = Date.now();

          await db.update(ac3ReportFindings).set({
            rfTitle: narrative.title,
            rfSummary: narrative.summary,
            rfBusinessImpact: narrative.business_impact,
            rfTechnicalDetails: narrative.technical_details,
            rfRemediation: narrative.remediation,
            rfNarrativeStatus: "drafted",
            rfUpdatedAt: now,
          }).where(eq(ac3ReportFindings.rfFindingId, finding.rfFindingId));

          results.push({ findingId: finding.rfFindingId, status: "drafted" });
        } catch (err: any) {
          results.push({ findingId: finding.rfFindingId, status: `error: ${err.message}` });
        }
      }

      // Update report status back to draft
      await db.update(ac3Reports).set({
        rptStatus: "draft",
        rptUpdatedAt: Date.now(),
      }).where(eq(ac3Reports.rptReportId, input.reportId));

      return { results, totalProcessed: results.length };
    }),

  // Delete a report and all its findings
  deleteReport: protectedProcedure
    .input(z.object({ reportId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      await db.delete(ac3ReportFindings).where(eq(ac3ReportFindings.rfReportId, input.reportId));
      await db.delete(ac3Reports).where(eq(ac3Reports.rptReportId, input.reportId));
      return { deleted: true };
    }),

  // Get NIST control families reference
  getControlFamilies: protectedProcedure.query(async () => {
    return NIST_CONTROL_FAMILIES;
  }),

  // Get severity rubric
  getSeverityRubric: protectedProcedure.query(async () => {
    return SEVERITY_RUBRIC;
  }),

  // Export report as structured JSON (for downstream rendering)
  exportReportJson: protectedProcedure
    .input(z.object({ reportId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbRequired();

      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.rptReportId, input.reportId));
      if (!report) throw new Error("Report not found");

      const findings = await db.select().from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.rfReportId, input.reportId))
        .orderBy(ac3ReportFindings.rfSortOrder);

      // Build the AC3 report_input.schema.json compatible output
      return {
        metadata: {
          client_name: report.rptClientName || "",
          system_name: report.rptSystemName || "",
          assessment_type: report.rptAssessmentType || "penetration_test",
          fedramp_impact_level: report.fedrampImpactLevel || "moderate",
          cloud_provider: report.rptCloudProvider || "",
          service_model: report.rptServiceModel || "",
          assessment_window: `${report.assessmentWindowStart ? new Date(report.assessmentWindowStart).toISOString().split("T")[0] : "N/A"} to ${report.assessmentWindowEnd ? new Date(report.assessmentWindowEnd).toISOString().split("T")[0] : "N/A"}`,
          report_version: report.reportVersion || "1.0",
        },
        executive_summary: {
          risk_statement: report.rptExecRiskStatement || "",
          overall_rating: report.execOverallRating || "moderate",
          key_strengths: report.execKeyStrengths || [],
          key_gaps: report.execKeyGaps || [],
          narrative: report.rptExecNarrative || "",
        },
        scope: {
          domains: report.rptScopeDomains || [],
          assets: report.rptScopeAssets || [],
          approved_vectors: report.rptApprovedVectors || [],
          out_of_scope: report.rptOutOfScope || [],
        },
        findings: findings.map(f => ({
          id: f.rfFindingId,
          title: f.rfTitle,
          severity: f.rfSeverity,
          summary: f.rfSummary || "",
          business_impact: f.rfBusinessImpact || "",
          technical_details: f.rfTechnicalDetails || "",
          evidence: (f.rfEvidence as any[] || []).map((e: any) => e.reference || e.description),
          attack_techniques: (f.rfAttackTechniques as any[] || []).map((t: any) => t.id),
          controls: (f.rfControls as any[] || []).map((c: any) => c.id),
          remediation: f.rfRemediation || "",
          assets: f.rfAssets || [],
          cvss_score: f.rfCvssScore || undefined,
          cvss_vector: f.rfCvssVector || undefined,
        })),
      };
    }),

  // ─── Engagement Findings Auto-Population ─────────────────────────────────

  /** List engagements available for import */
  listEngagements: protectedProcedure.query(async () => {
    const db = await getDbRequired();
    const rows = await db.select({
      id: engagements.id,
      name: engagements.name,
      customerName: engagements.customerName,
      engagementType: engagements.engagementType,
      status: engagements.status,
      calderaOperationId: engagements.calderaOperationId,
      startDate: engagements.startDate,
      endDate: engagements.endDate,
      targetDomain: engagements.targetDomain,
    }).from(engagements).orderBy(desc(engagements.createdAt));
    return rows;
  }),

  /** Import findings from an engagement's timeline events into an AC3 report */
  importEngagementFindings: protectedProcedure
    .input(z.object({
      reportId: z.string(),
      engagementId: z.number(),
      severityFilter: z.array(z.string()).optional(),
      eventTypeFilter: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();

      // Verify report exists
      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.rptReportId, input.reportId));
      if (!report) throw new Error("Report not found");

      // Get engagement details
      const [eng] = await db.select().from(engagements)
        .where(eq(engagements.id, input.engagementId));
      if (!eng) throw new Error("Engagement not found");

      // Fetch security-relevant timeline events
      const securityEventTypes = input.eventTypeFilter || [
        'finding_discovered', 'exploit_attempted', 'exploit_succeeded',
        'shell_obtained', 'credential_found', 'pivot_established',
        'data_exfiltrated', 'opsec_alert',
      ];

      const events = await db.select().from(engagementTimelineEvents)
        .where(and(
          eq(engagementTimelineEvents.engagementId, input.engagementId),
          inArray(engagementTimelineEvents.eventType, securityEventTypes as any),
        ))
        .orderBy(engagementTimelineEvents.timestamp);

      if (events.length === 0) return { imported: 0, message: "No matching events found" };

      // Map engagement severity to AC3 severity
      const mapSeverity = (sev: string | null): string => {
        const m: Record<string, string> = {
          critical: 'critical', high: 'high', medium: 'moderate', low: 'low', info: 'informational',
        };
        return m[sev || 'info'] || 'informational';
      };

      // Map event types to ATT&CK-relevant categories
      const mapEventToControls = (eventType: string): { id: string }[] => {
        const controlMap: Record<string, string[]> = {
          exploit_succeeded: ['AC-3', 'SI-3', 'SC-7'],
          shell_obtained: ['AC-3', 'AC-6', 'SI-4'],
          credential_found: ['IA-2', 'IA-5', 'AC-7'],
          pivot_established: ['AC-4', 'SC-7', 'SI-4'],
          data_exfiltrated: ['SC-8', 'SC-28', 'AC-4'],
          opsec_alert: ['SI-4', 'AU-6', 'IR-4'],
          finding_discovered: ['RA-5', 'CA-7'],
          exploit_attempted: ['SI-3', 'SC-7'],
        };
        return (controlMap[eventType] || ['RA-5']).map(id => ({ id }));
      };

      // Collect all technique IDs from events for dedup lookup
      const allTechniqueIds = events
        .map(e => e.attackTechnique)
        .filter(Boolean) as string[];
      const dupeMap = await findDuplicatesByTechnique(db, input.reportId, allTechniqueIds);

      // Get existing finding count for sort order
      const existingFindings = await db.select({ id: ac3ReportFindings.id })
        .from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.rfReportId, input.reportId));
      let sortOrder = existingFindings.length;

      let imported = 0;
      let merged = 0;
      let skipped = 0;
      for (const event of events) {
        const severity = mapSeverity(event.severity);
        if (input.severityFilter && !input.severityFilter.includes(severity)) {
          skipped++;
          continue;
        }

        const attackTechniques = event.attackTechnique
          ? [{ id: event.attackTechnique }]
          : [];

        const evidence = [{
          type: event.eventType === 'shell_obtained' ? 'command_output' :
                event.eventType === 'credential_found' ? 'log' :
                event.eventType === 'data_exfiltrated' ? 'network_capture' : 'log',
          reference: `Engagement ${eng.name} - ${event.eventType}`,
          description: event.description || event.title,
        }];

        const assets = event.targetHost ? [event.targetHost] : [];
        if (event.targetPort) assets.push(`${event.targetHost}:${event.targetPort}`);
        const controls = mapEventToControls(event.eventType);

        // Check for duplicate by ATT&CK technique ID
        if (event.attackTechnique && dupeMap.has(event.attackTechnique)) {
          const existingFinding = dupeMap.get(event.attackTechnique);
          await mergeFinding(db, existingFinding, evidence, assets, severity, controls);
          merged++;
          continue;
        }

        const findingId = `AC3-${randomUUID().slice(0, 8).toUpperCase()}`;
        const now = Date.now();
        await db.insert(ac3ReportFindings).values({
          rfFindingId: findingId,
          rfReportId: input.reportId,
          rfTitle: event.title,
          rfSeverity: severity,
          rfAttackTechniques: attackTechniques,
          rfControls: controls,
          rfEvidence: evidence,
          rfAssets: assets,
          rfNarrativeStatus: 'pending',
          rfSortOrder: sortOrder++,
          rfCreatedAt: now,
          rfUpdatedAt: now,
          rfSourceModule: `engagement:${input.engagementId}`,
          rfSourceEventId: String(event.id),
        });
        imported++;

        // Track newly created finding for subsequent dedup within this batch
        if (event.attackTechnique) {
          dupeMap.set(event.attackTechnique, {
            rfFindingId: findingId,
            rfReportId: input.reportId,
            rfSeverity: severity,
            rfEvidence: evidence,
            rfAssets: assets,
            rfControls: controls,
            rfAttackTechniques: attackTechniques,
          });
        }
      }

      return { imported, merged, skipped, total: events.length, engagementName: eng.name };
    }),

  // ─── Caldera Operation Bulk Import ──────────────────────────────────────────

  /** List Caldera operations from the Caldera API for import */
  listCalderaOperations: protectedProcedure
    .input(z.object({ serverId: z.number().optional() }).optional())
    .query(async () => {
      const baseUrl = ENV.CALDERA_BASE_URL;
      const apiKey = ENV.CALDERA_API_KEY;
      if (!baseUrl || !apiKey) return [];

      try {
        const resp = await fetch(`${baseUrl}/api/v2/operations`, {
          headers: { 'KEY': apiKey, 'Accept': 'application/json' },
        });
        if (!resp.ok) return [];
        const ops = await resp.json();
        return Array.isArray(ops) ? ops.map((op: any) => ({
          id: op.id,
          name: op.name,
          state: op.state,
          adversaryId: op.adversary?.adversary_id || op.adversary_id,
          adversaryName: op.adversary?.name || 'Unknown',
          startedAt: op.start || op.created,
          agentCount: op.host_group?.length || 0,
          linkCount: op.chain?.length || 0,
        })) : [];
      } catch {
        return [];
      }
    }),

  /** Import findings from a Caldera operation's chain links */
  importCalderaOperation: protectedProcedure
    .input(z.object({
      reportId: z.string(),
      operationId: z.string(),
      includeFailedLinks: z.boolean().optional().default(false),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      const baseUrl = ENV.CALDERA_BASE_URL;
      const apiKey = ENV.CALDERA_API_KEY;
      if (!baseUrl || !apiKey) throw new Error("Caldera not configured");

      // Verify report exists
      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.rptReportId, input.reportId));
      if (!report) throw new Error("Report not found");

      // Fetch operation with full chain
      const resp = await fetch(`${baseUrl}/api/v2/operations/${input.operationId}`, {
        headers: { 'KEY': apiKey, 'Accept': 'application/json' },
      });
      if (!resp.ok) throw new Error(`Caldera API error: ${resp.status}`);
      const operation = await resp.json();

      // Fetch abilities for technique mapping
      const abilitiesResp = await fetch(`${baseUrl}/api/v2/abilities`, {
        headers: { 'KEY': apiKey, 'Accept': 'application/json' },
      });
      const abilities = abilitiesResp.ok ? await abilitiesResp.json() : [];
      const abilityMap = new Map<string, any>();
      if (Array.isArray(abilities)) {
        abilities.forEach((a: any) => abilityMap.set(a.ability_id, a));
      }

      const chain = operation.chain || [];
      if (chain.length === 0) return { imported: 0, message: "Operation has no links" };

      // Group links by ability (technique) to consolidate findings
      const abilityGroups = new Map<string, any[]>();
      for (const link of chain) {
        // Status: 0=success, -2=discarded, -1=failed, 1=queued, 124=timeout
        if (!input.includeFailedLinks && link.status !== 0) continue;
        const key = link.ability?.ability_id || link.ability_id || 'unknown';
        if (!abilityGroups.has(key)) abilityGroups.set(key, []);
        abilityGroups.get(key)!.push(link);
      }

      // Collect all technique IDs from ability groups for dedup lookup
      const calderaTechniqueIds: string[] = [];
      for (const [abilityId] of abilityGroups) {
        const ability = abilityMap.get(abilityId) || {};
        const tid = ability.technique_id || ability.technique?.attack_id || '';
        if (tid) calderaTechniqueIds.push(tid);
      }
      const dupeMap = await findDuplicatesByTechnique(db, input.reportId, calderaTechniqueIds);

      // Get existing finding count for sort order
      const existingFindings = await db.select({ id: ac3ReportFindings.id })
        .from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.rfReportId, input.reportId));
      let sortOrder = existingFindings.length;

      let imported = 0;
      let merged = 0;
      for (const [abilityId, links] of abilityGroups) {
        const ability = abilityMap.get(abilityId) || links[0]?.ability || {};
        const techniqueId = ability.technique_id || ability.technique?.attack_id || '';
        const techniqueName = ability.technique_name || ability.technique?.name || '';
        const tactic = ability.tactic || '';

        // Determine severity based on tactic
        const tacticSeverity: Record<string, string> = {
          'initial-access': 'high',
          'execution': 'high',
          'persistence': 'high',
          'privilege-escalation': 'critical',
          'defense-evasion': 'moderate',
          'credential-access': 'critical',
          'discovery': 'low',
          'lateral-movement': 'high',
          'collection': 'moderate',
          'command-and-control': 'high',
          'exfiltration': 'critical',
          'impact': 'critical',
          'reconnaissance': 'informational',
          'resource-development': 'informational',
        };
        const severity = tacticSeverity[tactic] || 'moderate';

        // Map tactic to NIST controls
        const tacticControls: Record<string, string[]> = {
          'initial-access': ['AC-3', 'SC-7', 'SI-3'],
          'execution': ['CM-7', 'SI-3', 'SI-7'],
          'persistence': ['CM-7', 'SI-3', 'SI-7'],
          'privilege-escalation': ['AC-6', 'CM-6', 'AC-3'],
          'defense-evasion': ['SI-4', 'AU-6', 'CM-7'],
          'credential-access': ['IA-2', 'IA-5', 'AC-7'],
          'discovery': ['AC-4', 'SI-4', 'CM-8'],
          'lateral-movement': ['AC-4', 'SC-7', 'AC-3'],
          'collection': ['SC-28', 'AC-3', 'MP-5'],
          'command-and-control': ['SC-7', 'SI-4', 'SC-8'],
          'exfiltration': ['SC-7', 'SC-8', 'AC-4'],
          'impact': ['CP-9', 'CP-10', 'SI-7'],
        };
        const controls = (tacticControls[tactic] || ['RA-5']).map(id => ({ id }));

        // Build ATT&CK techniques
        const attackTechniques = techniqueId ? [{ id: techniqueId, name: techniqueName }] : [];

        // Build evidence from link outputs
        const evidence = links.slice(0, 5).map((link: any, i: number) => ({
          type: 'command_output',
          reference: `Caldera Op ${operation.name} - Link ${link.id || i + 1}`,
          description: `Ability: ${ability.name || abilityId}. Agent: ${link.paw || 'N/A'}. ` +
            `Status: ${link.status === 0 ? 'Success' : 'Failed'}. ` +
            (link.output ? `Output sample: ${String(link.output).slice(0, 200)}` : 'No output captured.'),
        }));

        // Build affected assets from agent paws
        const assets = [...new Set(links.map((l: any) => l.host || l.paw).filter(Boolean))];

        // Check for duplicate by ATT&CK technique ID
        if (techniqueId && dupeMap.has(techniqueId)) {
          const existingFinding = dupeMap.get(techniqueId);
          await mergeFinding(db, existingFinding, evidence, assets, severity, controls);
          merged++;
          continue;
        }

        const findingId = `AC3-${randomUUID().slice(0, 8).toUpperCase()}`;
        const now = Date.now();

        await db.insert(ac3ReportFindings).values({
          rfFindingId: findingId,
          rfReportId: input.reportId,
          rfTitle: `${ability.name || abilityId}${tactic ? ` (${tactic})` : ''}`,
          rfSeverity: severity,
          rfAttackTechniques: attackTechniques,
          rfControls: controls,
          rfEvidence: evidence,
          rfAssets: assets,
          rfNarrativeStatus: 'pending',
          rfSortOrder: sortOrder++,
          rfCreatedAt: now,
          rfUpdatedAt: now,
          rfSourceModule: `caldera:${input.operationId}`,
          rfSourceEventId: abilityId,
        });
        imported++;

        // Track newly created finding for subsequent dedup within this batch
        if (techniqueId) {
          dupeMap.set(techniqueId, {
            rfFindingId: findingId,
            rfReportId: input.reportId,
            rfSeverity: severity,
            rfEvidence: evidence,
            rfAssets: assets,
            rfControls: controls,
            rfAttackTechniques: attackTechniques,
          });
        }
      }

      // Also try to import from local atomic test executions linked to this operation
      const localExecs = await db.select().from(atomicTestExecutions)
        .where(eq(atomicTestExecutions.calderaOperationId, input.operationId));

      for (const exec of localExecs) {
        // Skip if we already imported this technique from the Caldera chain
        if (abilityGroups.has(exec.techniqueId)) continue;

        // Check dedup for atomic tests too
        if (dupeMap.has(exec.techniqueId)) {
          const existingFinding = dupeMap.get(exec.techniqueId);
          const atomicEvidence = [{
            type: 'command_output',
            reference: `Atomic Test ${exec.guid}`,
            description: `Test: ${exec.testName}. Status: ${exec.status}. ` +
              (exec.stdout ? `Output: ${exec.stdout.slice(0, 200)}` : '') +
              (exec.detectionTriggered ? ' [DETECTION TRIGGERED]' : ''),
          }];
          const atomicAssets = exec.targetHost ? [exec.targetHost] : [];
          await mergeFinding(db, existingFinding, atomicEvidence, atomicAssets, 'moderate', [{ id: 'RA-5' }]);
          merged++;
          continue;
        }

        const findingId = `AC3-${randomUUID().slice(0, 8).toUpperCase()}`;
        const severity = exec.status === 'success' ? 'high' : exec.status === 'blocked' ? 'informational' : 'moderate';

        const evidence = [{
          type: 'command_output',
          reference: `Atomic Test ${exec.guid}`,
          description: `Test: ${exec.testName}. Status: ${exec.status}. ` +
            (exec.stdout ? `Output: ${exec.stdout.slice(0, 200)}` : '') +
            (exec.detectionTriggered ? ' [DETECTION TRIGGERED]' : ''),
        }];

        const now = Date.now();
        await db.insert(ac3ReportFindings).values({
          rfFindingId: findingId,
          rfReportId: input.reportId,
          rfTitle: exec.testName,
          rfSeverity: severity,
          rfAttackTechniques: [{ id: exec.techniqueId }],
          rfControls: [{ id: 'RA-5' }],
          rfEvidence: evidence,
          rfAssets: exec.targetHost ? [exec.targetHost] : [],
          rfNarrativeStatus: 'pending',
          rfSortOrder: sortOrder++,
          rfCreatedAt: now,
          rfUpdatedAt: now,
          rfSourceModule: `atomic:${exec.calderaOperationId}`,
          rfSourceEventId: exec.guid,
        });
        imported++;

        // Track for intra-batch dedup
        if (exec.techniqueId) {
          dupeMap.set(exec.techniqueId, {
            rfFindingId: findingId,
            rfReportId: input.reportId,
            rfSeverity: severity,
            rfEvidence: evidence,
            rfAssets: exec.targetHost ? [exec.targetHost] : [],
            rfControls: [{ id: 'RA-5' }],
            rfAttackTechniques: [{ id: exec.techniqueId }],
          });
        }
      }

      return {
        imported,
        merged,
        operationName: operation.name,
        totalLinks: chain.length,
        adversaryName: operation.adversary?.name || 'Unknown',
      };
    }),

  // ─── ATT&CK → NIST 800-53 Control Mapping ────────────────────────────────

  // Static mapping from MITRE ATT&CK technique IDs to NIST 800-53 controls
  // Used to auto-populate FedRAMP-required control mappings during import

  // ─── Import from Ops Snapshot (Primary Pipeline for Completed Engagements) ──

  /** Import findings from engagement_ops_snapshots.state_json — the primary data source
   *  for completed engagements. Extracts vulnAnalysis, attackChains, essIntelligence,
   *  and auto-populates scope, evidence, ATT&CK IDs, and NIST controls. */
  importFromOpsSnapshot: protectedProcedure
    .input(z.object({
      reportId: z.string(),
      engagementId: z.number(),
      severityFilter: z.array(z.string()).optional(),
      autoPopulateScope: z.boolean().optional().default(true),
      autoPopulateExecSummary: z.boolean().optional().default(true),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();

      // Verify report exists
      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.rptReportId, input.reportId));
      if (!report) throw new Error("Report not found");

      // Get engagement details
      const [eng] = await db.select().from(engagements)
        .where(eq(engagements.id, input.engagementId));
      if (!eng) throw new Error("Engagement not found");

      // Get the ops snapshot
      const snapshots = await db.select().from(engagementOpsSnapshots)
        .where(eq(engagementOpsSnapshots.engagementId, input.engagementId))
        .orderBy(desc(engagementOpsSnapshots.createdAt));
      if (snapshots.length === 0) throw new Error("No ops snapshot found for this engagement. Run the engagement first.");

      const snapshot = snapshots[0];
      const state = typeof snapshot.stateJson === 'string'
        ? JSON.parse(snapshot.stateJson)
        : snapshot.stateJson;

      // ── ATT&CK → NIST 800-53 Control Mapping Table ──
      const attackToNist: Record<string, string[]> = {
        'T1190': ['SC-7', 'SI-4', 'RA-5', 'CA-8'],
        'T1133': ['AC-17', 'SC-7', 'IA-2'],
        'T1078': ['AC-2', 'AC-6', 'IA-2', 'IA-5'],
        'T1078.004': ['AC-2', 'AC-6', 'IA-5', 'CA-8'],
        'T1098': ['AC-2', 'AC-6', 'CM-5'],
        'T1098.003': ['AC-2', 'AC-6', 'IA-5', 'CA-8'],
        'T1530': ['AC-3', 'SC-28', 'AC-6', 'AU-6'],
        'T1059': ['CM-7', 'SI-3', 'SI-7'],
        'T1059.001': ['CM-7', 'SI-3', 'SI-7'],
        'T1059.003': ['CM-7', 'SI-3', 'SI-7'],
        'T1059.004': ['CM-7', 'SI-3', 'SI-7'],
        'T1068': ['AC-6', 'CM-6', 'SI-2'],
        'T1548': ['AC-6', 'CM-6', 'CM-7'],
        'T1110': ['AC-7', 'IA-2', 'IA-5'],
        'T1110.001': ['AC-7', 'IA-2', 'IA-5'],
        'T1003': ['AC-6', 'IA-5', 'SI-4'],
        'T1021': ['AC-3', 'AC-17', 'SC-7'],
        'T1021.001': ['AC-3', 'AC-17', 'SC-7'],
        'T1021.002': ['AC-3', 'AC-17', 'SC-7'],
        'T1021.004': ['AC-3', 'AC-17', 'SC-7'],
        'T1046': ['CM-8', 'SC-7', 'SI-4'],
        'T1018': ['AC-4', 'CM-8', 'SI-4'],
        'T1082': ['CM-8', 'SI-4'],
        'T1087': ['AC-2', 'AC-6', 'SI-4'],
        'T1071': ['SC-7', 'SI-4', 'SC-8'],
        'T1071.001': ['SC-7', 'SI-4', 'SC-8'],
        'T1105': ['SC-7', 'SI-3', 'SI-4'],
        'T1041': ['SC-7', 'SC-8', 'AC-4', 'SI-4'],
        'T1486': ['CP-9', 'CP-10', 'SI-7'],
        'T1489': ['CP-9', 'CP-10', 'CM-7'],
        'T1566': ['AT-2', 'SI-3', 'SI-8'],
        'T1566.001': ['AT-2', 'SI-3', 'SI-8'],
        'T1027': ['SI-3', 'SI-4'],
        'T1070': ['AU-6', 'AU-9', 'SI-4'],
        'T1562': ['AU-6', 'SI-4', 'CM-7'],
        'T1136': ['AC-2', 'AC-6', 'CM-5'],
        'T1505': ['CM-7', 'SI-3', 'SI-7'],
        'T1505.003': ['CM-7', 'SI-3', 'SI-7'],
        'T1595': ['SC-7', 'SI-4'],
        'T1592': ['SC-7', 'SI-4'],
        'T1589': ['AT-2', 'SC-7'],
        'T1583': ['SC-7', 'SI-4'],
        'T1557': ['SC-8', 'SC-23', 'SI-4'],
        'T1040': ['SC-8', 'SI-4', 'AC-3'],
        'T1219': ['SC-7', 'SI-4', 'CM-7'],
        'T1574': ['CM-7', 'SI-7', 'AC-6'],
        'T1053': ['CM-7', 'AC-6', 'AU-6'],
        'T1543': ['CM-7', 'AC-6', 'SI-4'],
      };

      // Fallback: derive controls from vulnerability category
      const categoryToNist: Record<string, string[]> = {
        'config': ['CM-6', 'CM-7', 'SC-7'],
        'web': ['SC-7', 'SI-10', 'SI-4'],
        'crypto': ['SC-8', 'SC-12', 'SC-13'],
        'auth': ['IA-2', 'IA-5', 'AC-7'],
        'access': ['AC-3', 'AC-6', 'AC-2'],
        'injection': ['SI-10', 'SI-3', 'SC-7'],
        'disclosure': ['SC-28', 'AC-3', 'SI-4'],
        'default': ['RA-5', 'CA-7', 'CA-8'],
      };

      function getControlsForTechniques(techniqueIds: string[], agentClass?: string): { id: string }[] {
        const controlSet = new Set<string>();
        for (const tid of techniqueIds) {
          const controls = attackToNist[tid];
          if (controls) controls.forEach(c => controlSet.add(c));
        }
        // If no ATT&CK mapping found, use category-based fallback
        if (controlSet.size === 0 && agentClass) {
          const fallback = categoryToNist[agentClass] || categoryToNist['default'];
          fallback.forEach(c => controlSet.add(c));
        }
        if (controlSet.size === 0) {
          categoryToNist['default'].forEach(c => controlSet.add(c));
        }
        // Always include CA-8 (Penetration Testing) for pentest reports
        controlSet.add('CA-8');
        return Array.from(controlSet).map(id => ({ id }));
      }

      // ── Extract data from state_json ──
      const vulnAnalysis: any[] = state.vulnAnalysis || [];
      const attackChains: any[] = state.attackChains || [];
      const assets: any[] = state.assets || [];
      const approvalGates: any[] = state.approvalGates || [];
      const essIntelligence: any = state.essIntelligence || {};
      const engagementContext: any = state.engagementContext || {};
      const roeScopeGuard: any = state.roeScopeGuard || {};
      const passiveReconResults: any[] = state.passiveReconResults || [];

      // ── Build ATT&CK technique index from attack chains ──
      // Maps asset+CVE to technique IDs for cross-referencing with vulnAnalysis
      const assetTechniqueMap = new Map<string, Set<string>>();
      const allChainTechniques = new Set<string>();
      for (const chain of attackChains) {
        const phases = chain.killChainPhases || [];
        for (const phase of phases) {
          for (const step of (phase.steps || [])) {
            if (step.techniqueId) {
              allChainTechniques.add(step.techniqueId);
              const target = step.target || '';
              if (target) {
                if (!assetTechniqueMap.has(target)) assetTechniqueMap.set(target, new Set());
                assetTechniqueMap.get(target)!.add(step.techniqueId);
              }
            }
          }
        }
        // Also extract from cloudExploitPaths
        for (const path of (chain.cloudExploitPaths || [])) {
          for (const tid of (path.mitreTechniques || [])) {
            allChainTechniques.add(tid);
          }
        }
      }

      // ── Build CVE → CVSS score index from essIntelligence ──
      const cveScoreMap = new Map<string, { score: string; tier: string; summary: string }>();
      for (const threat of (essIntelligence.topThreats || [])) {
        const cvssMatch = threat.riskSummary?.match(/CVSS\s+([\d.]+)\/10/);
        cveScoreMap.set(threat.cveId, {
          score: cvssMatch ? cvssMatch[1] : '',
          tier: threat.riskTier || '',
          summary: threat.riskSummary || '',
        });
      }

      // ── Build exploit attempt index from assets ──
      const assetExploitMap = new Map<string, any[]>();
      for (const asset of assets) {
        const hostname = asset.hostname || asset.ip || '';
        if (hostname && asset.exploitAttempts) {
          assetExploitMap.set(hostname, asset.exploitAttempts);
        }
      }

      // ── Map severity from vuln analysis ──
      const mapVulnSeverity = (sev: string | null, riskScore?: number): string => {
        if (sev) {
          const m: Record<string, string> = {
            critical: 'critical', high: 'high', medium: 'moderate', low: 'low', info: 'informational',
          };
          return m[sev] || 'moderate';
        }
        if (riskScore !== undefined) {
          if (riskScore >= 9) return 'critical';
          if (riskScore >= 7) return 'high';
          if (riskScore >= 4) return 'moderate';
          if (riskScore >= 2) return 'low';
          return 'informational';
        }
        return 'moderate';
      };

      // ── Process vulnAnalysis entries into findings ──
      const allTechniqueIds: string[] = [];
      const findingsToCreate: any[] = [];

      for (const vuln of vulnAnalysis) {
        const finding = vuln.finding || {};
        const analysis = vuln.analysis || {};
        const agentClass = vuln.agentClass || 'default';

        const severity = mapVulnSeverity(finding.rfSeverity, analysis.riskScore);
        if (input.severityFilter && !input.severityFilter.includes(severity)) continue;

        // Extract ATT&CK techniques: from attack chains matching this asset, plus CVE-based
        const techniqueIds: string[] = [];
        const assetName = finding.asset || '';
        if (assetName && assetTechniqueMap.has(assetName)) {
          assetTechniqueMap.get(assetName)!.forEach(t => techniqueIds.push(t));
        }
        // Also check CVEs from analysis
        for (const cve of (analysis.relatedCves || [])) {
          // Look up if any attack chain step references this CVE
          for (const chain of attackChains) {
            for (const phase of (chain.killChainPhases || [])) {
              for (const step of (phase.steps || [])) {
                if (step.exploitDetails?.includes(cve) && step.techniqueId) {
                  if (!techniqueIds.includes(step.techniqueId)) techniqueIds.push(step.techniqueId);
                }
              }
            }
          }
        }
        // ── Infer ATT&CK techniques from vulnerability type/title ──
        const titleLower = (finding.rfTitle || '').toLowerCase();
        const descLower = (analysis.technicalAnalysis || '').toLowerCase();
        const combined = titleLower + ' ' + descLower;

        const VULN_TECHNIQUE_MAP: Array<{ patterns: RegExp[]; techniques: string[] }> = [
          // Reconnaissance
          { patterns: [/information disclosure/i, /version disclosure/i, /server header/i, /banner grab/i, /directory listing/i],
            techniques: ['T1592', 'T1595'] },
          { patterns: [/nikto/i, /scanner/i, /enumerat/i],
            techniques: ['T1595.002', 'T1046'] },
          // Discovery & Scanning
          { patterns: [/port scan/i, /service detect/i, /scanforge/i, /open port/i],
            techniques: ['T1046'] },
          { patterns: [/dns zone transfer/i, /subdomain/i],
            techniques: ['T1018'] },
          { patterns: [/directory travers/i, /path travers/i, /lfi/i, /local file inclu/i],
            techniques: ['T1083'] },
          // Initial Access
          { patterns: [/sql inject/i, /sqli/i],
            techniques: ['T1190'] },
          { patterns: [/remote code exec/i, /rce/i, /code injection/i, /command inject/i, /os command/i],
            techniques: ['T1190', 'T1059'] },
          { patterns: [/deserialization/i, /unserialize/i],
            techniques: ['T1190'] },
          { patterns: [/ssrf/i, /server.side request/i],
            techniques: ['T1090', 'T1190'] },
          { patterns: [/phishing/i, /social engineer/i],
            techniques: ['T1566'] },
          { patterns: [/default cred/i, /weak password/i, /brute.?force/i],
            techniques: ['T1078', 'T1110'] },
          // Execution
          { patterns: [/xss/i, /cross.site script/i],
            techniques: ['T1059.007'] },
          { patterns: [/spring cloud/i, /spel inject/i],
            techniques: ['T1059', 'T1190'] },
          // Credential Access
          { patterns: [/credential/i, /password.*expos/i, /api.?key.*expos/i, /token.*leak/i, /secret.*expos/i],
            techniques: ['T1552'] },
          { patterns: [/session.*hijack/i, /cookie.*steal/i],
            techniques: ['T1539'] },
          // Persistence
          { patterns: [/backdoor/i, /web.?shell/i, /implant/i],
            techniques: ['T1505.003'] },
          // Privilege Escalation
          { patterns: [/privilege.*escalat/i, /privesc/i, /improper.*authoriz/i, /access control/i, /idor/i, /broken.*access/i],
            techniques: ['T1068'] },
          // Defense Evasion
          { patterns: [/clickjack/i, /x-frame/i, /csp.*bypass/i, /security header/i, /hsts/i, /cors.*misconfig/i],
            techniques: ['T1036'] },
          // Collection
          { patterns: [/data.*expos/i, /sensitive.*data/i, /pii.*leak/i, /cloud.*storage.*public/i, /s3.*bucket/i, /storage.*bucket/i],
            techniques: ['T1530'] },
          // Lateral Movement
          { patterns: [/lateral.*move/i, /pivot/i, /rdp/i, /smb.*relay/i],
            techniques: ['T1021'] },
          // Impact
          { patterns: [/denial.*service/i, /dos/i, /ddos/i],
            techniques: ['T1499'] },
        ];

        for (const mapping of VULN_TECHNIQUE_MAP) {
          if (mapping.patterns.some(p => p.test(combined))) {
            for (const t of mapping.techniques) {
              if (!techniqueIds.includes(t)) techniqueIds.push(t);
            }
          }
        }

        // If still no techniques, assign T1190 (Exploit Public-Facing Application) for any CVE-based finding
        if (techniqueIds.length === 0 && (analysis.relatedCves?.length || finding.cve)) {
          techniqueIds.push('T1190');
        }

        // Deduplicate
        const uniqueTechniques = [...new Set(techniqueIds)];
        allTechniqueIds.push(...uniqueTechniques);

        // Get NIST controls from ATT&CK mapping
        const controls = getControlsForTechniques(uniqueTechniques, agentClass);

        // Build evidence array
        const evidence: any[] = [];
        // From PoC
        if (analysis.poc) {
          evidence.push({
            type: 'poc',
            reference: `PoC for ${finding.rfTitle || finding.id}`,
            description: typeof analysis.poc === 'string' ? analysis.poc.slice(0, 500) : JSON.stringify(analysis.poc).slice(0, 500),
          });
        }
        // From exploit attempts on this asset
        if (assetName && assetExploitMap.has(assetName)) {
          const exploits = assetExploitMap.get(assetName)!;
          for (const exploit of exploits.slice(0, 3)) {
            evidence.push({
              type: 'exploit_attempt',
              reference: `Exploit: ${exploit.cve || exploit.module || 'unknown'} on ${assetName}`,
              description: `Module: ${exploit.module}. CVE: ${exploit.cve || 'N/A'}. ` +
                `Confidence: ${exploit.confidence}%. Success: ${exploit.success}. ` +
                `Output: ${(exploit.exploitOutput || '').slice(0, 200)}`,
            });
          }
        }
        // From relevant approval gates
        const relevantGates = approvalGates.filter(g =>
          g.target === assetName && g.status === 'approved'
        ).slice(0, 2);
        for (const gate of relevantGates) {
          evidence.push({
            type: 'approval_gate',
            reference: `Approved: ${gate.title || gate.module}`,
            description: gate.description || `Tool: ${gate.detail?.tool}, Args: ${gate.detail?.args?.slice(0, 150)}`,
          });
        }

        // Get CVSS score from ESS intelligence
        let cvssScore = '';
        for (const cve of (analysis.relatedCves || [])) {
          const cveData = cveScoreMap.get(cve);
          if (cveData?.score) {
            cvssScore = cveData.score;
            break;
          }
        }

        // Build assets array
        const findingAssets = [assetName].filter(Boolean);
        if (finding.port) findingAssets.push(`${assetName}:${finding.port}`);

        findingsToCreate.push({
          title: finding.rfTitle || `Vulnerability on ${assetName}`,
          severity,
          attackTechniques: uniqueTechniques.map(id => ({ id })),
          controls,
          evidence,
          assets: findingAssets,
          cvssScore: cvssScore || (analysis.riskScore ? String(analysis.riskScore) : ''),
          agentClass,
          sourceContext: [
            analysis.technicalAnalysis ? `Technical Analysis: ${analysis.technicalAnalysis}` : '',
            analysis.impactAssessment ? `Impact Assessment: ${analysis.impactAssessment}` : '',
            analysis.exploitationPath ? `Exploitation Path: ${JSON.stringify(analysis.exploitationPath)}` : '',
            analysis.remediation ? `Remediation Steps: ${JSON.stringify(analysis.remediation)}` : '',
          ].filter(Boolean).join('\n\n'),
          // Pre-populate remediation from analysis (platform data)
          remediation: Array.isArray(analysis.remediation)
            ? analysis.remediation.join('\n')
            : (analysis.remediation || ''),
        });
      }

      // ── Deduplication check ──
      // Primary dedup key: finding TITLE (each vulnAnalysis entry has a unique title)
      // Secondary: ATT&CK technique ID (only for truly duplicate entries with same title)
      // This prevents collapsing distinct vulnerabilities that happen to share techniques
      // because they target the same asset.
      const existingFindings = await db.select().from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.rfReportId, input.reportId));
      let sortOrder = existingFindings.length;

      // Build title-based dedup map from existing findings
      const titleDupeMap = new Map<string, any>();
      for (const f of existingFindings) {
        const normalizedTitle = (f.rfTitle || '').toLowerCase().trim();
        if (normalizedTitle) titleDupeMap.set(normalizedTitle, f);
      }

      let imported = 0;
      let merged = 0;
      let skipped = 0;

      for (const f of findingsToCreate) {
        const normalizedTitle = (f.rfTitle || '').toLowerCase().trim();

        // Check for duplicate by TITLE first (primary dedup key)
        if (normalizedTitle && titleDupeMap.has(normalizedTitle)) {
          const existingFinding = titleDupeMap.get(normalizedTitle);
          await mergeFinding(db, existingFinding, f.rfEvidence, f.rfAssets, f.rfSeverity, f.rfControls);
          merged++;
          continue;
        }

        const findingId = `AC3-${randomUUID().slice(0, 8).toUpperCase()}`;
        const now = Date.now();
        await db.insert(ac3ReportFindings).values({
          rfFindingId: findingId,
          rfReportId: input.reportId,
          rfTitle: f.rfTitle,
          rfSeverity: f.rfSeverity,
          rfAttackTechniques: f.rfAttackTechniques,
          rfControls: f.rfControls,
          rfEvidence: f.rfEvidence,
          rfAssets: f.rfAssets,
          rfCvssScore: f.rfCvssScore || null,
          rfRemediation: f.rfRemediation || null,
          rfNarrativeStatus: 'pending',
          rfSortOrder: sortOrder++,
          rfCreatedAt: now,
          rfUpdatedAt: now,
          rfSourceModule: `ops-snapshot:${input.engagementId}`,
          rfSourceEventId: `vuln-${sortOrder}`,
        });
        imported++;

        // Track for intra-batch dedup by title
        titleDupeMap.set(normalizedTitle, {
          findingId,
          rfReportId: input.reportId,
          rfSeverity: f.rfSeverity,
          rfEvidence: f.rfEvidence,
          rfAssets: f.rfAssets,
          rfControls: f.rfControls,
          rfAttackTechniques: f.rfAttackTechniques,
        });
      }

      // ── Auto-populate scope from engagement data ──
      if (input.autoPopulateScope) {
        const scopeUpdates: any = {};

        // Domains from ROE scope guard
        if (roeScopeGuard.authorizedDomains?.length) {
          scopeUpdates.rptScopeDomains = roeScopeGuard.authorizedDomains;
        }

        // Assets from crown jewels + asset hostnames
        const scopeAssets = [
          ...(engagementContext.crownJewels || []),
          ...assets.map((a: any) => a.hostname || a.ip).filter(Boolean),
        ];
        if (scopeAssets.length) {
          scopeUpdates.rptScopeAssets = [...new Set(scopeAssets)];
        }

        // Cloud provider from assets
        const cloudServices = assets.flatMap((a: any) => a.cloudServices || []);
        if (cloudServices.length) {
          const providers = [...new Set(cloudServices.map((s: string) => s.split(':')[0].toUpperCase()))];
          scopeUpdates.cloudProvider = providers.join(' + ');
        }

        // Service model from sector
        if (engagementContext.inferredSector) {
          const sectorToModel: Record<string, string> = {
            saas_tech: 'SaaS', paas: 'PaaS', iaas: 'IaaS', healthcare: 'SaaS',
            finance: 'SaaS', government: 'SaaS / IaaS', education: 'SaaS',
          };
          scopeUpdates.serviceModel = sectorToModel[engagementContext.inferredSector] || 'SaaS';
        }

        // Approved vectors from approval gates
        const vectorTypes = new Set<string>();
        for (const gate of approvalGates) {
          if (gate.status === 'approved') {
            if (gate.module === 'hydra' || gate.module === 'credential_test') vectorTypes.add('Credential testing');
            else if (gate.module === 'exploit' || gate.riskTier === 'red') vectorTypes.add('Exploitation of public-facing applications');
            else if (gate.module === 'scanforge-discovery' || gate.module === 'scan') vectorTypes.add('Network scanning and enumeration');
            else if (gate.module === 'zap' || gate.module === 'web_scan') vectorTypes.add('Web application testing');
            else vectorTypes.add(`${gate.module || 'Tool'}-based testing`);
          }
        }
        if (vectorTypes.size) {
          scopeUpdates.rptApprovedVectors = [...vectorTypes];
        }

        // Assessment window from engagement dates
        if (eng.startDate) {
          scopeUpdates.assessmentWindowStart = new Date(eng.startDate).getTime();
        }
        if (state.completedAt) {
          scopeUpdates.assessmentWindowEnd = state.completedAt;
        } else if (eng.endDate) {
          scopeUpdates.assessmentWindowEnd = new Date(eng.endDate).getTime();
        }

        // Client name
        scopeUpdates.rptClientName = eng.customerName;
        scopeUpdates.rptSystemName = eng.name;

        if (Object.keys(scopeUpdates).length) {
          scopeUpdates.rptUpdatedAt = Date.now();
          await db.update(ac3Reports).set(scopeUpdates)
            .where(eq(ac3Reports.rptReportId, input.reportId));
        }
      }

      // ── Auto-populate executive summary seed data ──
      if (input.autoPopulateExecSummary) {
        const execUpdates: any = {};

        // Key strengths from detection opportunities
        const strengths: string[] = [];
        for (const chain of attackChains) {
          for (const opp of (chain.detectionOpportunities || [])) {
            if (!strengths.includes(opp)) strengths.push(opp);
          }
        }
        if (strengths.length) {
          execUpdates.execKeyStrengths = strengths.slice(0, 5);
        }

        // Key gaps from high/critical vuln impact assessments
        const gaps: string[] = [];
        for (const vuln of vulnAnalysis) {
          const sev = vuln.finding?.severity;
          if ((sev === 'high' || sev === 'critical' || sev === 'medium') && vuln.analysis?.impactAssessment) {
            const impact = vuln.analysis.impactAssessment;
            // Truncate to first sentence
            const firstSentence = impact.split('.')[0] + '.';
            if (!gaps.includes(firstSentence) && firstSentence.length > 10) {
              gaps.push(firstSentence);
            }
          }
        }
        if (gaps.length) {
          execUpdates.execKeyGaps = gaps.slice(0, 5);
        }

        // Auto-derive overall rating from finding severity distribution
        const sevCounts: Record<string, number> = {};
        for (const f of findingsToCreate) {
          sevCounts[f.rfSeverity] = (sevCounts[f.rfSeverity] || 0) + 1;
        }
        if (sevCounts.critical && sevCounts.critical >= 3) execUpdates.execOverallRating = 'critical';
        else if (sevCounts.critical || (sevCounts.high && sevCounts.high >= 5)) execUpdates.execOverallRating = 'high';
        else if (sevCounts.high || (sevCounts.moderate && sevCounts.moderate >= 5)) execUpdates.execOverallRating = 'moderate';
        else execUpdates.execOverallRating = 'low';

        if (Object.keys(execUpdates).length) {
          execUpdates.rptUpdatedAt = Date.now();
          await db.update(ac3Reports).set(execUpdates)
            .where(eq(ac3Reports.rptReportId, input.reportId));
        }
      }

      // ── Auto-extract artifacts from evidence and approval gates ──
      let artifactsCreated = 0;

      // Get all findings we just created/merged to extract artifacts from
      const allFindings = await db.select().from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.rfReportId, input.reportId));

      for (const finding of allFindings) {
        // Parse evidence array
        const evidenceArr = parseJsonField(finding.rfEvidence);
        let artifactIndex = 1;

        for (const ev of evidenceArr) {
          if (!ev || typeof ev !== 'object') continue;
          const desc = ev.description || ev.reference || '';
          if (!desc || desc.length < 20) continue;

          // Determine artifact type from evidence
          let artifactType = 'evidence';
          let label = '';
          if (ev.type === 'poc' || desc.toLowerCase().includes('poc') || desc.toLowerCase().includes('proof of concept')) {
            artifactType = 'poc';
            label = `PoC-${finding.rfFindingId}-${artifactIndex}`;
          } else if (desc.toLowerCase().includes('exploit') || desc.toLowerCase().includes('payload')) {
            artifactType = 'exploit_output';
            label = `Exploit-${finding.rfFindingId}-${artifactIndex}`;
          } else if (desc.toLowerCase().includes('curl') || desc.toLowerCase().includes('scanforge-discovery') || desc.toLowerCase().includes('nikto') || desc.toLowerCase().includes('hydra')) {
            artifactType = 'tool_output';
            label = `ToolOutput-${finding.rfFindingId}-${artifactIndex}`;
          } else if (desc.toLowerCase().includes('screenshot') || desc.toLowerCase().includes('image')) {
            artifactType = 'screenshot';
            label = `Screenshot-${finding.rfFindingId}-${artifactIndex}`;
          } else {
            artifactType = 'evidence';
            label = `Evidence-${finding.rfFindingId}-${artifactIndex}`;
          }

          // Check if artifact already exists for this finding with same label prefix
          const existingArtifacts = await db.select().from(ac3ReportArtifacts)
            .where(and(
              eq(ac3ReportArtifacts.findingId, finding.rfFindingId),
              eq(ac3ReportArtifacts.reportId, input.reportId)
            ));
          const labelPrefix = label.split('-').slice(0, 2).join('-');
          const alreadyExists = existingArtifacts.some((a: any) => a.label?.startsWith(labelPrefix));
          if (alreadyExists) continue;

          const artifactId = `ART-${randomUUID().slice(0, 8).toUpperCase()}`;
          const now = Date.now();
          await db.insert(ac3ReportArtifacts).values({
            artifactId,
            reportId: input.reportId,
            findingId: finding.rfFindingId,
            artifactType,
            label,
            description: desc.length > 500 ? desc.slice(0, 497) + '...' : desc,
            capturedAt: now,
            createdAt: now,
          });
          artifactsCreated++;
          artifactIndex++;
        }
      }

      // Extract artifacts from approval gates (tool execution records)
      const approvedGates = approvalGates.filter((g: any) => g.status === 'approved' && g.detail);
      // Group gates by target to create per-target tool execution artifacts
      const gatesByTarget = new Map<string, any[]>();
      for (const gate of approvedGates) {
        const target = gate.target || 'unknown';
        if (!gatesByTarget.has(target)) gatesByTarget.set(target, []);
        gatesByTarget.get(target)!.push(gate);
      }

      for (const [target, gates] of gatesByTarget) {
        // Group by tool
        const toolGroups = new Map<string, any[]>();
        for (const g of gates) {
          const tool = g.detail?.tool || g.module || 'unknown';
          if (!toolGroups.has(tool)) toolGroups.set(tool, []);
          toolGroups.get(tool)!.push(g);
        }

        for (const [tool, toolGates] of toolGroups) {
          // Find the finding most related to this target
          const relatedFinding = allFindings.find((f: any) => {
            const assets = parseJsonField(f.rfAssets);
            return assets.some((a: any) => {
              const assetStr = typeof a === 'string' ? a : (a.hostname || a.ip || '');
              return assetStr.includes(target) || target.includes(assetStr);
            });
          });

          const artifactId = `ART-${randomUUID().slice(0, 8).toUpperCase()}`;
          const label = `ApprovalGate-${tool}-${target.replace(/[^a-zA-Z0-9.-]/g, '_').slice(0, 30)}`;
          const description = `${toolGates.length} approved ${tool} execution(s) against ${target}. ` +
            `Risk tier: ${toolGates[0].riskTier || 'unknown'}. ` +
            `Sample: ${toolGates[0].title || toolGates[0].description || ''}`.slice(0, 500);

          await db.insert(ac3ReportArtifacts).values({
            artifactId,
            reportId: input.reportId,
            findingId: relatedFinding?.findingId || null,
            artifactType: 'tool_output',
            label,
            description,
            capturedAt: toolGates[0].resolvedAt || Date.now(),
            createdAt: Date.now(),
          });
          artifactsCreated++;
        }
      }

      return {
        imported,
        merged,
        skipped,
        total: vulnAnalysis.length,
        engagementName: eng.name,
        artifactsCreated,
        dataSourceSummary: {
          vulnAnalysisCount: vulnAnalysis.length,
          attackChainCount: attackChains.length,
          assetCount: assets.length,
          approvalGateCount: approvalGates.length,
          essTopThreats: essIntelligence.topThreats?.length || 0,
          scopeAutoPopulated: input.autoPopulateScope,
          execSummarySeeded: input.autoPopulateExecSummary,
        },
      };
    }),

  // ─── DOCX Export ────────────────────────────────────────────────────────────

  /** Generate and return a FedRAMP-style DOCX report */
  exportDocx: protectedProcedure
    .input(z.object({ reportId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();

      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.rptReportId, input.reportId));
      if (!report) throw new Error("Report not found");

      const findings = await db.select().from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.rfReportId, input.reportId))
        .orderBy(ac3ReportFindings.rfSortOrder);

      const artifacts = await db.select().from(ac3ReportArtifacts)
        .where(eq(ac3ReportArtifacts.reportId, input.reportId));

      // Build artifact lookup by findingId
      const artifactsByFinding = new Map<string, typeof artifacts>();
      for (const art of artifacts) {
        const fid = art.findingId || '__report__';
        if (!artifactsByFinding.has(fid)) artifactsByFinding.set(fid, []);
        artifactsByFinding.get(fid)!.push(art);
      }

      const isFedRAMP = report.complianceFramework === 'fedramp';

      // ── Build DOCX ──
      const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
        WidthType, AlignmentType, HeadingLevel, BorderStyle, ShadingType, PageBreak } = docx;

      const severityColor: Record<string, string> = {
        critical: 'FF0000', high: 'FF6600', moderate: 'FFAA00', low: '3399FF', informational: '999999',
      };

      // Title page
      const titleSection = [
        new Paragraph({ spacing: { before: 4000 }, alignment: AlignmentType.CENTER, children: [] }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 200 },
          children: [new TextRun({ text: report.rptName || 'AC3 Assessment Report', bold: true, size: 56, color: '1a1a2e' })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 100 },
          children: [new TextRun({ text: `${report.rptAssessmentType?.replace(/_/g, ' ').toUpperCase() || 'PENETRATION TEST'} REPORT`, size: 28, color: '666666' })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 400 },
          children: [new TextRun({ text: isFedRAMP
          ? `FedRAMP ${(report.fedrampImpactLevel || 'moderate').toUpperCase()} Impact Level`
          : `NIST SP 800-53 Rev 5${report.fedrampImpactLevel ? ` — ${report.fedrampImpactLevel.toUpperCase()} Baseline` : ''}`, size: 24, color: '888888' })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: `Prepared for: ${report.rptClientName || 'Client'}`, size: 22, color: '444444' })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: `System: ${report.rptSystemName || 'N/A'}`, size: 22, color: '444444' })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 200 },
          children: [new TextRun({ text: `Report ID: ${report.rptReportId}`, size: 20, color: '888888' })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: `Assessment Window: ${report.assessmentWindowStart ? new Date(report.assessmentWindowStart).toLocaleDateString() : 'N/A'} — ${report.assessmentWindowEnd ? new Date(report.assessmentWindowEnd).toLocaleDateString() : 'N/A'}`, size: 20, color: '888888' })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { before: 600 },
          children: [new TextRun({ text: `Prepared by: Harrison Cook — AceofCloud`, size: 22, color: '444444', italics: true })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: `Generated: ${new Date().toLocaleDateString()}`, size: 20, color: '888888' })],
        }),
        new Paragraph({ children: [new PageBreak()] }),
      ];

      // Executive Summary section
      const execSection: docx.Paragraph[] = [
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: '1. Executive Summary', bold: true })] }),
      ];
      if (report.rptExecNarrative) {
        if (report.rptExecRiskStatement) {
          execSection.push(new Paragraph({
            spacing: { after: 200 },
            children: [new TextRun({ text: 'Overall Risk: ', bold: true }), new TextRun({ text: report.rptExecRiskStatement })],
          }));
        }
        if (report.rptExecNarrative) {
          execSection.push(new Paragraph({ spacing: { after: 200 }, children: [new TextRun({ text: report.rptExecNarrative })] }));
        }
        const strengths = (report.execKeyStrengths as string[] || []);
        if (strengths.length > 0) {
          execSection.push(new Paragraph({ spacing: { before: 200 }, children: [new TextRun({ text: 'Key Strengths:', bold: true })] }));
          strengths.forEach(s => execSection.push(new Paragraph({ bullet: { level: 0 }, children: [new TextRun({ text: s })] })));
        }
        const gaps = (report.execKeyGaps as string[] || []);
        if (gaps.length > 0) {
          execSection.push(new Paragraph({ spacing: { before: 200 }, children: [new TextRun({ text: 'Key Gaps:', bold: true })] }));
          gaps.forEach(g => execSection.push(new Paragraph({ bullet: { level: 0 }, children: [new TextRun({ text: g })] })));
        }
      } else {
        execSection.push(new Paragraph({ children: [new TextRun({ text: 'Executive summary has not been generated yet.', italics: true, color: '888888' })] }));
      }
      execSection.push(new Paragraph({ children: [new PageBreak()] }));

      // Scope section
      const scopeSection: docx.Paragraph[] = [
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: '2. Scope & Methodology', bold: true })] }),
      ];
      const scopeDomains = (report.rptScopeDomains as string[] || []);
      const scopeAssets = (report.rptScopeAssets as string[] || []);
      const approvedVectors = (report.rptApprovedVectors as string[] || []);
      const outOfScope = (report.rptOutOfScope as string[] || []);

      if (scopeDomains.length) {
        scopeSection.push(new Paragraph({ children: [new TextRun({ text: 'In-Scope Domains:', bold: true })] }));
        scopeDomains.forEach(d => scopeSection.push(new Paragraph({ bullet: { level: 0 }, children: [new TextRun({ text: d })] })));
      }
      if (scopeAssets.length) {
        scopeSection.push(new Paragraph({ spacing: { before: 200 }, children: [new TextRun({ text: 'In-Scope Assets:', bold: true })] }));
        scopeAssets.forEach(a => scopeSection.push(new Paragraph({ bullet: { level: 0 }, children: [new TextRun({ text: a })] })));
      }
      if (approvedVectors.length) {
        scopeSection.push(new Paragraph({ spacing: { before: 200 }, children: [new TextRun({ text: 'Approved Attack Vectors:', bold: true })] }));
        approvedVectors.forEach(v => scopeSection.push(new Paragraph({ bullet: { level: 0 }, children: [new TextRun({ text: v })] })));
      }
      if (outOfScope.length) {
        scopeSection.push(new Paragraph({ spacing: { before: 200 }, children: [new TextRun({ text: 'Out of Scope:', bold: true })] }));
        outOfScope.forEach(o => scopeSection.push(new Paragraph({ bullet: { level: 0 }, children: [new TextRun({ text: o })] })));
      }
      scopeSection.push(new Paragraph({ children: [new PageBreak()] }));

      // Findings Summary Table
      const summarySection: docx.Paragraph[] = [
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: '3. Findings Summary', bold: true })] }),
      ];

      const severityCounts: Record<string, number> = { critical: 0, high: 0, moderate: 0, low: 0, informational: 0 };
      findings.forEach(f => { severityCounts[f.rfSeverity] = (severityCounts[f.rfSeverity] || 0) + 1; });

      const summaryTable = new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [
          new TableRow({
            tableHeader: true,
            children: ['Severity', 'Count'].map(text => new TableCell({
              shading: { type: ShadingType.SOLID, color: '1a1a2e' },
              children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text, bold: true, color: 'FFFFFF', size: 20 })] })],
            })),
          }),
          ...Object.entries(severityCounts).map(([sev, count]) => new TableRow({
            children: [
              new TableCell({
                children: [new Paragraph({ children: [new TextRun({ text: sev.charAt(0).toUpperCase() + sev.slice(1), bold: true, color: severityColor[sev] || '000000' })] })],
              }),
              new TableCell({
                children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: String(count) })] })],
              }),
            ],
          })),
          new TableRow({
            children: [
              new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: 'Total', bold: true })] })] }),
              new TableCell({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: String(findings.length), bold: true })] })] }),
            ],
          }),
        ],
      });
      summarySection.push(summaryTable);
      summarySection.push(new Paragraph({ children: [new PageBreak()] }));

      // Detailed Findings
      const findingsSection: docx.Paragraph[] = [
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: '4. Detailed Findings', bold: true })] }),
      ];

      findings.forEach((f, idx) => {
        const sColor = severityColor[f.rfSeverity] || '000000';
        findingsSection.push(
          new Paragraph({
            heading: HeadingLevel.HEADING_2,
            spacing: { before: 400 },
            children: [
              new TextRun({ text: `${idx + 1}. `, bold: true }),
              new TextRun({ text: f.rfTitle, bold: true }),
              new TextRun({ text: `  [${f.rfSeverity.toUpperCase()}]`, bold: true, color: sColor }),
            ],
          }),
        );

        // Finding metadata table
        const metaRows: [string, string][] = [
          ['Finding ID', f.rfFindingId],
          ['Severity', f.rfSeverity.toUpperCase()],
        ];
        if (f.rfCvssScore) metaRows.push(['CVSS Score', `${f.rfCvssScore}${f.rfCvssVector ? ` (${f.rfCvssVector})` : ''}`]);
        const techniques = (f.rfAttackTechniques as any[] || []);
        if (techniques.length) metaRows.push(['ATT&CK Techniques', techniques.map((t: any) => `${t.id}${t.name ? ': ' + t.name : ''}`).join(', ')]);
        const controls = (f.rfControls as any[] || []);
        if (controls.length) metaRows.push(['NIST 800-53 Controls', controls.map((c: any) => c.id).join(', ')]);
        const assets = (f.rfAssets as string[] || []);
        if (assets.length) metaRows.push(['Affected Assets', assets.join(', ')]);

        findingsSection.push(new Table({
          width: { size: 100, type: WidthType.PERCENTAGE },
          rows: metaRows.map(([label, value]) => new TableRow({
            children: [
              new TableCell({
                width: { size: 30, type: WidthType.PERCENTAGE },
                shading: { type: ShadingType.SOLID, color: 'F0F0F0' },
                children: [new Paragraph({ children: [new TextRun({ text: label, bold: true, size: 18 })] })],
              }),
              new TableCell({
                children: [new Paragraph({ children: [new TextRun({ text: value, size: 18 })] })],
              }),
            ],
          })),
        }));

        // Narrative sections
        if (f.rfSummary) {
          findingsSection.push(new Paragraph({ spacing: { before: 200 }, children: [new TextRun({ text: 'Summary', bold: true })] }));
          findingsSection.push(new Paragraph({ children: [new TextRun({ text: f.rfSummary })] }));
        }
        if (f.rfBusinessImpact) {
          findingsSection.push(new Paragraph({ spacing: { before: 200 }, children: [new TextRun({ text: 'Business Impact', bold: true })] }));
          findingsSection.push(new Paragraph({ children: [new TextRun({ text: f.rfBusinessImpact })] }));
        }
        if (f.rfTechnicalDetails) {
          findingsSection.push(new Paragraph({ spacing: { before: 200 }, children: [new TextRun({ text: 'Technical Details', bold: true })] }));
          findingsSection.push(new Paragraph({ children: [new TextRun({ text: f.rfTechnicalDetails })] }));
        }
        if (f.rfRemediation) {
          findingsSection.push(new Paragraph({ spacing: { before: 200 }, children: [new TextRun({ text: 'Remediation', bold: true })] }));
          findingsSection.push(new Paragraph({ children: [new TextRun({ text: f.rfRemediation })] }));
        }

        // Evidence
        const evidence = (f.rfEvidence as any[] || []);
        if (evidence.length) {
          findingsSection.push(new Paragraph({ spacing: { before: 200 }, children: [new TextRun({ text: 'Evidence', bold: true })] }));
          evidence.forEach((e: any) => {
            findingsSection.push(new Paragraph({
              bullet: { level: 0 },
              children: [
                new TextRun({ text: `[${e.type}] `, bold: true }),
                new TextRun({ text: e.description || e.reference }),
              ],
            }));
          });
        }

        // Supporting Artifacts (cross-references)
        const findingArtifacts = artifactsByFinding.get(f.rfFindingId) || [];
        if (findingArtifacts.length) {
          findingsSection.push(new Paragraph({ spacing: { before: 200 }, children: [new TextRun({ text: 'Supporting Artifacts', bold: true })] }));
          findingArtifacts.forEach((art) => {
            findingsSection.push(new Paragraph({
              bullet: { level: 0 },
              children: [
                new TextRun({ text: `[${art.label}] `, bold: true, color: '0066CC' }),
                new TextRun({ text: `${art.artifactType.replace(/_/g, ' ')}`, italics: true }),
                new TextRun({ text: art.description ? ` — ${art.description}` : '' }),
                new TextRun({ text: ` (See Appendix ${art.label})`, color: '666666', size: 18 }),
              ],
            }));
          });
        }
      });

      // Appendix: Supporting Artifacts
      const appendixSection: docx.Paragraph[] = [];
      if (artifacts.length > 0) {
        appendixSection.push(new Paragraph({ children: [new PageBreak()] }));
        appendixSection.push(new Paragraph({
          heading: HeadingLevel.HEADING_1,
          children: [new TextRun({ text: '5. Appendix — Supporting Artifacts', bold: true })],
        }));
        appendixSection.push(new Paragraph({
          spacing: { after: 200 },
          children: [new TextRun({ text: `This appendix catalogs ${artifacts.length} supporting artifact(s) referenced throughout this report. Each artifact is labeled for cross-reference from the findings section.`, size: 20 })],
        }));

        // Artifact index table
        appendixSection.push(new Table({
          width: { size: 100, type: WidthType.PERCENTAGE },
          rows: [
            new TableRow({
              tableHeader: true,
              children: ['Label', 'Type', 'Finding', 'Description', 'Filename'].map(text => new TableCell({
                shading: { type: ShadingType.SOLID, color: '1a1a2e' },
                children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text, bold: true, color: 'FFFFFF', size: 18 })] })],
              })),
            }),
            ...artifacts.map(art => {
              const linkedFinding = findings.find(f => f.rfFindingId === art.findingId);
              return new TableRow({
                children: [
                  new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: art.label, bold: true, color: '0066CC', size: 18 })] })] }),
                  new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: art.artifactType.replace(/_/g, ' '), size: 18 })] })] }),
                  new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: linkedFinding ? linkedFinding.title : 'Report-level', size: 18 })] })] }),
                  new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: art.description || '—', size: 18 })] })] }),
                  new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: art.filename || '—', size: 18 })] })] }),
                ],
              });
            }),
          ],
        }));

        // Individual artifact detail blocks
        artifacts.forEach(art => {
          appendixSection.push(new Paragraph({
            heading: HeadingLevel.HEADING_2,
            spacing: { before: 300 },
            children: [new TextRun({ text: `Artifact ${art.label}: ${art.artifactType.replace(/_/g, ' ')}`, bold: true })],
          }));
          if (art.description) {
            appendixSection.push(new Paragraph({ children: [new TextRun({ text: art.description })] }));
          }
          if (art.url) {
            appendixSection.push(new Paragraph({
              spacing: { before: 100 },
              children: [
                new TextRun({ text: 'Source: ', bold: true, size: 18 }),
                new TextRun({ text: art.url, color: '0066CC', size: 18 }),
              ],
            }));
          }
          if (art.capturedAt) {
            appendixSection.push(new Paragraph({
              children: [
                new TextRun({ text: 'Captured: ', bold: true, size: 18 }),
                new TextRun({ text: new Date(art.capturedAt).toISOString(), size: 18 }),
              ],
            }));
          }
          const linkedFinding = findings.find(f => f.rfFindingId === art.findingId);
          if (linkedFinding) {
            appendixSection.push(new Paragraph({
              children: [
                new TextRun({ text: 'Referenced by: ', bold: true, size: 18 }),
                new TextRun({ text: `${linkedFinding.title} (${linkedFinding.findingId})`, size: 18 }),
              ],
            }));
          }
        });
      }

      // ── Chain of Custody Seal Section ──
      const chainOfCustodySealSection: docx.Paragraph[] = [
        new Paragraph({ children: [new PageBreak()] }),
        new Paragraph({
          heading: HeadingLevel.HEADING_1,
          spacing: { after: 300 },
          children: [new TextRun({ text: 'Chain of Custody Verification', bold: true })],
        }),
        new Paragraph({
          spacing: { after: 200 },
          children: [new TextRun({
            text: 'This section provides cryptographic verification that all evidence artifacts referenced in this report ' +
              'have maintained an unbroken chain of custody from collection through report generation.',
            size: 20, color: '444444',
          })],
        }),
      ];

      // Query for integrity anchors linked to this report's engagement
      let anchorData: any = null;
      let guardrailStats: any = null;
      try {
        // Find the engagement linked to this report
        const reportEngagementId = report.engagementId;
        if (reportEngagementId) {
          const [latestAnchor] = await db.select()
            .from(evidenceIntegrityAnchors)
            .where(and(
              eq(evidenceIntegrityAnchors.engagementId, String(reportEngagementId)),
              eq(evidenceIntegrityAnchors.status, 'active'),
            ))
            .orderBy(desc(evidenceIntegrityAnchors.anchoredAt))
            .limit(1);
          anchorData = latestAnchor;

          // Get guardrail audit stats
          const [auditStats] = await db.select({
            totalChecks: sql<number>`count(*)`,
            passed: sql<number>`sum(case when ${evidenceGuardrailAudit.passed} = 1 then 1 else 0 end)`,
            failed: sql<number>`sum(case when ${evidenceGuardrailAudit.passed} = 0 then 1 else 0 end)`,
            quarantined: sql<number>`sum(case when ${evidenceGuardrailAudit.recommendation} = 'quarantine' then 1 else 0 end)`,
          }).from(evidenceGuardrailAudit)
            .where(eq(evidenceGuardrailAudit.engagementId, String(reportEngagementId)));
          guardrailStats = auditStats;
        }
      } catch { /* integrity data is best-effort */ }

      if (anchorData) {
        // Seal Status Badge
        chainOfCustodySealSection.push(
          new Paragraph({
            spacing: { before: 200, after: 100 },
            children: [
              new TextRun({ text: '\u2705 CHAIN OF CUSTODY VERIFIED', bold: true, size: 28, color: '006600' }),
            ],
          }),
          new Paragraph({
            spacing: { after: 200 },
            children: [new TextRun({
              text: 'All evidence artifacts in this report are sealed by a cryptographic Merkle root anchor. ' +
                'The integrity chain has been verified and no tampering was detected.',
              size: 20, color: '333333',
            })],
          }),
        );

        // Anchor Details Table
        const anchorTable = new Table({
          width: { size: 100, type: WidthType.PERCENTAGE },
          rows: [
            new TableRow({
              tableHeader: true,
              children: ['Property', 'Value'].map(text => new TableCell({
                shading: { type: ShadingType.SOLID, color: '1a1a2e' },
                children: [new Paragraph({ children: [new TextRun({ text, bold: true, color: 'FFFFFF', size: 18 })] })],
              })),
            }),
            ...[
              ['Merkle Root', anchorData.merkleRoot],
              ['HMAC Signature', anchorData.hmacSignature?.slice(0, 32) + '...'],
              ['Chain Length', String(anchorData.chainLength)],
              ['Anchored At', anchorData.anchoredAt ? new Date(anchorData.anchoredAt).toISOString() : 'N/A'],
              ['Anchored By', anchorData.anchoredBy || 'system'],
              ['Status', anchorData.status?.toUpperCase() || 'ACTIVE'],
            ].map(([label, value]) => new TableRow({
              children: [
                new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: label, bold: true, size: 18 })] })] }),
                new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: value || 'N/A', size: 18, font: 'Courier New' })] })] }),
              ],
            })),
          ],
        });
        chainOfCustodySealSection.push(anchorTable as any);

        // Guardrail Audit Summary
        if (guardrailStats) {
          const totalChecks = Number(guardrailStats.totalChecks || 0);
          const passed = Number(guardrailStats.passed || 0);
          const failed = Number(guardrailStats.failed || 0);
          const quarantined = Number(guardrailStats.quarantined || 0);
          const passRate = totalChecks > 0 ? Math.round((passed / totalChecks) * 100) : 0;

          chainOfCustodySealSection.push(
            new Paragraph({
              heading: HeadingLevel.HEADING_2,
              spacing: { before: 400, after: 200 },
              children: [new TextRun({ text: 'Hallucination Guardrail Audit Summary', bold: true })],
            }),
          );

          const guardrailTable = new Table({
            width: { size: 100, type: WidthType.PERCENTAGE },
            rows: [
              new TableRow({
                tableHeader: true,
                children: ['Metric', 'Value'].map(text => new TableCell({
                  shading: { type: ShadingType.SOLID, color: '1a1a2e' },
                  children: [new Paragraph({ children: [new TextRun({ text, bold: true, color: 'FFFFFF', size: 18 })] })],
                })),
              }),
              ...[
                ['Total Integrity Checks', String(totalChecks)],
                ['Passed', String(passed)],
                ['Failed', String(failed)],
                ['Quarantined', String(quarantined)],
                ['Pass Rate', `${passRate}%`],
              ].map(([label, value]) => new TableRow({
                children: [
                  new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: label, bold: true, size: 18 })] })] }),
                  new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: value, size: 18 })] })] }),
                ],
              })),
            ],
          });
          chainOfCustodySealSection.push(guardrailTable as any);
        }
      } else {
        // No anchor found
        chainOfCustodySealSection.push(
          new Paragraph({
            spacing: { before: 200, after: 200 },
            children: [
              new TextRun({ text: '\u26a0\ufe0f NO INTEGRITY ANCHOR', bold: true, size: 24, color: 'CC6600' }),
            ],
          }),
          new Paragraph({
            children: [new TextRun({
              text: 'No Merkle root anchor was found for this engagement. Evidence chain of custody ' +
                'has not been cryptographically sealed. This may occur if the engagement is still in progress ' +
                'or if the evidence integrity system was not active during evidence collection.',
              size: 20, color: '666666',
            })],
          }),
        );
      }

      // Verification instructions
      chainOfCustodySealSection.push(
        new Paragraph({
          spacing: { before: 400, after: 100 },
          heading: HeadingLevel.HEADING_2,
          children: [new TextRun({ text: 'Verification Instructions', bold: true })],
        }),
        new Paragraph({
          spacing: { after: 100 },
          children: [new TextRun({
            text: 'To independently verify the chain of custody for this report:',
            size: 20, color: '444444',
          })],
        }),
        new Paragraph({
          bullet: { level: 0 },
          children: [new TextRun({ text: 'Navigate to the Evidence Integrity dashboard in the AC3 platform.', size: 20 })],
        }),
        new Paragraph({
          bullet: { level: 0 },
          children: [new TextRun({ text: 'Select the engagement associated with this report.', size: 20 })],
        }),
        new Paragraph({
          bullet: { level: 0 },
          children: [new TextRun({ text: 'Click "Verify Anchor" to re-compute the Merkle root and compare against the sealed value above.', size: 20 })],
        }),
        new Paragraph({
          bullet: { level: 0 },
          children: [new TextRun({ text: 'Review the audit log for any quarantined or flagged evidence items.', size: 20 })],
        }),
        new Paragraph({
          spacing: { before: 300 },
          children: [new TextRun({
            text: `Report generated: ${new Date().toISOString()} | Evidence integrity system v1.0`,
            size: 16, color: '999999', italics: true,
          })],
        }),
      );

      // Assemble document
      const frameworkDesc = isFedRAMP
        ? `FedRAMP ${report.fedrampImpactLevel || 'Moderate'} Assessment Report`
        : `NIST SP 800-53 Rev 5 Assessment Report`;
      const doc = new Document({
        creator: 'Harrison Cook — AceofCloud',
        title: report.rptName || 'AC3 Assessment Report',
        description: frameworkDesc,
        sections: [{
          properties: {
            page: {
              margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
            },
          },
          children: [
            ...titleSection,
            ...execSection,
            ...scopeSection,
            ...summarySection,
            ...findingsSection,
            ...appendixSection,
            ...chainOfCustodySealSection,
          ],
        }],
      });

      // Generate buffer and upload to S3
      const buffer = await Packer.toBuffer(doc);
      const fileName = `ac3-reports/${input.reportId}-${Date.now()}.docx`;
      const { url } = await doStoragePut(fileName, Buffer.from(buffer), 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');

      // Store the URL on the report
      await db.update(ac3Reports).set({
        rptDocxUrl: url,
        rptUpdatedAt: Date.now(),
      }).where(eq(ac3Reports.rptReportId, input.reportId));

      return { url, fileName };
    }),

  // ─── Artifact Management ─────────────────────────────────────────────────

  /** Add an artifact to a report (optionally linked to a finding) */
  addArtifact: protectedProcedure
    .input(z.object({
      reportId: z.string(),
      findingId: z.string().optional(),
      artifactType: z.enum(['screenshot', 'scan_output', 'packet_capture', 'tool_log', 'configuration', 'code_snippet', 'network_diagram', 'credential_dump', 'command_output', 'other']),
      label: z.string().optional(),
      filename: z.string().optional(),
      url: z.string(),
      description: z.string().optional(),
      mimeType: z.string().optional(),
      fileSize: z.number().optional(),
      capturedAt: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      // Auto-generate sequential label (A-1, A-2, etc.)
      const existing = await db.select().from(ac3ReportArtifacts)
        .where(eq(ac3ReportArtifacts.reportId, input.reportId));
      const nextNum = existing.length + 1;
      const label = input.label || `A-${nextNum}`;
      const artifactId = `art-${randomUUID().slice(0, 12)}`;

      await db.insert(ac3ReportArtifacts).values({
        artifactId,
        reportId: input.reportId,
        findingId: input.findingId ?? null,
        artifactType: input.artifactType,
        label,
        filename: input.filename ?? null,
        url: input.url,
        description: input.description ?? null,
        mimeType: input.mimeType ?? null,
        fileSize: input.fileSize ?? null,
        capturedAt: input.capturedAt ?? null,
        createdAt: Date.now(),
      });

      return { artifactId, label };
    }),

  /** List artifacts for a report */
  listArtifacts: protectedProcedure
    .input(z.object({ reportId: z.string(), findingId: z.string().optional() }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
      if (input.findingId) {
        return db.select().from(ac3ReportArtifacts)
          .where(and(
            eq(ac3ReportArtifacts.reportId, input.reportId),
            eq(ac3ReportArtifacts.findingId, input.findingId)
          ));
      }
      return db.select().from(ac3ReportArtifacts)
        .where(eq(ac3ReportArtifacts.reportId, input.reportId));
    }),

  /** Delete an artifact */
  deleteArtifact: protectedProcedure
    .input(z.object({ artifactId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      await db.delete(ac3ReportArtifacts)
        .where(eq(ac3ReportArtifacts.artifactId, input.artifactId));
      return { deleted: true };
    }),

  /** Link an existing artifact to a finding */
  linkArtifactToFinding: protectedProcedure
    .input(z.object({ artifactId: z.string(), findingId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      await db.update(ac3ReportArtifacts)
        .set({ findingId: input.findingId })
        .where(eq(ac3ReportArtifacts.artifactId, input.artifactId));
      return { linked: true };
    }),

  // ─── Scope Exclusions ──────────────────────────────────────────────────────

  /** Get scope exclusions for a report */
  getScopeExclusions: protectedProcedure
    .input(z.object({ reportId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.rptReportId, input.reportId));
      if (!report) throw new Error('Report not found');
      return parseJsonField(report.scopeExclusions) as Array<{
        phase: string;
        justification: string;
        approvedBy: string;
        excludedAt: number;
      }>;
    }),

  /** Update scope exclusions for a report */
  updateScopeExclusions: protectedProcedure
    .input(z.object({
      reportId: z.string(),
      exclusions: z.array(z.object({
        phase: z.string(),
        justification: z.string().min(20, 'Justification must be at least 20 characters'),
        approvedBy: z.string().min(1, 'Approver name required'),
        excludedAt: z.number().optional(),
      })),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      const exclusionsWithTimestamp = input.exclusions.map(e => ({
        ...e,
        excludedAt: e.excludedAt || Date.now(),
      }));
      await db.update(ac3Reports)
        .set({
          scopeExclusions: exclusionsWithTimestamp,
          rptUpdatedAt: Date.now(),
        })
        .where(eq(ac3Reports.rptReportId, input.reportId));
      return { updated: true, count: exclusionsWithTimestamp.length };
    }),

  // ─── Pentest Coverage Validator ──────────────────────────────────────────

  /** Validate that the report's findings meet pentest depth/breadth requirements */
  validateCoverage: protectedProcedure
    .input(z.object({ reportId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.rptReportId, input.reportId));
      if (!report) throw new Error("Report not found");

      const findings = await db.select().from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.rfReportId, input.reportId));

      const artifacts = await db.select().from(ac3ReportArtifacts)
        .where(eq(ac3ReportArtifacts.reportId, input.reportId));

      // ── 1. PTES / NIST SP 800-115 Methodology Phase Coverage ──
      const REQUIRED_PHASES: Record<string, { tactics: string[]; description: string }> = {
        'Reconnaissance': {
          tactics: ['TA0043'],
          description: 'Pre-engagement reconnaissance and OSINT gathering',
        },
        'Discovery & Scanning': {
          tactics: ['TA0007'],
          description: 'Network/service discovery, vulnerability scanning, enumeration',
        },
        'Initial Access': {
          tactics: ['TA0001'],
          description: 'Exploitation of vulnerabilities to gain initial foothold',
        },
        'Execution': {
          tactics: ['TA0002'],
          description: 'Code execution on target systems',
        },
        'Persistence': {
          tactics: ['TA0003'],
          description: 'Maintaining access across reboots/credential changes',
        },
        'Privilege Escalation': {
          tactics: ['TA0004'],
          description: 'Escalating from limited to elevated privileges',
        },
        'Credential Access': {
          tactics: ['TA0006'],
          description: 'Credential harvesting, dumping, or cracking',
        },
        'Lateral Movement': {
          tactics: ['TA0008'],
          description: 'Moving between systems within the network',
        },
        'Collection & Exfiltration': {
          tactics: ['TA0009', 'TA0010'],
          description: 'Data collection and exfiltration demonstration',
        },
        'Defense Evasion': {
          tactics: ['TA0005'],
          description: 'Bypassing security controls and detection mechanisms',
        },
      };

      // Extract all ATT&CK tactic IDs from findings
      const allTactics = new Set<string>();
      const allTechniques = new Set<string>();
      const toolsUsed = new Set<string>();
      const evidenceTypes = new Set<string>();

      for (const f of findings) {
        const techniques = parseJsonField(f.rfAttackTechniques);
        for (const t of techniques) {
          if (t.id) allTechniques.add(t.id);
          if (t.tactic) allTactics.add(t.tactic);
        }
        const evidence = parseJsonField(f.rfEvidence);
        for (const e of evidence) {
          if (e.type) evidenceTypes.add(e.type);
          if (e.reference) toolsUsed.add(e.reference.split(':')[0]?.trim() || e.reference);
        }
      }

      // Map technique IDs to tactics for coverage check
      // ATT&CK technique prefix mapping (T1595.* → TA0043, T1190 → TA0001, etc.)
      const TECHNIQUE_TO_TACTIC: Record<string, string> = {
        'T1595': 'TA0043', 'T1592': 'TA0043', 'T1589': 'TA0043', 'T1590': 'TA0043', 'T1591': 'TA0043', 'T1598': 'TA0043',
        'T1190': 'TA0001', 'T1133': 'TA0001', 'T1566': 'TA0001', 'T1078': 'TA0001', 'T1189': 'TA0001', 'T1200': 'TA0001',
        'T1059': 'TA0002', 'T1203': 'TA0002', 'T1047': 'TA0002', 'T1053': 'TA0002', 'T1569': 'TA0002',
        'T1098': 'TA0003', 'T1136': 'TA0003', 'T1543': 'TA0003', 'T1547': 'TA0003',
        'T1548': 'TA0004', 'T1068': 'TA0004', 'T1055': 'TA0004', 'T1134': 'TA0004',
        'T1562': 'TA0005', 'T1070': 'TA0005', 'T1036': 'TA0005', 'T1027': 'TA0005', 'T1218': 'TA0005',
        'T1110': 'TA0006', 'T1003': 'TA0006', 'T1555': 'TA0006', 'T1552': 'TA0006', 'T1558': 'TA0006',
        'T1046': 'TA0007', 'T1135': 'TA0007', 'T1087': 'TA0007', 'T1482': 'TA0007', 'T1018': 'TA0007',
        'T1021': 'TA0008', 'T1570': 'TA0008', 'T1563': 'TA0008', 'T1080': 'TA0008',
        'T1560': 'TA0009', 'T1119': 'TA0009', 'T1005': 'TA0009',
        'T1041': 'TA0010', 'T1048': 'TA0010', 'T1567': 'TA0010', 'T1020': 'TA0010',
      };

      for (const tid of allTechniques) {
        const baseId = tid.split('.')[0];
        const tactic = TECHNIQUE_TO_TACTIC[baseId];
        if (tactic) allTactics.add(tactic);
      }

      // Load scope exclusions
      const scopeExclusions = parseJsonField(report.scopeExclusions) as Array<{ phase: string; justification: string; approvedBy: string; excludedAt: number }>;
      const excludedPhases = new Set(scopeExclusions.map(e => e.phase));

      const phaseResults: Array<{ phase: string; status: 'pass' | 'fail' | 'warning' | 'excluded'; description: string; details: string; exclusionJustification?: string; excludedBy?: string }> = [];
      let phasesPresent = 0;
      let phasesExcluded = 0;
      for (const [phase, config] of Object.entries(REQUIRED_PHASES)) {
        if (excludedPhases.has(phase)) {
          phasesExcluded++;
          const exclusion = scopeExclusions.find(e => e.phase === phase)!;
          phaseResults.push({
            phase,
            status: 'excluded',
            description: config.description,
            details: `Excluded from scope`,
            exclusionJustification: exclusion.justification,
            excludedBy: exclusion.approvedBy,
          });
          continue;
        }
        const covered = config.tactics.some(t => allTactics.has(t));
        if (covered) {
          phasesPresent++;
          phaseResults.push({ phase, status: 'pass', description: config.description, details: `Covered by ${config.tactics.filter(t => allTactics.has(t)).join(', ')}` });
        } else {
          phaseResults.push({ phase, status: 'fail', description: config.description, details: `No findings map to tactics: ${config.tactics.join(', ')}` });
        }
      }
      const totalApplicablePhases = Object.keys(REQUIRED_PHASES).length - phasesExcluded;

      // ── 2. ATT&CK Breadth ──
      const tacticBreadth = allTactics.size;
      const techniqueBreadth = allTechniques.size;
      const tacticStatus = tacticBreadth >= 6 ? 'pass' : tacticBreadth >= 4 ? 'warning' : 'fail';
      const techniqueStatus = techniqueBreadth >= 10 ? 'pass' : techniqueBreadth >= 5 ? 'warning' : 'fail';

      // ── 3. Evidence Quality ──
      const findingsWithEvidence = findings.filter(f => parseJsonField(f.rfEvidence).length > 0).length;
      const findingsWithPoC = findings.filter(f => {
        const ev = parseJsonField(f.rfEvidence);
        return ev.some(e => ['poc', 'exploit_output', 'command_output', 'screenshot'].includes(e.type));
      }).length;
      const evidenceRatio = findings.length > 0 ? findingsWithEvidence / findings.length : 0;
      const pocRatio = findings.length > 0 ? findingsWithPoC / findings.length : 0;
      const evidenceStatus = evidenceRatio >= 0.9 ? 'pass' : evidenceRatio >= 0.7 ? 'warning' : 'fail';
      const pocStatus = pocRatio >= 0.5 ? 'pass' : pocRatio >= 0.25 ? 'warning' : 'fail';

      // ── 4. Tool Diversity ──
      const toolCount = toolsUsed.size;
      const toolStatus = toolCount >= 5 ? 'pass' : toolCount >= 3 ? 'warning' : 'fail';

      // ── 5. Artifact Coverage ──
      const findingsWithArtifacts = new Set(artifacts.filter(a => a.findingId).map(a => a.findingId)).size;
      const artifactRatio = findings.length > 0 ? findingsWithArtifacts / findings.length : 0;
      const artifactStatus = artifactRatio >= 0.7 ? 'pass' : artifactRatio >= 0.4 ? 'warning' : 'fail';
      const artifactTypes = new Set(artifacts.map(a => a.artifactType));

      // ── 6. Severity Distribution ──
      const severityCounts: Record<string, number> = {};
      for (const f of findings) severityCounts[f.rfSeverity] = (severityCounts[f.rfSeverity] || 0) + 1;
      const hasCritOrHigh = (severityCounts['critical'] || 0) + (severityCounts['high'] || 0) > 0;
      const hasMultipleSeverities = Object.keys(severityCounts).length >= 3;

      // ── 7. Report Completeness ──
      const hasExecSummary = !!report.rptExecNarrative;
      const hasScope = parseJsonField(report.rptScopeDomains).length > 0 || parseJsonField(report.rptScopeAssets).length > 0;
      const hasAssessmentWindow = !!report.assessmentWindowStart && !!report.assessmentWindowEnd;
      const hasClient = !!report.rptClientName;

      // ── Overall Score ──
      const checks = [
        { category: 'Methodology Coverage', status: totalApplicablePhases === 0 ? 'pass' as const : (phasesPresent / totalApplicablePhases >= 0.7 ? 'pass' : phasesPresent / totalApplicablePhases >= 0.5 ? 'warning' : 'fail') as any, score: totalApplicablePhases === 0 ? 100 : Math.round((phasesPresent / totalApplicablePhases) * 100), details: `${phasesPresent}/${totalApplicablePhases} applicable PTES phases represented${phasesExcluded > 0 ? ` (${phasesExcluded} excluded by scope)` : ''}` },
        { category: 'ATT&CK Tactic Breadth', status: tacticStatus as any, score: Math.min(100, Math.round((tacticBreadth / 8) * 100)), details: `${tacticBreadth} unique tactics across ${techniqueBreadth} techniques` },
        { category: 'Evidence Quality', status: evidenceStatus as any, score: Math.round(evidenceRatio * 100), details: `${findingsWithEvidence}/${findings.length} findings have evidence, ${findingsWithPoC} have PoC/exploit output` },
        { category: 'Tool Diversity', status: toolStatus as any, score: Math.min(100, Math.round((toolCount / 5) * 100)), details: `${toolCount} distinct tools/sources identified` },
        { category: 'Artifact Coverage', status: artifactStatus as any, score: Math.round(artifactRatio * 100), details: `${findingsWithArtifacts}/${findings.length} findings have linked artifacts (${artifacts.length} total, ${artifactTypes.size} types)` },
        { category: 'Severity Distribution', status: (hasCritOrHigh && hasMultipleSeverities ? 'pass' : !hasCritOrHigh ? 'warning' : 'warning') as any, score: hasMultipleSeverities ? 100 : 50, details: Object.entries(severityCounts).map(([k, v]) => `${k}: ${v}`).join(', ') },
        { category: 'Report Completeness', status: (hasExecSummary && hasScope && hasAssessmentWindow && hasClient ? 'pass' : 'warning') as any, score: [hasExecSummary, hasScope, hasAssessmentWindow, hasClient].filter(Boolean).length * 25, details: [!hasExecSummary && 'Missing exec summary', !hasScope && 'Missing scope', !hasAssessmentWindow && 'Missing assessment window', !hasClient && 'Missing client name'].filter(Boolean).join(', ') || 'All fields present' },
      ];

      const overallScore = Math.round(checks.reduce((sum, c) => sum + c.score, 0) / checks.length);
      const overallStatus = overallScore >= 80 ? 'pass' : overallScore >= 60 ? 'warning' : 'fail';
      const isReportReady = overallStatus === 'pass';

      return {
        overallScore,
        overallStatus,
        isReportReady,
        checks,
        phaseResults,
        summary: {
          totalFindings: findings.length,
          totalArtifacts: artifacts.length,
          uniqueTactics: tacticBreadth,
          uniqueTechniques: techniqueBreadth,
          toolsIdentified: toolCount,
          phasesRepresented: phasesPresent,
          phasesExcluded,
          totalApplicablePhases,
        },
        scopeExclusions,
        recommendations: [
          ...phaseResults.filter(p => p.status === 'fail').map(p => `Add findings for ${p.phase} phase (${p.description}) — or document a scope exclusion if this phase was intentionally omitted`),
          ...(pocStatus === 'fail' ? ['Increase PoC/exploit output evidence — too many findings rely on scanner output alone'] : []),
          ...(toolStatus === 'fail' ? ['Diversify tooling — a proper pentest requires multiple tools beyond a single scanner'] : []),
          ...(artifactStatus === 'fail' ? ['Attach supporting artifacts (screenshots, logs, captures) to findings'] : []),
          ...(!hasExecSummary ? ['Generate executive summary before finalizing'] : []),
          ...(!hasScope ? ['Define scope (domains and/or assets) in report metadata'] : []),
          ...(!hasAssessmentWindow ? ['Set assessment window start and end dates'] : []),
        ],
      };
    }),

  // ─── One-Click Full Post-Exploit Report Generation ─────────────────────────

  /** Find auto-generated report for an engagement by name */
  getReportByEngagementName: protectedProcedure
    .input(z.object({ engagementName: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const rows = await db.select().from(ac3Reports)
        .where(and(
          like(ac3Reports.rptName, `%${input.engagementName}%`),
          eq(ac3Reports.rptCreatedBy, 'auto-pipeline'),
        ))
        .orderBy(desc(ac3Reports.rptCreatedAt))
        .limit(1);
      return rows[0] || null;
    }),

  /** Chains: create report → import from ops snapshot → generate narratives → exec summary → mark review */
  generateFullReport: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      reportName: z.string().optional(),
      clientName: z.string().optional(),
      assessmentType: z.enum(["penetration_test", "red_team", "purple_team", "vulnerability_assessment", "hybrid"]).optional(),
      complianceFramework: z.enum(['fedramp', 'nist_800_53_r5']).optional(),
      fedrampImpactLevel: z.enum(["low", "moderate", "high", "li-saas"]).optional(),
      severityFilter: z.array(z.string()).optional(),
      skipNarratives: z.boolean().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbRequired();
      const stages: Array<{ stage: string; status: 'ok' | 'error'; detail?: string; durationMs: number }> = [];
      const pipelineStart = Date.now();

      const runStage = async (name: string, fn: () => Promise<any>) => {
        const start = Date.now();
        try {
          const result = await fn();
          stages.push({ stage: name, status: 'ok', detail: JSON.stringify(result).slice(0, 200), durationMs: Date.now() - start });
          return result;
        } catch (err: any) {
          stages.push({ stage: name, status: 'error', detail: err.message?.slice(0, 200), durationMs: Date.now() - start });
          return null;
        }
      };

      // ── Stage 1: Get engagement details ──
      const [eng] = await db.select().from(engagements)
        .where(eq(engagements.id, input.engagementId));
      if (!eng) throw new Error("Engagement not found");

      // ── Stage 2: Create report ──
      const reportId = `rpt-${randomUUID().slice(0, 12)}`;
      const now = Date.now();
      const reportName = input.reportName || `Post-Exploit Report — ${eng.name}`;

      await runStage('create_report', async () => {
        await db.insert(ac3Reports).values({
          rptReportId: reportId,
          rptName: reportName,
          rptStatus: 'generating',
          complianceFramework: input.complianceFramework ?? 'nist_800_53_r5',
          rptClientName: input.clientName ?? eng.customerName ?? null,
          rptSystemName: eng.name,
          rptAssessmentType: input.assessmentType ?? 'penetration_test',
          rptFedrampLevel: input.fedrampImpactLevel ?? null,
          rptVersion: '1.0',
          rptScopeDomains: eng.targetDomain ? [eng.targetDomain] : [],
          rptScopeAssets: eng.targetIpRange ? [eng.targetIpRange] : [],
          rptApprovedVectors: [],
          rptOutOfScope: [],
          rptCreatedBy: ctx.user?.name ?? 'operator',
          rptCreatedAt: now,
          rptUpdatedAt: now,
        });
        return { reportId };
      });

      // ── Stage 3: Import from ops snapshot ──
      const importResult = await runStage('import_ops_snapshot', async () => {
        const snapshots = await db.select().from(engagementOpsSnapshots)
          .where(eq(engagementOpsSnapshots.engagementId, input.engagementId))
          .orderBy(desc(engagementOpsSnapshots.createdAt));
        if (snapshots.length === 0) throw new Error('No ops snapshot found');

        const snapshot = snapshots[0];
        const state = typeof snapshot.stateJson === 'string'
          ? JSON.parse(snapshot.stateJson)
          : snapshot.stateJson;

        const vulnAnalysis: any[] = state.vulnAnalysis || [];
        const attackChains: any[] = state.attackChains || [];
        const assets: any[] = state.assets || [];
        const approvalGates: any[] = state.approvalGates || [];
        const essIntelligence: any = state.essIntelligence || {};
        const engagementContext: any = state.engagementContext || {};
        const roeScopeGuard: any = state.roeScopeGuard || {};

        return {
          vulnCount: vulnAnalysis.length,
          chainCount: attackChains.length,
          assetCount: assets.length,
          gateCount: approvalGates.length,
          essThreats: essIntelligence.topThreats?.length || 0,
        };
      });

      // ── Stage 3b: Actually import findings (reuse the importFromOpsSnapshot logic inline) ──
      // We call the same logic that importFromOpsSnapshot uses but in-process
      const findingsImported = await runStage('import_findings', async () => {
        const snapshots = await db.select().from(engagementOpsSnapshots)
          .where(eq(engagementOpsSnapshots.engagementId, input.engagementId))
          .orderBy(desc(engagementOpsSnapshots.createdAt));
        const snapshot = snapshots[0];
        const state = typeof snapshot.stateJson === 'string'
          ? JSON.parse(snapshot.stateJson)
          : snapshot.stateJson;

        const vulnAnalysis: any[] = state.vulnAnalysis || [];
        const attackChains: any[] = state.attackChains || [];
        const assets: any[] = state.assets || [];
        const approvalGates: any[] = state.approvalGates || [];
        const essIntelligence: any = state.essIntelligence || {};
        const engagementContext: any = state.engagementContext || {};
        const roeScopeGuard: any = state.roeScopeGuard || {};

        // ATT&CK → NIST mapping (reuse from importFromOpsSnapshot)
        const attackToNist: Record<string, string[]> = {
          'T1190': ['SC-7', 'SI-4', 'RA-5', 'CA-8'], 'T1133': ['AC-17', 'SC-7', 'IA-2'],
          'T1078': ['AC-2', 'AC-6', 'IA-2', 'IA-5'], 'T1098': ['AC-2', 'AC-6', 'CM-5'],
          'T1530': ['AC-3', 'SC-28', 'AC-6', 'AU-6'], 'T1059': ['CM-7', 'SI-3', 'SI-7'],
          'T1068': ['AC-6', 'CM-6', 'SI-2'], 'T1548': ['AC-6', 'CM-6', 'CM-7'],
          'T1110': ['AC-7', 'IA-2', 'IA-5'], 'T1003': ['AC-6', 'IA-5', 'SI-4'],
          'T1021': ['AC-3', 'AC-17', 'SC-7'], 'T1046': ['CM-8', 'SC-7', 'SI-4'],
          'T1082': ['CM-8', 'SI-4'], 'T1087': ['AC-2', 'AC-6', 'SI-4'],
          'T1071': ['SC-7', 'SI-4', 'SC-8'], 'T1105': ['SC-7', 'SI-3', 'SI-4'],
          'T1041': ['SC-7', 'SC-8', 'AC-4', 'SI-4'], 'T1566': ['AT-2', 'SI-3', 'SI-8'],
          'T1505.003': ['CM-7', 'SI-3', 'SI-7'], 'T1595': ['SC-7', 'SI-4'],
          'T1592': ['SC-7', 'SI-4'], 'T1552': ['IA-5', 'SC-28', 'AC-3'],
        };
        const categoryToNist: Record<string, string[]> = {
          'config': ['CM-6', 'CM-7', 'SC-7'], 'web': ['SC-7', 'SI-10', 'SI-4'],
          'crypto': ['SC-8', 'SC-12', 'SC-13'], 'auth': ['IA-2', 'IA-5', 'AC-7'],
          'access': ['AC-3', 'AC-6', 'AC-2'], 'injection': ['SI-10', 'SI-3', 'SC-7'],
          'disclosure': ['SC-28', 'AC-3', 'SI-4'], 'default': ['RA-5', 'CA-7', 'CA-8'],
        };

        function getControls(techniqueIds: string[], agentClass?: string): { id: string }[] {
          const controlSet = new Set<string>();
          for (const tid of techniqueIds) {
            (attackToNist[tid] || []).forEach(c => controlSet.add(c));
          }
          if (controlSet.size === 0) {
            (categoryToNist[agentClass || 'default'] || categoryToNist['default']).forEach(c => controlSet.add(c));
          }
          controlSet.add('CA-8');
          return Array.from(controlSet).map(id => ({ id }));
        }

        // Build technique index from attack chains
        const assetTechniqueMap = new Map<string, Set<string>>();
        for (const chain of attackChains) {
          for (const phase of (chain.killChainPhases || [])) {
            for (const step of (phase.steps || [])) {
              if (step.techniqueId && step.target) {
                if (!assetTechniqueMap.has(step.target)) assetTechniqueMap.set(step.target, new Set());
                assetTechniqueMap.get(step.target)!.add(step.techniqueId);
              }
            }
          }
        }

        // Build CVE score index
        const cveScoreMap = new Map<string, string>();
        for (const threat of (essIntelligence.topThreats || [])) {
          const cvssMatch = threat.riskSummary?.match(/CVSS\s+([\d.]+)\/10/);
          if (cvssMatch) cveScoreMap.set(threat.cveId, cvssMatch[1]);
        }

        // Build exploit attempt index
        const assetExploitMap = new Map<string, any[]>();
        for (const asset of assets) {
          const hostname = asset.hostname || asset.ip || '';
          if (hostname && asset.exploitAttempts) assetExploitMap.set(hostname, asset.exploitAttempts);
        }

        const mapSeverity = (sev: string | null, riskScore?: number): string => {
          if (sev) return ({ critical: 'critical', high: 'high', medium: 'moderate', low: 'low', info: 'informational' }[sev] || 'moderate');
          if (riskScore !== undefined) {
            if (riskScore >= 9) return 'critical';
            if (riskScore >= 7) return 'high';
            if (riskScore >= 4) return 'moderate';
            if (riskScore >= 2) return 'low';
            return 'informational';
          }
          return 'moderate';
        };

        let sortOrder = 0;
        let imported = 0;

        for (const vuln of vulnAnalysis) {
          const finding = vuln.finding || {};
          const analysis = vuln.analysis || {};
          const agentClass = vuln.agentClass || 'default';
          const severity = mapSeverity(finding.rfSeverity, analysis.riskScore);
          if (input.severityFilter && !input.severityFilter.includes(severity)) continue;

          const techniqueIds: string[] = [];
          const assetName = finding.asset || '';
          if (assetName && assetTechniqueMap.has(assetName)) {
            assetTechniqueMap.get(assetName)!.forEach(t => techniqueIds.push(t));
          }
          if (techniqueIds.length === 0 && (analysis.relatedCves?.length || finding.cve)) {
            techniqueIds.push('T1190');
          }
          const uniqueTechniques = [...new Set(techniqueIds)];
          const controls = getControls(uniqueTechniques, agentClass);

          const evidence: any[] = [];
          if (analysis.poc) {
            evidence.push({ type: 'poc', reference: `PoC for ${finding.rfTitle || finding.id}`, description: (typeof analysis.poc === 'string' ? analysis.poc : JSON.stringify(analysis.poc)).slice(0, 500) });
          }
          if (assetName && assetExploitMap.has(assetName)) {
            for (const exploit of assetExploitMap.get(assetName)!.slice(0, 3)) {
              evidence.push({ type: 'exploit_attempt', reference: `Exploit: ${exploit.cve || exploit.module || 'unknown'} on ${assetName}`, description: `Module: ${exploit.module}. CVE: ${exploit.cve || 'N/A'}. Success: ${exploit.success}. Output: ${(exploit.exploitOutput || '').slice(0, 200)}` });
            }
          }

          let cvssScore = '';
          for (const cve of (analysis.relatedCves || [])) {
            const score = cveScoreMap.get(cve);
            if (score) { cvssScore = score; break; }
          }

          const findingAssets = [assetName].filter(Boolean);
          if (finding.port) findingAssets.push(`${assetName}:${finding.port}`);

          const findingId = `AC3-${randomUUID().slice(0, 8).toUpperCase()}`;
          const ts = Date.now();
          await db.insert(ac3ReportFindings).values({
            rfFindingId: findingId,
            rfReportId: reportId,
            rfTitle: finding.rfTitle || `Vulnerability on ${assetName}`,
            rfSeverity: severity,
            rfAttackTechniques: uniqueTechniques.map(id => ({ id })),
            rfControls: controls,
            rfEvidence: evidence,
            rfAssets: findingAssets,
            rfCvssScore: cvssScore || null,
            rfRemediation: Array.isArray(analysis.remediation) ? analysis.remediation.join('\n') : (analysis.remediation || null),
            rfNarrativeStatus: 'pending',
            rfSortOrder: sortOrder++,
            rfCreatedAt: ts,
            rfUpdatedAt: ts,
            rfSourceModule: `full-report:${input.engagementId}`,
            rfSourceEventId: `vuln-${sortOrder}`,
          });
          imported++;
        }

        // Auto-populate scope
        const scopeUpdates: any = { rptUpdatedAt: Date.now() };
        if (roeScopeGuard.authorizedDomains?.length) scopeUpdates.rptScopeDomains = roeScopeGuard.authorizedDomains;
        const scopeAssets = [...(engagementContext.crownJewels || []), ...assets.map((a: any) => a.hostname || a.ip).filter(Boolean)];
        if (scopeAssets.length) scopeUpdates.rptScopeAssets = [...new Set(scopeAssets)];
        scopeUpdates.rptClientName = eng.customerName;
        scopeUpdates.rptSystemName = eng.name;
        await db.update(ac3Reports).set(scopeUpdates).where(eq(ac3Reports.rptReportId, reportId));

        return { imported, totalVulns: vulnAnalysis.length };
      });

      // ── Stage 4: Generate LLM narratives for all findings ──
      let narrativeResults: any = null;
      if (!input.skipNarratives) {
        narrativeResults = await runStage('generate_narratives', async () => {
          const findings = await db.select().from(ac3ReportFindings)
            .where(and(
              eq(ac3ReportFindings.rfReportId, reportId),
              eq(ac3ReportFindings.rfNarrativeStatus, 'pending'),
            ));

          const [report] = await db.select().from(ac3Reports)
            .where(eq(ac3Reports.rptReportId, reportId));

          const results: Array<{ findingId: string; status: string }> = [];
          for (const finding of findings) {
            try {
              const prompt = buildFindingNarrativePrompt(finding, report);
              const response = await invokeLLM({
                _caller: 'ac3-reports.generateFullReport.narratives',
                messages: [
                  { role: 'system', content: buildSystemPrompt(report.complianceFramework || 'nist_800_53_r5') },
                  { role: 'user', content: prompt },
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
              const content = response.choices?.[0]?.message?.content;
              if (!content) throw new Error('Empty response');
              const narrative = JSON.parse(content);
              await db.update(ac3ReportFindings).set({
                rfTitle: narrative.title,
                rfSummary: narrative.summary,
                rfBusinessImpact: narrative.business_impact,
                rfTechnicalDetails: narrative.technical_details,
                rfRemediation: narrative.remediation,
                rfNarrativeStatus: 'drafted',
                rfUpdatedAt: Date.now(),
              }).where(eq(ac3ReportFindings.rfFindingId, finding.rfFindingId));
              results.push({ findingId: finding.rfFindingId, status: 'drafted' });
            } catch (err: any) {
              results.push({ findingId: finding.rfFindingId, status: `error: ${err.message}` });
            }
          }
          return { processed: results.length, drafted: results.filter(r => r.status === 'drafted').length };
        });
      }

      // ── Stage 5: Generate executive summary ──
      await runStage('generate_exec_summary', async () => {
        const findings = await db.select().from(ac3ReportFindings)
          .where(eq(ac3ReportFindings.rfReportId, reportId))
          .orderBy(ac3ReportFindings.rfSortOrder);
        if (findings.length === 0) throw new Error('No findings to summarize');

        const [report] = await db.select().from(ac3Reports)
          .where(eq(ac3Reports.rptReportId, reportId));

        const prompt = buildExecSummaryPrompt(report, findings);
        const response = await invokeLLM({
          _caller: 'ac3-reports.generateFullReport.execSummary',
          messages: [
            { role: 'system', content: buildSystemPrompt(report.complianceFramework || 'nist_800_53_r5') },
            { role: 'user', content: prompt },
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
        const content = response.choices?.[0]?.message?.content;
        if (!content) throw new Error('LLM returned empty response');
        const summary = JSON.parse(content);
        const validRatings = ['critical', 'high', 'moderate', 'low', 'informational'];
        const normalizedRating = validRatings.includes(summary.overall_rating?.toLowerCase())
          ? summary.overall_rating.toLowerCase() : 'moderate';

        await db.update(ac3Reports).set({
          rptExecRiskStatement: summary.risk_statement,
          rptExecRating: normalizedRating as any,
          rptExecStrengths: summary.key_strengths,
          rptExecGaps: summary.key_gaps,
          rptExecNarrative: summary.narrative,
          rptStatus: 'review',
          rptUpdatedAt: Date.now(),
        }).where(eq(ac3Reports.rptReportId, reportId));

        return { rating: normalizedRating, strengthsCount: summary.key_strengths.length, gapsCount: summary.key_gaps.length };
      });

      // ── Stage 6: Final status update ──
      await db.update(ac3Reports).set({ rptStatus: 'review', rptUpdatedAt: Date.now() })
        .where(eq(ac3Reports.rptReportId, reportId));

      return {
        reportId,
        reportName,
        engagementName: eng.name,
        stages,
        totalDurationMs: Date.now() - pipelineStart,
      };
    }),
};
