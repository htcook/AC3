import { z } from "zod";
import { protectedProcedure } from "../_core/trpc";
import { getDbRequired } from "../db";
import { ac3Reports, ac3ReportFindings, engagements, engagementTimelineEvents, atomicTestExecutions, atomicTests } from "../../drizzle/schema";
import { eq, desc, and, sql, inArray } from "drizzle-orm";
import { randomUUID } from "crypto";
import { invokeLLM } from "../_core/llm";
import { storagePut } from "../storage";
import { ENV } from "../_core/env";
import * as docx from "docx";

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

const SYSTEM_PROMPT = `You are the AC3 security report writer. Your job is to convert structured assessment data into professional, audit-defensible penetration test and red team reporting.

## Operating rules
- Write in a calm, precise, professional consulting tone.
- Produce evidence-backed narratives only. Do not invent assets, dates, screenshots, logs, controls, or impact.
- Use high-level reproduction language only. Never include exploit code, malware instructions, payloads, or step-by-step offensive procedures.
- Keep executive summaries concise and business-readable.
- Keep technical sections explicit, structured, and internally consistent.
- Every finding must include: title, severity, summary, business impact, technical details, evidence references, ATT&CK mapping, control mapping, remediation.
- When facts are missing, state that additional evidence is required rather than guessing.

## FedRAMP-aware style rules
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

function buildFindingNarrativePrompt(finding: any, metadata: any): string {
  return `Generate professional narrative fields for this security finding. The platform provides the severity, evidence, ATT&CK IDs, and control mappings as source of truth. You are drafting ONLY the narrative text fields.

## Assessment Context
- Client: ${metadata.clientName || "Not specified"}
- System: ${metadata.systemName || "Not specified"}
- Assessment Type: ${metadata.assessmentType || "penetration_test"}
- FedRAMP Impact Level: ${metadata.fedrampImpactLevel || "moderate"}

## Finding Data (Platform Source of Truth - DO NOT modify these)
- Finding ID: ${finding.findingId}
- Severity: ${finding.severity} — ${SEVERITY_RUBRIC[finding.severity as keyof typeof SEVERITY_RUBRIC] || ""}
- Evidence: ${JSON.stringify(finding.evidence || [])}
- ATT&CK Techniques: ${JSON.stringify(finding.attackTechniques || [])}
- NIST 800-53 Controls: ${JSON.stringify(finding.controls || [])}
- Affected Assets: ${JSON.stringify(finding.assets || [])}
${finding.cvssScore ? `- CVSS Score: ${finding.cvssScore}` : ""}
${finding.cvssVector ? `- CVSS Vector: ${finding.cvssVector}` : ""}

## Source Context
${finding.sourceContext || "No additional context provided."}

## Task
Draft the following narrative fields. Be precise, evidence-backed, and FedRAMP-appropriate:

Return strict JSON:
{
  "title": "A concise, descriptive finding title",
  "summary": "2-3 sentence finding summary for the findings table",
  "business_impact": "Business impact paragraph explaining organizational risk",
  "technical_details": "Technical details paragraph with high-level reproduction steps (no exploit code)",
  "remediation": "Specific, actionable remediation recommendations"
}`;
}

function buildExecSummaryPrompt(reportData: any, findings: any[]): string {
  const severityCounts = findings.reduce((acc: any, f: any) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  return `Generate a one-page executive summary for this security assessment report.

## Assessment Metadata
- Client: ${reportData.clientName || "Not specified"}
- System: ${reportData.systemName || "Not specified"}
- Assessment Type: ${reportData.assessmentType || "penetration_test"}
- FedRAMP Impact Level: ${reportData.fedrampImpactLevel || "moderate"}
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
${findings.map((f, i) => `${i + 1}. [${f.severity.toUpperCase()}] ${f.title}`).join("\n")}

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
  id: f.findingId,
  title: f.title,
  severity: f.severity,
  summary: f.summary,
  business_impact: f.businessImpact,
  technical_details: f.technicalDetails,
  evidence: f.evidence,
  attack_techniques: f.attackTechniques,
  controls: f.controls,
  remediation: f.remediation,
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
  listReports: protectedProcedure.query(async () => {
    const db = await getDbRequired();
    const rows = await db.select().from(ac3Reports).orderBy(desc(ac3Reports.updatedAt));
    return rows;
  }),

  // Get a single report with findings
  getReport: protectedProcedure
    .input(z.object({ reportId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.reportId, input.reportId));
      if (!report) return null;

      const findings = await db.select().from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.reportId, input.reportId))
        .orderBy(ac3ReportFindings.sortOrder);

      return { ...report, findings };
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
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbRequired();
      const now = Date.now();
      const reportId = `rpt-${randomUUID().slice(0, 12)}`;

      await db.insert(ac3Reports).values({
        reportId,
        name: input.name,
        status: "draft",
        clientName: input.clientName ?? null,
        systemName: input.systemName ?? null,
        assessmentType: input.assessmentType ?? "penetration_test",
        fedrampImpactLevel: input.fedrampImpactLevel ?? null,
        cloudProvider: input.cloudProvider ?? null,
        serviceModel: input.serviceModel ?? null,
        assessmentWindowStart: input.assessmentWindowStart ?? null,
        assessmentWindowEnd: input.assessmentWindowEnd ?? null,
        reportVersion: "1.0",
        scopeDomains: input.scopeDomains ?? [],
        scopeAssets: input.scopeAssets ?? [],
        approvedVectors: input.approvedVectors ?? [],
        outOfScope: input.outOfScope ?? [],
        campaignId: input.campaignId ?? null,
        createdBy: ctx.user?.name ?? "operator",
        createdAt: now,
        updatedAt: now,
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
    }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      const now = Date.now();
      const updates: any = { updatedAt: now };

      if (input.name !== undefined) updates.name = input.name;
      if (input.clientName !== undefined) updates.clientName = input.clientName;
      if (input.systemName !== undefined) updates.systemName = input.systemName;
      if (input.assessmentType !== undefined) updates.assessmentType = input.assessmentType;
      if (input.fedrampImpactLevel !== undefined) updates.fedrampImpactLevel = input.fedrampImpactLevel;
      if (input.cloudProvider !== undefined) updates.cloudProvider = input.cloudProvider;
      if (input.serviceModel !== undefined) updates.serviceModel = input.serviceModel;
      if (input.assessmentWindowStart !== undefined) updates.assessmentWindowStart = input.assessmentWindowStart;
      if (input.assessmentWindowEnd !== undefined) updates.assessmentWindowEnd = input.assessmentWindowEnd;
      if (input.scopeDomains !== undefined) updates.scopeDomains = input.scopeDomains;
      if (input.scopeAssets !== undefined) updates.scopeAssets = input.scopeAssets;
      if (input.approvedVectors !== undefined) updates.approvedVectors = input.approvedVectors;
      if (input.outOfScope !== undefined) updates.outOfScope = input.outOfScope;
      if (input.status !== undefined) updates.status = input.status;

      await db.update(ac3Reports).set(updates)
        .where(eq(ac3Reports.reportId, input.reportId));

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
        .where(eq(ac3ReportFindings.reportId, input.reportId));
      const sortOrder = Number(existing[0]?.count ?? 0);

      await db.insert(ac3ReportFindings).values({
        findingId,
        reportId: input.reportId,
        sortOrder,
        severity: input.severity,
        title: input.title,
        evidence: input.evidence ?? [],
        attackTechniques: input.attackTechniques ?? [],
        controls: enrichedControls,
        assets: input.assets ?? [],
        cvssScore: input.cvssScore ?? null,
        cvssVector: input.cvssVector ?? null,
        summary: input.summary ?? null,
        businessImpact: input.businessImpact ?? null,
        technicalDetails: input.technicalDetails ?? null,
        remediation: input.remediation ?? null,
        sourceTaskId: input.sourceTaskId ?? null,
        sourceCampaignId: input.sourceCampaignId ?? null,
        sourceAgentId: input.sourceAgentId ?? null,
        narrativeStatus: (input.summary && input.businessImpact) ? "drafted" : "pending",
        createdAt: now,
        updatedAt: now,
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
      const updates: any = { updatedAt: now };

      if (input.severity !== undefined) updates.severity = input.severity;
      if (input.title !== undefined) updates.title = input.title;
      if (input.evidence !== undefined) updates.evidence = input.evidence;
      if (input.attackTechniques !== undefined) updates.attackTechniques = input.attackTechniques;
      if (input.controls !== undefined) {
        updates.controls = input.controls.map(c => ({
          ...c,
          family: c.family || NIST_CONTROL_FAMILIES[c.id.split("-")[0]] || undefined,
        }));
      }
      if (input.assets !== undefined) updates.assets = input.assets;
      if (input.cvssScore !== undefined) updates.cvssScore = input.cvssScore;
      if (input.cvssVector !== undefined) updates.cvssVector = input.cvssVector;
      if (input.summary !== undefined) updates.summary = input.summary;
      if (input.businessImpact !== undefined) updates.businessImpact = input.businessImpact;
      if (input.technicalDetails !== undefined) updates.technicalDetails = input.technicalDetails;
      if (input.remediation !== undefined) updates.remediation = input.remediation;
      if (input.narrativeStatus !== undefined) {
        updates.narrativeStatus = input.narrativeStatus;
        if (input.narrativeStatus === "reviewed" || input.narrativeStatus === "approved") {
          updates.reviewedBy = ctx.user?.name ?? "operator";
          updates.reviewedAt = now;
        }
      }

      await db.update(ac3ReportFindings).set(updates)
        .where(eq(ac3ReportFindings.findingId, input.findingId));

      return { updated: true };
    }),

  // Delete a finding
  deleteFinding: protectedProcedure
    .input(z.object({ findingId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      await db.delete(ac3ReportFindings)
        .where(eq(ac3ReportFindings.findingId, input.findingId));
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
        .where(eq(ac3ReportFindings.findingId, input.findingId));
      if (!finding) throw new Error("Finding not found");

      // Get the report for context
      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.reportId, finding.reportId));
      if (!report) throw new Error("Report not found");

      const findingData = {
        ...finding,
        sourceContext: input.sourceContext || "",
      };

      const prompt = buildFindingNarrativePrompt(findingData, report);

      const response = await invokeLLM({
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
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
        _caller: "ac3-reports.generateFindingNarrative",
      });

      const content = response.choices?.[0]?.message?.content;
      if (!content) throw new Error("LLM returned empty response");

      const narrative = JSON.parse(content);
      const now = Date.now();

      // Update finding with LLM-drafted narratives
      await db.update(ac3ReportFindings).set({
        title: narrative.title,
        summary: narrative.summary,
        businessImpact: narrative.business_impact,
        technicalDetails: narrative.technical_details,
        remediation: narrative.remediation,
        narrativeStatus: "drafted",
        updatedAt: now,
      }).where(eq(ac3ReportFindings.findingId, input.findingId));

      return { narrative, status: "drafted" };
    }),

  // Generate executive summary for a report
  generateExecSummary: protectedProcedure
    .input(z.object({ reportId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();

      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.reportId, input.reportId));
      if (!report) throw new Error("Report not found");

      const findings = await db.select().from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.reportId, input.reportId))
        .orderBy(ac3ReportFindings.sortOrder);

      if (findings.length === 0) throw new Error("No findings to summarize");

      const prompt = buildExecSummaryPrompt(report, findings);

      const response = await invokeLLM({
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
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
        _caller: "ac3-reports.generateExecSummary",
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
        execRiskStatement: summary.risk_statement,
        execOverallRating: normalizedRating as any,
        execKeyStrengths: summary.key_strengths,
        execKeyGaps: summary.key_gaps,
        execNarrative: summary.narrative,
        updatedAt: now,
      }).where(eq(ac3Reports.reportId, input.reportId));

      return { summary, generated: true };
    }),

  // Run QA review on a report
  runQaReview: protectedProcedure
    .input(z.object({ reportId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();

      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.reportId, input.reportId));
      if (!report) throw new Error("Report not found");

      const findings = await db.select().from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.reportId, input.reportId))
        .orderBy(ac3ReportFindings.sortOrder);

      const prompt = buildQaReviewPrompt(report, findings);

      const response = await invokeLLM({
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
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
        _caller: "ac3-reports.runQaReview",
      });

      const content = response.choices?.[0]?.message?.content;
      if (!content) throw new Error("LLM returned empty response");

      const review = JSON.parse(content);
      const now = Date.now();

      const qaStatus = review.status === "pass" ? "pass" : "revise";

      await db.update(ac3Reports).set({
        qaStatus: qaStatus as any,
        qaIssues: review.issues,
        qaReviewedAt: now,
        status: qaStatus === "pass" ? "review" : "draft",
        updatedAt: now,
      }).where(eq(ac3Reports.reportId, input.reportId));

      return { review, qaStatus };
    }),

  // Generate all finding narratives for a report
  generateAllNarratives: protectedProcedure
    .input(z.object({ reportId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();

      const findings = await db.select().from(ac3ReportFindings)
        .where(and(
          eq(ac3ReportFindings.reportId, input.reportId),
          eq(ac3ReportFindings.narrativeStatus, "pending"),
        ));

      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.reportId, input.reportId));
      if (!report) throw new Error("Report not found");

      // Update report status
      await db.update(ac3Reports).set({
        status: "generating",
        updatedAt: Date.now(),
      }).where(eq(ac3Reports.reportId, input.reportId));

      const results: Array<{ findingId: string; status: string }> = [];

      for (const finding of findings) {
        try {
          const prompt = buildFindingNarrativePrompt(finding, report);

          const response = await invokeLLM({
            messages: [
              { role: "system", content: SYSTEM_PROMPT },
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
            _caller: "ac3-reports.generateAllNarratives",
          });

          const content = response.choices?.[0]?.message?.content;
          if (!content) throw new Error("Empty response");

          const narrative = JSON.parse(content);
          const now = Date.now();

          await db.update(ac3ReportFindings).set({
            title: narrative.title,
            summary: narrative.summary,
            businessImpact: narrative.business_impact,
            technicalDetails: narrative.technical_details,
            remediation: narrative.remediation,
            narrativeStatus: "drafted",
            updatedAt: now,
          }).where(eq(ac3ReportFindings.findingId, finding.findingId));

          results.push({ findingId: finding.findingId, status: "drafted" });
        } catch (err: any) {
          results.push({ findingId: finding.findingId, status: `error: ${err.message}` });
        }
      }

      // Update report status back to draft
      await db.update(ac3Reports).set({
        status: "draft",
        updatedAt: Date.now(),
      }).where(eq(ac3Reports.reportId, input.reportId));

      return { results, totalProcessed: results.length };
    }),

  // Delete a report and all its findings
  deleteReport: protectedProcedure
    .input(z.object({ reportId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      await db.delete(ac3ReportFindings).where(eq(ac3ReportFindings.reportId, input.reportId));
      await db.delete(ac3Reports).where(eq(ac3Reports.reportId, input.reportId));
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
        .where(eq(ac3Reports.reportId, input.reportId));
      if (!report) throw new Error("Report not found");

      const findings = await db.select().from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.reportId, input.reportId))
        .orderBy(ac3ReportFindings.sortOrder);

      // Build the AC3 report_input.schema.json compatible output
      return {
        metadata: {
          client_name: report.clientName || "",
          system_name: report.systemName || "",
          assessment_type: report.assessmentType || "penetration_test",
          fedramp_impact_level: report.fedrampImpactLevel || "moderate",
          cloud_provider: report.cloudProvider || "",
          service_model: report.serviceModel || "",
          assessment_window: `${report.assessmentWindowStart ? new Date(report.assessmentWindowStart).toISOString().split("T")[0] : "N/A"} to ${report.assessmentWindowEnd ? new Date(report.assessmentWindowEnd).toISOString().split("T")[0] : "N/A"}`,
          report_version: report.reportVersion || "1.0",
        },
        executive_summary: {
          risk_statement: report.execRiskStatement || "",
          overall_rating: report.execOverallRating || "moderate",
          key_strengths: report.execKeyStrengths || [],
          key_gaps: report.execKeyGaps || [],
          narrative: report.execNarrative || "",
        },
        scope: {
          domains: report.scopeDomains || [],
          assets: report.scopeAssets || [],
          approved_vectors: report.approvedVectors || [],
          out_of_scope: report.outOfScope || [],
        },
        findings: findings.map(f => ({
          id: f.findingId,
          title: f.title,
          severity: f.severity,
          summary: f.summary || "",
          business_impact: f.businessImpact || "",
          technical_details: f.technicalDetails || "",
          evidence: (f.evidence as any[] || []).map((e: any) => e.reference || e.description),
          attack_techniques: (f.attackTechniques as any[] || []).map((t: any) => t.id),
          controls: (f.controls as any[] || []).map((c: any) => c.id),
          remediation: f.remediation || "",
          assets: f.assets || [],
          cvss_score: f.cvssScore || undefined,
          cvss_vector: f.cvssVector || undefined,
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
        .where(eq(ac3Reports.reportId, input.reportId));
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

      // Get existing finding count for sort order
      const existingFindings = await db.select({ id: ac3ReportFindings.id })
        .from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.reportId, input.reportId));
      let sortOrder = existingFindings.length;

      let imported = 0;
      for (const event of events) {
        const severity = mapSeverity(event.severity);
        if (input.severityFilter && !input.severityFilter.includes(severity)) continue;

        const findingId = `AC3-${randomUUID().slice(0, 8).toUpperCase()}`;
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

        const now = Date.now();
        await db.insert(ac3ReportFindings).values({
          findingId,
          reportId: input.reportId,
          title: event.title,
          severity,
          attackTechniques: JSON.stringify(attackTechniques),
          controls: JSON.stringify(mapEventToControls(event.eventType)),
          evidence: JSON.stringify(evidence),
          assets: JSON.stringify(assets),
          narrativeStatus: 'pending',
          sortOrder: sortOrder++,
          createdAt: now,
          updatedAt: now,
          sourceModule: `engagement:${input.engagementId}`,
          sourceEventId: String(event.id),
        });
        imported++;
      }

      return { imported, total: events.length, engagementName: eng.name };
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
        .where(eq(ac3Reports.reportId, input.reportId));
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

      // Get existing finding count for sort order
      const existingFindings = await db.select({ id: ac3ReportFindings.id })
        .from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.reportId, input.reportId));
      let sortOrder = existingFindings.length;

      let imported = 0;
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

        const findingId = `AC3-${randomUUID().slice(0, 8).toUpperCase()}`;
        const now = Date.now();

        await db.insert(ac3ReportFindings).values({
          findingId,
          reportId: input.reportId,
          title: `${ability.name || abilityId}${tactic ? ` (${tactic})` : ''}`,
          severity,
          attackTechniques: JSON.stringify(attackTechniques),
          controls: JSON.stringify(controls),
          evidence: JSON.stringify(evidence),
          assets: JSON.stringify(assets),
          narrativeStatus: 'pending',
          sortOrder: sortOrder++,
          createdAt: now,
          updatedAt: now,
          sourceModule: `caldera:${input.operationId}`,
          sourceEventId: abilityId,
        });
        imported++;
      }

      // Also try to import from local atomic test executions linked to this operation
      const localExecs = await db.select().from(atomicTestExecutions)
        .where(eq(atomicTestExecutions.calderaOperationId, input.operationId));

      for (const exec of localExecs) {
        // Skip if we already imported this technique from the Caldera chain
        if (abilityGroups.has(exec.techniqueId)) continue;

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
          findingId,
          reportId: input.reportId,
          title: exec.testName,
          severity,
          attackTechniques: JSON.stringify([{ id: exec.techniqueId }]),
          controls: JSON.stringify([{ id: 'RA-5' }]),
          evidence: JSON.stringify(evidence),
          assets: JSON.stringify(exec.targetHost ? [exec.targetHost] : []),
          narrativeStatus: 'pending',
          sortOrder: sortOrder++,
          createdAt: now,
          updatedAt: now,
          sourceModule: `atomic:${exec.calderaOperationId}`,
          sourceEventId: exec.guid,
        });
        imported++;
      }

      return {
        imported,
        operationName: operation.name,
        totalLinks: chain.length,
        adversaryName: operation.adversary?.name || 'Unknown',
      };
    }),

  // ─── DOCX Export ────────────────────────────────────────────────────────────

  /** Generate and return a FedRAMP-style DOCX report */
  exportDocx: protectedProcedure
    .input(z.object({ reportId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();

      const [report] = await db.select().from(ac3Reports)
        .where(eq(ac3Reports.reportId, input.reportId));
      if (!report) throw new Error("Report not found");

      const findings = await db.select().from(ac3ReportFindings)
        .where(eq(ac3ReportFindings.reportId, input.reportId))
        .orderBy(ac3ReportFindings.sortOrder);

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
          children: [new TextRun({ text: report.name || 'AC3 Assessment Report', bold: true, size: 56, color: '1a1a2e' })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 100 },
          children: [new TextRun({ text: `${report.assessmentType?.replace(/_/g, ' ').toUpperCase() || 'PENETRATION TEST'} REPORT`, size: 28, color: '666666' })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 400 },
          children: [new TextRun({ text: `FedRAMP ${(report.fedrampImpactLevel || 'moderate').toUpperCase()} Impact Level`, size: 24, color: '888888' })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: `Prepared for: ${report.clientName || 'Client'}`, size: 22, color: '444444' })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: `System: ${report.systemName || 'N/A'}`, size: 22, color: '444444' })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 200 },
          children: [new TextRun({ text: `Report ID: ${report.reportId}`, size: 20, color: '888888' })],
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
      if (report.execNarrative) {
        if (report.execRiskStatement) {
          execSection.push(new Paragraph({
            spacing: { after: 200 },
            children: [new TextRun({ text: 'Overall Risk: ', bold: true }), new TextRun({ text: report.execRiskStatement })],
          }));
        }
        if (report.execNarrative) {
          execSection.push(new Paragraph({ spacing: { after: 200 }, children: [new TextRun({ text: report.execNarrative })] }));
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
      const scopeDomains = (report.scopeDomains as string[] || []);
      const scopeAssets = (report.scopeAssets as string[] || []);
      const approvedVectors = (report.approvedVectors as string[] || []);
      const outOfScope = (report.outOfScope as string[] || []);

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
      findings.forEach(f => { severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1; });

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
        const sColor = severityColor[f.severity] || '000000';
        findingsSection.push(
          new Paragraph({
            heading: HeadingLevel.HEADING_2,
            spacing: { before: 400 },
            children: [
              new TextRun({ text: `${idx + 1}. `, bold: true }),
              new TextRun({ text: f.title, bold: true }),
              new TextRun({ text: `  [${f.severity.toUpperCase()}]`, bold: true, color: sColor }),
            ],
          }),
        );

        // Finding metadata table
        const metaRows: [string, string][] = [
          ['Finding ID', f.findingId],
          ['Severity', f.severity.toUpperCase()],
        ];
        if (f.cvssScore) metaRows.push(['CVSS Score', `${f.cvssScore}${f.cvssVector ? ` (${f.cvssVector})` : ''}`]);
        const techniques = (f.attackTechniques as any[] || []);
        if (techniques.length) metaRows.push(['ATT&CK Techniques', techniques.map((t: any) => `${t.id}${t.name ? ': ' + t.name : ''}`).join(', ')]);
        const controls = (f.controls as any[] || []);
        if (controls.length) metaRows.push(['NIST 800-53 Controls', controls.map((c: any) => c.id).join(', ')]);
        const assets = (f.assets as string[] || []);
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
        if (f.summary) {
          findingsSection.push(new Paragraph({ spacing: { before: 200 }, children: [new TextRun({ text: 'Summary', bold: true })] }));
          findingsSection.push(new Paragraph({ children: [new TextRun({ text: f.summary })] }));
        }
        if (f.businessImpact) {
          findingsSection.push(new Paragraph({ spacing: { before: 200 }, children: [new TextRun({ text: 'Business Impact', bold: true })] }));
          findingsSection.push(new Paragraph({ children: [new TextRun({ text: f.businessImpact })] }));
        }
        if (f.technicalDetails) {
          findingsSection.push(new Paragraph({ spacing: { before: 200 }, children: [new TextRun({ text: 'Technical Details', bold: true })] }));
          findingsSection.push(new Paragraph({ children: [new TextRun({ text: f.technicalDetails })] }));
        }
        if (f.remediation) {
          findingsSection.push(new Paragraph({ spacing: { before: 200 }, children: [new TextRun({ text: 'Remediation', bold: true })] }));
          findingsSection.push(new Paragraph({ children: [new TextRun({ text: f.remediation })] }));
        }

        // Evidence
        const evidence = (f.evidence as any[] || []);
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
      });

      // Assemble document
      const doc = new Document({
        creator: 'Harrison Cook — AceofCloud',
        title: report.name || 'AC3 Assessment Report',
        description: `FedRAMP ${report.fedrampImpactLevel || 'Moderate'} Assessment Report`,
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
          ],
        }],
      });

      // Generate buffer and upload to S3
      const buffer = await Packer.toBuffer(doc);
      const fileName = `ac3-reports/${input.reportId}-${Date.now()}.docx`;
      const { url } = await storagePut(fileName, Buffer.from(buffer), 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');

      // Store the URL on the report
      await db.update(ac3Reports).set({
        docxUrl: url,
        updatedAt: Date.now(),
      }).where(eq(ac3Reports.reportId, input.reportId));

      return { url, fileName };
    }),
};
