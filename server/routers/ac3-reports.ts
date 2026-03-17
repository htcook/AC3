import { z } from "zod";
import { protectedProcedure } from "../_core/trpc";
import { getDbRequired } from "../db";
import { ac3Reports, ac3ReportFindings } from "../../drizzle/schema";
import { eq, desc, and, sql } from "drizzle-orm";
import { randomUUID } from "crypto";
import { invokeLLM } from "../_core/llm";

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
};
