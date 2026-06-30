/**
 * Report Narrative Generator — P2 Gap Remediation
 * 
 * Generates executive-quality narrative sections for penetration test reports
 * using LLM with structured prompts. Produces consistent, professional prose
 * that contextualizes findings for different audiences.
 * 
 * Features:
 * - Executive summary generation from findings data
 * - Technical narrative for each finding category
 * - Risk context paragraphs with business impact
 * - Remediation roadmap narratives
 * - Compliance mapping narratives (NIST, FedRAMP, CMMC)
 * - Tone calibration (executive, technical, compliance)
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type NarrativeTone = "executive" | "technical" | "compliance" | "client_facing";
export type NarrativeSection =
  | "executive_summary"
  | "scope_and_methodology"
  | "findings_overview"
  | "risk_analysis"
  | "remediation_roadmap"
  | "compliance_mapping"
  | "conclusion";

export interface NarrativeInput {
  engagementName: string;
  clientName: string;
  engagementType: string;
  startDate: string;
  endDate: string;
  scope: string[];
  findings: FindingSummary[];
  riskScore: number;
  complianceFrameworks: string[];
}

export interface FindingSummary {
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  description: string;
  impact: string;
  remediation: string;
  cvssScore?: number;
  affectedAssets: string[];
}

export interface NarrativeOutput {
  section: NarrativeSection;
  tone: NarrativeTone;
  content: string;
  wordCount: number;
  generatedAt: number;
}

// ─── Prompt Templates ───────────────────────────────────────────────────────

const TONE_INSTRUCTIONS: Record<NarrativeTone, string> = {
  executive: `Write in a clear, business-focused tone suitable for C-suite executives and board members. 
Avoid technical jargon. Focus on business risk, financial impact, and strategic recommendations. 
Use confident, decisive language. Keep paragraphs concise (3-4 sentences max).`,

  technical: `Write in a precise, technical tone suitable for security engineers and IT staff. 
Include specific technical details, attack vectors, and remediation steps. 
Reference CVEs, MITRE ATT&CK techniques, and tool outputs where relevant.`,

  compliance: `Write in a formal, compliance-oriented tone suitable for auditors and regulators. 
Reference specific control frameworks (NIST 800-53, FedRAMP, CMMC). 
Use compliance terminology (control objectives, implementation status, evidence).
Structure content to align with assessment report requirements.`,

  client_facing: `Write in a professional, accessible tone suitable for the client's security team. 
Balance technical accuracy with readability. Explain impact in business terms 
while providing enough technical detail for remediation planning.`,
};

function buildSeverityDistribution(findings: FindingSummary[]): string {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return `Critical: ${counts.critical}, High: ${counts.high}, Medium: ${counts.medium}, Low: ${counts.low}, Informational: ${counts.info}`;
}

function buildCategoryBreakdown(findings: FindingSummary[]): string {
  const cats = new Map<string, number>();
  for (const f of findings) cats.set(f.category, (cats.get(f.category) || 0) + 1);
  return Array.from(cats.entries()).map(([cat, count]) => `${cat}: ${count}`).join(", ");
}

// ─── Narrative Generators ───────────────────────────────────────────────────

export function buildExecutiveSummaryPrompt(input: NarrativeInput, tone: NarrativeTone): string {
  return `${TONE_INSTRUCTIONS[tone]}

Generate an executive summary for the following penetration test engagement:

Engagement: ${input.engagementName}
Client: ${input.clientName}
Type: ${input.engagementType}
Period: ${input.startDate} to ${input.endDate}
Scope: ${input.scope.join(", ")}
Overall Risk Score: ${input.riskScore}/100

Findings Distribution: ${buildSeverityDistribution(input.findings)}
Category Breakdown: ${buildCategoryBreakdown(input.findings)}

Top Critical/High Findings:
${input.findings
  .filter(f => f.severity === "critical" || f.severity === "high")
  .slice(0, 5)
  .map(f => `- ${f.title} (${f.severity.toUpperCase()}, CVSS: ${f.cvssScore || "N/A"}): ${f.impact}`)
  .join("\n")}

Compliance Frameworks: ${input.complianceFrameworks.join(", ") || "None specified"}

Write a 3-5 paragraph executive summary that:
1. Opens with the engagement purpose and scope
2. Summarizes the overall security posture and risk level
3. Highlights the most critical findings and their business impact
4. Provides a high-level remediation priority
5. Concludes with a forward-looking recommendation

Do NOT include section headers. Write flowing prose paragraphs.`;
}

export function buildFindingsOverviewPrompt(input: NarrativeInput, tone: NarrativeTone): string {
  return `${TONE_INSTRUCTIONS[tone]}

Generate a findings overview narrative for this penetration test:

Total Findings: ${input.findings.length}
Distribution: ${buildSeverityDistribution(input.findings)}
Categories: ${buildCategoryBreakdown(input.findings)}

All Findings:
${input.findings.map(f => 
  `- [${f.severity.toUpperCase()}] ${f.title} | Category: ${f.category} | Assets: ${f.affectedAssets.join(", ")} | CVSS: ${f.cvssScore || "N/A"}`
).join("\n")}

Write a 2-4 paragraph narrative that:
1. Summarizes the findings landscape and patterns
2. Groups findings by theme/category and explains trends
3. Identifies systemic issues vs. isolated vulnerabilities
4. Notes any positive security controls observed

Do NOT list individual findings. Write analytical prose that synthesizes patterns.`;
}

export function buildRiskAnalysisPrompt(input: NarrativeInput, tone: NarrativeTone): string {
  return `${TONE_INSTRUCTIONS[tone]}

Generate a risk analysis narrative:

Overall Risk Score: ${input.riskScore}/100
Findings: ${buildSeverityDistribution(input.findings)}

Critical Attack Chains:
${input.findings
  .filter(f => f.severity === "critical")
  .map(f => `- ${f.title}: ${f.impact}`)
  .join("\n") || "No critical findings"}

Write a 2-3 paragraph risk analysis that:
1. Contextualizes the risk score against industry benchmarks
2. Describes the most likely attack scenarios and their business impact
3. Quantifies potential impact (data breach, downtime, regulatory fines)
4. Prioritizes risks by exploitability and impact`;
}

export function buildRemediationRoadmapPrompt(input: NarrativeInput, tone: NarrativeTone): string {
  return `${TONE_INSTRUCTIONS[tone]}

Generate a remediation roadmap narrative:

Findings requiring remediation:
${input.findings
  .filter(f => f.severity !== "info")
  .map(f => `- [${f.severity.toUpperCase()}] ${f.title}: ${f.remediation}`)
  .join("\n")}

Write a 3-4 paragraph remediation roadmap that:
1. Defines immediate actions (0-30 days) for critical/high findings
2. Outlines short-term improvements (30-90 days) for medium findings
3. Describes long-term strategic improvements
4. Recommends validation testing after remediation`;
}

export function buildComplianceMappingPrompt(input: NarrativeInput, tone: NarrativeTone): string {
  return `${TONE_INSTRUCTIONS[tone]}

Generate a compliance mapping narrative:

Frameworks: ${input.complianceFrameworks.join(", ")}
Findings: ${buildSeverityDistribution(input.findings)}

Findings with compliance impact:
${input.findings
  .filter(f => f.severity === "critical" || f.severity === "high")
  .map(f => `- ${f.title} (${f.category}): ${f.impact}`)
  .join("\n")}

Write a 2-3 paragraph compliance analysis that:
1. Maps critical findings to specific control failures
2. Assesses impact on authorization/certification status
3. Recommends compliance-specific remediation priorities`;
}

// ─── Main Generator ─────────────────────────────────────────────────────────

/**
 * Build the LLM prompt for a given narrative section.
 * Returns the prompt string to be passed to invokeLLM.
 */
export function buildNarrativePrompt(
  section: NarrativeSection,
  input: NarrativeInput,
  tone: NarrativeTone
): string {
  switch (section) {
    case "executive_summary":
      return buildExecutiveSummaryPrompt(input, tone);
    case "findings_overview":
      return buildFindingsOverviewPrompt(input, tone);
    case "risk_analysis":
      return buildRiskAnalysisPrompt(input, tone);
    case "remediation_roadmap":
      return buildRemediationRoadmapPrompt(input, tone);
    case "compliance_mapping":
      return buildComplianceMappingPrompt(input, tone);
    case "scope_and_methodology":
      return `${TONE_INSTRUCTIONS[tone]}\n\nGenerate a scope and methodology section for a ${input.engagementType} engagement.\nScope: ${input.scope.join(", ")}\nPeriod: ${input.startDate} to ${input.endDate}\n\nWrite 2-3 paragraphs covering the assessment scope, methodology (OWASP, PTES, MITRE ATT&CK), tools used, and any limitations.`;
    case "conclusion":
      return `${TONE_INSTRUCTIONS[tone]}\n\nGenerate a conclusion for a penetration test report.\nRisk Score: ${input.riskScore}/100\nFindings: ${buildSeverityDistribution(input.findings)}\n\nWrite 1-2 paragraphs that summarize the overall security posture, acknowledge positive controls, and provide a forward-looking recommendation for the next assessment cycle.`;
    default:
      return buildExecutiveSummaryPrompt(input, tone);
  }
}

/**
 * Parse LLM response into a NarrativeOutput.
 */
export function parseNarrativeResponse(
  section: NarrativeSection,
  tone: NarrativeTone,
  content: string
): NarrativeOutput {
  const cleaned = content.trim();
  return {
    section,
    tone,
    content: cleaned,
    wordCount: cleaned.split(/\s+/).length,
    generatedAt: Date.now(),
  };
}
